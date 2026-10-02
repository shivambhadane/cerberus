"""Connecting Vercel, Netlify and Cloudflare accounts.

The browser never sees a provider token or client secret: `connect` returns only the provider's
authorisation URL, the provider redirects back to `callback` on THIS server, and the token is exchanged
and stored here (encrypted). What the dashboard gets afterwards is a list of connections and projects.

Why the callback is a plain GET and not an authenticated call: it is a top-level browser redirect from the
provider, which cannot carry an `Authorization` header. It is authenticated instead by the state (single
use, ten minutes, tied to the user who asked) plus a cookie that only the browser that started the flow
holds. See core/provider_service.py.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

import providers
from api.auth import _cookie_options
from api.deps import ApiError, current_user, get_session
from api.schemas import (
    ConnectionOut,
    ConnectStarted,
    Disconnected,
    ProjectList,
    ProjectOut,
    ProviderInfo,
    ProviderList,
    TokenConnect,
)
from core import provider_service
from core.config import load_config
from core.crypto import CryptoError, TokenCipher, get_cipher
from core.models import ConnectedProvider, Domain, User
from core.provider_service import STATE_TTL, ProviderServiceError
from core.throttle import FailureLimiter, Throttled

router = APIRouter(prefix="/api/v1", tags=["providers"])

OAUTH_COOKIE = "cerberus_oauth"
COOKIE_PATH = "/api/v1/providers"
list_limiter = FailureLimiter(max_failures=60, window_seconds=3600)
# Wrong tokens only: each one is a guess sent on to the platform, so this stays tight.
token_limiter = FailureLimiter(max_failures=10, window_seconds=3600)

_STATUS = {
    "invalid_state": 400, "authorization_failed": 400, "provider_not_configured": 503,
    "too_many_pending": 429, "too_many_connections": 400, "connection_not_found": 404,
    "connection_expired": 409, "provider_unavailable": 503, "ownership_not_proven": 403,
    "not_a_platform_hostname": 400, "invalid_domain": 400, "domain_already_verified": 409,
    "not_found": 404, "ownership_lost": 403, "provider_error": 502,
    "invalid_token": 400, "not_supported": 400, "invalid_team_id": 400,
}


def reset_limiters() -> None:
    list_limiter._failures.clear()
    token_limiter._failures.clear()


def to_api_error(exc: ProviderServiceError) -> ApiError:
    """A provider's 401 is *its* problem with a stored token; it must never become our 401, which would
    sign the person out of Cerberus. Provider failures are 4xx/5xx of their own kinds."""
    return ApiError(_STATUS.get(exc.code, 400), exc.code, exc.message)


def cipher_or_error() -> TokenCipher:
    try:
        cipher = get_cipher()
    except CryptoError:
        cipher = None
    if cipher is None:
        raise ApiError(
            503, "provider_not_configured",
            "Connecting deployment accounts is not set up on this server (PROVIDER_TOKEN_ENCRYPTION_KEY).",
        )
    return cipher


def provider_or_404(name: str) -> providers.DeploymentProvider:
    try:
        return providers.get_provider(name)
    except providers.ProviderError:
        raise ApiError(404, "not_found", "That provider is not supported.") from None


def connection_out(connection: ConnectedProvider) -> ConnectionOut:
    return ConnectionOut(
        id=connection.id, provider=connection.provider,
        label=connection.account_label or connection.provider,
        connected_at=connection.created_at, scopes=connection.scopes.split() if connection.scopes else [],
        method="token" if (connection.extra or {}).get("method") == "token" else "oauth",
    )


def _my_connections(session: Session, user: User) -> list[ConnectedProvider]:
    stmt = select(ConnectedProvider).where(ConnectedProvider.user_id == user.id)
    return list(session.scalars(stmt.order_by(ConnectedProvider.created_at)))


def _throttle(user: User) -> None:
    try:
        list_limiter.check(user.id)
    except Throttled as exc:
        raise ApiError(
            429, "too_many_attempts", f"Too many requests. Try again in {exc.retry_after} seconds.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None
    list_limiter.record_failure(user.id)


@router.get("/providers", response_model=ProviderList)
def list_providers(
    user: User = Depends(current_user), session: Session = Depends(get_session)
) -> ProviderList:
    try:
        keyed = get_cipher() is not None
    except CryptoError:
        keyed = False
    mine = _my_connections(session, user)
    items = []
    for name in providers.PROVIDER_NAMES:
        provider = providers.get_provider(name)
        items.append(ProviderInfo(
            provider=name, label=provider.label, configured=keyed and provider.is_configured(),
            token_paste=keyed and provider.supports_token,
            connections=[connection_out(c) for c in mine if c.provider == name],
        ))
    return ProviderList(providers=items)


@router.post("/providers/{provider}/connect", response_model=ConnectStarted)
def connect(
    provider: str,
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> ConnectStarted:
    impl = provider_or_404(provider)
    cipher = cipher_or_error()
    try:
        url, nonce = provider_service.start_authorization(
            session, user, impl, cipher, load_config().public_api_url
        )
    except ProviderServiceError as exc:
        raise to_api_error(exc) from None
    # Ties the flow to this browser: the callback must present it. Not readable by scripts.
    options = {**_cookie_options(), "path": COOKIE_PATH}
    response.set_cookie(OAUTH_COOKIE, nonce, max_age=int(STATE_TTL.total_seconds()), **options)
    return ConnectStarted(authorization_url=url)


@router.post("/providers/{provider}/token", response_model=ConnectionOut)
def connect_with_token(
    provider: str,
    payload: TokenConnect,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> ConnectionOut:
    """Connect with an access token the person made on the platform (Vercel only for now).

    The token travels in the request body once, is proved by using it, is stored encrypted, and is never
    returned, logged or shown again. It is the fallback for when an OAuth app cannot be used; the same
    ownership checks apply to everything done with it.
    """
    impl = provider_or_404(provider)
    cipher = cipher_or_error()
    try:
        token_limiter.check(user.id)
    except Throttled as exc:
        raise ApiError(
            429, "too_many_attempts", f"Too many attempts. Try again in {exc.retry_after} seconds.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None
    try:
        connection = provider_service.connect_with_token(
            session, user, impl, cipher, payload.token, {"team_id": payload.team_id}
        )
    except ProviderServiceError as exc:
        if exc.code == "invalid_token":
            token_limiter.record_failure(user.id)
        raise to_api_error(exc) from None
    return connection_out(connection)


def _back_to_dashboard(provider: str, **params: str) -> RedirectResponse:
    from urllib.parse import urlencode

    query = urlencode({"provider": provider, **params})
    redirect = RedirectResponse(
        f"{load_config().frontend_url}/platform/#/domains?{query}", status_code=HTTP_303_SEE_OTHER
    )
    redirect.delete_cookie(OAUTH_COOKIE, **{**_cookie_options(), "path": COOKIE_PATH})
    return redirect


@router.get("/providers/{provider}/callback", include_in_schema=False)
def callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """The provider sends the browser here. The outcome is reported to the dashboard as a short code in
    the URL; never anything from the provider, and never a token."""
    if provider not in providers.PROVIDER_NAMES:
        raise ApiError(404, "not_found", "That provider is not supported.")
    if error:
        return _back_to_dashboard(provider, error="access_denied")
    try:
        impl = providers.get_provider(provider)
        connection = provider_service.complete_authorization(
            session, impl, cipher_or_error(), load_config().public_api_url,
            code=code, state=state, browser_nonce=request.cookies.get(OAUTH_COOKIE),
        )
    except ProviderServiceError as exc:
        return _back_to_dashboard(provider, error=exc.code)
    except ApiError as exc:
        return _back_to_dashboard(provider, error=exc.code)
    return _back_to_dashboard(provider, connected="1", account=connection.id)


@router.get("/connections", response_model=list[ConnectionOut])
def list_connections(
    user: User = Depends(current_user), session: Session = Depends(get_session)
) -> list[ConnectionOut]:
    return [connection_out(c) for c in _my_connections(session, user)]


@router.get("/connections/{connection_id}/projects", response_model=ProjectList)
def connection_projects(
    connection_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> ProjectList:
    """The projects the connected account controls, and which of their platform hostnames can be verified."""
    try:
        connection = provider_service.owned_connection(session, user, connection_id)
    except ProviderServiceError as exc:
        raise to_api_error(exc) from None
    _throttle(user)
    impl = provider_or_404(connection.provider)
    try:
        projects = provider_service.list_projects(session, connection, impl, cipher_or_error())
    except ProviderServiceError as exc:
        raise to_api_error(exc) from None
    verified = {
        d.domain for d in session.scalars(
            select(Domain).where(Domain.user_id == user.id, Domain.verification_status == "verified")
        )
    }
    return ProjectList(
        connection=connection_out(connection),
        projects=[
            ProjectOut(
                id=p.id, name=p.name, hostnames=list(p.hostnames),
                verified_hostnames=[h for h in p.hostnames if h in verified],
            )
            for p in projects
        ],
    )


@router.post("/connections/{connection_id}/disconnect", response_model=Disconnected)
def disconnect(
    connection_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> Disconnected:
    try:
        connection = provider_service.owned_connection(session, user, connection_id)
    except ProviderServiceError as exc:
        raise to_api_error(exc) from None
    return Disconnected(targets_reset=provider_service.disconnect(session, connection))
