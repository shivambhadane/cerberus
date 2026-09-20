"""Connecting a deployment platform account and using it to prove a target is the user's.

`providers/` only talks to the platforms. This module decides what that is worth:

  connect      an OAuth flow that is single-use, expires in ten minutes, and is bound to BOTH the Cerberus
               user who started it AND the browser it was started in
  store        tokens encrypted at rest, tied to their own row (core/crypto.py)
  verify       a target is verified only if the platform, asked with the user's own token, reports that
               hostname on a project that token can see
  re-check     before every scan of a platform-verified target, ask again: platform names can be
               released and re-registered by someone else, and a verification must not outlive the
               ownership it recorded

Errors are `ProviderServiceError` with a stable `code`; the API maps them to HTTP. None of them carry a
token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import providers
from core.crypto import CryptoError, TokenCipher
from core.models import ConnectedProvider, Domain, OAuthState, User, new_id, utcnow
from core.ownership import OwnershipError, normalize_domain
from providers import DeploymentProvider, ProviderError, ProviderProject, ProviderTokens

STATE_TTL = timedelta(minutes=10)
MAX_PENDING_STATES_PER_USER = 10
TOKEN_REFRESH_MARGIN = timedelta(seconds=60)
MAX_CONNECTIONS_PER_USER = 10


class ProviderServiceError(Exception):
    """`code` is stable and safe to show; `message` never contains a token."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def refused_state() -> ProviderServiceError:
    """The one answer for every way a callback can be wrong. It never says which check failed."""
    return ProviderServiceError("invalid_state", "This connection attempt is not valid. Start again.")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def redirect_uri_for(provider: str, public_api_url: str) -> str:
    """The exact redirect URI registered with the provider. Never derived from a request."""
    return f"{public_api_url.rstrip('/')}/api/v1/providers/{provider}/callback"


def _map_provider_error(exc: ProviderError, provider_label: str) -> ProviderServiceError:
    code = exc.code
    if code == "unauthorized":
        return ProviderServiceError(
            "connection_expired",
            f"{provider_label} no longer accepts this connection. Disconnect and connect it again.",
        )
    if code in ("unavailable", "bad_response"):
        return ProviderServiceError(
            "provider_unavailable", f"{provider_label} could not be reached. Try again."
        )
    if code == "not_a_platform_hostname":
        return ProviderServiceError("not_a_platform_hostname", exc.message)
    if code == "invalid_grant":
        return ProviderServiceError(
            "authorization_failed", f"{provider_label} did not accept the authorisation."
        )
    if code in ("not_found", "forbidden", "hostname_not_in_project", "invalid_identifier"):
        return ProviderServiceError(
            "ownership_not_proven",
            f"{provider_label} does not show that project and address as belonging to your account.",
        )
    return ProviderServiceError("provider_error", f"{provider_label} returned an error.")


# --- connecting ---------------------------------------------------------------------------------

# What a bearer token looks like. Whitespace inside one means a bad copy, so it is refused, not "fixed".
_TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9._~+/=-]{8,512}$")


def clean_token(raw: str | None) -> str:
    """The pasted token without the whitespace and quotes a copy-paste brings along, or `invalid_token`.
    The message never repeats the value."""
    token = (raw or "").strip().strip("\"'").strip()
    if not _TOKEN_SHAPE.match(token):
        raise ProviderServiceError(
            "invalid_token", "That does not look like an access token. Copy it again, without spaces."
        )
    return token


def connect_with_token(
    session: Session,
    user: User,
    provider: DeploymentProvider,
    cipher: TokenCipher,
    raw_token: str | None,
    options: dict[str, str | None],
    now: datetime | None = None,
) -> ConnectedProvider:
    """Connect an account with an access token the person pasted, instead of OAuth.

    The token is proved the same way an OAuth token is: it is used, right now, to ask the platform who it
    belongs to, and that answer (never anything the browser says) becomes the connection's account id. It is
    then stored encrypted like any other token and can never be read back.
    """
    now = now or datetime.now(UTC)
    if not provider.supports_token:
        raise ProviderServiceError(
            "not_supported", f"{provider.label} cannot be connected with an access token."
        )
    token = clean_token(raw_token)
    try:
        tokens = provider.tokens_from_pasted(token, options)
        account = provider.get_account(tokens)
    except ProviderError as exc:
        if exc.code in ("unauthorized", "forbidden", "not_found", "invalid_identifier"):
            raise ProviderServiceError(
                "invalid_token",
                f"{provider.label} did not accept that token. Check that it is current and, if it is "
                "limited to a team, that the team ID is right.",
            ) from exc
        raise _map_provider_error(exc, provider.label) from exc
    return _store_connection(session, user, provider, cipher, tokens, account, now)

def start_authorization(
    session: Session,
    user: User,
    provider: DeploymentProvider,
    cipher: TokenCipher,
    public_api_url: str,
    now: datetime | None = None,
) -> tuple[str, str]:
    """Begin an OAuth flow. Returns (URL to send the browser to, browser-binding nonce for the cookie)."""
    now = now or datetime.now(UTC)
    if not provider.is_configured():
        raise ProviderServiceError(
            "provider_not_configured", f"{provider.label} is not set up on this server."
        )

    session.execute(delete(OAuthState).where(OAuthState.user_id == user.id, OAuthState.expires_at < now))
    open_states = select(func.count()).select_from(OAuthState).where(
        OAuthState.user_id == user.id, OAuthState.used_at.is_(None)
    )
    pending = session.scalar(open_states) or 0
    if pending >= MAX_PENDING_STATES_PER_USER:
        raise ProviderServiceError(
            "too_many_pending", "Finish or wait out your earlier connection attempts first."
        )

    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64) if provider.uses_pkce else None
    row_id = new_id()
    session.add(OAuthState(
        id=row_id, user_id=user.id, provider=provider.name,
        state_hash=_digest(state), browser_hash=_digest(nonce),
        code_verifier_encrypted=cipher.encrypt(verifier, row_id) if verifier else None,
        created_at=now, expires_at=now + STATE_TTL,
    ))
    session.flush()
    challenge = _pkce_challenge(verifier) if verifier else None
    url = provider.build_authorization_url(
        state, redirect_uri_for(provider.name, public_api_url), challenge
    )
    return url, nonce


def complete_authorization(
    session: Session,
    provider: DeploymentProvider,
    cipher: TokenCipher,
    public_api_url: str,
    *,
    code: str | None,
    state: str | None,
    browser_nonce: str | None,
    now: datetime | None = None,
) -> ConnectedProvider:
    """Finish an OAuth flow started by `start_authorization`, or raise. Every refusal is a
    ProviderServiceError('invalid_state' | ...) that says nothing about *which* check failed."""
    now = now or datetime.now(UTC)
    refused = refused_state()

    if not code or not state or not browser_nonce:
        raise refused
    row = session.scalar(select(OAuthState).where(OAuthState.state_hash == _digest(state)))
    if row is None or row.provider != provider.name:
        raise refused
    # Single use: burn it *before* anything else can fail, and make that durable, so a replayed callback
    # can never get a second attempt even if the first one errors out.
    already_used = row.used_at is not None
    row.used_at = row.used_at or now
    session.commit()
    if already_used or _aware(row.expires_at) <= now:
        raise refused
    if not hmac.compare_digest(_digest(browser_nonce), row.browser_hash):
        raise refused  # another browser: a forwarded link, or a page trying to complete someone's flow
    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise refused

    try:
        sealed = row.code_verifier_encrypted
        verifier = cipher.decrypt(sealed, row.id) if sealed else None
    except CryptoError as exc:
        raise refused from exc
    try:
        tokens = provider.exchange_code(code, redirect_uri_for(provider.name, public_api_url), verifier)
        account = provider.get_account(tokens)  # who the provider says this is; never taken from the browser
    except ProviderError as exc:
        raise _map_provider_error(exc, provider.label) from exc

    return _store_connection(session, user, provider, cipher, tokens, account, now)


def _store_connection(session, user, provider, cipher, tokens, account, now) -> ConnectedProvider:
    connection = session.scalar(
        select(ConnectedProvider).where(
            ConnectedProvider.user_id == user.id,
            ConnectedProvider.provider == provider.name,
            ConnectedProvider.provider_account_id == account.account_id,
        )
    )
    if connection is None:
        count = session.scalar(
            select(func.count()).select_from(ConnectedProvider).where(ConnectedProvider.user_id == user.id)
        ) or 0
        if count >= MAX_CONNECTIONS_PER_USER:
            raise ProviderServiceError("too_many_connections", "Disconnect an account before adding another.")
        connection = ConnectedProvider(
            id=new_id(), user_id=user.id, provider=provider.name, provider_account_id=account.account_id,
            access_token_encrypted="", created_at=now,
        )
        session.add(connection)
    connection.account_label = account.label[:255]
    connection.access_token_encrypted = cipher.encrypt(tokens.access_token, connection.id)
    connection.refresh_token_encrypted = (
        cipher.encrypt(tokens.refresh_token, connection.id) if tokens.refresh_token else None
    )
    connection.token_expires_at = tokens.expires_at
    connection.scopes = tokens.scopes
    connection.extra = {**tokens.extra, **account.extra}
    connection.updated_at = now
    try:
        session.flush()
    except IntegrityError as exc:  # two callbacks for one account at the same instant
        session.rollback()
        raise refused_state() from exc
    return connection


# --- using a connection ------------------------------------------------------------------------

def owned_connection(session: Session, user: User, connection_id: str) -> ConnectedProvider:
    """The user's own connection, or `connection_not_found`. Someone else's is indistinguishable
    from one that does not exist."""
    connection = session.get(ConnectedProvider, connection_id)
    if connection is None or connection.user_id != user.id:
        raise ProviderServiceError("connection_not_found", "No such connection.")
    return connection


def load_tokens(
    session: Session,
    connection: ConnectedProvider,
    provider: DeploymentProvider,
    cipher: TokenCipher,
    now: datetime | None = None,
) -> ProviderTokens:
    """The connection's tokens, decrypted, and refreshed first if they are about to expire."""
    now = now or datetime.now(UTC)
    try:
        access = cipher.decrypt(connection.access_token_encrypted, connection.id)
        refresh = (
            cipher.decrypt(connection.refresh_token_encrypted, connection.id)
            if connection.refresh_token_encrypted else None
        )
    except CryptoError as exc:
        raise ProviderServiceError(
            "connection_expired", f"{provider.label} needs to be connected again."
        ) from exc
    expires = _aware(connection.token_expires_at) if connection.token_expires_at else None
    tokens = ProviderTokens(access, refresh, expires, connection.scopes, dict(connection.extra or {}))

    if expires is not None and expires - TOKEN_REFRESH_MARGIN <= now:
        if not refresh:
            raise ProviderServiceError("connection_expired", f"{provider.label} needs to be connected again.")
        try:
            fresh = provider.refresh(refresh)
        except ProviderError as exc:
            raise _map_provider_error(exc, provider.label) from exc
        connection.access_token_encrypted = cipher.encrypt(fresh.access_token, connection.id)
        if fresh.refresh_token:
            connection.refresh_token_encrypted = cipher.encrypt(fresh.refresh_token, connection.id)
        connection.token_expires_at = fresh.expires_at
        connection.updated_at = now
        session.flush()
        tokens = ProviderTokens(
            fresh.access_token, fresh.refresh_token or refresh, fresh.expires_at,
            connection.scopes, tokens.extra,
        )
    return tokens


def list_projects(
    session: Session, connection: ConnectedProvider, provider: DeploymentProvider, cipher: TokenCipher
) -> list[ProviderProject]:
    tokens = load_tokens(session, connection, provider, cipher)
    try:
        return provider.list_projects(tokens)
    except ProviderError as exc:
        raise _map_provider_error(exc, provider.label) from exc


def disconnect(session: Session, connection: ConnectedProvider) -> int:
    """Forget a connection. Targets it verified lose that proof: they go back to `pending`, so a
    connection that no longer exists cannot keep vouching for a hostname. Returns how many."""
    domains = session.scalars(select(Domain).where(Domain.provider_connection_id == connection.id)).all()
    for domain in domains:
        domain.verification_status = "pending"
        domain.verified_at = None
        domain.provider_connection_id = None
    session.flush()
    session.delete(connection)
    session.flush()
    return len(domains)


# --- verifying a target ------------------------------------------------------------------------

def verify_platform_target(
    session: Session,
    user: User,
    cipher: TokenCipher,
    *,
    connection_id: str,
    project_id: str,
    hostname: str,
    domain_id: str | None = None,
) -> Domain:
    """Make `hostname` a verified target for `user` -- if, and only if, the platform confirms it.

    `connection_id`, `project_id` and `hostname` all come from the browser, and none is believed: the
    connection must be the user's own; the project is fetched with that connection's token, so the
    platform decides whether this account can see it; and the hostname must be one the platform lists on
    that project. A wrong answer at any step is `ownership_not_proven`.
    """
    connection = owned_connection(session, user, connection_id)
    provider = providers.get_provider(connection.provider)
    # A token the person pasted needs no OAuth app on this server to be used; an OAuth connection does.
    if (connection.extra or {}).get("method") != "token" and not provider.is_configured():
        raise ProviderServiceError(
            "provider_not_configured", f"{provider.label} is not set up on this server."
        )

    try:
        name = normalize_domain(hostname)
    except OwnershipError as exc:
        raise ProviderServiceError("invalid_domain", str(exc)) from exc

    tokens = load_tokens(session, connection, provider, cipher)
    try:
        project = provider.verify_target(tokens, project_id, name)
    except ProviderError as exc:
        raise _map_provider_error(exc, provider.label) from exc

    domain = _domain_for(session, user, name, domain_id)
    holder = session.scalar(
        select(Domain.id).where(
            Domain.domain == name, Domain.verification_status == "verified", Domain.id != domain.id
        )
    )
    if holder is not None:
        raise ProviderServiceError(
            "domain_already_verified", f"Another account has already verified {name}."
        )
    domain.verification_method = connection.provider
    domain.verification_status = "verified"
    domain.verified_at = utcnow()
    domain.provider = connection.provider
    domain.provider_connection_id = connection.id
    domain.provider_project_id = project.id
    domain.provider_resource_id = project.scope_id
    try:
        session.flush()  # the partial unique index is the final arbiter: first to prove it owns it
    except IntegrityError as exc:
        session.rollback()
        raise ProviderServiceError(
            "domain_already_verified", f"Another account has already verified {name}."
        ) from exc
    return domain


def _domain_for(session: Session, user: User, name: str, domain_id: str | None) -> Domain:
    if domain_id is not None:
        domain = session.get(Domain, domain_id)
        if domain is None or domain.user_id != user.id:
            raise ProviderServiceError("not_found", "No such domain.")
        if domain.domain != name:
            raise ProviderServiceError("ownership_not_proven", "That address is not this target.")
        return domain
    existing = session.scalar(select(Domain).where(Domain.user_id == user.id, Domain.domain == name))
    if existing is not None:
        return existing
    domain = Domain(user_id=user.id, domain=name)
    session.add(domain)
    session.flush()
    return domain


def recheck_platform_target(session: Session, domain: Domain, cipher: TokenCipher | None) -> None:
    """Confirm, right now, that a platform-verified target is still the user's. Called before a scan.

    Vercel, Netlify and Cloudflare all release a project's name when it is deleted, and anyone can then
    register it. A verification that was true last month must not authorise scanning that name today.
      * The platform says it is no longer this account's -> the target becomes `failed`, scan refused.
      * The connection's token no longer works -> refused (`connection_expired`); the user reconnects.
      * The platform cannot be reached -> refused (`provider_unavailable`); nothing is changed.
    """
    if domain.verification_method not in providers.PROVIDER_NAMES:
        return  # DNS-verified targets are unaffected
    if cipher is None:
        raise ProviderServiceError(
            "provider_not_configured", "Provider verification is not set up on this server."
        )

    connection = (
        session.get(ConnectedProvider, domain.provider_connection_id)
        if domain.provider_connection_id else None
    )
    if connection is None or connection.user_id != domain.user_id:
        _mark_lost(session, domain)
        raise ProviderServiceError(
            "ownership_lost", f"{domain.domain} is no longer verified. Verify it again."
        )

    provider = providers.get_provider(connection.provider)
    tokens = load_tokens(session, connection, provider, cipher)
    try:
        provider.verify_target(tokens, domain.provider_project_id or "", domain.domain)
    except ProviderError as exc:
        mapped = _map_provider_error(exc, provider.label)
        if mapped.code == "ownership_not_proven":
            _mark_lost(session, domain)
            raise ProviderServiceError(
                "ownership_lost",
                f"{provider.label} no longer shows {domain.domain} as yours, so it cannot be scanned.",
            ) from exc
        raise mapped from exc


def _mark_lost(session: Session, domain: Domain) -> None:
    domain.verification_status = "failed"
    domain.verified_at = None
    session.commit()  # this must outlive the error response that follows
