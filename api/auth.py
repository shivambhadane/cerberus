"""Accounts: register, sign in, refresh, sign out, who am I.

How a session works
  * Signing in returns a short-lived **access token** (JWT, ~15 minutes) in the response body. The
    dashboard keeps it in memory only and sends it as `Authorization: Bearer`.
  * It also sets a long-lived **refresh token** as an httpOnly, SameSite=Lax cookie scoped to
    /api/v1/auth. JavaScript cannot read it, so an XSS bug cannot steal the session, and the
    browser will not attach it to a cross-site request.
  * The refresh token is opaque and single-use. Refreshing replaces it (rotation). If a token that
    was already rotated out is presented again, a copy has leaked, so the whole login is revoked.
    A short leeway forgives two tabs refreshing at the same instant.

The scanner never sees any of this. It is handed a user id by `api.deps.current_user`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.deps import ApiError, current_user, get_session
from api.schemas import AuthResponse, LoginRequest, RegisterRequest, UserOut
from core.config import load_config
from core.models import AuthSession, User, new_id
from core.ownership import OwnershipError, normalize_email
from core.security import (
    PasswordPolicyError,
    create_access_token,
    hash_password,
    hash_refresh_token,
    new_refresh_token,
    password_needs_rehash,
    spend_password_check_time,
    validate_password,
    verify_password,
)
from core.throttle import FailureLimiter, Throttled

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

REFRESH_COOKIE = "cerberus_refresh"
COOKIE_PATH = "/api/v1/auth"
# A token that was rotated out within this window may be used once more: two tabs refreshing at the
# same instant are a race, not theft. A *revoked* token (signed out, or theft detected) gets no
# leeway at all.
REUSE_LEEWAY = timedelta(seconds=10)

# Failures per email (guessing one account) and per address (guessing many). In-process; see
# core/throttle.py.
email_limiter = FailureLimiter(max_failures=5, window_seconds=900)
ip_limiter = FailureLimiter(max_failures=30, window_seconds=900)
register_limiter = FailureLimiter(max_failures=10, window_seconds=3600)


def reset_limiters() -> None:
    """For tests: each starts with a clean slate."""
    for limiter in (email_limiter, ip_limiter, register_limiter):
        limiter._failures.clear()


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(moment: datetime) -> datetime:
    """SQLite hands timezone-aware columns back naive; treat those as UTC."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _client_ip(request: Request) -> str:
    # The socket peer, not X-Forwarded-For: a client-supplied header would let an attacker pick
    # their own throttle bucket. Behind a reverse proxy this is the proxy's address (DEPLOYMENT.md).
    return request.client.host if request.client else "unknown"


def _require_allowed_origin(request: Request) -> None:
    """Browsers always send Origin on cross-origin POSTs. One we do not list is a foreign page
    trying to use the visitor's cookie. (SameSite=Lax already stops the cookie; this is the second
    lock.) Non-browser clients send no Origin and are unaffected."""
    origin = request.headers.get("origin")
    if origin and origin not in load_config().cors_origins:
        raise ApiError(403, "forbidden_origin", "This origin is not allowed to use the API.")


def _throttle(limiter: FailureLimiter, key: str) -> None:
    try:
        limiter.check(key)
    except Throttled as exc:
        raise ApiError(
            429, "too_many_attempts",
            f"Too many attempts. Try again in {exc.retry_after} seconds.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None


def _cookie_options() -> dict:
    return {"httponly": True, "samesite": "lax", "secure": load_config().cookie_secure, "path": COOKIE_PATH}


def _expired_cookie_header() -> dict[str, str]:
    """A Set-Cookie that deletes the refresh cookie, for error responses (which cannot carry the
    cookie changes made on the route's own Response)."""
    probe = Response()
    probe.delete_cookie(REFRESH_COOKIE, **_cookie_options())
    return {"Set-Cookie": probe.headers["set-cookie"]}


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id, email=user.email, name=user.name,
        email_verified=user.email_verified, created_at=user.created_at,
    )


def _start_session(
    session: Session, user: User, response: Response, family_id: str | None = None
) -> AuthResponse:
    config = load_config()
    raw = new_refresh_token()
    session.add(AuthSession(
        user_id=user.id,
        family_id=family_id or new_id(),
        token_hash=hash_refresh_token(raw),
        expires_at=_now() + timedelta(days=config.refresh_token_days),
    ))
    response.set_cookie(
        REFRESH_COOKIE, raw, max_age=config.refresh_token_days * 86400, **_cookie_options()
    )
    ttl = timedelta(minutes=config.access_token_minutes)
    return AuthResponse(
        user=_user_out(user),
        access_token=create_access_token(user.id, config.api_secret_key, ttl),
        expires_in=int(ttl.total_seconds()),
    )


def _revoke_family(session: Session, family_id: str) -> None:
    session.execute(
        update(AuthSession)
        .where(AuthSession.family_id == family_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=_now())
    )


@router.post("/register", response_model=AuthResponse, status_code=201)
def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> AuthResponse:
    _require_allowed_origin(request)
    ip = _client_ip(request)
    _throttle(register_limiter, ip)
    register_limiter.record_failure(ip)  # every attempt counts, not only the failed ones

    try:
        email = normalize_email(payload.email)
    except OwnershipError as exc:
        raise ApiError(400, "invalid_email", str(exc)) from None
    try:
        validate_password(payload.password, email)
    except PasswordPolicyError as exc:
        raise ApiError(400, "weak_password", str(exc)) from None

    taken = ApiError(409, "email_taken", "An account with this email already exists. Sign in instead.")
    if session.scalar(select(User.id).where(User.email == email)) is not None:
        raise taken
    user = User(email=email, password_hash=hash_password(payload.password), name=payload.name.strip())
    session.add(user)
    try:
        session.flush()
    except IntegrityError:  # two registrations for one email at the same instant
        raise taken from None
    return _start_session(session, user, response)


@router.post("/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> AuthResponse:
    _require_allowed_origin(request)
    ip = _client_ip(request)
    try:
        email = normalize_email(payload.email)
    except OwnershipError:
        email = payload.email.strip().lower()  # not a real address: still throttled, still refused
    email_key, ip_key = f"email:{email}", f"ip:{ip}"
    _throttle(email_limiter, email_key)
    _throttle(ip_limiter, ip_key)

    user = session.scalar(select(User).where(User.email == email))
    verified = False
    if user is not None and user.is_active and user.password_hash:
        verified = verify_password(user.password_hash, payload.password)
    else:
        spend_password_check_time(payload.password)  # an unknown email must not answer faster

    if not verified:
        email_limiter.record_failure(email_key)
        ip_limiter.record_failure(ip_key)
        # One message for "no such account", "wrong password" and "disabled account".
        raise ApiError(401, "invalid_credentials", "Email or password is incorrect.")

    email_limiter.reset(email_key)
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
    user.last_login_at = _now()
    return _start_session(session, user, response)


@router.post("/refresh", response_model=AuthResponse)
def refresh(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> AuthResponse:
    _require_allowed_origin(request)
    raw = request.cookies.get(REFRESH_COOKIE)
    if not raw:
        raise ApiError(401, "no_session", "Sign in to continue.")

    def refuse(code: str, message: str) -> ApiError:
        return ApiError(401, code, message, headers=_expired_cookie_header())

    record = session.scalar(select(AuthSession).where(AuthSession.token_hash == hash_refresh_token(raw)))
    if record is None:
        raise refuse("invalid_session", "Sign in to continue.")

    now = _now()
    if record.revoked_at is not None:
        raise refuse("session_revoked", "This session was signed out. Sign in again.")
    if record.rotated_at is not None and now - _aware(record.rotated_at) > REUSE_LEEWAY:
        # A token that was already replaced came back. Whoever holds the newer one and whoever
        # holds this one cannot both be the user, so end the login for both.
        _revoke_family(session, record.family_id)
        session.commit()  # the revocation must outlive the error response below
        raise refuse("session_revoked", "This session was signed out. Sign in again.")
    if _aware(record.expires_at) <= now:
        raise refuse("session_expired", "Your session has expired. Sign in again.")

    user = session.get(User, record.user_id)
    if user is None or not user.is_active:
        _revoke_family(session, record.family_id)
        session.commit()
        raise refuse("invalid_session", "Sign in to continue.")

    if record.rotated_at is None:
        record.rotated_at = now  # this token is now spent; a newer one replaces it
    return _start_session(session, user, response, family_id=record.family_id)


@router.post("/logout", status_code=204)
def logout(request: Request, session: Session = Depends(get_session)) -> Response:
    """Ends this login (the whole token family). Idempotent: signing out twice is fine."""
    _require_allowed_origin(request)
    raw = request.cookies.get(REFRESH_COOKIE)
    if raw:
        record = session.scalar(select(AuthSession).where(AuthSession.token_hash == hash_refresh_token(raw)))
        if record is not None:
            _revoke_family(session, record.family_id)
    response = Response(status_code=204)
    response.delete_cookie(REFRESH_COOKIE, **_cookie_options())
    return response


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> UserOut:
    return _user_out(user)
