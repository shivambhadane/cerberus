"""What every route depends on: the error type, the database session, and who is calling.

`current_user` is the only place an access token is turned into a user. Routes take a `User`; they
never see a token, a password, or a header. Swapping the identity provider later (a managed
service issuing its own tokens) means changing this one function.
"""

from __future__ import annotations

from fastapi import Depends, Header
from sqlalchemy.orm import Session

from core.config import load_config
from core.db import session_scope
from core.firebase_auth import (
    FirebaseAuthError,
    FirebaseTokenExpiredError,
    verify_firebase_id_token,
)
from core.models import User, new_id, utcnow
from core.ownership import OwnershipError, normalize_email
from core.security import TokenError, decode_access_token


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers or {}


def get_session():
    with session_scope() as session:
        yield session


def current_user(
    authorization: str = Header(default=""),
    session: Session = Depends(get_session),
) -> User:
    scheme, _, token = authorization.partition(" ")
    if scheme != "Bearer" or not token:
        raise ApiError(401, "unauthorized", "Sign in to continue.")

    # 1. Try Firebase Authentication ID token
    try:
        payload = verify_firebase_id_token(token)
        token_email = payload.get("email") or ""
        uid = payload.get("uid") or payload.get("sub") or ""
        try:
            normalized_email = normalize_email(token_email) if token_email else ""
        except OwnershipError:
            normalized_email = token_email.strip().lower()

        user: User | None = None
        if normalized_email:
            user = session.query(User).filter(User.email == normalized_email).first()
        if user is None and uid:
            user = session.get(User, uid[:36])

        if user is None:
            # Auto-provision user from verified Firebase identity
            user_id = uid[:36] if uid else new_id()
            user = User(
                id=user_id,
                email=normalized_email or f"{uid}@cerberus.internal",
                password_hash="firebase_managed",
                name=payload.get("name") or "",
                email_verified=bool(payload.get("email_verified", False)),
                is_active=True,
                last_login_at=utcnow(),
            )
            session.add(user)
            session.commit()
            session.refresh(user)
        else:
            if not user.is_active:
                raise ApiError(401, "unauthorized", "Sign in to continue.")
            user.last_login_at = utcnow()
            if payload.get("email_verified") and not user.email_verified:
                user.email_verified = True
            session.commit()

        return user
    except FirebaseTokenExpiredError as exc:
        raise ApiError(401, "token_expired", str(exc)) from None
    except FirebaseAuthError:
        pass  # Fall back to internal/legacy token verification

    # 2. Legacy / internal JWT fallback (CLI tools, background workers, tests)
    try:
        user_id = decode_access_token(token, load_config().api_secret_key)
    except TokenError as exc:
        # `token_expired` is distinct so a client knows a refresh (not a sign-in) will fix it.
        raise ApiError(401, exc.code, str(exc)) from None
    user = session.get(User, user_id)
    # A disabled account stops working at once, not when its 15-minute token runs out.
    if user is None or not user.is_active:
        raise ApiError(401, "unauthorized", "Sign in to continue.")
    return user
