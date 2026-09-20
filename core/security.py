"""Passwords and tokens. The only module that touches either.

Everything here is a pure function of its inputs (no database, no HTTP), so it can be tested
exhaustively and, if Cerberus later moves to a managed identity provider, replaced without the
scanner or the ownership rules noticing: the rest of the system only ever sees a user id.

  * Passwords are hashed with Argon2id (argon2-cffi's defaults follow RFC 9106). The plain
    password is never stored, logged, or returned.
  * Access tokens are short-lived signed JWTs (HS256) carrying only the user id. They are the
    credential for API calls and are kept in the browser's memory, never in storage.
  * Refresh tokens are opaque random strings. Only their SHA-256 hash is stored, so a copy of
    the database cannot be used to mint sessions. They live in an httpOnly cookie.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

ALGORITHM = "HS256"
ISSUER = "cerberus"
ACCESS_TOKEN_TYPE = "access"
CLOCK_LEEWAY_SECONDS = 5

MIN_PASSWORD_LENGTH = 5  # a demo convenience; 12+ is the real floor (NIST SP 800-63B)
MAX_PASSWORD_LENGTH = 128  # bounds hashing cost; a longer "password" is an attack, not a secret

_hasher = PasswordHasher()  # Argon2id


class PasswordPolicyError(ValueError):
    """The password is unacceptable. The message says how to fix it."""


class TokenError(Exception):
    """An access token was refused. `code` is stable; `expired` lets a client refresh."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# --- passwords -------------------------------------------------------------------------

def validate_password(password: str, email: str | None = None) -> None:
    """Length, not composition rules: a long passphrase beats "P@ssw0rd!" (NIST SP 800-63B).

    The floor is deliberately low so this portfolio project is quick to sign into. It is not a
    defensible minimum: five characters falls to an offline guess in seconds, and Argon2id slows
    that down without making it safe. Raise MIN_PASSWORD_LENGTH before anyone real has an account.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Use at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Use at most {MAX_PASSWORD_LENGTH} characters.")
    if email and password.strip().lower() in {email.strip().lower(), email.split("@")[0].strip().lower()}:
        raise PasswordPolicyError("The password must not be your email address.")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """False for a wrong password *and* for a malformed or empty stored hash."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    """True when the stored hash used weaker parameters than today's defaults."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _hasher.hash("cerberus-timing-equaliser")


def spend_password_check_time(password: str) -> None:
    """Do the same work as a real verification.

    Login for an unknown email would otherwise return instantly while a known one takes ~50ms,
    which tells an attacker which addresses have accounts.
    """
    verify_password(_dummy_hash(), password)


# --- access tokens ---------------------------------------------------------------------

def create_access_token(user_id: str, secret: str, ttl: timedelta, now: datetime | None = None) -> str:
    issued = now or datetime.now(UTC)
    claims = {
        "sub": user_id,
        "iss": ISSUER,
        "typ": ACCESS_TOKEN_TYPE,
        "iat": int(issued.timestamp()),
        "exp": int((issued + ttl).timestamp()),
    }
    return jwt.encode(claims, secret, algorithm=ALGORITHM)


def decode_access_token(token: str, secret: str) -> str:
    """The user id a valid, unexpired access token was issued to; TokenError otherwise.

    The algorithm is pinned: accepting whatever the token header claims is how `alg: none` and
    key-confusion forgeries work.
    """
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            leeway=CLOCK_LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise TokenError("token_expired", "The access token has expired.") from None
    except jwt.PyJWTError:
        raise TokenError("token_invalid", "The access token is not valid.") from None
    if claims.get("typ") != ACCESS_TOKEN_TYPE or not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise TokenError("token_invalid", "The access token is not valid.")
    return claims["sub"]


# --- refresh tokens --------------------------------------------------------------------

def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
