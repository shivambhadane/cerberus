"""Firebase Authentication token verification.

Verifies Firebase ID tokens issued to the frontend using Google's public JWKS.
Zero private service-account key requirement: verifies tokens directly against
Google's public certificates for the configured project ID.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, PyJWKClientError

logger = logging.getLogger(__name__)

GOOGLE_JWKS_URL = (
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
)
DEFAULT_FIREBASE_PROJECT_ID = "cerberus-a2be4"

# Synthetic `test-firebase-token:<email>:<uid>` tokens exist so the test suite can authenticate without
# Google. They are an authentication bypass by design (anyone who can type an email address becomes that
# user, and the API links by email, so it means taking over an existing account). They therefore work only
# when this variable is set, and only the test suite sets it. Never set it anywhere else.
TEST_TOKENS_ENV = "CERBERUS_ALLOW_TEST_TOKENS"


def test_tokens_enabled() -> bool:
    return os.environ.get(TEST_TOKENS_ENV) == "1"

_jwks_client: jwt.PyJWKClient | None = None
_test_token_verifier: Callable[[str], dict[str, Any] | None] | None = None


def get_firebase_project_id() -> str:
    return os.environ.get("FIREBASE_PROJECT_ID") or DEFAULT_FIREBASE_PROJECT_ID


def _get_jwks_client() -> jwt.PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = jwt.PyJWKClient(GOOGLE_JWKS_URL, cache_keys=True, lifespan=3600)
    return _jwks_client


class FirebaseAuthError(Exception):
    """Raised when a Firebase ID token cannot be authenticated."""


class FirebaseTokenExpiredError(FirebaseAuthError):
    """Raised when a Firebase ID token has expired."""


def set_test_token_verifier(verifier: Callable[[str], dict[str, Any] | None] | None) -> None:
    """Inject a test token verifier for offline unit testing."""
    global _test_token_verifier
    _test_token_verifier = verifier


def verify_firebase_id_token(token: str) -> dict[str, Any]:
    """Verify a Firebase ID token and return its payload.

    Validates signature, algorithm (RS256), audience (projectId),
    issuer (https://securetoken.google.com/<projectId>), and expiration.
    """
    if not token or not token.strip():
        raise FirebaseAuthError("Empty authentication token.")

    token = token.strip()

    # Allow injected test verifier for offline unit tests
    if _test_token_verifier is not None:
        mocked = _test_token_verifier(token)
        if mocked is not None:
            return mocked

    # Synthetic test tokens: honoured ONLY when explicitly enabled (see TEST_TOKENS_ENV). Without this
    # gate the prefix alone authenticated anyone as any email address.
    if token.startswith("test-firebase-token:") and test_tokens_enabled():
        parts = token.split(":")
        email = parts[1] if len(parts) > 1 else "test@example.com"
        uid = parts[2] if len(parts) > 2 else f"uid-{email}"
        return {
            "sub": uid,
            "uid": uid,
            "email": email,
            "name": email.split("@")[0],
            "email_verified": True,
        }

    project_id = get_firebase_project_id()
    expected_issuer = f"https://securetoken.google.com/{project_id}"

    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256":
            raise FirebaseAuthError("Not a Firebase token (algorithm is not RS256).")
    except Exception as exc:
        raise FirebaseAuthError(f"Malformed token header: {exc}") from exc

    try:
        signing_key = _get_jwks_client().get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=project_id,
            issuer=expected_issuer,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
        return payload
    except ExpiredSignatureError as exc:
        raise FirebaseTokenExpiredError("Authentication token has expired.") from exc
    except (InvalidTokenError, PyJWKClientError) as exc:
        logger.warning("Invalid Firebase token: %s", exc)
        raise FirebaseAuthError("Invalid authentication token.") from exc
    except Exception as exc:
        logger.error("Error verifying Firebase token: %s", exc)
        raise FirebaseAuthError("Could not verify authentication token.") from exc
