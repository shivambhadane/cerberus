"""What we keep from an identity provider's profile, and how much we trust it.

Name, picture and sign-in method come from the provider's *verified* ID token (Firebase, which
fronts Google and GitHub), so they are the provider's claims about the person, not something the
browser told us. They are still untrusted text: a picture URL ends up in an `<img src>`, so only a
plain https URL is accepted, and a name is trimmed and bounded.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

MAX_PICTURE_URL_LENGTH = 2048
MAX_NAME_LENGTH = 255
_KNOWN_PROVIDERS = frozenset({"google.com", "github.com", "password", "anonymous"})


def clean_picture_url(value: Any) -> str | None:
    """An https URL, or None. Anything else (javascript:, data:, http:, garbage) is dropped."""
    if not isinstance(value, str):
        return None
    url = value.strip()
    if not url or len(url) > MAX_PICTURE_URL_LENGTH or any(ch in url for ch in " \t\r\n\x00\\"):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        return None
    return url


def clean_display_name(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:MAX_NAME_LENGTH]


def sign_in_provider(payload: dict[str, Any]) -> str | None:
    """`firebase.sign_in_provider` from a verified Firebase token, if it is one we recognise."""
    firebase = payload.get("firebase")
    provider = firebase.get("sign_in_provider") if isinstance(firebase, dict) else None
    return provider if provider in _KNOWN_PROVIDERS else None
