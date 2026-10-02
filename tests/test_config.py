"""Config reading, and one sharp edge in particular.

`_load_dotenv` uses `os.environ.setdefault`, so a line like `PUBLIC_API_URL=` in `.env` puts an
EMPTY value into the environment rather than leaving the key absent. A default passed to
`os.environ.get(key, default)` only applies when the key is missing entirely, so a blank line in
`.env` used to silently win over the documented default: `public_api_url` became `""` and every
OAuth redirect URI built from it became a relative path like
`/api/v1/providers/cloudflare/callback`, which providers reject as a redirect mismatch. The error
surfaces at the provider, pointing nowhere near the real cause, so these are pinned here.
"""

import pytest

from core.config import load_config

BLANKABLE = [
    ("PUBLIC_API_URL", "public_api_url", "http://localhost:8000"),
    ("FRONTEND_URL", "frontend_url", "http://localhost:5173"),
    ("API_SECRET_KEY", "api_secret_key", "change-me"),
    ("ACCESS_TOKEN_MINUTES", "access_token_minutes", 15),
    ("REFRESH_TOKEN_DAYS", "refresh_token_days", 14),
]


@pytest.mark.parametrize("env_key, attribute, expected", BLANKABLE)
def test_a_blank_env_value_falls_back_to_the_default(monkeypatch, env_key, attribute, expected):
    monkeypatch.setenv(env_key, "")
    assert getattr(load_config(), attribute) == expected


@pytest.mark.parametrize("env_key, attribute, expected", BLANKABLE)
def test_a_real_env_value_still_wins(monkeypatch, env_key, attribute, expected):
    """The fallback must not swallow a value someone actually set."""
    value = "7" if isinstance(expected, int) else "http://example.test"
    monkeypatch.setenv(env_key, value)
    assert getattr(load_config(), attribute) == (7 if isinstance(expected, int) else value)


def test_a_blank_cors_origins_falls_back_rather_than_blocking_the_dashboard(monkeypatch):
    """Empty would otherwise mean no allowed origin at all, which blocks the dashboard."""
    monkeypatch.setenv("CORS_ORIGINS", "")
    assert load_config().cors_origins == ["http://localhost:5173", "http://127.0.0.1:5173"]


def test_a_trailing_slash_is_stripped_so_redirect_uris_do_not_double_up(monkeypatch):
    monkeypatch.setenv("PUBLIC_API_URL", "https://cerberus.example/")
    assert load_config().public_api_url == "https://cerberus.example"


def test_a_blank_provider_credential_is_still_blank_not_a_default(monkeypatch):
    """The opposite case: a missing provider secret must stay missing, so the provider reports
    itself unconfigured instead of attempting a flow with an empty client id."""
    monkeypatch.setenv("CLOUDFLARE_CLIENT_ID", "")
    monkeypatch.setenv("CLOUDFLARE_CLIENT_SECRET", "")
    assert load_config().provider_credentials("cloudflare") == ("", "")
