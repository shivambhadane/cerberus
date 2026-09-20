from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = ROOT / "config.yaml"


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


@dataclass
class DiscoveryConfig:
    subdomain_enum: bool = True
    port_scan: bool = True
    scan_interval_hours: int = 24
    ports: list[int] = field(default_factory=list)
    max_concurrency: int = 50
    connect_timeout: float = 2.0
    # Scope controls. Hosts and ports listed here are never probed, even when the
    # target domain would otherwise permit them.
    excluded_hosts: list[str] = field(default_factory=list)
    excluded_ports: list[int] = field(default_factory=list)
    # Permit scanning loopback/private addresses (the Docker lab, a home network).
    # Deliberately operator-level config or a CLI flag and NEVER a request parameter: an
    # API caller who could set this could point the server at its own internal network.
    allow_private_addresses: bool = False


@dataclass
class EnrichmentConfig:
    refresh_interval_hours: int = 24
    sources: list[str] = field(default_factory=lambda: ["nvd", "kev", "epss", "osv"])


@dataclass
class ScanningConfig:
    """Which scan profile a scan uses unless one is requested explicitly."""

    profile: str = "safe"


@dataclass
class ScoringConfig:
    weights: dict[str, float] = field(default_factory=dict)


@dataclass
class Config:
    discovery: DiscoveryConfig
    enrichment: EnrichmentConfig
    scanning: ScanningConfig
    scoring: ScoringConfig
    integrations: dict

    @property
    def database_url(self) -> str:
        return os.environ.get("DATABASE_URL") or f"sqlite:///{ROOT / 'cerberus.db'}"

    @property
    def nvd_api_key(self) -> str | None:
        return os.environ.get("NVD_API_KEY") or None

    @property
    def api_secret_key(self) -> str:
        return os.environ.get("API_SECRET_KEY", "change-me")

    @property
    def access_token_minutes(self) -> int:
        """How long an access token lives. Short, because it cannot be revoked; the refresh
        token (which can) mints the next one."""
        return int(os.environ.get("ACCESS_TOKEN_MINUTES", "15"))

    @property
    def refresh_token_days(self) -> int:
        return int(os.environ.get("REFRESH_TOKEN_DAYS", "14"))

    @property
    def cookie_secure(self) -> bool:
        """Send the refresh cookie over HTTPS only. Off by default so http://localhost works;
        set COOKIE_SECURE=1 in any real deployment (docs/DEPLOYMENT.md)."""
        return os.environ.get("COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}

    # --- deployment providers (Vercel, Netlify, Cloudflare Pages) --------------------------------

    @property
    def provider_token_keys(self) -> list[str]:
        """Fernet keys that encrypt provider tokens at rest. The first encrypts; all decrypt, so a key
        can be rotated by prepending a new one. Empty means provider connections are disabled."""
        raw = os.environ.get("PROVIDER_TOKEN_ENCRYPTION_KEY", "")
        return [key.strip() for key in raw.split(",") if key.strip()]

    @property
    def public_api_url(self) -> str:
        """The API's public base URL. OAuth redirect URIs are built from it and must match, exactly,
        what is registered with each provider."""
        return os.environ.get("PUBLIC_API_URL", "http://localhost:8000").rstrip("/")

    @property
    def frontend_url(self) -> str:
        """Where the browser is sent after an OAuth callback."""
        return os.environ.get("FRONTEND_URL", "http://localhost:5173").rstrip("/")

    def provider_credentials(self, provider: str) -> tuple[str, str]:
        """(client id, client secret) for a provider, from the environment. Never sent to the browser."""
        prefix = provider.upper()
        return os.environ.get(f"{prefix}_CLIENT_ID", ""), os.environ.get(f"{prefix}_CLIENT_SECRET", "")

    @property
    def vercel_integration_slug(self) -> str:
        return os.environ.get("VERCEL_INTEGRATION_SLUG", "")

    @property
    def cloudflare_oauth_scopes(self) -> list[str]:
        """The scopes the Cloudflare OAuth client was created with (its Pages read and account read
        scopes). Cloudflare does not publish the identifiers, so the operator supplies them."""
        return os.environ.get("CLOUDFLARE_OAUTH_SCOPES", "").split()

    @property
    def cors_origins(self) -> list[str]:
        raw = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
        return [origin.strip() for origin in raw.split(",") if origin.strip()]


def load_config(path: Path | None = None) -> Config:
    _load_dotenv(ROOT / ".env")
    raw = yaml.safe_load((path or DEFAULT_CONFIG_PATH).read_text()) or {}
    return Config(
        discovery=DiscoveryConfig(**(raw.get("discovery") or {})),
        enrichment=EnrichmentConfig(**(raw.get("enrichment") or {})),
        scanning=ScanningConfig(**(raw.get("scanning") or {})),
        scoring=ScoringConfig(**(raw.get("scoring") or {})),
        integrations=raw.get("integrations") or {},
    )
