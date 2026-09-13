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
    def cors_origins(self) -> list[str]:
        raw = os.environ.get("CORS_ORIGINS", "http://localhost:5173")
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
