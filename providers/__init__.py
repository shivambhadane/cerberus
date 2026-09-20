"""Deployment providers: how Cerberus asks Vercel, Netlify and Cloudflare Pages what an account controls.

Adding a provider = one module that subclasses `DeploymentProvider`, a branch for it in `get_provider`,
its name in `PROVIDER_NAMES` (here and in core.models), and its platform suffix in
`providers.base.PLATFORM_SUFFIXES`. See docs/API.md, "How to add a provider".
"""

from __future__ import annotations

from core.config import Config, load_config
from providers.base import (
    PLATFORM_SUFFIXES,
    DeploymentProvider,
    HttpResult,
    ProviderAccount,
    ProviderError,
    ProviderHttp,
    ProviderProject,
    ProviderTokens,
    platform_for_hostname,
)
from providers.cloudflare import CloudflareProvider
from providers.netlify import NetlifyProvider
from providers.vercel import VercelProvider

PROVIDER_NAMES = ("vercel", "netlify", "cloudflare")

# Tests substitute the HTTP layer so nothing here ever touches a real provider.
_http_override: ProviderHttp | None = None


def use_http(http: ProviderHttp | None) -> None:
    global _http_override
    _http_override = http


def get_provider(name: str, config: Config | None = None) -> DeploymentProvider:
    """The configured provider called `name`. Raises ProviderError('unknown_provider') otherwise."""
    config = config or load_config()
    http = _http_override
    if name not in PROVIDER_NAMES:
        raise ProviderError("unknown_provider", "That provider is not supported.")
    client_id, client_secret = config.provider_credentials(name)
    if name == "vercel":
        return VercelProvider(client_id, client_secret, config.vercel_integration_slug, http)
    if name == "netlify":
        return NetlifyProvider(client_id, client_secret, http)
    return CloudflareProvider(client_id, client_secret, config.cloudflare_oauth_scopes, http)


__all__ = [
    "PLATFORM_SUFFIXES", "PROVIDER_NAMES", "DeploymentProvider", "HttpResult", "ProviderAccount",
    "ProviderError", "ProviderHttp", "ProviderProject", "ProviderTokens", "get_provider",
    "platform_for_hostname", "use_http",
]
