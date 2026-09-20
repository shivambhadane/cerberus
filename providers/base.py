"""The contract every deployment provider implements, and the guard rails they share.

Cerberus asks a platform (Vercel, Netlify, Cloudflare Pages) one question on the user's behalf:
"which projects does this account control, and what platform hostnames do they answer on?" A target is
then verified only if the hostname is one the platform itself reports for a project the user's own
token can see. Nothing the browser says about ownership is ever trusted.

Two rules are enforced here, once, so no provider can forget them:

  1. Only PLATFORM hostnames prove anything (`*.vercel.app`, `*.netlify.app`, `*.pages.dev`). A custom
     domain attached to a project does not: platforms let an account attach a domain it does not
     control (Netlify does not require DNS to be pointed first), so "it is listed on my project" would
     let anyone "verify" somebody else's domain. Custom domains keep using DNS TXT verification.
  2. Every identifier that came from the browser is validated before it is placed in a URL path.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote

import requests

from core.http import build_session

# The hostname suffix each platform hands out to projects, and only to the project's owner.
PLATFORM_SUFFIXES: dict[str, str] = {
    "vercel": "vercel.app",
    "netlify": "netlify.app",
    "cloudflare": "pages.dev",
}

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ProviderError(Exception):
    """A provider call failed. `code` is stable; `message` is safe to show a person (no secrets)."""

    def __init__(self, code: str, message: str = "", retryable: bool = False):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.retryable = retryable


@dataclass(frozen=True)
class ProviderTokens:
    access_token: str
    refresh_token: str | None = None
    expires_at: datetime | None = None
    scopes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)  # non-secret (a team id); never tokens


@dataclass(frozen=True)
class ProviderAccount:
    account_id: str  # the account's id AT THE PROVIDER
    label: str
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderProject:
    id: str
    name: str
    hostnames: tuple[str, ...]  # platform hostnames only (see the module docstring)
    scope_id: str | None = None  # the team / account the project sits under


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: Any
    text: str


class ProviderHttp:
    """HTTP for provider APIs: HTTPS only, no redirects, bounded time and size, errors as ProviderError."""

    def __init__(
        self, session: requests.Session | None = None, timeout: float = 10.0, max_bytes: int = 2_000_000
    ):
        self.session = session or build_session(
            total_retries=2, backoff_factor=0.5, user_agent="cerberus-asm"
        )
        self.timeout = timeout
        self.max_bytes = max_bytes

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> HttpResult:
        if not url.startswith("https://"):
            raise ProviderError("bad_request", "Provider requests must use HTTPS.")
        try:
            response = self.session.request(
                method, url, headers=headers, data=data, params=params,
                timeout=self.timeout, allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise ProviderError("unavailable", "The provider could not be reached.", retryable=True) from exc
        content = getattr(response, "content", b"") or b""
        if len(content) > self.max_bytes:
            raise ProviderError("bad_response", "The provider sent an unexpectedly large response.")
        try:
            body = response.json()
        except ValueError:
            body = None
        return HttpResult(response.status_code, body, getattr(response, "text", "") or "")


def raise_for_status(result: HttpResult, what: str) -> None:
    """Turn a non-2xx provider answer into a ProviderError. A provider's 401/403 means *its* token was
    rejected, which is not the same as the Cerberus user being signed out (callers map it accordingly)."""
    if 200 <= result.status < 300:
        return
    if result.status == 401:
        raise ProviderError("unauthorized", f"The provider rejected the connection while {what}.")
    if result.status == 403:
        raise ProviderError("forbidden", f"The provider refused access while {what}.")
    if result.status == 404:
        raise ProviderError("not_found", f"The provider has no such resource ({what}).")
    if result.status == 429 or result.status >= 500:
        raise ProviderError("unavailable", f"The provider is unavailable ({what}).", retryable=True)
    raise ProviderError("bad_request", f"The provider rejected the request ({what}).")


def safe_id(value: str, what: str = "identifier") -> str:
    """A provider identifier that is safe to put in a URL path.

    Project and site ids arrive from the browser and are interpolated into `/projects/{id}`. Without
    this, `../../user` or `x?teamId=other` would steer the call at a different endpoint.
    """
    if not isinstance(value, str) or not _SAFE_ID.match(value) or ".." in value:
        raise ProviderError("invalid_identifier", f"That {what} is not valid.")
    return quote(value, safe="")


def is_platform_hostname(provider: str, hostname: str) -> bool:
    """True for exactly `<one-label>.<platform suffix>`: `my-app.vercel.app`, never `vercel.app` itself
    (which would put every customer on the platform in scope) and never a deeper or foreign name."""
    suffix = PLATFORM_SUFFIXES.get(provider)
    host = (hostname or "").strip().lower().rstrip(".")
    if not suffix or not host.endswith("." + suffix):
        return False
    label = host[: -(len(suffix) + 1)]
    return "." not in label and bool(_HOST_LABEL.match(label))


def platform_for_hostname(hostname: str) -> str | None:
    """The provider whose platform suffix `hostname` is under (or is), else None. Used to send people who
    type `my-app.vercel.app` into the DNS form to the right flow: nobody can publish a TXT record there."""
    host = (hostname or "").strip().lower().rstrip(".")
    for provider, suffix in PLATFORM_SUFFIXES.items():
        if host == suffix or host.endswith("." + suffix):
            return provider
    return None


def platform_hostnames(provider: str, candidates: list[str | None]) -> tuple[str, ...]:
    """The candidates that are platform hostnames, normalised, de-duplicated, in a stable order."""
    seen: dict[str, None] = {}
    for candidate in candidates:
        if not candidate:
            continue
        host = candidate.strip().lower().rstrip(".")
        if is_platform_hostname(provider, host):
            seen.setdefault(host, None)
    return tuple(sorted(seen))


class DeploymentProvider(ABC):
    """One platform. Implementations only talk to the platform; storing tokens and deciding who may
    scan what is done elsewhere (core/provider_service.py, core/ownership.py)."""

    name: str
    label: str
    uses_pkce: bool = False

    def __init__(self, client_id: str, client_secret: str, http: ProviderHttp | None = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.http = http or ProviderHttp()

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    @abstractmethod
    def build_authorization_url(self, state: str, redirect_uri: str, code_challenge: str | None) -> str: ...

    @abstractmethod
    def exchange_code(self, code: str, redirect_uri: str, code_verifier: str | None) -> ProviderTokens: ...

    def refresh(self, refresh_token: str) -> ProviderTokens:
        raise ProviderError("unsupported", f"{self.label} tokens cannot be refreshed.")

    @abstractmethod
    def get_account(self, tokens: ProviderTokens) -> ProviderAccount: ...

    @abstractmethod
    def list_projects(self, tokens: ProviderTokens) -> list[ProviderProject]: ...

    @abstractmethod
    def get_project(self, tokens: ProviderTokens, project_id: str) -> ProviderProject: ...

    def requested_scopes(self) -> list[str]:
        return []

    def verify_target(self, tokens: ProviderTokens, project_id: str, hostname: str) -> ProviderProject:
        """Prove that `hostname` is a platform hostname of `project_id`, as the provider reports it.

        The project is fetched *with the connection's own token*, so the provider itself decides
        whether this account can see it: a project belonging to someone else is a 404/403 there, not
        something we have to guess at. The hostname must then be one the provider lists for that
        project, exactly. Nothing from the browser is believed.
        """
        host = (hostname or "").strip().lower().rstrip(".")
        if not is_platform_hostname(self.name, host):
            raise ProviderError(
                "not_a_platform_hostname",
                f"Only {PLATFORM_SUFFIXES[self.name]} addresses can be verified this way. "
                "Verify a custom domain with a DNS TXT record instead.",
            )
        project = self.get_project(tokens, project_id)
        if host not in project.hostnames:
            raise ProviderError("hostname_not_in_project", "That address does not belong to this project.")
        return project
