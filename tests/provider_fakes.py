"""A fake HTTP layer for provider tests, and payloads shaped like the providers' documented responses.

Nothing in the test suite talks to Vercel, Netlify or Cloudflare. `FakeHttp` replaces `ProviderHttp`, so
what is asserted is exactly what Cerberus would have sent (URL, form fields, headers) and how it reacts
to what a provider would have said.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from providers import HttpResult, ProviderHttp


@dataclass
class Call:
    method: str
    url: str
    headers: dict[str, str]
    data: dict[str, str] | None
    params: dict[str, Any] | None


Reply = tuple[int, Any]


class FakeHttp(ProviderHttp):
    def __init__(self) -> None:  # no real session
        self.calls: list[Call] = []
        self._routes: list[tuple[str, str, Callable[[Call], Reply] | Reply]] = []

    def route(self, method: str, url: str, reply: Callable[[Call], Reply] | Reply) -> None:
        """Answer `method url` (exact URL, query string excluded). Later routes win."""
        self._routes.insert(0, (method, url, reply))

    def request(self, method, url, *, headers=None, data=None, params=None) -> HttpResult:
        call = Call(method, url, dict(headers or {}), data, params)
        self.calls.append(call)
        for route_method, route_url, reply in self._routes:
            if route_method == method and route_url == url:
                status, body = reply(call) if callable(reply) else reply
                return HttpResult(status, body, str(body))
        return HttpResult(404, {"error": "not routed in this test"}, "not routed")

    def calls_to(self, url_part: str) -> list[Call]:
        return [c for c in self.calls if url_part in c.url]


# --- Vercel (shapes from vercel.com/docs/integrations/create-integration/vercel-api-integrations)

VERCEL_TOKEN = {
    "token_type": "Bearer",
    "access_token": "vercel-secret-token-AAA",
    "installation_id": "icfg_1",
    "user_id": "usr_alice",
    "team_id": None,
}
VERCEL_TEAM_TOKEN = {**VERCEL_TOKEN, "access_token": "vercel-team-token-BBB", "team_id": "team_erp"}


def vercel_routes(
    fake: FakeHttp, projects: dict[str, list[dict]] | None = None, *, team: bool = False
) -> None:
    """`projects` maps project id -> the domain objects Vercel would list for it."""
    projects = (
        projects
        if projects is not None
        else {
            "prj_erp": [
                {"name": "college-erp.vercel.app", "verified": True},
                {"name": "erp.college.edu", "verified": True},  # a custom domain: must never be offered
                {"name": "unverified.vercel.app", "verified": False},  # unverified: must never be offered
            ],
        }
    )
    fake.route(
        "POST",
        "https://api.vercel.com/v2/oauth/access_token",
        (200, VERCEL_TEAM_TOKEN if team else VERCEL_TOKEN),
    )
    fake.route(
        "GET", "https://api.vercel.com/v2/user", (200, {"user": {"id": "usr_alice", "username": "alice"}})
    )
    fake.route(
        "GET", "https://api.vercel.com/v2/teams/team_erp", (200, {"id": "team_erp", "name": "ERP Team"})
    )
    fake.route(
        "GET",
        "https://api.vercel.com/v9/projects",
        (
            200,
            {
                "projects": [{"id": pid, "name": pid.removeprefix("prj_")} for pid in projects],
                "pagination": {"count": len(projects), "next": None, "prev": None},
            },
        ),
    )
    for pid, domains in projects.items():
        fake.route(
            "GET",
            f"https://api.vercel.com/v9/projects/{pid}",
            (200, {"id": pid, "name": pid.removeprefix("prj_")}),
        )
        fake.route(
            "GET",
            f"https://api.vercel.com/v9/projects/{pid}/domains",
            (200, {"domains": domains, "pagination": {"count": len(domains), "next": None, "prev": None}}),
        )


# --- Netlify (shapes from open-api.netlify.com) ---------------------------------------------------

NETLIFY_TOKEN = {"access_token": "netlify-secret-token-CCC", "token_type": "Bearer"}


def netlify_routes(fake: FakeHttp, sites: list[dict] | None = None) -> None:
    sites = (
        sites
        if sites is not None
        else [
            {
                "id": "0e6d5c9a-1111-4222-8333-444455556666",
                "name": "campus-portal",
                "url": "http://campus-portal.netlify.app",
                "ssl_url": "https://campus-portal.netlify.app",
                "custom_domain": "portal.college.edu",
                "domain_aliases": ["www.college.edu"],
                "account_slug": "alice",
            }
        ]
    )
    fake.route("POST", "https://api.netlify.com/oauth/token", (200, NETLIFY_TOKEN))
    fake.route(
        "GET",
        "https://api.netlify.com/api/v1/user",
        (200, {"id": "nl_alice", "email": "alice@example.com", "full_name": "Alice"}),
    )
    fake.route("GET", "https://api.netlify.com/api/v1/sites", (200, sites))
    for site in sites:
        fake.route("GET", f"https://api.netlify.com/api/v1/sites/{site['id']}", (200, site))


# --- Cloudflare (shapes from developers.cloudflare.com/pages/configuration/api and /fundamentals/oa

CLOUDFLARE_TOKEN = {
    "access_token": "cf-secret-token-DDD",
    "refresh_token": "cf-refresh-token-EEE",
    "expires_in": 3600,
    "token_type": "bearer",
    "scope": "openid offline_access pages.read",
}
CF_ACCOUNT = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def cloudflare_routes(fake: FakeHttp, projects: list[dict] | None = None) -> None:
    projects = (
        projects
        if projects is not None
        else [
            {"name": "docs-site", "subdomain": "docs-site.pages.dev", "domains": ["docs.example.com"]},
        ]
    )
    fake.route("POST", "https://dash.cloudflare.com/oauth2/token", (200, CLOUDFLARE_TOKEN))
    fake.route("GET", "https://dash.cloudflare.com/oauth2/userinfo", (200, {"sub": "cf_alice"}))
    fake.route(
        "GET",
        "https://api.cloudflare.com/client/v4/accounts",
        (200, {"success": True, "result": [{"id": CF_ACCOUNT, "name": "Alice's Account"}]}),
    )
    fake.route(
        "GET",
        f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT}/pages/projects",
        (200, {"success": True, "result": projects}),
    )
    for project in projects:
        fake.route(
            "GET",
            f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT}/pages/projects/{project['name']}",
            (200, {"success": True, "result": project}),
        )
