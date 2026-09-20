"""Netlify, through OAuth2.

What Netlify documents, and what this relies on (verified 2026-09):
  * Authorize:  https://app.netlify.com/authorize     (docs.netlify.com/api-and-cli-guides/api-guides)
  * OAuth apps are registered at https://app.netlify.com/applications  (client id + secret).
  * API base:   https://api.netlify.com/api/v1/       (GET /user, GET /sites, GET /sites/{id})
  * The access token is sent as `Authorization: Bearer`.

LIMITATIONS, stated plainly because they affect a security decision:
  * Netlify's current reference documents the *implicit* grant (`response_type=token`), which puts the
    token in the browser. Cerberus must keep provider tokens off the browser, so it uses the
    *authorization code* grant. Netlify's own OAuth2 post describes that grant ("the final access token
    ends up stored server-side"), and the token endpoint https://api.netlify.com/oauth/token is used by
    third parties in Netlify's support forum, but the endpoint is NOT in the current API reference, and
    forum reports show `invalid_grant` failures without a public resolution. It has not been exercised
    against a live Netlify account here; the first real connection is the test of it.
  * Netlify OAuth has no scopes. A token can do anything the user can do. Cerberus only ever reads
    (`GET /user`, `GET /sites`), stores the token encrypted, and forgets it on disconnect, but the user
    should also revoke the app at https://app.netlify.com/user/applications when they are done.
  * Tokens have no refresh token; when one stops working the user reconnects.
"""

from __future__ import annotations

from urllib.parse import urlencode, urlsplit

from providers.base import (
    DeploymentProvider,
    ProviderAccount,
    ProviderError,
    ProviderProject,
    ProviderTokens,
    platform_hostnames,
    raise_for_status,
    safe_id,
)

AUTHORIZE_URL = "https://app.netlify.com/authorize"
TOKEN_URL = "https://api.netlify.com/oauth/token"
API = "https://api.netlify.com/api/v1"
PAGE_SIZE = 100
MAX_SITES = 200


def _host(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    return urlsplit(url).hostname


class NetlifyProvider(DeploymentProvider):
    name = "netlify"
    label = "Netlify"

    def build_authorization_url(self, state: str, redirect_uri: str, code_challenge: str | None) -> str:
        query = urlencode({
            "client_id": self.client_id, "response_type": "code",
            "redirect_uri": redirect_uri, "state": state,
        })
        return f"{AUTHORIZE_URL}?{query}"

    def exchange_code(self, code: str, redirect_uri: str, code_verifier: str | None) -> ProviderTokens:
        result = self.http.request(
            "POST", TOKEN_URL,
            data={"grant_type": "authorization_code", "code": code, "client_id": self.client_id,
                  "client_secret": self.client_secret, "redirect_uri": redirect_uri},
        )
        if result.status in (400, 401, 403):
            raise ProviderError("invalid_grant", "Netlify did not accept the authorisation code.")
        raise_for_status(result, "exchanging the authorisation code")
        body = result.body if isinstance(result.body, dict) else {}
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise ProviderError("bad_response", "Netlify did not return an access token.")
        return ProviderTokens(access_token=token, scopes="full-access")

    def _get(self, tokens: ProviderTokens, path: str, what: str, params: dict | None = None):
        result = self.http.request(
            "GET", f"{API}{path}", params=params,
            headers={"Authorization": f"Bearer {tokens.access_token}"},
        )
        raise_for_status(result, what)
        return result.body

    def get_account(self, tokens: ProviderTokens) -> ProviderAccount:
        body = self._get(tokens, "/user", "reading the account")
        user = body if isinstance(body, dict) else {}
        account_id = user.get("id")
        if not isinstance(account_id, str) or not account_id:
            raise ProviderError("bad_response", "Netlify did not identify the account.")
        label = str(user.get("full_name") or user.get("email") or account_id)
        return ProviderAccount(account_id=account_id, label=label)

    @staticmethod
    def _project(site: dict) -> ProviderProject:
        name = str(site.get("name") or "")
        candidates = [
            f"{name}.netlify.app" if name else None, _host(site.get("url")), _host(site.get("ssl_url")),
        ]
        return ProviderProject(
            id=str(site["id"]), name=name or str(site["id"]),
            # Custom domains and domain aliases are deliberately not offered: see providers/base.py.
            hostnames=platform_hostnames("netlify", candidates),
            scope_id=site.get("account_slug") if isinstance(site.get("account_slug"), str) else None,
        )

    def list_projects(self, tokens: ProviderTokens) -> list[ProviderProject]:
        projects: list[ProviderProject] = []
        for page in range(1, MAX_SITES // PAGE_SIZE + 1):
            body = self._get(tokens, "/sites", "listing sites",
                             params={"filter": "all", "per_page": PAGE_SIZE, "page": page})
            sites = [s for s in body if isinstance(s, dict) and s.get("id")] if isinstance(body, list) else []
            projects.extend(self._project(site) for site in sites)
            if len(sites) < PAGE_SIZE:
                break
        return projects

    def get_project(self, tokens: ProviderTokens, project_id: str) -> ProviderProject:
        site_id = safe_id(project_id, "site id")
        body = self._get(tokens, f"/sites/{site_id}", "reading the site")
        if not isinstance(body, dict) or not body.get("id"):
            raise ProviderError("not_found", "Netlify has no such site.")
        return self._project(body)
