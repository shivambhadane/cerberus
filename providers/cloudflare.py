"""Cloudflare Pages, through Cloudflare's self-managed OAuth (launched June 2026).

From developers.cloudflare.com/fundamentals/oauth/ (create-an-oauth-client, integrate-with-cloudflare) and
https://dash.cloudflare.com/.well-known/openid-configuration:
  * Authorization endpoint  https://dash.cloudflare.com/oauth2/auth
  * Token endpoint          https://dash.cloudflare.com/oauth2/token
  * Grant: authorization code (the only third-party flow); PKCE S256 supported and required for public
    clients. Cerberus is a confidential client (client_secret_post) and uses PKCE as well.
  * Refresh tokens via the `offline_access` scope; identity via `openid` + /oauth2/userinfo (claim `sub`).
  * Scopes are chosen when the OAuth client is created and repeated in the authorisation request.
  * API: GET /client/v4/accounts, GET /client/v4/accounts/{id}/pages/projects[/{name}], whose project
    objects carry `subdomain` (the *.pages.dev hostname) and `domains` (custom domains).

The identifier of the read-only Pages scope is not published in the public docs (the full list is served
by an authenticated endpoint, GET /client/v4/oauth/scopes; the docs' examples use names like
`workers-platform.read`). Rather than guess, the scopes are supplied by the operator in
CLOUDFLARE_OAUTH_SCOPES, and the provider reports itself as not configured until they are. For the
record, the one this adapter needs turned out to be `pages.metadata_read` (see docs/DEPLOYMENT.md 7.5);
it is still not hardcoded here, because the operator's OAuth client must have been created with it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from providers.base import (
    DeploymentProvider,
    ProviderAccount,
    ProviderError,
    ProviderHttp,
    ProviderProject,
    ProviderTokens,
    platform_hostnames,
    raise_for_status,
    safe_id,
)

AUTH_URL = "https://dash.cloudflare.com/oauth2/auth"
TOKEN_URL = "https://dash.cloudflare.com/oauth2/token"
USERINFO_URL = "https://dash.cloudflare.com/oauth2/userinfo"
API = "https://api.cloudflare.com/client/v4"
MAX_ACCOUNTS = 20
PAGE_SIZE = 10


class CloudflareProvider(DeploymentProvider):
    name = "cloudflare"
    label = "Cloudflare Pages"
    uses_pkce = True

    def __init__(
        self, client_id: str, client_secret: str, scopes: list[str], http: ProviderHttp | None = None
    ):
        super().__init__(client_id, client_secret, http)
        self.scopes = scopes

    def is_configured(self) -> bool:
        return bool(super().is_configured() and self.scopes)

    def requested_scopes(self) -> list[str]:
        # `offline_access` for a refresh token. Cloudflare OAuth does not use `openid`.
        return list(dict.fromkeys([*self.scopes, "offline_access"]))

    def build_authorization_url(self, state: str, redirect_uri: str, code_challenge: str | None) -> str:
        if not code_challenge:
            raise ProviderError("bad_request", "Cloudflare requires PKCE.")
        query = urlencode({
            "response_type": "code", "client_id": self.client_id, "redirect_uri": redirect_uri,
            "scope": " ".join(self.requested_scopes()), "state": state,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
        })
        return f"{AUTH_URL}?{query}"

    def _token_request(self, data: dict[str, str], what: str) -> ProviderTokens:
        result = self.http.request(
            "POST", TOKEN_URL, data={**data, "client_id": self.client_id, "client_secret": self.client_secret}
        )
        if result.status in (400, 401, 403):
            raise ProviderError("invalid_grant", "Cloudflare did not accept the authorisation.")
        raise_for_status(result, what)
        body = result.body if isinstance(result.body, dict) else {}
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise ProviderError("bad_response", "Cloudflare did not return an access token.")
        expires_in = body.get("expires_in")
        expires_at = (
            datetime.now(UTC) + timedelta(seconds=int(expires_in))
            if isinstance(expires_in, (int, float)) and expires_in > 0 else None
        )
        refresh = body.get("refresh_token")
        return ProviderTokens(
            access_token=token, refresh_token=refresh if isinstance(refresh, str) and refresh else None,
            expires_at=expires_at, scopes=str(body.get("scope") or " ".join(self.requested_scopes())),
        )

    def exchange_code(self, code: str, redirect_uri: str, code_verifier: str | None) -> ProviderTokens:
        return self._token_request(
            {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
             "code_verifier": code_verifier or ""},
            "exchanging the authorisation code",
        )

    def refresh(self, refresh_token: str) -> ProviderTokens:
        fresh = self._token_request(
            {"grant_type": "refresh_token", "refresh_token": refresh_token}, "refreshing"
        )
        # Some servers rotate the refresh token, some do not: keep the old one if no new one came.
        return fresh if fresh.refresh_token else ProviderTokens(
            fresh.access_token, refresh_token, fresh.expires_at, fresh.scopes, fresh.extra
        )

    # -- reading ----------------------------------------------------------------------------------

    def _get(self, tokens: ProviderTokens, url: str, what: str, params: dict | None = None):
        result = self.http.request("GET", url, params=params,
                                   headers={"Authorization": f"Bearer {tokens.access_token}"})
        raise_for_status(result, what)
        return result.body

    def _result(self, tokens: ProviderTokens, path: str, what: str, params: dict | None = None):
        body = self._get(tokens, f"{API}{path}", what, params)
        if not isinstance(body, dict) or body.get("success") is not True:
            raise ProviderError("bad_response", f"Cloudflare reported a failure while {what}.")
        return body.get("result")

    def _accounts(self, tokens: ProviderTokens) -> list[dict]:
        result = self._result(tokens, "/accounts", "listing accounts", {"per_page": MAX_ACCOUNTS})
        accounts = [a for a in (result or []) if isinstance(a, dict) and isinstance(a.get("id"), str)]
        return accounts[:MAX_ACCOUNTS]

    def get_account(self, tokens: ProviderTokens) -> ProviderAccount:
        subject = None
        try:
            info = self._get(tokens, USERINFO_URL, "reading the account")
            subject = info.get("sub") if isinstance(info, dict) else None
        except Exception:
            subject = None

        accounts = self._accounts(tokens)
        if not subject:
            if not accounts or not accounts[0].get("id"):
                raise ProviderError("bad_response", "Cloudflare did not identify the account.")
            subject = str(accounts[0]["id"])

        names = [str(a.get("name")) for a in accounts if a.get("name")]
        return ProviderAccount(account_id=subject, label=", ".join(names)[:255] or "Cloudflare account")

    @staticmethod
    def _project(account_id: str, item: dict) -> ProviderProject:
        name = str(item.get("name") or "")
        return ProviderProject(
            id=f"{account_id}:{name}", name=name,
            # The `domains` field lists custom domains: not offered (see providers/base.py).
            hostnames=platform_hostnames("cloudflare", [item.get("subdomain")]), scope_id=account_id,
        )

    def list_projects(self, tokens: ProviderTokens) -> list[ProviderProject]:
        projects: list[ProviderProject] = []
        for account in self._accounts(tokens):
            account_id = safe_id(account["id"], "account id")
            result = self._result(tokens, f"/accounts/{account_id}/pages/projects", "listing Pages projects",
                                  {"per_page": PAGE_SIZE})
            for item in result or []:
                if isinstance(item, dict) and item.get("name"):
                    projects.append(self._project(account["id"], item))
        return projects

    def get_project(self, tokens: ProviderTokens, project_id: str) -> ProviderProject:
        account_id, sep, name = (project_id or "").partition(":")
        if not sep:
            raise ProviderError("invalid_identifier", "That project id is not valid.")
        account, project = safe_id(account_id, "account id"), safe_id(name, "project name")
        item = self._result(
            tokens, f"/accounts/{account}/pages/projects/{project}", "reading the Pages project"
        )
        if not isinstance(item, dict) or not item.get("name"):
            raise ProviderError("not_found", "Cloudflare has no such Pages project.")
        return self._project(account_id, item)
