"""Vercel, through an OAuth *Integration*.

Why an Integration and not "Sign in with Vercel": Vercel's newer Sign in with Vercel only carries identity
scopes, and its permissions for making REST API requests are documented as "currently in private beta"
(vercel.com/docs/sign-in-with-vercel/scopes-and-permissions). An Integration is the documented way today
for a third-party app to read a user's projects with their consent.

Flow (vercel.com/docs/integrations/create-integration/vercel-api-integrations and .../submit-integration):
  1. Send the user to  https://vercel.com/integrations/<slug>/new?state=<state>
  2. Vercel redirects to the Redirect URL registered on the integration with `code` (valid 30 min, one
     use) and our `state` returned unchanged. There is no PKCE.
  3. POST https://api.vercel.com/v2/oauth/access_token  ->  { access_token, user_id, team_id, ... }.
     The token is long-lived and has no refresh token.
  4. Read with  GET /v2/user, GET /v9/projects, GET /v9/projects/{id}/domains  (add `teamId` when the
     integration was installed on a team).

Scopes are not requested in the URL; they are set on the integration in the Vercel console. Cerberus needs
read access to: user, team, project (and nothing else).
"""

from __future__ import annotations

from urllib.parse import quote, urlencode

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

API = "https://api.vercel.com"
TOKEN_URL = f"{API}/v2/oauth/access_token"
INSTALL_URL = "https://vercel.com/integrations/{slug}/new"
MAX_PROJECTS = 50  # domains are one call per project, so a listing is bounded


class VercelProvider(DeploymentProvider):
    name = "vercel"
    label = "Vercel"

    def __init__(self, client_id: str, client_secret: str, slug: str, http: ProviderHttp | None = None):
        super().__init__(client_id, client_secret, http)
        self.slug = slug

    def is_configured(self) -> bool:
        return bool(super().is_configured() and self.slug)

    def build_authorization_url(self, state: str, redirect_uri: str, code_challenge: str | None) -> str:
        # The redirect URI is registered on the integration, not passed here.
        return f"{INSTALL_URL.format(slug=quote(self.slug, safe=''))}?{urlencode({'state': state})}"

    def exchange_code(self, code: str, redirect_uri: str, code_verifier: str | None) -> ProviderTokens:
        result = self.http.request(
            "POST", TOKEN_URL,
            data={"client_id": self.client_id, "client_secret": self.client_secret,
                  "code": code, "redirect_uri": redirect_uri},
        )
        if result.status in (400, 401, 403):
            raise ProviderError("invalid_grant", "Vercel did not accept the authorisation code.")
        raise_for_status(result, "exchanging the authorisation code")
        body = result.body if isinstance(result.body, dict) else {}
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise ProviderError("bad_response", "Vercel did not return an access token.")
        return ProviderTokens(
            access_token=token,
            scopes="project user team",
            extra={
                "team_id": body.get("team_id") or None,
                "user_id": body.get("user_id") or None,
                "installation_id": body.get("installation_id") or None,
            },
        )

    # -- reading ----------------------------------------------------------------------------------

    @staticmethod
    def _headers(tokens: ProviderTokens) -> dict[str, str]:
        return {"Authorization": f"Bearer {tokens.access_token}"}

    @staticmethod
    def _team(tokens: ProviderTokens) -> str | None:
        team = tokens.extra.get("team_id")
        return team if isinstance(team, str) and team else None

    def _get(self, tokens: ProviderTokens, path: str, what: str, params: dict | None = None):
        query = dict(params or {})
        if self._team(tokens):
            query["teamId"] = self._team(tokens)
        result = self.http.request("GET", f"{API}{path}", headers=self._headers(tokens), params=query)
        raise_for_status(result, what)
        return result.body if isinstance(result.body, dict) else {}

    def get_account(self, tokens: ProviderTokens) -> ProviderAccount:
        user = self._get(tokens, "/v2/user", "reading the account").get("user")
        user = user if isinstance(user, dict) else {}
        team = self._team(tokens)
        if team:
            label = team
            try:
                team_body = self._get(tokens, f"/v2/teams/{safe_id(team, 'team id')}", "reading the team")
                label = str(team_body.get("name") or team_body.get("slug") or team)
            except ProviderError:
                pass  # the label is cosmetic; identity is the team id
            return ProviderAccount(account_id=team, label=label, extra={"team_id": team})
        user_id = user.get("id") or tokens.extra.get("user_id")
        if not isinstance(user_id, str) or not user_id:
            raise ProviderError("bad_response", "Vercel did not identify the account.")
        label = str(user.get("username") or user.get("name") or user_id)
        return ProviderAccount(account_id=user_id, label=label)

    def _hostnames(self, tokens: ProviderTokens, project_id: str) -> tuple[str, ...]:
        body = self._get(tokens, f"/v9/projects/{project_id}/domains", "reading the project's domains",
                         params={"limit": 100})
        names = [
            d.get("name") for d in body.get("domains", [])
            if isinstance(d, dict) and d.get("verified") in (True, "true")
        ]
        return platform_hostnames("vercel", names)

    def list_projects(self, tokens: ProviderTokens) -> list[ProviderProject]:
        body = self._get(tokens, "/v9/projects", "listing projects", params={"limit": 100})
        projects: list[ProviderProject] = []
        for item in body.get("projects", [])[:MAX_PROJECTS]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            pid = safe_id(item["id"], "project id")
            projects.append(ProviderProject(
                id=item["id"], name=str(item.get("name") or item["id"]),
                hostnames=self._hostnames(tokens, pid), scope_id=self._team(tokens),
            ))
        return projects

    def get_project(self, tokens: ProviderTokens, project_id: str) -> ProviderProject:
        pid = safe_id(project_id, "project id")
        item = self._get(tokens, f"/v9/projects/{pid}", "reading the project")
        if not item.get("id"):
            raise ProviderError("not_found", "Vercel has no such project.")
        return ProviderProject(
            id=str(item["id"]), name=str(item.get("name") or project_id),
            hostnames=self._hostnames(tokens, pid), scope_id=self._team(tokens),
        )
