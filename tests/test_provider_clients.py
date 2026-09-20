"""What Cerberus sends to Vercel, Netlify and Cloudflare, and how it reads what comes back.

Every request is asserted against the shape the provider's documentation gives, and every payload the
providers might return that could trick us into a false "verified" is tried.
"""

import pytest

import providers
from providers import ProviderError, ProviderTokens
from providers.base import (
    is_platform_hostname,
    platform_for_hostname,
    platform_hostnames,
    safe_id,
)
from providers.vercel import MAX_PROJECTS
from tests.provider_fakes import (
    CF_ACCOUNT,
    FakeHttp,
    cloudflare_routes,
    netlify_routes,
    vercel_routes,
)

TOKENS = ProviderTokens(access_token="tok-123")


# --- the hostname rules that keep "verified" honest -----------------------------------------------


@pytest.mark.parametrize(
    "provider,host",
    [
        ("vercel", "my-app.vercel.app"),
        ("netlify", "campus-portal.netlify.app"),
        ("cloudflare", "docs.pages.dev"),
        ("vercel", "MY-APP.vercel.app."),
    ],
)
def test_a_platform_hostname_is_recognised(provider, host):
    assert is_platform_hostname(provider, host)


@pytest.mark.parametrize(
    "provider,host",
    [
        ("vercel", "vercel.app"),  # the platform itself: every customer would be in scope
        ("vercel", "a.b.vercel.app"),  # deeper than one label
        ("vercel", "evil-vercel.app"),  # suffix confusion
        ("vercel", "my-app.vercel.app.evil.io"),
        ("vercel", "my-app.netlify.app"),  # another platform's suffix
        ("netlify", "example.com"),
        ("cloudflare", "pages.dev"),
        ("cloudflare", "-bad.pages.dev"),
        ("vercel", ""),
        ("vercel", "*.vercel.app"),
        ("nonsense", "a.vercel.app"),
    ],
)
def test_anything_else_is_not(provider, host):
    assert not is_platform_hostname(provider, host)


def test_hostnames_are_filtered_normalised_deduplicated_and_sorted():
    got = platform_hostnames(
        "vercel", ["B.vercel.app", "a.vercel.app", "a.vercel.app.", "erp.college.edu", None, ""]
    )
    assert got == ("a.vercel.app", "b.vercel.app")


def test_which_platform_owns_a_hostname_suffix():
    assert platform_for_hostname("x.vercel.app") == "vercel"
    assert platform_for_hostname("vercel.app") == "vercel"
    assert platform_for_hostname("x.pages.dev") == "cloudflare"
    assert platform_for_hostname("example.com") is None and platform_for_hostname("evil-vercel.app") is None


@pytest.mark.parametrize(
    "bad", ["../user", "x/../y", "a?teamId=other", "a b", "a#b", "", "-x", "x" * 200, "a/b", "%2e%2e"]
)
def test_an_identifier_that_could_steer_the_request_elsewhere_is_refused(bad):
    with pytest.raises(ProviderError) as error:
        safe_id(bad)
    assert error.value.code == "invalid_identifier"


def test_ordinary_ids_pass():
    assert safe_id("prj_abc123") == "prj_abc123" and safe_id("0e6d5c9a-1111-4222-8333-444455556666")


# --- Vercel ---------------------------------------------------------------------------------------


@pytest.fixture
def vercel(fake_http):
    vercel_routes(fake_http)
    return providers.get_provider("vercel")


def test_vercel_needs_client_id_secret_and_the_integration_slug(platform_env, monkeypatch):
    assert providers.get_provider("vercel").is_configured()
    monkeypatch.setenv("VERCEL_INTEGRATION_SLUG", "")
    assert not providers.get_provider("vercel").is_configured()


def test_vercel_sends_the_user_to_the_integration_install_url_with_state(vercel):
    url = vercel.build_authorization_url("STATE123", "https://api.cerberus.test/x", None)
    assert url == "https://vercel.com/integrations/cerberus-test/new?state=STATE123"


def test_vercel_code_exchange_uses_the_documented_endpoint_and_form(vercel, fake_http):
    tokens = vercel.exchange_code("the-code", "https://api.cerberus.test/cb", None)
    call = fake_http.calls_to("/v2/oauth/access_token")[0]
    assert call.method == "POST" and call.url == "https://api.vercel.com/v2/oauth/access_token"
    assert call.data == {
        "client_id": "oac_vercel_id",
        "client_secret": "vercel-client-secret",
        "code": "the-code",
        "redirect_uri": "https://api.cerberus.test/cb",
    }
    assert tokens.access_token == "vercel-secret-token-AAA" and tokens.refresh_token is None
    assert "access_token" not in str(tokens.extra)  # the non-secret extras never hold the token


@pytest.mark.parametrize("status", [400, 401, 403])
def test_vercel_refusing_the_code_is_invalid_grant(fake_http, platform_env, status):
    fake_http.route(
        "POST", "https://api.vercel.com/v2/oauth/access_token", (status, {"error": "invalid_grant"})
    )
    with pytest.raises(ProviderError) as error:
        providers.get_provider("vercel").exchange_code("bad", "https://x", None)
    assert error.value.code == "invalid_grant"


def test_vercel_returning_no_token_is_a_bad_response(fake_http, platform_env):
    fake_http.route("POST", "https://api.vercel.com/v2/oauth/access_token", (200, {"token_type": "Bearer"}))
    with pytest.raises(ProviderError) as error:
        providers.get_provider("vercel").exchange_code("c", "https://x", None)
    assert error.value.code == "bad_response"


def test_vercel_sends_the_token_as_a_bearer_header_only(vercel, fake_http):
    vercel.list_projects(TOKENS)
    assert all(c.headers == {"Authorization": "Bearer tok-123"} for c in fake_http.calls)
    assert not any("tok-123" in str(c.params) or "tok-123" in c.url for c in fake_http.calls)


def test_vercel_offers_only_verified_platform_hostnames(vercel):
    (project,) = vercel.list_projects(TOKENS)
    assert project.hostnames == ("college-erp.vercel.app",)  # not the custom domain, not the unverified one


def test_vercel_team_installs_pass_the_team_id_on_every_call(fake_http, platform_env):
    vercel_routes(fake_http, team=True)
    provider = providers.get_provider("vercel")
    tokens = provider.exchange_code("c", "https://x", None)
    account = provider.get_account(tokens)
    provider.list_projects(tokens)
    assert account.account_id == "team_erp" and account.label == "ERP Team"
    reads = [c for c in fake_http.calls if c.method == "GET" and "/v9/" in c.url]
    assert reads and all(c.params.get("teamId") == "team_erp" for c in reads)


def test_vercel_personal_account_identity_comes_from_the_provider(vercel):
    account = vercel.get_account(TOKENS)
    assert (account.account_id, account.label) == ("usr_alice", "alice")


def test_vercel_a_project_that_is_not_yours_is_not_found(vercel, fake_http):
    fake_http.route(
        "GET", "https://api.vercel.com/v9/projects/prj_theirs", (404, {"error": {"code": "not_found"}})
    )
    with pytest.raises(ProviderError) as error:
        vercel.get_project(TOKENS, "prj_theirs")
    assert error.value.code == "not_found"


def test_vercel_a_rejected_token_is_reported_as_such(vercel, fake_http):
    fake_http.route("GET", "https://api.vercel.com/v9/projects", (401, {}))
    with pytest.raises(ProviderError) as error:
        vercel.list_projects(TOKENS)
    assert error.value.code == "unauthorized"


def test_vercel_a_project_id_cannot_redirect_the_call(vercel, fake_http):
    with pytest.raises(ProviderError):
        vercel.get_project(TOKENS, "../../v2/user")
    assert not fake_http.calls_to("/v2/user")


def test_vercel_the_project_listing_is_bounded(fake_http, platform_env):
    many = {f"prj_{i}": [{"name": f"p{i}.vercel.app", "verified": True}] for i in range(MAX_PROJECTS + 30)}
    vercel_routes(fake_http, many)
    assert len(providers.get_provider("vercel").list_projects(TOKENS)) == MAX_PROJECTS


# --- Netlify --------------------------------------------------------------------------------------


@pytest.fixture
def netlify(fake_http):
    netlify_routes(fake_http)
    return providers.get_provider("netlify")


def test_netlify_authorization_url_uses_the_code_grant_and_state(netlify):
    url = netlify.build_authorization_url("S", "https://api.cerberus.test/cb", None)
    assert url.startswith("https://app.netlify.com/authorize?")
    for part in (
        "client_id=netlify_id",
        "response_type=code",
        "state=S",
        "redirect_uri=https%3A%2F%2Fapi.cerberus.test%2Fcb",
    ):
        assert part in url
    assert "response_type=token" not in url  # never the implicit grant: it would put the token in the browser


def test_netlify_code_exchange_request(netlify, fake_http):
    tokens = netlify.exchange_code("c0de", "https://api.cerberus.test/cb", None)
    call = fake_http.calls_to("/oauth/token")[0]
    assert call.url == "https://api.netlify.com/oauth/token"
    assert call.data == {
        "grant_type": "authorization_code",
        "code": "c0de",
        "client_id": "netlify_id",
        "client_secret": "netlify-client-secret",
        "redirect_uri": "https://api.cerberus.test/cb",
    }
    assert tokens.access_token == "netlify-secret-token-CCC"


def test_netlify_invalid_grant_is_reported(fake_http, platform_env):
    fake_http.route("POST", "https://api.netlify.com/oauth/token", (400, {"error": "invalid_grant"}))
    with pytest.raises(ProviderError) as error:
        providers.get_provider("netlify").exchange_code("x", "https://x", None)
    assert error.value.code == "invalid_grant"


def test_netlify_offers_only_the_netlify_app_hostname_not_custom_domains(netlify):
    (site,) = netlify.list_projects(TOKENS)
    assert site.hostnames == ("campus-portal.netlify.app",)  # not portal.college.edu, not www.college.edu
    assert site.name == "campus-portal"


def test_netlify_lists_sites_the_account_can_access_and_paginates(fake_http, platform_env):
    page1 = [{"id": f"id-{i}", "name": f"s{i}", "url": f"https://s{i}.netlify.app"} for i in range(100)]
    page2 = [{"id": f"id-x{i}", "name": f"t{i}", "url": f"https://t{i}.netlify.app"} for i in range(5)]
    fake_http.route(
        "GET",
        "https://api.netlify.com/api/v1/sites",
        lambda call: (200, page1 if call.params["page"] == 1 else page2),
    )
    sites = providers.get_provider("netlify").list_projects(TOKENS)
    assert len(sites) == 105
    assert fake_http.calls[0].params == {"filter": "all", "per_page": 100, "page": 1}


def test_netlify_a_site_that_is_not_yours_is_not_found(netlify, fake_http):
    fake_http.route(
        "GET", "https://api.netlify.com/api/v1/sites/aaaaaaaa-0000-4000-8000-000000000000", (404, {})
    )
    with pytest.raises(ProviderError) as error:
        netlify.get_project(TOKENS, "aaaaaaaa-0000-4000-8000-000000000000")
    assert error.value.code == "not_found"


def test_netlify_identity_comes_from_the_provider(netlify):
    account = netlify.get_account(TOKENS)
    assert (account.account_id, account.label) == ("nl_alice", "Alice")


def test_netlify_cannot_refresh(netlify):
    with pytest.raises(ProviderError) as error:
        netlify.refresh("r")
    assert error.value.code == "unsupported"


# --- Cloudflare -----------------------------------------------------------------------------------


@pytest.fixture
def cloudflare(fake_http):
    cloudflare_routes(fake_http)
    return providers.get_provider("cloudflare")


def test_cloudflare_is_not_configured_until_the_operator_names_the_scopes(platform_env, monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_OAUTH_SCOPES", "")
    assert not providers.get_provider("cloudflare").is_configured()


def test_cloudflare_authorization_url_carries_pkce_scopes_and_state(cloudflare):
    url = cloudflare.build_authorization_url("S", "https://api.cerberus.test/cb", "CHALLENGE")
    assert url.startswith("https://dash.cloudflare.com/oauth2/auth?")
    for part in (
        "response_type=code",
        "client_id=cf_id",
        "state=S",
        "code_challenge=CHALLENGE",
        "code_challenge_method=S256",
    ):
        assert part in url
    scope = url.split("scope=")[1].split("&")[0]
    assert set(scope.split("+")) == {"pages.read", "account.read", "openid", "offline_access"}


def test_cloudflare_refuses_to_start_without_pkce(cloudflare):
    with pytest.raises(ProviderError):
        cloudflare.build_authorization_url("S", "https://x", None)


def test_cloudflare_code_exchange_sends_the_verifier_and_keeps_the_refresh_token(cloudflare, fake_http):
    tokens = cloudflare.exchange_code("c", "https://api.cerberus.test/cb", "VERIFIER")
    call = fake_http.calls_to("/oauth2/token")[0]
    assert call.url == "https://dash.cloudflare.com/oauth2/token"
    assert call.data["code_verifier"] == "VERIFIER" and call.data["grant_type"] == "authorization_code"
    assert call.data["client_secret"] == "cf-client-secret"
    assert tokens.refresh_token == "cf-refresh-token-EEE" and tokens.expires_at is not None


def test_cloudflare_refresh_uses_the_refresh_grant_and_keeps_the_old_refresh_token_if_none_returned(
    cloudflare,
    fake_http,
):
    fake_http.route(
        "POST",
        "https://dash.cloudflare.com/oauth2/token",
        (200, {"access_token": "new-access", "expires_in": 3600}),
    )
    fresh = cloudflare.refresh("old-refresh")
    assert fake_http.calls[-1].data["grant_type"] == "refresh_token"
    assert fresh.access_token == "new-access" and fresh.refresh_token == "old-refresh"


def test_cloudflare_offers_only_the_pages_dev_subdomain(cloudflare):
    (project,) = cloudflare.list_projects(TOKENS)
    assert project.hostnames == ("docs-site.pages.dev",)  # not docs.example.com
    assert project.id == f"{CF_ACCOUNT}:docs-site"


def test_cloudflare_a_project_id_names_an_account_and_a_project(cloudflare):
    assert cloudflare.get_project(TOKENS, f"{CF_ACCOUNT}:docs-site").name == "docs-site"
    for bad in ("docs-site", ":docs-site", f"{CF_ACCOUNT}:", f"{CF_ACCOUNT}:../x", "../x:docs-site"):
        with pytest.raises(ProviderError):
            cloudflare.get_project(TOKENS, bad)


def test_cloudflare_another_accounts_project_is_refused_by_cloudflare(cloudflare, fake_http):
    other = "ffffffffffffffffffffffffffffffff"
    fake_http.route(
        "GET",
        f"https://api.cloudflare.com/client/v4/accounts/{other}/pages/projects/docs-site",
        (403, {"success": False}),
    )
    with pytest.raises(ProviderError) as error:
        cloudflare.get_project(TOKENS, f"{other}:docs-site")
    assert error.value.code == "forbidden"


def test_cloudflare_a_success_false_envelope_is_a_failure(cloudflare, fake_http):
    fake_http.route(
        "GET", "https://api.cloudflare.com/client/v4/accounts", (200, {"success": False, "result": []})
    )
    with pytest.raises(ProviderError) as error:
        cloudflare.list_projects(TOKENS)
    assert error.value.code == "bad_response"


def test_cloudflare_identity_is_the_subject_from_userinfo(cloudflare):
    account = cloudflare.get_account(TOKENS)
    assert account.account_id == "cf_alice" and "Alice" in account.label


# --- verify_target: the one question that matters -------------------------------------------------


def test_verifying_a_hostname_the_project_owns_succeeds(vercel):
    assert vercel.verify_target(TOKENS, "prj_erp", "college-erp.vercel.app").id == "prj_erp"


def test_verifying_someone_elses_hostname_on_my_project_fails(vercel):
    with pytest.raises(ProviderError) as error:
        vercel.verify_target(TOKENS, "prj_erp", "somebody-elses.vercel.app")
    assert error.value.code == "hostname_not_in_project"


def test_a_custom_domain_listed_on_the_project_does_not_verify(vercel):
    """Attaching a domain to a project does not prove you own it, so only DNS can verify it."""
    with pytest.raises(ProviderError) as error:
        vercel.verify_target(TOKENS, "prj_erp", "erp.college.edu")
    assert error.value.code == "not_a_platform_hostname"


def test_the_platform_apex_never_verifies(vercel, fake_http):
    with pytest.raises(ProviderError):
        vercel.verify_target(TOKENS, "prj_erp", "vercel.app")
    assert not fake_http.calls  # refused before asking the provider anything


def test_a_wrong_platform_suffix_never_verifies(vercel):
    with pytest.raises(ProviderError) as error:
        vercel.verify_target(TOKENS, "prj_erp", "college-erp.netlify.app")
    assert error.value.code == "not_a_platform_hostname"


def test_an_unverified_vercel_domain_does_not_verify(vercel):
    with pytest.raises(ProviderError) as error:
        vercel.verify_target(TOKENS, "prj_erp", "unverified.vercel.app")
    assert error.value.code == "hostname_not_in_project"


def test_the_fake_http_never_reaches_a_real_network(fake_http):
    assert isinstance(fake_http, FakeHttp)
