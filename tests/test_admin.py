"""The admin flag: read-only cross-tenant visibility, and nothing else.

What must hold: a non-admin cannot reach any `/admin/*` route; an admin sees every account's domains,
scans and findings; and — the one that matters most — being an admin grants no scanning power beyond
what any verified-domain owner already has. `is_admin` is also never settable through any API.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.main import app, get_session
from core.db import get_default_tenant
from core.models import Domain, Scan, User, utcnow
from tests.helpers import auth_for

V1 = "/api/v1"


@pytest.fixture
def world(session, make_user):
    app.dependency_overrides[get_session] = lambda: session
    admin = make_user("admin@example.com", is_admin=True)
    alice = make_user("alice@example.com")
    bob = make_user("bob@example.com")

    alice_domain = Domain(
        user_id=alice.id, domain="alice.example.com",
        verification_status="verified", verification_method="dns_txt",
    )
    bob_domain = Domain(
        user_id=bob.id, domain="bob.example.com",
        verification_status="pending", verification_method="dns_txt",
    )
    session.add_all([alice_domain, bob_domain])
    session.flush()

    tenant = get_default_tenant(session)
    bob_scan = Scan(
        tenant_id=tenant.id, user_id=bob.id, domain_id=bob_domain.id,
        target_domain="bob.example.com", status="completed", started_at=utcnow(),
    )
    legacy_scan = Scan(  # predates accounts: no owner
        tenant_id=tenant.id, user_id=None, domain_id=None,
        target_domain="legacy.example.com", status="completed", started_at=utcnow(),
    )
    session.add_all([bob_scan, legacy_scan])
    session.flush()

    yield {
        "session": session, "admin": admin, "alice": alice, "bob": bob,
        "alice_domain": alice_domain, "bob_domain": bob_domain,
        "bob_scan": bob_scan, "legacy_scan": legacy_scan,
    }
    app.dependency_overrides.clear()


def client_for(user) -> TestClient:
    return TestClient(app, headers=auth_for(user))


# --- who may reach it ---------------------------------------------------------------------------


def test_signed_out_gets_401_not_404(world):
    """Being signed out and being a non-admin must read differently: the first is `sign in`, the
    second is `not found`. If both were 404, a client could not tell "retry after signing in" from
    "this path does not exist"."""
    assert TestClient(app).get(f"{V1}/admin/overview").status_code == 401


@pytest.mark.parametrize("path", ["/admin/overview", "/admin/users", "/admin/domains", "/admin/scans"])
def test_a_signed_in_non_admin_sees_not_found(world, path):
    """Every admin route is a plain 404 for a non-admin — the same answer a wrong-tenant resource
    gets elsewhere in this API, so an admin surface existing is not itself discoverable."""
    for user in (world["alice"], world["bob"]):
        response = client_for(user).get(f"{V1}{path}")
        assert response.status_code == 404, (path, user.email)
        assert response.json()["error"]["code"] == "not_found"


def test_an_admin_reaches_every_route(world):
    admin = client_for(world["admin"])
    for path in ("/admin/overview", "/admin/users", "/admin/domains", "/admin/scans"):
        assert admin.get(f"{V1}{path}").status_code == 200, path


# --- what an admin sees: everyone's, not just their own -------------------------------------------


def test_admin_sees_every_users_domains(world):
    body = client_for(world["admin"]).get(f"{V1}/admin/domains").json()
    seen = {d["domain"]: d for d in body["domains"]}
    assert body["total"] == 2
    assert seen["alice.example.com"]["owner_email"] == "alice@example.com"
    assert seen["alice.example.com"]["verification_status"] == "verified"
    assert seen["bob.example.com"]["owner_email"] == "bob@example.com"
    assert seen["bob.example.com"]["verification_status"] == "pending"


def test_admin_sees_every_users_scans_including_unowned_legacy_ones(world):
    body = client_for(world["admin"]).get(f"{V1}/admin/scans").json()
    by_target = {s["target_domain"]: s for s in body["scans"]}
    assert body["total"] == 2
    assert by_target["bob.example.com"]["owner_email"] == "bob@example.com"
    assert by_target["legacy.example.com"]["owner_email"] is None  # never invented


def test_admin_sees_every_account_with_their_counts(world):
    body = client_for(world["admin"]).get(f"{V1}/admin/users").json()
    by_email = {u["email"]: u for u in body["users"]}
    assert body["total"] == 3  # admin, alice, bob
    assert by_email["alice@example.com"]["domain_count"] == 1
    assert by_email["bob@example.com"]["domain_count"] == 1
    assert by_email["bob@example.com"]["scan_count"] == 1
    assert by_email["admin@example.com"]["is_admin"] is True
    assert by_email["alice@example.com"]["is_admin"] is False


def test_admin_overview_counts_are_not_scoped_to_the_admins_own_account(world):
    """The admin here owns no domains and ran no scans; the counts must still show alice's and bob's."""
    body = client_for(world["admin"]).get(f"{V1}/admin/overview").json()
    assert body["user_count"] == 3
    assert body["domain_counts"].get("verified") == 1 and body["domain_counts"].get("pending") == 1
    assert body["scan_counts"].get("completed") == 2


def test_a_regular_user_still_only_sees_their_own_domain(world):
    """The existing, non-admin endpoints are completely unaffected by any of this."""
    mine = client_for(world["alice"]).get(f"{V1}/domains").json()
    assert mine["total"] == 1 and mine["domains"][0]["domain"] == "alice.example.com"


# --- the invariant that matters most: visibility is not scanning power ----------------------------


def test_being_admin_does_not_authorise_scanning_someone_elses_domain(world, monkeypatch):
    """This is the whole point of saying yes to "admin" instead of "superuser, no auth, scan
    anything": an admin can SEE bob's and alice's domains through /admin/domains, but `POST /scans`
    is unaware admin visibility exists at all — it is the same `core/ownership.py` check as for
    anyone, and a domain that is not the caller's own looks exactly like no domain, admin or not."""
    monkeypatch.setattr("api.main.run_pipeline", lambda scan_id, config: None)
    admin = client_for(world["admin"])

    verified_but_not_mine = admin.post(f"{V1}/scans", json={"domain_id": world["alice_domain"].id})
    assert verified_but_not_mine.status_code == 404
    assert verified_but_not_mine.json()["error"]["code"] == "not_found"

    unverified_and_not_mine = admin.post(f"{V1}/scans", json={"domain_id": world["bob_domain"].id})
    assert unverified_and_not_mine.status_code == 404
    assert unverified_and_not_mine.json()["error"]["code"] == "not_found"

    # the admin's own view of their own (nonexistent) domains is unaffected: they have none
    assert client_for(world["admin"]).get(f"{V1}/domains").json()["total"] == 0


def test_is_admin_cannot_be_set_through_any_api(world):
    """No registration field, no profile update, no way to self-promote. Only
    scripts/grant_admin.py, with direct database access, sets this column."""
    reg = TestClient(app).post(
        f"{V1}/auth/register",
        json={"email": "eve@example.com", "password": "eves-password", "is_admin": True},
    )
    assert reg.status_code in (201, 422)
    if reg.status_code == 201:
        assert reg.json()["user"]["is_admin"] is False
        eve = world["session"].scalar(select(User).where(User.email == "eve@example.com"))
        assert eve.is_admin is False


def test_grant_admin_script_grants_and_revokes(world):
    from scripts.grant_admin import set_admin

    user = set_admin(world["session"], "bob@example.com", admin=True)
    assert user.is_admin is True
    user = set_admin(world["session"], "bob@example.com", admin=False)
    assert user.is_admin is False


def test_grant_admin_script_refuses_an_unknown_email(world):
    from scripts.grant_admin import set_admin

    with pytest.raises(LookupError):
        set_admin(world["session"], "nobody@example.com", admin=True)
