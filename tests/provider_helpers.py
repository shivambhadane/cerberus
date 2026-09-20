"""Helpers for driving the connect / callback flow in tests (fixtures live in conftest.py)."""

from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from sqlalchemy import select

from api.main import app
from core.models import ConnectedProvider
from tests.helpers import auth_for

V1 = "/api/v1"
FRONTEND = "https://app.cerberus.test/platform/#/domains?"


def browser(user) -> TestClient:
    """One person's browser: their credentials, and their own cookie jar."""
    return TestClient(app, headers=auth_for(user))


def begin(client, provider="vercel") -> tuple[str, str]:
    response = client.post(f"{V1}/providers/{provider}/connect")
    assert response.status_code == 200, response.text
    url = response.json()["authorization_url"]
    return url, parse_qs(urlsplit(url).query)["state"][0]


def finish(client, provider, state, code="the-code", **params):
    query = {"code": code, "state": state, **params}
    query = {k: v for k, v in query.items() if v is not None}
    return client.get(f"{V1}/providers/{provider}/callback", params=query, follow_redirects=False)


def outcome(response) -> dict[str, str]:
    """What the dashboard is told: the fragment query of the redirect."""
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(FRONTEND), location
    return {k: v[0] for k, v in parse_qs(location[len(FRONTEND) :]).items()}


def connections(session) -> list[ConnectedProvider]:
    return list(session.scalars(select(ConnectedProvider)))


def connect(user, provider="vercel") -> TestClient:
    """Run a whole successful connection for `user` and return their browser."""
    client = browser(user)
    _, state = begin(client, provider)
    result = outcome(finish(client, provider, state))
    assert result.get("connected") == "1", result
    return client
