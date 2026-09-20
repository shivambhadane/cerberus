"""Small helpers shared by test modules (fixtures live in conftest.py)."""

import os
from datetime import timedelta

from core.models import User
from core.security import create_access_token


def auth_for(user: User, minutes: int = 15) -> dict[str, str]:
    """Authorization headers for `user`, signed with the test secret."""
    token = create_access_token(user.id, os.environ["API_SECRET_KEY"], timedelta(minutes=minutes))
    return {"Authorization": f"Bearer {token}"}
