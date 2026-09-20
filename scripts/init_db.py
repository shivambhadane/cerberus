#!/usr/bin/env python3
"""Bring the database to the latest schema by running migrations."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import load_config  # noqa: E402
from core.db import init_db, redact_url  # noqa: E402


def main() -> int:
    init_db()
    # Never print the raw URL: it contains the database password.
    print(f"schema up to date on {redact_url(load_config().database_url)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
