#!/usr/bin/env python3
"""Create database tables from the SQLAlchemy models."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import load_config  # noqa: E402
from core.db import init_db  # noqa: E402


def main() -> int:
    init_db()
    print(f"schema created against {load_config().database_url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
