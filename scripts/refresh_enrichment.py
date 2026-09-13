#!/usr/bin/env python3
"""Pull the latest CVE/KEV/EPSS data into the local enrichment cache."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.db import init_db, session_scope  # noqa: E402
from enrichment.cache import refresh_global_sources  # noqa: E402


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    init_db()
    with session_scope() as session:
        counts = refresh_global_sources(session)
    print(f"KEV records: {counts['kev']}   EPSS scores: {counts['epss']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
