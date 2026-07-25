#!/usr/bin/env python3
"""
SENTINEL-GRC — Test Database Initialiser
========================================
Creates all SQLAlchemy tables in the CI test Postgres database.

Run this ONCE before pytest in CI (and locally when using a real Postgres):

    python scripts/init_test_db.py

Uses the synchronous engine (SYNC_DATABASE_URL) so no asyncio event loop is
required. This is intentional: the script is a one-shot setup utility and the
async engine adds no value here.

Environment variable required:
    SYNC_DATABASE_URL  postgresql://sentinel:sentinel_secret@localhost:5432/sentinel_grc_test
"""

import os
import sys

# ── Make sure the app package is importable regardless of CWD ─────────────────
# When run as  `python scripts/init_test_db.py` from the `backend/` directory,
# the `backend/` folder is already on sys.path via the cwd, but be explicit.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Import models BEFORE Base so metadata is populated ────────────────────────
# Each model module calls Base's metaclass which registers the table.
# Skipping any import here = that table won't be created.
import app.models  # noqa: F401  — registers User, Risk, ThreatEvent, …

from app.db.database import Base, sync_engine


def main() -> None:
    url = str(sync_engine.url)
    # Mask password in log output
    safe_url = url.split("@")[-1] if "@" in url else url
    print(f"[init_test_db] Connecting to: ...@{safe_url}")

    print("[init_test_db] Running Base.metadata.create_all …")
    Base.metadata.create_all(bind=sync_engine)
    print("[init_test_db] ✓ All tables created (or already exist).")


if __name__ == "__main__":
    main()
