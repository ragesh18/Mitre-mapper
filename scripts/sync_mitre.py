"""Manual sync:  python scripts/sync_mitre.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.db import models  # noqa: E402,F401
from backend.app.db.database import Base, SessionLocal, engine  # noqa: E402
from backend.app.services.mitre_sync import seed_if_empty, sync_mitre  # noqa: E402

Base.metadata.create_all(engine)
with SessionLocal() as db:
    seed_if_empty(db)
    print(f"Synced {sync_mitre(db)} techniques")
