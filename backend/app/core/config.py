import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DB_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT / 'data' / 'mitre.db'}")
RULES_PATH = Path(os.getenv("RULES_PATH", ROOT / "rules" / "rules.json"))
FRONTEND_DIR = ROOT / "frontend"
STIX_URL = os.getenv(
    "STIX_URL",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
)
SYNC_INTERVAL_HOURS = float(os.getenv("SYNC_INTERVAL_HOURS", "24"))
AUTO_SYNC = os.getenv("AUTO_SYNC", "true").lower() == "true"
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")  # if set, required for /admin/sync
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(1_000_000)))
MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "200000"))
ALLOWED_EXTENSIONS = {".txt", ".log", ".csv", ".json"}
