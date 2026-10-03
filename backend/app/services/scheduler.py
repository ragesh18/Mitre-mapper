import asyncio
import logging

from ..core.config import SYNC_INTERVAL_HOURS
from ..db.database import SessionLocal
from .mitre_sync import sync_mitre

log = logging.getLogger("mitre.scheduler")


async def sync_loop(on_synced=None):
    """Sync at startup and then every SYNC_INTERVAL_HOURS. Failures (e.g. offline) are logged, not fatal."""
    while True:
        try:
            def work():
                with SessionLocal() as db:
                    return sync_mitre(db)
            n = await asyncio.to_thread(work)
            log.info("MITRE sync OK: %s techniques", n)
            if on_synced:
                on_synced()
        except Exception as exc:  # noqa: BLE001
            log.warning("MITRE sync failed: %s", exc)
        await asyncio.sleep(SYNC_INTERVAL_HOURS * 3600)
