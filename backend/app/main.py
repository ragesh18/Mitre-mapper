import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import routes
from .core import config
from .db import models  # noqa: F401  (register tables)
from .db.database import Base, SessionLocal, engine
from .engine.mapper import Mapper
from .engine.rules import load_rules
from .services.mitre_sync import seed_if_empty
from .services.scheduler import sync_loop


def reload_mapper():
    with SessionLocal() as db:
        techs = [t.to_dict() for t in db.query(models.Technique).all()]
    routes._state["mapper"] = Mapper(load_rules(config.RULES_PATH), techs)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        seed_if_empty(db)
    routes._state["reload"] = reload_mapper
    reload_mapper()
    task = asyncio.create_task(sync_loop(reload_mapper)) if config.AUTO_SYNC else None
    yield
    if task:
        task.cancel()


app = FastAPI(title="MITRE ATT&CK Mapping Tool", version="1.0.0", lifespan=lifespan)
app.include_router(routes.router)
app.mount("/static", StaticFiles(directory=config.FRONTEND_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(config.FRONTEND_DIR / "index.html")
