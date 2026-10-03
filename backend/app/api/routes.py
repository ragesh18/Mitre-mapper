import csv
import io
import json
import os
from typing import Optional

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core import config
from ..db.database import get_db
from ..db.models import Analysis, Technique
from ..services.mitre_sync import sync_mitre

router = APIRouter(prefix="/api/v1")
_state = {"mapper": None, "reload": None}  # set by main.py


class MapRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=config.MAX_TEXT_CHARS)
    top_n: int = Field(10, ge=1, le=50)


def _analyze(db: Session, text: str, source: str, top_n: int = 10) -> dict:
    if not text.strip():
        raise HTTPException(422, "Input is empty")
    results = _state["mapper"].map_text(text[: config.MAX_TEXT_CHARS], top_n)
    # attach MITRE URL from the DB
    urls = {t.attack_id: t.url for t in db.query(Technique).filter(Technique.attack_id.in_([r["attack_id"] for r in results]))}
    for r in results:
        r["url"] = urls.get(r["attack_id"], "")
    a = Analysis(source=source, preview=text.strip()[:300], results_json=json.dumps(results))
    db.add(a)
    db.commit()
    return {"analysis_id": a.id, "source": source, "count": len(results), "results": results}


@router.get("/health")
def health(db: Session = Depends(get_db)):
    return {"status": "ok", "techniques": db.query(Technique).count(), "rules": len(_state["mapper"].rules)}


@router.post("/map")
def map_text(req: MapRequest, db: Session = Depends(get_db)):
    return _analyze(db, req.text, "text", req.top_n)


@router.post("/map/file")
async def map_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in config.ALLOWED_EXTENSIONS:
        raise HTTPException(415, f"Unsupported file type. Allowed: {', '.join(sorted(config.ALLOWED_EXTENSIONS))}")
    data = await file.read(config.MAX_UPLOAD_BYTES + 1)
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File exceeds {config.MAX_UPLOAD_BYTES} bytes")
    return _analyze(db, data.decode("utf-8", errors="replace"), f"file:{os.path.basename(file.filename)[:150]}")


@router.get("/techniques")
def list_techniques(q: Optional[str] = None, tactic: Optional[str] = None,
                    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    query = db.query(Technique)
    if q:
        like = f"%{q}%"
        query = query.filter(Technique.name.ilike(like) | Technique.attack_id.ilike(like))
    if tactic:
        query = query.filter(Technique.tactics.ilike(f"%{tactic}%"))
    total = query.count()
    items = query.order_by(Technique.attack_id).offset(offset).limit(limit).all()
    return {"total": total, "items": [t.to_dict() for t in items]}


@router.get("/techniques/{attack_id}")
def get_technique(attack_id: str, db: Session = Depends(get_db)):
    t = db.query(Technique).filter(Technique.attack_id == attack_id.upper()).first()
    if not t:
        raise HTTPException(404, "Technique not found")
    return t.to_dict(full=True)


@router.get("/history")
def history(limit: int = Query(25, ge=1, le=200), db: Session = Depends(get_db)):
    rows = db.query(Analysis).order_by(Analysis.id.desc()).limit(limit).all()
    return [{"analysis_id": a.id, "created_at": a.created_at.isoformat(), "source": a.source, "preview": a.preview,
             "count": len(json.loads(a.results_json))} for a in rows]


@router.get("/export/{analysis_id}")
def export(analysis_id: int, format: str = Query("json", pattern="^(json|csv)$"), db: Session = Depends(get_db)):
    a = db.get(Analysis, analysis_id)
    if not a:
        raise HTTPException(404, "Analysis not found")
    results = json.loads(a.results_json)
    if format == "json":
        return {"analysis_id": a.id, "source": a.source, "created_at": a.created_at.isoformat(), "results": results}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["attack_id", "name", "tactics", "confidence_pct", "indicators", "methods", "url"])
    for r in results:
        # prefix cells that could be interpreted as spreadsheet formulas (CSV injection)
        safe = lambda s: "'" + s if s[:1] in "=+-@" else s  # noqa: E731
        w.writerow([r["attack_id"], r["name"], "; ".join(r["tactics"]), r["confidence"],
                    safe("; ".join(r["indicators"])), "; ".join(r["methods"]), r.get("url", "")])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename=analysis_{a.id}.csv"})


@router.post("/admin/sync")
def admin_sync(x_admin_token: str = Header(default=""), db: Session = Depends(get_db)):
    if config.ADMIN_TOKEN and x_admin_token != config.ADMIN_TOKEN:
        raise HTTPException(401, "Invalid admin token")
    try:
        n = sync_mitre(db)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"Sync failed: {exc}")
    _state["reload"]()
    return {"synced": n}
