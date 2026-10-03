"""API tests (require: pip install -r requirements.txt)."""
import os
import sys
import tempfile
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["AUTO_SYNC"] = "false"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from backend.app.main import app  # noqa: E402


def test_flow():
    with TestClient(app) as c:
        assert c.get("/api/v1/health").json()["status"] == "ok"
        r = c.post("/api/v1/map", json={"text": "mimikatz sekurlsa::logonpasswords"}).json()
        assert r["results"][0]["attack_id"] == "T1003.001"
        assert c.post("/api/v1/map", json={"text": ""}).status_code == 422
        assert "attack_id" in c.get(f"/api/v1/export/{r['analysis_id']}?format=csv").text
        assert c.get("/api/v1/techniques/T1082").status_code == 200
        assert c.get("/api/v1/techniques/T0000").status_code == 404
        assert c.get("/api/v1/history").json()[0]["analysis_id"] == r["analysis_id"]


def test_upload_validation():
    with TestClient(app) as c:
        assert c.post("/api/v1/map/file", files={"file": ("a.exe", b"x")}).status_code == 415
        ok = c.post("/api/v1/map/file", files={"file": ("a.log", b"User executed powershell.exe")})
        assert ok.status_code == 200 and ok.json()["results"][0]["attack_id"] == "T1059.001"
