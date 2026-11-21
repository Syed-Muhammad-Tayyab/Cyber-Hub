"""
Cyber Hub Backend - Part 1 tests
Developed by Syed Muhammad Tayyab
Run:  python -m pytest -q
"""
import pytest
from fastapi.testclient import TestClient

from cyberhub.config import BUILD_PART, Settings
from cyberhub.database import MIGRATIONS
from cyberhub.main import create_app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    app = create_app(Settings(), start_workers=False)
    with TestClient(app) as c:
        tok = c.get("/api/bootstrap").json()["token"]
        c.headers["X-CyberHub-Token"] = tok
        yield c


def test_health_is_public(client):
    r = client.get("/api/health", headers={"X-CyberHub-Token": ""})
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.json()["schema_version"] == MIGRATIONS[-1][0]


def test_token_required(client):
    r = client.get("/api/system/info", headers={"X-CyberHub-Token": "wrong"})
    assert r.status_code == 401


def test_bootstrap_blocks_foreign_origin(client):
    assert client.get("/api/bootstrap", headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.get("/api/bootstrap", headers={"Origin": "null"}).status_code == 403


def test_token_persists(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path))
    toks = []
    for _ in range(2):
        with TestClient(create_app(Settings(), start_workers=False)) as c:
            toks.append(c.get("/api/bootstrap").json()["token"])
    assert toks[0] == toks[1]


def test_info_lists_20_modules(client):
    j = client.get("/api/info").json()
    assert j["total_parts"] == 20 and len(j["modules"]) == 20
    assert "core" in j["available_modules"] and j["progress_percent"] == BUILD_PART * 5


def test_device_info(client):
    j = client.get("/api/system/info").json()
    assert j["hostname"] and j["cpu"]["logical_cores"] >= 1 and j["memory"]["total_gb"] > 0


def test_live_stats(client):
    j = client.get("/api/system/stats").json()
    for k in ("cpu_percent", "memory_percent", "disk_percent", "net_upload_kbps", "process_count"):
        assert k in j
    assert 0 <= j["memory_percent"] <= 100


def test_snapshot_and_history(client):
    client.post("/api/system/snapshot")
    client.post("/api/system/snapshot")
    pts = client.get("/api/system/history?hours=1").json()["points"]
    assert len(pts) == 2


def test_activity_crud_and_summary(client):
    r = client.post("/api/activity", json={"category": "scan", "title": "Quick scan", "severity": "high"})
    assert r.status_code == 201 and r.json()["source"] == "ui"
    assert client.post("/api/activity", json={"category": "bogus", "title": "x"}).status_code == 422
    lst = client.get("/api/activity?category=scan").json()
    assert lst["total"] == 1
    s = client.get("/api/activity/summary").json()
    assert s["by_severity"]["high"] == 1
    assert client.delete("/api/activity").json()["deleted"] >= 2  # includes 'engine started'


def test_settings(client):
    s = client.get("/api/settings").json()
    assert s["theme"] == "dark"
    s = client.patch("/api/settings", json={"theme": "light", "metrics_interval_seconds": 5}).json()
    assert s["theme"] == "light" and s["metrics_interval_seconds"] == 5
    assert client.patch("/api/settings", json={"nope": 1}).status_code == 422
    assert client.patch("/api/settings", json={"theme": 3}).status_code == 422
    assert client.patch("/api/settings", json={"metrics_interval_seconds": True}).status_code == 422
    assert client.patch("/api/settings", json={"metrics_interval_seconds": 999}).status_code == 422
    assert client.post("/api/settings/reset").json()["theme"] == "dark"


def test_websocket_stream(client):
    tok = client.headers["X-CyberHub-Token"]
    with client.websocket_connect(f"/api/system/stream?token={tok}") as ws:
        assert "cpu_percent" in ws.receive_json()


def test_websocket_rejects_bad_token(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/system/stream?token=bad") as ws:
            ws.receive_json()
