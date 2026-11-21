"""
Cyber Hub Backend - Part 3 tests: Live System Monitor
Developed by Syed Muhammad Tayyab
"""
import sqlite3

import psutil
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from cyberhub.config import Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import hardware
from cyberhub.services.alerts import severity_for

PW = "Cyb3r!Hub#2026"


@pytest.fixture()
def c(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        r = cl.post("/api/account/setup", json={"username": "syed", "display_name": "Syed", "password": PW})
        cl.session_token = r.json()["session_token"]
        cl.headers["X-CyberHub-Session"] = cl.session_token
        yield cl


# ------------------------------------------------------------------ access control
def test_monitor_requires_session_and_unlocked(c):
    assert c.get("/api/monitor/cpu", headers={"X-CyberHub-Session": ""}).status_code == 401
    assert c.get("/api/monitor/cpu", headers={"X-CyberHub-Token": "bad"}).status_code == 401
    c.post("/api/account/lock")
    assert c.get("/api/monitor/overview").status_code == 423
    c.post("/api/account/unlock", json={"password": PW})
    assert c.get("/api/monitor/cpu").status_code == 200


# ------------------------------------------------------------------ live data
def test_overview_shape(c):
    j = c.get("/api/monitor/overview?top=3").json()
    for key in ("cpu", "memory", "disk_io", "network", "gpu", "temperatures", "health",
                "top_cpu", "top_memory", "alerts", "process_count", "uptime_seconds"):
        assert key in j, key
    assert j["health"]["overall"] in ("ok", "warning", "critical")
    assert len(j["top_cpu"]) <= 3 and len(j["top_memory"]) <= 3
    assert j["top_memory"] == sorted(j["top_memory"], key=lambda p: -p["memory_mb"])


def test_cpu_per_core_and_breakdown(c):
    j = c.get("/api/monitor/cpu").json()
    assert len(j["per_core"]) == psutil.cpu_count()
    assert all(0 <= v <= 100 for v in j["per_core"]) and 0 <= j["percent"] <= 100
    assert "idle" in j["times_percent"]


def test_memory_disks_network(c):
    m = c.get("/api/monitor/memory").json()
    assert 0 < m["total_gb"] and "swap" in m and 0 <= m["percent"] <= 100
    d = c.get("/api/monitor/disks").json()
    assert {"read_mb_s", "write_mb_s", "read_iops", "write_iops", "disks", "partitions"} <= d.keys()
    assert d["partitions"] and all(0 <= p["percent"] <= 100 for p in d["partitions"])
    n = c.get("/api/monitor/network").json()
    assert n["upload_kbps"] >= 0 and isinstance(n["interfaces"], list)


def test_gpu_and_temperatures_degrade_gracefully(c):
    g = c.get("/api/monitor/gpu").json()
    assert "available" in g and isinstance(g["gpus"], list)
    if not g["available"]:
        assert g["note"]
    t = c.get("/api/monitor/temperatures").json()
    assert {"available", "cpu_celsius", "sensors", "fans"} <= t.keys()


def test_top_processes(c):
    for by in ("cpu", "memory", "disk"):
        j = c.get(f"/api/monitor/top?by={by}&limit=5").json()
        assert j["by"] == by and len(j["items"]) <= 5 and j["process_count"] > 0
        assert {"pid", "name", "cpu_percent", "memory_mb", "memory_percent"} <= j["items"][0].keys()
    assert c.get("/api/monitor/top?by=nonsense").status_code == 422


# ------------------------------------------------------------------ history
def test_history_buckets(c):
    db = c.app.state.db
    # Timestamps aligned to the 10-minute grid so the first two can never straddle a bucket edge.
    import time as _t
    base = (int(_t.time()) - 30 * 60) // 600 * 600
    iso = lambda t: _t.strftime("%Y-%m-%dT%H:%M:%S.000Z", _t.gmtime(t))  # noqa: E731
    rows = [  # two points in one 10-minute bucket, one in a later one
        (iso(base + 60), 20, 50, 1000, 2000, 40), (iso(base + 120), 40, 60, 1000 + 1024 ** 2, 2000, 50),
        (iso(int(_t.time()) - 60), 90, 70, 5000, 9000, 70),
    ]
    for ts, cpu, mem, sent, recv, temp in rows:
        db.execute("INSERT INTO metric_snapshots(ts, cpu, memory, disk, net_sent, net_recv, cpu_temp) "
                   "VALUES (?,?,?,10,?,?,?)", (ts, cpu, mem, sent, recv, temp))
    j = c.get("/api/monitor/history?hours=1&bucket_minutes=10").json()
    assert j["bucket_minutes"] == 10
    assert sum(p["samples"] for p in j["points"]) == 3
    assert max(p["cpu_peak"] for p in j["points"]) == 90
    assert any(p["net_sent_mb"] == 1.0 for p in j["points"])
    assert c.get("/api/monitor/history?hours=168").json()["bucket_minutes"] == 84  # ~120 points


def test_snapshot_records_new_columns(c):
    row = c.post("/api/system/snapshot").json()
    for col in ("swap", "disk_read_mbs", "disk_write_mbs", "gpu", "cpu_temp"):
        assert col in row
    assert row["swap"] is not None


# ------------------------------------------------------------------ thresholds
def test_thresholds_get_put_validate(c):
    t = c.get("/api/monitor/thresholds").json()
    assert t["alert_cpu_percent"] == 90 and t["alert_sustain_seconds"] == 60
    j = c.put("/api/monitor/thresholds", json={"alert_cpu_percent": 80, "alert_sustain_seconds": 0}).json()
    assert j["alert_cpu_percent"] == 80
    assert c.get("/api/settings").json()["alert_cpu_percent"] == 80
    assert c.put("/api/monitor/thresholds", json={"alert_cpu_percent": 20}).status_code == 422
    assert c.put("/api/monitor/thresholds", json={}).status_code == 422
    assert c.patch("/api/settings", json={"alert_temperature_c": 500}).status_code == 422


# ------------------------------------------------------------------ alert engine
def test_alert_needs_sustain_then_escalates_and_resolves(c):
    eng = c.app.state.alerts
    assert eng.evaluate([("cpu", "cpu", 95)], now=0) == []
    assert eng.evaluate([("cpu", "cpu", 96)], now=30) == []          # not sustained yet
    ev = eng.evaluate([("cpu", "cpu", 93)], now=61)
    assert ev[0]["event"] == "opened" and ev[0]["alert"]["severity"] == "medium"
    assert eng.evaluate([("cpu", "cpu", 94)], now=65) == []          # no duplicate
    ev = eng.evaluate([("cpu", "cpu", 99)], now=70)
    assert ev[0]["event"] == "escalated" and ev[0]["alert"]["severity"] == "high"
    assert eng.evaluate([("cpu", "cpu", 85)], now=75) == []          # inside hysteresis margin
    ev = eng.evaluate([("cpu", "cpu", 40)], now=80)
    assert ev[0]["event"] == "resolved" and ev[0]["alert"]["peak"] == 99
    log = c.get("/api/activity?category=system&severity=high").json()["items"]
    assert any(e["source"] == "monitor" for e in log)


def test_spike_below_sustain_never_alerts(c):
    eng = c.app.state.alerts
    eng.evaluate([("cpu", "cpu", 99)], now=0)
    eng.evaluate([("cpu", "cpu", 10)], now=5)                        # spike ends -> timer resets
    assert eng.evaluate([("cpu", "cpu", 99)], now=62) == []
    assert c.get("/api/monitor/alerts?status=active").json()["items"] == []


def test_disk_alerts_per_drive_and_disabled_switch(c):
    c.put("/api/monitor/thresholds", json={"alert_sustain_seconds": 0})
    eng = c.app.state.alerts
    ev = eng.evaluate([("disk_space", "C:\\", 97), ("disk_space", "D:\\", 40), ("gpu", "gpu", None)], now=1)
    assert len(ev) == 1 and ev[0]["alert"]["target"] == "C:\\" and "C:\\" in ev[0]["alert"]["message"]
    c.put("/api/monitor/thresholds", json={"monitor_alerts_enabled": False})
    assert eng.evaluate([("memory", "memory", 99)], now=2) == []


def test_temperature_severity():
    assert severity_for("temperature", 88, 85) == "medium"
    assert severity_for("temperature", 96, 85) == "high"
    assert severity_for("cpu", 94, 90) == "medium" and severity_for("cpu", 95, 90) == "high"


def test_alert_api_list_ack_summary_clear(c):
    c.put("/api/monitor/thresholds", json={"alert_sustain_seconds": 0})
    eng = c.app.state.alerts
    eng.evaluate([("memory", "memory", 97), ("cpu", "cpu", 92)], now=1)
    s = c.get("/api/monitor/alerts/summary").json()
    assert s["active"] == 2 and s["unacknowledged"] == 2 and s["active_by_severity"]["high"] == 1
    aid = c.get("/api/monitor/alerts?status=active").json()["items"][0]["id"]
    assert c.post(f"/api/monitor/alerts/{aid}/ack").json()["acknowledged_at"]
    assert c.post("/api/monitor/alerts/999/ack").status_code == 404
    assert c.post("/api/monitor/alerts/ack-all").json()["acknowledged"] == 1
    assert c.get("/api/monitor/alerts?status=unacknowledged").json()["items"] == []
    eng.evaluate([("memory", "memory", 10), ("cpu", "cpu", 10)], now=2)
    assert c.delete("/api/monitor/alerts").json()["deleted"] == 2
    assert c.get("/api/monitor/alerts").json()["items"] == []


def test_check_now_endpoint(c):
    assert isinstance(c.post("/api/monitor/alerts/check").json()["events"], list)


# ------------------------------------------------------------------ sensor parsers
def test_parse_nvidia_smi():
    g = hardware.parse_nvidia_smi("0, NVIDIA GeForce RTX 3060, 37, 2048, 12288, 61, 45.20, 30, 551.86\n")[0]
    assert g["name"] == "NVIDIA GeForce RTX 3060" and g["usage_percent"] == 37
    assert g["memory_percent"] == 16.7 and g["temperature_c"] == 61 and g["power_w"] == 45.2


def test_parse_nvidia_smi_handles_not_supported():
    g = hardware.parse_nvidia_smi("0, Quadro, [N/A], 100, 4096, 50, [N/A], [N/A], 1.0\n")[0]
    assert g["usage_percent"] is None and g["fan_percent"] is None and g["temperature_c"] == 50


def test_parse_windows_gpu():
    gpus = hardware.parse_windows_gpu({
        "adapters": [{"Name": "Intel(R) UHD Graphics 620", "AdapterRAM": 1073741824,
                      "DriverVersion": "31.0", "AdapterCompatibility": "Intel Corporation"},
                     {"Name": "Microsoft Basic Display Adapter"}],
        "util": 142.5, "dedicated": 268435456})
    assert len(gpus) == 1 and gpus[0]["usage_percent"] == 100.0       # clamped
    assert gpus[0]["memory_used_mb"] == 256 and gpus[0]["memory_total_mb"] == 1024


def test_parse_windows_temps_and_cpu_pick():
    s = hardware.parse_windows_temps({
        "hw": [{"Name": "CPU Package", "Identifier": "/intelcpu/0/temperature/6", "Value": 64.0},
               {"Name": "CPU Core #1", "Identifier": "/intelcpu/0/temperature/0", "Value": 70.0},
               {"Name": "GPU Core", "Identifier": "/nvidiagpu/0/temperature/0", "Value": 55}],
        "hw_source": "LibreHardwareMonitor",
        "zones": {"Name": "\\_TZ.TZ00", "HighPrecisionTemperature": 3232, "Temperature": 323}})
    assert {x["group"] for x in s} == {"cpu", "gpu", "acpi"}
    assert hardware.pick_cpu_temp(s) == 64.0                            # package beats hottest core
    acpi = [x for x in s if x["group"] == "acpi"][0]
    assert acpi["celsius"] == 50.1                                      # 323.2 K
    assert hardware.pick_cpu_temp([acpi]) == 50.1
    assert hardware.parse_windows_temps({"hw": [{"Name": "x", "Identifier": "/cpu", "Value": 999}]}) == []


# ------------------------------------------------------------------ WebSocket
def test_stream_rejects_bad_token_or_session(c):
    tok = c.headers["X-CyberHub-Token"]
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect("/api/monitor/stream?token=bad&session=" + c.session_token):
            pass
    assert e.value.code == 4401
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect(f"/api/monitor/stream?token={tok}&session=nope"):
            pass
    assert e.value.code == 4401
    c.post("/api/account/lock")
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect(f"/api/monitor/stream?token={tok}&session={c.session_token}"):
            pass
    assert e.value.code == 4423


def test_stream_pushes_monitor_frames(c):
    tok = c.headers["X-CyberHub-Token"]
    with c.websocket_connect(f"/api/monitor/stream?token={tok}&session={c.session_token}&top=3") as ws:
        f = ws.receive_json()
    assert f["type"] == "monitor" and len(f["cpu"]["per_core"]) == psutil.cpu_count()
    assert {"memory", "disk_io", "network", "health", "active_alerts", "cpu_temp_c"} <= f.keys()
    assert len(f["top_cpu"]) <= 3


def test_stream_check_does_not_count_as_activity(c):
    db = c.app.state.db
    db.execute("UPDATE sessions SET last_seen_at='2000-01-01T00:00:00.000Z'")
    c.app.state.accounts.authenticate(c.session_token, allow_locked=True, touch=False)
    assert db.fetchone("SELECT last_seen_at FROM sessions")["last_seen_at"].startswith("2000")


# ------------------------------------------------------------------ upgrade + info
def test_upgrade_from_part2_database_keeps_data(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path, isolation_level=None)
    con.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, description TEXT, applied_at TEXT)")
    for v, d, sql in MIGRATIONS[:3]:
        con.executescript(sql)
        con.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (v, d))
    con.execute("INSERT INTO metric_snapshots(cpu, memory, disk, net_sent, net_recv) VALUES (1,2,3,4,5)")
    con.close()
    db = Database(path)
    assert db.migrate() == MIGRATIONS[-1][0]          # upgrades all the way to the newest schema
    row = db.fetchone("SELECT * FROM metric_snapshots")
    assert row["cpu"] == 1 and row["cpu_temp"] is None
    assert db.fetchall("SELECT * FROM resource_alerts") == []
    db.close()


def test_info_reports_part3(c):
    j = c.get("/api/info").json()
    assert j["build_part"] >= 3 and "monitor" in j["available_modules"]
