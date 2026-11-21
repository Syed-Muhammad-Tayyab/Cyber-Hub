"""
Cyber Hub Backend - Part 5 tests: Antivirus Scan Engine
Developed by Syed Muhammad Tayyab

The EICAR test string is assembled at runtime (services.malware_db.EICAR) so
this file never trips a real antivirus.
"""
import hashlib
import io
import os
import sqlite3
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services.malware_db import EICAR, parse_hash_list
from cyberhub.services.platform_tools import CACHE

PW = "Cyb3r!Hub#2026"
EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    quick = tmp_path / "quick"; quick.mkdir()
    full = tmp_path / "full"; full.mkdir()
    (full / "a.txt").write_text("hello")
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    monkeypatch.setenv("CYBERHUB_QUICK_SCAN_DIRS", str(quick))
    monkeypatch.setenv("CYBERHUB_FULL_SCAN_ROOTS", str(full))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_USER_DIR", str(tmp_path / "as-user"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_SYSTEM_DIR", str(tmp_path / "as-sys"))
    return tmp_path


@pytest.fixture()
def c(env):
    CACHE.clear()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        r = cl.post("/api/account/setup", json={"username": "syed", "display_name": "Syed", "password": PW})
        cl.headers["X-CyberHub-Session"] = r.json()["session_token"]
        yield cl
    CACHE.clear()


def wait(c, jid, until=("completed", "cancelled", "failed"), timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        j = c.get(f"/api/scan/jobs/{jid}").json()
        if j["status"] in until:
            return j
        time.sleep(0.05)
    raise AssertionError(f"job {jid} stuck in {j['status']}")


def make_zip(entries: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, data in entries.items():
            z.writestr(n, data)
    return b.getvalue()


@pytest.fixture()
def sample(env):
    d = env / "sample"
    (d / "sub").mkdir(parents=True)
    (d / "eicar.com").write_bytes(EICAR)                         # hash + pattern
    (d / "eicar_copy.txt").write_bytes(EICAR + b"\r\n")         # pattern only (hash differs)
    (d / "clean.txt").write_text("nothing to see here")
    (d / "sub" / "photos.zip").write_bytes(make_zip({"a.txt": b"hi", "x/eicar.com": EICAR}))
    (d / "sub" / "nested.zip").write_bytes(make_zip({"inner.zip": make_zip({"deep.com": EICAR})}))
    (d / "custom_bad.bin").write_bytes(b"pretend this is ransomware")
    (d / "excluded").mkdir()
    (d / "excluded" / "eicar.com").write_bytes(EICAR)
    (d / "skip.iso").write_bytes(EICAR)
    (d / "big.dat").write_bytes(b"\0" * (2 * 1024 * 1024))
    return d


# ================================================================== access
def test_access_rules(c):
    assert c.get("/api/scan/summary", headers={"X-CyberHub-Session": ""}).status_code == 401
    c.post("/api/account/users", json={"username": "kid", "display_name": "K", "password": PW, "role": "standard"})
    h = {"X-CyberHub-Session": c.post("/api/account/login", json={"username": "kid", "password": PW}).json()["session_token"]}
    r = c.post("/api/scan/quick", headers=h)                       # standard users may scan
    assert r.status_code == 202 and r.json()["started_by"] == "kid"
    wait(c, r.json()["id"])
    assert c.post("/api/scan/signatures/import", headers=h, json={"text": EICAR_SHA}).status_code == 403
    assert c.post("/api/scan/signatures", headers=h, json={"hash": "a" * 64, "name": "x"}).status_code == 403
    assert c.put("/api/scan/exclusions", headers=h, json={"paths": []}).status_code == 403


def test_self_test_and_lookup(c):
    j = c.post("/api/scan/self-test").json()
    assert j["passed"] and all(j["checks"].values())
    r = c.post("/api/scan/lookup", json={"hash": EICAR_SHA.upper()}).json()
    assert r["known_malware"] and r["hash_type"] == "sha256" and "EICAR" in r["signature"]["name"]
    assert c.post("/api/scan/lookup", json={"hash": "44d88612fea8a8f36de82e1278abb02f"}).json()["known_malware"]
    assert not c.post("/api/scan/lookup", json={"hash": "0" * 64}).json()["known_malware"]
    assert c.post("/api/scan/lookup", json={"hash": "z" * 64}).status_code == 422


# ================================================================== the main scan
def test_custom_scan_finds_everything(c, sample):
    bad_sha = hashlib.sha256(b"pretend this is ransomware").hexdigest()
    assert c.post("/api/scan/signatures", json={"hash": bad_sha, "name": "Ransom.Test", "severity": "critical"}).status_code == 201
    c.put("/api/scan/exclusions", json={"paths": [str(sample / "excluded")], "extensions": ["ISO"]})
    c.patch("/api/settings", json={"scan_max_file_mb": 1})

    r = c.post("/api/scan/custom", json={"paths": [str(sample)]})
    assert r.status_code == 202
    j = wait(c, r.json()["id"])
    assert j["status"] == "completed" and j["percent"] == 100.0
    assert j["files_scanned"] == 6                                # 9 files - excluded dir - .iso - too big
    assert j["skipped_by_reason"] == {"excluded_type": 1, "too_large": 1}
    assert j["archive_entries"] >= 4 and j["threats_found"] == 5

    dets = c.get(f"/api/scan/jobs/{j['id']}/detections").json()["items"]
    found = {(os.path.basename(d["path"]), d["archive_member"], d["method"]) for d in dets}
    assert ("eicar.com", None, "hash") in found
    assert ("eicar_copy.txt", None, "pattern") in found
    assert ("photos.zip", "x/eicar.com", "hash") in found
    assert ("nested.zip", "inner.zip > deep.com", "hash") in found
    assert ("custom_bad.bin", None, "hash") in found
    assert next(d for d in dets if d["path"].endswith("custom_bad.bin"))["severity"] == "critical"

    s = c.get("/api/scan/summary").json()
    assert s["status"] == "action_needed" and s["active_threats"] == 5
    assert s["active_by_severity"]["critical"] == 1 and s["last_by_kind"]["custom"]["id"] == j["id"]
    assert s["by_day"] and s["by_day"][-1]["threats"] == 5
    acts = c.get("/api/activity?category=threat").json()["items"]
    assert len(acts) == 5 and any(a["severity"] == "critical" for a in acts)


def test_rescan_uses_cache_and_supersedes(c, sample):
    j1 = wait(c, c.post("/api/scan/custom", json={"paths": [str(sample)]}).json()["id"])
    j2 = wait(c, c.post("/api/scan/custom", json={"paths": [str(sample)]}).json()["id"])
    assert j2["files_scanned"] == j1["files_scanned"]
    # second run reads only archive contents again, never the whole files
    assert j2["bytes_scanned"] < j1["bytes_scanned"]
    assert c.get("/api/scan/summary").json()["active_threats"] == j1["threats_found"]   # not doubled
    assert c.get("/api/scan/detections?status=superseded").json()["total"] == j1["threats_found"]


def test_deleted_or_cleaned_files_resolve(c, sample):
    wait(c, c.post("/api/scan/custom", json={"paths": [str(sample)]}).json()["id"])
    before = c.get("/api/scan/summary").json()["active_threats"]
    (sample / "eicar.com").unlink()                                # removed by the user
    (sample / "eicar_copy.txt").write_text("cleaned")              # file cleaned in place
    wait(c, c.post("/api/scan/custom", json={"paths": [str(sample)]}).json()["id"])
    assert c.get("/api/scan/summary").json()["active_threats"] == before - 2
    assert c.get("/api/scan/detections?status=resolved").json()["total"] == 2


def test_quick_and_full_scan(c, env):
    (env / "quick" / "dropper.com").write_bytes(EICAR)
    j = wait(c, c.post("/api/scan/quick").json()["id"])
    assert j["status"] == "completed" and j["threats_found"] == 1
    labels = {t["label"] for t in j["targets"]}
    assert "Running program / startup item" in labels             # running programs are included
    assert j["files_scanned"] >= 2
    f = wait(c, c.post("/api/scan/full").json()["id"])
    assert f["status"] == "completed" and f["files_scanned"] == 1 and f["threats_found"] == 0
    loc = c.get("/api/scan/locations").json()
    assert loc["full"] == [str(env / "full")] and loc["quick"][0]["path"] == str(env / "quick")


# ================================================================== job control
@pytest.fixture()
def many(env):
    d = env / "many"
    d.mkdir()
    for i in range(400):
        (d / f"f{i}.txt").write_text(f"file {i}")
    return d


def test_pause_resume_cancel(c, many):
    c.app.state.scanner.per_file_delay = 0.01
    jid = c.post("/api/scan/custom", json={"paths": [str(many)]}).json()["id"]
    time.sleep(0.6)
    p = c.post(f"/api/scan/jobs/{jid}/pause").json()
    assert p["status"] == "paused"
    time.sleep(0.2)
    n = c.get(f"/api/scan/jobs/{jid}").json()["files_scanned"]
    time.sleep(0.5)
    still = c.get(f"/api/scan/jobs/{jid}").json()
    assert still["status"] == "paused" and still["files_scanned"] == n            # really stopped
    assert c.post(f"/api/scan/jobs/{jid}/pause").status_code == 409
    assert c.post(f"/api/scan/jobs/{jid}/resume").json()["status"] == "running"
    time.sleep(0.3)
    assert c.get(f"/api/scan/jobs/{jid}").json()["files_scanned"] > n
    x = c.post(f"/api/scan/jobs/{jid}/cancel").json()
    assert x["status"] == "cancelled" and x["files_scanned"] < 400
    row = c.get(f"/api/scan/jobs/{jid}").json()
    assert row["status"] == "cancelled" and row["message"] == "Cancelled by user"
    assert c.post(f"/api/scan/jobs/{jid}/resume").status_code == 409


def test_queue_and_duplicates(c, many):
    c.app.state.scanner.per_file_delay = 0.01
    a = c.post("/api/scan/custom", json={"paths": [str(many)]}).json()
    b = c.post("/api/scan/quick").json()
    assert b["status"] == "queued"
    assert c.post("/api/scan/quick").status_code == 409                       # one quick scan at a time
    act = c.get("/api/scan/jobs/active").json()["items"]
    assert [j["id"] for j in act] == [a["id"], b["id"]]
    assert c.post(f"/api/scan/jobs/{b['id']}/cancel").json()["status"] == "cancelled"
    assert c.delete(f"/api/scan/jobs/{a['id']}").status_code == 409           # still running
    c.post(f"/api/scan/jobs/{a['id']}/cancel")
    assert c.delete(f"/api/scan/jobs/{a['id']}").json() == {"deleted": 1}
    assert c.get(f"/api/scan/jobs/{a['id']}").status_code == 404


def test_custom_validation(c, env):
    assert c.post("/api/scan/custom", json={"paths": []}).status_code == 422
    assert c.post("/api/scan/custom", json={"paths": ["relative/path"]}).status_code == 422
    assert c.post("/api/scan/custom", json={"paths": [str(env / "nope")]}).status_code == 404
    assert c.post("/api/scan/jobs/999/pause").status_code == 404


def test_websocket_progress_and_events(c, many):
    (many / "evil.com").write_bytes(EICAR)
    c.app.state.scanner.per_file_delay = 0.003
    tok, ses = c.headers["X-CyberHub-Token"], c.headers["X-CyberHub-Session"]
    with c.websocket_connect(f"/api/scan/stream?token={tok}&session={ses}") as ws:
        assert ws.receive_json()["hello"] is True
        jid = c.post("/api/scan/custom", json={"paths": [str(many)]}).json()["id"]
        types, saw_progress = [], False
        for _ in range(80):
            m = ws.receive_json()
            types += [e["type"] for e in m["events"]]
            saw_progress |= any(j["id"] == jid and j["phase"] == "scanning" and j["percent"] is not None
                                for j in m["jobs"])
            if "job_finished" in types:
                break
    assert {"job_queued", "job_started", "threat", "job_finished"} <= set(types) and saw_progress
    with pytest.raises(Exception):
        with c.websocket_connect(f"/api/scan/stream?token=bad&session={ses}") as ws:
            ws.receive_json()


# ================================================================== on-demand + detections
def test_scan_single_file_and_dismiss(c, sample):
    r = c.post("/api/scan/file", json={"path": str(sample / "sub" / "photos.zip")}).json()
    assert r["status"] == "infected" and r["detections"][0]["archive_member"] == "x/eicar.com"
    assert r["detections"][0]["id"] and r["detections"][0]["job_id"] is None
    clean = c.post("/api/scan/file", json={"path": str(sample / "clean.txt")}).json()
    assert clean["status"] == "clean" and clean["sha256"] == hashlib.sha256(b"nothing to see here").hexdigest()
    assert c.post("/api/scan/file", json={"path": str(sample)}).status_code == 422
    did = r["detections"][0]["id"]
    d = c.post(f"/api/scan/detections/{did}/dismiss").json()
    assert d["status"] == "dismissed" and d["status_by"] == "syed"
    assert c.post(f"/api/scan/detections/{did}/dismiss").status_code == 409
    assert c.get("/api/scan/summary").json()["status"] != "action_needed"


# ================================================================== signature database
def test_parse_hash_list_formats():
    a, b = "a" * 64, "b" * 32
    plain, bad = parse_hash_list(f"{a}\n\n# comment\nnot-a-hash\n{b}\n")
    assert {e["hash"] for e in plain} == {a, b} and bad == 1
    csv_, _ = parse_hash_list(f"sha256,name\n{a},Trojan.Foo\n")
    assert csv_[0]["name"] == "Trojan.Foo"
    sums, _ = parse_hash_list(f"{a}  *evil.exe\n")
    assert sums[0]["name"] == "evil.exe"
    mb = ('# MalwareBazaar export\n# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter",'
          '"file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"\n'
          f'"2026-11-01 10:00:00","{a}","{b}","{"c" * 40}","abuse_ch","x.exe","exe","app/x","AgentTesla",'
          '"n/a","10","n/a","n/a","n/a"\n')
    rows, _ = parse_hash_list(mb)
    assert rows == [{"hash": a, "hash_type": "sha256", "name": "AgentTesla"}]


def test_import_disable_delete(c, env, sample):
    shas = [hashlib.sha256(f"x{i}".encode()).hexdigest() for i in range(50)]
    r = c.post("/api/scan/signatures/import", json={"text": "\n".join(shas), "label": "feed1"}).json()
    assert r["added"] == 50 and r["source"] == "import:feed1"
    again = c.post("/api/scan/signatures/import", json={"text": "\n".join(shas), "label": "feed1"}).json()
    assert again["added"] == 0
    zf = env / "full_sha256.zip"
    zf.write_bytes(make_zip({"full_sha256.txt": "# header\n" + "\n".join(
        hashlib.sha256(f"y{i}".encode()).hexdigest() for i in range(20))}))
    z = c.post("/api/scan/signatures/import", json={"path": str(zf)}).json()
    assert z["added"] == 20 and z["source"] == "import:full_sha256.zip/full_sha256.txt"
    st = c.get("/api/scan/signatures/stats").json()
    assert st["total"] == 73 and st["by_source"]["import"] == 70 and st["by_source"]["builtin"] == 3
    assert c.get("/api/scan/signatures?search=feed").json()["total"] == 0          # search is by hash / name
    assert c.get("/api/scan/signatures?source=import:feed1").json()["total"] == 50
    assert c.delete("/api/scan/signatures?source=import:feed1").json()["deleted"] == 50
    assert c.post("/api/scan/signatures/import", json={"text": "nothing here"}).status_code == 422
    assert c.post("/api/scan/signatures/import", json={}).status_code == 422

    # built-ins: can be disabled, never deleted. Disabled hash -> the byte pattern still catches EICAR.
    assert c.delete(f"/api/scan/signatures/{EICAR_SHA}").status_code == 403
    for h in (EICAR_SHA, "44d88612fea8a8f36de82e1278abb02f", "3395856ce81f2b7382dee72602f798b642f14140"):
        assert c.patch(f"/api/scan/signatures/{h}", json={"enabled": False}).json()["enabled"] is False
    r = c.post("/api/scan/file", json={"path": str(sample / "eicar.com")}).json()
    assert r["status"] == "infected" and r["detections"][0]["method"] == "pattern"


def test_exclusion_validation(c, env):
    root = os.path.abspath(os.sep)
    assert c.put("/api/scan/exclusions", json={"paths": [root]}).status_code == 422
    assert c.put("/api/scan/exclusions", json={"paths": ["rel/dir"]}).status_code == 422
    assert c.put("/api/scan/exclusions", json={"extensions": ["e x e"]}).status_code == 422
    j = c.put("/api/scan/exclusions", json={"paths": [str(env)], "extensions": ["VHDX", ".iso", "iso"]}).json()
    assert j == {"paths": [str(env)], "extensions": [".vhdx", ".iso"]}
    assert c.patch("/api/settings", json={"scan_excluded_paths": [1, 2]}).status_code in (400, 422)
    assert c.delete("/api/scan/cache").status_code == 200


# ================================================================== lifecycle
def test_unfinished_jobs_marked_interrupted(env):
    s = Settings()
    s.ensure_dirs()
    db = Database(s.db_path)
    db.migrate()
    db.execute("INSERT INTO scan_jobs(kind, status, targets) VALUES ('full','running','[]')")
    db.close()
    CACHE.clear()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        cl.headers["X-CyberHub-Session"] = cl.post("/api/account/setup", json={
            "username": "syed", "display_name": "S", "password": PW}).json()["session_token"]
        j = cl.get("/api/scan/jobs/1").json()
        assert j["status"] == "interrupted"


def test_shutdown_stops_running_scan(env, many):
    CACHE.clear()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        cl.headers["X-CyberHub-Session"] = cl.post("/api/account/setup", json={
            "username": "syed", "display_name": "S", "password": PW}).json()["session_token"]
        cl.app.state.scanner.per_file_delay = 0.05
        cl.post("/api/scan/custom", json={"paths": [str(many)]})
        time.sleep(0.3)
    db = Database(Settings().db_path)
    assert db.fetchone("SELECT status FROM scan_jobs WHERE id=1")["status"] == "interrupted"
    db.close()


def test_migration_from_v5(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, description TEXT, applied_at TEXT)")
    for v, d, sql in MIGRATIONS[:5]:
        con.executescript(sql)
        con.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (v, d))
    con.commit(); con.close()
    db = Database(path)
    assert db.migrate() >= 6
    names = {r["name"] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"malware_signatures", "scan_jobs", "scan_detections", "file_hash_cache"} <= names
    db.close()


def test_info_reports_part5(c):
    j = c.get("/api/info").json()
    assert j["build_part"] >= 5 and j["progress_percent"] >= 25 and "scanner" in j["available_modules"]
    assert c.get("/api/health").json()["schema_version"] >= 6
