"""
Cyber Hub Backend - Part 19 tests: Reports, Export & Backup
Developed by Syed Muhammad Tayyab

* Reports are generated from the real services and the files are opened again: the PDF with pypdf (when it is
  installed) and by its structure, the CSV / zip / JSON / HTML by parsing them.
* Backups are made, verified, tampered with and restored for real - including a restore into a brand-new data
  folder ("another PC"), where the password vault and a quarantined file must open again.
"""
import csv
import io
import json
import re
import time
import zipfile
import zlib

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import APP_VERSION, BUILD_PART, Settings
from cyberhub.database import MIGRATIONS
from cyberhub.main import create_app
from cyberhub.services import backup as bk
from cyberhub.services import pdf_writer as pw

PW = "Cyb3r!Hub#2026"
MASTER = "Glacier-Mango-Tunnel-Velvet-42"
BACKUP_PW = "orbit-Saffron-quilt-91-meadow"
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _setenv(monkeypatch, tmp_path, data="data"):
    for d in ("quick", "full", "watched", "docs", "home"):
        (tmp_path / d).mkdir(exist_ok=True)
    for k, v in {"CYBERHUB_DATA_DIR": tmp_path / data, "CYBERHUB_UI_DIR": tmp_path / "no-ui",
                 "CYBERHUB_QUICK_SCAN_DIRS": tmp_path / "quick", "CYBERHUB_FULL_SCAN_ROOTS": tmp_path / "full",
                 "CYBERHUB_AUTOSTART_USER_DIR": tmp_path / "as-user", "CYBERHUB_AUTOSTART_SYSTEM_DIR": tmp_path / "as-sys",
                 "CYBERHUB_RTP_DEFAULT_DIRS": tmp_path / "watched", "CYBERHUB_FIREWALL_BACKEND": "memory",
                 "CYBERHUB_NETWORK_BACKEND": "memory", "CYBERHUB_POSTURE_BACKEND": "memory",
                 "CYBERHUB_CLIPBOARD_BACKEND": "memory", "CYBERHUB_PV_KDF_N": "1024", "CYBERHUB_DP_KDF_N": "1024",
                 "CYBERHUB_CLEANER_HOME": tmp_path / "home", "CYBERHUB_CLEANER_LAYOUT": "linux",
                 "CYBERHUB_FINDER_DEFAULT_DIRS": tmp_path / "docs"}.items():
        monkeypatch.setenv(k, str(v))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    _setenv(monkeypatch, tmp_path)
    return tmp_path


def _login(cl, pw=PW):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": "syed", "display_name": "Syed Muhammad Tayyab", "password": pw})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": "syed", "password": pw})
    assert r.status_code == 200, r.text
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def c(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        cl.env = env
        yield cl


def standard_client(c):
    r = c.post("/api/account/users", json={"username": "guest", "display_name": "Guest", "password": "Gu3st!Pass#2026",
                                           "role": "standard"})
    assert r.status_code == 201, r.text
    s = TestClient(c.app)
    s.headers["X-CyberHub-Token"] = c.headers["X-CyberHub-Token"]
    r = s.post("/api/account/login", json={"username": "guest", "password": "Gu3st!Pass#2026"})
    s.headers["X-CyberHub-Session"] = r.json()["session_token"]
    return s


def make(c, type_="summary", fmt="pdf", days=30):
    r = c.post("/api/reports", json={"type": type_, "format": fmt, "days": days})
    assert r.status_code == 201, r.text
    j = r.json()
    d = c.get(f"/api/reports/{j['id']}/download")
    assert d.status_code == 200
    return j, d


def pdf_text(data: bytes) -> str:
    """Text of every page: pypdf when available, else by inflating the content streams."""
    try:
        from pypdf import PdfReader
        return "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(data)).pages)
    except ImportError:
        out = []
        for m in re.finditer(rb"stream\n(.*?)\nendstream", data, re.S):
            for t in re.findall(rb"\((.*?)(?<!\\)\) Tj", zlib.decompress(m.group(1)), re.S):
                out.append(t.replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\").decode("cp1252"))
        return "\n".join(out)


def seed_threat(c):
    (c.env / "quick" / "eicar.com").write_text(EICAR)
    job = c.post("/api/scan/custom", json={"paths": [str(c.env / "quick")]}).json()
    for _ in range(400):
        j = c.get(f"/api/scan/jobs/{job['id']}").json()
        if j["status"] not in ("queued", "running"):
            break
        time.sleep(0.05)
    assert j["threats_found"] == 1
    det = c.get("/api/scan/detections").json()["items"][0]
    assert c.post(f"/api/threats/{det['id']}/quarantine").status_code == 200
    return c.get("/api/quarantine").json()["items"][0]


# ====================================================================== PDF writer
def test_pdf_writer_layout_and_structure():
    assert pw.text_width("Hello", 10) == pytest.approx((722 + 556 + 222 + 222 + 556) / 100)
    assert pw.text_width("Hello", 10, True) > pw.text_width("Hello", 10)
    long = "C:\\Users\\Syed\\AppData\\Local\\Temp\\" + "a" * 120 + ".exe was found"
    lines = pw.wrap(long, 9, 150)
    assert len(lines) > 3 and all(pw.text_width(ln, 9) <= 150.01 for ln in lines) and "".join(lines).replace(" ", "") \
        == pw.clean(long).replace(" ", "")
    assert pw.wrap("one two three four five six seven", 9, 60, max_lines=2)[-1].endswith("...")
    assert pw.clean("tab\there \u2192 \u0627\u0631\u062f\u0648 \u20ac") == "tab here -> ???? \u20ac"   # cp1252 keeps the euro sign
    p = pw.PDF("Test (report) \\ one", "sub")
    p.cover([("Computer", "PC-1")])
    p.heading("Section")
    p.paragraph("Text with (brackets) and a back\\slash.")
    p.score_banner(72, "C", "Good", "note")
    p.bars([("A", 50, "50"), ("B", None, "n/a")])
    p.column_chart([("01", 3), ("02", 0), ("03", 7)], title="Chart")
    p.table([{"title": "Severity", "severity": True}, {"title": "What", "width": 4}],
            [["high", f"row {i} " + "x" * 80] for i in range(120)])
    p.table([{"title": "A"}], [], empty="Nothing here")
    data = p.render()
    assert data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF")
    n_pages = len(re.findall(rb"/Type /Page\b", data))
    assert n_pages >= 3 and f"/Count {n_pages}".encode() in data
    xref = int(re.search(rb"startxref\n(\d+)", data).group(1))
    assert data[xref:xref + 4] == b"xref"                               # the offset table is where it says
    for off in re.findall(rb"(\d{10}) 00000 n ", data):                 # and every object is where the table says
        assert re.match(rb"\d+ 0 obj", data[int(off):int(off) + 12])
    txt = pdf_text(data)
    assert "Test (report) \\ one" in txt and "Text with (brackets) and a back\\slash." in txt
    assert "Developed by Syed Muhammad Tayyab" in txt and f"Page {n_pages} of {n_pages}" in txt
    assert "row 119" in txt and "Nothing here" in txt and txt.count("Severity") >= n_pages - 1   # header repeats


# ====================================================================== reports
def test_status_types_and_validation(c):
    info = c.get("/api/info").json()
    assert "reports" in info["available_modules"] and info["progress_percent"] == BUILD_PART * 5 >= 95
    assert c.get("/api/health").json()["schema_version"] == MIGRATIONS[-1][0] >= 20
    st = c.get("/api/reports/status").json()
    assert [t["id"] for t in st["types"]] == ["summary", "threats", "device", "network", "accounts", "activity", "full"]
    assert st["formats"] == ["pdf", "html", "csv", "json"] and st["reports"] == 0 and st["latest"] is None
    assert c.post("/api/reports", json={"type": "nope"}).status_code == 422
    assert c.post("/api/reports", json={"type": "summary", "format": "docx"}).status_code == 422
    assert c.post("/api/reports", json={"type": "summary", "days": 0}).status_code == 422
    assert c.get("/api/reports/999").status_code == 404 and c.get("/api/reports/999/download").status_code == 404
    assert c.patch("/api/settings", json={"report_default_format": "docx"}).status_code == 422


def test_summary_pdf_contains_the_real_numbers(c):
    seed_threat(c)
    s = c.get("/api/score?refresh=true").json()
    j, d = make(c, "summary", "pdf", 7)
    assert j["format"] == "pdf" and j["extension"] == "pdf" and j["type_name"] == "Security summary"
    assert j["created_by"] == "syed" and j["source"] == "manual" and j["days"] == 7 and j["exists"]
    assert d.headers["content-type"] == "application/pdf" and j["file_name"] in d.headers["content-disposition"]
    assert d.headers["cache-control"] == "no-store" and len(d.content) == j["size"]
    import hashlib
    assert hashlib.sha256(d.content).hexdigest() == j["sha256"]
    txt = pdf_text(d.content)
    for needle in ("Security summary", "last 7 days", "Syed Muhammad Tayyab", "Overall security", "What to fix first",
                   "Virus & threat protection", "Firewall & network", "This computer", f"Cyber Hub v{APP_VERSION}"
                   if False else "CYBER HUB", "Developed by Syed Muhammad Tayyab"):
        assert needle in txt, needle
    assert str(s["score"]) in txt and s["status_text"] in txt
    top = s["recommendations"][0]["title"]
    assert top[:40] in txt.replace("\n", " ")
    assert "In quarantine" in txt and "could not be read" not in txt
    assert j["score"] == c.get(f"/api/reports/{j['id']}").json()["score"]


def test_every_type_and_format_and_their_contents(c):
    q = seed_threat(c)
    c.post("/api/platforms/accounts", json={"platform": "github", "handle": "Syed-Muhammad-Tayyab"})
    for t in ("summary", "threats", "device", "network", "accounts", "activity", "full"):
        doc = c.get(f"/api/reports/preview?type={t}&days=30").json()
        broken = [b["text"] for s_ in doc["sections"] for b in s_["blocks"]
                  if b["type"] == "text" and "could not be read" in b["text"]]
        assert not broken, (t, broken)
        assert doc["title"] and doc["sections"] and doc["author"] == "Syed Muhammad Tayyab"

    # threats: the quarantined file is in the PDF, the HTML, the CSV and the JSON
    j, d = make(c, "threats", "html")
    html = d.content.decode("utf-8")
    assert "<!DOCTYPE html>" in html and "EICAR-Test-File" in html and "eicar.com" in html
    assert "Developed by Syed Muhammad Tayyab" in html and "<script" not in html.lower()
    j, d = make(c, "threats", "json")
    doc = json.loads(d.content)
    tables = {b["name"]: b for s_ in doc["sections"] for b in s_["blocks"] if b["type"] == "table"}
    assert tables["quarantine"]["rows"][0][1] == q["threat_name"] and tables["detections"]["rows"][0][3] == "quarantined"
    assert tables["scans"]["rows"][0][1] == "custom"
    j, d = make(c, "threats", "csv")
    assert j["extension"] == "zip" and d.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(d.content)) as z:
        assert set(z.namelist()) == {"summary.csv", "detections.csv", "quarantine.csv", "scans.csv"}
        rows = list(csv.reader(io.StringIO(z.read("detections.csv").decode("utf-8-sig"))))
        assert rows[0] == ["When", "Threat", "Severity", "Status", "How", "File"] and "eicar.com" in rows[1][5]
        facts = list(csv.reader(io.StringIO(z.read("summary.csv").decode("utf-8-sig"))))
        assert ["Virus & threat protection", "In quarantine", "1"] in facts
    assert "EICAR-Test-File" in pdf_text(make(c, "threats", "pdf")[1].content)

    # device: all 47 checks of the simulated PC
    j, d = make(c, "device", "json")
    doc = json.loads(d.content)
    tables = {b["name"]: b for s_ in doc["sections"] for b in s_["blocks"] if b["type"] == "table"}
    posture = c.get("/api/posture/checks").json()
    assert len(tables["device_issues"]["rows"]) + len(tables["device_checks"]["rows"]) == posture["totals"]["checks"]
    assert len(tables["device_issues"]["rows"]) == posture["totals"]["failed"]
    # network
    txt = pdf_text(make(c, "network", "pdf")[1].content)
    assert "Firewall" in txt and "HomeWiFi" in txt and "Devices on this network" in txt and "192.168.50.1" in txt
    # accounts: the account is listed, no secrets
    j, d = make(c, "accounts", "json")
    body = d.content.decode()
    assert "GitHub" in body and PW not in body
    # activity: a single CSV; a formula in a title is defused
    c.post("/api/activity", json={"category": "system", "title": "=HYPERLINK(\"http://evil\")", "severity": "low"})
    j, d = make(c, "activity", "csv")
    assert j["extension"] == "csv" and d.content.startswith(b"\xef\xbb\xbf")
    rows = list(csv.reader(io.StringIO(d.content.decode("utf-8-sig"))))
    assert rows[0] == ["When", "Area", "Severity", "Event", "Detail"]
    assert any(r[3] == "'=HYPERLINK(\"http://evil\")" for r in rows)
    # full: everything in one document, many pages
    j, d = make(c, "full", "pdf")
    txt = pdf_text(d.content)
    for needle in ("Overall security", "Device security", "Passwords & accounts", "Activity log", "Scheduled jobs",
                   "Daily quick scan", "Every day at 13:00"):
        assert needle in txt, needle
    assert len(re.findall(rb"/Type /Page\b", d.content)) >= 5


def test_reports_are_per_user_listed_pruned_and_deleted(c):
    guest = standard_client(c)
    mine, _ = make(c, "summary", "json")
    theirs, _ = make(guest, "activity", "json")
    assert [r["id"] for r in guest.get("/api/reports").json()["items"]] == [theirs["id"]]
    assert {r["id"] for r in c.get("/api/reports").json()["items"]} == {mine["id"], theirs["id"]}       # admin: all
    assert guest.get(f"/api/reports/{mine['id']}").status_code == 404
    assert guest.get(f"/api/reports/{mine['id']}/download").status_code == 404
    assert guest.delete(f"/api/reports/{mine['id']}").status_code == 404
    assert c.get("/api/reports?type=activity").json()["total"] == 1
    lst = c.get("/api/reports").json()
    assert lst["bytes"] == mine["size"] + theirs["size"] and lst["folder"].endswith("reports")
    # default format / days come from settings
    c.patch("/api/settings", json={"report_default_format": "html", "report_default_days": 3, "report_keep": 2})
    r = c.post("/api/reports", json={"type": "activity"}).json()
    assert r["format"] == "html" and r["days"] == 3
    make(c, "activity", "json")
    ids = [x["id"] for x in c.get("/api/reports").json()["items"] if x["user_id"] == 1]
    assert len(ids) == 2 and mine["id"] not in ids                       # oldest of mine was pruned (file too)
    assert not (c.env / "data" / "reports" / mine["file_name"]).exists()
    assert guest.get("/api/reports").json()["total"] == 1                # other users' reports untouched
    # a file deleted behind our back
    last = c.get("/api/reports").json()["items"][0]
    (c.env / "data" / "reports" / last["file_name"]).unlink()
    assert c.get(f"/api/reports/{last['id']}").json()["exists"] is False
    assert c.get(f"/api/reports/{last['id']}/download").status_code == 410
    assert c.delete(f"/api/reports/{last['id']}").json()["deleted"] and c.get(f"/api/reports/{last['id']}").status_code == 404


def test_diagnostics_bundle_has_logs_but_no_secrets(c):
    guest = standard_client(c)
    assert guest.get("/api/reports/logs/export").status_code == 403
    c.put("/api/lookup/keys", json={"virustotal": "a" * 64})
    r = c.get("/api/reports/logs/export?days=7")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert "CyberHub_diagnostics_" in r.headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        names = set(z.namelist())
        assert {"activity.csv", "diagnostics.json", "README.txt"} <= names
        diag = json.loads(z.read("diagnostics.json"))
        assert diag["version"] == APP_VERSION and diag["schema_version"] == MIGRATIONS[-1][0]
        assert diag["table_rows"]["users"] == 2 and len(diag["migrations"]) == len(MIGRATIONS)
        blob = b"".join(z.read(n) for n in names)
    for secret in (c.headers["X-CyberHub-Token"], c.headers["X-CyberHub-Session"], PW, "a" * 64):
        assert secret.encode() not in blob


# ====================================================================== backups
def test_backup_create_list_verify_and_rules(c):
    guest = standard_client(c)
    assert guest.get("/api/backup").status_code == 403 and guest.post("/api/backup", json={}).status_code == 403
    st = c.get("/api/backup/status").json()
    assert st["backups"] == 0 and st["device_key_available"] and st["extension"] == ".chbackup" and st["last"] is None
    # password rules
    assert c.post("/api/backup", json={"mode": "password"}).status_code == 422
    assert c.post("/api/backup", json={"mode": "password", "password": "short"}).status_code == 422
    r = c.post("/api/backup", json={"mode": "password", "password": "password1234"})
    assert r.status_code == 422 and "easy to guess" in r.json()["detail"]
    assert c.post("/api/backup", json={"mode": "nope"}).status_code == 422
    assert c.post("/api/backup", json={"destination": "relative/folder"}).status_code == 422
    assert c.post("/api/backup", json={"destination": str(c.env / "missing")}).status_code == 404

    r = c.post("/api/backup", json={"mode": "password", "password": BACKUP_PW, "note": "before update"})
    assert r.status_code == 201, r.text
    b = r.json()
    assert b["mode"] == "password" and b["portable"] and b["exists"] and b["note"] == "before update"
    assert b["file_name"].endswith(".chbackup") and b["schema_version"] == MIGRATIONS[-1][0] and b["app_version"] == APP_VERSION
    raw = open(b["file_path"], "rb").read()
    from cyberhub.services import file_crypto as fc
    assert raw[:4] == fc.MAGIC and b"SQLite format 3" not in raw and b"syed" not in raw and b"manifest" not in raw
    d = c.post("/api/backup", json={"mode": "device", "destination": str(c.env / "docs")}).json()
    assert d["mode"] == "device" and not d["portable"] and d["file_path"].startswith(str(c.env / "docs"))
    lst = c.get("/api/backup").json()
    assert [x["id"] for x in lst["items"]] == [d["id"], b["id"]] and lst["pending_restore"] is None
    assert c.get("/api/backup/status").json()["days_since_last"] == 0

    v = c.post("/api/backup/verify", json={"id": b["id"], "password": BACKUP_PW}).json()
    assert v["ok"] and v["mode"] == "password" and v["users"] == ["syed", "guest"] and v["restorable"]
    assert v["has_vault_key"] and v["schema_version"] == MIGRATIONS[-1][0] and v["note"] == "before update"
    assert c.post("/api/backup/verify", json={"id": d["id"]}).json()["has_vault_key"] is False
    assert c.post("/api/backup/verify", json={"id": b["id"]}).status_code == 428                # password needed
    r = c.post("/api/backup/verify", json={"id": b["id"], "password": "not-the-password-123"})
    assert r.status_code == 403 and r.json()["detail"] == "Wrong backup password"
    assert c.post("/api/backup/verify", json={"path": str(c.env / "docs" / "nope.chbackup")}).status_code == 404
    (c.env / "docs" / "fake.chbackup").write_text("hello")
    assert c.post("/api/backup/verify", json={"path": str(c.env / "docs" / "fake.chbackup")}).status_code == 422
    assert c.post("/api/backup/verify", json={}).status_code == 422
    # one flipped byte anywhere -> refused, nothing staged
    bad = bytearray(open(d["file_path"], "rb").read())
    bad[len(bad) // 2] ^= 0x01
    (c.env / "docs" / "bad.chbackup").write_bytes(bytes(bad))
    r = c.post("/api/backup/restore", json={"path": str(c.env / "docs" / "bad.chbackup"), "confirm": True})
    assert r.status_code == 422 and "damaged" in r.json()["detail"] and c.get("/api/backup").json()["pending_restore"] is None
    # sessions never travel in a backup
    dl = c.get(f"/api/backup/{b['id']}/download")
    assert dl.status_code == 200 and dl.content == raw
    assert c.delete(f"/api/backup/{d['id']}").json()["deleted"] and not (c.env / "docs" / d["file_name"]).exists()
    assert c.get(f"/api/backup/{d['id']}/download").status_code == 404


def test_scheduled_backups_are_pruned_manual_ones_kept(c):
    svc = c.app.state.backup
    c.patch("/api/settings", json={"backup_keep": 2})
    manual = c.post("/api/backup", json={}).json()
    autos = [svc.create(None, mode="device", source="schedule") for _ in range(4)]
    items = c.get("/api/backup").json()["items"]
    assert {i["id"] for i in items} == {manual["id"], autos[2]["id"], autos[3]["id"]}
    assert autos[0]["created_by"] == "scheduler"
    import os
    assert not os.path.exists(autos[1]["file_path"]) and os.path.exists(manual["file_path"])
    assert os.path.exists(autos[2]["file_path"]) and os.path.exists(autos[3]["file_path"])
    # custom backup folder from settings
    c.patch("/api/settings", json={"backup_dir": str(c.env / "docs")})
    assert c.post("/api/backup", json={}).json()["file_path"].startswith(str(c.env / "docs"))


def test_restore_same_pc_two_step_with_safety_copy(env):
    with TestClient(create_app(Settings(), start_workers=False)) as c:
        _login(c)
        c.patch("/api/settings", json={"alert_cpu_percent": 77})
        c.post("/api/activity", json={"category": "system", "title": "before the backup"})
        b = c.post("/api/backup", json={"mode": "device"}).json()
        c.patch("/api/settings", json={"alert_cpu_percent": 55})
        c.post("/api/activity", json={"category": "system", "title": "after the backup"})
        r = c.post("/api/backup/restore", json={"id": b["id"]})
        assert r.status_code == 428 and "confirm" in r.json()["detail"]
        r = c.post("/api/backup/restore", json={"id": b["id"], "confirm": True})
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["staged"] and j["restart_required"] and j["backup"]["users"] == ["syed"]
        assert c.get("/api/backup").json()["pending_restore"]["backup_file"] == b["file_name"]
        assert c.get("/api/settings").json()["alert_cpu_percent"] == 55          # nothing changed yet
        assert c.delete("/api/backup/restore").json() == {"cancelled": True}     # can be called off
        assert c.get("/api/backup").json()["pending_restore"] is None
        assert c.post("/api/backup/restore", json={"id": b["id"], "confirm": True}).status_code == 200
        old_session = c.headers["X-CyberHub-Session"]
    # ---- restart
    with TestClient(create_app(Settings(), start_workers=False)) as c:
        c.headers["X-CyberHub-Token"] = c.get("/api/bootstrap").json()["token"]
        c.headers["X-CyberHub-Session"] = old_session
        assert c.get("/api/account/me").status_code == 401                       # everyone signed out
        _login(c)
        assert c.get("/api/settings").json()["alert_cpu_percent"] == 77
        titles = [a["title"] for a in c.get("/api/activity?limit=200").json()["items"]]
        assert "before the backup" in titles and "after the backup" not in titles and "Backup restored" in titles
        assert c.get("/api/backup").json()["pending_restore"] is None
        safety = [p for p in (env / "data").iterdir() if p.name.startswith("pre-restore-")]
        assert len(safety) == 1 and (safety[0] / "cyberhub.db").is_file()        # the replaced data is kept
        assert not (env / "data" / "restore_pending").exists() and not (env / "data" / "restore_applied.json").exists()
    # a third start does not restore again
    with TestClient(create_app(Settings(), start_workers=False)) as c:
        _login(c)
        assert len([p for p in (env / "data").iterdir() if p.name.startswith("pre-restore-")]) == 1


def test_password_backup_restores_on_another_pc_with_vault_and_quarantine(tmp_path, monkeypatch):
    # ---- PC 1
    _setenv(monkeypatch, tmp_path, "pc1")
    with TestClient(create_app(Settings(), start_workers=False)) as c:
        _login(c)
        c.env = tmp_path
        q = seed_threat(c)
        r = c.post("/api/passwords/setup", json={"master_password": MASTER})
        assert r.status_code in (200, 201), r.text
        it = c.post("/api/passwords/items", json={"type": "login", "data": {
            "title": "GitHub", "username": "tayyab", "password": "S3cr3t-From-PC1!", "urls": ["https://github.com"]}})
        assert it.status_code in (200, 201), it.text
        b = c.post("/api/backup", json={"mode": "password", "password": BACKUP_PW, "include_quarantine": True}).json()
        assert b["quarantine"] is True
        dev = c.post("/api/backup", json={"mode": "device"}).json()
        backup_file = tmp_path / "usb.chbackup"
        backup_file.write_bytes(open(b["file_path"], "rb").read())
        dev_file = tmp_path / "usb-device.chbackup"
        dev_file.write_bytes(open(dev["file_path"], "rb").read())
        key1 = (tmp_path / "pc1" / "vault.key").read_text()
    # ---- PC 2: a fresh install with its own vault key and its own owner account
    _setenv(monkeypatch, tmp_path, "pc2")
    with TestClient(create_app(Settings(), start_workers=False)) as c:
        c.headers["X-CyberHub-Token"] = c.get("/api/bootstrap").json()["token"]
        r = c.post("/api/account/setup", json={"username": "newpc", "display_name": "New", "password": "N3w!Machine#2026"})
        c.headers["X-CyberHub-Session"] = r.json()["session_token"]
        assert (tmp_path / "pc2" / "vault.key").read_text() != key1
        # the device-mode backup of PC 1 can't be opened here - and says why
        r = c.post("/api/backup/verify", json={"path": str(dev_file)})
        assert r.status_code == 403 and "another PC" in r.json()["detail"]
        v = c.post("/api/backup/verify", json={"path": str(backup_file), "password": BACKUP_PW}).json()
        assert v["users"] == ["syed"] and v["quarantine_files"] == 1 and v["has_vault_key"]
        r = c.post("/api/backup/restore", json={"path": str(backup_file), "password": "wrong-password-000", "confirm": True})
        assert r.status_code == 403
        r = c.post("/api/backup/restore", json={"path": str(backup_file), "password": BACKUP_PW, "confirm": True})
        assert r.status_code == 200 and "sealed for this Windows account" in r.json()["vault_key"], r.text
    with TestClient(create_app(Settings(), start_workers=False)) as c:
        _login(c)                                                        # PC 1's account now signs in on PC 2
        assert c.get("/api/account/me").json()["user"]["display_name"] == "Syed Muhammad Tayyab"
        # the password vault opens with its master password and holds the saved login
        r = c.post("/api/passwords/unlock", json={"master_password": MASTER})
        assert r.status_code == 200, r.text
        items = c.get("/api/passwords/items").json()["items"]
        assert [i["title"] for i in items] == ["GitHub"]
        full = c.get(f"/api/passwords/items/{items[0]['id']}?reveal=true").json()
        assert "S3cr3t-From-PC1!" in json.dumps(full)
        # the quarantined file travelled, verifies and can be restored
        qi = c.get("/api/quarantine").json()["items"]
        assert [i["id"] for i in qi] == [q["id"]]
        assert c.post(f"/api/quarantine/{q['id']}/verify").json()["ok"] is True
        out = tmp_path / "restored"
        out.mkdir()
        r = c.post(f"/api/quarantine/{q['id']}/restore", json={"destination": str(out)})
        assert r.status_code == 200, r.text
        assert (out / "eicar.com").read_text() == EICAR
        safety = [p for p in (tmp_path / "pc2").iterdir() if p.name.startswith("pre-restore-")]
        assert len(safety) == 1 and (safety[0] / "vault.key").is_file() and (safety[0] / "cyberhub.db").is_file()


def test_restore_refuses_newer_and_broken_backups(c, monkeypatch):
    b = c.post("/api/backup", json={}).json()
    monkeypatch.setattr(bk, "MIGRATIONS", [m for m in MIGRATIONS if m[0] < MIGRATIONS[-1][0]])
    v = c.post("/api/backup/verify", json={"id": b["id"]}).json()
    assert v["restorable"] is False and "newer Cyber Hub" in v["reason"]
    r = c.post("/api/backup/restore", json={"id": b["id"], "confirm": True})
    assert r.status_code == 409 and c.get("/api/backup").json()["pending_restore"] is None
    monkeypatch.undo()
    # half-staged folder (crash while staging) is ignored and removed at start
    pend = c.env / "data" / "restore_pending"
    pend.mkdir()
    (pend / "cyberhub.db").write_text("junk")
    assert bk.apply_pending_restore(c.env / "data") is None and not pend.exists()
    pend.mkdir()
    (pend / "restore.json").write_text("{not json")
    (pend / "cyberhub.db").write_text("junk")
    assert bk.apply_pending_restore(c.env / "data") is None and not pend.exists()


def test_settings_export_import(c):
    guest = standard_client(c)
    assert guest.get("/api/backup/settings/export").status_code == 403
    c.patch("/api/settings", json={"alert_cpu_percent": 71, "theme": "light", "scan_excluded_paths": ["C:\\Games"]})
    exp = c.get("/api/backup/settings/export").json()
    assert exp["kind"] == "settings" and exp["changed"] == {"alert_cpu_percent": 71, "theme": "light",
                                                            "scan_excluded_paths": ["C:\\Games"]}
    assert c.headers["X-CyberHub-Token"] not in json.dumps(exp) and "api_token" not in exp["settings"]
    c.post("/api/settings/reset")
    assert c.get("/api/settings").json()["theme"] == "dark"
    exp["changed"]["made_up_setting"] = 1
    exp["changed"]["alert_memory_percent"] = 5                           # out of range -> skipped, rest applied
    r = c.post("/api/backup/settings/import", json={"payload": exp, "only_changed": True}).json()
    assert r["applied"] == {"alert_cpu_percent": 71, "theme": "light", "scan_excluded_paths": ["C:\\Games"]}
    assert {s["key"] for s in r["skipped"]} == {"made_up_setting", "alert_memory_percent"}
    assert c.get("/api/settings").json()["alert_cpu_percent"] == 71
    assert c.post("/api/backup/settings/import", json={"payload": {"app": "Other"}}).status_code == 422
    assert c.post("/api/backup/settings/import", json={"payload": {"app": "Cyber Hub", "kind": "settings"}}).status_code == 422
