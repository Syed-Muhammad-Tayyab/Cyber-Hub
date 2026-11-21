"""
Cyber Hub Backend - Part 2 tests: Account & Login
Developed by Syed Muhammad Tayyab
"""
import pytest
from fastapi.testclient import TestClient

from cyberhub.config import Settings
from cyberhub.main import create_app

PW = "Cyb3r!Hub#2026"


@pytest.fixture()
def c(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        yield cl


def setup(c, username="syed", password=PW):
    r = c.post("/api/account/setup", json={"username": username, "display_name": "Syed", "password": password})
    assert r.status_code == 201, r.text
    return r.json()


def auth(tok):
    return {"X-CyberHub-Session": tok}


def test_status_then_setup(c):
    assert c.get("/api/account/status").json()["setup_required"] is True
    j = setup(c)
    assert j["session_token"] and j["user"]["username"] == "syed" and j["user"]["role"] == "admin"
    assert c.get("/api/account/status").json()["has_account"] is True
    assert c.post("/api/account/setup", json={"username": "x2", "password": PW}).status_code == 409


def test_weak_password_and_bad_username_rejected(c):
    assert c.post("/api/account/setup", json={"username": "syed", "password": "password1"}).status_code == 422
    assert c.post("/api/account/setup", json={"username": "a", "password": PW}).status_code == 422
    assert c.post("/api/account/setup", json={"username": "bad name!", "password": PW}).status_code == 422


def test_password_strength_meter(c):
    weak = c.post("/api/account/password-strength", json={"password": "123456"}).json()
    strong = c.post("/api/account/password-strength", json={"password": "Tr0ub4dor&3-Horse!"}).json()
    assert weak["score"] == 0 and weak["feedback"]
    assert strong["score"] >= 3


def test_login_logout_me(c):
    setup(c)
    assert c.post("/api/account/login", json={"username": "syed", "password": "wrong"}).status_code == 401
    assert c.post("/api/account/login", json={"username": "ghost", "password": PW}).status_code == 401
    tok = c.post("/api/account/login", json={"username": "SYED", "password": PW}).json()["session_token"]
    assert c.get("/api/account/me", headers=auth(tok)).json()["user"]["username"] == "syed"
    assert c.post("/api/account/logout", headers=auth(tok)).status_code == 200
    assert c.get("/api/account/me", headers=auth(tok)).status_code == 401
    assert c.get("/api/account/me").status_code == 401


def test_session_token_not_stored_in_plain(c):
    tok = setup(c)["session_token"]
    rows = c.app.state.db.fetchall("SELECT token_hash FROM sessions")
    assert all(tok not in r["token_hash"] for r in rows)
    pwrow = c.app.state.db.fetchone("SELECT password_hash FROM users")
    assert pwrow["password_hash"].startswith("scrypt$") and PW not in pwrow["password_hash"]


def test_bruteforce_lockout(c):
    setup(c)
    for _ in range(5):
        assert c.post("/api/account/login", json={"username": "syed", "password": "nope"}).status_code == 401
    r = c.post("/api/account/login", json={"username": "syed", "password": PW})
    assert r.status_code == 423  # locked even with the right password
    events = c.get("/api/activity?category=account&severity=high").json()
    assert events["total"] >= 1


def test_lock_unlock_with_pin(c):
    tok = setup(c)["session_token"]
    h = auth(tok)
    assert c.put("/api/account/pin", headers=h, json={"password": PW, "pin": "1234"}).status_code == 422  # too easy
    assert c.put("/api/account/pin", headers=h, json={"password": PW, "pin": "4829"}).status_code == 200
    assert c.post("/api/account/lock", headers=h).status_code == 200
    assert c.get("/api/account/sessions", headers=h).status_code == 423        # locked
    assert c.get("/api/account/me", headers=h).json()["session"]["is_locked"] is True
    assert c.post("/api/account/unlock", headers=h, json={"pin": "0000"}).status_code == 401
    assert c.post("/api/account/unlock", headers=h, json={"pin": "4829"}).status_code == 200
    assert c.get("/api/account/sessions", headers=h).status_code == 200


def test_pin_login(c):
    tok = setup(c)["session_token"]
    c.put("/api/account/pin", headers=auth(tok), json={"password": PW, "pin": "4829"})
    assert c.post("/api/account/login", json={"username": "syed", "pin": "4829"}).status_code == 200
    assert c.post("/api/account/login", json={"username": "syed", "pin": "9999"}).status_code == 401
    assert c.post("/api/account/login", json={"username": "syed", "pin": "4829", "password": PW}).status_code == 422


def test_auto_lock_after_idle(c):
    tok = setup(c)["session_token"]
    c.app.state.db.execute("UPDATE sessions SET last_seen_at='2000-01-01T00:00:00.000Z'")
    assert c.get("/api/account/sessions", headers=auth(tok)).status_code == 423


def test_expired_session(c):
    tok = setup(c)["session_token"]
    c.app.state.db.execute("UPDATE sessions SET expires_at='2000-01-01T00:00:00.000Z'")
    assert c.get("/api/account/me", headers=auth(tok)).status_code == 401


def test_change_password_revokes_other_sessions(c):
    t1 = setup(c)["session_token"]
    t2 = c.post("/api/account/login", json={"username": "syed", "password": PW}).json()["session_token"]
    new = "N3w!Secure#Pass"
    assert c.post("/api/account/change-password", headers=auth(t1),
                  json={"current_password": "bad", "new_password": new}).status_code == 401
    r = c.post("/api/account/change-password", headers=auth(t1), json={"current_password": PW, "new_password": new})
    assert r.json()["other_sessions_signed_out"] == 1
    assert c.get("/api/account/me", headers=auth(t2)).status_code == 401
    assert c.get("/api/account/me", headers=auth(t1)).status_code == 200
    assert c.post("/api/account/login", json={"username": "syed", "password": new}).status_code == 200


def test_recovery_codes(c):
    tok = setup(c)["session_token"]
    codes = c.post("/api/account/recovery-codes", headers=auth(tok), json={"password": PW}).json()["codes"]
    assert len(codes) == 8
    new = "Rec0vered!Pass#1"
    r = c.post("/api/account/recover", json={"username": "syed", "recovery_code": codes[0].lower(), "new_password": new})
    assert r.status_code == 200
    assert c.get("/api/account/me", headers=auth(tok)).status_code == 401          # old sessions revoked
    again = c.post("/api/account/recover", json={"username": "syed", "recovery_code": codes[0], "new_password": new})
    assert again.status_code == 401                                                # one-time use
    assert c.get("/api/account/recovery-codes", headers=auth(r.json()["session_token"])).json()["remaining"] == 7


def test_sessions_list_and_revoke(c):
    t1 = setup(c)["session_token"]
    t2j = c.post("/api/account/login", json={"username": "syed", "password": PW, "device": "Laptop"}).json()
    lst = c.get("/api/account/sessions", headers=auth(t1)).json()
    assert len(lst) == 2 and sum(s["current"] for s in lst) == 1
    assert c.delete(f"/api/account/sessions/{t2j['session_id']}", headers=auth(t1)).status_code == 200
    assert c.get("/api/account/me", headers=auth(t2j["session_token"])).status_code == 401
    assert c.delete("/api/account/sessions/9999", headers=auth(t1)).status_code == 404


def test_profile_and_history(c):
    tok = setup(c)["session_token"]
    c.post("/api/account/login", json={"username": "syed", "password": "bad"})
    u = c.patch("/api/account/me", headers=auth(tok), json={"display_name": "Syed M. Tayyab", "email": "s@example.com"}).json()
    assert u["display_name"] == "Syed M. Tayyab"
    assert c.patch("/api/account/me", headers=auth(tok), json={"email": "not-an-email"}).status_code == 422
    h = c.get("/api/account/login-history", headers=auth(tok)).json()
    assert h["stats"]["failed"] == 1 and h["stats"]["successful"] == 1


def test_admin_users(c):
    tok = setup(c)["session_token"]
    u = c.post("/api/account/users", headers=auth(tok),
               json={"username": "guest1", "password": "Gu3st!Account#9", "role": "standard"}).json()
    gtok = c.post("/api/account/login", json={"username": "guest1", "password": "Gu3st!Account#9"}).json()["session_token"]
    assert c.get("/api/account/users", headers=auth(gtok)).status_code == 403       # not admin
    assert len(c.get("/api/account/users", headers=auth(tok)).json()) == 2
    assert c.delete(f"/api/account/users/{u['id']}", headers=auth(tok)).status_code == 200


def test_settings_need_session_after_setup(c):
    assert c.patch("/api/settings", json={"theme": "light"}).status_code == 200     # before setup: allowed
    tok = setup(c)["session_token"]
    assert c.patch("/api/settings", json={"theme": "dark"}).status_code == 401
    assert c.patch("/api/settings", headers=auth(tok), json={"theme": "dark"}).status_code == 200
    assert c.delete("/api/activity").status_code == 401
    assert c.patch("/api/settings", headers=auth(tok), json={"max_failed_logins": 1}).status_code == 422


def test_delete_account(c):
    tok = setup(c)["session_token"]
    assert c.post("/api/account/delete", headers=auth(tok), json={"password": "x"}).status_code == 401
    assert c.post("/api/account/delete", headers=auth(tok), json={"password": PW}).status_code == 200
    assert c.get("/api/account/status").json()["setup_required"] is True
