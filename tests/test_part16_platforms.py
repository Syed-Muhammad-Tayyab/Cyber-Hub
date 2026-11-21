"""
Cyber Hub Backend - Part 16 tests: Social & Platform Accounts
Developed by Syed Muhammad Tayyab

No internet needed:
* FakeNet replaces the service's HTTP transport: the public HIBP breach list, XposedOrNot, HIBP breachedaccount and
  the GitHub API (/user, /user/keys) - every request is recorded so privacy rules can be asserted.
* Part 12's real password vault (unlocked in the test session) provides vault evidence.
* Part 15's real threat-intel service answers link checks; Part 5's real scanner runs the extension scan.
* Browser / VS Code extensions live in a fake home folder (CYBERHUB_CLEANER_HOME, like Part 13's tests).
"""
import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import BUILD_PART, Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import breach_watch as bw
from cyberhub.services import extensions_audit as ext
from cyberhub.services import platform_catalog as cat

PW = "Cyb3r!Hub#2026"
MASTER = "Glacier-Mango-Tunnel-Velvet-42"
EMAIL = "syed.tayyab@gmail.com"
CLEAN_EMAIL = "nobody.clean@example.org"
GOOD_TOKEN = "ghp_" + "A1b2C3d4E5" * 4
BROAD_TOKEN = "ghp_" + "Z9y8X7w6V5" * 4
TWOFA_TOKEN = "github_pat_" + "Q1w2E3r4T5" * 4
HIBP_KEY = "0123456789abcdef0123456789abcdef"
RECENT = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")


def breach(name, domain, date, classes, added="2016-05-21T21:35:40Z", **flags):
    return {"Name": name, "Title": name, "Domain": domain, "BreachDate": date, "AddedDate": added,
            "PwnCount": 1000, "Description": f"<p>In {date[:4]}, <a href='x'>{name}</a> &amp; co.</p>",
            "DataClasses": classes, "IsVerified": True, **flags}


CATALOG = [
    breach("LinkedIn", "linkedin.com", "2012-05-05", ["Email addresses", "Passwords"]),
    breach("Canva", "canva.com", "2019-05-24", ["Email addresses", "Names", "Passwords", "Usernames"]),
    breach("Facebook", "facebook.com", "2019-08-01", ["Phone numbers", "Names", "Genders"]),
    breach("SpamBot", "", "2018-01-01", ["Email addresses"], IsSpamList=True),
    breach("FiverrLeak", "fiverr.com", "2026-10-30", ["Email addresses", "Passwords"], added=RECENT),
]


class FakeNet:
    def __init__(self):
        self.calls: list[tuple] = []
        self.catalog = list(CATALOG)
        self.catalog_status = 200
        self.etag = '"cat-1"'
        self.gh_2fa = {GOOD_TOKEN: False, BROAD_TOKEN: True, TWOFA_TOKEN: True}

    def __call__(self, method, url, headers, data, timeout):
        self.calls.append((method, url, dict(headers)))
        if url == bw.HIBP_CATALOG_URL:
            if headers.get("If-None-Match") == self.etag:
                return 304, b"", {}
            if self.catalog_status != 200:
                return self.catalog_status, b"oops", {}
            return 200, json.dumps(self.catalog).encode(), {"etag": self.etag}
        if url.startswith("https://api.xposedornot.com/v1/check-email/"):
            if EMAIL.replace("@", "%40") in url or EMAIL in url:
                return 200, b'{"breaches": [["LinkedIn", "Canva", "SomethingUnknown"]]}', {}
            return 404, b'{"Error": "Not found"}', {}
        if url.startswith("https://haveibeenpwned.com/api/v3/breachedaccount/"):
            if headers.get("hibp-api-key") != HIBP_KEY:
                return 401, b"", {}
            if "syed.tayyab" in url:
                return 200, json.dumps([CATALOG[0]]).encode(), {}
            return 404, b"", {}
        if url.startswith("https://api.github.com/"):
            tok = headers.get("Authorization", "").removeprefix("Bearer ")
            if tok not in self.gh_2fa:
                return 401, b'{"message":"Bad credentials"}', {}
            scopes = {"x-oauth-scopes": "repo, read:user" if tok == BROAD_TOKEN else "read:user, read:public_key"} \
                if tok.startswith("ghp_") else {}
            if url.endswith("/user"):
                return 200, json.dumps({"login": "Syed-Muhammad-Tayyab", "two_factor_authentication": self.gh_2fa[tok],
                                        "created_at": "2022-01-01T00:00:00Z", "public_repos": 30,
                                        "plan": {"name": "free"}}).encode(), scopes
            if "/user/keys" in url:
                return 200, json.dumps([{"id": 1, "title": "old-laptop", "created_at": "2021-01-01T00:00:00Z"},
                                        {"id": 2, "title": "this-pc", "created_at": RECENT}]).encode(), scopes
        return 404, b"", {}

    def hits(self, part):
        return [c for c in self.calls if part in c[1]]


# ====================================================================== fixtures
@pytest.fixture()
def env(tmp_path, monkeypatch):
    for d in ("quick", "full", "watched", "docs", "home"):
        (tmp_path / d).mkdir()
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    monkeypatch.setenv("CYBERHUB_QUICK_SCAN_DIRS", str(tmp_path / "quick"))
    monkeypatch.setenv("CYBERHUB_FULL_SCAN_ROOTS", str(tmp_path / "full"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_USER_DIR", str(tmp_path / "as-user"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_SYSTEM_DIR", str(tmp_path / "as-sys"))
    monkeypatch.setenv("CYBERHUB_RTP_DEFAULT_DIRS", str(tmp_path / "watched"))
    monkeypatch.setenv("CYBERHUB_FIREWALL_BACKEND", "memory")
    monkeypatch.setenv("CYBERHUB_NETWORK_BACKEND", "memory")
    monkeypatch.setenv("CYBERHUB_POSTURE_BACKEND", "memory")
    monkeypatch.setenv("CYBERHUB_CLIPBOARD_BACKEND", "memory")
    monkeypatch.setenv("CYBERHUB_PV_KDF_N", "1024")
    monkeypatch.setenv("CYBERHUB_DP_KDF_N", "1024")
    monkeypatch.setenv("CYBERHUB_CLEANER_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CYBERHUB_CLEANER_LAYOUT", "linux")
    monkeypatch.setenv("CYBERHUB_FINDER_DEFAULT_DIRS", str(tmp_path / "docs"))
    return tmp_path


def _login(cl, user="syed", pw=PW):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": user, "display_name": "Syed", "password": pw,
                                            "email": EMAIL})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": user, "password": pw})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def c(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        cl.env = env
        cl.net = FakeNet()
        svc_ = cl.app.state.platforms
        svc_.transport = cl.net
        svc_.pace = {}
        yield cl


def svc(c):
    return c.app.state.platforms


def add(c, platform, **kw):
    r = c.post("/api/platforms/accounts", json={"platform": platform, **kw})
    assert r.status_code == 201, r.text
    return r.json()["account"]


def acct(c, aid):
    r = c.get(f"/api/platforms/accounts/{aid}")
    assert r.status_code == 200, r.text
    return r.json()["account"]


def item(a, iid):
    return next(i for i in a["checklist"] if i["id"] == iid)


def codes(a):
    return {i["code"] for i in a["issues"]}


def standard_client(c):
    r = c.post("/api/account/users", json={"username": "guest", "display_name": "Guest", "password": "Gu3st!Pass#2026",
                                           "role": "standard"})
    assert r.status_code == 201, r.text
    s = TestClient(c.app)
    s.headers["X-CyberHub-Token"] = c.headers["X-CyberHub-Token"]
    r = s.post("/api/account/login", json={"username": "guest", "password": "Gu3st!Pass#2026"})
    s.headers["X-CyberHub-Session"] = r.json()["session_token"]
    return s, r.json()["user"]["id"] if "user" in r.json() else None


def load_catalog(c):
    r = c.post("/api/platforms/breaches/refresh?force=true")
    assert r.status_code == 200, r.text
    return r.json()


# ====================================================================== pure helpers
def test_catalog_helpers_and_parsers():
    keys = {p["key"] for p in cat.PLATFORMS}
    assert {"google", "facebook", "instagram", "whatsapp", "linkedin", "youtube", "github", "fiverr", "upwork",
            "vscode", "chrome", "google_meet", "jazzcash", "easypaisa"} <= keys and len(keys) >= 50
    for p in cat.PLATFORMS:
        assert p["importance"] in cat.IMPORTANCE and p["category"] in cat.CATEGORIES
        assert set(p["mfa"]) <= set(cat.MFA_LABELS) and set(p["recovery"]) <= set(cat.RECOVERY_LABELS)
        assert not p["sso"] or p["sso"] in cat.BY_KEY
        assert all(u.startswith("https://") for u in p["links"].values())
        assert p["links"] or p["where"]
    g, yt, nf = cat.BY_KEY["google"], cat.BY_KEY["youtube"], cat.BY_KEY["netflix"]
    assert cat.item_applies("two_factor", g) and not cat.item_applies("two_factor", yt)
    assert cat.item_applies("strong_two_factor", g) and not cat.item_applies("two_factor", nf)
    assert cat.item_applies("password_after_breach", g, True) and not cat.item_applies("password_after_breach", g)
    assert cat.platform_for_domain("youtube.com")["key"] == "google"
    assert cat.public(cat.BY_KEY["whatsapp"])["sso_name"] is None and cat.public(yt)["sso_name"].startswith("Google")
    # e-mail helpers
    assert bw.normalize_email("  <Syed.Tayyab@GMAIL.com> ") == EMAIL
    assert bw.normalize_email("mailto:a@bücher.de") == "a@xn--bcher-kva.de"
    for bad in ("nope", "a@b", "a..b@x.com", "x@-bad-.com"):
        with pytest.raises(bw.BreachError):
            bw.normalize_email(bad)
    assert bw.mask_email(EMAIL) == "sy••••••@gmail.com" and bw.mask_email("ab@x.io") == "a•••@x.io"
    assert bw.parse_xon(200, b'{"breaches":[["Adobe","LinkedIn"]]}') == ["Adobe", "LinkedIn"]
    assert bw.parse_xon(200, b'{"breaches":[["Adobe"],["LinkedIn"]]}') == ["Adobe", "LinkedIn"]
    assert bw.parse_xon(404, b"") == [] and bw.parse_xon(200, b'{"Error":"Not found"}') == []
    with pytest.raises(bw.BreachError) as e:
        bw.parse_xon(429, b"")
    assert e.value.status == 429
    with pytest.raises(bw.BreachError):
        bw.parse_catalog(200, b"[]")                         # empty list never replaces the last good copy
    rows = bw.parse_catalog(200, json.dumps(CATALOG).encode())
    li = rows[0]
    assert li["domain"] == "linkedin.com" and li["description"] == "In 2012, LinkedIn & co." and bw.has_secrets(
        li["data_classes"]) and bw.severity(li["data_classes"]) == "high"
    assert bw.severity(["Phone numbers"]) == "low" and bw.severity(["Credit cards"]) == "medium"
    assert any("SMS" in a for a in bw.advice(["Phone numbers"]))
    # extension risk
    s, f = ext.score_browser(["cookies", "webRequest", "nativeMessaging"], ["<all_urls>"], False, 3, "unpacked", True)
    assert s >= 60 and ext.level(s) == "high" and {"all_sites", "unpacked", "perm_cookies", "combo"} <= {x["code"]
                                                                                                         for x in f}
    s2, _ = ext.score_browser(["storage"], ["https://example.com/*"], False, 3, "store", True)
    assert s2 == 0


def test_catalog_endpoints(c):
    r = c.get("/api/platforms/catalog").json()
    assert r["reviewed"] == cat.CATALOG_REVIEWED and len(r["platforms"]) == len(cat.PLATFORMS)
    assert {"two_factor", "backup_codes", "password_after_breach"} <= {i["id"] for i in r["checklist"]}
    gh = c.get("/api/platforms/catalog/github").json()
    assert gh["links"]["keys"] == "https://github.com/settings/keys" and gh["breaches"] == []
    assert c.get("/api/platforms/catalog/myspace2").status_code == 404
    assert c.get("/api/platforms/catalog", headers={"X-CyberHub-Session": ""}).status_code == 401


# ====================================================================== accounts
def test_accounts_encrypted_autolink_and_recovery_graph(c):
    g = add(c, "google", email=EMAIL, label="Personal")
    yt = add(c, "youtube", handle="@syedtech")
    li = add(c, "linkedin", email=EMAIL.upper(), handle="syed-tayyab", phone_last4="4321")
    assert acct(c, yt["id"])["sso_account_id"] == g["id"]                  # YouTube -> Google login
    assert acct(c, li["id"])["recovery_account_id"] == g["id"]             # signed up with the Gmail address
    assert acct(c, li["id"])["email"] == EMAIL and acct(c, li["id"])["phone_last4"] == "4321"
    # duplicates / validation
    assert c.post("/api/platforms/accounts", json={"platform": "linkedin", "handle": "Syed-Tayyab"}).status_code == 409
    assert c.post("/api/platforms/accounts", json={"platform": "linkedin", "phone_last4": "03001234567"}
                  ).status_code == 422
    assert c.post("/api/platforms/accounts", json={"platform": "orkut"}).status_code == 422
    assert c.post("/api/platforms/accounts", json={"platform": "custom"}).status_code == 422
    cu = add(c, "custom", custom_name="University portal", custom_domain="https://lms.fuuast.edu.pk/login",
             email="Syed.Tayyab@Gmail.com")
    assert cu["custom_domain"] == "fuuast.edu.pk" and cu["name"] == "University portal"
    # nothing personal in clear in the database
    raw = (c.env / "data" / "cyberhub.db").read_bytes()
    for s in (b"syedtech", b"syed-tayyab", b"syed.tayyab@gmail.com", b"4321"):
        assert s not in raw.lower()
    em = c.get("/api/platforms/emails").json()["items"]
    assert len(em) == 1 and em[0]["masked"] == "sy••••••@gmail.com" and len(em[0]["accounts"]) == 3
    assert c.get(f"/api/platforms/emails/{em[0]['id']}?reveal=true").json()["email"] == EMAIL
    # recovery graph: Google can reset LinkedIn + the portal and signs in YouTube
    rg = c.get("/api/platforms/recovery-graph").json()
    hub = next(n for n in rg["hubs"] if n["id"] == g["id"])
    assert hub["can_reset"] == 3 and {e["kind"] for e in rg["edges"]} == {"recovers", "signs_in"}
    assert rg["weak_hubs"][0]["id"] == g["id"]                               # 2FA not confirmed yet
    # loop prevention + update + delete
    r = c.patch(f"/api/platforms/accounts/{g['id']}", json={"recovery_account_id": li["id"]})
    assert r.status_code == 422 and "loop" in r.json()["detail"]
    r = c.patch(f"/api/platforms/accounts/{li['id']}", json={"label": "Work", "importance": "critical"})
    assert r.json()["account"]["label"] == "Work" and r.json()["account"]["importance"] == "critical"
    assert c.delete(f"/api/platforms/accounts/{g['id']}").json()["deleted"]
    assert acct(c, yt["id"])["sso_account_id"] is None and acct(c, li["id"])["recovery_account_id"] is None
    assert "sso_missing" in codes(acct(c, yt["id"]))
    assert c.get("/api/platforms/accounts/99999").status_code == 404


def test_checklist_scoring_and_issues(c):
    g = add(c, "google", email=EMAIL)
    add(c, "linkedin", email=EMAIL)
    a = acct(c, g["id"])
    nf = next(i for i in a["issues"] if i["code"] == "no_2fa")
    assert nf["severity"] == "critical" and "reset 1" in nf["text"] and a["score"] <= 49
    before = a["score"]
    ov = c.get("/api/platforms/accounts").json()["overview"]
    assert ov["score"] <= 49 and ov["critical_without_2fa"] == 1 and ov["grade"] == "At risk"
    # tick 2FA (with an app) -> the critical issue goes away
    r = c.put(f"/api/platforms/accounts/{g['id']}/checklist", json={"items": {"two_factor": "done",
                                                                              "strong_two_factor": "done",
                                                                              "backup_codes": "done"}})
    a = r.json()["account"]
    assert "no_2fa" not in codes(a) and item(a, "two_factor")["source"] == "you" and a["score"] > before
    assert a["checklist_done"] == 3 and a["checklist_total"] == 12           # unknown items still count as to-do
    assert a["two_factor"] == "done"
    # SMS-only warning
    c.put(f"/api/platforms/accounts/{g['id']}/checklist", json={"items": {"strong_two_factor": "not_done"}})
    assert "sms_only" in codes(acct(c, g["id"]))
    # item validation
    nflx = add(c, "netflix")
    assert c.put(f"/api/platforms/accounts/{nflx['id']}/checklist", json={"items": {"two_factor": "done"}}
                 ).status_code == 422
    assert "no_2fa_offered" in codes(acct(c, nflx["id"]))
    assert c.put(f"/api/platforms/accounts/{g['id']}/checklist", json={"items": {"flux": "done"}}).status_code == 422
    assert c.put(f"/api/platforms/accounts/{g['id']}/checklist", json={"items": {"two_factor": "maybe"}}
                 ).status_code == 422
    # reviewed -> review items done; stale after platform_review_days
    a = c.post(f"/api/platforms/accounts/{g['id']}/reviewed").json()["account"]
    assert item(a, "sessions_reviewed")["status"] == "done" and a["last_reviewed_at"]
    old = (datetime.now(timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
    c.app.state.db.execute("UPDATE platform_checks SET updated_at=? WHERE item='sessions_reviewed'", (old,))
    c.app.state.db.execute("UPDATE platform_accounts SET last_reviewed_at=? WHERE id=?", (old, g["id"]))
    a = acct(c, g["id"])
    assert item(a, "sessions_reviewed")["stale"] and "review_due" in codes(a)
    assert svc(c).review_reminders() == 1 and svc(c).review_reminders() == 0      # once per month
    # unknown resets an item
    a = c.put(f"/api/platforms/accounts/{g['id']}/checklist", json={"items": {"two_factor": "unknown"}}
              ).json()["account"]
    assert item(a, "two_factor")["status"] == "unknown"
    assert svc(c).recovery_alerts() == 0                                     # unknown is not "off"
    c.put(f"/api/platforms/accounts/{g['id']}/checklist", json={"items": {"two_factor": "not_done"}})
    assert svc(c).recovery_alerts() == 1
    ev = c.get("/api/platforms/events?kind=recovery_weak").json()["items"]
    assert ev and ev[0]["severity"] == "critical"


def test_vault_evidence_discover_and_create(c):
    r = c.post("/api/passwords/setup", json={"master_password": MASTER})
    assert r.status_code == 200, r.text
    same = "Sunflower2024!"
    for title, url, pw, totp in (("LinkedIn", "https://www.linkedin.com/login", same, None),
                                 ("Upwork", "https://www.upwork.com/ab/account-security/login", same, None),
                                 ("GitHub", "https://github.com/login", "Kx9!vQ2#mT7$wL4&pZ8@", "JBSWY3DPEHPK3PXP")):
        d = {"title": title, "urls": [url], "username": EMAIL, "password": pw}
        if totp:
            d["totp"] = totp
        assert c.post("/api/passwords/items", json={"type": "login", "data": d}).status_code == 200
    d = c.post("/api/platforms/discover", json={"sources": ["vault"]}).json()
    assert {i["platform"] for i in d["items"]} == {"linkedin", "upwork", "github"} and not d["vault_locked"]
    d = c.post("/api/platforms/discover", json={"sources": ["vault"], "create": True, "platforms": ["linkedin",
                                                                                                    "github"]}).json()
    assert len(d["created"]) == 2
    opened = next(iter(c.app.state.passwords._opens.values()))
    opened.last_used -= 100
    used = opened.last_used
    lst = c.get("/api/platforms/accounts").json()
    assert lst["vault_unlocked"] and lst["total"] == 2
    assert opened.last_used == used                       # looking at Platforms doesn't keep the vault unlocked
    li = next(a for a in lst["items"] if a["platform"] == "linkedin")
    gh = next(a for a in lst["items"] if a["platform"] == "github")
    a = acct(c, li["id"])
    assert a["email"] == EMAIL and a["vault_linked"] and item(a, "unique_password")["status"] == "not_done"
    assert item(a, "unique_password")["source"] == "vault" and "password_reused" in codes(a)
    a = acct(c, gh["id"])
    assert item(a, "two_factor") == {**item(a, "two_factor"), "status": "done", "source": "vault"}
    assert item(a, "unique_password")["status"] == "done" and item(a, "strong_password")["status"] == "done"
    # vault locked -> evidence still comes from the stored snapshot
    c.post("/api/passwords/lock")
    a = acct(c, li["id"])
    assert "password_reused" in codes(a) and c.get("/api/platforms/accounts").json()["vault_unlocked"] is False
    assert c.get(f"/api/platforms/accounts/{li['id']}/vault-matches").status_code == 423
    assert c.post("/api/platforms/discover", json={"sources": ["vault"]}).json()["vault_locked"]
    # snapshots hold flags only - no vault content in the platform tables
    rows = json.dumps(c.app.state.db.fetchall("SELECT * FROM platform_accounts"))
    assert same not in rows and "Sunflower" not in rows and "JBSWY3DP" not in rows and "linkedin.com/login" not in rows
    # create a vault login straight from an account
    assert c.post("/api/passwords/unlock", json={"master_password": MASTER}).status_code == 200
    fv = add(c, "fiverr", handle="syed_dev")
    m = c.get(f"/api/platforms/accounts/{fv['id']}/vault-matches").json()
    assert m["items"] == [] and m["linked"] is None
    a = c.post(f"/api/platforms/accounts/{fv['id']}/vault-link", json={"create": True,
                                                                         "password": "Tiger-Lamp-Orbit-93"}).json()
    assert a["account"]["vault_linked"]
    items = c.get("/api/passwords/items?q=fiverr").json()["items"]
    assert len(items) == 1 and items[0]["username"] == "syed_dev"
    assert c.post(f"/api/platforms/accounts/{fv['id']}/vault-link", json={"item_id": "nope"}).status_code == 404
    a = c.post(f"/api/platforms/accounts/{fv['id']}/vault-link", json={"item_id": None}).json()["account"]
    assert not a["vault_linked"]


# ====================================================================== breach list
def test_breach_catalog_platform_alerts_and_password_age(c):
    li = add(c, "linkedin", handle="syed")
    fv = add(c, "fiverr", handle="syed_dev")
    st = load_catalog(c)
    assert st["breaches"] == 5 and st["added"] == 5 and st["error"] is None
    ev = c.get("/api/platforms/events?kind=platform_breach").json()["items"]
    assert len(ev) == 1 and "FiverrLeak" in ev[0]["title"] and ev[0]["account_id"] == fv["id"]   # baseline: recent only
    a = acct(c, li["id"])
    assert a["platform_breaches"][0]["name"] == "LinkedIn" and "platform_breach" in codes(a)
    assert item(a, "password_after_breach")["status"] == "unknown"
    c.put(f"/api/platforms/accounts/{li['id']}/checklist", json={"items": {"password_after_breach": "done"}})
    assert "platform_breach" not in codes(acct(c, li["id"]))
    # facebook breach had no passwords -> the item doesn't apply
    fb = acct(c, add(c, "facebook")["id"])
    assert not any(i["id"] == "password_after_breach" for i in fb["checklist"]) and fb["platform_breaches"]
    # a new breach of a site you use -> alert; unchanged list -> 304, nothing re-downloaded
    assert load_catalog(c)["changed"] is True
    c.net.catalog.append(breach("LinkedIn2026", "linkedin.com", "2026-11-01", ["Email addresses", "Passwords"]))
    c.net.etag = '"cat-2"'
    assert svc(c).refresh_catalog()["added"] == 1
    ev = c.get("/api/platforms/events?kind=platform_breach").json()["items"]
    assert any("LinkedIn2026" in e["title"] and e["severity"] == "high" for e in ev)
    assert svc(c).refresh_catalog()["changed"] is False
    # broken download keeps the last good copy
    c.net.catalog_status = 500
    assert c.post("/api/platforms/breaches/refresh?force=true").status_code == 502
    st = c.get("/api/platforms/status").json()["catalog"]
    assert st["breaches"] == 6 and "HTTP 500" in st["error"]
    assert c.get("/api/platforms/events?kind=catalog_error").json()["items"]
    # search
    r = c.get("/api/platforms/breaches?q=linked").json()
    assert r["total"] == 2 and r["attribution"]["hibp"].startswith("https://")
    assert c.get("/api/platforms/breaches?domain=www.canva.com").json()["items"][0]["name"] == "Canva"
    assert c.get("/api/platforms/breaches?q=%25").json()["total"] == 0           # wildcards escaped
    # only the public list URL was called - no personal data
    assert all(call[1] == bw.HIBP_CATALOG_URL for call in c.net.calls)


# ====================================================================== e-mail breach monitoring
def test_email_breach_check_xposedornot(c):
    load_catalog(c)
    li = add(c, "linkedin", email=EMAIL)
    clean = c.post("/api/platforms/emails", json={"email": CLEAN_EMAIL}).json()
    assert clean["masked"].startswith("no") and clean["existing"] is False
    assert c.post("/api/platforms/emails", json={"email": CLEAN_EMAIL.upper()}).json()["existing"] is True
    job = c.post("/api/platforms/emails/check", json={}).json()
    j = svc(c).wait(job["id"], 30)
    assert j["status"] == "done" and j["result"]["checked"] == 2 and j["result"]["breached"] == 1
    sent = c.net.hits("xposedornot")
    assert len(sent) == 2 and all("@" in s[1] or "%40" in s[1] for s in sent)
    assert all("hibp-api-key" not in s[2] for s in sent)
    items = {e["masked"]: e for e in c.get("/api/platforms/emails").json()["items"]}
    mine = items[bw.mask_email(EMAIL)]
    names = {b["name"] for b in mine["breaches"]}
    assert names == {"LinkedIn", "Canva", "SomethingUnknown"} and mine["worst"] == "high"
    lb = next(b for b in mine["breaches"] if b["name"] == "LinkedIn")
    assert lb["your_accounts_there"] == [li["id"]] and lb["passwords_exposed"] and lb["advice"]
    assert items[clean["masked"]]["breach_count"] == 0
    ev = c.get("/api/platforms/events?kind=email_breach").json()["items"]
    assert len(ev) == 1 and "found in 3" in ev[0]["title"] and ev[0]["severity"] == "high"
    a = acct(c, li["id"])
    assert "account_in_breach" in codes(a) and a["score"] <= 49
    # second check: nothing new -> no new alert
    svc(c).wait(c.post("/api/platforms/emails/check", json={"ids": [mine["id"]]}).json()["id"], 30)
    assert len(c.get("/api/platforms/events?kind=email_breach").json()["items"]) == 1
    # acknowledge -> the breach stops counting
    assert c.post(f"/api/platforms/emails/{mine['id']}/ack", json={}).json()["acknowledged"] == 3
    assert "account_in_breach" not in codes(acct(c, li["id"]))
    # switched off / unknown ids / privacy toggle
    c.patch("/api/settings", json={"platform_breach_check": "off"})
    assert c.post("/api/platforms/emails/check", json={}).status_code == 403
    c.patch("/api/settings", json={"platform_breach_check": "manual"})
    assert c.post("/api/platforms/emails/check", json={"ids": [9999]}).status_code == 404
    assert c.patch(f"/api/platforms/emails/{clean['id']}", json={"monitor": False}).json()["monitor"] is False
    assert c.delete(f"/api/platforms/emails/{clean['id']}").json()["deleted"]
    sug = c.get("/api/platforms/emails/suggest").json()["items"]
    assert sug == []                                      # the sign-in e-mail is already monitored (from LinkedIn)


def test_email_breach_check_hibp_key_and_auto_mode(c):
    std, _ = standard_client(c)
    assert std.put("/api/platforms/providers/hibp/key", json={"key": HIBP_KEY}).status_code == 403
    assert c.put("/api/platforms/providers/hibp/key", json={"key": "short"}).status_code == 422
    assert c.put("/api/platforms/providers/virustotal/key", json={"key": HIBP_KEY}).status_code == 422
    p = c.put("/api/platforms/providers/hibp/key", json={"key": HIBP_KEY}).json()
    assert p["hibp"]["ready"] and p["hibp"]["key_hint"] == "…cdef" and p["order"][0] == "hibp"
    assert HIBP_KEY.encode() not in (c.env / "data" / "cyberhub.db").read_bytes()
    c.post("/api/platforms/emails", json={"email": EMAIL})
    j = svc(c).wait(c.post("/api/platforms/emails/check", json={}).json()["id"], 30)
    assert j["status"] == "done"
    call = c.net.hits("breachedaccount")[0]
    assert call[2]["hibp-api-key"] == HIBP_KEY and "truncateResponse=false" in call[1]
    e = c.get("/api/platforms/emails").json()["items"][0]
    assert e["last_provider"] == "hibp" and e["breaches"][0]["data_classes"] == ["Email addresses", "Passwords"]
    assert svc(c).catalog_status()["breaches"] == 1                         # details stored for enrichment
    # refused key -> error recorded, job fails
    svc(c).set_key(None, "hibp", "f" * 32)
    j = svc(c).wait(c.post("/api/platforms/emails/check", json={}).json()["id"], 30)
    assert j["status"] == "failed" and "refused" in j["error"]
    assert "refused" in c.get("/api/platforms/emails").json()["items"][0]["last_error"]
    # HIBP only + no key -> 409; XposedOrNot back -> works without a key
    c.put("/api/platforms/providers/hibp/key", json={"key": None})
    c.patch("/api/settings", json={"platform_breach_providers": ["hibp"]})
    assert c.post("/api/platforms/emails/check", json={}).status_code == 409
    c.patch("/api/settings", json={"platform_breach_providers": ["xposedornot", "hibp"]})
    # auto mode: due addresses are checked by the background tick (and not again until the interval passes)
    c.patch("/api/settings", json={"platform_breach_check": "auto"})
    c.app.state.db.execute("UPDATE platform_emails SET last_checked_at='2020-01-01T00:00:00Z'")
    out = svc(c).tick()
    assert out["breach_job"]["status"] in ("running", "done")
    svc(c).wait(out["breach_job"]["id"], 30)
    assert svc(c).due_emails() == []


# ====================================================================== GitHub
def test_github_connection_read_only(c):
    gh = add(c, "github")
    li = add(c, "linkedin")
    assert c.post(f"/api/platforms/accounts/{li['id']}/github", json={"token": GOOD_TOKEN}).status_code == 422
    assert c.post(f"/api/platforms/accounts/{gh['id']}/github", json={"token": "password123456"}).status_code == 422
    r = c.post(f"/api/platforms/accounts/{gh['id']}/github", json={"token": BROAD_TOKEN})
    assert r.status_code == 422 and "repo" in r.json()["detail"]
    r = c.post(f"/api/platforms/accounts/{gh['id']}/github", json={"token": "ghp_" + "x" * 36})
    assert r.status_code == 422 and "refused" in r.json()["detail"]
    a = c.post(f"/api/platforms/accounts/{gh['id']}/github", json={"token": GOOD_TOKEN}).json()["account"]
    assert a["handle"] == "Syed-Muhammad-Tayyab" and a["github"]["result"]["two_factor"] is False
    assert item(a, "two_factor") == {**item(a, "two_factor"), "status": "not_done", "source": "github"}
    assert item(a, "keys_tokens_reviewed")["status"] == "not_done" and {"no_2fa", "old_ssh_keys"} <= codes(a)
    assert a["github"]["scopes"] == ["read:user", "read:public_key"] and a["github"]["result"]["old_keys"] == 1
    kinds = {e["kind"]: e for e in c.get("/api/platforms/events").json()["items"]}
    assert kinds["github_2fa_off"]["severity"] == "critical" and "github_old_keys" in kinds
    assert GOOD_TOKEN.encode() not in (c.env / "data" / "cyberhub.db").read_bytes()
    # the user turns 2FA on at GitHub -> next sync says so (a tick "done" can't hide GitHub's own answer)
    c.put(f"/api/platforms/accounts/{gh['id']}/checklist", json={"items": {"two_factor": "done"}})
    assert item(acct(c, gh["id"]), "two_factor")["status"] == "not_done"
    c.net.gh_2fa[GOOD_TOKEN] = True
    a = c.post(f"/api/platforms/accounts/{gh['id']}/github/sync").json()["account"]
    assert item(a, "two_factor")["status"] == "done" and "no_2fa" not in codes(a)
    # fine-grained token: no scope header, still accepted
    a = c.post(f"/api/platforms/accounts/{gh['id']}/github", json={"token": TWOFA_TOKEN}).json()["account"]
    assert a["github"]["scopes"] is None and a["github"]["result"]["token_type"] == "fine-grained"
    # background sync when due; revoked token recorded
    c.app.state.db.execute("UPDATE platform_connections SET last_sync_at='2020-01-01T00:00:00Z'")
    c.net.gh_2fa.pop(TWOFA_TOKEN)
    svc(c).tick()
    assert "refused" in acct(c, gh["id"])["github"]["last_error"]
    a = c.delete(f"/api/platforms/accounts/{gh['id']}/github").json()["account"]
    assert a["github"] is None and not a["github_connected"]
    assert all(call[1].startswith("https://api.github.com/") or call[1] == bw.HIBP_CATALOG_URL
               for call in c.net.calls)
    assert all(call[0] == "GET" for call in c.net.calls)                   # read-only, always


# ====================================================================== link / sender check
def test_check_link_official_and_lookalikes(c):
    r = c.post("/api/platforms/check-link", json={"value": "https://www.facebook.com/settings", "platform": "facebook"})
    j = r.json()
    assert r.status_code == 200 and j["official"] is True and j["verdict"] == "clean" and j["engine"] == "threat_intel"
    j = c.post("/api/platforms/check-link", json={"value": "hxxps://facebook-security-check[.]xyz/login",
                                                  "platform": "facebook"}).json()
    assert j["official"] is False and j["verdict"] in ("suspicious", "malicious") and j["score"] >= 80
    assert "NOT one of Facebook" in j["reasons"][0] and j["advice"][0].startswith("Don't open")
    j = c.post("/api/platforms/check-link", json={"value": "https://linkedln.com/jobs/view", "platform": "linkedin"}
               ).json()
    assert j["verdict"] in ("suspicious", "malicious")
    j = c.post("/api/platforms/check-link", json={"value": "security@jazzcash-support.com", "platform": "jazzcash"}
               ).json()
    assert j["kind"] == "email" and not j["official"] and "jazzcash.com.pk" in j["advice"][0]
    j = c.post("/api/platforms/check-link", json={"value": "https://github.com/Syed-Muhammad-Tayyab"}).json()
    assert j["owner_platform"] == "github" and j["official"] is True
    assert c.post("/api/platforms/check-link", json={"value": "8.8.8.8"}).status_code == 422
    assert c.post("/api/platforms/check-link", json={"value": "x.com", "platform": "myspace"}).status_code == 422
    assert c.get("/api/intel/checks").json()["items"]                       # shows up in the Part 15 history too


# ====================================================================== extensions
def _fake_extensions(home):
    prof = home / ".config" / "google-chrome" / "Default"
    (prof / "Extensions" / "goodextid" / "1.2.0_0").mkdir(parents=True)
    (prof / "Extensions" / "goodextid" / "1.2.0_0" / "manifest.json").write_text(json.dumps({
        "name": "__MSG_appName__", "default_locale": "en", "version": "1.2.0", "manifest_version": 3,
        "permissions": ["storage"], "update_url": "https://clients2.google.com/service/update2/crx"}))
    (prof / "Extensions" / "goodextid" / "1.2.0_0" / "_locales" / "en").mkdir(parents=True)
    (prof / "Extensions" / "goodextid" / "1.2.0_0" / "_locales" / "en" / "messages.json").write_text(
        json.dumps({"appName": {"message": "Dark Reader"}}))
    unpacked = home / "dev" / "coupon-helper"
    unpacked.mkdir(parents=True)
    (unpacked / "manifest.json").write_text(json.dumps({
        "name": "Coupon Helper", "version": "0.1", "manifest_version": 3,
        "permissions": ["cookies", "webRequest", "nativeMessaging"], "host_permissions": ["<all_urls>"]}))
    (prof / "Preferences").write_text(json.dumps({"extensions": {"settings": {
        "goodextid": {"location": 1, "from_webstore": True, "state": 1},
        "badunpackedid": {"location": 4, "path": str(unpacked), "state": 1}}}}))
    ff = home / ".mozilla" / "firefox" / "abc.default-release"
    ff.mkdir(parents=True)
    (ff / "prefs.js").write_text("")
    (ff / "extensions.json").write_text(json.dumps({"addons": [
        {"id": "ublock@raymondhill.net", "type": "extension", "location": "app-profile", "active": True,
         "signedState": 2, "version": "1.60", "defaultLocale": {"name": "uBlock Origin"},
         "userPermissions": {"permissions": ["storage"], "origins": ["<all_urls>"]}},
        {"id": "sneaky@evil", "type": "extension", "location": "app-profile", "active": True, "signedState": -1,
         "version": "0.0.1", "defaultLocale": {"name": "Sneaky"},
         "userPermissions": {"permissions": ["proxy"], "origins": []}},
        {"id": "builtin@mozilla.org", "type": "extension", "location": "app-builtin"}]}))
    vs = home / ".vscode" / "extensions"
    (vs / "ms-python.python-2026.1.0").mkdir(parents=True)
    (vs / "ms-python.python-2026.1.0" / "package.json").write_text(json.dumps({
        "name": "python", "publisher": "ms-python", "displayName": "Python", "version": "2026.1.0"}))
    (vs / "random.theme-1.0.0").mkdir(parents=True)
    (vs / "random.theme-1.0.0" / "package.json").write_text(json.dumps({
        "name": "theme", "publisher": "random", "displayName": "Cool Theme", "version": "1.0.0",
        "activationEvents": ["*"]}))
    (vs / "extensions.json").write_text(json.dumps([
        {"identifier": {"id": "ms-python.python"}, "relativeLocation": "ms-python.python-2026.1.0",
         "metadata": {"source": "gallery", "publisherDisplayName": "Microsoft"}},
        {"identifier": {"id": "random.theme"}, "relativeLocation": "random.theme-1.0.0",
         "metadata": {"source": "vsix"}}]))
    return prof


def test_extensions_audit_watch_and_scan(c):
    home = c.env / "home"
    assert c.get("/api/platforms/extensions").json()["total"] == 0
    assert svc(c).watch_extensions() == 0                                  # baseline (empty)
    prof = _fake_extensions(home)
    r = c.get("/api/platforms/extensions?refresh=true").json()
    by = {i["name"]: i for i in r["items"]}
    assert {"Dark Reader", "Coupon Helper", "uBlock Origin", "Sneaky", "Python", "Cool Theme"} == set(by)
    assert {a["app"] for a in r["apps"]} == {"chrome", "firefox", "vscode"}
    assert by["Coupon Helper"]["level"] == "high" and by["Coupon Helper"]["source"] == "unpacked"
    assert by["Dark Reader"]["level"] == "none" and by["Dark Reader"]["store_url"].endswith("/goodextid")
    assert by["Sneaky"]["source"] == "unsigned" and by["Sneaky"]["level"] in ("medium", "high")
    assert by["uBlock Origin"]["all_sites"] and by["Cool Theme"]["source"] == "vsix"
    assert by["Python"]["store_url"] == "https://marketplace.visualstudio.com/items?itemName=ms-python.python"
    assert r["items"][0]["name"] == "Coupon Helper" and by["Coupon Helper"]["new"]
    # the watch alerts once per new risky extension (baseline was taken before they appeared)
    n = svc(c).watch_extensions()
    ev = c.get("/api/platforms/events?kind=extension_new").json()["items"]
    assert n == len(ev) >= 2 and any("Coupon Helper" in e["title"] and e["severity"] == "high" for e in ev)
    assert svc(c).watch_extensions() == 0
    # one-click antivirus scan of an extension folder (Part 5 custom scan)
    r = c.post("/api/platforms/extensions/scan", json={"key": by["Coupon Helper"]["key"]})
    assert r.status_code == 200, r.text
    job = r.json()["scan_job"]
    assert job["kind"] == "custom" and job["paths"] == [str(home / "dev" / "coupon-helper")]
    assert c.post("/api/platforms/extensions/scan", json={"key": "chrome:Default:nope"}).status_code == 404
    assert prof.exists()                                                    # nothing was changed or removed


# ====================================================================== dashboard, settings, isolation
def test_summary_status_settings_events_and_stream(c):
    g = add(c, "google", email=EMAIL)
    add(c, "youtube")
    add(c, "whatsapp")
    add(c, "fiverr")
    load_catalog(c)                                      # FiverrLeak (recent) -> one platform_breach alert
    c.put(f"/api/platforms/accounts/{g['id']}/checklist", json={"items": {"two_factor": "done"}})
    assert svc(c).record_scores() == 1 and svc(c).record_scores() == 0
    s = c.get("/api/platforms/summary").json()
    assert {x["category"] for x in s["by_category"]} == {"identity", "social", "messaging", "freelance"}
    assert s["overview"]["two_fa"]["done"] == 2 and s["score_history"][0]["accounts"] == 4   # YouTube via Google
    assert any(x["item"] == "two_factor" and x["done"] == 1 for x in s["checklist_completion"])
    st = c.get("/api/platforms/status").json()
    assert st["features"]["encrypted_details"] and st["features"]["threat_intel"] and st["catalog"]["breaches"] == 5
    assert st["platforms_known"] == len(cat.PLATFORMS) and st["unacknowledged"] >= 1
    h = c.get("/api/platforms/health").json()
    assert h["accounts"] == 4 and h["emails"] == 1 and h["breach_check"] == "manual"
    for bad in ({"platform_breach_check": "always"}, {"platform_review_days": 5},
                {"platform_breach_providers": ["dehashed"]}):
        assert c.patch("/api/settings", json=bad).status_code == 422
    std, _ = standard_client(c)
    for k, v in (("platform_breach_check", "auto"), ("platform_alert_breaches", False),
                 ("platform_extension_audit", False), ("platform_catalog_auto_update", False)):
        assert std.patch("/api/settings", json={k: v}).status_code == 403
    assert std.patch("/api/settings", json={"platform_review_days": 90}).status_code == 200
    assert c.post("/api/platforms/events/ack", json={}).json()["acknowledged"] >= 1
    assert c.get("/api/platforms/events?unacknowledged=true").json()["items"] == []
    acts = c.get("/api/activity?category=platform").json()
    assert (acts["items"] if isinstance(acts, dict) else acts)
    info = c.get("/api/info").json()
    assert "platforms" in info["available_modules"] and info["progress_percent"] == BUILD_PART * 5 >= 80
    with c.websocket_connect(f"/api/platforms/stream?token={c.headers['X-CyberHub-Token']}&session="
                             f"{c.headers['X-CyberHub-Session']}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "platforms" and "events" in msg
    with pytest.raises(Exception):
        with c.websocket_connect("/api/platforms/stream?token=bad&session=x") as ws:
            ws.receive_json()
    assert c.get("/api/platforms/status", headers={"X-CyberHub-Session": ""}).status_code == 401


def test_users_are_isolated_and_removal_cascades(c):
    g = add(c, "google", email=EMAIL)
    std, _ = standard_client(c)
    assert std.get(f"/api/platforms/accounts/{g['id']}").status_code == 404
    assert std.get("/api/platforms/accounts").json()["total"] == 0
    assert std.get("/api/platforms/emails").json()["items"] == []
    r = std.post("/api/platforms/accounts", json={"platform": "google", "email": EMAIL})
    assert r.status_code == 201                                             # same address, separate user
    assert std.patch(f"/api/platforms/accounts/{r.json()['account']['id']}",
                     json={"recovery_account_id": g["id"]}).status_code == 404     # can't link to another user's
    uid = c.app.state.db.fetchone("SELECT id FROM users WHERE username='guest'")["id"]
    assert c.delete(f"/api/account/users/{uid}").status_code == 200
    db = c.app.state.db
    assert db.fetchone("SELECT COUNT(*) AS n FROM platform_accounts WHERE user_id=?", (uid,))["n"] == 0
    assert db.fetchone("SELECT COUNT(*) AS n FROM platform_emails WHERE user_id=?", (uid,))["n"] == 0
    assert c.get("/api/platforms/accounts").json()["total"] == 1


def test_damaged_row_and_moved_database(c):
    g = add(c, "google", email=EMAIL, handle="syed")
    db = c.app.state.db
    other = add(c, "linkedin", handle="x")
    sec = db.fetchone("SELECT secret FROM platform_accounts WHERE id=?", (other["id"],))["secret"]
    db.execute("UPDATE platform_accounts SET secret=? WHERE id=?", (sec, g["id"]))       # swapped blob
    a = acct(c, g["id"])
    assert a["damaged"] and a["handle"] is None
    assert c.patch(f"/api/platforms/accounts/{g['id']}", json={"label": "x"}).status_code == 409
    assert c.delete(f"/api/platforms/accounts/{g['id']}").json()["deleted"]


def test_cleanup_tick_and_shutdown(c):
    db = c.app.state.db
    db.execute("INSERT INTO platform_events(ts, kind, severity, title) VALUES ('2020-01-01T00:00:00Z','review_due',"
               "'low','old')")
    assert svc(c).cleanup() == 1
    out = svc(c).tick()                                    # catalog due -> downloaded; daily jobs run once
    assert out["catalog"]["breaches"] == 5 and "cleanup" in out
    assert "cleanup" not in svc(c).tick() and "catalog" not in svc(c).tick()
    svc(c).shutdown()
    assert svc(c)._stopping.is_set()


def test_migration_from_part15_keeps_data(env):
    data = env / "data"
    data.mkdir(parents=True, exist_ok=True)
    db = Database(data / "cyberhub.db")
    db._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, description TEXT, "
                     "applied_at TEXT)")
    for ver, d, sql in MIGRATIONS:
        if ver <= 16:
            db._conn.executescript("BEGIN;" + sql + "COMMIT;")
            db._conn.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (ver, d))
    db._conn.execute("INSERT INTO intel_events(kind, severity, title) VALUES ('feed_error','low','kept')")
    assert db.schema_version() == 16
    db.close()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        assert cl.get("/api/health").json()["schema_version"] == MIGRATIONS[-1][0] >= 17
        assert cl.app.state.db.fetchone("SELECT title FROM intel_events")["title"] == "kept"
        assert cl.get("/api/platforms/accounts").json()["total"] == 0


def test_earlier_parts_still_answer(c):
    """Part 16 adds a service and a migration - every earlier module must still start and answer."""
    for path in ("/api/monitor/overview", "/api/processes/summary", "/api/startup", "/api/scan/jobs", "/api/quarantine",
                 "/api/realtime/status", "/api/rules/status", "/api/lookup/status", "/api/firewall/status",
                 "/api/network/status", "/api/posture/status", "/api/passwords/status", "/api/data/status",
                 "/api/web/status", "/api/intel/status", "/api/account/me", "/api/settings"):
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code, r.text[:200])
    assert c.get("/api/intel/status").json()["catalog_reviewed"] == "2026-11-13"
    time.sleep(0)
