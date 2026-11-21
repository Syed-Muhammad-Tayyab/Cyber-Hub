"""
Cyber Hub Backend - Part 15 tests: Threat Intelligence
Developed by Syed Muhammad Tayyab

No internet needed:
* FakeNet replaces the service's HTTP transport: it serves the built-in feeds (Feodo, URLhaus, ThreatFox, Spamhaus,
  OpenPhish, ET, Tor) and fakes VirusTotal / abuse.ch / AbuseIPDB / RDAP, recording every request.
* Deep checks run against a real local HTTP server (CYBERHUB_WEB_PUBLIC_HOSTS=localhost makes it count as public).
* Live connections come from Part 10's MemoryNet with a real child process; blocks go to Part 9's memory firewall.
* Antivirus integration uses Part 5's real single-file scan.
"""
import hashlib
import io
import json
import socket
import threading
import time
import zipfile
from collections import namedtuple
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psutil
import pytest
from fastapi.testclient import TestClient

from cyberhub.config import BUILD_PART, Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import intel_feeds as feeds
from cyberhub.services import ioc
from cyberhub.services import phishing as ph

PW = "Cyb3r!Hub#2026"
addr = namedtuple("addr", "ip port")
sconn = namedtuple("sconn", "fd family type laddr raddr status pid")

C2_IP = "185.220.101.47"            # Feodo + ThreatFox botnet C2
ET_IP = "91.92.240.10"               # ET compromised + hosts a URLhaus malware URL
DROP_IP = "45.153.160.77"            # inside Spamhaus DROP 45.153.160.0/24
TOR_IP = "185.220.101.1"             # Tor exit (feed off by default)
CLEAN_IP = "8.8.4.4"
BAD_FILE = b"Cyber Hub Part 15 - pretend Agent Tesla sample\n" * 20
BAD_SHA = hashlib.sha256(BAD_FILE).hexdigest()

FEODO = f"""################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (recommended)  #
################################################################
#
# DstIP
{C2_IP}
5.188.86.172
# END 2 entries
"""
URLHAUS = f"""################################################################
# abuse.ch URLhaus Database Dump (CSV - online URLs only)      #
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3301","2026-11-12 10:00:00","http://{ET_IP}/bins/mozi.m","online","2026-11-13 08:00:00","malware_download","elf,Mozi","https://urlhaus.abuse.ch/url/3301/","lrz"
"3302","2026-11-12 11:00:00","https://bad-cdn-files.top/update/setup.exe","online","2026-11-13 08:00:00","malware_download","exe,RedLine","https://urlhaus.abuse.ch/url/3302/","x"
"3303","2026-11-12 12:00:00","not a url","online","","malware_download","","",""
"""
TF_HEADER = ('# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias",'
             '"malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"')
THREATFOX = f"""################################################################
# ThreatFox IOCs: full data dump (CSV)                         #
{TF_HEADER}
"2026-11-10 08:00:00","1001","{C2_IP}:443","ip:port","botnet_cc","win.cobalt_strike","","Cobalt Strike","","100","","c2","0","x"
"2026-11-10 09:00:00","1002","evil-c2-panel.com","domain","botnet_cc","win.asyncrat","","AsyncRAT","","90","https://example.org/r","rat","0","x"
"2026-11-10 10:00:00","1003","{BAD_SHA}","sha256_hash","payload","win.agent_tesla","","Agent Tesla","","80","","stealer","0","x"
"2026-11-10 11:00:00","1004","http://loader.example-bad.net/a.ps1","url","payload_delivery","","","Unknown malware","","50","","","0","x"
"2026-11-10 12:00:00","1005","nonsense","sha256_hash","payload","","","X","","50","","","0","x"
"""
SPAMHAUS = ('{"cidr":"45.153.160.0/24","sblid":"SBL567890","rir":"ripencc"}\n'
            '{"cidr":"2a0b:4340::/32","sblid":"SBL1","rir":"ripencc"}\n'
            '{"type":"metadata","timestamp":1731500000,"size":2}\n')
OPENPHISH = ("https://secure-paypal-login.example-phish.com/signin\n"
             "https://docs.google.com/forms/d/e/1FAIpQLSeEVILFORM/viewform\n")
ET = f"# ET compromised\n{ET_IP}\n"
TOR = f"{TOR_IP}\n"


def zipped(name: str, text: str) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, text)
    return b.getvalue()


class FakeNet:
    """Transport stand-in: routes by URL prefix, records (method, url, headers, data)."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.routes: dict = {
            "https://feodotracker.abuse.ch/": (200, FEODO.encode(), {"etag": '"feodo-1"'}),
            "https://urlhaus.abuse.ch/downloads/csv_online/": (200, URLHAUS.encode(), {}),
            "https://threatfox-api.abuse.ch/v2/files/exports/": (200, zipped("full.csv", THREATFOX), {}),
            "https://www.spamhaus.org/drop/drop_v4.json": (200, SPAMHAUS.encode(), {}),
            "https://www.spamhaus.org/drop/drop_v6.json": (200, b'{"type":"metadata"}\n', {}),
            "https://openphish.com/feed.txt": (200, OPENPHISH.encode(), {}),
            "https://rules.emergingthreats.net/": (200, ET.encode(), {}),
            "https://check.torproject.org/": (200, TOR.encode(), {}),
        }

    def __call__(self, method, url, headers, data, timeout):
        self.calls.append((method, url, dict(headers), data))
        if headers.get("If-None-Match") and "feodo" in url and self.routes.get("feodo304"):
            return 304, b"", {}
        for prefix, r in sorted(self.routes.items(), key=lambda kv: -len(kv[0])):
            if url.startswith(prefix):
                return r(method, url, headers, data) if callable(r) else r
        return 404, b"not found", {}

    def hits(self, part: str) -> list[tuple]:
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
    monkeypatch.setenv("CYBERHUB_FINDER_DEFAULT_DIRS", str(tmp_path / "docs"))
    monkeypatch.delenv("CYBERHUB_WEB_PUBLIC_HOSTS", raising=False)
    monkeypatch.delenv("CYBERHUB_WEB_CA_FILE", raising=False)
    return tmp_path


def _login(cl, user="syed", pw=PW):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": user, "display_name": "Syed", "password": pw})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": user, "password": pw})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def c(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        cl.env = env
        cl.net = FakeNet()
        cl.app.state.intel.transport = cl.net
        yield cl


def svc(c):
    return c.app.state.intel


def load_feeds(c, keys=None):
    """Download feeds through FakeNet and wait for the job."""
    ids = None
    if keys:
        fs = {f["key"]: f["id"] for f in c.get("/api/intel/feeds").json()["items"]}
        ids = [fs[k] for k in keys]
    r = c.post("/api/intel/feeds/refresh", json={"feed_ids": ids, "force": True})
    assert r.status_code == 200, r.text
    j = svc(c).wait(r.json()["id"], 60)
    assert j["status"] == "done", j
    return j


def set_abusech_key(c, key="abusech-test-key-0123456789"):
    r = c.put("/api/lookup/keys", json={"malwarebazaar": key})
    assert r.status_code == 200, r.text


def feed(c, key):
    return next(f for f in c.get("/api/intel/feeds").json()["items"] if f["key"] == key)


def standard_client(c):
    r = c.post("/api/account/users", json={"username": "guest", "display_name": "Guest", "password": "Gu3st!Pass#2026",
                                           "role": "standard"})
    assert r.status_code == 201, r.text
    s = TestClient(c.app)
    s.headers["X-CyberHub-Token"] = c.headers["X-CyberHub-Token"]
    r = s.post("/api/account/login", json={"username": "guest", "password": "Gu3st!Pass#2026"})
    s.headers["X-CyberHub-Session"] = r.json()["session_token"]
    return s


@pytest.fixture()
def child():
    """A real process that is not the Cyber Hub engine (Part 10 never reports the engine's own sockets)."""
    import shutil
    import subprocess
    p = subprocess.Popen([shutil.which("sleep"), "60"])
    for _ in range(50):
        try:
            if psutil.Process(p.pid).exe():
                break
        except psutil.Error:
            pass
        time.sleep(0.02)
    yield p
    p.kill()
    p.wait()


def out_conn(pid, rip, rport=443, lport=50123):
    return sconn(-1, socket.AF_INET, socket.SOCK_STREAM, addr("192.168.50.23", lport), addr(rip, rport),
                 "ESTABLISHED", pid)


# ====================================================================== pure helpers
def test_ioc_classify_refang_extract():
    assert ioc.classify("hxxps://evil[.]com/login?x=1")["value"] == "https://evil.com/login?x=1"
    assert ioc.classify("1.2.3[.]4:8080") == {"type": "ip", "value": "1.2.3.4", "display": "1.2.3.4", "port": 8080,
                                             "scope": "public", "version": 4}
    assert ioc.classify("[2a00:1450::1]:443")["value"] == "2a00:1450::1"
    assert ioc.classify("2a00:1450::1")["port"] is None
    assert ioc.classify("10.0.0.0/8")["type"] == "cidr" and ioc.classify("192.168.1.9")["scope"] == "private"
    assert ioc.classify("Bob@Evil.RU")["value"] == "bob@evil.ru"
    assert ioc.classify("münchen.de")["value"] == "xn--mnchen-3ya.de"
    assert ioc.classify("D41D8CD98F00B204E9800998ECF8427E")["type"] == "md5"
    u = ioc.classify("https://user:secret@site.pk:443/a")
    assert u["value"] == "https://site.pk/a" and u["userinfo"] == "user:***"
    for bad in ("", "not a thing!", "javascript:alert(1)", "http://exa mple.com"):
        with pytest.raises(ioc.IOCError):
            ioc.classify(bad)
    items, _ = ioc.extract("Block hxxp://bad[.]site/x.exe and 185.220.101[.]1, mail bob[@]evil.ru, read report.pdf, "
                           f"hash {BAD_SHA} and printer.local")
    assert [(i["type"], i["value"]) for i in items] == [("url", "http://bad.site/x.exe"), ("ip", "185.220.101.1"),
                                                        ("email", "bob@evil.ru"), ("sha256", BAD_SHA)]
    assert ioc.defang("https://evil.com/x", "url") == "hxxps://evil[.]com/x" and ioc.defang("1.2.3.4", "ip") == "1.2.3[.]4"
    assert ioc.registrable("login.secure.example.co.uk") == "example.co.uk"
    assert ioc.registrable("www.hbl.com.pk") == "hbl.com.pk" and ioc.registrable("a.b.github.io") == "b.github.io"
    assert ioc.parent_domains("a.b.example.com.pk") == ["a.b.example.com.pk", "b.example.com.pk", "example.com.pk"]
    v, lo, hi = ioc.net_range("45.153.160.0/24")
    assert v == 4 and lo < ioc.ip_hex(DROP_IP)[1] <= hi
    assert ioc.url_key_variants("https://a.com/x/") == ["https://a.com/x/", "https://a.com/x", "http://a.com/x/",
                                                        "http://a.com/x"]


def test_stix_round_trip():
    bundle = ioc.to_stix([{"type": "ip", "value": C2_IP, "threat": "C2"}, {"type": "url", "value": "http://a.com/it's"},
                          {"type": "sha256", "value": BAD_SHA}, {"type": "domain", "value": "evil.com"}])
    items, skipped = ioc.parse_stix(json.dumps(bundle))
    assert skipped == 0 and {(i["type"], i["value"]) for i in items} == {
        ("ip", C2_IP), ("url", "http://a.com/it's"), ("sha256", BAD_SHA), ("domain", "evil.com")}
    with pytest.raises(ioc.IOCError):
        ioc.parse_stix("{broken")


def test_phishing_offline_heuristics():
    def score(u):
        return ph.analyze_url(u)["score"]

    def codes(u):
        return {f["code"] for f in ph.analyze_url(u)["findings"]}
    for official in ("https://www.paypal.com/signin", "https://login.microsoftonline.com/common",
                     "https://www.meezanbank.com/", "https://www.nadra.gov.pk/", "https://github.com/user/repo",
                     "https://groups.google.com/", "https://amazon.co.uk/x"):
        assert score(official) <= 5, official
    assert "brand_subdomain" in codes("paypal.com.secure-login.xyz")
    assert "typosquat" in codes("http://paypa1.com/login") and score("http://paypa1.com/login") >= 70
    assert "typosquat" in codes("https://rnicrosoft.com")
    assert {"homoglyph", "idn"} <= codes("https://pаypal.com/")                     # Cyrillic а
    assert "homoglyph" in codes("https://xn--80ak6aa92e.com")                        # all-Cyrillic "apple"
    assert "at_sign" in codes("https://google.com@evil.tk/login.php")
    assert {"brand_in_domain", "brand_lure"} <= codes("https://hbl-verify-account.top/kyc")
    assert "dynamic_dns" in codes("https://facebook-security-check.duckdns.org")
    assert "exec_download" in codes("https://example.com/download/setup.exe")
    assert "ip_host" in codes("http://203.0.114.5/admin")
    assert "shortener" in codes("https://bit.ly/abc")
    assert "open_redirect" in codes("https://site.com/r?url=https%3A%2F%2Fevil.com")
    assert ph.levenshtein("paypal", "paypa1") == 1 and ph.levenshtein("kitten", "sitting", 5) == 3


def test_page_analysis_flags_fake_login():
    html = """<html><head><title>Sign in to your Microsoft account</title></head><body>
    <form action="https://collector.ru/p.php" method="post"><input type="email" name="login">
    <input type="password" name="passwd"></form>
    <img src="https://www.microsoft.com/a.png"><img src="https://www.microsoft.com/b.png">
    <link href="https://www.microsoft.com/c.css"><script>eval(atob("YWxlcnQoMSk="))</script>
    <p>Your account has been suspended. Verify your identity within 24 hours.</p></body></html>"""
    r = ph.analyze_page(html, "https://office-login.web.app/", "office-login.web.app")
    got = {f["code"] for f in r["findings"]}
    assert {"brand_login_page", "form_offsite", "brand_assets", "obfuscated_js", "urgency"} <= got
    assert r["score"] == 100 and r["password_fields"] == 1
    real = ph.analyze_page(html.replace("collector.ru", "login.live.com"), "https://login.live.com/",
                           "login.live.com")
    assert not {"brand_login_page", "form_offsite", "brand_assets"} & {f["code"] for f in real["findings"]}


def test_feed_parsers():
    items, bad = feeds.parse_lines(FEODO, ["ip"])
    assert [i["value"] for i in items] == [C2_IP, "5.188.86.172"] and bad == 0
    items, bad = feeds.parse_urlhaus(URLHAUS)
    assert len(items) == 2 and bad == 1 and items[0]["host"] == ET_IP and items[1]["threat"] == "malware_download"
    items, bad = feeds.parse_threatfox(feeds.decode(feeds.unpack(zipped("full.csv", THREATFOX), 10 ** 7)))
    by = {i["value"]: i for i in items}
    assert bad == 1 and by[C2_IP]["port"] == 443 and by[C2_IP]["severity"] == "critical" and by[C2_IP]["category"] == "c2"
    assert by[BAD_SHA]["threat"] == "Agent Tesla" and by["http://loader.example-bad.net/a.ps1"].get("threat") is None
    items, bad = feeds.parse_spamhaus(SPAMHAUS)
    assert [i["value"] for i in items] == ["45.153.160.0/24", "2a0b:4340::/32"] and items[0]["threat"] == "SBL567890"
    items, _ = feeds.parse_spamhaus("; Spamhaus DROP List\n1.10.16.0/20 ; SBL256894\n")      # legacy .txt
    assert items[0]["value"] == "1.10.16.0/20"
    items, _ = feeds.parse_hosts("0.0.0.0 evil.com\n127.0.0.1 localhost\n0.0.0.0 ads.bad.net tracker.bad.net # x\n")
    assert [i["value"] for i in items] == ["evil.com", "ads.bad.net", "tracker.bad.net"]
    items, _ = feeds.parse_csv("name,indicator,score\nbad,1.2.3.4,9\nworse,evil.com,8\n", "indicator")
    assert [i["value"] for i in items] == ["1.2.3.4", "evil.com"]
    items, _ = feeds.parse_csv("1.2.3.4,x\n5.6.7.8,y\n")
    assert len(items) == 2
    with pytest.raises(feeds.FeedError):
        feeds.parse_csv("a,b\n1,2\n", "missing")
    assert feeds.parse("auto", SPAMHAUS)[0][0]["type"] == "cidr"
    assert feeds.parse("auto", THREATFOX)[0]
    with pytest.raises(feeds.FeedError):
        feeds.unpack(b"PK\x03\x04broken", 100)
    big = zipped("big.txt", "1.2.3.4\n" * 50000)
    with pytest.raises(feeds.FeedError):
        feeds.unpack(big, 1000)                                   # unpacks to more than allowed


def test_custom_url_rules():
    with pytest.raises(feeds.FeedError) as e:
        feeds.check_custom_url("http://example.com/list.txt")
    assert e.value.status == 422
    for bad in ("https://127.0.0.1/x", "https://192.168.1.5/x", "https://printer.local/x", "https://localhost/x",
                "https://[::1]/x"):
        with pytest.raises(feeds.FeedError) as e:
            feeds.check_custom_url(bad)
        assert e.value.status == 403, bad
    with pytest.raises(feeds.FeedError):
        feeds.check_custom_url("https://user:pw@example.com/x")
    assert feeds.check_custom_url("https://raw.githubusercontent.com/x/y/main/list.txt")


# ====================================================================== feeds + checks
def test_builtin_feeds_refresh_and_check(c):
    st = c.get("/api/intel/status").json()
    assert st["health"]["iocs"] == 0 and st["settings"]["intel_online_lookup"] is False
    j = load_feeds(c)
    res = {f["key"]: f for f in j["result"]["feeds"]}
    assert res["threatfox"]["status"] == "needs_key"               # no abuse.ch key yet -> never even asked
    assert not c.net.hits("threatfox-api")
    assert res["feodo"]["iocs"] == 2 and res["urlhaus"]["iocs"] == 2 and res["openphish"]["iocs"] == 2
    assert "tor_exits" not in res                                  # off by default
    assert not c.net.hits("urlhaus")[0][2].get("Auth-Key")         # optional key not sent when there is none
    f = feed(c, "threatfox")
    assert f["status"] == "needs_key" and f["key_required"] and f["key_ready"] is False and "auth.abuse.ch" in f["key_help"]
    assert feed(c, "urlhaus")["key_required"] is False
    assert "your-abuse.ch-key" in f["url"]

    r = c.post("/api/intel/check", json={"value": C2_IP}).json()
    assert r["verdict"] == "malicious" and r["score"] == 100 and r["matches"][0]["category"] == "c2"
    assert any(a["action"] == "block_ip" for a in r["actions"]) and "Feodo" in r["summary"]
    r = c.post("/api/intel/check", json={"value": DROP_IP}).json()
    assert r["verdict"] == "malicious" and r["matches"][0]["matched_on"] == "cidr" and r["matches"][0]["threat"] == "SBL567890"
    r = c.post("/api/intel/check", json={"value": "2a0b:4340::99"}).json()
    assert r["matches"] and r["matches"][0]["value"] == "2a0b:4340::/32"
    r = c.post("/api/intel/check", json={"value": "hxxps://secure-paypal-login.example-phish[.]com/signin"}).json()
    assert r["verdict"] == "malicious" and r["matches"][0]["feed"] == "openphish" and r["matches"][0]["matched_on"] == "exact"
    r = c.post("/api/intel/check", json={"value": "secure-paypal-login.example-phish.com"}).json()
    assert r["matches"][0]["matched_on"] == "url_host" and r["verdict"] in ("suspicious", "malicious")
    # shared hosting: one bad Google Form must not make all of docs.google.com bad
    r = c.post("/api/intel/check", json={"value": "https://docs.google.com/forms/d/e/1FAIpQLSeEVILFORM/viewform"}).json()
    assert r["verdict"] == "malicious"
    r = c.post("/api/intel/check", json={"value": "https://docs.google.com/document/d/abc/edit"}).json()
    assert r["verdict"] == "clean" and not r["matches"]
    r = c.post("/api/intel/check", json={"value": ET_IP}).json()     # listed by ET + hosts a URLhaus URL
    assert {h["feed"] for h in r["matches"]} == {"et_compromised", "urlhaus"}
    assert next(h for h in r["matches"] if h["feed"] == "urlhaus")["matched_on"] == "url_host"
    r = c.post("/api/intel/check", json={"value": TOR_IP}).json()
    assert r["verdict"] == "clean" and not r["matches"]
    r = c.post("/api/intel/check", json={"value": "192.168.1.20"}).json()
    assert r["private"] and r["verdict"] == "clean" and "own PC" in r["reasons"][-1]
    r = c.post("/api/intel/check", json={"value": CLEAN_IP}).json()
    assert r["verdict"] == "clean" and r["matches"] == [] and any(a["action"] == "add_blocklist" for a in r["actions"])
    r = c.post("/api/intel/check", json={"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}).json()
    assert r["verdict"] == "unknown"                               # absence from lists proves nothing for files
    assert c.post("/api/intel/check", json={"value": "!!!"}).status_code == 422
    h = c.get("/api/intel/checks").json()["items"]
    assert len(h) == 12 and all("?" not in x["value"] for x in h)
    assert c.get("/api/intel/health").json()["iocs"] > 0
    # Tor feed switched on (anyone may raise protection)
    tor = feed(c, "tor_exits")
    assert c.patch(f"/api/intel/feeds/{tor['id']}", json={"enabled": True}).status_code == 200
    load_feeds(c, ["tor_exits"])
    r = c.post("/api/intel/check", json={"value": TOR_IP}).json()
    assert r["verdict"] == "low_risk" and r["matches"][0]["category"] == "tor"


def test_threatfox_with_part8_key_feeds_antivirus(c):
    """The abuse.ch Auth-Key saved for MalwareBazaar (Part 8) unlocks ThreatFox; its hashes become Part 5 signatures."""
    set_abusech_key(c)
    assert feed(c, "threatfox")["key_ready"] is True
    load_feeds(c, ["threatfox", "urlhaus"])
    tf = c.net.hits("threatfox-api")[0]
    assert "/exports/abusech-test-key-0123456789/full.csv.zip" in tf[1]
    assert c.net.hits("urlhaus.abuse.ch")[0][2]["Auth-Key"] == "abusech-test-key-0123456789"
    assert feed(c, "threatfox")["ioc_count"] == 4 and feed(c, "threatfox")["skipped"] == 1
    r = c.post("/api/intel/check", json={"value": "panel.evil-c2-panel.com"}).json()
    assert r["verdict"] == "malicious" and r["matches"][0]["matched_on"] == "parent_domain" and \
        r["matches"][0]["threat"] == "AsyncRAT"
    r = c.post("/api/intel/check", json={"value": "bob@evil-c2-panel.com"}).json()
    assert r["matches"][0]["matched_on"] == "email_domain"
    sig = c.app.state.malware_db.get(BAD_SHA)
    assert sig and sig["source"] == "intel:threatfox" and sig["name"].startswith("Agent Tesla")
    # Part 5 now catches the file offline
    p = c.env / "docs" / "invoice.exe"
    p.write_bytes(BAD_FILE)
    r = c.post("/api/scan/file", json={"path": str(p)})
    assert r.status_code == 200 and r.json()["status"] == "infected", r.text
    r = c.post("/api/intel/check", json={"value": BAD_SHA}).json()
    assert r["verdict"] == "malicious" and r["matches"][0]["feed"] == "threatfox"
    # a user signature with the same hash is never overwritten / removed by the feed
    c.app.state.malware_db.add("b" * 64, "My.Own.Signature", "high", source="user")
    # switching the feed off removes only its own signatures
    tfid = feed(c, "threatfox")["id"]
    std = standard_client(c)
    assert std.patch(f"/api/intel/feeds/{tfid}", json={"enabled": False}).status_code == 403
    assert c.patch(f"/api/intel/feeds/{tfid}", json={"enabled": False}).status_code == 200
    assert c.app.state.malware_db.get(BAD_SHA) is None and c.app.state.malware_db.get("b" * 64)
    assert c.post("/api/intel/check", json={"value": "evil-c2-panel.com"}).json()["matches"] == []
    assert c.patch(f"/api/intel/feeds/{tfid}", json={"enabled": True}).status_code == 200
    assert c.app.state.malware_db.get(BAD_SHA)["source"] == "intel:threatfox"
    # setting off -> signatures leave Part 5 on the next sync
    assert c.patch("/api/settings", json={"intel_hashes_to_signatures": False}).status_code == 200
    svc(c).resync_signatures()
    assert c.app.state.malware_db.get(BAD_SHA) is None


def test_abusech_rejected_key_and_conditional_download(c):
    set_abusech_key(c, "wrong-key-0123456789abcdef")
    c.net.routes["https://threatfox-api.abuse.ch/v2/files/exports/"] = (403, b"forbidden", {})
    load_feeds(c, ["threatfox", "feodo"])
    tf = feed(c, "threatfox")
    assert tf["status"] == "error" and "rejected the Auth-Key" in tf["last_error"]
    assert "wrong-key" not in json.dumps(c.get("/api/intel/feeds").json())       # the key never leaks
    # ETag: second download is "not modified"
    c.net.routes["feodo304"] = True
    svc(c).refresh(None, [feed(c, "feodo")["id"]], wait=True)
    f = feed(c, "feodo")
    assert f["ioc_count"] == 2 and f["status"] == "ok"
    assert c.net.hits("feodotracker")[-1][2]["If-None-Match"] == '"feodo-1"'
    # a broken / empty download never wipes the previous copy and raises one alert per day
    c.net.routes.pop("feodo304")
    c.net.routes["https://feodotracker.abuse.ch/"] = (200, b"<html>maintenance</html>", {})
    load_feeds(c, ["feodo"])
    load_feeds(c, ["feodo"])
    f = feed(c, "feodo")
    assert f["status"] == "error" and f["ioc_count"] == 2 and "keeping the previous copy" in f["last_error"]
    assert c.post("/api/intel/check", json={"value": C2_IP}).json()["verdict"] == "malicious"
    ev = c.get("/api/intel/events?kind=feed_error").json()["items"]
    assert len(ev) == 1 and ev[0]["severity"] == "low"
    c.net.routes["https://feodotracker.abuse.ch/"] = (500, b"", {})
    assert svc(c).refresh(None, [f["id"]], wait=True)
    assert "HTTP 500" in feed(c, "feodo")["last_error"]
    # size cap
    c.patch("/api/settings", json={"intel_max_feed_mb": 1})
    c.net.routes["https://feodotracker.abuse.ch/"] = (200, b"1.2.3.4\n" * 200000, {})
    load_feeds(c, ["feodo"])
    assert "larger" in feed(c, "feodo")["last_error"]


def test_refresh_job_conflict_and_due(c):
    gate = threading.Event()

    def slow(method, url, headers, data):
        gate.wait(5)
        return 200, FEODO.encode(), {}
    c.net.routes["https://feodotracker.abuse.ch/"] = slow
    r = c.post("/api/intel/feeds/refresh", json={"feed_ids": [feed(c, "feodo")["id"]], "force": True})
    assert r.status_code == 200
    assert c.post("/api/intel/feeds/refresh", json={}).status_code == 409
    assert c.get("/api/intel/jobs").json()["running"]
    gate.set()
    assert svc(c).wait(r.json()["id"], 20)["status"] == "done"
    local = feed(c, "local")
    assert c.post("/api/intel/feeds/refresh", json={"feed_ids": [local["id"]]}).status_code == 409   # no URL
    due = {f["key"] for f in svc(c).due_feeds()}
    assert "feodo" not in due and "openphish" in due and "threatfox" in due and "tor_exits" not in due
    out = svc(c).tick()                                       # loop: watch + due feeds + daily cleanup
    assert "refresh" in out and "cleanup" in out
    svc(c).wait(out["refresh"]["id"], 30)
    assert feed(c, "openphish")["ioc_count"] == 2


# ====================================================================== lists
def test_blocklist_allowlist_and_permissions(c):
    load_feeds(c, ["feodo", "et_compromised"])
    std = standard_client(c)
    r = std.post("/api/intel/blocklist", json={"text": "Seen in phishing mail: hxxps://fake-hbl-login[.]top/kyc, "
                                                      "203.0.114.9 and 127.0.0.1", "note": "=HYPERLINK(evil)",
                                              "severity": "critical"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["added"] == 1 + 1 and j["refused"][0]["value"] == "127.0.0.1"
    r = std.post("/api/intel/check", json={"value": "https://fake-hbl-login.top/kyc"}).json()
    assert r["verdict"] == "malicious" and r["matches"][0]["feed"] == "local"
    assert not any(a["action"] == "add_blocklist" for a in r["actions"])
    assert std.post("/api/intel/blocklist", json={"values": ["203.0.114.9"], "severity": "low"}).json()["updated"] == 1
    bl = c.get("/api/intel/blocklist?q=fake").json()
    assert bl["total"] == 1 and bl["items"][0]["defanged"].startswith("hxxps://fake-hbl-login[.]top")
    assert std.post("/api/intel/blocklist/remove", json={"value": "203.0.114.9"}).status_code == 403
    assert c.post("/api/intel/blocklist/remove", json={"value": "203.0.114.9"}).json()["deleted"] == 1
    assert c.post("/api/intel/blocklist/remove", json={"value": "203.0.114.9"}).status_code == 404
    assert c.post("/api/intel/blocklist", json={"values": ["10.0.0.0/7"]}).json()["refused"]
    assert c.post("/api/intel/blocklist", json={"values": ["nope nope"]}).status_code == 422
    # local feed can't be switched off
    assert c.patch(f"/api/intel/feeds/{feed(c, 'local')['id']}", json={"enabled": False}).status_code == 409
    # allow list: admin only, beats every feed, covers sub-domains
    assert std.post("/api/intel/allowlist", json={"value": C2_IP}).status_code == 403
    a = c.post("/api/intel/allowlist", json={"value": C2_IP, "note": "our pentest box"})
    assert a.status_code == 201
    r = c.post("/api/intel/check", json={"value": C2_IP}).json()
    assert r["verdict"] == "clean" and r["allowed"]["note"] == "our pentest box" and r["matches"]
    assert c.post("/api/intel/block-ip", json={"ip": C2_IP}).status_code == 409
    c.post("/api/intel/blocklist", json={"values": ["bad.example-phish.com"]})
    c.post("/api/intel/allowlist", json={"value": "example-phish.com"})
    assert c.post("/api/intel/check", json={"value": "https://x.bad.example-phish.com/a"}).json()["verdict"] == "clean"
    assert c.post("/api/intel/allowlist", json={"value": "10.0.0.0/8"}).status_code == 422
    assert std.delete(f"/api/intel/allowlist/{a.json()['id']}").status_code == 200       # raising protection: anyone
    assert c.post("/api/intel/check", json={"value": C2_IP}).json()["verdict"] == "malicious"


def test_import_export_formats(c):
    stix = ioc.to_stix([{"type": "domain", "value": "stix-evil.com"}, {"type": "ip", "value": "198.18.0.9"},
                        {"type": "sha256", "value": "a" * 64}])
    r = c.post("/api/intel/import", json={"text": json.dumps(stix), "format": "stix", "note": "from CERT"})
    assert r.status_code == 200 and r.json()["added"] == 3, r.text
    assert c.app.state.malware_db.get("a" * 64)["source"] == "intel:local"
    p = c.env / "docs" / "list.csv"
    p.write_text("indicator,comment\nhosts-evil.net,x\n91.200.1.1,y\n")
    r = c.post("/api/intel/import", json={"path": str(p), "format": "csv", "column": "indicator"})
    assert r.json()["added"] == 2
    hz = c.env / "docs" / "hosts.zip"
    hz.write_bytes(zipped("hosts.txt", "0.0.0.0 zipped-evil.org\n"))
    assert c.post("/api/intel/import", json={"path": str(hz), "format": "hosts"}).json()["added"] == 1
    assert c.post("/api/intel/import", json={"text": "nothing here"}).status_code == 422
    assert c.post("/api/intel/import", json={"path": str(c.env / "nope.txt")}).status_code == 404
    c.post("/api/intel/blocklist", json={"values": ["formula-evil.com"], "note": "=cmd|' /C calc'!A0"})
    csv_ = c.get("/api/intel/export?format=csv").content.decode("utf-8-sig")
    assert "'=cmd" in csv_ and "stix-evil.com" in csv_ and "Content-Disposition" not in csv_
    st = c.get("/api/intel/export?format=stix")
    assert st.headers["content-disposition"].endswith('.stix.json"')
    back, _ = ioc.parse_stix(st.text)
    assert {"stix-evil.com", "hosts-evil.net", "zipped-evil.org"} <= {i["value"] for i in back}
    txt = c.get("/api/intel/export?format=txt").text
    assert txt.startswith("# Cyber Hub - Developed by Syed Muhammad Tayyab") and "91.200.1.1" in txt
    assert c.get("/api/intel/export?format=json&what=matches").json()["what"] == "matches"


def test_custom_feed_admin_validation(c):
    std = standard_client(c)
    body = {"name": "Team list", "url": "https://lists.example.org/bad.csv", "format": "csv", "column": "ioc",
            "severity": "medium", "refresh_now": False}
    assert std.post("/api/intel/feeds", json=body).status_code == 403
    assert c.post("/api/intel/feeds", json=dict(body, url="http://lists.example.org/x")).status_code == 422
    assert c.post("/api/intel/feeds", json=dict(body, url="https://192.168.1.10/x")).status_code == 403
    assert c.post("/api/intel/feeds", json=dict(body, format="spamhaus_json")).status_code == 422
    r = c.post("/api/intel/feeds", json=body)
    assert r.status_code == 201, r.text
    fid = r.json()["id"]
    assert c.post("/api/intel/feeds", json=body).status_code == 409
    c.net.routes["https://lists.example.org/bad.csv"] = (200, b"ioc,why\nteam-evil.com,phish\n77.91.124.1,scan\n", {})
    svc(c).refresh(None, [fid], wait=True)
    f = c.get(f"/api/intel/feeds/{fid}").json()
    assert f["ioc_count"] == 2 and f["by_type"] == {"domain": 1, "ip": 1} and not f["builtin"]
    r = c.post("/api/intel/check", json={"value": "team-evil.com"}).json()
    assert r["matches"][0]["feed_name"] == "Team list" and r["matches"][0]["severity"] == "medium"
    assert c.patch(f"/api/intel/feeds/{fid}", json={"refresh_hours": 48, "name": "Team"}).json()["refresh_hours"] == 48
    assert std.patch(f"/api/intel/feeds/{fid}", json={"refresh_hours": 2}).status_code == 403
    assert c.delete(f"/api/intel/feeds/{feed(c, 'feodo')['id']}").status_code == 409
    assert std.delete(f"/api/intel/feeds/{fid}").status_code == 403
    assert c.delete(f"/api/intel/feeds/{fid}").json()["iocs_removed"] == 2
    assert c.post("/api/intel/check", json={"value": "team-evil.com"}).json()["matches"] == []


# ====================================================================== search + hunt + retro hunt
def test_ioc_search(c):
    set_abusech_key(c)
    load_feeds(c)
    s = c.get(f"/api/intel/iocs?q={C2_IP}").json()
    assert s["query_type"] == "ip" and {i["feed"] for i in s["items"]} == {"feodo", "threatfox"}
    s = c.get(f"/api/intel/iocs?q={DROP_IP}").json()
    assert any(i["type"] == "cidr" and i["value"] == "45.153.160.0/24" for i in s["items"])
    s = c.get("/api/intel/iocs?q=asyncrat").json()                       # text search on malware family
    assert s["items"][0]["value"] == "evil-c2-panel.com" and s["items"][0]["category"] == "c2"
    assert c.get("/api/intel/iocs?type=url&feed=urlhaus").json()["total"] == 2
    assert c.get("/api/intel/iocs?threat=Agent%20Tesla").json()["items"][0]["type"] == "sha256"
    assert c.get("/api/intel/iocs?q=100%25_x").json()["total"] == 0     # LIKE wildcards escaped
    assert c.get("/api/intel/iocs?category=hijacked_network").json()["total"] == 2


def test_hunt_across_modules(c):
    db = c.app.state.db
    p = c.env / "docs" / "dropper.exe"
    p.write_bytes(BAD_FILE)
    db.execute("INSERT INTO file_hash_cache(path, size, mtime, sha256, sha1, md5) VALUES (?,?,?,?,?,?)",
               (str(p), len(BAD_FILE), 1.0, BAD_SHA, "1" * 40, "2" * 32))
    db.execute("INSERT INTO realtime_events(path, event, origin, status, sha256, downloaded_from) VALUES "
               "(?,?,?,?,?,?)", (str(p), "created", "folder", "clean", BAD_SHA,
                                 "https://cdn.evil-downloads.net/payload/dropper.exe"))
    c.post("/api/firewall/block/ip", json={"addresses": [C2_IP], "reason": "manual test"})
    c.post("/api/web/targets", json={"kind": "site", "target": "https://shop.evil-downloads.net"})
    h = c.get(f"/api/intel/hunt?value={BAD_SHA}").json()
    assert h["counts"]["files"] == 1 and h["counts"]["realtime"] == 1 and h["items"][0]["exists"]
    h = c.get("/api/intel/hunt?value=hxxps://cdn.evil-downloads[.]net/x").json()
    assert h["counts"]["downloads"] == 1 and "evil-downloads" in h["items"][0]["detail"]
    h = c.get("/api/intel/hunt?value=shop.evil-downloads.net").json()
    assert h["counts"].get("web") == 1
    h = c.get(f"/api/intel/hunt?value={C2_IP}").json()
    assert h["counts"].get("firewall", 0) >= 1 and h["indicator"]["defanged"] == "185.220.101[.]47"
    assert c.get("/api/intel/hunt?value=___").status_code == 422


def test_retro_hunt_files_and_downloads(c):
    db = c.app.state.db
    p = c.env / "docs" / "old-download.exe"
    p.write_bytes(BAD_FILE)
    db.execute("INSERT INTO file_hash_cache(path, size, mtime, sha256, sha1, md5) VALUES (?,?,?,?,?,?)",
               (str(p), len(BAD_FILE), 1.0, BAD_SHA, "1" * 40, "2" * 32))
    db.execute("INSERT INTO realtime_events(path, event, origin, status, downloaded_from) VALUES (?,?,?,?,?)",
               (str(c.env / "docs" / "setup.exe"), "created", "folder", "clean",
                "https://bad-cdn-files.top/update/setup.exe"))
    set_abusech_key(c)
    j = load_feeds(c, ["threatfox", "urlhaus"])
    assert j["result"]["retro_hunt"] == {"files": 1, "downloads": 1}
    ev = {e["kind"]: e for e in c.get("/api/intel/events").json()["items"]}
    f = ev["retro_file"]
    assert f["severity"] == "high" and f["data"]["path"] == str(p) and f["data"]["fix"]["action"] == "scan_file"
    assert "Agent Tesla" in f["detail"]
    d = ev["retro_download"]
    assert d["severity"] == "medium" and d["data"]["host"] == "bad-cdn-files.top"            # file is gone
    assert svc(c).retro_hunt() == {"files": 0, "downloads": 0}                               # alerted once
    # adding to your own block list also retro-hunts
    db.execute("INSERT INTO realtime_events(path, event, origin, status, downloaded_from) VALUES (?,?,?,?,?)",
               (str(p), "created", "folder", "clean", "https://my-own-bad.site/x"))
    r = c.post("/api/intel/blocklist", json={"values": ["my-own-bad.site"]}).json()
    assert r["retro_hunt"]["downloads"] == 1


# ====================================================================== live connections (Part 10 + Part 9)
def test_connection_watch_alert_and_one_click_block(c, child):
    load_feeds(c, ["feodo", "spamhaus_drop", "et_compromised"])
    me = child.pid
    net = c.app.state.network.probe
    net.fake_connections = [out_conn(me, C2_IP), out_conn(me, CLEAN_IP, lport=50124),
                            out_conn(me, "192.168.50.1", 80, 50125), out_conn(me, DROP_IP, 8080, 50126)]
    out = c.post("/api/intel/watch/run").json()
    assert out["checked"] == 3 and out["matches"] == 2 and out["alerts"] == 2 and out["blocked"] == 0
    ev = c.get("/api/intel/events?kind=connection_match").json()
    by = {e["data"]["ip"]: e for e in ev["items"]}
    e = by[C2_IP]
    assert e["severity"] == "critical" and e["data"]["pid"] == me and e["data"]["category"] == "c2"
    assert e["data"]["fix"]["endpoint"] == f"POST /api/intel/events/{e['id']}/block" and e["user_id"] is None
    assert by[DROP_IP]["data"]["matched_on"] == "cidr"
    assert svc(c).watch_once()["alerts"] == 0                             # once a day per address + program
    r = c.post(f"/api/intel/events/{e['id']}/block")
    assert r.status_code == 200, r.text
    blocks = c.get("/api/firewall/blocks").json()
    items = blocks["items"] if isinstance(blocks, dict) else blocks
    assert any(b["target"] == C2_IP and b["kind"] == "ip" and "Threat intel" in (b["reason"] or "") for b in items)
    e = next(x for x in c.get("/api/intel/events?kind=connection_match").json()["items"] if x["id"] == e["id"])
    assert e["acknowledged"] and e["data"]["fix"] is None
    assert c.post("/api/intel/block-ip", json={"ip": "192.168.1.5"}).status_code == 422
    # Part 10 hunt shows the live connection
    h = c.get(f"/api/intel/hunt?value={DROP_IP}").json()
    assert h["counts"].get("live") == 1
    # auto-block (admin setting): only exact C2 matches in 'c2' mode
    std = standard_client(c)
    assert std.patch("/api/settings", json={"intel_auto_block": "c2"}).status_code == 403
    assert c.patch("/api/settings", json={"intel_auto_block": "c2"}).status_code == 200
    net.fake_connections = [out_conn(me, "5.188.86.172", 443, 50130), out_conn(me, ET_IP, 22, 50131)]
    out = svc(c).watch_once()
    assert out["alerts"] == 2 and out["blocked"] == 1
    ab = c.get("/api/intel/events?kind=auto_block").json()["items"]
    assert ab and ab[0]["data"]["ip"] == "5.188.86.172"
    ev = {x["data"]["ip"]: x for x in c.get("/api/intel/events?kind=connection_match").json()["items"]}
    assert ev["5.188.86.172"]["data"]["blocked"]["id"] and ev[ET_IP]["data"]["blocked"] is None
    # allow-listed addresses are never alerted; watch off = nothing
    c.post("/api/intel/allowlist", json={"value": "77.91.0.0/16"})
    load_feeds(c, ["feodo"])
    c.patch("/api/settings", json={"intel_watch_connections": False})
    assert svc(c).watch_once()["skipped"] == "off"
    h = c.get("/api/intel/health").json()
    assert h["open_alerts"]["critical"] >= 1 and h["score"] <= 49 and h["watch_connections"] is False


# ====================================================================== online reputation
def vt_answer(mal, harmless=60):
    return json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": 0,
                                                                         "harmless": harmless, "undetected": 10},
                                               "reputation": -20, "country": "NL", "as_owner": "Bad Host BV",
                                               "categories": {"x": "malware"}}}}).encode()


def test_online_lookups_privacy_cache_and_shared_limits(c):
    net = c.net
    net.routes["https://www.virustotal.com/api/v3/ip_addresses/"] = (200, vt_answer(14), {})
    net.routes["https://www.virustotal.com/api/v3/urls/"] = (200, vt_answer(0, 70), {})
    net.routes["https://www.virustotal.com/api/v3/domains/"] = (404, b"{}", {})
    net.routes["https://urlhaus-api.abuse.ch/v1/host/"] = (200, json.dumps({"query_status": "ok", "url_count": "3", "urls": [
        {"url_status": "online", "threat": "malware_download"}, {"url_status": "offline"}]}).encode(), {})
    net.routes["https://urlhaus-api.abuse.ch/v1/url/"] = (200, b'{"query_status":"no_results"}', {})
    net.routes["https://threatfox-api.abuse.ch/api/v1/"] = (200, b'{"query_status":"no_result"}', {})
    net.routes["https://api.abuseipdb.com/"] = (200, json.dumps({"data": {"abuseConfidenceScore": 96, "totalReports": 412,
                                                                          "countryCode": "NL", "isp": "Bad Host",
                                                                          "isTor": False}}).encode(), {})
    # off by default: nothing leaves the PC
    r = c.post("/api/intel/check", json={"value": "45.9.148.3"}).json()
    assert not r["online_used"] and not net.hits("virustotal")
    # keys: VirusTotal + abuse.ch through Part 8, AbuseIPDB here (admin)
    assert c.put("/api/lookup/keys", json={"virustotal": "vt-key-0123456789abcdef0123",
                                           "malwarebazaar": "abusech-test-key-0123456789"}).status_code == 200
    std = standard_client(c)
    assert std.put("/api/intel/providers/abuseipdb/key", json={"key": "abuseipdb-key-0123456789"}).status_code == 403
    assert c.put("/api/intel/providers/virustotal/key", json={"key": "x" * 20}).status_code == 422
    p = c.put("/api/intel/providers/abuseipdb/key", json={"key": "abuseipdb-key-0123456789abcd"}).json()
    assert p["abuseipdb"]["ready"] and p["abuseipdb"]["key_hint"] == "…abcd" and p["virustotal"]["ready"]
    assert "abuseipdb-key" not in json.dumps(c.get("/api/intel/providers").json())
    r = c.post("/api/intel/check", json={"value": "45.9.148.3", "online": True}).json()
    assert r["online_used"] and r["verdict"] == "malicious"
    assert r["online"]["virustotal"]["malicious"] == 14 and r["online"]["abuseipdb"]["score"] == 96
    assert r["online"]["abusech"]["urlhaus"]["online"] == 1
    assert net.hits("api.abuseipdb.com")[0][2]["Key"] == "abuseipdb-key-0123456789abcd"
    assert net.hits("urlhaus-api")[0][2]["Auth-Key"] == "abusech-test-key-0123456789"
    assert any("VirusTotal: 14 of" in x for x in r["reasons"])
    n = len(net.calls)
    r = c.post("/api/intel/check", json={"value": "45.9.148.3", "online": True}).json()
    assert len(net.calls) == n and r["online"]["virustotal"]["cached"]            # cache, no new request
    # private addresses never go online
    r = c.post("/api/intel/check", json={"value": "10.1.2.3", "online": True}).json()
    assert len(net.calls) == n and "never sent online" in r["online_errors"]["all"]
    # URL: query string stripped unless full_url
    r = c.post("/api/intel/check", json={"value": "https://shop.example.net/reset?token=SECRET123", "online": True}).json()
    sent = [x for x in net.calls[n:] if "SECRET123" in x[1] or (x[3] and b"SECRET123" in x[3])]
    assert not sent and r["online_sent"] == "https://shop.example.net/reset" and r["verdict"] == "clean"
    import base64
    vt_id = base64.urlsafe_b64encode(b"https://shop.example.net/reset").decode().rstrip("=")
    assert any(x[1].endswith(vt_id) for x in net.calls)
    c.post("/api/intel/check", json={"value": "https://shop.example.net/reset?token=SECRET123", "online": True,
                                     "full_url": True})
    assert any(x[3] and b"SECRET123" in x[3] for x in net.calls)                   # only when asked
    # VirusTotal budget is shared with Part 8 (cloud_vt_per_minute)
    c.patch("/api/settings", json={"cloud_vt_per_minute": 1})
    r = c.post("/api/intel/check", json={"value": "never-seen-before.org", "online": True}).json()
    assert "rate limit" in r["online_errors"]["virustotal"].lower()
    # hashes go through Part 8's lookup (VirusTotal + MalwareBazaar) + ThreatFox
    net.routes["https://www.virustotal.com/api/v3/files/"] = (200, json.dumps({"data": {"attributes": {
        "last_analysis_stats": {"malicious": 40, "harmless": 0, "undetected": 20}, "sha256": BAD_SHA,
        "popular_threat_classification": {"suggested_threat_label": "trojan.agenttesla"}}}}).encode(), {})
    net.routes["https://mb-api.abuse.ch/"] = (200, b'{"query_status":"hash_not_found"}', {})
    c.app.state.cloud.transport = lambda m, u, h, d, t: net(m, u, h, d, t)[:2]
    c.patch("/api/settings", json={"cloud_vt_per_minute": 100})
    time.sleep(0.01)
    c.app.state.cloud._recent["virustotal"].clear()
    r = c.post("/api/intel/check", json={"value": BAD_SHA, "online": True}).json()
    assert r["verdict"] == "malicious" and r["online"]["virustotal"]["verdict"] == "malicious"
    assert c.app.state.malware_db.get(BAD_SHA)                                     # Part 8 learned it


def test_bulk_check(c):
    load_feeds(c, ["feodo", "openphish"])
    text = (f"From the incident report: C2 at {C2_IP}, phishing hxxps://secure-paypal-login.example-phish[.]com/signin, "
            f"benign {CLEAN_IP}, internal 192.168.0.4, and the look-alike paypa1.com")
    r = c.post("/api/intel/check/bulk", json={"text": text}).json()
    assert r["total"] == 5 and r["counts"]["malicious"] == 2 and r["items"][0]["score"] == 100
    by = {i["value"]: i for i in r["items"]}
    assert by["paypa1.com"]["verdict"] in ("suspicious", "low_risk") and by["192.168.0.4"]["private"]
    assert c.post("/api/intel/check/bulk", json={"text": "hello world"}).status_code == 422
    many = " ".join(f"1.2.{i // 250}.{i % 250 + 1}" for i in range(501))
    assert c.post("/api/intel/check/bulk", json={"text": many}).status_code == 422
    assert c.post("/api/intel/check/bulk", json={"text": text, "online": True}).json()["online_used"] is True


# ====================================================================== deep check (Part 14 web_probe)
class _Site:
    def __init__(self, routes):
        site = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                st, hdrs, body = site.routes.get(self.path.split("?")[0], (404, [], b"nf"))
                self.send_response(st)
                for k, v in hdrs:
                    self.send_header(k, v.replace("{port}", str(site.port)))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.routes = routes
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


FAKE_LOGIN = b"""<html><head><title>Microsoft 365 - Sign in</title></head><body>
<form action="https://grabber.example-bad.net/save.php" method="post"><input name="loginfmt" type="email">
<input name="passwd" type="password"><input type="submit"></form>
<img src="https://www.microsoft.com/logo.png"><img src="https://www.microsoft.com/a.png">
<img src="https://www.microsoft.com/b.png"></body></html>"""


def test_deep_check_opens_page_safely(c, monkeypatch):
    s = _Site({"/go": (302, [("Location", "http://localhost:{port}/login")], b""),
               "/login": (200, [("Content-Type", "text/html")], FAKE_LOGIN),
               "/payload": (200, [("Content-Type", "application/x-msdownload")], b"MZ" + b"\0" * 100)})
    try:
        monkeypatch.setenv("CYBERHUB_WEB_PUBLIC_HOSTS", "localhost")
        r = c.post("/api/intel/check", json={"value": f"http://localhost:{s.port}/go", "deep": True}).json()
        pg = r["page"]
        assert pg["fetched"] and pg["final_url"].endswith("/login") and len(pg["redirects"]) == 2
        codes = {f["code"] for f in pg["findings"]}
        assert {"brand_login_page", "form_offsite", "brand_assets", "password_form"} <= codes
        assert r["verdict"] == "malicious" and pg["title"] == "Microsoft 365 - Sign in"
        assert any("Microsoft" in x for x in r["reasons"])
        r = c.post("/api/intel/check", json={"value": f"http://localhost:{s.port}/payload", "deep": True}).json()
        assert "serves_file" in {f["code"] for f in r["page"]["findings"]}
        # without the override localhost is this PC -> never opened
        monkeypatch.delenv("CYBERHUB_WEB_PUBLIC_HOSTS")
        r = c.post("/api/intel/check", json={"value": f"http://localhost:{s.port}/go", "deep": True}).json()
        assert r["private"] and r["page"] is None
    finally:
        s.close()


def test_deep_check_rdap_and_redirect_into_lan(c, monkeypatch):
    s = _Site({"/": (200, [("Content-Type", "text/html")], b"<html><title>Hi</title></html>"),
               "/lan": (302, [("Location", "http://192.168.1.1/admin")], b"")})
    try:
        monkeypatch.setenv("CYBERHUB_WEB_PUBLIC_HOSTS", "localhost")
        r = c.post("/api/intel/check", json={"value": f"http://localhost:{s.port}/lan", "deep": True}).json()
        assert "redirect_local" in {f["code"] for f in r["page"]["findings"]}
        # domain age via RDAP (fake): 5-day-old domain
        from datetime import datetime, timedelta, timezone
        reg = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c.net.routes["https://rdap.org/domain/"] = (200, json.dumps({"events": [
            {"eventAction": "registration", "eventDate": reg}]}).encode(), {})
        age = svc(c).domain_age("login.brand-new-shop.com")
        assert age["age_days"] == 5 and c.net.hits("rdap.org/domain/brand-new-shop.com")
        assert svc(c).domain_age("brand-new-shop.com")["cached"]                 # cached 7 days
    finally:
        s.close()


# ====================================================================== dashboard, settings, stream, migration
def test_summary_status_settings_and_events(c, child):
    load_feeds(c, ["feodo", "spamhaus_drop"])
    c.app.state.network.probe.fake_connections = [out_conn(child.pid, C2_IP)]
    svc(c).watch_once()
    c.post("/api/intel/check", json={"value": C2_IP})
    s = c.get("/api/intel/summary").json()
    assert s["iocs_by_type"] == {"ip": 2, "cidr": 2} and s["alerts_per_day"][0]["critical"] == 1
    assert s["checks_per_day"][0]["malicious"] == 1 and s["top_matched_addresses"][0]["ip"] == C2_IP
    assert {f["feed"] for f in s["feeds"]} >= {"feodo", "local"}
    st = c.get("/api/intel/status").json()
    assert st["features"]["connection_watch"] and st["features"]["firewall_block"] and st["unacknowledged"] == 1
    assert st["catalog_reviewed"] == "2026-11-13"
    assert c.post("/api/intel/events/ack", json={}).json()["acknowledged"] == 1
    assert c.get("/api/intel/events?unacknowledged=true").json()["items"] == []
    for bad in ({"intel_auto_block": "everything"}, {"intel_update_hours": 0}, {"intel_online_providers": ["shodan"]}):
        assert c.patch("/api/settings", json=bad).status_code == 422
    std = standard_client(c)
    for k, v in (("intel_watch_connections", False), ("intel_online_lookup", True), ("intel_auto_update", False)):
        assert std.patch("/api/settings", json={k: v}).status_code == 403
    assert std.patch("/api/settings", json={"intel_cache_hours": 6}).status_code == 200
    assert c.delete("/api/intel/checks").json()["deleted"] == 1
    assert c.get("/api/intel/export?what=matches&format=csv").text.count(f"\nip,{C2_IP},critical") == 1
    # activity log category + Part 1 module map
    acts = c.get("/api/activity?category=intel").json()
    assert (acts["items"] if isinstance(acts, dict) else acts)
    info = c.get("/api/info").json()
    assert "intel" in info["available_modules"] and info["progress_percent"] == BUILD_PART * 5 >= 75   # later parts add more
    with c.websocket_connect(f"/api/intel/stream?token={c.headers['X-CyberHub-Token']}&session="
                             f"{c.headers['X-CyberHub-Session']}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "intel" and "events" in msg
    with pytest.raises(Exception):
        with c.websocket_connect("/api/intel/stream?token=bad&session=x") as ws:
            ws.receive_json()
    assert c.get("/api/intel/status", headers={"X-CyberHub-Session": ""}).status_code == 401


def test_cleanup_and_shutdown(c):
    db = c.app.state.db
    db.execute("INSERT INTO intel_events(ts, kind, severity, title) VALUES ('2020-01-01T00:00:00Z','feed_error','low','old')")
    db.execute("INSERT INTO intel_checks(ts, user_id, type, value, verdict, score) VALUES "
               "('2020-01-01T00:00:00Z', 1, 'ip', '1.2.3.4', 'clean', 0)")
    svc(c)._state("conn:1.2.3.4|x", "2020-01-01T00:00:00Z")
    assert svc(c).cleanup() == 2
    assert svc(c)._state("conn:1.2.3.4|x") is None
    svc(c).shutdown()
    assert svc(c)._stopping.is_set()


def test_migration_from_part14_keeps_data(env):
    data = env / "data"
    data.mkdir(parents=True, exist_ok=True)
    db = Database(data / "cyberhub.db")
    db._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, description TEXT, "
                     "applied_at TEXT)")
    for ver, d, sql in MIGRATIONS:
        if ver <= 15:
            db._conn.executescript("BEGIN;" + sql + "COMMIT;")
            db._conn.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (ver, d))
    db._conn.execute("INSERT INTO malware_signatures(hash, hash_type, name, source) VALUES (?,?,?,?)",
                     ("c" * 64, "sha256", "Old.User.Sig", "user"))
    assert db.schema_version() == 15
    db.close()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        assert cl.get("/api/health").json()["schema_version"] == MIGRATIONS[-1][0] >= 16
        assert cl.app.state.malware_db.get("c" * 64)["name"] == "Old.User.Sig"
        keys = {f["key"] for f in cl.get("/api/intel/feeds").json()["items"]}
        assert {"local", "feodo", "urlhaus", "threatfox", "spamhaus_drop", "openphish", "tor_exits"} <= keys
    with TestClient(create_app(Settings(), start_workers=False)) as cl:           # second start: no duplicates
        _login(cl)
        assert len(cl.get("/api/intel/feeds").json()["items"]) == len(feeds.CATALOG) + 1


def test_earlier_parts_still_answer(c):
    """Part 15 adds a service and a migration - every earlier module must still start and answer."""
    for path in ("/api/monitor/overview", "/api/processes/summary", "/api/startup", "/api/scan/jobs", "/api/quarantine",
                 "/api/realtime/status", "/api/rules/status", "/api/lookup/status", "/api/firewall/status",
                 "/api/network/status", "/api/posture/status", "/api/passwords/status", "/api/data/status",
                 "/api/web/status", "/api/account/me", "/api/settings"):
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code, r.text[:200])
    st = c.get("/api/lookup/status").json()                  # Part 8 keys untouched by Part 15's sharing helpers
    assert "providers" in st
