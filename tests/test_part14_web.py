"""
Cyber Hub Backend - Part 14 tests: Website / Developer Scanner
Developed by Syed Muhammad Tayyab

Everything runs against real local servers - no internet needed:
* LocalSite: a threaded HTTP / HTTPS server whose routes each test sets (headers, cookies, debug pages,
  exposed .git / .env files, directory listing, soft-404 pages, slow answers).
* Certificates are generated per test with `cryptography` (test CA, trusted / expired / expiring /
  self-signed / wrong-name leaves); CYBERHUB_WEB_CA_FILE makes the test CA trusted.
* FakeOSV: a local osv.dev (querybatch + vulns/{id}) via CYBERHUB_OSV_URL.
* Dev servers: fake listening sockets through Part 10's MemoryNet + Part 9's memory firewall.
"""
import io
import json
import os
import socket
import ssl
import threading
import time
import zipfile
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psutil
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from cyberhub.config import BUILD_PART, Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import dep_audit as da
from cyberhub.services import web_checks as wc
from cyberhub.services import web_probe as wp

PW = "Cyb3r!Hub#2026"
NOW = datetime.now(timezone.utc)
addr = namedtuple("addr", "ip port")
sconn = namedtuple("sconn", "fd family type laddr raddr status pid")


# ====================================================================== local servers
class _TLSServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, a, handler, ctx):
        super().__init__(a, handler)
        self.ctx = ctx

    def finish_request(self, request, client_address):
        try:
            request.settimeout(5)
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        self.RequestHandlerClass(tls, client_address, self)


class _Plain(ThreadingHTTPServer):
    daemon_threads = True


class LocalSite:
    def __init__(self, ctx: ssl.SSLContext | None = None):
        self.routes: dict = {}
        self.not_found = (404, [("Content-Type", "text/html")], b"<html><body><h1>Not found</h1></body></html>")
        self.delay = 0.0
        self.hits: list = []
        site = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def version_string(self):
                return "LocalSite"                     # no version number in the test server's own header

            def do_GET(self):
                self._go()

            def do_HEAD(self):
                self._go(head=True)

            def _go(self, head=False):
                site.hits.append((self.path, dict(self.headers)))
                if site.delay:
                    time.sleep(site.delay)
                r = site.routes.get(self.path.split("?")[0], site.not_found)
                if callable(r):
                    r = r(self)
                status, headers, body = r
                try:
                    self.send_response(status)
                    for k, v in headers:
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if not head:
                        self.wfile.write(body)
                except OSError:
                    pass
        self.tls = ctx is not None
        self.httpd = _TLSServer(("127.0.0.1", 0), H, ctx) if ctx else _Plain(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

    def url(self, path="/", host="127.0.0.1"):
        return f"{'https' if self.tls else 'http'}://{host}:{self.port}{path}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


GOOD_HEADERS = [("Content-Type", "text/html; charset=utf-8"),
                ("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'self'"),
                ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Permissions-Policy", "camera=(), microphone=()"), ("X-Frame-Options", "SAMEORIGIN")]
GOOD_PAGE = b"<!doctype html><html><head><title>Shop</title></head><body><p>Welcome</p></body></html>"


# ---------------------------------------------------------------- certificates
class PKI:
    def __init__(self, tmp):
        self.tmp = tmp
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CyberHub Test CA"),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberHub Test")])
        self.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.ca_key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(NOW - timedelta(days=30))
                   .not_valid_after(NOW + timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()), critical=False)
                   .sign(self.ca_key, hashes.SHA256()))
        self.ca_file = str(tmp / "ca.pem")
        with open(self.ca_file, "wb") as f:
            f.write(self.ca.public_bytes(serialization.Encoding.PEM))

    def ctx(self, names=("localhost",), days=90, start_days=-1, self_signed=False) -> ssl.SSLContext:
        key = ec.generate_private_key(ec.SECP256R1())
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
        sans = [x509.DNSName(n) for n in names] + [x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))] \
            if "localhost" in names else [x509.DNSName(n) for n in names]
        b = (x509.CertificateBuilder().subject_name(subj)
             .issuer_name(subj if self_signed else self.ca.subject).public_key(key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(NOW + timedelta(days=start_days)).not_valid_after(NOW + timedelta(days=days))
             .add_extension(x509.SubjectAlternativeName(sans), critical=False)
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
        if not self_signed:
            b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                                critical=False)
        cert = b.sign(key if self_signed else self.ca_key, hashes.SHA256())
        n = os.urandom(4).hex()
        cf, kf = self.tmp / f"leaf-{n}.pem", self.tmp / f"leaf-{n}.key"
        cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM) +
                       (b"" if self_signed else self.ca.public_bytes(serialization.Encoding.PEM)))
        kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(str(cf), str(kf))
        return ctx


# ---------------------------------------------------------------- fake osv.dev
VULNS = {
    "GHSA-35jh-r3h4-6jhm": {
        "id": "GHSA-35jh-r3h4-6jhm", "summary": "Command Injection in lodash", "aliases": ["CVE-2021-23337"],
        "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "HIGH"}, "references": [{"url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"}]},
    "GHSA-xvch-5gv4-984h": {
        "id": "GHSA-xvch-5gv4-984h", "summary": "Prototype Pollution in minimist", "aliases": ["CVE-2021-44906"],
        "affected": [{"package": {"ecosystem": "npm", "name": "minimist"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.2.4"},
                                                               {"introduced": "1.0.0"}, {"fixed": "1.2.6"}]}]}],
        "database_specific": {"severity": "CRITICAL"}},
    "PYSEC-2024-0001": {
        "id": "PYSEC-2024-0001", "details": "Django SQL injection in QuerySet.values()\nMore text",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "django"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "4.2"}, {"fixed": "4.2.16"},
                                                                  {"introduced": "5.0"}, {"fixed": "5.0.9"}]}]}],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
    "GHSA-laravel-0001": {
        "id": "GHSA-laravel-0001", "summary": "Laravel environment manipulation",
        "affected": [{"package": {"ecosystem": "Packagist", "name": "laravel/framework"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "10.0.0"}, {"fixed": "10.48.23"}]}]}],
        "database_specific": {"severity": "MODERATE"}},
    "MAL-2025-1234": {
        "id": "MAL-2025-1234", "summary": "Malicious code in evil-pkg (npm)",
        "affected": [{"package": {"ecosystem": "npm", "name": "evil-pkg"}, "versions": ["1.0.0"]}]},
}


class FakeOSV:
    def __init__(self):
        self.vulns = dict(VULNS)
        self.batch_calls = 0
        self.detail_calls = 0
        osv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                osv.batch_calls += 1
                res = []
                for q in body["queries"]:
                    e, n, v = q["package"]["ecosystem"], q["package"]["name"], q["version"]
                    ids = [vid for vid, rec in osv.vulns.items() if da.is_affected(rec, e, n, v)]
                    res.append({"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in ids]} if ids else {})
                self._send(200, {"results": res})

            def do_GET(self):
                vid = self.path.rsplit("/", 1)[-1]
                osv.detail_calls += 1
                if vid in osv.vulns:
                    self._send(200, osv.vulns[vid])
                else:
                    self._send(404, {"code": 5, "message": "Bug not found."})
        self.httpd = _Plain(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# ====================================================================== fixtures
@pytest.fixture()
def osv():
    o = FakeOSV()
    yield o
    o.close()


@pytest.fixture()
def env(tmp_path, monkeypatch, osv):
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
    monkeypatch.setenv("CYBERHUB_OSV_URL", osv.url)
    monkeypatch.delenv("CYBERHUB_WEB_PUBLIC_HOSTS", raising=False)
    monkeypatch.delenv("CYBERHUB_WEB_CA_FILE", raising=False)
    return tmp_path


def _login(cl, user="syed"):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": user, "display_name": "Syed", "password": PW})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": user, "password": PW})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def c(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        cl.env = env
        yield cl


@pytest.fixture()
def site():
    s = LocalSite()
    yield s
    s.close()


@pytest.fixture()
def pki(tmp_path):
    return PKI(tmp_path)


def svc(c):
    return c.app.state.web


def done(c, r, ok=(200,)):
    assert r.status_code in ok, r.text
    j = svc(c).wait(r.json()["id"], 90)
    assert j["status"] != "running"
    return c.get(f"/api/web/scans/{j['id']}").json()


def ids(rep):
    return {f["id"]: f["severity"] for f in rep["result"]["findings"]}


NO_PORTS = ["https", "headers", "content", "tech", "exposure"]


# ====================================================================== targets & scopes
def test_parse_target_and_refusals():
    t = wp.parse_target("Shop.Example.PK/cart?x=1")
    assert t["url"] == "https://shop.example.pk/cart?x=1" and not t["explicit_scheme"] and t["port"] == 443
    assert wp.parse_target("http://[::1]:8080")["url"] == "http://[::1]:8080/"
    assert wp.parse_target("localhost:5173")["origin"] == "https://localhost:5173"
    assert wp.parse_target("bücher.de")["host"] == "xn--bcher-kva.de"
    for bad in ("ftp://x.com", "https://user:pw@x.com", "a b.com", "", "http://x.com:99999", "https://exa<mple.com"):
        with pytest.raises(wp.ProbeError):
            wp.parse_target(bad)
    assert [wp.ip_scope(i) for i in ("127.0.0.1", "::1", "10.1.2.3", "192.168.1.5", "100.64.1.1", "8.8.8.8",
                                     "169.254.169.254", "fe80::1", "224.0.0.1", "0.0.0.0", "::ffff:127.0.0.1")] == \
        ["loopback", "loopback", "private", "private", "private", "public", "refused", "refused", "refused",
         "refused", "loopback"]
    assert wp.scope_of("x", ["8.8.8.8", "10.0.0.1"])[0] == "public"
    assert wp.scope_of("x", ["169.254.169.254"])[0] == "refused"


def test_api_refuses_bad_targets(c):
    assert c.post("/api/web/scan", json={"target": "http://169.254.169.254/latest/meta-data"}).status_code == 403
    assert c.post("/api/web/scan", json={"target": "ftp://files.example.com"}).status_code == 422
    r = c.post("/api/web/scan", json={"target": "https://admin:secret@site.pk"})
    assert r.status_code == 422 and "credentials" in r.json()["detail"]
    assert c.post("/api/web/scan", json={"target": "no-such-host.invalid"}).status_code == 422
    assert c.post("/api/web/scan", json={"target": "127.0.0.1", "checks": ["sqlmap"]}).status_code == 422
    assert c.post("/api/web/project/scan", json={"path": "/definitely/not/here"}).status_code == 404
    assert c.post("/api/web/project/scan", json={"path": "/"}).status_code == 403


# ====================================================================== analyzers (no network)
def H(**kw):
    return {k.replace("_", "-").lower(): [v] for k, v in kw.items()}


def test_headers_good_and_bad():
    good = H(strict_transport_security="max-age=31536000; includeSubDomains",
             content_security_policy="default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'",
             x_content_type_options="nosniff", referrer_policy="no-referrer", permissions_policy="camera=()")
    fs, ok, facts = wc.analyze_headers(good, True)
    assert fs == [] and {p["id"] for p in ok} >= {"hsts", "csp", "clickjacking", "nosniff", "referrer", "permissions"}
    assert facts["hsts"]["include_subdomains"]
    fs, ok, _ = wc.analyze_headers(H(server="nginx/1.18.0", x_powered_by="PHP/7.4.3"), True)
    got = {f["id"]: f["severity"] for f in fs}
    assert got == {"hsts_missing": "medium", "csp_missing": "medium", "clickjacking": "medium", "nosniff_missing": "low",
                   "referrer_missing": "low", "permissions_missing": "low", "server_version": "low", "powered_by": "low"}
    fs, _, _ = wc.analyze_headers(H(strict_transport_security="max-age=600",
                                    content_security_policy="default-src * 'unsafe-inline' 'unsafe-eval'",
                                    x_frame_options="ALLOW-FROM https://x.com", referrer_policy="unsafe-url"), True)
    got = {f["id"]: f["severity"] for f in fs}
    assert got["hsts_short"] == "low" and got["csp_unsafe_inline"] == "medium" and got["csp_wildcard"] == "medium"
    assert got["csp_unsafe_eval"] == "low" and got["xfo_allow_from"] == "low" and got["referrer_unsafe"] == "medium"
    fs, _, _ = wc.analyze_headers(H(strict_transport_security="max-age=0"), True)
    assert {f["id"]: f["severity"] for f in fs}["hsts_short"] == "medium"
    fs, _, _ = wc.analyze_headers({}, False, is_html=False)
    assert fs == []                                         # plain-HTTP API answer: nothing to say about headers


def test_cors_and_cookies():
    evil = "https://cyberhub-cors-check.invalid"
    f = wc.analyze_cors(H(access_control_allow_origin=evil, access_control_allow_credentials="true"), evil)
    assert f[0]["id"] == "cors_reflect_creds" and f[0]["severity"] == "high"
    assert wc.analyze_cors(H(access_control_allow_origin=evil), evil)[0]["severity"] == "medium"
    assert wc.analyze_cors(H(access_control_allow_origin="*"), evil) == []
    assert wc.analyze_cors(H(access_control_allow_origin="*", access_control_allow_credentials="true"),
                           evil)[0]["id"] == "cors_wildcard_creds"
    fs, ok, cookies = wc.analyze_cookies(["PHPSESSID=abc123; path=/", "theme=dark; Secure; SameSite=Lax",
                                          "track=1; SameSite=None"], True)
    got = {f["id"]: f for f in fs}
    assert got["cookie_secure"]["severity"] == "medium" and "PHPSESSID" in got["cookie_secure"]["evidence"]
    assert got["cookie_httponly"]["evidence"] == "PHPSESSID" and "cookie_samesite_none" in got
    assert [c["name"] for c in cookies] == ["PHPSESSID", "theme", "track"]
    assert all("abc123" not in json.dumps(x) for x in (fs, cookies))   # values are never kept
    fs, ok, _ = wc.analyze_cookies(["sid=1; Secure; HttpOnly; SameSite=Strict"], True)
    assert fs == [] and ok


def test_page_content_checks():
    html = """<html><head><meta name="generator" content="WordPress 6.4.2">
      <script src="http://cdn.example.com/a.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
      <script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>
      <script src="/static/app.js"></script>
      <link rel="stylesheet" href="https://cdn.x.com/s.css" integrity="sha384-x">
      </head><body><img src="http://img.example.com/logo.png">
      <form action="http://shop.example.com/login" method="post"><input type="password" name="p"></form></body></html>"""
    fs, ok, facts = wc.analyze_html(html, "https://shop.example.com/", True)
    got = {f["id"]: f["severity"] for f in fs}
    assert got == {"mixed_active": "medium", "mixed_passive": "low", "form_http": "high", "sri_missing": "low",
                   "compromised_cdn": "critical"}
    assert facts["generator"] == "WordPress 6.4.2" and facts["external_scripts_without_sri"] == 3
    assert "https://shop.example.com/static/app.js" in facts["scripts"]
    fs, _, _ = wc.analyze_html('<form><input type="password"></form>', "http://x.pk/", False)
    assert [f["id"] for f in fs] == ["password_http"]


def test_debug_page_detection():
    pages = {
        "django_debug": "<p>You’re seeing this error because you have <code>DEBUG = True</code> in your Django",
        "laravel_debug": "<title>Whoops! There was an error.</title>",
        "werkzeug_debugger": "<title>TypeError // Werkzeug Debugger</title>",
        "php_errors": "<b>Warning</b>:  include(x.php): failed to open stream in <b>/var/www/a.php</b> on line <b>3</b>",
        "python_traceback": "Traceback (most recent call last):\n  File \"app.py\"",
        "aspnet_ysod": "<h1>Server Error in '/' Application.</h1>",
    }
    for fid, text in pages.items():
        assert [f["id"] for f in wc.find_debug_leaks(text, "x")] == [fid], fid
    assert wc.find_debug_leaks("<html>All good</html>", "x") == []
    assert wc.find_debug_leaks(pages["werkzeug_debugger"], "x")[0]["severity"] == "critical"


def test_fingerprint_and_vulnerable_versions():
    now = datetime(2026, 11, 13, tzinfo=timezone.utc)
    techs, fs = wc.fingerprint(
        H(server="Microsoft-IIS/7.5", x_powered_by="PHP/8.2.12", x_aspnet_version="4.0.30319"), ["laravel_session"],
        '<div id="__next"></div><script id="__NEXT_DATA__"></script>', None,
        ["https://code.jquery.com/jquery-1.8.3.min.js", "/js/bootstrap.bundle.min.js?ver=4.1.3",
         "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js",
         "https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js",
         "https://cdn.jsdelivr.net/npm/handlebars@4.0.5/dist/handlebars.min.js",
         "https://unpkg.com/vue@2.7.14/dist/vue.js", "/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"],
        {"/js/moment.js": "//! moment.js\n//! version : 2.24.0\n"}, now)
    names = {t["name"]: t["version"] for t in techs}
    assert names["jQuery"] == "1.8.3" and names["Bootstrap"] == "4.1.3" and names["AngularJS"] == "1.8.2"
    assert names["Lodash"] == "4.17.15" and names["Moment.js"] == "2.24.0" and names["Vue"] == "2.7.14"
    assert names["Microsoft IIS"] == "7.5" and names["PHP"] == "8.2.12" and "Laravel" in names and "Next.js" in names
    got = {f["id"]: f for f in fs}
    assert got["lib_jquery"]["severity"] == "high" and got["lib_jquery"]["fixed"] == "3.5.0"
    assert got["lib_bootstrap"]["severity"] == "medium" and got["lib_lodash"]["fixed"] == "4.17.21"
    assert got["lib_handlebars"]["severity"] == "high" and got["lib_angularjs"]["severity"] == "medium"
    assert got["lib_momentjs"]["severity"] == "medium" and got["eol_vue"]["severity"] == "low"
    assert got["iis_eol"]["severity"] == "high" and got["php_eol_soon"]["severity"] == "low"     # 8.2 ends 2026-12-31
    techs, fs = wc.fingerprint(H(x_powered_by="PHP/8.1.2"), [], "", "WordPress 6.6", ["/x/jquery-3.7.1.min.js"], None, now)
    got = {f["id"]: f["severity"] for f in fs}
    assert got == {"php_eol": "high", "wp_version": "low"}                     # jQuery 3.7.1 is fine


def _tls(**kw):
    base = {"available": True, "trusted": True, "verify_code": None, "verify_error": None, "hostname_ok": True,
            "host": "shop.pk", "cipher": "TLS_AES_256_GCM_SHA384", "versions": {"TLS 1.0": False, "TLS 1.1": False,
                                                                                 "TLS 1.2": True, "TLS 1.3": True},
            "cert": {"days_left": 80, "not_after": "2027-02-01T00:00:00Z", "not_before": "2026-11-01T00:00:00Z",
                     "not_yet_valid": False, "signature_hash": "sha256", "key_type": "EC", "key_bits": 256,
                     "issuer": "R11", "issuer_org": "Let's Encrypt", "sans": ["shop.pk"], "subject": "shop.pk"}}
    for k, v in kw.items():
        if k in ("days_left", "signature_hash", "key_type", "key_bits"):
            base["cert"][k] = v
        else:
            base[k] = v
    return base


def test_tls_evaluation():
    fs, ok = wc.evaluate_tls(_tls(), "public", 21, True)
    assert fs == [] and {p["id"] for p in ok} >= {"cert_valid", "cert_trusted", "tls_modern", "http_redirect"}
    sev = lambda **kw: {f["id"]: f["severity"] for f in wc.evaluate_tls(_tls(**kw), kw.pop("scope", "public"), 21,
                                                                         kw.pop("redir", None))[0]}
    assert sev(days_left=-3, trusted=False, verify_code=10, verify_error="certificate has expired") == \
        {"cert_expired": "critical"}
    assert sev(days_left=5) == {"cert_expiring": "high"} and sev(days_left=15) == {"cert_expiring": "medium"}
    assert sev(trusted=False, verify_code=18, verify_error="self-signed certificate") == {"cert_self_signed": "high"}
    fs, _ = wc.evaluate_tls(_tls(trusted=False, verify_code=18, verify_error="self-signed certificate"), "loopback",
                            21, None)
    assert fs[0]["severity"] == "low"
    assert sev(trusted=False, verify_code=62, verify_error="Hostname mismatch", hostname_ok=False) == \
        {"cert_hostname": "high"}
    assert sev(trusted=False, verify_code=20, verify_error="unable to get local issuer certificate") == \
        {"cert_untrusted": "high"}
    assert sev(versions={"TLS 1.0": True, "TLS 1.1": True, "TLS 1.2": True, "TLS 1.3": False}) == \
        {"tls_old": "medium", "tls13_missing": "low"}
    assert sev(cipher="DES-CBC3-SHA") == {"tls_weak_cipher": "high"}
    assert sev(signature_hash="sha1", key_type="RSA", key_bits=1024) == {"cert_sha1": "high", "cert_weak_key": "high"}
    fs, _ = wc.evaluate_tls(_tls(), "public", 21, False)
    assert [f["id"] for f in fs] == ["http_no_redirect"]
    fs, _ = wc.evaluate_tls({"available": False, "error": "refused"}, "public", 21, None)
    assert fs[0]["id"] == "https_missing" and fs[0]["severity"] == "high"


def test_port_evaluation():
    res = [{"port": p, "service": wp.PORTS[p], "state": "open", "banner": b} for p, b in
           ((22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"), (443, None), (2375, None), (6379, None), (3306, "MySQL 8.0.36"),
            (21, "220 ProFTPD Server"))] + [{"port": 23, "service": "Telnet", "state": "closed", "banner": None}]
    fs, ok, sw = wc.evaluate_ports(res, "public", 443)
    got = {f["id"]: f["severity"] for f in fs}
    assert got == {"port_2375": "critical", "port_6379": "critical", "port_3306": "high", "port_21": "medium",
                   "openssh_regresshion": "medium"}
    assert {"service": "SSH", "product": "OpenSSH", "version": "9.6p1"} in sw
    fs, _, _ = wc.evaluate_ports(res, "private", 443)
    assert {f["id"]: f["severity"] for f in fs}["port_2375"] == "high"         # one step lower inside your network
    fs, ok, _ = wc.evaluate_ports([{"port": 443, "service": "HTTPS", "state": "open", "banner": None}], "public", 443)
    assert fs == [] and ok


def test_scoring_and_grades():
    F = lambda s, cat="headers", i="x": {"id": i + s, "severity": s, "category": cat}
    assert wc.score([])["grade"] == "A+" and wc.score([])["score"] == 100
    assert wc.score([F("low")])["grade"] == "A+"
    assert wc.score([F("medium")])["grade"] == "A"
    s = wc.score([F("high")] + [F("low", i=str(i)) for i in range(2)])
    assert s["score"] <= 84 and s["grade"] in ("B", "C")
    s = wc.score([F("critical", "exposure"), F("low")])
    assert s["score"] <= 49 and s["grade"] == "F" and s["categories"]["exposure"]["grade"] == "F"
    assert s["categories"]["headers"]["grade"] == "A+" and s["by_severity"]["critical"] == 1
    G = lambda i, s: {"id": i, "severity": s, "category": "headers"}
    d = wc.diff([G("a", "medium"), G("b", "low")], [G("a", "high"), G("c", "low")])
    assert [x["id"] for x in d["new"]] == ["c"] and [x["id"] for x in d["fixed"]] == ["b"]
    assert [x["id"] for x in d["worse"]] == ["a"]


def test_exposure_validators_reject_soft_404():
    git = next(p for p in wc.EXPOSURE_PROBES if p["path"] == "/.git/HEAD")
    env = next(p for p in wc.EXPOSURE_PROBES if p["path"] == "/.env")
    html = b"<!doctype html><html><body>Page not found ref: refs/heads/main DB_PASSWORD=x APP_KEY=y</body></html>"
    base = wc.soft404_signature(200, html)
    assert wc.check_exposure(git, 200, b"ref: refs/heads/main\n", {}, base)
    assert wc.check_exposure(git, 200, b"9fceb02d0ae598e95dc970b74767f19372d61af8\n", {}, base)
    assert not wc.check_exposure(git, 200, html, {}, base)
    assert not wc.check_exposure(git, 404, b"ref: refs/heads/main", {}, None)
    assert wc.check_exposure(env, 200, b"APP_NAME=Shop\nDB_PASSWORD=secret123\nAPP_DEBUG=false\n", {}, base)
    assert not wc.check_exposure(env, 200, b"# just a comment\nNODE_ENV=production\n", {}, base)
    assert not wc.check_exposure(env, 200, html, {}, base)
    ds = next(p for p in wc.EXPOSURE_PROBES if p["path"] == "/.DS_Store")
    assert wc.check_exposure(ds, 200, b"\x00\x00\x00\x01Bud1\x00\x00", {}, None)
    assert wc.robots_paths("User-agent: *\nDisallow: /admin/\nDisallow: /blog/\nDisallow: /backup-2024/") == \
        ["/admin/", "/backup-2024/"]


# ====================================================================== dependency parsing / matching
def test_semver_pep440_and_osv_ranges():
    assert da.vcmp("npm", "1.0.0-alpha", "1.0.0-alpha.1") == -1
    assert da.vcmp("npm", "1.0.0-alpha.beta", "1.0.0-beta") == -1
    assert da.vcmp("npm", "1.0.0-rc.1", "1.0.0") == -1 and da.vcmp("npm", "v2.0.0", "2.0.0") == 0
    assert da.vcmp("Packagist", "10.48.22", "10.48.23") == -1 and da.vcmp("npm", "1.10.0", "1.9.9") == 1
    assert da.vcmp("PyPI", "2.0.0rc1", "2.0.0") == -1 and da.vcmp("PyPI", "1.0.post1", "1.0") == 1
    assert da.vcmp("PyPI", "1.0.dev1", "1.0a1") == -1 and da.vcmp("PyPI", "not a version", "1.0") is None
    fb = da._pep440_fallback
    assert fb("1.0.dev1") < fb("1.0a1") < fb("1.0rc1") < fb("1.0") < fb("1.0.post1") < fb("1.1")
    mm = VULNS["GHSA-xvch-5gv4-984h"]
    assert [da.is_affected(mm, "npm", "minimist", v) for v in ("0.0.8", "0.2.4", "1.0.0", "1.2.5", "1.2.6", "2.0.0")] \
        == [True, False, True, True, False, False]
    assert da.fixed_in(mm, "npm", "minimist", "1.2.5") == "1.2.6" and da.fixed_in(mm, "npm", "minimist", "0.1.0") == "0.2.4"
    la = {"affected": [{"package": {"ecosystem": "PyPI", "name": "Pillow"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "9.0"}, {"last_affected": "9.5.0"}]}]}]}
    assert da.is_affected(la, "PyPI", "pillow", "9.5.0") and not da.is_affected(la, "PyPI", "PILLOW", "9.5.1")
    assert da.is_affected(VULNS["MAL-2025-1234"], "npm", "evil-pkg", "1.0.0")
    assert not da.is_affected(VULNS["MAL-2025-1234"], "npm", "evil-pkg", "1.0.1")
    assert da.vuln_severity(VULNS["MAL-2025-1234"]) == ("critical", None)
    assert da.vuln_severity(VULNS["PYSEC-2024-0001"]) == ("critical", 9.8)
    assert da.vuln_severity(VULNS["GHSA-laravel-0001"])[0] == "medium"
    assert da.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert da.cvss3_score("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N") == 2.5
    assert da.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert da.cvss3_score("CVSS:4.0/AV:N") is None and da.rating(0.0) == "info"
    c = da.compact(VULNS["PYSEC-2024-0001"])
    assert c["summary"] == "Django SQL injection in QuerySet.values()" and c["severity"] == "critical"


def test_lockfile_parsers(tmp_path):
    lock3 = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"minimist": "^1.2.0"}},
        "node_modules/lodash": {"version": "4.17.20"}, "node_modules/minimist": {"version": "1.2.5", "dev": True},
        "node_modules/@babel/core": {"version": "7.24.0", "dev": True},
        "node_modules/x/node_modules/lodash": {"version": "4.17.21"}, "packages/app": {"link": True}}}
    got = da.parse_package_lock(json.dumps(lock3), "package-lock.json")
    assert {(d["name"], d["version"], d["direct"], d["dev"]) for d in got} == {
        ("lodash", "4.17.20", True, False), ("minimist", "1.2.5", True, True), ("@babel/core", "7.24.0", False, True),
        ("lodash", "4.17.21", False, False)}
    lock1 = {"lockfileVersion": 1, "dependencies": {"express": {"version": "4.17.1", "dependencies": {
        "qs": {"version": "6.7.0"}}}, "mylib": {"version": "github:me/mylib#abc"}}}
    got = da.parse_package_lock(json.dumps(lock1), "package-lock.json")
    assert [(d["name"], d["version"], d["direct"]) for d in got] == [("express", "4.17.1", True), ("qs", "6.7.0", False),
                                                                     ("mylib", None, True)]
    yarn1 = '# yarn lockfile v1\n\n"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":\n  version "7.12.13"\n' \
            '  resolved "https://x"\n\nlodash@^4.17.15:\n  version "4.17.20"\n'
    assert [(d["name"], d["version"]) for d in da.parse_yarn_lock(yarn1, "yarn.lock")] == \
        [("@babel/code-frame", "7.12.13"), ("lodash", "4.17.20")]
    berry = '__metadata:\n  version: 6\n\n"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"' \
            '\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n'
    assert [(d["name"], d["version"]) for d in da.parse_yarn_lock(berry, "yarn.lock")] == [("lodash", "4.17.21")]
    pnpm6 = "lockfileVersion: '6.0'\n\ndependencies:\n  lodash:\n    specifier: ^4\n    version: 4.17.20\n\npackages:\n\n" \
            "  /lodash@4.17.20:\n    resolution: {integrity: sha512-x}\n    dev: false\n\n" \
            "  /@types/node@20.11.5:\n    dev: true\n\n  /react-dom@18.2.0(react@18.2.0):\n    dev: false\n"
    assert [(d["name"], d["version"]) for d in da.parse_pnpm_lock(pnpm6, "pnpm-lock.yaml")] == \
        [("lodash", "4.17.20"), ("@types/node", "20.11.5"), ("react-dom", "18.2.0")]
    pnpm9 = "lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {}\n\n  '@scope/pkg@1.2.3':\n" \
            "    resolution: {}\n\nsnapshots:\n\n  lodash@4.17.21: {}\n"
    assert [(d["name"], d["version"]) for d in da.parse_pnpm_lock(pnpm9, "pnpm-lock.yaml")] == \
        [("lodash", "4.17.21"), ("@scope/pkg", "1.2.3")]
    (tmp_path / "requirements.txt").write_text("# app\nDjango==4.2.3  # web\nrequests>=2.0\nnumpy\n-r dev.txt\n"
                                               "-e git+https://github.com/x/y#egg=y\nuvicorn[standard]==0.29.0 ; "
                                               "python_version>'3.8'\nflask==2.*\n")
    (tmp_path / "dev.txt").write_text("pytest==8.0.0\n")
    pinned, loose = da.parse_requirements(str(tmp_path / "requirements.txt"), "requirements.txt")
    assert [(d["name"], d["version"]) for d in pinned] == [("Django", "4.2.3"), ("pytest", "8.0.0"),
                                                          ("uvicorn", "0.29.0")]
    assert loose == ["requests", "numpy", "flask"]
    pip = {"default": {"django": {"version": "==4.2.3"}}, "develop": {"black": {"version": "==24.1.0"}}}
    assert [(d["name"], d["version"], d["dev"]) for d in da.parse_pipfile_lock(json.dumps(pip), "Pipfile.lock")] == \
        [("django", "4.2.3", False), ("black", "24.1.0", True)]
    poetry = '[[package]]\nname = "django"\nversion = "4.2.3"\ncategory = "main"\n\n[[package]]\nname = "pytest"\n' \
             'version = "8.0.0"\ncategory = "dev"\n\n[metadata]\nlock-version = "2.0"\n'
    assert [(d["name"], d["version"], d["dev"]) for d in da.parse_toml_lock(poetry, "poetry.lock")] == \
        [("django", "4.2.3", False), ("pytest", "8.0.0", True)]
    uv = '[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "httpx"\n' \
         'version = "0.27.0"\nsource = { registry = "https://pypi.org/simple" }\n'
    assert [(d["name"], d["version"]) for d in da.parse_toml_lock(uv, "uv.lock")] == [("httpx", "0.27.0")]
    comp = {"packages": [{"name": "laravel/framework", "version": "v10.0.0"}, {"name": "x/y", "version": "dev-main"}],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.2"}]}
    assert [(d["name"], d["version"], d["dev"]) for d in da.parse_composer_lock(json.dumps(comp), "composer.lock")] == \
        [("laravel/framework", "10.0.0", False), ("phpunit/phpunit", "10.5.2", True)]
    pj = {"dependencies": {"lodash": "^4.17.15", "local": "file:../x", "any": "*"}, "devDependencies": {"jest": "~29.1"}}
    assert [(d["name"], d["version"], d["approx"]) for d in da.parse_package_json(json.dumps(pj), "package.json")] == \
        [("lodash", "4.17.15", True), ("local", None, True), ("any", None, True), ("jest", "29.1.0", True)]


def test_collect_skips_dependency_folders(tmp_path):
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}))
    (tmp_path / "web" / "package.json").write_text('{"dependencies": {"lodash": "^4"}}')
    (tmp_path / "web" / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "web" / "node_modules" / "x" / "package.json").write_text('{"dependencies": {"evil": "1.0.0"}}')
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "package.json").write_text('{"dependencies": {"express": "^4.17.1"}}')
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "composer.lock").write_text("{not json")
    col = da.collect(str(tmp_path))
    assert {(d["name"], d["version"], d["approx"]) for d in col["deps"]} == {("lodash", "4.17.20", False),
                                                                             ("express", "4.17.1", True)}
    assert col["no_lockfile"] == ["api/package.json"] and col["errors"][0]["file"] == "broken/composer.lock"
    assert {f["file"] for f in col["files"]} == {"web/package-lock.json", "api/package.json"}


def test_project_config_checks(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".env").write_text("APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=base64:abc\n")
    (tmp_path / ".gitignore").write_text("node_modules/\n")
    (tmp_path / "mysite").mkdir()
    (tmp_path / "mysite" / "settings.py").write_text("DEBUG = True\nSECRET_KEY = 'k8#2jd9$lskdjf9283jksdf9823jksdf'\n")
    (tmp_path / ".npmrc").write_text("//registry.npmjs.org/:_authToken=npm_AbCdEf1234567890xyz\n")
    (tmp_path / "app.py").write_text("app.run(host='0.0.0.0', debug=True)\n")
    got = {f["id"]: f["severity"] for f in da.config_checks(str(tmp_path))}
    assert got == {"env_not_ignored": "high", "laravel_debug_prod": "high", "django_debug_setting": "low",
                   "django_secret_in_code": "medium", "npmrc_token": "high", "flask_debug_run": "medium"}
    (tmp_path / ".gitignore").write_text("node_modules/\n.env*\n")
    (tmp_path / ".npmrc").write_text("//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
    got = {f["id"] for f in da.config_checks(str(tmp_path))}
    assert "env_not_ignored" not in got and "npmrc_token" not in got


# ====================================================================== website scans (API, local servers)
def bad_site(site):
    page = (b"<!doctype html><html><head><title>Shop</title><script src=\"/static/jquery-1.8.3.min.js\"></script>"
            b"</head><body><p>BODY-MARKER-7731</p></body></html>")
    site.routes["/"] = (200, [("Content-Type", "text/html"), ("Server", "Apache/2.2.15 (CentOS)"),
                              ("X-Powered-By", "PHP/7.4.3"),
                              ("Set-Cookie", "PHPSESSID=SECRETCOOKIEVALUE123; Path=/")], page)
    site.routes["/static/jquery-1.8.3.min.js"] = (200, [("Content-Type", "application/javascript")],
                                                   b"/*! jQuery v1.8.3 jquery.com | jquery.org/license */\n(function(){})")
    site.routes["/.git/HEAD"] = (200, [("Content-Type", "text/plain")], b"ref: refs/heads/main\n")
    site.routes["/.git/config"] = (200, [("Content-Type", "text/plain")], b"[core]\n\trepositoryformatversion = 0\n")
    site.routes["/.env"] = (200, [("Content-Type", "text/plain")],
                            b"APP_NAME=Shop\nDB_PASSWORD=hunter2hunter\nAPP_KEY=base64:xyz\n")
    site.routes["/uploads/"] = (200, [("Content-Type", "text/html")],
                                b"<html><head><title>Index of /uploads</title></head><body></body></html>")
    site.routes["/phpinfo.php"] = (200, [("Content-Type", "text/html")], b"<html><body>Hello</body></html>")
    site.not_found = (404, [("Content-Type", "text/html")],
                      "<html><body>Page not found. You’re seeing this error because you have <code>DEBUG = True</code>"
                      " in your Django settings file.</body></html>".encode())


def test_site_scan_finds_real_problems(c, site):
    bad_site(site)
    rep = done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": NO_PORTS, "save": True}))
    assert rep["status"] == "done" and rep["kind"] == "site"
    res = rep["result"]
    got = ids(rep)
    for fid, sev in {"exposed_git": "critical", "exposed_env": "critical", "django_debug": "high",
                     "dir_listing": "medium", "csp_missing": "medium", "clickjacking": "medium",
                     "cookie_httponly": "medium", "lib_jquery": "high", "php_eol": "high", "apache_eol": "high",
                     "server_version": "low", "https_missing": "low"}.items():
        assert got.get(fid) == sev, (fid, got)
    assert "exposed_phpinfo" not in got                      # 200 page without phpinfo content = not reported
    assert res["score"]["grade"] == "F" and res["score"]["score"] <= 49
    assert res["target"]["scope"] == "loopback" and res["skipped"] == [] and res["exposure"]["probed"] > 20
    assert {"name": "jQuery", "version": "1.8.3"}.items() <= next(t for t in res["technologies"]
                                                                   if t["name"] == "jQuery").items()
    assert res["cookies"] == [{"name": "PHPSESSID", "secure": False, "httponly": False, "samesite": None,
                               "session_like": True, "domain": None, "persistent": False}]
    git = next(f for f in res["findings"] if f["id"] == "exposed_git")
    assert git["evidence"].endswith("/.git/HEAD") and git["advice"]
    assert res["findings"][0]["severity"] == "critical"      # most severe first
    assert res["score"]["categories"]["exposure"]["grade"] == "F"
    t = c.get("/api/web/targets").json()["items"]
    assert len(t) == 1 and t[0]["last_grade"] == "F" and t[0]["last_scan_id"] == rep["id"]
    # values and page bodies never reach the database
    c.app.state.db.execute("PRAGMA wal_checkpoint(FULL)")
    raw = b"".join(open(p, "rb").read() for p in (c.app.state.settings.db_path,
                                                  str(c.app.state.settings.db_path) + "-wal") if os.path.exists(p))
    assert b"SECRETCOOKIEVALUE123" not in raw and b"BODY-MARKER-7731" not in raw and b"hunter2hunter" not in raw


def test_good_site_gets_top_grade_and_passed_checks(c, site):
    site.routes["/"] = (200, GOOD_HEADERS + [("Set-Cookie", "sid=1; HttpOnly; SameSite=Lax")], GOOD_PAGE)
    site.routes["/.well-known/security.txt"] = (200, [("Content-Type", "text/plain")],
                                                b"Contact: mailto:security@shop.pk\nExpires: 2027-01-01T00:00:00Z\n")
    rep = done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": NO_PORTS}))
    got = ids(rep)
    assert set(got) <= {"https_missing"} and got.get("https_missing") == "low"     # local dev site without TLS
    assert rep["result"]["score"]["grade"] == "A+"
    passed = {p["id"] for p in rep["result"]["passed"]}
    assert {"csp", "clickjacking", "nosniff", "referrer", "permissions", "exposure", "security_txt", "tech"} <= passed


def test_soft_404_site_has_no_false_positives(c, site):
    page = (200, GOOD_HEADERS, GOOD_PAGE)
    site.routes["/"] = page
    site.not_found = page                                    # every address answers 200 with the home page
    rep = done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": NO_PORTS}))
    got = ids(rep)
    assert not [k for k in got if k.startswith("exposed_")] and "dir_listing" not in got
    assert got.get("soft_404") == "info"


def test_cors_reflection_found_over_http(c, site):
    def page(h):
        o = h.headers.get("Origin")
        extra = [("Access-Control-Allow-Origin", o), ("Access-Control-Allow-Credentials", "true")] if o else []
        return 200, GOOD_HEADERS + extra, GOOD_PAGE
    site.routes["/"] = page
    rep = done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": ["headers"]}))
    assert ids(rep)["cors_reflect_creds"] == "high"
    origins = [h.get("Origin") for p, h in site.hits if h.get("Origin")]
    assert origins == ["https://cyberhub-cors-check.invalid"]


def test_https_with_trusted_certificate(c, site, pki, monkeypatch):
    monkeypatch.setenv("CYBERHUB_WEB_CA_FILE", pki.ca_file)
    s = LocalSite(pki.ctx(("localhost",), days=200))
    try:
        s.routes["/"] = (200, GOOD_HEADERS + [("Strict-Transport-Security", "max-age=31536000; includeSubDomains")],
                         GOOD_PAGE)
        rep = done(c, c.post("/api/web/scan", json={"target": s.url(host="localhost"), "checks": ["https", "headers"]}))
    finally:
        s.close()
    res = rep["result"]
    assert ids(rep) == {} and res["score"]["grade"] == "A+", ids(rep)
    tls = res["tls"]
    assert tls["trusted"] and tls["hostname_ok"] and tls["protocol"] in ("TLSv1.2", "TLSv1.3")
    assert tls["versions"]["TLS 1.2"] and tls["versions"]["TLS 1.3"] and not tls["versions"]["TLS 1.0"]
    assert tls["cert"]["issuer_org"] == "CyberHub Test" and 198 <= tls["cert"]["days_left"] <= 200
    assert tls["cert"]["key_type"] == "EC" and "localhost" in tls["cert"]["sans"]
    assert {"cert_trusted", "cert_valid", "tls_modern", "hsts"} <= {p["id"] for p in res["passed"]}


@pytest.mark.parametrize("kind,expect", [
    ("expired", {"cert_expired": "critical"}),
    ("expiring", {"cert_expiring": "high"}),
    ("self_signed", {"cert_self_signed": "low"}),
    ("wrong_name", {"cert_hostname": "medium"}),
])
def test_certificate_problems(c, pki, monkeypatch, kind, expect):
    monkeypatch.setenv("CYBERHUB_WEB_CA_FILE", pki.ca_file)
    ctx = {"expired": lambda: pki.ctx(days=-2, start_days=-100), "expiring": lambda: pki.ctx(days=5),
           "self_signed": lambda: pki.ctx(self_signed=True), "wrong_name": lambda: pki.ctx(("shop.example.org",))}[kind]()
    s = LocalSite(ctx)
    try:
        s.routes["/"] = (200, GOOD_HEADERS + [("Strict-Transport-Security", "max-age=31536000")], GOOD_PAGE)
        rep = done(c, c.post("/api/web/scan", json={"target": s.url(host="localhost"), "checks": ["https"]}))
    finally:
        s.close()
    assert {k: v for k, v in ids(rep).items() if k.startswith("cert")} == expect
    assert rep["result"]["tls"]["cert"] is not None


def test_public_site_needs_owner_confirmation_for_active_checks(c, site, monkeypatch):
    monkeypatch.setenv("CYBERHUB_WEB_PUBLIC_HOSTS", "localhost")
    bad_site(site)
    url = site.url(host="localhost")
    rep = done(c, c.post("/api/web/scan", json={"target": url}))
    res = rep["result"]
    assert res["target"]["scope"] == "public" and {s["check"] for s in res["skipped"]} == {"exposure", "ports"}
    assert "exposed_git" not in ids(rep) and ids(rep)["https_missing"] == "high"     # public site without HTTPS
    assert not any(p.startswith("/.git") for p, _h in site.hits)                      # never even asked
    r = c.post("/api/web/scan", json={"target": url, "checks": ["exposure"]})
    assert r.status_code == 428 and "confirm_owner" in r.json()["detail"]
    rep = done(c, c.post("/api/web/scan", json={"target": url, "checks": ["exposure"], "confirm_owner": True}))
    assert ids(rep)["exposed_git"] == "critical"
    t = c.get("/api/web/targets").json()["items"][0]
    assert t["owner_confirmed"] and t["target"] == url
    rep = done(c, c.post(f"/api/web/targets/{t['id']}/scan"))                       # saved + confirmed -> full scan
    assert rep["result"]["skipped"] == [] and "ports" in rep["result"]["checks"]
    assert rep["result"]["changes"] is not None and rep["result"]["previous"]["id"]


def test_public_site_redirecting_into_local_network_is_stopped(c, site, monkeypatch):
    monkeypatch.setenv("CYBERHUB_WEB_PUBLIC_HOSTS", "localhost")
    site.routes["/"] = (302, [("Location", site.url("/admin"))], b"")              # -> 127.0.0.1
    rep = done(c, c.post("/api/web/scan", json={"target": site.url(host="localhost")}))
    assert rep["status"] == "failed" and "your own PC" in rep["error"]
    assert not any(p == "/admin" for p, _h in site.hits)


def test_unreachable_site_fails_cleanly(c):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    rep = done(c, c.post("/api/web/scan", json={"target": f"127.0.0.1:{port}"}))
    assert rep["status"] == "failed" and "Could not reach" in rep["error"]


def test_port_scan_reports_risky_local_service(c, site):
    site.routes["/"] = (200, GOOD_HEADERS, GOOD_PAGE)
    srv = socket.socket()
    try:
        srv.bind(("127.0.0.1", 6379))
    except OSError:
        pytest.skip("port 6379 busy on this machine")
    srv.listen()
    try:
        rep = done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": ["ports"]}))
    finally:
        srv.close()
    got = ids(rep)
    assert got["port_6379"] == "high"                        # Redis: critical on the internet, one step lower here
    assert any(p["port"] == 6379 for p in rep["result"]["ports"]["open"])
    assert rep["result"]["ports"]["checked"] == len(wp.PORTS)


def test_duplicate_cancel_and_limits(c, site):
    site.routes["/"] = (200, GOOD_HEADERS, GOOD_PAGE)
    site.delay = 1.2
    r = c.post("/api/web/scan", json={"target": site.url(), "checks": ["headers"]})
    assert r.status_code == 200
    assert c.post("/api/web/scan", json={"target": site.url(), "checks": ["headers"]}).status_code == 409
    others = [c.post("/api/web/scan", json={"target": site.url(f"/p{i}"), "checks": ["headers"]}) for i in range(2)]
    assert all(x.status_code == 200 for x in others)
    assert c.post("/api/web/scan", json={"target": site.url("/p9"), "checks": ["headers"]}).status_code == 429
    assert c.post(f"/api/web/jobs/{r.json()['id']}/cancel").json()["cancelling"]
    j = svc(c).wait(r.json()["id"], 30)
    assert j["status"] == "cancelled"
    for x in others:
        svc(c).wait(x.json()["id"], 30)
    jobs = c.get("/api/web/jobs").json()
    assert jobs["running"] == [] and len(jobs["history"]) == 3
    assert c.post(f"/api/web/jobs/{r.json()['id']}/cancel").status_code == 409
    assert c.get("/api/web/jobs/nope").status_code == 404


# ====================================================================== project scans
def make_project(root, *, git=True):
    root.mkdir(parents=True, exist_ok=True)
    if git:
        (root / ".git").mkdir()
    (root / "package.json").write_text('{"name": "shop", "dependencies": {"lodash": "^4.17.20"}}')
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"lodash": "^4.17.20", "evil-pkg": "1.0.0"}, "devDependencies": {"minimist": "^1"}},
        "node_modules/lodash": {"version": "4.17.20"}, "node_modules/minimist": {"version": "1.2.5", "dev": True},
        "node_modules/evil-pkg": {"version": "1.0.0"}, "node_modules/express": {"version": "4.19.2"}}}))
    (root / "backend").mkdir()
    (root / "backend" / "requirements.txt").write_text("Django==4.2.3\nrequests>=2.31\n")
    (root / "php").mkdir()
    (root / "php" / "composer.lock").write_text(json.dumps({"packages": [
        {"name": "laravel/framework", "version": "v10.0.0"}, {"name": "monolog/monolog", "version": "3.5.0"}]}))
    (root / "src").mkdir()
    (root / "src" / "config.js").write_text('const awsKey = "AKIAIOSFODNN7ABCDEFG";\nmodule.exports = {awsKey};\n')
    (root / ".env").write_text("DB_HOST=localhost\nDB_PASSWORD=Sunflower2024\nAWS_KEY=AKIAIOSFODNN7ENVFILE\n")
    (root / ".env.example").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPL2\nDB_PASSWORD=\n")
    (root / "tests" / "fixtures").mkdir(parents=True)
    (root / "tests" / "fixtures" / "keys.py").write_text('KEY = "AKIAIOSFODNN7TESTKEY"\n')
    (root / "node_modules" / "leaky").mkdir(parents=True)
    (root / "node_modules" / "leaky" / "index.js").write_text('const k = "AKIAIOSFODNN7NODEMOD";\n')
    return root


def test_project_scan_end_to_end(c, osv):
    proj = make_project(c.env / "shop")
    rep = done(c, c.post("/api/web/project/scan", json={"path": str(proj), "save": True, "label": "Shop"}))
    assert rep["status"] == "done", rep.get("error")
    res = rep["result"]
    got = ids(rep)
    assert got["dep:npm:lodash@4.17.20"] == "high"
    assert got["dep:npm:minimist@1.2.5"] == "high"            # critical, but only a dev dependency
    assert got["dep:npm:evil-pkg@1.0.0"] == "critical"        # malicious packages never get lowered
    assert got["dep:PyPI:django@4.2.3"] == "critical" and got["dep:Packagist:laravel/framework@10.0.0"] == "medium"
    assert "dep:npm:express@4.19.2" not in got and "dep:Packagist:monolog/monolog@3.5.0" not in got
    lodash = next(f for f in res["findings"] if f["id"] == "dep:npm:lodash@4.17.20")
    assert lodash["package"]["fixed"] == "4.17.21" and "Upgrade lodash to 4.17.21" in lodash["advice"]
    assert lodash["advisories"][0]["aliases"] == ["CVE-2021-23337"] and lodash["advisories"][0]["cvss"] == 7.2
    assert next(f for f in res["findings"] if f["id"] == "dep:PyPI:django@4.2.3")["package"]["fixed"] == "4.2.16"
    assert got["secret:src/config.js"] == "high" and got["secret:.env.example"] == "medium"
    assert "secret:.env" not in got                           # .env is where secrets belong (it must be git-ignored)
    assert got["secret:tests/fixtures/keys.py"] == "low"       # example / test file
    assert not any("node_modules" in k for k in got)
    assert got["env_not_ignored"] == "high" and got["unpinned_requirements"] == "low"
    sec = next(f for f in res["findings"] if f["id"] == "secret:src/config.js")
    assert "AKIAIOSFODNN7ABCDEFG" not in json.dumps(res)       # masked
    assert "AKIA" in sec["detail"]
    deps = res["dependencies"]
    assert deps["total"] == 7 and deps["by_ecosystem"] == {"npm": 4, "PyPI": 1, "Packagist": 2} and deps["vulnerable"] == 5
    assert res["lookup"]["ok"] and res["lookup"]["queried"] == 7 and res["lookup"]["details_fetched"] == 5
    assert res["score"]["grade"] == "F"
    assert c.get("/api/web/targets?kind=project").json()["items"][0]["label"] == "Shop"
    # second scan: osv.dev answers are cached, advisories stored; fixing lodash shows up as "fixed"
    calls = osv.batch_calls, osv.detail_calls
    lock = json.loads((proj / "package-lock.json").read_text())
    lock["packages"]["node_modules/lodash"]["version"] = "4.17.21"
    (proj / "package-lock.json").write_text(json.dumps(lock))
    rep2 = done(c, c.post("/api/web/project/scan", json={"path": str(proj)}))
    assert "dep:npm:lodash@4.17.21" not in ids(rep2)
    assert "dep:npm:lodash@4.17.20" in [x["id"] for x in rep2["result"]["changes"]["fixed"]]
    assert rep2["result"]["lookup"]["cached"] == 6 and rep2["result"]["lookup"]["queried"] == 1
    assert osv.detail_calls == calls[1]                        # nothing downloaded twice
    assert rep2["target_id"] == rep["target_id"]


def test_project_scan_offline_import_and_unreachable_osv(c, osv, monkeypatch):
    proj = make_project(c.env / "shop2", git=False)
    c.app.state.web.osv = __import__("cyberhub.services.dep_audit", fromlist=["x"]).OSVClient("http://127.0.0.1:9")
    rep = done(c, c.post("/api/web/project/scan", json={"path": str(proj), "secrets": False}))
    look = rep["result"]["lookup"]
    assert look["ok"] is False and "Could not reach" in look["error"]
    assert not [k for k in ids(rep) if k.startswith("dep:")] and "env_not_ignored" not in ids(rep)   # no .git here
    # import an OSV all.zip (offline copy) - admin only
    z = c.env / "npm-all.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for vid in ("GHSA-35jh-r3h4-6jhm", "MAL-2025-1234", "GHSA-xvch-5gv4-984h"):
            zf.writestr(f"{vid}.json", json.dumps(VULNS[vid]))
        zf.writestr("PYSEC-2024-0001.json", json.dumps(VULNS["PYSEC-2024-0001"]))     # other ecosystem: skipped
        zf.writestr("junk.json", "{not json")
    r = c.post("/api/web/vulndb/import", json={"path": str(z), "ecosystems": ["npm"]})
    assert r.status_code == 200, r.text
    j = svc(c).wait(r.json()["id"], 30)
    assert j["status"] == "done"
    st = c.get("/api/web/vulndb").json()
    assert st["imported"] == 3 and st["by_ecosystem"]["npm"]["import"] == 3 and "PyPI" not in st["by_ecosystem"]
    rep = done(c, c.post("/api/web/project/scan", json={"path": str(proj), "secrets": False, "online": False}))
    got = ids(rep)
    assert got["dep:npm:lodash@4.17.20"] == "high" and got["dep:npm:evil-pkg@1.0.0"] == "critical"
    assert "dep:PyPI:django@4.2.3" not in got and rep["result"]["lookup"]["online"] is False
    one = c.post("/api/web/packages/check", json={"ecosystem": "npm", "name": "minimist", "version": "1.2.5",
                                                  "online": False}).json()
    assert one["vulnerable"] and one["severity"] == "critical" and one["advisories"][0]["fixed"] == "1.2.6"
    safe = c.post("/api/web/packages/check", json={"ecosystem": "npm", "name": "minimist", "version": "1.2.8",
                                                   "online": False}).json()
    assert not safe["vulnerable"]
    assert c.post("/api/web/packages/check", json={"ecosystem": "npm", "name": "x", "version": "banana"}).status_code \
        == 422
    events = c.get("/api/web/events?kind=vulndb_imported").json()["items"]
    assert len(events) == 1 and "3 advisories" in events[0]["title"]
    assert c.delete("/api/web/vulndb?source=import").json()["deleted"] == 3
    assert c.post("/api/web/vulndb/import", json={"path": str(z), "download": True}).status_code == 422
    assert c.post("/api/web/vulndb/import", json={"path": "/nope.zip"}).status_code == 404


def test_standard_user_isolation_and_admin_only_db(c, site):
    site.routes["/"] = (200, GOOD_HEADERS, GOOD_PAGE)
    rep = done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": ["headers"], "save": True}))
    c.post("/api/account/users", json={"username": "kid", "display_name": "K", "password": PW, "role": "standard"})
    admin = c.headers["X-CyberHub-Session"]
    c.headers["X-CyberHub-Session"] = c.post("/api/account/login", json={"username": "kid", "password": PW}).json()[
        "session_token"]
    try:
        assert c.get(f"/api/web/scans/{rep['id']}").status_code == 404
        assert c.get("/api/web/targets").json()["items"] == []
        assert c.get("/api/web/scans").json()["total"] == 0
        tid = rep["target_id"]
        assert c.patch(f"/api/web/targets/{tid}", json={"monitor": True}).status_code == 404
        assert c.post("/api/web/vulndb/import", json={"download": True}).status_code == 403
        assert c.patch("/api/settings", json={"web_dev_watch": False}).status_code == 403
        assert c.patch("/api/settings", json={"web_cert_warn_days": 14}).status_code == 200    # not a protection key
        own = done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": ["headers"]}))
        assert own["status"] == "done"
    finally:
        c.headers["X-CyberHub-Session"] = admin
    assert c.get(f"/api/web/scans/{own['id']}").status_code == 200       # admins can open any scan
    assert c.patch("/api/settings", json={"web_cert_warn_days": 0}).status_code == 422
    assert c.patch("/api/settings", json={"web_monitor_interval_hours": 1000}).status_code == 422


# ====================================================================== dev servers (Part 10 + Part 9)
def tcp(pid, lip, lport, status="LISTEN"):
    return sconn(-1, socket.AF_INET, socket.SOCK_STREAM, addr(lip, lport), (), status, pid)


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


def test_dev_servers_use_part10_and_part9(c, child):
    me = child.pid
    net = c.app.state.network.probe
    net.fake_connections = [tcp(me, "0.0.0.0", 5173), tcp(me, "127.0.0.1", 3000), tcp(me, "0.0.0.0", 9229),
                            tcp(me, "0.0.0.0", 49999), tcp(me, "0.0.0.0", 445)]
    ds = c.get("/api/web/dev-servers?refresh=true").json()
    by = {x["port"]: x for x in ds["items"]}
    assert set(by) == {5173, 3000, 9229}                      # SMB / random ports are Part 10's business
    assert by[3000]["severity"] == "info" and by[3000]["exposure"] == "local" and by[3000]["fix"] is None
    assert by[5173]["firewall"]["verdict"] == "blocked" and by[5173]["severity"] == "low"
    assert by[9229]["severity"] == "medium" and by[9229]["debugger"]
    exe = psutil.Process(me).exe()
    r = c.post("/api/firewall/allow/app", json={"path": exe, "profiles": ["private"]})
    assert r.status_code == 201, r.text
    by = {x["port"]: x for x in c.get("/api/web/dev-servers?refresh=true").json()["items"]}
    assert by[5173]["reachable"] and by[5173]["severity"] == "medium" and by[5173]["fix"]["action"] == "block_port"
    assert by[9229]["severity"] == "critical"
    out = svc(c).watch_once()
    assert out["dev_alerts"] == 2 and svc(c).watch_once()["dev_alerts"] == 0        # once a day per port
    ev = c.get("/api/web/events?kind=dev_exposed").json()["items"]
    assert {e["data"]["port"] for e in ev} == {5173, 9229} and all(e["user_id"] is None for e in ev)
    r = c.post("/api/web/dev-servers/5173/block")
    assert r.status_code == 200, r.text
    assert r.json()["block"]["kind"] == "port" and r.json()["block"]["target"] == "5173"
    by = {x["port"]: x for x in c.get("/api/web/dev-servers?refresh=true").json()["items"]}
    assert by[5173]["firewall"]["verdict"] == "blocked" and by[5173]["fix"] is None and by[5173]["severity"] == "low"
    assert c.post("/api/web/dev-servers/5173/block").status_code == 409
    assert c.post("/api/web/dev-servers/4321/block").status_code == 404
    blocks = c.get("/api/firewall/blocks").json()
    assert any(b["target"] == "5173" for b in (blocks["items"] if isinstance(blocks, dict) else blocks))
    h = c.get("/api/web/health").json()
    assert h["dev_servers_exposed"] == 1                      # the debugger is still reachable


def test_dev_server_quick_scan(c, site):
    site.routes["/"] = (200, GOOD_HEADERS, GOOD_PAGE)
    r = c.post(f"/api/web/dev-servers/{site.port}/scan")
    rep = done(c, r)
    assert rep["status"] == "done" and rep["result"]["target"]["scope"] == "loopback"


# ====================================================================== monitoring & alerts
def test_monitoring_alerts_on_regressions_and_certificates(c, pki, monkeypatch):
    monkeypatch.setenv("CYBERHUB_WEB_CA_FILE", pki.ca_file)
    s = LocalSite(pki.ctx(days=5))
    try:
        hdrs = GOOD_HEADERS + [("Strict-Transport-Security", "max-age=31536000")]
        s.routes["/"] = (200, hdrs, GOOD_PAGE)
        url = s.url(host="localhost")
        rep = done(c, c.post("/api/web/scan", json={"target": url, "monitor": True,
                                                    "checks": ["https", "headers", "content"]}))
        tid = rep["target_id"]
        t = c.get(f"/api/web/targets/{tid}/history").json()
        assert t["target"]["monitor"] and t["target"]["cert_days_left"] in (4, 5) and len(t["points"]) == 1
        ev = c.get("/api/web/events?kind=cert_expiring").json()["items"]
        assert len(ev) == 1 and ev[0]["severity"] == "high" and ev[0]["target_id"] == tid
        assert svc(c).watch_once()["started"] == []            # not due yet
        c.app.state.db.execute("UPDATE web_targets SET last_scan_at='2020-01-01T00:00:00Z' WHERE id=?", (tid,))
        s.routes["/"] = (200, [("Content-Type", "text/html")], GOOD_PAGE)   # someone removed the security headers
        started = svc(c).watch_once()["started"]
        assert len(started) == 1
        assert svc(c).wait(started[0], 60)["status"] == "done"
        scan = c.get(f"/api/web/scans/{started[0]}").json()
        assert scan["trigger"] == "monitor" and "monitor" in [j["trigger"] for j in c.get("/api/web/jobs").json()["history"]]
    finally:
        s.close()
    kinds = {e["kind"]: e for e in c.get("/api/web/events").json()["items"]}
    assert kinds["new_issues"]["severity"] == "medium" and "new problem" in kinds["new_issues"]["title"]
    # first grade is capped at B by the 5-day certificate (high); losing the headers drops it further
    assert kinds["grade_drop"]["data"]["from"] == "B" and kinds["grade_drop"]["data"]["to"] in ("C", "D", "F")
    assert len(c.get("/api/web/events?kind=cert_expiring").json()["items"]) == 1    # not repeated
    assert len(c.get(f"/api/web/targets/{tid}/history").json()["points"]) == 2
    # the site goes down -> one 'unreachable' alert per day
    c.app.state.db.execute("UPDATE web_targets SET last_scan_at='2020-01-01T00:00:00Z' WHERE id=?", (tid,))
    j = svc(c).watch_once()["started"][0]
    assert svc(c).wait(j, 60)["status"] == "failed"
    ev = c.get("/api/web/events?kind=unreachable").json()["items"]
    assert len(ev) == 1 and c.get(f"/api/web/targets/{tid}").status_code in (200, 404, 405)
    tgt = next(x for x in c.get("/api/web/targets").json()["items"] if x["id"] == tid)
    assert tgt["last_error"] and tgt["last_grade"]           # last good grade kept
    # events: ack + clear
    unack = c.get("/api/web/events?unacknowledged=true").json()
    assert unack["unacknowledged"] >= 4
    assert c.post("/api/web/events/ack", json={"ids": [unack["items"][0]["id"]]}).json()["acknowledged"] == 1
    assert c.post("/api/web/events/ack", json={}).json()["acknowledged"] >= 3
    assert c.get("/api/web/events?unacknowledged=true").json()["unacknowledged"] == 0
    assert c.delete("/api/web/events").json()["deleted"] >= 4


def test_monitor_settings_off_and_target_crud(c, site):
    site.routes["/"] = (200, GOOD_HEADERS, GOOD_PAGE)
    t = c.post("/api/web/targets", json={"kind": "site", "target": site.url(), "monitor": True, "label": "Dev"}).json()
    assert t["monitor"] and t["label"] == "Dev" and t["last_scan_at"] is None
    assert c.post("/api/web/targets", json={"kind": "site", "target": site.url()}).json()["id"] == t["id"]  # same target
    c.patch("/api/settings", json={"web_monitor_enabled": False})
    assert svc(c).watch_once()["started"] == []
    c.patch("/api/settings", json={"web_monitor_enabled": True})
    started = svc(c).watch_once()["started"]
    assert len(started) == 1 and svc(c).wait(started[0], 60)["status"] == "done"
    p = c.patch(f"/api/web/targets/{t['id']}", json={"label": "Shop dev", "monitor": False}).json()
    assert p["label"] == "Shop dev" and not p["monitor"] and p["last_grade"]
    proj = c.post("/api/web/targets", json={"kind": "project", "target": str(c.env / "docs")}).json()
    assert c.patch(f"/api/web/targets/{proj['id']}", json={"owner_confirmed": True}).status_code == 422
    assert c.post("/api/web/targets", json={"kind": "project", "target": str(c.env / "nope")}).status_code == 404
    r = c.delete(f"/api/web/targets/{t['id']}?delete_scans=true").json()
    assert r["scans_deleted"] == 1 and len(c.get("/api/web/targets").json()["items"]) == 1
    assert c.get(f"/api/web/scans/{started[0]}").status_code == 404


# ====================================================================== dashboard, stream, other parts
def test_status_health_summary_for_part18(c, site):
    bad_site(site)
    done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": NO_PORTS, "save": True}))
    proj = make_project(c.env / "p1")
    done(c, c.post("/api/web/project/scan", json={"path": str(proj), "save": True}))
    st = c.get("/api/web/status").json()
    assert st["features"]["dependencies"] and st["features"]["dev_servers"] and st["features"]["firewall_fix"]
    assert st["targets"] == 2 and st["ports_checked"] == len(wp.PORTS) and st["active_checks"] == ["exposure", "ports"]
    h = st["health"]
    assert h["sites"] == 1 and h["projects"] == 1 and h["scanned"] == 2 and h["grade"] == "F"
    assert h["open"]["critical"] >= 4 and h["vulnerable_packages"] == 5 and h["worst"]["grade"] == "F"
    s = c.get("/api/web/summary?days=7").json()
    cats = {x["category"]: x for x in s["findings_by_category"]}
    assert cats["exposure"]["critical"] == 2 and cats["deps"]["critical"] >= 2
    assert s["grades"] == {"F": 2} and len(s["per_day"]) == 1 and s["per_day"][0]["sites"] == 1
    assert {p["name"].lower() for p in s["top_vulnerable_packages"]} >= {"lodash", "evil-pkg", "django"}
    assert any(t["name"] == "jQuery" for t in s["technologies"])
    assert c.app.state.web.health(1)["score"] == h["score"]
    lst = c.get("/api/web/scans?kind=project").json()
    assert lst["total"] == 1 and lst["items"][0]["grade"] == "F" and "result" not in lst["items"][0]
    assert c.delete(f"/api/web/scans/{lst['items'][0]['id']}").json()["deleted"]


def test_websocket_stream(c, site):
    site.routes["/"] = (200, GOOD_HEADERS, GOOD_PAGE)
    tok, ses = c.headers["X-CyberHub-Token"], c.headers["X-CyberHub-Session"]
    with c.websocket_connect(f"/api/web/stream?token={tok}&session={ses}") as ws:
        frame = ws.receive_json()
        assert frame["type"] == "web" and "jobs" in frame and "unacknowledged" in frame
    with pytest.raises(Exception):
        with c.websocket_connect(f"/api/web/stream?token=bad&session={ses}") as ws:
            ws.receive_json()


def test_earlier_parts_still_work_and_info(c, site):
    site.routes["/"] = (200, GOOD_HEADERS, GOOD_PAGE)
    done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": ["headers"]}))
    for path in ("/api/data/status", "/api/firewall/status", "/api/network/status", "/api/posture/status",
                 "/api/passwords/status", "/api/realtime/status", "/api/quarantine", "/api/scan/jobs",
                 "/api/account/me", "/api/rules/status", "/api/network/listening"):
        assert c.get(path).status_code == 200, path
    info = c.get("/api/info").json()
    assert "web" in info["available_modules"] and info["progress_percent"] == BUILD_PART * 5 >= 70   # later parts add more
    assert info["version"] >= "0.14.0"
    acts = c.get("/api/activity?category=web").json()
    assert isinstance(acts, (dict, list))


def test_migration_from_part13_database_keeps_data(env):
    cfg = Settings()
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    db._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, description TEXT, "
                     "applied_at TEXT)")
    for ver, d, sql in MIGRATIONS:
        if ver <= 14:
            db._conn.executescript("BEGIN;" + sql + "COMMIT;")
            db._conn.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (ver, d))
    db.execute("INSERT INTO dp_events(kind, title) VALUES ('finding', 'kept')")
    assert db.schema_version() == 14
    db.close()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        assert cl.get("/api/health").json()["schema_version"] == MIGRATIONS[-1][0] >= 15   # later parts add more
        assert cl.app.state.db.fetchone("SELECT title FROM dp_events")["title"] == "kept"
        tables = {r["name"] for r in cl.app.state.db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"web_targets", "web_scans", "web_vulns", "web_vuln_pkgs", "web_osv_cache", "web_events",
                "web_state"} <= tables


def test_shutdown_cancels_running_scan_and_restart_marks_interrupted(env, site):
    site.routes["/"] = (200, GOOD_HEADERS, GOOD_PAGE)
    site.delay = 0.8
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        jid = cl.post("/api/web/scan", json={"target": site.url()}).json()["id"]
        w = cl.app.state.web
    j = w._jobs[jid]
    assert j.status in ("cancelled", "done") and not j.thread.is_alive()
    # a crash mid-scan leaves 'running' in the DB -> next start marks it interrupted
    db = Database(Settings().db_path)
    db.execute("UPDATE web_scans SET status='running' WHERE id=?", (jid,))
    db.close()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        assert cl.get(f"/api/web/jobs/{jid}").json()["status"] == "interrupted"


def test_cleanup_keeps_latest_scan_per_target(c, site):
    site.routes["/"] = (200, GOOD_HEADERS, GOOD_PAGE)
    a = done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": ["headers"], "save": True}))
    b = done(c, c.post("/api/web/scan", json={"target": site.url(), "checks": ["headers"]}))
    db = c.app.state.db
    db.execute("UPDATE web_scans SET created_at='2001-01-01T00:00:00Z'")
    db.execute("INSERT INTO web_events(kind, title, ts) VALUES ('x', 'old', '2001-01-01T00:00:00Z')")
    assert svc(c).cleanup() == 2                               # the first scan + the old event
    left = {r["id"] for r in db.fetchall("SELECT id FROM web_scans")}
    assert left == {b["id"]} and a["id"] not in left
