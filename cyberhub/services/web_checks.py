"""
Cyber Hub Backend - Website checks (Part 14)
Developed by Syed Muhammad Tayyab

Pure, explainable analyzers used by the Website / Developer Scanner. They never touch the
network themselves - web_probe fetches, these functions judge. Every finding is:

    {id, category, severity, title, detail, advice, evidence?}

Categories: https, headers, cookies, content, exposure, ports, tech (website scans) and
deps, secrets, config (project scans). Severity: info | low | medium | high | critical.

Version tables (JavaScript libraries with public CVEs, PHP / IIS / Apache end-of-life) are built in and
carry the date they were last reviewed, so a finding always says *why* and *since when*.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV = {s: i for i, s in enumerate(SEVERITIES)}
POINTS = {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}
CATEGORIES = {
    "https": "HTTPS & certificate", "headers": "Security headers", "cookies": "Cookies", "content": "Page content",
    "exposure": "Exposed files & debug info", "ports": "Open ports", "tech": "Software & libraries",
    "deps": "Vulnerable dependencies", "secrets": "Secrets in code", "config": "Project settings",
}
TABLES_REVIEWED = "2026-11-01"


def F(fid: str, category: str, severity: str, title: str, detail: str, advice: str,
      evidence: str | None = None, **extra: Any) -> dict:
    f = {"id": fid, "category": category, "severity": severity, "title": title, "detail": detail, "advice": advice}
    if evidence:
        f["evidence"] = evidence[:400]
    f.update(extra)
    return f


def P(pid: str, category: str, title: str) -> dict:
    """A passed check (shown green in the UI)."""
    return {"id": pid, "category": category, "title": title}


def sev_max(a: str, b: str) -> str:
    return a if SEV[a] >= SEV[b] else b


def first(h: dict, name: str) -> str | None:
    v = h.get(name.lower())
    return v[0].strip() if v else None


# ====================================================================== versions
def vtuple(v: str) -> tuple:
    """'3.4.1' -> (3, 4, 1); suffixes after the numbers are ignored."""
    m = re.match(r"v?(\d+(?:\.\d+)*)", str(v).strip())
    if not m:
        return ()
    parts = [int(x) for x in m.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


def vlt(a: str, b: str) -> bool:
    ta, tb = vtuple(a), vtuple(b)
    return bool(ta and tb) and ta < tb


# ====================================================================== headers
CSP_LOOSE_SOURCES = {"*", "http:", "https:", "data:", "blob:"}


def parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            out.setdefault(bits[0].lower(), [b.lower() for b in bits[1:]])
    return out


def analyze_headers(h: dict, is_https: bool, is_html: bool = True) -> tuple[list[dict], list[dict], dict]:
    """(findings, passed, facts) for the final page's response headers."""
    fs: list[dict] = []
    ok: list[dict] = []
    facts: dict[str, Any] = {}
    # ---- HSTS
    if is_https:
        hsts = first(h, "strict-transport-security")
        if not hsts:
            fs.append(F("hsts_missing", "headers", "medium", "HSTS is not enabled",
                        "Without Strict-Transport-Security a visitor's first visit (or a typed http:// link) can be "
                        "downgraded to plain HTTP on public Wi-Fi.",
                        "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains"))
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            facts["hsts"] = {"max_age": age, "include_subdomains": "includesubdomains" in hsts.lower(),
                             "preload": "preload" in hsts.lower()}
            if age < 15552000:
                fs.append(F("hsts_short", "headers", "low" if age else "medium",
                            "HSTS time is too short" if age else "HSTS is switched off (max-age=0)",
                            f"max-age is {age} seconds ({age // 86400} days). Browsers forget the rule quickly.",
                            "Use at least 6 months: max-age=15552000 (1 year = 31536000 is common)", hsts))
            else:
                ok.append(P("hsts", "headers", f"HSTS enabled ({age // 86400} days)"))
    if not is_html:
        return fs, ok, facts
    # ---- CSP
    csp = first(h, "content-security-policy")
    csp_ro = first(h, "content-security-policy-report-only")
    frame_ancestors = False
    if not csp:
        if csp_ro:
            fs.append(F("csp_report_only", "headers", "low", "Content-Security-Policy is only in report mode",
                        "The policy is sent as Content-Security-Policy-Report-Only, so browsers log violations "
                        "but don't block anything.",
                        "When the reports look clean, send the same policy as Content-Security-Policy"))
        else:
            fs.append(F("csp_missing", "headers", "medium", "No Content-Security-Policy",
                        "A CSP is the browser's second line of defence against cross-site scripting (XSS) and "
                        "injected scripts / skimmers.",
                        "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; "
                        "frame-ancestors 'self'; base-uri 'self' - then allow the CDNs you use"))
    else:
        d = parse_csp(csp)
        facts["csp"] = sorted(d)
        frame_ancestors = "frame-ancestors" in d
        scripts = d.get("script-src", d.get("default-src"))
        if scripts is None:
            fs.append(F("csp_no_script_rule", "headers", "low", "CSP does not restrict scripts",
                        "The policy has neither script-src nor default-src, so any script can run.",
                        "Add default-src 'self' (or a script-src list)", csp))
        else:
            strict = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or s == "'strict-dynamic'"
                         for s in scripts)
            loose = sorted(set(scripts) & CSP_LOOSE_SOURCES)
            if "'unsafe-inline'" in scripts and not strict:
                fs.append(F("csp_unsafe_inline", "headers", "medium", "CSP allows inline scripts",
                            "'unsafe-inline' lets injected <script> tags run, which removes most of CSP's XSS "
                            "protection.", "Move inline scripts to files, or use nonces / hashes", csp))
            if "'unsafe-eval'" in scripts:
                fs.append(F("csp_unsafe_eval", "headers", "low", "CSP allows eval()",
                            "'unsafe-eval' lets strings be run as code (eval, new Function).",
                            "Remove 'unsafe-eval' if your libraries don't need it", csp))
            if loose:
                fs.append(F("csp_wildcard", "headers", "medium", "CSP allows scripts from anywhere",
                            f"The script sources include {', '.join(loose)} - an attacker can load a script from "
                            "their own server.", "List the exact domains you load scripts from", csp))
            if not any(x["id"].startswith("csp_") for x in fs):
                ok.append(P("csp", "headers", "Content-Security-Policy restricts scripts"))
    # ---- clickjacking
    xfo = first(h, "x-frame-options")
    if frame_ancestors or (xfo and xfo.lower() in ("deny", "sameorigin")):
        ok.append(P("clickjacking", "headers", "Protected against clickjacking"))
    elif xfo and xfo.lower().startswith("allow-from"):
        fs.append(F("xfo_allow_from", "headers", "low", "X-Frame-Options ALLOW-FROM is ignored by browsers",
                    "Modern browsers don't support ALLOW-FROM, so the page can be framed by anyone.",
                    "Use CSP frame-ancestors 'self' https://partner.example instead", xfo))
    else:
        fs.append(F("clickjacking", "headers", "medium", "Page can be framed (clickjacking)",
                    "Another site can load this page inside an invisible frame and trick visitors into clicking "
                    "buttons (likes, payments, settings).",
                    "Send X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'"))
    # ---- nosniff
    if (first(h, "x-content-type-options") or "").lower() == "nosniff":
        ok.append(P("nosniff", "headers", "X-Content-Type-Options: nosniff"))
    else:
        fs.append(F("nosniff_missing", "headers", "low", "X-Content-Type-Options is missing",
                    "Browsers may guess ('sniff') file types, so an uploaded text file can be run as a script.",
                    "Send X-Content-Type-Options: nosniff"))
    # ---- referrer
    rp = (first(h, "referrer-policy") or "").lower()
    if not rp:
        fs.append(F("referrer_missing", "headers", "low", "No Referrer-Policy",
                    "Without it, full page addresses (which can contain tokens or search terms) may be sent to "
                    "other sites in older browsers.", "Send Referrer-Policy: strict-origin-when-cross-origin"))
    elif "unsafe-url" in rp or rp.strip() == "no-referrer-when-downgrade":
        fs.append(F("referrer_unsafe", "headers", "medium" if "unsafe-url" in rp else "low",
                    "Referrer-Policy leaks full addresses",
                    f"'{rp}' sends the complete URL (path + query) to every other site the page links to.",
                    "Use strict-origin-when-cross-origin or no-referrer", rp))
    else:
        ok.append(P("referrer", "headers", f"Referrer-Policy: {rp}"))
    # ---- permissions
    if first(h, "permissions-policy") or first(h, "feature-policy"):
        ok.append(P("permissions", "headers", "Permissions-Policy set"))
    else:
        fs.append(F("permissions_missing", "headers", "low", "No Permissions-Policy",
                    "The page doesn't say which browser features (camera, microphone, location, payment) it and "
                    "its embedded frames may use.",
                    "Send Permissions-Policy: camera=(), microphone=(), geolocation=()"))
    # ---- information leaks
    server = next((v.strip() for v in h.get("server", []) if re.search(r"\d", v)), None)
    if server:
        fs.append(F("server_version", "headers", "low", "Server software version is shown",
                    f"The Server header says '{server}'. Version numbers help attackers pick matching exploits.",
                    "Hide it: nginx server_tokens off; Apache ServerTokens Prod + ServerSignature Off; IIS "
                    "removeServerHeader", server))
    xpb = first(h, "x-powered-by")
    if xpb:
        fs.append(F("powered_by", "headers", "low", "X-Powered-By reveals the technology",
                    f"X-Powered-By: {xpb}", "Remove it: PHP expose_php = Off; Express app.disable('x-powered-by'); "
                                            "IIS remove the custom header", xpb))
    for k in ("x-aspnet-version", "x-aspnetmvc-version"):
        v = first(h, k)
        if v:
            fs.append(F(k.replace("-", "_"), "headers", "low", "ASP.NET version is shown", f"{k}: {v}",
                        "Set <httpRuntime enableVersionHeader=\"false\" /> and MvcHandler.DisableMvcResponseHeader",
                        v))
    return fs, ok, facts


def analyze_cors(h: dict, sent_origin: str) -> list[dict]:
    """Headers of a request sent with Origin: <sent_origin> (an origin the site can't know)."""
    acao = first(h, "access-control-allow-origin")
    creds = (first(h, "access-control-allow-credentials") or "").lower() == "true"
    if not acao:
        return []
    if acao == sent_origin or acao.lower() == "null":
        return [F("cors_reflect_creds" if creds else "cors_reflect", "headers", "high" if creds else "medium",
                  "Any website can read responses (CORS)" + (" with the visitor's login" if creds else ""),
                  f"The server copied our made-up origin into Access-Control-Allow-Origin ({acao})" +
                  (" and allows credentials - another site can read signed-in users' data." if creds else "."),
                  "Only allow a fixed list of your own origins in Access-Control-Allow-Origin",
                  f"Access-Control-Allow-Origin: {acao}" + ("; Allow-Credentials: true" if creds else ""))]
    if acao == "*" and creds:
        return [F("cors_wildcard_creds", "headers", "medium", "CORS wildcard with credentials",
                  "Access-Control-Allow-Origin: * together with Allow-Credentials: true is a broken configuration "
                  "that usually means the CORS setup was copied without review.",
                  "Use an allow-list of origins; never combine * with credentials")]
    return []


# ====================================================================== cookies
SESSION_COOKIE = re.compile(r"(?i)(sess|sid\b|token|auth|jwt|login|remember|phpsessid|jsessionid|aspnet|connect\.sid|"
                            r"_session|identity)")


def parse_set_cookie(v: str) -> dict:
    parts = [p.strip() for p in v.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and "=" in parts[0] else parts[0][:60]
    attrs: dict[str, str | bool] = {}
    for p in parts[1:]:
        if "=" in p:
            k, val = p.split("=", 1)
            attrs[k.strip().lower()] = val.strip()
        elif p:
            attrs[p.lower()] = True
    return {"name": name[:80], "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": str(attrs.get("samesite") or "").lower() or None,
            "session_like": bool(SESSION_COOKIE.search(name)), "domain": attrs.get("domain"),
            "persistent": "expires" in attrs or "max-age" in attrs}


def analyze_cookies(values: list[str], is_https: bool) -> tuple[list[dict], list[dict], list[dict]]:
    """(findings, passed, cookies[name + flags only - values are never kept])."""
    cookies = []
    seen = set()
    for v in values:
        c = parse_set_cookie(v)
        if c["name"] and c["name"] not in seen:
            seen.add(c["name"])
            cookies.append(c)
    fs: list[dict] = []
    if not cookies:
        return fs, [], cookies
    no_secure = [c["name"] for c in cookies if not c["secure"]] if is_https else []
    no_http = [c["name"] for c in cookies if c["session_like"] and not c["httponly"]]
    no_ss = [c["name"] for c in cookies if not c["samesite"]]
    none_insecure = [c["name"] for c in cookies if c["samesite"] == "none" and not c["secure"]]
    sess_no_secure = [n for n in no_secure if SESSION_COOKIE.search(n)]
    if no_secure:
        fs.append(F("cookie_secure", "cookies", "medium" if sess_no_secure else "low",
                    "Cookies without the Secure flag",
                    f"{len(no_secure)} cookie(s) can also travel over plain HTTP, where anyone on the same Wi-Fi can "
                    f"read them: {', '.join(no_secure[:8])}", "Add Secure to every cookie on an HTTPS site",
                    ", ".join(no_secure[:20])))
    if no_http:
        fs.append(F("cookie_httponly", "cookies", "medium", "Login / session cookies readable by JavaScript",
                    f"Without HttpOnly, an XSS bug lets an attacker steal the session: {', '.join(no_http[:8])}",
                    "Add HttpOnly to session cookies", ", ".join(no_http[:20])))
    if none_insecure:
        fs.append(F("cookie_samesite_none", "cookies", "medium", "SameSite=None cookies without Secure",
                    "Browsers reject these cookies or send them cross-site over HTTP.",
                    "SameSite=None always needs Secure", ", ".join(none_insecure[:20])))
    if no_ss:
        fs.append(F("cookie_samesite", "cookies", "low", "Cookies without SameSite",
                    f"Cookies without SameSite rely on browser defaults for CSRF protection: {', '.join(no_ss[:8])}",
                    "Set SameSite=Lax (or Strict) explicitly", ", ".join(no_ss[:20])))
    ok = [] if fs else [P("cookies", "cookies", f"{len(cookies)} cookie(s) correctly flagged")]
    return fs, ok, cookies


# ====================================================================== page content
TAG = re.compile(r"<(script|iframe|link|img|form|input|meta|object|embed|audio|video|source|frame)\b([^>]{0,4000})>",
                 re.I)
ATTR = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+))")


def attrs_of(s: str) -> dict[str, str]:
    out = {}
    for m in ATTR.finditer(s):
        out.setdefault(m.group(1).lower(), next(g for g in (m.group(3), m.group(4), m.group(5)) if g is not None))
    return out


def page_text(body: bytes, h: dict | None = None) -> str:
    ct = (first(h or {}, "content-type") or "").lower()
    m = re.search(r"charset=([\w-]+)", ct)
    enc = m.group(1) if m else "utf-8"
    try:
        return body.decode(enc, "replace")
    except LookupError:
        return body.decode("utf-8", "replace")


def analyze_html(html: str, page_url: str, is_https: bool) -> tuple[list[dict], list[dict], dict]:
    """(findings, passed, facts{scripts[], generator, forms, external_scripts, ...})."""
    from urllib.parse import urljoin, urlsplit
    own = urlsplit(page_url).hostname or ""
    fs: list[dict] = []
    ok: list[dict] = []
    scripts, active_mixed, passive_mixed, ext_no_sri, insecure_forms = [], [], [], [], []
    generator = None
    password_field = False
    for m in TAG.finditer(html[:MAX_HTML]):
        tag, a = m.group(1).lower(), attrs_of(m.group(2))
        src = a.get("src") or (a.get("href") if tag == "link" else None) or a.get("data")
        if tag == "meta" and a.get("name", "").lower() == "generator" and a.get("content"):
            generator = a["content"][:120]
        if tag == "input" and a.get("type", "").lower() == "password":
            password_field = True
        if tag == "form":
            act = a.get("action", "")
            if act.lower().startswith("http://") and is_https:
                insecure_forms.append(act[:200])
        if not src:
            continue
        absu = urljoin(page_url, src.strip())
        if tag == "script":
            scripts.append(absu[:500])
            host = urlsplit(absu).hostname or ""
            if host and host != own and absu.startswith(("http://", "https://")) and not a.get("integrity"):
                ext_no_sri.append(absu[:200])
        if is_https and absu.startswith("http://"):
            if tag in ("script", "iframe", "object", "embed", "frame") or (
                    tag == "link" and "stylesheet" in a.get("rel", "").lower()):
                active_mixed.append(absu[:200])
            elif tag in ("img", "audio", "video", "source"):
                passive_mixed.append(absu[:200])
    if active_mixed:
        fs.append(F("mixed_active", "content", "medium", "Scripts / styles loaded over plain HTTP",
                    f"{len(active_mixed)} script, style or frame address(es) use http:// on an HTTPS page. Browsers "
                    "block them (page breaks) and on old browsers anyone on the network can change them.",
                    "Load them with https:// (or a relative //path)", "\n".join(active_mixed[:10])))
    if passive_mixed:
        fs.append(F("mixed_passive", "content", "low", "Images / media loaded over plain HTTP",
                    f"{len(passive_mixed)} image or media address(es) use http:// - the padlock shows a warning.",
                    "Change them to https://", "\n".join(passive_mixed[:10])))
    if insecure_forms:
        fs.append(F("form_http", "content", "high", "A form sends data over plain HTTP",
                    "Something typed into this form (login, contact details) is sent unencrypted.",
                    "Point the form action at an https:// address", "\n".join(insecure_forms[:5])))
    if password_field and not is_https:
        fs.append(F("password_http", "content", "high", "Login form on a page without HTTPS",
                    "A password box on an http:// page: anyone on the same network can read the password.",
                    "Serve the whole site over HTTPS"))
    if ext_no_sri:
        fs.append(F("sri_missing", "content", "low", "Scripts from other sites without integrity check",
                    f"{len(ext_no_sri)} script(s) from CDNs / other domains have no integrity= hash. If that CDN is "
                    "hacked (as polyfill.io was in 2024) your site runs the attacker's code.",
                    "Add integrity=\"sha384-...\" crossorigin=\"anonymous\" to CDN scripts",
                    "\n".join(ext_no_sri[:10])))
    known_bad = [s for s in scripts if re.search(r"(?i)//(?:cdn\.)?polyfill\.io/|//(?:www\.)?bootcss\.com/|"
                                                 r"//(?:www\.)?staticfile\.org/|//polyfill\.com/", s)]
    if known_bad:
        fs.append(F("compromised_cdn", "content", "critical", "Script from a hijacked CDN",
                    "The page loads code from polyfill.io / bootcss / staticfile - domains taken over in the June 2024 "
                    "supply-chain attack that injected redirects to scam sites.",
                    "Remove the script now (modern browsers don't need polyfill.io) or use cdnjs.cloudflare.com",
                    "\n".join(known_bad[:5])))
    if not fs and is_https:
        ok.append(P("content", "content", "No mixed content or insecure forms"))
    facts = {"scripts": scripts[:200], "generator": generator, "external_scripts_without_sri": len(ext_no_sri),
             "password_field": password_field}
    return fs, ok, facts


MAX_HTML = 2 * 1024 * 1024

# Debug pages / stack traces shown to visitors.
DEBUG_PATTERNS = [
    ("werkzeug_debugger", "critical", "Werkzeug / Flask interactive debugger is open",
     re.compile(r"(?i)werkzeug debugger|the debugger caught an exception"),
     "The Flask debugger gives anyone who can reach the page a Python console on the server."),
    ("django_debug", "high", "Django DEBUG = True on a live site",
     re.compile(r"(?i)you(?:'|’|&#x27;|&#39;)re seeing this (?:error|page) because you have\s*<code>DEBUG = True"),
     "Django's debug page shows settings, file paths, SQL and URL patterns."),
    ("laravel_debug", "high", "Laravel debug page (APP_DEBUG=true)",
     re.compile(r"(?i)whoops! there was an error|illuminate\\[a-z]+\\|ignition-|<title>[^<]{0,80}laravel</title>"),
     "Laravel's debug page shows source code, environment variables and sometimes database passwords."),
    ("symfony_debug", "high", "Symfony debug mode", re.compile(r"(?i)symfony exception|sf-toolbar|symfony profiler"),
     "The Symfony profiler / debug page exposes requests, configuration and code."),
    ("rails_debug", "high", "Rails development error page",
     re.compile(r"(?i)action controller: exception caught"), "Rails shows source code and parameters."),
    ("python_traceback", "high", "Python error details shown",
     re.compile(r"Traceback \(most recent call last\)"), "Stack traces reveal code paths and library versions."),
    ("aspnet_ysod", "medium", "ASP.NET error details shown",
     re.compile(r"(?i)server error in '/[^']*' application|<b>\s*stack trace:\s*</b>"),
     "Detailed ASP.NET errors reveal code, paths and versions."),
    ("php_errors", "medium", "PHP errors shown to visitors",
     re.compile(r"(?i)<b>(?:fatal error|warning|parse error|notice|deprecated)</b>:\s.{0,300}? on line <b>\d+</b>"),
     "PHP warnings reveal file paths on the server."),
    ("node_stack", "medium", "Node.js stack trace shown",
     re.compile(r"\n\s+at [\w.<>]+ \((?:/|[A-Z]:\\)[^)]*node_modules[^)]*\)"), "Stack traces reveal code paths."),
]
DEBUG_ADVICE = {
    "werkzeug_debugger": "Never run app.run(debug=True) / FLASK_DEBUG=1 on a server; use gunicorn / waitress.",
    "django_debug": "Set DEBUG = False in production settings and configure ALLOWED_HOSTS.",
    "laravel_debug": "Set APP_DEBUG=false and APP_ENV=production in .env, then php artisan config:cache.",
    "symfony_debug": "Use APP_ENV=prod and remove the web profiler bundle from production.",
    "rails_debug": "Run in RAILS_ENV=production (config.consider_all_requests_local = false).",
    "python_traceback": "Turn off debug mode and show a generic error page.",
    "aspnet_ysod": "Set <customErrors mode=\"RemoteOnly\" /> / UseExceptionHandler in production.",
    "php_errors": "Set display_errors = Off (log_errors = On) in php.ini.",
    "node_stack": "Set NODE_ENV=production and use an error handler that hides stack traces.",
}


def find_debug_leaks(text: str, where: str) -> list[dict]:
    out = []
    t = text[:MAX_HTML]
    for fid, sev, title, rx, why in DEBUG_PATTERNS:
        m = rx.search(t)
        if m:
            out.append(F(fid, "exposure", sev, title, f"{why} Seen on: {where}", DEBUG_ADVICE[fid],
                         m.group(0)[:200]))
    return out


# ====================================================================== exposed files (active check)
def _is_html(b: bytes) -> bool:
    head = b[:600].lower()
    return b"<html" in head or b"<!doctype" in head or b"<head" in head or b"<body" in head


def _txt(b: bytes) -> str:
    return b[:65536].decode("utf-8", "replace")


ENV_KEY = re.compile(r"(?m)^\s*(?:export\s+)?[A-Z][A-Z0-9_]{1,60}\s*=")
ENV_SENSITIVE = re.compile(r"(?m)^\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|SECRET|PASS|TOKEN|DB_|DATABASE|AWS|MAIL_)[A-Z0-9_]*\s*=")


def _env_ok(b: bytes, h: dict) -> bool:
    if _is_html(b):
        return False
    t = _txt(b)
    return len(ENV_KEY.findall(t)) >= 2 and bool(ENV_SENSITIVE.search(t))


EXPOSURE_PROBES: list[dict] = [
    {"path": "/.git/HEAD", "group": "git", "severity": "critical", "title": "Git repository is downloadable",
     "detail": "/.git/ is public: your full source code, its history and any password ever committed can be "
               "downloaded with free tools.",
     "advice": "Block /.git in the web server (nginx: location ~ /\\.git { deny all; }) and deploy without the "
               ".git folder. Rotate secrets that were ever committed.",
     "check": lambda b, h: bool(re.match(rb"(ref: refs/|[0-9a-f]{40}\s*$)", b[:120].strip()))},
    {"path": "/.git/config", "group": "git", "severity": "critical", "title": "Git repository is downloadable",
     "detail": "/.git/config is public - the whole repository can be rebuilt from /.git/.",
     "advice": "Block /.git in the web server and deploy without the .git folder.",
     "check": lambda b, h: b"[core]" in b[:4096] and not _is_html(b)},
    {"path": "/.env", "group": "env", "severity": "critical", "title": ".env file with secrets is public",
     "detail": "The site's .env file (database passwords, API keys, APP_KEY) can be downloaded by anyone.",
     "advice": "Move .env outside the web root / block dotfiles, then CHANGE every password and key in it - assume "
               "they are already stolen.", "check": _env_ok},
    {"path": "/.env.production", "group": "env", "severity": "critical", "title": ".env file with secrets is public",
     "detail": ".env.production can be downloaded by anyone.", "advice": "Block dotfiles and rotate every secret.",
     "check": _env_ok},
    {"path": "/.env.local", "group": "env", "severity": "critical", "title": ".env file with secrets is public",
     "detail": ".env.local can be downloaded by anyone.", "advice": "Block dotfiles and rotate every secret.",
     "check": _env_ok},
    {"path": "/.svn/entries", "group": "svn", "severity": "high", "title": "Subversion (.svn) folder is public",
     "detail": "Source code can be rebuilt from the public .svn folder.", "advice": "Block /.svn and redeploy.",
     "check": lambda b, h: not _is_html(b) and bool(re.match(rb"\s*(\d+\s*$|<\?xml[^>]*>\s*<wc-entries)", b[:200]))},
    {"path": "/.DS_Store", "group": "dsstore", "severity": "low", "title": ".DS_Store file is public",
     "detail": "A macOS folder index lists the names of every file in the folder, including hidden ones.",
     "advice": "Delete .DS_Store files from the server and block them.",
     "check": lambda b, h: b[:8] == b"\x00\x00\x00\x01Bud1"},
    {"path": "/wp-config.php.bak", "group": "config_backup", "severity": "critical",
     "title": "Backup of a config file is public",
     "detail": "A backup copy of wp-config.php is served as text - it contains the database password.",
     "advice": "Delete backup files from the web root and change the database password.",
     "check": lambda b, h: b"DB_PASSWORD" in b[:65536] or (b"<?php" in b[:200] and not _is_html(b))},
    {"path": "/wp-config.php~", "group": "config_backup", "severity": "critical",
     "title": "Backup of a config file is public", "detail": "An editor backup of wp-config.php is public.",
     "advice": "Delete it and change the database password.",
     "check": lambda b, h: b"DB_PASSWORD" in b[:65536]},
    {"path": "/config.php.bak", "group": "config_backup", "severity": "critical",
     "title": "Backup of a config file is public", "detail": "config.php.bak is served as plain text.",
     "advice": "Delete backup files from the web root and rotate the secrets in it.",
     "check": lambda b, h: b"<?php" in b[:400] and not _is_html(b)},
    {"path": "/backup.sql", "group": "db_dump", "severity": "critical", "title": "Database dump is public",
     "detail": "A database export can be downloaded - customer data and password hashes included.",
     "advice": "Delete it from the web root now; keep backups outside public folders.",
     "check": lambda b, h: bool(re.search(rb"(?i)(create table|insert into|-- mysql dump|pg_dump)", b[:8192]))},
    {"path": "/dump.sql", "group": "db_dump", "severity": "critical", "title": "Database dump is public",
     "detail": "dump.sql can be downloaded.", "advice": "Delete it from the web root now.",
     "check": lambda b, h: bool(re.search(rb"(?i)(create table|insert into|-- mysql dump|pg_dump)", b[:8192]))},
    {"path": "/backup.zip", "group": "archive", "severity": "high", "title": "Backup archive is public",
     "detail": "backup.zip can be downloaded - usually the whole site including config files.",
     "advice": "Remove archives from the web root.", "check": lambda b, h: b[:4] == b"PK\x03\x04"},
    {"path": "/.htpasswd", "group": "htpasswd", "severity": "high", "title": ".htpasswd (password hashes) is public",
     "detail": "Password hashes for protected folders can be downloaded and cracked offline.",
     "advice": "Keep .htpasswd outside the web root and change those passwords.",
     "check": lambda b, h: bool(re.search(rb"(?m)^[\w.@-]{1,64}:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$[156]\$)", b[:4096]))},
    {"path": "/phpinfo.php", "group": "phpinfo", "severity": "medium", "title": "phpinfo() page is public",
     "detail": "phpinfo() shows PHP version, modules, server paths and environment variables.",
     "advice": "Delete phpinfo.php / info.php from the server.",
     "check": lambda b, h: b"phpinfo()" in b[:65536] or b"PHP Version" in b[:65536] and b"PHP License" in b},
    {"path": "/info.php", "group": "phpinfo", "severity": "medium", "title": "phpinfo() page is public",
     "detail": "info.php shows PHP's full configuration.", "advice": "Delete it from the server.",
     "check": lambda b, h: b"phpinfo()" in b[:65536] or b"PHP Version" in b[:65536] and b"PHP License" in b},
    {"path": "/server-status", "group": "server_status", "severity": "medium",
     "title": "Apache server-status is public",
     "detail": "Shows every address visitors are opening right now (including secret links) and their IPs.",
     "advice": "Restrict mod_status to localhost (Require local).",
     "check": lambda b, h: b"Apache Server Status" in b[:4096]},
    {"path": "/server-info", "group": "server_info", "severity": "medium", "title": "Apache server-info is public",
     "detail": "Shows the complete Apache configuration.", "advice": "Disable mod_info or Require local.",
     "check": lambda b, h: b"Apache Server Information" in b[:4096]},
    {"path": "/web.config", "group": "webconfig", "severity": "high", "title": "web.config is downloadable",
     "detail": "IIS / ASP.NET configuration (often connection strings) is served as a file.",
     "advice": "Never serve web.config as static content; check the handler mappings.",
     "check": lambda b, h: b"<configuration" in b[:4096] and not _is_html(b)},
    {"path": "/.vscode/sftp.json", "group": "sftp", "severity": "critical", "title": "Editor SFTP settings are public",
     "detail": "VS Code SFTP settings with the server's host, user name and often the password.",
     "advice": "Delete .vscode from the server and change the SFTP password.",
     "check": lambda b, h: b"\"host\"" in b[:8192] and (b"\"password\"" in b or b"\"privateKeyPath\"" in b)},
    {"path": "/sftp-config.json", "group": "sftp", "severity": "critical", "title": "Editor SFTP settings are public",
     "detail": "Sublime Text SFTP settings with the server login.", "advice": "Delete it and change the password.",
     "check": lambda b, h: b"\"host\"" in b[:8192] and b"\"user\"" in b},
    {"path": "/docker-compose.yml", "group": "compose", "severity": "medium", "title": "docker-compose.yml is public",
     "detail": "Reveals the services, images, ports and sometimes passwords used to run the site.",
     "advice": "Don't deploy it into the web root.",
     "check": lambda b, h: bool(re.search(rb"(?m)^services:\s*$", b[:8192])) and not _is_html(b)},
    {"path": "/id_rsa", "group": "ssh_key", "severity": "critical", "title": "Private SSH key is public",
     "detail": "A private key file can be downloaded - anyone can log in where it is trusted.",
     "advice": "Delete it, remove the key from authorized_keys everywhere and make a new one.",
     "check": lambda b, h: b"PRIVATE KEY-----" in b[:200]},
    {"path": "/actuator/env", "group": "actuator", "severity": "high", "title": "Spring Boot actuator /env is public",
     "detail": "Shows environment variables and configuration of the Java application.",
     "advice": "Expose only health / info actuator endpoints, behind authentication.",
     "check": lambda b, h: b"propertySources" in b[:65536] or b"activeProfiles" in b[:65536]},
    {"path": "/_ignition/health-check", "group": "ignition", "severity": "high",
     "title": "Laravel Ignition endpoint is reachable",
     "detail": "Ignition's execute-solution endpoint was the target of CVE-2021-3129 (remote code execution) on "
               "old versions and only exists with debug tools installed.",
     "advice": "Set APP_DEBUG=false and install facade/ignition only as a dev dependency (composer --no-dev).",
     "check": lambda b, h: b"can_execute_commands" in b[:1024]},
    {"path": "/elmah.axd", "group": "elmah", "severity": "high", "title": "ELMAH error log is public",
     "detail": "ASP.NET error log with full requests, sometimes including session cookies.",
     "advice": "Set allowRemoteAccess=\"false\" or require authentication.",
     "check": lambda b, h: b"Error Log for" in b[:8192]},
    {"path": "/crossdomain.xml", "group": "crossdomain", "severity": "medium", "title": "Open crossdomain.xml policy",
     "detail": "crossdomain.xml allows every domain (*) - legacy Flash / Silverlight clients could read your data.",
     "advice": "Delete crossdomain.xml unless you really need it, or list exact domains.",
     "check": lambda b, h: bool(re.search(rb"<allow-access-from[^>]+domain=\"\*\"", b[:8192]))},
    {"path": "/package.json", "group": "manifest", "severity": "low", "title": "package.json is public",
     "detail": "Lists your project's libraries and versions - attackers can match them to known bugs.",
     "advice": "Serve only the build output folder, not the project root.",
     "check": lambda b, h: not _is_html(b) and b"\"dependencies\"" in b[:65536] and b[:1].strip() in (b"{", b"")},
    {"path": "/composer.json", "group": "manifest", "severity": "low", "title": "composer.json is public",
     "detail": "Lists your PHP libraries and versions.",
     "advice": "Point the web root at /public (Laravel) instead of the project folder.",
     "check": lambda b, h: not _is_html(b) and b"\"require\"" in b[:65536]},
]
WP_PROBES: list[dict] = [
    {"path": "/wp-json/wp/v2/users", "group": "wp_users", "severity": "low", "title": "WordPress user names are listed",
     "detail": "The REST API lists author accounts, which gives attackers the user names for password guessing.",
     "advice": "Restrict /wp-json/wp/v2/users to signed-in users (a security plugin can do this) and use 2FA.",
     "check": lambda b, h: b[:1] == b"[" and b"\"slug\"" in b[:65536]},
    {"path": "/xmlrpc.php", "group": "wp_xmlrpc", "severity": "low", "title": "WordPress XML-RPC is enabled",
     "detail": "xmlrpc.php lets attackers try hundreds of passwords in one request and is used for DDoS pingbacks.",
     "advice": "Disable XML-RPC if you don't use the mobile app / Jetpack.",
     "check": lambda b, h: b"XML-RPC server accepts POST requests only" in b[:2048]},
]
DIR_PROBES = ["/uploads/", "/images/", "/files/", "/backup/", "/assets/"]
DIR_LISTING = re.compile(r"(?i)<title>\s*(index of /|directory listing for)|<h1>\s*index of /")


def soft404_signature(status: int, body: bytes) -> tuple[int, int, bytes]:
    return status, len(body), body[:256]


def same_as_baseline(status: int, body: bytes, base: tuple[int, int, bytes] | None) -> bool:
    if not base:
        return False
    bs, blen, bhead = base
    return status == bs and abs(len(body) - blen) <= max(64, blen // 20) and body[:256] == bhead


def check_exposure(probe: dict, status: int, body: bytes, h: dict, base) -> bool:
    if status not in (200, 206) or not body:
        return False
    if same_as_baseline(status, body, base):
        return False
    try:
        return bool(probe["check"](body, h))
    except Exception:                                       # pragma: no cover
        return False


def robots_paths(text: str) -> list[str]:
    hits = re.findall(r"(?im)^\s*disallow:\s*(\S+)", text[:65536])
    juicy = [p for p in hits if re.search(r"(?i)admin|backup|private|secret|config|db|dump|old|test|staging|"
                                          r"internal|cpanel|phpmyadmin", p)]
    return juicy[:20]


# ====================================================================== TLS
WEAK_CIPHER = re.compile(r"(?i)(RC4|3DES|DES-CBC|NULL|EXPORT|anon|MD5)")


def evaluate_tls(t: dict, scope: str, warn_days: int, http_redirects: bool | None) -> tuple[list[dict], list[dict]]:
    """Findings for tls_info() output. scope = loopback | private | public."""
    fs: list[dict] = []
    ok: list[dict] = []
    local = scope in ("loopback", "private")
    if not t.get("available"):
        fs.append(F("https_missing", "https", "low" if local else "high", "HTTPS is not available",
                    f"Could not open a secure connection ({t.get('error') or t.get('verify_error') or 'no TLS'}). "
                    "Everything visitors send or receive can be read and changed on the way.",
                    "Install a free certificate (Let's Encrypt / Cloudflare) and redirect http:// to https://"))
        return fs, ok
    c = t.get("cert") or {}
    if http_redirects is False:
        fs.append(F("http_no_redirect", "https", "low" if local else "medium",
                    "http:// does not redirect to https://",
                    "Visitors who type the address or follow old links stay on the unencrypted version.",
                    "Add a permanent (301) redirect from http:// to https://"))
    elif http_redirects:
        ok.append(P("http_redirect", "https", "http:// redirects to https://"))
    if c:
        dl = c.get("days_left", 0)
        if dl < 0:
            fs.append(F("cert_expired", "https", "critical", "Certificate has expired",
                        f"It expired {-dl} day(s) ago ({c['not_after'][:10]}). Browsers show a full-page warning.",
                        "Renew the certificate now (certbot renew / your host's SSL page)", c["not_after"]))
        elif c.get("not_yet_valid"):
            fs.append(F("cert_not_yet_valid", "https", "high", "Certificate is not valid yet",
                        f"It only becomes valid on {c['not_before'][:10]} - check the server clock.",
                        "Install the correct certificate or fix the server's date", c["not_before"]))
        elif dl <= 7:
            fs.append(F("cert_expiring", "https", "high", f"Certificate expires in {dl} day(s)",
                        f"Expires {c['not_after'][:10]}. Automatic renewal may be broken.",
                        "Renew now and check that auto-renewal (certbot timer / host) works", c["not_after"],
                        days_left=dl))
        elif dl <= warn_days:
            fs.append(F("cert_expiring", "https", "medium", f"Certificate expires in {dl} days",
                        f"Expires {c['not_after'][:10]}.", "Make sure auto-renewal is working", c["not_after"],
                        days_left=dl))
        else:
            ok.append(P("cert_valid", "https", f"Certificate valid for {dl} more days"))
        if c.get("signature_hash") in ("sha1", "md5"):
            fs.append(F("cert_sha1", "https", "high", f"Certificate signed with {c['signature_hash'].upper()}",
                        "This signature algorithm is broken and rejected by browsers.",
                        "Get a new certificate (SHA-256)"))
        if c.get("key_type") == "RSA" and c.get("key_bits", 0) < 2048:
            fs.append(F("cert_weak_key", "https", "high", f"Weak {c['key_bits']}-bit RSA key",
                        "RSA keys under 2048 bits can be broken.", "Create a new key (RSA 2048+ or ECDSA P-256)"))
    trusted = t.get("trusted")
    code = t.get("verify_code")
    if trusted is False:
        msg = t.get("verify_error") or "untrusted"
        if code == 10 or "expired" in msg.lower():
            pass                                            # already reported as cert_expired
        elif code in (18, 19) or "self-signed" in msg.lower() or "self signed" in msg.lower():
            fs.append(F("cert_self_signed", "https", "low" if local else "high", "Self-signed certificate",
                        "Browsers don't trust it, so visitors see a warning and learn to click through warnings." +
                        (" (Normal for a local development server.)" if local else ""),
                        "Use a certificate from a public authority (Let's Encrypt is free)" if not local else
                        "For local HTTPS use mkcert so your browser trusts it", msg))
        elif code == 62 or "hostname" in msg.lower() or "mismatch" in msg.lower():
            pass                                            # reported below via hostname_ok
        else:
            fs.append(F("cert_untrusted", "https", "low" if local else "high", "Certificate chain is not trusted",
                        f"Verification failed: {msg}. Often the intermediate certificate is missing.",
                        "Install the full chain (fullchain.pem), not only the site certificate", msg))
    elif trusted:
        ok.append(P("cert_trusted", "https", f"Trusted certificate from {c.get('issuer_org') or c.get('issuer')}"))
    if t.get("hostname_ok") is False:
        fs.append(F("cert_hostname", "https", "medium" if local else "high", "Certificate is for a different name",
                    f"The certificate covers {', '.join((c.get('sans') or [c.get('subject', '?')])[:5])} but not "
                    f"{t.get('host')}.", "Get a certificate that includes this exact host name (or *.domain)"))
    v = t.get("versions") or {}
    old = [k for k in ("TLS 1.0", "TLS 1.1") if v.get(k)]
    if old:
        fs.append(F("tls_old", "https", "low" if local else "medium", f"Old {' and '.join(old)} still accepted",
                    "TLS 1.0 / 1.1 are deprecated (RFC 8996) and have known weaknesses; PCI-DSS forbids them.",
                    "Allow only TLS 1.2 and 1.3 (nginx: ssl_protocols TLSv1.2 TLSv1.3;)"))
    if v and v.get("TLS 1.3") is False:
        fs.append(F("tls13_missing", "https", "info" if local else "low", "TLS 1.3 is not supported",
                    "TLS 1.3 is faster and removes old, risky options.", "Enable TLS 1.3 on the server / CDN"))
    if v.get("TLS 1.2") or v.get("TLS 1.3"):
        ok.append(P("tls_modern", "https", "Modern TLS (" + ", ".join(k for k in ("TLS 1.2", "TLS 1.3") if v.get(k))
                    + ")"))
    if t.get("cipher") and WEAK_CIPHER.search(t["cipher"]):
        fs.append(F("tls_weak_cipher", "https", "high", "Weak encryption cipher negotiated",
                    f"The server picked {t['cipher']}, which is broken.", "Disable RC4 / 3DES / NULL / EXPORT ciphers",
                    t["cipher"]))
    return fs, ok


# ====================================================================== ports
EXPOSED_SERVICE: dict[int, tuple[str, str]] = {
    2375: ("critical", "The Docker API without TLS gives full control of the server (root) to anyone."),
    9229: ("critical", "The Node.js debugger lets anyone run code inside your app."),
    10250: ("critical", "The kubelet API can run commands in your Kubernetes containers."),
    6379: ("critical", "Redis usually has no password and can be abused to write files / take over the server."),
    11211: ("high", "Memcached exposes cached data and is abused for huge DDoS amplification."),
    27017: ("critical", "MongoDB on the internet is a top cause of database leaks and ransom wipes."),
    9200: ("critical", "Elasticsearch on the internet exposes all indexed data."),
    5984: ("high", "CouchDB's API is exposed to the internet."),
    5601: ("high", "Kibana dashboards expose your log / search data."),
    3306: ("high", "The database server accepts connections from the internet (password guessing, exploits)."),
    5432: ("high", "The database server accepts connections from the internet (password guessing, exploits)."),
    1433: ("high", "SQL Server on the internet is hit by constant password-guessing attacks."),
    1521: ("high", "The Oracle database listener is exposed."),
    23: ("high", "Telnet sends passwords in plain text."),
    3389: ("high", "Remote Desktop on the internet is a top ransomware entry point."),
    5900: ("high", "VNC on the internet is often weakly protected."),
    445: ("high", "SMB file sharing must never face the internet (WannaCry, EternalBlue)."),
    2049: ("high", "NFS shares are exposed."),
    21: ("medium", "FTP sends passwords in plain text - use SFTP."),
    3000: ("medium", "A development server is reachable - dev servers aren't hardened and often show debug info."),
    5000: ("medium", "A development server is reachable."),
    8000: ("medium", "A development server is reachable."),
    8888: ("medium", "A Jupyter / dev server is reachable - Jupyter without a token gives a shell."),
    110: ("low", "POP3 without TLS sends mail passwords in plain text."),
    143: ("low", "IMAP without TLS sends mail passwords in plain text."),
}
LOWER = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}


def evaluate_ports(results: list[dict], scope: str, web_port: int) -> tuple[list[dict], list[dict], list[dict]]:
    """(findings, passed, software[{service, product, version}] from banners)."""
    fs: list[dict] = []
    software: list[dict] = []
    opened = [r for r in results if r["state"] == "open"]
    for r in opened:
        p = r["port"]
        if p in (80, 443, web_port):
            continue
        if p in EXPOSED_SERVICE:
            sev, why = EXPOSED_SERVICE[p]
            if scope != "public":
                sev = LOWER[sev]
            where = "the internet" if scope == "public" else ("your network" if scope == "private" else "this PC")
            fs.append(F(f"port_{p}", "ports", sev, f"{r['service']} (port {p}) is open to {where}", why,
                        "Close it in the firewall / cloud security group, or bind the service to 127.0.0.1. "
                        "Use a VPN or SSH tunnel for admin access.", r.get("banner"), port=p))
    for r in opened:
        b = r.get("banner") or ""
        m = re.search(r"OpenSSH[_-](\d+)\.(\d+)(p\d+)?", b)
        if m:
            ver = f"{m.group(1)}.{m.group(2)}"
            software.append({"service": "SSH", "product": "OpenSSH", "version": ver + (m.group(3) or "")})
            vt = (int(m.group(1)), int(m.group(2)))
            if (8, 5) <= vt <= (9, 7):
                fs.append(F("openssh_regresshion", "ports", "medium",
                            f"OpenSSH {ver} may be affected by regreSSHion (CVE-2024-6387)",
                            "OpenSSH 8.5p1-9.7p1 on Linux (glibc) had a remote code execution bug. Distributions "
                            "back-ported the fix without changing the version number.",
                            "Update the server's packages (apt / dnf upgrade openssh-server) and confirm the fix "
                            "with your distribution's advisory", b, port=r["port"]))
            elif vt < (7, 4):
                fs.append(F("openssh_old", "ports", "medium", f"Very old OpenSSH {ver}",
                            "This OpenSSH release is from before 2017 and misses many security fixes.",
                            "Upgrade the operating system / OpenSSH", b, port=r["port"]))
        elif r["port"] in (21, 25, 587, 110, 143) and b:
            software.append({"service": r["service"], "product": b[:80], "version": None})
        elif b.startswith("MySQL "):
            software.append({"service": "MySQL", "product": "MySQL / MariaDB", "version": b[6:40]})
    ok = [] if fs else [P("ports", "ports", f"No risky services open ({len(opened)} open port(s) checked)")]
    return fs, ok, software


# ====================================================================== technology fingerprint
PHP_EOL = {"5.6": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30", "7.3": "2021-12-06",
           "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31",
           "8.4": "2028-12-31", "8.5": "2029-12-31"}
IIS_EOL = {"6.0": ("high", "Windows Server 2003 (end of support 2015)"),
           "7.0": ("high", "Windows Server 2008 (end of support 2020)"),
           "7.5": ("high", "Windows Server 2008 R2 (end of support 2020)"),
           "8.0": ("medium", "Windows Server 2012 (end of support October 2023)"),
           "8.5": ("medium", "Windows Server 2012 R2 (end of support October 2023)")}

# (library, [(introduced, fixed, severity, cves, what)]) - vulnerable if introduced <= version < fixed.
JS_VULNS: dict[str, list[tuple[str, str, str, str, str]]] = {
    "jQuery": [("0", "1.9.0", "high", "CVE-2012-6708", "XSS through selector strings"),
               ("0", "3.5.0", "medium", "CVE-2020-11022, CVE-2020-11023, CVE-2019-11358",
                "XSS when HTML from untrusted sources is passed to .html()/.append(); prototype pollution")],
    "jQuery UI": [("0", "1.13.2", "medium", "CVE-2021-41182, CVE-2021-41183, CVE-2021-41184, CVE-2022-31160",
                   "XSS through widget options")],
    "Bootstrap": [("0", "3.4.1", "medium", "CVE-2018-14040, CVE-2018-14041, CVE-2018-14042, CVE-2019-8331",
                   "XSS through tooltip / popover / collapse data attributes"),
                  ("4.0.0", "4.3.1", "medium", "CVE-2019-8331", "XSS in tooltip / popover data-template")],
    "Lodash": [("0", "4.17.21", "medium", "CVE-2021-23337, CVE-2020-8203", "command injection in template(); "
                                                                           "prototype pollution")],
    "Moment.js": [("0", "2.29.4", "medium", "CVE-2022-31129, CVE-2022-24785", "ReDoS in date parsing; path "
                                                                              "traversal in locale loading")],
    "Handlebars": [("0", "4.7.7", "high", "CVE-2021-23369, CVE-2021-23383", "remote code execution when compiling "
                                                                            "untrusted templates")],
    "AngularJS": [("1.0.0", "2.0.0", "medium", "CVE-2022-25869, CVE-2023-26116",
                   "AngularJS reached end of life in January 2022 - XSS / ReDoS bugs are no longer fixed")],
}
JS_EOL = {"Vue": ("2.0.0", "3.0.0", "low", "Vue 2 reached end of life on 31 Dec 2023"),
          "Bootstrap": ("3.0.0", "5.0.0", "low", "Bootstrap 3 and 4 no longer receive fixes (4 ended Jan 2023)")}

_V = r"v?(\d+\.\d+(?:\.\d+)?)"
JS_SRC: dict[str, list[re.Pattern]] = {
    "jQuery": [re.compile(r"(?i)/jquery(?![-.]?(?:ui|migrate|mobile|validat|cookie|easing|form|color))[-.@]" + _V +
                          r"(?:[./-]|$)"), re.compile(r"(?i)/jquery/" + _V + r"/"),
               re.compile(r"(?i)/jquery(?:\.min)?\.js\?ver=" + _V)],
    "jQuery UI": [re.compile(r"(?i)jquery[-.]ui[-.@/]" + _V), re.compile(r"(?i)/jqueryui/" + _V + r"/"),
                  re.compile(r"(?i)jquery-ui(?:\.min)?\.js\?ver=" + _V)],
    "Bootstrap": [re.compile(r"(?i)bootstrap[-@/]" + _V + r"(?:[./]|$)"), re.compile(r"(?i)/bootstrap/" + _V + r"/"),
                  re.compile(r"(?i)bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)\?ver=" + _V)],
    "AngularJS": [re.compile(r"(?i)angular(?:js)?[-@/]v?(1\.\d+\.\d+)"), re.compile(r"(?i)/angular\.js/(1\.\d+\.\d+)/")],
    "Lodash": [re.compile(r"(?i)lodash[-@/.]" + _V + r"(?:[./]|$)"), re.compile(r"(?i)/lodash\.js/" + _V + "/")],
    "Moment.js": [re.compile(r"(?i)moment[-@/]" + _V + r"(?:[./]|$)"), re.compile(r"(?i)/moment\.js/" + _V + "/")],
    "Vue": [re.compile(r"(?i)/vue[-@/]" + _V + r"(?:[./]|$)"), re.compile(r"(?i)/vue/" + _V + "/")],
    "Handlebars": [re.compile(r"(?i)handlebars[-@/.]" + _V + r"(?:[./]|$)"),
                   re.compile(r"(?i)/handlebars\.js/" + _V + "/")],
    "React": [re.compile(r"(?i)react(?:-dom)?@" + _V), re.compile(r"(?i)/react/" + _V + "/")],
}
JS_BANNER: dict[str, re.Pattern] = {
    "jQuery": re.compile(r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)"),
    "jQuery UI": re.compile(r"jQuery UI - v(\d+\.\d+\.\d+)"),
    "Bootstrap": re.compile(r"Bootstrap v(\d+\.\d+\.\d+)"),
    "AngularJS": re.compile(r"AngularJS v(1\.\d+\.\d+)"),
    "Moment.js": re.compile(r"moment\.js\s*(?://!|\*)?\s*version\s*:\s*(\d+\.\d+\.\d+)", re.I),
    "Vue": re.compile(r"Vue\.js v(\d+\.\d+\.\d+)"),
    "Handlebars": re.compile(r"(?i)handlebars v(\d+\.\d+\.\d+)"),
    "Lodash": re.compile(r"(?i)lodash(?: lodash\.com)?(?:/license)? ?<?\S*>? ?v?(\d+\.\d+\.\d+)"),
}

# (name, category, where, regex, version group?) - where: header:<name> | cookie | html | generator
TECH_RULES: list[tuple[str, str, str, str]] = [
    ("nginx", "server", "header:server", r"(?i)\bnginx(?:/(\d[\d.]*))?"),
    ("Apache", "server", "header:server", r"(?i)\bapache(?:/(\d[\d.]*))?"),
    ("Microsoft IIS", "server", "header:server", r"(?i)microsoft-iis(?:/(\d[\d.]*))?"),
    ("LiteSpeed", "server", "header:server", r"(?i)litespeed"),
    ("OpenResty", "server", "header:server", r"(?i)openresty(?:/(\d[\d.]*))?"),
    ("Caddy", "server", "header:server", r"(?i)\bcaddy\b"),
    ("Gunicorn", "server", "header:server", r"(?i)gunicorn(?:/(\d[\d.]*))?"),
    ("Uvicorn", "server", "header:server", r"(?i)uvicorn"),
    ("Kestrel", "server", "header:server", r"(?i)kestrel"),
    ("Cloudflare", "cdn", "header:server", r"(?i)cloudflare"),
    ("Cloudflare", "cdn", "header:cf-ray", r"."),
    ("Vercel", "hosting", "header:x-vercel-id", r"."),
    ("Netlify", "hosting", "header:x-nf-request-id", r"."),
    ("GitHub Pages", "hosting", "header:x-github-request-id", r"."),
    ("Amazon CloudFront", "cdn", "header:x-amz-cf-id", r"."),
    ("Firebase Hosting", "hosting", "header:x-firebase-hosting", r"."),
    ("PHP", "language", "header:x-powered-by", r"(?i)\bphp(?:/(\d[\d.]*))?"),
    ("Express", "framework", "header:x-powered-by", r"(?i)\bexpress\b"),
    ("Next.js", "framework", "header:x-powered-by", r"(?i)next\.js(?:\s*(\d[\d.]*))?"),
    ("ASP.NET", "framework", "header:x-powered-by", r"(?i)asp\.net"),
    ("ASP.NET", "framework", "header:x-aspnet-version", r"(\d[\d.]*)"),
    ("Drupal", "cms", "header:x-generator", r"(?i)drupal(?:\s*(\d+))?"),
    ("Drupal", "cms", "header:x-drupal-cache", r"."),
    ("Shopify", "ecommerce", "header:x-shopid", r"."),
    ("Shopify", "ecommerce", "header:x-shopify-stage", r"."),
    ("Wix", "cms", "header:x-wix-request-id", r"."),
    ("LiteSpeed Cache", "cache", "header:x-litespeed-cache", r"."),
    ("PHP", "language", "cookie", r"^PHPSESSID$"),
    ("Laravel", "framework", "cookie", r"(?i)^laravel_session$"),
    ("Django", "framework", "cookie", r"^csrftoken$"),
    ("Java", "language", "cookie", r"^JSESSIONID$"),
    ("ASP.NET", "framework", "cookie", r"(?i)^(asp\.net_sessionid|\.aspnetcore\.)"),
    ("Express", "framework", "cookie", r"^connect\.sid$"),
    ("WordPress", "cms", "cookie", r"^(wordpress_|wp-settings-)"),
    ("CodeIgniter", "framework", "cookie", r"^ci_session$"),
    ("Shopify", "ecommerce", "cookie", r"^_shopify_"),
    ("PrestaShop", "ecommerce", "cookie", r"^PrestaShop-"),
    ("WordPress", "cms", "generator", r"(?i)wordpress\s*(\d[\d.]*)?"),
    ("Joomla", "cms", "generator", r"(?i)joomla!?(?:\s*(\d[\d.]*))?"),
    ("Drupal", "cms", "generator", r"(?i)drupal\s*(\d+)?"),
    ("Wix", "cms", "generator", r"(?i)wix\.com"),
    ("Squarespace", "cms", "generator", r"(?i)squarespace"),
    ("Ghost", "cms", "generator", r"(?i)ghost\s*(\d[\d.]*)?"),
    ("Hugo", "framework", "generator", r"(?i)hugo\s*(\d[\d.]*)?"),
    ("Jekyll", "framework", "generator", r"(?i)jekyll\s*v?(\d[\d.]*)?"),
    ("Gatsby", "framework", "generator", r"(?i)gatsby\s*(\d[\d.]*)?"),
    ("Webflow", "cms", "generator", r"(?i)webflow"),
    ("Blogger", "cms", "generator", r"(?i)blogger"),
    ("WooCommerce", "ecommerce", "generator", r"(?i)woocommerce\s*(\d[\d.]*)?"),
    ("WordPress", "cms", "html", r"/wp-(?:content|includes)/"),
    ("WooCommerce", "ecommerce", "html", r"/wp-content/plugins/woocommerce/"),
    ("Next.js", "framework", "html", r"__NEXT_DATA__|/_next/static/"),
    ("Nuxt", "framework", "html", r"__NUXT__|/_nuxt/"),
    ("Angular", "framework", "html", r"ng-version=\"(\d[\d.]*)\""),
    ("AngularJS", "framework", "html", r"\bng-app\b"),
    ("React", "framework", "html", r"data-reactroot|react-dom(?:\.production)?(?:\.min)?\.js"),
    ("Vue", "framework", "html", r"\bdata-v-[0-9a-f]{8}\b|vue(?:\.global)?(?:\.prod)?(?:\.min)?\.js"),
    ("Svelte", "framework", "html", r"\bsvelte-[a-z0-9]{6}\b"),
    ("Vite", "build", "html", r"/@vite/client|type=\"module\" crossorigin src=\"/assets/index-"),
    ("Shopify", "ecommerce", "html", r"cdn\.shopify\.com"),
    ("Wix", "cms", "html", r"static\.wixstatic\.com"),
    ("Squarespace", "cms", "html", r"static1\.squarespace\.com"),
    ("Joomla", "cms", "html", r"/media/jui/|/media/system/js/core\.js"),
    ("Drupal", "cms", "html", r"drupal-settings-json|Drupal\.settings"),
    ("Magento", "ecommerce", "html", r"/static/version\d+/frontend/|Mage\.Cookies|mage/cookies"),
    ("PrestaShop", "ecommerce", "html", r"prestashop"),
    ("Laravel", "framework", "html", r"<meta name=\"csrf-token\"[^>]+>.{0,2000}?livewire|/vendor/livewire/"),
    ("Bootstrap", "library", "html", r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)"),
    ("Tailwind CSS", "library", "html", r"tailwindcss|cdn\.tailwindcss\.com"),
    ("Font Awesome", "library", "html", r"font-?awesome"),
    ("Google Analytics", "analytics", "html", r"googletagmanager\.com/gtag/js|google-analytics\.com/analytics\.js"),
    ("Google Tag Manager", "analytics", "html", r"googletagmanager\.com/gtm\.js"),
    ("Facebook Pixel", "analytics", "html", r"connect\.facebook\.net/[^\"']*/fbevents\.js"),
    ("Hotjar", "analytics", "html", r"static\.hotjar\.com"),
    ("Google reCAPTCHA", "security", "html", r"google\.com/recaptcha/|recaptcha/api\.js"),
    ("Cloudflare Turnstile", "security", "html", r"challenges\.cloudflare\.com/turnstile"),
]
_COMPILED = [(n, c, w, re.compile(rx)) for n, c, w, rx in TECH_RULES]


def fingerprint(h: dict, cookie_names: list[str], html: str, generator: str | None, scripts: list[str],
                banners: dict[str, str] | None = None, now: datetime | None = None) -> tuple[list[dict], list[dict]]:
    """(technologies[{name, category, version, evidence}], findings)."""
    now = now or datetime.now(timezone.utc)
    tech: dict[str, dict] = {}

    def add(name: str, cat: str, version: str | None, evidence: str) -> None:
        t = tech.setdefault(name, {"name": name, "category": cat, "version": None, "evidence": evidence[:120]})
        if version and not t["version"]:
            t["version"] = version.strip(".")
            t["evidence"] = evidence[:120]
    html_head = html[:MAX_HTML]
    for name, cat, where, rx in _COMPILED:
        if where.startswith("header:"):
            for v in h.get(where[7:].lower(), []):         # every value - proxies can add a second Server header
                m = rx.search(v)
                if m:
                    add(name, cat, m.group(1) if m.groups() else None, f"{where[7:]}: {v.strip()}")
                    break
        elif where == "cookie":
            for cn in cookie_names:
                if rx.search(cn):
                    add(name, cat, None, f"cookie {cn}")
                    break
        elif where == "generator" and generator:
            m = rx.search(generator)
            if m:
                add(name, cat, m.group(1) if m.groups() else None, f"generator: {generator}")
        elif where == "html":
            m = rx.search(html_head)
            if m:
                add(name, cat, m.group(1) if m.groups() else None, m.group(0))
    # JavaScript libraries with versions (script addresses, then the files' own banners)
    for lib, rxs in JS_SRC.items():
        for s in scripts:
            for rx in rxs:
                m = rx.search(s)
                if m:
                    add(lib, "library", m.group(1), s)
                    break
            if lib in tech and tech[lib]["version"]:
                break
    for src, head in (banners or {}).items():
        for lib, rx in JS_BANNER.items():
            m = rx.search(head)
            if m and not (lib in tech and tech[lib]["version"]):
                add(lib, "library", m.group(1), f"{src.rsplit('/', 1)[-1][:60]}: {m.group(0)[:60]}")
    if "Laravel" in tech and "PHP" not in tech:
        add("PHP", "language", None, "Laravel")
    if "WooCommerce" in tech and "WordPress" not in tech:
        add("WordPress", "cms", None, "WooCommerce")
    fs: list[dict] = []
    for lib, rows in JS_VULNS.items():
        t = tech.get(lib)
        if not t or not t["version"]:
            continue
        hits = [r for r in rows if not vlt(t["version"], r[0]) and vlt(t["version"], r[1])]
        if hits:
            sev = max((r[2] for r in hits), key=lambda s: SEV[s])
            fixed = max((r[1] for r in hits), key=vtuple)
            fs.append(F(f"lib_{lib.lower().replace(' ', '_').replace('.', '')}", "tech", sev,
                        f"{lib} {t['version']} has known vulnerabilities",
                        "; ".join(r[4] for r in hits) + f" ({', '.join(r[3] for r in hits)}).",
                        f"Upgrade {lib} to {fixed} or later" if lib != "AngularJS" else
                        "Plan a move from AngularJS to Angular / another maintained framework",
                        t["evidence"], library=lib, version=t["version"], fixed=fixed))
    for lib, (intro, end, sev, why) in JS_EOL.items():
        t = tech.get(lib)
        if t and t["version"] and not vlt(t["version"], intro) and vlt(t["version"], end) and \
                not any(f.get("library") == lib for f in fs):
            fs.append(F(f"eol_{lib.lower()}", "tech", sev, f"{lib} {t['version']} is end-of-life", why,
                        f"Plan an upgrade to the current {lib} release", t["evidence"], library=lib,
                        version=t["version"]))
    php = tech.get("PHP")
    if php and php["version"]:
        br = ".".join(php["version"].split(".")[:2])
        eol = PHP_EOL.get(br)
        if eol is None and vlt(php["version"], "5.6"):
            eol = "2018-12-31"
        if eol:
            eol_dt = datetime.strptime(eol, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            days = (eol_dt - now).days
            if days < 0:
                fs.append(F("php_eol", "tech", "high", f"PHP {br} no longer gets security fixes",
                            f"PHP {br} reached end of life on {eol}. New PHP bugs will never be fixed for it.",
                            "Upgrade to a supported PHP version (8.3 or newer) - test your site on staging first",
                            php["evidence"], version=php["version"]))
            elif days <= 120:
                fs.append(F("php_eol_soon", "tech", "low", f"PHP {br} support ends {eol}",
                            f"Security fixes for PHP {br} stop in {days} days.", "Plan the upgrade to PHP 8.3+",
                            php["evidence"], version=php["version"]))
    iis = tech.get("Microsoft IIS")
    if iis and iis["version"] in IIS_EOL:
        sev, os_name = IIS_EOL[iis["version"]]
        fs.append(F("iis_eol", "tech", sev, f"IIS {iis['version']} means an unsupported Windows Server",
                    f"IIS {iis['version']} ships with {os_name} - Microsoft no longer patches it.",
                    "Move the site to a supported Windows Server (2019 / 2022 / 2025)", iis["evidence"]))
    ap = tech.get("Apache")
    if ap and ap["version"] and vlt(ap["version"], "2.4.0"):
        fs.append(F("apache_eol", "tech", "high", f"Apache {ap['version']} is end-of-life",
                    "Apache 2.2 and older stopped receiving security fixes in 2017.", "Upgrade to Apache 2.4",
                    ap["evidence"]))
    wp = tech.get("WordPress")
    if wp and wp["version"] and "generator" in wp["evidence"]:
        fs.append(F("wp_version", "tech", "low", f"WordPress version {wp['version']} is shown",
                    "The generator tag tells attackers exactly which WordPress bugs to try.",
                    "Keep WordPress updated (auto-updates on) and remove the generator tag", wp["evidence"]))
    return sorted(tech.values(), key=lambda t: (t["category"], t["name"])), fs


# ====================================================================== scoring
GRADES = [(95, "A+"), (90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def score(findings: list[dict]) -> dict:
    """{score 0-100, grade, by_severity, penalty, categories{cat: {score, grade, findings}}}."""
    def calc(fs: list[dict]) -> tuple[int, str]:
        pen = sum(POINTS[f["severity"]] for f in fs)
        s = 100.0 * 100 / (100 + pen)
        if any(f["severity"] == "critical" for f in fs):
            s = min(s, 49)
        elif any(f["severity"] == "high" for f in fs):
            s = min(s, 84)
        s = int(round(s))
        g = next(g for lim, g in GRADES if s >= lim)
        if g == "A+" and any(SEV[f["severity"]] >= SEV["medium"] for f in fs):
            g = "A"
        return s, g
    total, grade = calc(findings)
    by = {s: 0 for s in SEVERITIES}
    for f in findings:
        by[f["severity"]] += 1
    cats: dict[str, dict] = {}
    for cat in dict.fromkeys(f["category"] for f in findings):
        fs = [f for f in findings if f["category"] == cat]
        s, g = calc(fs)
        cats[cat] = {"label": CATEGORIES.get(cat, cat), "score": s, "grade": g, "findings": len(fs)}
    return {"score": total, "grade": grade, "by_severity": by,
            "penalty": sum(POINTS[f["severity"]] for f in findings), "categories": cats}


def sort_findings(fs: list[dict]) -> list[dict]:
    order = list(CATEGORIES)
    return sorted(fs, key=lambda f: (-SEV[f["severity"]], order.index(f["category"]) if f["category"] in order else 99,
                                     f["id"]))


def dedupe(fs: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for f in fs:
        k = f["id"]
        if k not in seen or SEV[f["severity"]] > SEV[seen[k]["severity"]]:
            seen[k] = f
    return list(seen.values())


def diff(prev: list[dict], cur: list[dict]) -> dict:
    """New / fixed findings between two scans of the same target (by finding id)."""
    p = {f["id"]: f for f in prev}
    c = {f["id"]: f for f in cur}
    return {"new": [c[k] for k in c if k not in p], "fixed": [p[k] for k in p if k not in c],
            "worse": [c[k] for k in c if k in p and SEV[c[k]["severity"]] > SEV[p[k]["severity"]]]}


Check = Callable[[bytes, dict], bool]
