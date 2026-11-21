"""
Cyber Hub Backend - Indicators of compromise (Part 15)
Developed by Syed Muhammad Tayyab

Pure helpers shared by the Threat Intelligence service, its feed parsers and its tests - no I/O here.

* classify()        - what an indicator is: ipv4 / ipv6 (-> "ip"), cidr, domain, url, email, md5 / sha1 / sha256.
* refang()          - hxxp://, [.], (dot), [:], [@] ... back into a real indicator (analysts "defang" IOCs).
* defang()          - the opposite, for showing / exporting indicators safely.
* normalize_url()   - lower-case scheme + host, IDN -> punycode, default port and fragment dropped.
* extract()         - every indicator in a pasted block of text (e-mails, reports, chat messages).
* registrable()     - "login.secure.example.co.uk" -> "example.co.uk" (built-in public-suffix subset incl. .pk).
* parent_domains()  - a.b.example.com -> [a.b.example.com, b.example.com, example.com].
* net_range()       - CIDR -> (version, lo_hex, hi_hex) so IP ranges can be compared as text in SQLite.
* parse_stix()      - indicators from a STIX 2.x bundle (simple [ipv4-addr:value = '...'] patterns).
"""
from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse

TYPES = ("ip", "cidr", "domain", "url", "email", "md5", "sha1", "sha256")
HASH_TYPES = ("md5", "sha1", "sha256")
HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
MAX_LEN = 2048

# Public suffixes with two labels (subset that covers the sites Cyber Hub users meet most, incl. Pakistan).
TWO_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "sch.uk",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk", "gob.pk", "web.pk", "fam.pk", "biz.pk", "res.pk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "co.in", "net.in", "org.in", "gov.in",
    "ac.in", "edu.in", "co.za", "org.za", "gov.za", "com.br", "net.br", "org.br", "gov.br", "com.cn", "net.cn",
    "org.cn", "gov.cn", "edu.cn", "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "com.sa", "gov.sa", "edu.sa",
    "com.eg", "gov.eg", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "go.kr", "com.my", "gov.my",
    "com.sg", "gov.sg", "edu.sg", "com.hk", "gov.hk", "com.tw", "gov.tw", "com.mx", "gob.mx", "com.ar", "gob.ar",
    "co.id", "go.id", "ac.id", "or.id", "com.ng", "gov.ng", "co.ke", "go.ke", "com.bd", "gov.bd", "com.np",
    "gov.np", "com.lk", "gov.lk", "ac.ae", "co.ae", "gov.ae", "com.qa", "gov.qa", "com.kw", "com.om", "com.bh",
    "co.il", "org.il", "gov.il", "ac.il", "com.ua", "gov.ua", "co.th", "go.th", "ac.th", "com.vn", "gov.vn",
    "com.ph", "gov.ph", "com.co", "gov.co", "com.pe", "gob.pe", "com.ve", "co.ve",
    # shared hosting / platforms where every customer gets a sub-domain (treated as a suffix)
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "herokuapp.com",
    "web.app", "firebaseapp.com", "appspot.com", "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com",
    "000webhostapp.com", "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com", "glitch.me", "repl.co",
    "onrender.com", "fly.dev", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org", "no-ip.org",
    "ddns.net", "hopto.org", "zapto.org", "sytes.net", "serveo.net", "r2.dev", "surge.sh", "translate.goog",
}
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".corp", ".intranet", ".localdomain", ".home.arpa",
                  ".localhost", ".test", ".invalid", ".example")

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{1,59}|[a-z]{2,63})$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)*$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@([A-Za-z0-9.-]{1,253})$")


class IOCError(ValueError):
    pass


# ====================================================================== refang / defang
_REFANG = [
    (re.compile(r"^hxxp", re.I), "http"), (re.compile(r"^hXXp", re.I), "http"), (re.compile(r"^fxp", re.I), "ftp"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)|\{dot\}|\s+dot\s+", re.I), "."),
    (re.compile(r"\[\s*:\s*\]|\[:\]"), ":"), (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\[\s*@\s*\]|\(\s*@\s*\)|\[at\]|\(at\)|\s+at\s+", re.I), "@"),
    (re.compile(r"\[://\]"), "://"),
]


def refang(s: str) -> str:
    s = (s or "").strip().strip("<>\"'`")
    for rx, rep in _REFANG:
        s = rx.sub(rep, s)
    return s.replace("\\.", ".")


def defang(value: str, kind: str | None = None) -> str:
    """For display / export: example[.]com, hxxps://evil[.]com/x, 1.2.3[.]4"""
    if kind in HASH_TYPES:
        return value
    v = re.sub(r"^http", "hxxp", value, flags=re.I)
    if kind in ("ip", "cidr") or (kind is None and re.match(r"^[\d.]+(/\d+)?$", value)):
        i = v.rfind(".")
        return v[:i] + "[.]" + v[i + 1:] if i > 0 else v
    return v.replace(".", "[.]").replace("@", "[@]")


# ====================================================================== domains
def to_ascii_host(host: str) -> str:
    h = (host or "").strip().rstrip(".").lower()
    if not h:
        raise IOCError("Empty host name")
    try:
        ipaddress.ip_address(h.strip("[]"))
        return h.strip("[]")
    except ValueError:
        pass
    if all(ord(c) < 128 for c in h):
        return h
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        raise IOCError("That host name is not a valid internet name")


def unicode_host(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        return host


def is_domain(s: str) -> bool:
    return bool(_DOMAIN.match(s or ""))


def registrable(host: str) -> str:
    """eTLD+1 using a built-in suffix subset (good enough for matching and brand checks)."""
    h = (host or "").lower().rstrip(".")
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    for n in (3, 2):                                       # longest suffix first (e.g. s3.amazonaws.com)
        if len(parts) > n and ".".join(parts[-n:]) in TWO_LEVEL:
            return ".".join(parts[-(n + 1):])
    if ".".join(parts[-2:]) in TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parent_domains(host: str) -> list[str]:
    """a.b.example.com -> [a.b.example.com, b.example.com, example.com] (never a bare public suffix)."""
    h = (host or "").lower().rstrip(".")
    reg = registrable(h)
    out = [h]
    parts = h.split(".")
    for i in range(1, len(parts)):
        p = ".".join(parts[i:])
        if len(p) < len(reg):
            break
        out.append(p)
    return list(dict.fromkeys(out))


def is_local_name(host: str) -> bool:
    """A valid host name that only means something on your own network (printer, nas.local, router.lan)."""
    h = (host or "").lower().rstrip(".")
    return bool(_HOSTNAME.match(h)) and ("." not in h or h == "localhost" or h.endswith(LOCAL_SUFFIXES))


# ====================================================================== IPs / networks
def ip_kind(ip: str) -> str:
    """public | private | loopback | reserved (never sent to online services unless public)."""
    a = ipaddress.ip_address(ip)
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    if a.is_loopback:
        return "loopback"
    if a.is_private or a.is_link_local or (a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10")):
        return "private"
    if a.is_multicast or a.is_reserved or a.is_unspecified:
        return "reserved"
    return "public"


def net_range(cidr: str) -> tuple[int, str, str]:
    """(version, lo, hi) as zero-padded hex so ranges compare as text (32 chars for both families)."""
    n = ipaddress.ip_network(cidr, strict=False)
    return n.version, format(int(n.network_address), "032x"), format(int(n.broadcast_address), "032x")


def ip_hex(ip: str) -> tuple[int, str]:
    a = ipaddress.ip_address(ip)
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.version, format(int(a), "032x")


def norm_ip(ip: str) -> str:
    a = ipaddress.ip_address(ip.strip().strip("[]"))
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return str(a)


# ====================================================================== URLs
def normalize_url(raw: str) -> dict:
    """{url, scheme, host, port, path, query, userinfo, ip} - raises IOCError."""
    s = refang(raw)
    if len(s) > MAX_LEN or any(ord(c) < 32 for c in s):
        raise IOCError("URL too long or contains control characters")
    if "://" not in s:
        s = "http://" + s
    try:
        u = urllib.parse.urlsplit(s)
        port = u.port
    except ValueError:
        raise IOCError("That URL has an invalid port number")
    scheme = u.scheme.lower()
    if scheme not in ("http", "https", "ftp", "ftps", "ws", "wss"):
        raise IOCError(f"Unsupported URL scheme '{scheme}'")
    host = to_ascii_host(u.hostname or "")
    ip = None
    try:
        ip = norm_ip(host)
        host = ip
    except ValueError:
        if not is_domain(host) and not is_local_name(host):
            raise IOCError("That URL's host is not a valid name or IP address")
    default = {"http": 80, "https": 443, "ftp": 21, "ftps": 990, "ws": 80, "wss": 443}[scheme]
    netloc = f"[{host}]" if ip and ":" in host else host
    if port and port != default:
        netloc += f":{port}"
    path = u.path or "/"
    url = f"{scheme}://{netloc}{path}" + (f"?{u.query}" if u.query else "")
    return {"url": url, "scheme": scheme, "host": host, "port": port or default, "path": path, "query": u.query,
            "userinfo": (u.username or "") + (":***" if u.password else ""), "ip": ip,
            "raw_host": u.hostname or ""}


def url_key_variants(url: str) -> list[str]:
    """Exact-match variants: with / without trailing slash and with http <-> https (feeds disagree)."""
    out = [url]
    if url.endswith("/") and url.count("/") > 3:
        out.append(url[:-1])
    elif not url.endswith("/") and "?" not in url:
        out.append(url + "/")
    for v in list(out):
        if v.startswith("http://"):
            out.append("https://" + v[7:])
        elif v.startswith("https://"):
            out.append("http://" + v[8:])
    return list(dict.fromkeys(out))


# ====================================================================== classify
def classify(raw: str) -> dict:
    """{type, value, display, ...}. type in TYPES. Raises IOCError for anything it can't use."""
    s = refang(raw)
    if not s:
        raise IOCError("Enter an IP address, domain, URL, e-mail address or file hash")
    if len(s) > MAX_LEN:
        raise IOCError("Indicator too long")
    if _HEX.match(s) and len(s) in HASH_LEN:
        return {"type": HASH_LEN[len(s)], "value": s.lower(), "display": s.lower()}
    # ip / ip:port / [v6]:port
    m = re.match(r"^\[?([0-9a-fA-F:.]+?)\]?(?::(\d{1,5}))?$", s)
    if m:
        cand = m.group(1)
        port = m.group(2)
        if port and ":" in cand and not s.startswith("["):       # bare IPv6 - the last group is not a port
            cand, port = s, None
        try:
            ip = norm_ip(cand)
            return {"type": "ip", "value": ip, "display": ip, "port": int(port) if port else None,
                    "scope": ip_kind(ip), "version": ipaddress.ip_address(ip).version}
        except ValueError:
            pass
    if "/" in s and "://" not in s:
        try:
            n = ipaddress.ip_network(s, strict=False)
            return {"type": "cidr", "value": str(n), "display": str(n), "version": n.version,
                    "size": n.num_addresses}
        except ValueError:
            pass
    me = _EMAIL.match(s)
    if me and "://" not in s:
        dom = to_ascii_host(me.group(1))
        if is_domain(dom):
            local = s.split("@", 1)[0]
            return {"type": "email", "value": f"{local.lower()}@{dom}", "display": s, "domain": dom}
    looks_url = "://" in s or "/" in s or "?" in s
    if not looks_url:
        try:
            host = to_ascii_host(s)
        except IOCError:
            raise IOCError("That doesn't look like an IP address, domain, URL, e-mail or hash")
        if is_domain(host) or is_local_name(host):
            return {"type": "domain", "value": host, "display": unicode_host(host), "local": is_local_name(host)}
        raise IOCError("That doesn't look like an IP address, domain, URL, e-mail or hash")
    u = normalize_url(s)
    return {"type": "url", "value": u["url"], "display": u["url"], "host": u["host"], "ip": u["ip"],
            "scheme": u["scheme"], "port": u["port"], "path": u["path"], "query": u["query"],
            "userinfo": u["userinfo"], "raw_host": u["raw_host"]}


# ====================================================================== extract from text
_TOKEN = re.compile(
    r"(?:h[tx]{2}ps?|ftp)(?:\[?://\]?|\[:\]//)[^\s<>\"'`]+"          # URLs, also hxxp[://]
    r"|[A-Za-z0-9._%+\-]+(?:@|\[@\]|\(@\)|\[at\])[A-Za-z0-9.\-\[\]()]+"   # e-mails
    r"|\b[0-9a-fA-F]{32,64}\b"                                         # hashes
    r"|\b\d{1,3}(?:(?:\.|\[\.\]|\(\.\))\d{1,3}){3}(?:/\d{1,2}|:\d{1,5})?\b"   # IPv4 (+cidr/port), defanged too
    r"|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"                # IPv6 (simple)
    r"|\b(?:[A-Za-z0-9-]{1,63}(?:\.|\[\.\]|\(\.\)|\[dot\]))+[A-Za-z]{2,24}\b(?:/[^\s<>\"'`]*)?",  # domains
    re.I)
# file names that look like domains
_NOT_DOMAIN_TLD = {"exe", "dll", "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "zip", "rar", "png", "jpg",
                   "jpeg", "gif", "js", "py", "json", "xml", "csv", "log", "bat", "ps1", "lnk", "html", "htm",
                   "php", "asp", "aspx", "css", "md", "ini", "cfg", "sys", "tmp", "bak", "iso", "msi", "jar",
                   "vbs", "hta", "img", "eml", "msg"}


def extract(text: str, limit: int = 1000) -> tuple[list[dict], int]:
    """Indicators found in free text, de-duplicated, in order. Returns (items, skipped_invalid)."""
    out: dict[tuple[str, str], dict] = {}
    bad = 0
    for m in _TOKEN.finditer(text or ""):
        tok = m.group(0).rstrip(".,;:!?)]}'\"")
        if tok.count("(") < tok.count(")"):
            tok = tok.rstrip(")")
        low = refang(tok).lower()
        if "/" not in low and "@" not in low and "." in low and low.rsplit(".", 1)[-1] in _NOT_DOMAIN_TLD:
            continue
        try:
            c = classify(tok)
        except IOCError:
            bad += 1
            continue
        if c["type"] == "domain" and c.get("local"):
            continue
        out.setdefault((c["type"], c["value"]), c)
        if len(out) >= limit:
            break
    return list(out.values()), bad


# ====================================================================== STIX 2.x
_STIX_PAT = re.compile(r"\[\s*(ipv4-addr|ipv6-addr|domain-name|url|email-addr|file:hashes\.'?(?:SHA-256|SHA-1|MD5)'?"
                       r"|file:hashes\.(?:SHA256|SHA1|MD5))(?::value)?\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]", re.I)


def parse_stix(text: str) -> tuple[list[dict], int]:
    """Indicators from a STIX 2.0 / 2.1 bundle (or a single indicator object). Returns (iocs, skipped)."""
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise IOCError(f"Not valid JSON: {e}")
    objs = doc.get("objects", []) if isinstance(doc, dict) and doc.get("type") == "bundle" else \
        (doc if isinstance(doc, list) else [doc])
    out, skipped = [], 0
    for o in objs:
        if not isinstance(o, dict) or o.get("type") != "indicator":
            continue
        pat = str(o.get("pattern") or "")
        found = False
        for m in _STIX_PAT.finditer(pat):
            val = m.group(2).replace("\\'", "'")
            try:
                c = classify(val)
            except IOCError:
                skipped += 1
                continue
            found = True
            out.append({"type": c["type"], "value": c["value"], "threat": (o.get("name") or "")[:120] or None,
                        "tags": ",".join(o.get("labels") or o.get("indicator_types") or [])[:200] or None,
                        "first_seen": o.get("valid_from") or o.get("created")})
        if not found:
            skipped += 1
    return out, skipped


def to_stix(items: list[dict], identity_name: str = "Cyber Hub") -> dict:
    """A small STIX 2.1 bundle of indicators (for exporting the personal block list)."""
    import uuid
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pat = {"ip": lambda v: f"[{'ipv6' if ':' in v else 'ipv4'}-addr:value = '{v}']",
           "cidr": lambda v: f"[{'ipv6' if ':' in v else 'ipv4'}-addr:value = '{v}']",
           "domain": lambda v: f"[domain-name:value = '{v}']", "url": lambda v: f"[url:value = '{_esc(v)}']",
           "email": lambda v: f"[email-addr:value = '{v}']",
           "md5": lambda v: f"[file:hashes.MD5 = '{v}']", "sha1": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
           "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']"}
    ident = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'cyberhub-local')}"
    objs: list[dict] = [{"type": "identity", "spec_version": "2.1", "id": ident, "created": now, "modified": now,
                         "name": identity_name, "identity_class": "individual"}]
    for it in items:
        if it["type"] not in pat:
            continue
        objs.append({"type": "indicator", "spec_version": "2.1",
                     "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, it['type'] + ':' + it['value'])}",
                     "created": now, "modified": now, "created_by_ref": ident,
                     "name": it.get("threat") or it.get("note") or f"{it['type']} {it['value']}"[:120],
                     "pattern": pat[it["type"]](it["value"]), "pattern_type": "stix", "valid_from": now,
                     "indicator_types": ["malicious-activity"]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")
