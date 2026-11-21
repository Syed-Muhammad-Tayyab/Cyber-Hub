"""
Cyber Hub Backend - Threat feeds: catalog, downloader, parsers (Part 15)
Developed by Syed Muhammad Tayyab

Built-in feeds (free; reviewed 2026-11-13):
  * Feodo Tracker recommended botnet C2 IPs (abuse.ch)       - no key
  * URLhaus online malware URLs (abuse.ch)                     - abuse.ch Auth-Key sent when you have one
  * ThreatFox IOCs (abuse.ch): IPs, domains, URLs, hashes      - needs the free abuse.ch Auth-Key
  * Spamhaus DROP IPv4 + IPv6 (hijacked / criminal networks)  - no key (JSON format, the .txt files are legacy)
  * OpenPhish community phishing URLs                          - no key
  * Emerging Threats compromised hosts (Proofpoint)            - no key
  * Tor exit nodes (Tor Project) - informational, off by default
The abuse.ch Auth-Key is the SAME key Part 8 stores for MalwareBazaar (/api/lookup/keys) - it works across
all abuse.ch platforms, so it is entered once.

Downloads: verified TLS only, system proxy honoured, size cap (intel_max_feed_mb), zip-bomb guard, ETag /
Last-Modified so unchanged feeds cost nothing, custom feeds must be https:// on a public address and can't
redirect into your network.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from . import ioc

USER_AGENT = "CyberHub/0.15 (+local security app; threat-intel feed update)"
ABUSECH_KEY_URL = "https://auth.abuse.ch/"

CATALOG: list[dict] = [
    {"key": "feodo", "name": "Feodo Tracker - botnet C2 servers", "provider": "abuse.ch",
     "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "format": "lines",
     "types": ["ip"], "category": "c2", "severity": "critical", "enabled": True, "min_hours": 1,
     "homepage": "https://feodotracker.abuse.ch/blocklist/", "license": "CC0",
     "description": "IP addresses of active botnet command-and-control servers (Emotet, QakBot, Pikabot ...). "
                    "A PC talking to one is very likely infected."},
    {"key": "urlhaus", "name": "URLhaus - malware download sites", "provider": "abuse.ch",
     "url": "https://urlhaus.abuse.ch/downloads/csv_online/", "format": "urlhaus_csv", "types": ["url"],
     "category": "malware_download", "severity": "high", "enabled": True, "min_hours": 1, "auth": "abusech",
     "auth_in": "header", "auth_optional": True, "homepage": "https://urlhaus.abuse.ch/", "license": "CC0",
     "description": "Web addresses currently serving malware. Your abuse.ch Auth-Key is sent if you have one."},
    {"key": "threatfox", "name": "ThreatFox - IOCs of named malware", "provider": "abuse.ch",
     "url": "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip", "format": "threatfox_csv",
     "types": ["ip", "domain", "url", "md5", "sha1", "sha256"], "category": "malware", "severity": "high",
     "enabled": True, "min_hours": 1, "auth": "abusech", "auth_in": "path", "homepage": "https://threatfox.abuse.ch/",
     "license": "CC0", "description": "IPs, domains, URLs and file hashes tied to named malware families "
                                     "(last 6 months). Needs the free abuse.ch Auth-Key."},
    {"key": "spamhaus_drop", "name": "Spamhaus DROP - hijacked networks (IPv4)", "provider": "Spamhaus",
     "url": "https://www.spamhaus.org/drop/drop_v4.json", "format": "spamhaus_json", "types": ["cidr"],
     "category": "hijacked_network", "severity": "high", "enabled": True, "min_hours": 12,
     "homepage": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/", "license": "Spamhaus DROP terms",
     "description": "Address ranges run by criminals or hijacked from their owners - no legitimate traffic."},
    {"key": "spamhaus_drop6", "name": "Spamhaus DROP - hijacked networks (IPv6)", "provider": "Spamhaus",
     "url": "https://www.spamhaus.org/drop/drop_v6.json", "format": "spamhaus_json", "types": ["cidr"],
     "category": "hijacked_network", "severity": "high", "enabled": True, "min_hours": 12,
     "homepage": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/", "license": "Spamhaus DROP terms",
     "description": "IPv6 ranges controlled by criminals."},
    {"key": "openphish", "name": "OpenPhish - phishing pages", "provider": "OpenPhish",
     "url": "https://openphish.com/feed.txt", "format": "lines", "types": ["url"], "category": "phishing",
     "severity": "high", "enabled": True, "min_hours": 6, "homepage": "https://openphish.com/",
     "license": "OpenPhish community feed terms", "description": "Live fake login pages (banks, e-mail, "
                                                                "social media) found by OpenPhish."},
    {"key": "et_compromised", "name": "Emerging Threats - compromised hosts", "provider": "Proofpoint ET",
     "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "format": "lines", "types": ["ip"],
     "category": "compromised", "severity": "medium", "enabled": True, "min_hours": 6,
     "homepage": "https://rules.emergingthreats.net/", "license": "ET Open (BSD)",
     "description": "Hosts seen attacking others (brute force, scanning, exploitation)."},
    {"key": "tor_exits", "name": "Tor exit nodes", "provider": "Tor Project",
     "url": "https://check.torproject.org/torbulkexitlist", "format": "lines", "types": ["ip"], "category": "tor",
     "severity": "info", "enabled": False, "min_hours": 1, "homepage": "https://metrics.torproject.org/",
     "license": "CC0", "description": "Not malicious by itself - shows when a program on this PC talks to the Tor "
                                     "network (privacy tools, but also some malware)."},
]
CATALOG_BY_KEY = {f["key"]: f for f in CATALOG}
FORMATS = ("auto", "lines", "csv", "hosts", "stix", "urlhaus_csv", "threatfox_csv", "spamhaus_json")
CUSTOM_FORMATS = ("auto", "lines", "csv", "hosts", "stix")
CATEGORIES = {"c2": "Botnet / command-and-control server", "malware_download": "Malware download site",
              "malware": "Malware infrastructure", "phishing": "Phishing", "hijacked_network": "Hijacked network",
              "compromised": "Compromised / attacking host", "tor": "Tor exit node", "blocklist": "Your block list",
              "spam": "Spam / scam", "scanner": "Scanner", "custom": "Custom feed"}
SEVERITIES = ("info", "low", "medium", "high", "critical")


class FeedError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ====================================================================== download
class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Custom feeds: redirects must stay on https:// and public addresses."""
    def __init__(self, strict: bool):
        super().__init__()
        self.strict = strict

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.strict:
            check_custom_url(newurl, resolve=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_custom_url(url: str, resolve: bool = False) -> str:
    """Raises FeedError(422/403) for URLs a custom feed may not use."""
    try:
        u = urllib.parse.urlsplit(url.strip())
        port = u.port
    except ValueError:
        raise FeedError(422, "That feed address is not a valid URL")
    if u.scheme.lower() != "https":
        raise FeedError(422, "Feed addresses must start with https:// (so nobody can change the list on the way)")
    if u.username or u.password:
        raise FeedError(422, "Remove the user name / password from the feed address")
    host = (u.hostname or "").lower()
    if not host:
        raise FeedError(422, "The feed address has no host name")
    if port is not None and not 1 <= port <= 65535:
        raise FeedError(422, "Invalid port")
    ips = []
    try:
        ips = [ioc.norm_ip(host)]
    except ValueError:
        if ioc.is_local_name(host):
            raise FeedError(403, "Feeds must come from a public internet address")
        if resolve:
            try:
                ips = [a[4][0].split("%")[0] for a in socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)]
            except OSError:
                raise FeedError(422, f"Could not find {host} (DNS lookup failed)")
    for ip in ips:
        if ioc.ip_kind(ip) != "public":
            raise FeedError(403, "Feeds must come from a public internet address, not this PC or your network")
    return url.strip()


def urllib_transport(method: str, url: str, headers: dict, data: bytes | None, timeout: float,
                     max_bytes: int = 64 * 1024 * 1024, strict: bool = False) -> tuple[int, bytes, dict]:
    """Default HTTP client: verified TLS, system proxy, size cap. Returns (status, body, headers lower-case)."""
    if strict:
        check_custom_url(url, resolve=True)
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _SafeRedirect(strict))
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with opener.open(req, timeout=timeout) as r:                              # nosec - checked URL
            body = r.read(max_bytes + 1)
            return r.status, body, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, (e.read(64 * 1024) if e.fp else b""), {k.lower(): v for k, v in (e.headers or {}).items()}


# ====================================================================== content helpers
def unpack(body: bytes, max_bytes: int) -> bytes:
    """Zip files -> the first data member (CSV / TXT / JSON), with a zip-bomb guard."""
    if body[:2] != b"PK":
        return body
    try:
        z = zipfile.ZipFile(io.BytesIO(body))
    except zipfile.BadZipFile:
        raise FeedError(422, "The feed is a damaged zip file")
    members = [i for i in z.infolist() if not i.is_dir() and re.search(r"\.(csv|txt|json|tsv)$", i.filename, re.I)]
    if not members:
        raise FeedError(422, "The zip file has no CSV / TXT / JSON file inside")
    m = members[0]
    if m.file_size > max_bytes or (m.compress_size and m.file_size / max(1, m.compress_size) > 200 and
                                   m.file_size > 50 * 1024 * 1024):
        raise FeedError(413, f"The feed unpacks to {m.file_size // (1024 * 1024)} MB - more than allowed")
    with z.open(m) as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise FeedError(413, "The feed is larger than allowed")
    return data


def decode(b: bytes) -> str:
    if b.startswith(b"\xef\xbb\xbf"):
        b = b[3:]
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1")


def _entry(c: dict, **kw) -> dict:
    e = {"type": c["type"], "value": c["value"], "host": c.get("host") if c["type"] == "url" else None,
         "port": c.get("port") if c["type"] == "ip" else None}
    e.update({k: v for k, v in kw.items() if v not in (None, "")})
    return e


# ====================================================================== parsers
def parse_lines(text: str, types: list[str] | None = None) -> tuple[list[dict], int]:
    out, bad = [], 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;!" or s.startswith("//"):
            continue
        s = re.split(r"\s+[#;]", s, maxsplit=1)[0].split()[0]
        try:
            c = ioc.classify(s)
        except ioc.IOCError:
            bad += 1
            continue
        if types and c["type"] not in types:
            bad += 1
            continue
        out.append(_entry(c))
    return out, bad


def parse_hosts(text: str) -> tuple[list[dict], int]:
    """hosts-file block lists: '0.0.0.0 evil.com' / '127.0.0.1 evil.com' / bare domains."""
    out, bad = [], 0
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        parts = s.split()
        names = parts[1:] if len(parts) > 1 and re.match(r"^[\d.:]+$", parts[0]) else parts[:1]
        for n in names:
            if n in ("localhost", "localhost.localdomain", "broadcasthost", "local", "0.0.0.0"):
                continue
            try:
                c = ioc.classify(n)
            except ioc.IOCError:
                bad += 1
                continue
            if c["type"] == "domain" and not c.get("local"):
                out.append(_entry(c))
            else:
                bad += 1
    return out, bad


def parse_csv(text: str, column: str | int | None = None) -> tuple[list[dict], int]:
    """Generic CSV: the named / numbered column, or the first column whose cells look like indicators."""
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return [], 0
    rows = list(csv.reader(lines))
    col = None
    header = [h.strip().lower() for h in rows[0]]
    start = 0
    if isinstance(column, str) and not column.isdigit():
        if column.lower() not in header:
            raise FeedError(422, f"Column '{column}' not found (columns: {', '.join(header[:20])})")
        col, start = header.index(column.lower()), 1
    elif column is not None:
        col = int(column)
        start = 1 if not _looks_ioc(rows[0][col] if col < len(rows[0]) else "") else 0
    else:
        for i in range(max(len(r) for r in rows[:20])):
            vals = [r[i] for r in rows[1:21] if i < len(r)]
            if vals and sum(_looks_ioc(v) for v in vals) >= max(1, len(vals) // 2):
                col = i
                break
        if col is None:
            return [], len(rows)
        start = 0 if _looks_ioc(rows[0][col] if col < len(rows[0]) else "") else 1
    out, bad = [], 0
    for r in rows[start:]:
        if col >= len(r):
            bad += 1
            continue
        try:
            c = ioc.classify(r[col])
        except ioc.IOCError:
            bad += 1
            continue
        out.append(_entry(c))
    return out, bad


def _looks_ioc(s: str) -> bool:
    try:
        ioc.classify(s)
        return True
    except ioc.IOCError:
        return False


def _comment_header(text: str, needle: str) -> list[str] | None:
    for line in text.splitlines()[:40]:
        if line.startswith("#") and needle in line:
            h = line.lstrip("#").strip()
            return [x.strip().strip('"').lower() for x in next(csv.reader([h]))]
    return None


def parse_urlhaus(text: str) -> tuple[list[dict], int]:
    hdr = _comment_header(text, "url") or ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags",
                                           "urlhaus_link", "reporter"]
    ix = {h: i for i, h in enumerate(hdr)}
    out, bad = [], 0
    for r in csv.reader(ln for ln in text.splitlines() if ln and not ln.startswith("#")):
        get = lambda k: r[ix[k]].strip() if k in ix and ix[k] < len(r) else None          # noqa: E731
        try:
            c = ioc.classify(get("url") or "")
        except ioc.IOCError:
            bad += 1
            continue
        if c["type"] != "url":
            bad += 1
            continue
        out.append(_entry(c, threat=get("threat"), tags=get("tags"), first_seen=get("dateadded"),
                          ref=get("urlhaus_link")))
    return out, bad


TF_TYPES = {"ip:port": "ip", "domain": "domain", "url": "url", "md5_hash": "md5", "sha1_hash": "sha1",
            "sha256_hash": "sha256"}


def parse_threatfox(text: str) -> tuple[list[dict], int]:
    hdr = _comment_header(text, "ioc_value") or [
        "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type", "fk_malware", "malware_alias",
        "malware_printable", "last_seen_utc", "confidence_level", "reference", "tags", "anonymous", "reporter"]
    ix = {h: i for i, h in enumerate(hdr)}
    out, bad = [], 0
    for r in csv.reader(ln for ln in text.splitlines() if ln and not ln.startswith("#")):
        get = lambda k: (r[ix[k]].strip() if k in ix and ix[k] < len(r) else None) or None   # noqa: E731
        t = TF_TYPES.get((get("ioc_type") or "").lower())
        if not t:
            bad += 1
            continue
        try:
            c = ioc.classify(get("ioc_value") or "")
        except ioc.IOCError:
            bad += 1
            continue
        if c["type"] != t:
            bad += 1
            continue
        try:
            conf = int(get("confidence_level") or 0)
        except ValueError:
            conf = None
        tt = (get("threat_type") or "").lower()
        sev = "critical" if tt == "botnet_cc" and (conf or 0) >= 75 else "high" if (conf or 0) >= 75 else "medium"
        cat = {"botnet_cc": "c2", "payload_delivery": "malware_download", "payload": "malware"}.get(tt, "malware")
        mal = get("malware_printable")
        out.append(_entry(c, threat=None if mal in (None, "Unknown malware") else mal, tags=get("tags"),
                          first_seen=get("first_seen_utc"), confidence=conf, severity=sev, category=cat,
                          ref=get("reference") if (get("reference") or "").startswith("http") else None))
    return out, bad


def parse_spamhaus(text: str) -> tuple[list[dict], int]:
    out, bad = [], 0
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith(";"):                               # legacy drop.txt also accepted
            continue
        if s.startswith("{"):
            try:
                o = json.loads(s)
            except ValueError:
                bad += 1
                continue
            if o.get("type") == "metadata" or "cidr" not in o:
                continue
            cidr, sbl = o["cidr"], o.get("sblid")
        else:
            cidr, _, rest = s.partition(";")
            cidr, sbl = cidr.strip(), rest.strip() or None
        try:
            n = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            bad += 1
            continue
        out.append({"type": "cidr", "value": str(n), "host": None, "port": None, "threat": sbl,
                    "ref": f"https://check.spamhaus.org/sbl/query/{sbl}" if sbl else None})
    return out, bad


def parse(fmt: str, text: str, types: list[str] | None = None, column: str | int | None = None
          ) -> tuple[list[dict], int]:
    if fmt == "lines":
        return parse_lines(text, types)
    if fmt == "hosts":
        return parse_hosts(text)
    if fmt == "csv":
        return parse_csv(text, column)
    if fmt == "stix":
        try:
            items, bad = ioc.parse_stix(text)
        except ioc.IOCError as e:
            raise FeedError(422, str(e))
        return [dict(i, host=ioc.classify(i["value"]).get("host") if i["type"] == "url" else None, port=None)
                for i in items], bad
    if fmt == "urlhaus_csv":
        return parse_urlhaus(text)
    if fmt == "threatfox_csv":
        return parse_threatfox(text)
    if fmt == "spamhaus_json":
        return parse_spamhaus(text)
    if fmt == "auto":
        s = text.lstrip()[:2000]
        if s.startswith("{") and '"type"' in s and ("bundle" in s or "indicator" in s):
            return parse("stix", text)
        if s.startswith("{") and '"cidr"' in s:
            return parse_spamhaus(text)
        if "ioc_value" in s:
            return parse_threatfox(text)
        if re.search(r"^\s*(0\.0\.0\.0|127\.0\.0\.1)\s+\S+", s, re.M):
            return parse_hosts(text)
        items, bad = ioc.extract(text, limit=2_000_000)
        return [_entry(c) for c in items if not (c["type"] == "ip" and c["value"] in ("0.0.0.0", "127.0.0.1"))], bad
    raise FeedError(422, f"Unknown feed format '{fmt}'")
