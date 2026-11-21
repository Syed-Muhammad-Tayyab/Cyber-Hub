"""
Cyber Hub Backend - Firewall log reader (Part 9)
Developed by Syed Muhammad Tayyab

Reads the tail of the firewall's packet log and turns it into graph data:
dropped vs allowed per hour, top blocked sources, top targeted ports and
"port scan" suspects (one address knocking on many ports).

Understands both formats, line by line:
  * Windows  pfirewall.log (W3C):  date time action protocol src-ip dst-ip src-port dst-port
                                   size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path [pid]
  * Linux    ufw / kernel log:     ... [UFW BLOCK] IN=eth0 OUT= ... SRC=a DST=b ... PROTO=TCP SPT=1 DPT=2
Logging must be switched on first (PATCH /api/firewall/profiles/{name} {"log_blocked": true}).
"""
from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

PORT_NAMES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS / SMB", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "IPsec", 587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "SQL Server", 1434: "SQL Browser",
    1900: "SSDP / UPnP", 2375: "Docker API", 3306: "MySQL", 3389: "Remote Desktop", 5353: "mDNS",
    5355: "LLMNR", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM (HTTPS)", 6379: "Redis",
    8080: "HTTP alt", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

_MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
                                         "nov", "dec"], 1)}
_KV = re.compile(r"\b(IN|OUT|SRC|DST|PROTO|SPT|DPT)=(\S*)")
_UFW = re.compile(r"\[UFW (BLOCK|ALLOW|LIMIT BLOCK|AUDIT)\]")
_SYSLOG_TS = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)")
_ISO_TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)")


def _int(s: str | None) -> int | None:
    try:
        return int(s) if s not in (None, "", "-") else None
    except ValueError:
        return None


def parse_line(line: str, now: datetime | None = None) -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _UFW.search(line)
    if m:
        if m.group(1) == "AUDIT":
            return None
        kv = dict(_KV.findall(line))
        ts = None
        sm = _SYSLOG_TS.match(line)
        if sm:
            now = now or datetime.now()
            mon = _MONTHS.get(sm.group(1).lower())
            if mon:
                try:
                    ts = datetime(now.year, mon, int(sm.group(2)), int(sm.group(3)), int(sm.group(4)),
                                  int(sm.group(5)))
                    if ts > now + timedelta(days=1):
                        ts = ts.replace(year=now.year - 1)
                except ValueError:
                    ts = None
        else:
            im = _ISO_TS.match(line)
            if im:
                ts = datetime.fromisoformat(im.group(1))
        if ts is None:
            return None
        direction = "in" if kv.get("IN") and not kv.get("OUT") else ("out" if kv.get("OUT") and not kv.get("IN")
                                                                     else "fwd")
        return {"ts": ts, "action": "allow" if m.group(1) == "ALLOW" else "drop",
                "protocol": (kv.get("PROTO") or "?").lower(), "src": kv.get("SRC"), "dst": kv.get("DST"),
                "sport": _int(kv.get("SPT")), "dport": _int(kv.get("DPT")), "direction": direction, "pid": None}
    parts = line.split()
    if len(parts) < 8 or not re.match(r"\d{4}-\d\d-\d\d$", parts[0]):
        return None
    try:
        ts = datetime.fromisoformat(f"{parts[0]} {parts[1]}")
    except ValueError:
        return None
    action = parts[2].upper()
    if action not in ("DROP", "ALLOW"):
        return None                                        # INFO-EVENTS-LOST etc.
    path = parts[16].upper() if len(parts) > 16 else ""
    return {"ts": ts, "action": "drop" if action == "DROP" else "allow", "protocol": parts[3].lower(),
            "src": parts[4], "dst": parts[5], "sport": _int(parts[6]), "dport": _int(parts[7]),
            "direction": {"RECEIVE": "in", "SEND": "out", "FORWARD": "fwd"}.get(path, "in"),
            "pid": _int(parts[17]) if len(parts) > 17 else None}


def read_tail(path: str | Path, max_bytes: int) -> list[str]:
    """Last `max_bytes` of the file as lines (first partial line dropped)."""
    p = Path(os.path.expandvars(str(path)))
    size = p.stat().st_size
    with open(p, "rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
            f.readline()
        data = f.read()
    return data.decode("utf-8", errors="replace").splitlines()


def summarize(lines: list[str], hours: int = 24, now: datetime | None = None, recent: int = 50,
              scan_ports: int = 10) -> dict:
    now = now or datetime.now()
    since = now - timedelta(hours=hours)
    entries = [e for e in (parse_line(x, now) for x in lines) if e and e["ts"] >= since]
    drops = [e for e in entries if e["action"] == "drop"]
    inbound_drops = [e for e in drops if e["direction"] == "in"]

    buckets: dict[str, dict] = {}
    start = since.replace(minute=0, second=0, microsecond=0)
    t = start
    while t <= now:
        buckets[t.strftime("%Y-%m-%dT%H:00")] = {"hour": t.strftime("%Y-%m-%dT%H:00"), "drops": 0, "allows": 0}
        t += timedelta(hours=1)
    for e in entries:
        k = e["ts"].strftime("%Y-%m-%dT%H:00")
        if k in buckets:
            buckets[k]["drops" if e["action"] == "drop" else "allows"] += 1

    src_count = Counter(e["src"] for e in inbound_drops if e["src"])
    src_ports: dict[str, set] = defaultdict(set)
    src_last: dict[str, datetime] = {}
    for e in inbound_drops:
        if e["src"] and e["dport"] is not None:
            src_ports[e["src"]].add(e["dport"])
        if e["src"]:
            src_last[e["src"]] = max(src_last.get(e["src"], e["ts"]), e["ts"])
    port_count = Counter(e["dport"] for e in inbound_drops if e["dport"] is not None)

    def label(p):
        return PORT_NAMES.get(p)

    top_sources = [{"address": a, "drops": n, "ports": sorted(src_ports[a])[:20], "distinct_ports": len(src_ports[a]),
                    "last_seen": src_last[a].isoformat(timespec="seconds")} for a, n in src_count.most_common(10)]
    scanners = [{"address": a, "distinct_ports": len(ps), "drops": src_count[a],
                 "sample_ports": sorted(ps)[:15], "last_seen": src_last[a].isoformat(timespec="seconds")}
                for a, ps in src_ports.items() if len(ps) >= scan_ports]
    scanners.sort(key=lambda x: -x["distinct_ports"])
    return {
        "hours": hours, "entries": len(entries), "drops": len(drops),
        "allows": len(entries) - len(drops), "inbound_drops": len(inbound_drops),
        "outbound_drops": sum(1 for e in drops if e["direction"] == "out"),
        "by_protocol": dict(Counter(e["protocol"] for e in drops)),
        "by_hour": list(buckets.values()),
        "top_sources": top_sources,
        "top_ports": [{"port": p, "service": label(p), "drops": n} for p, n in port_count.most_common(10)],
        "port_scan_suspects": scanners[:10],
        "recent_drops": [{**{k: v for k, v in e.items() if k != "ts"}, "ts": e["ts"].isoformat(timespec="seconds"),
                          "service": label(e["dport"])} for e in reversed(drops[-recent:])],
    }
