"""
Cyber Hub Backend - Firewall & Network Protection service (Part 9)
Developed by Syed Muhammad Tayyab

What the Firewall & network protection section does with it:

  * Profiles   - Domain / Private / Public status, which network is on which
                 profile, turn the firewall on / off, default inbound / outbound
                 action, "block all incoming connections" (shields up),
                 notifications and packet logging.
  * Rules      - every rule with search / filters and risk flags (allow-all,
                 exposed RDP / SMB / databases, programs in Temp / Downloads,
                 rules for programs that no longer exist); switch on / off,
                 delete.
  * Blocks     - one click: block a program, a running process, IP addresses /
                 CIDR / ranges, or ports - in, out or both, permanently or for
                 N minutes (expired blocks are removed automatically). Each
                 block is one row here plus 1-4 OS rules named CyberHub-B<id>-...
                 in the "Cyber Hub" group. Blocks removed outside Cyber Hub are
                 detected (missing) and can be repaired. "Allow an app" too.
  * Analysis   - 0-100 firewall health score with findings and one-click fixes.
  * Watch      - background check that alerts when another program adds an
                 inbound allow rule (a classic malware move), switches a block
                 rule off or turns the firewall off.
  * Log        - dropped / allowed packets per hour, top blocked sources and
                 ports, port-scan suspects (fwlog.py).
  * Snapshots  - export the whole policy before risky changes, restore it,
                 reset to Windows defaults (snapshot taken first).

Reusable later: block_ip() by Part 10 (block a connection's remote address)
and Part 15 (block a bad IP from threat intel); analyze()["score"] by Part 18.
Part 10 reads inbound_verdict() / blocked_networks() (read-only helpers).
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import secrets
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psutil

from ..database import Database
from ..logger import get_logger
from . import fwlog
from .firewall_backends import BackendError, FirewallBackend, pick_backend
from .platform_tools import IS_WINDOWS
from .signatures import sha256_file

log = get_logger("firewall")

GROUP = "Cyber Hub"
RULE_PREFIX = "CyberHub-"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
PROFILE_KEYS = {"enabled", "default_inbound", "default_outbound", "allow_inbound_rules", "notify_on_listen",
                "log_blocked", "log_allowed"}

# Inbound ports that should never be open to the whole internet on a home PC.
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 69: "TFTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS / SMB",
    445: "SMB file sharing", 1433: "SQL Server", 1434: "SQL Browser", 2375: "Docker API", 3306: "MySQL",
    3389: "Remote Desktop", 5432: "PostgreSQL", 5900: "VNC remote control", 5985: "WinRM", 5986: "WinRM",
    6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
# Outbound ports whose blocking breaks the internet for the whole PC - needs force.
CRITICAL_OUT_PORTS = {53: "DNS (every website name lookup)", 67: "DHCP (getting an IP address)",
                      68: "DHCP (getting an IP address)", 80: "web browsing (HTTP)", 443: "web browsing (HTTPS)"}
# Programs whose network access Windows / Linux itself needs.
CRITICAL_PROGRAMS = {"svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "csrss.exe", "smss.exe",
                     "winlogon.exe", "system", "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
                     "mpdefendercoreservice.exe", "dnscache", "systemd", "systemd-resolved",
                     "systemd-networkd", "networkmanager", "dhclient", "dhcpcd", "wpa_supplicant"}
SUSPICIOUS_DIRS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\", "\\users\\public\\",
                   "\\$recycle.bin\\", "/tmp/", "/var/tmp/", "/dev/shm/", "/downloads/")
EXPOSED_ADDR = {"any", "internet", "*"}
SEVERITY_WEIGHT = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}
MAX_ADDRESSES, MAX_PORT_ITEMS = 64, 20
# Home / office network ranges (ipaddress.is_private also counts documentation ranges, so a list is used).
LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                                              "fc00::/7", "fe80::/10")]


def _is_lan(x) -> bool:
    """x = address or network, fully inside a LAN range."""
    net = x if isinstance(x, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else ipaddress.ip_network(x)
    return any(net.version == n.version and net.subnet_of(n) for n in LAN_NETS)


class FirewallError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _iso(dt: datetime | None = None) -> str:
    dt = (dt or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _sev_max(a: str, b: str) -> str:
    return a if SEVERITIES.index(a) >= SEVERITIES.index(b) else b


# ====================================================================== parsing helpers
def parse_port_ranges(text: str | None) -> list[tuple[int, int]] | None:
    """'any' -> None (all ports). '80,443,5000-5010' -> ranges. Keywords (RPC, IPHTTPS...) are ignored."""
    s = str(text or "any").strip().lower()
    if s in ("any", "*", ""):
        return None
    out = []
    for part in s.replace(" ", "").split(","):
        lo, _, hi = part.partition("-")
        if lo.isdigit() and (not hi or hi.isdigit()):
            a, b = int(lo), int(hi or lo)
            if 0 < a <= b <= 65535:
                out.append((a, b))
    return out


def parse_port_spec(spec: str | int) -> list[str]:
    """User input '445' | '6000-6010' | '80, 443' -> ['445', '6000-6010'] (validated)."""
    items = [x.strip() for x in str(spec).split(",") if x.strip()]
    if not items:
        raise FirewallError(400, "Enter a port, a range like 6000-6010, or a list like 80,443")
    if len(items) > MAX_PORT_ITEMS:
        raise FirewallError(400, f"At most {MAX_PORT_ITEMS} ports or ranges per block")
    out = []
    for it in items:
        lo, sep, hi = it.partition("-")
        if not lo.strip().isdigit() or (sep and not hi.strip().isdigit()):
            raise FirewallError(400, f"'{it}' is not a port number or range")
        a, b = int(lo), int(hi) if sep else int(lo)
        if not (1 <= a <= 65535 and 1 <= b <= 65535) or a > b:
            raise FirewallError(400, f"'{it}' is outside 1-65535 or the range is reversed")
        norm = str(a) if a == b else f"{a}-{b}"
        if norm not in out:
            out.append(norm)
    return out


def _covers(ranges: list[tuple[int, int]] | None, port: int) -> bool:
    return ranges is None or any(a <= port <= b for a, b in ranges)


def local_addresses() -> set:
    out = set()
    try:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                try:
                    out.add(ipaddress.ip_address(a.address.split("%")[0]))
                except ValueError:
                    pass
    except Exception:                                           # pragma: no cover
        pass
    return out


def parse_address(text: str, force: bool = False, own: set | None = None) -> tuple[str, list[str]]:
    """Validate one IP / CIDR / range. Returns (normalised text, warnings)."""
    s = str(text).strip()
    if not s:
        raise FirewallError(400, "Empty address")
    own = own if own is not None else local_addresses()
    warnings: list[str] = []
    if "-" in s:
        a_s, b_s = (x.strip() for x in s.split("-", 1))
        try:
            a, b = ipaddress.ip_address(a_s), ipaddress.ip_address(b_s)
        except ValueError:
            raise FirewallError(400, f"'{s}' is not a valid address range (use 10.0.0.5-10.0.0.20)")
        if a.version != b.version or int(a) > int(b):
            raise FirewallError(400, f"'{s}': both ends must be the same IP version and in order")
        size = int(b) - int(a) + 1
        if size > (2 ** 24 if a.version == 4 else 2 ** 80) and not force:
            raise FirewallError(400, f"'{s}' covers {size:,} addresses - too broad (pass force to insist)")
        loop = ipaddress.ip_network("127.0.0.0/8") if a.version == 4 else ipaddress.ip_network("::1/128")
        if int(a) <= int(loop.broadcast_address) and int(b) >= int(loop.network_address):
            raise FirewallError(400, f"'{s}' includes this computer's loopback addresses")
        if any(x.version == a.version and int(a) <= int(x) <= int(b) for x in own) and not force:
            raise FirewallError(400, f"'{s}' includes this computer's own address")
        if _is_lan(a) and _is_lan(b):
            warnings.append(f"{s} is on your local network - blocking it can cut off your router, printer or "
                            f"other devices")
        return f"{a}-{b}", warnings
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
        else:
            net = ipaddress.ip_network(ipaddress.ip_address(s))
    except ValueError:
        raise FirewallError(400, f"'{s}' is not a valid IP address or CIDR network")
    single = net.num_addresses == 1
    ip = net.network_address
    if single and (ip.is_loopback or ip.is_unspecified):
        raise FirewallError(400, f"{s} is this computer itself (loopback / unspecified) - it cannot be blocked")
    if not single:
        min_prefix = 8 if net.version == 4 else 16
        if net.prefixlen < min_prefix and not force:
            raise FirewallError(400, f"{net} covers {net.num_addresses:,} addresses - blocks wider than "
                                     f"/{min_prefix} need force")
        if any(net.overlaps(ipaddress.ip_network(x)) for x in ("127.0.0.0/8", "::1/128")
               if ipaddress.ip_network(x).version == net.version):
            raise FirewallError(400, f"{net} includes this computer's loopback addresses")
    if any(x.version == net.version and x in net for x in own):
        if single:
            raise FirewallError(400, f"{s} is this computer's own address")
        if not force:
            raise FirewallError(400, f"{net} includes this computer's own address (pass force to insist)")
    if ip.is_multicast:
        warnings.append(f"{s} is a multicast address - device discovery (printers, casting) may stop working")
    elif _is_lan(net):
        warnings.append(f"{s} is on your local network - blocking it can cut off your router, printer or "
                        f"other devices")
    return (str(ip) if single else str(net)), warnings


def _norm_path_key(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


def _expand_program(p: str | None) -> str | None:
    if not p:
        return None
    return os.path.expandvars(p)


def _is_suspicious_location(program: str | None) -> bool:
    if not program:
        return False
    low = _expand_program(program).lower().replace("/", "\\") if IS_WINDOWS else _expand_program(program).lower()
    return any(d in low or d.replace("\\", "/") in low for d in SUSPICIOUS_DIRS)


def _program_missing(program: str | None) -> bool:
    if not program or program.lower() == "system":
        return False
    p = _expand_program(program)
    if "%" in p or not os.path.isabs(p):
        return False
    return not os.path.exists(p)


def rule_flags(r: dict) -> list[dict]:
    """Explainable risk flags for one rule."""
    flags: list[dict] = []
    remote = str(r.get("remote_addresses") or "any").lower()
    exposed = any(x in EXPOSED_ADDR for x in remote.split(","))
    public = "public" in r.get("profiles", []) or "all" in r.get("profiles", [])
    if r.get("enabled") and r.get("direction") == "in" and r.get("action") == "allow":
        ports = parse_port_ranges(r.get("local_ports"))
        if (not r.get("program") and not r.get("service") and not r.get("package") and ports is None
                and exposed and r.get("protocol", "any") == "any"):
            flags.append({"code": "allow_all", "severity": "high",
                          "text": "Allows every incoming connection from anywhere - this cancels the firewall"})
        elif ports is not None and exposed:
            hit = sorted({name for port, name in RISKY_PORTS.items() if _covers(ports, port)})
            if hit:
                flags.append({"code": "exposed_service", "severity": "high" if public else "medium",
                              "text": f"Opens {', '.join(hit)} to any address"
                                      f"{' on public networks' if public else ''}"})
        if _is_suspicious_location(r.get("program")):
            flags.append({"code": "suspicious_location", "severity": "medium",
                          "text": "Lets a program in a Temp / Downloads / Public folder accept connections"})
    if r.get("enabled") and _program_missing(r.get("program")):
        flags.append({"code": "orphaned", "severity": "low",
                      "text": "The program this rule is for no longer exists"})
    return flags


def _fingerprint(r: dict) -> str:
    keys = ("name", "enabled", "direction", "action", "program", "service", "protocol", "local_ports",
            "remote_ports", "remote_addresses", "profiles")
    return hashlib.sha1(json.dumps([r.get(k) for k in keys], sort_keys=True, default=str).encode()).hexdigest()


# ====================================================================== service
class FirewallService:
    RULE_TTL = 30.0
    PROFILE_TTL = 10.0

    def __init__(self, db: Database, settings, activity, processes=None, data_dir: Path | None = None,
                 backend: FirewallBackend | None = None):
        self.db, self.settings, self.activity, self.processes = db, settings, activity, processes
        self.backend = backend or pick_backend()
        self.snap_dir = Path(data_dir or ".") / "firewall"
        self.snap_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._rules_cache: tuple[float, list[dict] | None] = (0.0, None)
        self._prof_cache: tuple[float, list[dict] | None] = (0.0, None)
        self.self_exe = sys.executable

    # ------------------------------------------------------------------ plumbing
    def _call(self, fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except BackendError as e:
            raise FirewallError(e.status, e.message)

    def available(self) -> bool:
        return self.backend.available()[0]

    def _require_available(self) -> None:
        ok, why = self.backend.available()
        if not ok:
            raise FirewallError(501, why or "No supported firewall on this computer")

    def invalidate(self) -> None:
        self._rules_cache = (0.0, None)
        self._prof_cache = (0.0, None)

    def _rules(self, refresh: bool = False) -> list[dict]:
        self._require_available()
        ts, data = self._rules_cache
        if refresh or data is None or time.monotonic() - ts > self.RULE_TTL:
            data = self._call(self.backend.rules)
            self._rules_cache = (time.monotonic(), data)
        return data

    def _profiles(self, refresh: bool = False) -> list[dict]:
        self._require_available()
        ts, data = self._prof_cache
        if refresh or data is None or time.monotonic() - ts > self.PROFILE_TTL:
            data = self._call(self.backend.profiles)
            self._prof_cache = (time.monotonic(), data)
        return data

    def _state_get(self, key: str, default: Any = None) -> Any:
        row = self.db.fetchone("SELECT value FROM firewall_state WHERE key=?", (key,))
        return json.loads(row["value"]) if row else default

    def _state_set(self, key: str, value: Any) -> None:
        self.db.execute("INSERT INTO firewall_state(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET "
                        "value=excluded.value", (key, json.dumps(value)))

    def _event(self, kind: str, severity: str, title: str, detail: str | None = None, rule_id: str | None = None,
               block_id: int | None = None, username: str | None = None, activity: bool = True) -> dict:
        cur = self.db.execute(
            "INSERT INTO firewall_events(kind, severity, title, detail, rule_id, block_id, username, acknowledged) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (kind, severity, title, detail, rule_id, block_id, username, 0 if SEVERITIES.index(severity) >= 2 else 1))
        if activity:
            who = f" (by {username})" if username else ""
            self.activity.record("firewall", title, (detail or "") + who or None, severity=severity,
                                 source="firewall")
        return self.db.fetchone("SELECT * FROM firewall_events WHERE id=?", (cur.lastrowid,))

    def _require_modify(self) -> None:
        self._require_available()
        if not self.backend.can_modify():
            from .firewall_backends import NEEDS_ADMIN
            raise FirewallError(403, NEEDS_ADMIN if self.backend.name in ("windows", "memory")
                                else "Changing the firewall needs root / administrator rights")

    # ------------------------------------------------------------------ baseline (rule watch)
    def _mark_seen(self, rules: list[dict]) -> None:
        now = _iso()
        with self.db.tx() as c:
            for r in rules:
                c.execute(
                    "INSERT INTO firewall_rule_seen(rule_id, name, direction, action, enabled, fingerprint, "
                    "first_seen, last_seen, present) VALUES (?,?,?,?,?,?,?,?,1) ON CONFLICT(rule_id) DO UPDATE SET "
                    "name=excluded.name, direction=excluded.direction, action=excluded.action, "
                    "enabled=excluded.enabled, fingerprint=excluded.fingerprint, last_seen=excluded.last_seen, "
                    "present=1",
                    (r["id"], r["name"], r["direction"], r["action"], int(bool(r["enabled"])), _fingerprint(r),
                     now, now))

    def _mark_gone(self, ids: list[str]) -> None:
        with self.db.tx() as c:
            for i in ids:
                c.execute("UPDATE firewall_rule_seen SET present=0 WHERE rule_id=?", (i,))

    def _sync_ids(self, ids: list[str]) -> None:
        """After our own change: record the new state of these rules so the watch stays quiet."""
        if not self._state_get("baseline_at"):
            return
        cur = {r["id"]: r for r in self._rules(refresh=True)}
        self._mark_seen([cur[i] for i in ids if i in cur])
        self._mark_gone([i for i in ids if i not in cur])

    def _sync_profiles(self) -> None:
        if self._state_get("baseline_at"):
            self._state_set("profiles", {p["name"]: p for p in self._profiles(refresh=True)})

    def rebaseline(self) -> dict:
        with self._lock:
            rules = self._rules(refresh=True)
            self.db.execute("DELETE FROM firewall_rule_seen")
            self._mark_seen(_dedupe(rules))
            self._state_set("profiles", {p["name"]: p for p in self._profiles(refresh=True)})
            self._state_set("baseline_at", _iso())
            return {"rules": len(rules)}

    # ------------------------------------------------------------------ Part 10 hooks (read-only)
    def active_profile_names(self) -> list[str]:
        """Profiles of the networks connected right now (all profiles if none is reported)."""
        names = [p["name"] for p in self._profiles()]
        try:
            active = [n["profile"] for n in self._call(self.backend.networks) if n.get("profile") in names]
        except FirewallError:
            active = []
        return sorted(set(active)) or names

    def inbound_verdict(self, port: int, protocol: str, program: str | None) -> dict:
        """Would an incoming connection to this local port reach the program listening on it?
        verdict = blocked | allowed | open | unknown, plus the deciding rule and the address scope.
        Used by Part 10 (listening ports) - never changes anything."""
        try:
            profiles = {p["name"]: p for p in self._profiles()}
            active = self.active_profile_names()
            rules = [r for r in self._rules() if r.get("enabled") and r.get("direction") == "in"]
        except FirewallError as e:
            return {"verdict": "unknown", "rule": None, "scope": None, "reason": e.message}
        prog = _norm_path_key(program) if program else None
        proto = (protocol or "tcp").lower()

        def matches(r: dict, prof: str) -> bool:
            rp = r.get("profiles") or []
            if rp and prof not in rp and "all" not in rp:
                return False
            rproto = str(r.get("protocol") or "any").lower()
            if rproto not in ("any", "", proto) and not (rproto == "both" and proto in ("tcp", "udp")):
                return False
            if not _covers(parse_port_ranges(r.get("local_ports")), port):
                return False
            if r.get("service") or r.get("package"):
                return False                       # service / store-app scoped rules: cannot tell -> ignore
            rprog = r.get("program")
            if rprog and str(rprog).lower() != "any":
                if not prog:                       # program unknown (kernel / access denied): assume it may apply
                    return True
                if str(rprog).lower() == "system":
                    return False
                return _norm_path_key(_expand_program(rprog) or rprog) == prog
            return True

        results = []
        for name in active:
            p = profiles.get(name)
            if not p:
                continue
            if not p.get("enabled"):
                results.append({"verdict": "open", "rule": None, "scope": "any", "profile": name,
                                "reason": f"The firewall is off for the {name} profile"})
                continue
            if not p.get("allow_inbound_rules", True):
                results.append({"verdict": "blocked", "rule": None, "scope": None, "profile": name,
                                "reason": "Block all incoming connections is on"})
                continue
            hits = [r for r in rules if matches(r, name)]
            blk = next((r for r in hits if r.get("action") == "block"), None)
            alw = next((r for r in hits if r.get("action") == "allow"), None)
            if blk:
                results.append({"verdict": "blocked", "rule": blk["name"], "scope": None, "profile": name,
                                "reason": f"Blocked by rule '{blk['name']}'"})
            elif alw:
                remote = str(alw.get("remote_addresses") or "any").lower()
                scope = "any" if any(x in EXPOSED_ADDR for x in remote.split(",")) else "limited"
                results.append({"verdict": "allowed", "rule": alw["name"], "scope": scope, "profile": name,
                                "reason": f"Allowed by rule '{alw['name']}'" +
                                          ("" if scope == "any" else f" (only from {alw.get('remote_addresses')})")})
            elif p.get("default_inbound") == "allow":
                results.append({"verdict": "open", "rule": None, "scope": "any", "profile": name,
                                "reason": f"The {name} profile allows incoming connections by default"})
            else:
                results.append({"verdict": "blocked", "rule": None, "scope": None, "profile": name,
                                "reason": "No rule allows it - blocked by default"})
        if not results:
            return {"verdict": "unknown", "rule": None, "scope": None, "reason": "No firewall profile is active"}
        order = {"open": 0, "allowed": 1, "blocked": 2}             # the most exposed active profile decides
        out = dict(min(results, key=lambda r: order[r["verdict"]]))
        out["program_known"] = bool(prog)
        return out

    def blocked_networks(self) -> list[tuple[Any, int]]:
        """Addresses under an active Cyber Hub IP block as (network | (first, last) int range, block id)."""
        out: list[tuple[Any, int]] = []
        for b in self.db.fetchall("SELECT id, target FROM firewall_blocks WHERE kind='ip' AND status IN "
                                  "('active','missing','pending')"):
            for item in str(b["target"]).split(","):
                item = item.strip()
                try:
                    if "-" in item:
                        a, z = (ipaddress.ip_address(x.strip()) for x in item.split("-", 1))
                        out.append(((a.version, int(a), int(z)), b["id"]))
                    else:
                        out.append((ipaddress.ip_network(item, strict=False), b["id"]))
                except ValueError:
                    continue
        return out

    # ------------------------------------------------------------------ status & profiles
    def profiles(self, refresh: bool = False) -> dict:
        profs = self._profiles(refresh)
        nets = self._call(self.backend.networks)
        active = {n["profile"] for n in nets}
        return {"profiles": [dict(p, active=p["name"] in active,
                                  block_all_inbound=not p["allow_inbound_rules"]) for p in profs],
                "networks": nets}

    def status(self) -> dict:
        info = self.backend.info()
        out: dict[str, Any] = {"backend": info, "can_modify": info["can_modify"], "error": None,
                               "state": "unavailable", "profiles": [], "networks": [], "rules": {},
                               "blocks": self._block_counts(), "score": None, "findings": {},
                               "unacknowledged_alerts": self.db.fetchone(
                                   "SELECT COUNT(*) AS n FROM firewall_events WHERE acknowledged=0")["n"],
                               "last_watch": self._state_get("last_watch")}
        if not info["available"]:
            return out
        try:
            pr = self.profiles()
            out["profiles"], out["networks"] = pr["profiles"], pr["networks"]
            on = [p["enabled"] for p in pr["profiles"]]
            out["state"] = "on" if on and all(on) else ("off" if not any(on) else "partial")
            out["shields_up"] = bool(pr["profiles"]) and all(p["block_all_inbound"] for p in pr["profiles"])
            rules = self._rules()
            out["rules"] = _rule_counts(rules)
            a = self.analyze()
            out["score"], out["grade"] = a["score"], a["grade"]
            out["findings"] = a["counts"]
        except FirewallError as e:
            out["error"] = e.message
        return out

    @staticmethod
    def lowers_protection(changes: dict) -> bool:
        return (changes.get("enabled") is False or changes.get("default_inbound") == "allow"
                or changes.get("default_outbound") == "allow" or changes.get("allow_inbound_rules") is True
                or changes.get("notify_on_listen") is False or changes.get("log_blocked") is False)

    def set_profile(self, name: str, changes: dict, username: str) -> dict:
        changes = {k: v for k, v in changes.items() if v is not None}
        bad = set(changes) - PROFILE_KEYS
        if bad:
            raise FirewallError(400, f"Unknown profile setting(s): {', '.join(sorted(bad))}")
        if not changes:
            raise FirewallError(400, "Nothing to change")
        for k in ("default_inbound", "default_outbound"):
            if k in changes and changes[k] not in ("allow", "block"):
                raise FirewallError(400, f"{k} must be allow or block")
        names = list(self.backend.profile_names) if name == "all" else [name]
        if any(n not in self.backend.profile_names for n in names):
            raise FirewallError(404, f"Unknown profile '{name}' (use {', '.join(self.backend.profile_names)} "
                                     f"or all)")
        with self._lock:
            self._require_modify()
            self._call(self.backend.set_profile, names, changes)
            self.invalidate()
            self._sync_profiles()
        label = "all networks" if name == "all" else f"{name.capitalize()} networks"
        if changes.get("enabled") is False:
            self._event("firewall_off", "high", f"Firewall turned OFF for {label}", None, username=username)
        elif changes.get("enabled") is True:
            self._event("firewall_on", "info", f"Firewall turned on for {label}", None, username=username)
        if "allow_inbound_rules" in changes:
            on = not changes["allow_inbound_rules"]
            self._event("shields_up", "info" if on else "low",
                        f"Block all incoming connections {'ON' if on else 'off'} for {label}", None,
                        username=username)
        rest = {k: v for k, v in changes.items() if k not in ("enabled", "allow_inbound_rules")}
        if rest:
            self._event("profile_changed", "medium" if self.lowers_protection(rest) else "info",
                        f"Firewall settings changed for {label}",
                        ", ".join(f"{k} = {v}" for k, v in rest.items()), username=username)
        return self.profiles(refresh=True)

    # ------------------------------------------------------------------ rules
    def _block_of_rule(self) -> dict[str, int]:
        out = {}
        for b in self.db.fetchall("SELECT id, rule_ids FROM firewall_blocks WHERE status IN ('active','missing')"):
            for rid in json.loads(b["rule_ids"]):
                out[rid] = b["id"]
        return out

    def _annotate(self, r: dict, owners: dict[str, int]) -> dict:
        flags = rule_flags(r)
        sev = "info"
        for f in flags:
            sev = _sev_max(sev, f["severity"])
        return dict(r, cyberhub=r["id"].startswith(RULE_PREFIX), block_id=owners.get(r["id"]), flags=flags,
                    risk=sev if flags else None)

    def list_rules(self, search: str | None = None, direction: str | None = None, action: str | None = None,
                   enabled: bool | None = None, profile: str | None = None, origin: str = "all",
                   flagged: bool = False, sort: str = "name", limit: int = 200, offset: int = 0,
                   refresh: bool = False) -> dict:
        owners = self._block_of_rule()
        rows = [self._annotate(r, owners) for r in self._rules(refresh)]
        counts = _rule_counts(rows) | {"flagged": sum(1 for r in rows if r["flags"])}
        q = (search or "").strip().lower()

        def keep(r: dict) -> bool:
            if direction and r["direction"] != direction:
                return False
            if action and r["action"] != action:
                return False
            if enabled is not None and r["enabled"] != enabled:
                return False
            if profile and profile not in r["profiles"]:
                return False
            if origin == "cyberhub" and not r["cyberhub"]:
                return False
            if origin == "system" and r["cyberhub"]:
                return False
            if origin == "policy" and r["source"] != "group_policy":
                return False
            if flagged and not r["flags"]:
                return False
            if q:
                hay = " ".join(str(r.get(k) or "") for k in ("id", "name", "group", "program", "service",
                                                              "local_ports", "remote_ports",
                                                              "remote_addresses", "description")).lower()
                if q not in hay:
                    return False
            return True

        items = [r for r in rows if keep(r)]
        if sort == "risk":
            items.sort(key=lambda r: (-(SEVERITIES.index(r["risk"]) if r["risk"] else -1), r["name"].lower()))
        elif sort == "program":
            items.sort(key=lambda r: ((r["program"] or "~").lower(), r["name"].lower()))
        else:
            items.sort(key=lambda r: (r["name"].lower(), r["direction"]))
        return {"total": len(items), "limit": limit, "offset": offset, "counts": counts,
                "items": items[offset:offset + limit]}

    def get_rule(self, rule_id: str, refresh: bool = False) -> dict:
        for r in self._rules(refresh):
            if r["id"] == rule_id:
                return self._annotate(r, self._block_of_rule())
        raise FirewallError(404, "No firewall rule with that id")

    @staticmethod
    def toggle_lowers(rule: dict, enabled: bool) -> bool:
        """Switching a BLOCK rule off or an ALLOW rule on lowers protection (admin)."""
        return (rule["action"] == "block" and not enabled) or (rule["action"] == "allow" and enabled)

    def set_rule_enabled(self, rule_id: str, enabled: bool, username: str) -> dict:
        with self._lock:
            r = self.get_rule(rule_id, refresh=True)
            if not r["editable"]:
                raise FirewallError(409, "This rule is managed by Group Policy / your organisation and cannot be "
                                         "changed here")
            if not self.backend.supports_toggle:
                raise FirewallError(501, f"{self.backend.label} rules cannot be switched off - delete it instead")
            if r["enabled"] == enabled:
                return r
            self._require_modify()
            self._call(self.backend.set_rule_enabled, rule_id, enabled)
            self.invalidate()
            self._sync_ids([rule_id])
        sev = "medium" if self.toggle_lowers(r, enabled) else "info"
        self._event("rule_enabled" if enabled else "rule_disabled", sev,
                    f"Firewall rule {'switched on' if enabled else 'switched off'}: {r['name']}",
                    f"{r['action']} {r['direction']}", rule_id=rule_id, block_id=r["block_id"], username=username)
        return self.get_rule(rule_id)

    def delete_rule(self, rule_id: str, username: str, force: bool = False) -> dict:
        with self._lock:
            r = self.get_rule(rule_id, refresh=True)
            if r["block_id"]:
                raise FirewallError(409, f"This rule belongs to Cyber Hub block #{r['block_id']} - remove the "
                                         f"block instead")
            if not r["editable"]:
                raise FirewallError(409, "This rule is managed by Group Policy / your organisation")
            if not r["cyberhub"] and not force:
                raise FirewallError(409, "This rule was made by Windows or another program - switch it off "
                                         "instead, or pass force=true to delete it")
            self._require_modify()
            self._call(self.backend.delete_rule, rule_id)
            self.invalidate()
            self._mark_gone([rule_id])
        self._event("rule_deleted", "medium" if r["action"] == "block" else "info",
                    f"Firewall rule deleted: {r['name']}", f"{r['action']} {r['direction']}", rule_id=rule_id,
                    username=username)
        return {"deleted": rule_id, "name": r["name"]}

    # ------------------------------------------------------------------ blocks
    @staticmethod
    def _public_block(b: dict) -> dict:
        out = dict(b)
        out["rule_ids"] = json.loads(b.get("rule_ids") or "[]")
        out["profiles"] = json.loads(b["profiles"]) if b.get("profiles") else None
        out.pop("specs", None)
        out.pop("target_key", None)
        exp = _parse_iso(b.get("expires_at"))
        out["temporary"] = exp is not None
        out["remaining_seconds"] = (max(0, int((exp - datetime.now(timezone.utc)).total_seconds()))
                                    if exp and b["status"] in ("active", "missing") else None)
        return out

    def get_block(self, block_id: int) -> dict:
        b = self.db.fetchone("SELECT * FROM firewall_blocks WHERE id=?", (block_id,))
        if not b:
            raise FirewallError(404, f"No Cyber Hub block #{block_id}")
        return self._public_block(b)

    def blocks(self, status: str | None = None, kind: str | None = None, limit: int = 200,
               offset: int = 0) -> dict:
        where, params = ["status != 'pending'"], []
        if status == "current":
            where.append("status IN ('active','missing')")
        elif status:
            where.append("status=?"); params.append(status)
        if kind:
            where.append("kind=?"); params.append(kind)
        clause = "WHERE " + " AND ".join(where)
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM firewall_blocks {clause}", tuple(params))["n"]
        rows = self.db.fetchall(f"SELECT * FROM firewall_blocks {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                                tuple(params) + (limit, offset))
        return {"total": total, "items": [self._public_block(b) for b in rows], "counts": self._block_counts()}

    def _block_counts(self) -> dict:
        rows = self.db.fetchall("SELECT kind, status, COUNT(*) AS n FROM firewall_blocks "
                                "WHERE status IN ('active','missing') GROUP BY kind, status")
        by_kind = {k: 0 for k in ("app", "ip", "port", "allow_app")}
        missing = 0
        for r in rows:
            by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + r["n"]
            missing += r["n"] if r["status"] == "missing" else 0
        soon = self.db.fetchone(
            "SELECT COUNT(*) AS n FROM firewall_blocks WHERE status IN ('active','missing') AND expires_at IS NOT "
            "NULL AND expires_at <= ?", (_iso(datetime.now(timezone.utc) + timedelta(hours=24)),))["n"]
        return {"active": sum(by_kind.values()), "by_kind": by_kind, "missing": missing, "expiring_24h": soon}

    def _create_block(self, *, kind: str, target: str, target_key: str, label: str, direction: str,
                      protocol: str, profiles: list[str] | None, reason: str | None, username: str,
                      minutes: int | None, sha256: str | None, spec_fn, warnings: list[str] | None = None) -> dict:
        with self._lock:
            self._require_modify()
            dup = self.db.fetchone(
                "SELECT * FROM firewall_blocks WHERE kind=? AND target_key=? AND direction=? AND protocol=? "
                "AND status IN ('active','missing')", (kind, target_key, direction, protocol))
            if dup:
                return self._public_block(dup) | {"already": True, "warnings": warnings or []}
            expires = _iso(datetime.now(timezone.utc) + timedelta(minutes=minutes)) if minutes else None
            cur = self.db.execute(
                "INSERT INTO firewall_blocks(kind, target, target_key, label, direction, protocol, profiles, reason, "
                "sha256, status, created_by, expires_at) VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?)",
                (kind, target, target_key, label, direction, protocol, json.dumps(profiles) if profiles else None,
                 reason, sha256, username, expires))
            bid = cur.lastrowid
            specs = spec_fn(bid)
            done: list[str] = []
            try:
                for s in specs:
                    self._call(self.backend.add_rule, s)
                    done.append(s["id"])
            except FirewallError:
                for rid in done:
                    try:
                        self.backend.delete_rule(rid)
                    except BackendError:
                        pass
                self.db.execute("DELETE FROM firewall_blocks WHERE id=?", (bid,))
                self.invalidate()
                raise
            ids = list(dict.fromkeys(s["id"] for s in specs))
            self.db.execute("UPDATE firewall_blocks SET rule_ids=?, specs=?, status='active', last_verified=? "
                            "WHERE id=?", (json.dumps(ids), json.dumps(specs), _iso(), bid))
            self.invalidate()
            self._sync_ids(ids)
        verb = "Allowed" if kind == "allow_app" else "Blocked"
        when = f" for {minutes} min" if minutes else ""
        self._event("block_created", "info", f"{verb} {label}{when}",
                    f"{_dir_text(direction)}{'; ' + reason if reason else ''}", block_id=bid, username=username)
        return self.get_block(bid) | {"already": False, "warnings": warnings or []}

    def _spec(self, rid: str, name: str, direction: str, action: str = "block", **kw) -> dict:
        return {"id": rid, "name": name, "group": GROUP, "direction": direction, "action": action,
                "profiles": kw.pop("profiles", None) or ["any"],
                "description": kw.pop("description", "Created by Cyber Hub"), **kw}

    @staticmethod
    def _dirs(direction: str) -> list[str]:
        if direction not in ("in", "out", "both"):
            raise FirewallError(400, "direction must be in, out or both")
        return ["in", "out"] if direction == "both" else [direction]

    def _check_program(self, path: str, force: bool) -> tuple[str, str]:
        if not path or not os.path.isabs(os.path.expanduser(path)):
            raise FirewallError(400, "Give the full path of the program (e.g. C:\\Program Files\\App\\app.exe)")
        p = os.path.normpath(os.path.expanduser(path))
        if not os.path.isfile(p):
            raise FirewallError(404, f"Program not found: {p}")
        try:
            if os.path.samefile(p, self.self_exe):
                raise FirewallError(403, "That is the program running Cyber Hub's own engine")
        except OSError:
            pass
        name = os.path.basename(p)
        stem = name.lower()
        if (stem in CRITICAL_PROGRAMS or os.path.splitext(stem)[0] in CRITICAL_PROGRAMS) and not force:
            raise FirewallError(403, f"{name} carries the operating system's own networking (DNS, DHCP, updates) - "
                                     f"blocking it can take the whole PC offline. Pass force=true if you are sure")
        return p, name

    def block_app(self, path: str, username: str, direction: str = "both", minutes: int | None = None,
                  reason: str | None = None, force: bool = False) -> dict:
        self._require_available()
        if not self.backend.supports_programs:
            raise FirewallError(501, f"{self.backend.label} cannot block a single program - block its ports or "
                                     f"addresses instead")
        p, name = self._check_program(path, force)
        dirs = self._dirs(direction)

        def specs(bid: int) -> list[dict]:
            return [self._spec(f"{RULE_PREFIX}B{bid}-{d}", f"Cyber Hub - Block {name} ({d})", d, program=p)
                    for d in dirs]
        return self._create_block(kind="app", target=p, target_key=_norm_path_key(p), label=name,
                                  direction=direction, protocol="any", profiles=None, reason=reason,
                                  username=username, minutes=minutes, sha256=sha256_file(p), spec_fn=specs)

    def block_process(self, pid: int, username: str, create_time: float | None = None, direction: str = "both",
                      minutes: int | None = None, reason: str | None = None, force: bool = False) -> dict:
        try:
            proc = psutil.Process(pid)
            if create_time is not None and abs(proc.create_time() - create_time) > 1:
                raise FirewallError(409, f"PID {pid} now belongs to a different process - refresh the list")
            name, exe = proc.name(), proc.exe()
        except psutil.NoSuchProcess:
            raise FirewallError(404, f"No process with PID {pid}")
        except psutil.AccessDenied:
            raise FirewallError(403, "Access denied - run Cyber Hub as administrator to read this process")
        if not exe:
            raise FirewallError(400, f"{name} (PID {pid}) has no program file to block")
        if self.processes is not None:
            why = self.processes.protection(pid, name, exe)
            if why and not force:
                raise FirewallError(403, f"Protected: {why}")
        return self.block_app(exe, username, direction, minutes,
                              reason or f"Blocked from running process {name} (PID {pid})", force)

    def block_ip(self, addresses: list[str], username: str, direction: str = "both", minutes: int | None = None,
                 reason: str | None = None, force: bool = False) -> dict:
        self._require_available()
        addresses = [a for a in (x.strip() for x in addresses) if a]
        if not addresses:
            raise FirewallError(400, "Give at least one IP address, CIDR network or range")
        if len(addresses) > MAX_ADDRESSES:
            raise FirewallError(400, f"At most {MAX_ADDRESSES} addresses per block")
        own = local_addresses()
        norm, warnings = [], []
        for a in addresses:
            n, w = parse_address(a, force, own)
            if "-" in n and not self.backend.supports_ranges:
                raise FirewallError(400, f"{self.backend.label} does not accept address ranges - use CIDR "
                                         f"notation (e.g. 10.0.0.0/24)")
            if n not in norm:
                norm.append(n)
                warnings += w
        dirs = self._dirs(direction)
        target = ",".join(norm)
        label = norm[0] + (f" +{len(norm) - 1} more" if len(norm) > 1 else "")

        def specs(bid: int) -> list[dict]:
            return [self._spec(f"{RULE_PREFIX}B{bid}-{d}", f"Cyber Hub - Block {label} ({d})", d,
                               remote_addresses=norm) for d in dirs]
        return self._create_block(kind="ip", target=target, target_key=",".join(sorted(norm)), label=label,
                                  direction=direction, protocol="any", profiles=None, reason=reason,
                                  username=username, minutes=minutes, sha256=None, spec_fn=specs,
                                  warnings=warnings)

    def block_port(self, ports: str | int, username: str, protocol: str = "tcp", direction: str = "in",
                   minutes: int | None = None, reason: str | None = None, force: bool = False) -> dict:
        self._require_available()
        items = parse_port_spec(ports)
        if protocol not in ("tcp", "udp", "both"):
            raise FirewallError(400, "protocol must be tcp, udp or both")
        dirs = self._dirs(direction)
        ranges = parse_port_ranges(",".join(items))
        if "out" in dirs and not force:
            hit = [f"{p} = {why}" for p, why in CRITICAL_OUT_PORTS.items() if _covers(ranges, p)]
            if hit:
                raise FirewallError(400, "Blocking outgoing " + "; ".join(hit) + " would break the internet for "
                                         "this PC. Pass force=true if that is really what you want")
        protos = ["tcp", "udp"] if protocol == "both" else [protocol]
        names = sorted({RISKY_PORTS.get(a) or fwlog.PORT_NAMES.get(a) for a, b in ranges if a == b} - {None})
        label = f"{'TCP/UDP' if protocol == 'both' else protocol.upper()} {', '.join(items)}" + (
            f" ({', '.join(names)})" if names else "")

        def specs(bid: int) -> list[dict]:
            out = []
            for d in dirs:
                for pr in protos:
                    key = "local_ports" if d == "in" else "remote_ports"
                    out.append(self._spec(f"{RULE_PREFIX}B{bid}-{d}-{pr}", f"Cyber Hub - Block {pr.upper()} "
                                          f"{', '.join(items)} ({d})", d, protocol=pr, **{key: items}))
            return out
        return self._create_block(kind="port", target=",".join(items), target_key=",".join(items), label=label,
                                  direction=direction, protocol=protocol, profiles=None, reason=reason,
                                  username=username, minutes=minutes, sha256=None, spec_fn=specs)

    def allow_app(self, path: str, username: str, profiles: list[str] | None = None, reason: str | None = None,
                  force: bool = False) -> dict:
        """Windows Security's 'Allow an app through firewall' (inbound). Private networks by default."""
        self._require_available()
        if not self.backend.supports_programs:
            raise FirewallError(501, f"{self.backend.label} cannot allow a single program")
        p, name = self._check_program(path, True)
        if _is_suspicious_location(p) and not force:
            raise FirewallError(403, f"{name} is in a Temp / Downloads / Public folder - malware lives there. Move "
                                     f"it to Program Files first, or pass force=true")
        profiles = sorted(set(profiles or ["private"]))
        if any(x not in self.backend.profile_names for x in profiles):
            raise FirewallError(400, f"profiles must be from {', '.join(self.backend.profile_names)}")
        where = "all networks" if set(profiles) >= set(self.backend.profile_names) else \
            ", ".join(x.capitalize() for x in profiles) + " networks"

        def specs(bid: int) -> list[dict]:
            return [self._spec(f"{RULE_PREFIX}A{bid}-in", f"Cyber Hub - Allow {name} ({where})", "in",
                               action="allow", program=p, profiles=profiles)]
        return self._create_block(kind="allow_app", target=p, target_key=_norm_path_key(p), label=name,
                                  direction="in", protocol="any", profiles=profiles, reason=reason,
                                  username=username, minutes=None, sha256=sha256_file(p), spec_fn=specs)

    def unblock(self, block_id: int, username: str, status: str = "removed", note: str | None = None) -> dict:
        with self._lock:
            b = self.db.fetchone("SELECT * FROM firewall_blocks WHERE id=?", (block_id,))
            if not b:
                raise FirewallError(404, f"No Cyber Hub block #{block_id}")
            if b["status"] not in ("active", "missing"):
                raise FirewallError(409, f"Block #{block_id} is already {b['status']}")
            self._require_modify()
            ids = json.loads(b["rule_ids"])
            for rid in ids:
                try:
                    self.backend.delete_rule(rid)
                except BackendError as e:
                    if e.status != 404:
                        raise FirewallError(e.status, e.message)
            self.db.execute("UPDATE firewall_blocks SET status=?, ended_at=?, ended_by=? WHERE id=?",
                            (status, _iso(), username, block_id))
            self.invalidate()
            self._mark_gone(ids)
        verb = "Allow" if b["kind"] == "allow_app" else "Block"
        if status == "expired":
            self._event("block_expired", "info", f"{verb} ended (time limit reached): {b['label']}", None,
                        block_id=block_id, username=username)
        else:
            self._event("block_removed", "low" if b["kind"] != "allow_app" else "info",
                        f"{verb} removed: {b['label']}", note, block_id=block_id, username=username)
        return self.get_block(block_id)

    def expire_due(self) -> list[int]:
        if not self.available():
            return []
        due = self.db.fetchall("SELECT id FROM firewall_blocks WHERE status IN ('active','missing') AND "
                               "expires_at IS NOT NULL AND expires_at <= ?", (_iso(),))
        done = []
        for r in due:
            try:
                self.unblock(r["id"], "Cyber Hub (time limit)", status="expired")
                done.append(r["id"])
            except FirewallError as e:
                log.warning("Could not end block #%s: %s", r["id"], e.message)
        return done

    def verify_blocks(self, quiet: bool = False) -> dict:
        with self._lock:
            present = {r["id"] for r in self._rules(refresh=True)}
            rows = self.db.fetchall("SELECT * FROM firewall_blocks WHERE status IN ('active','missing')")
            missing, back = [], []
            now = _iso()
            for b in rows:
                ids = json.loads(b["rule_ids"])
                gone = [i for i in ids if i not in present]
                if gone and b["status"] == "active":
                    self.db.execute("UPDATE firewall_blocks SET status='missing', last_verified=? WHERE id=?",
                                    (now, b["id"]))
                    missing.append(b["id"])
                    if not quiet:
                        self._event("block_missing", "high", f"A Cyber Hub block was removed outside Cyber Hub: "
                                    f"{b['label']}", f"{len(gone)} of {len(ids)} firewall rule(s) are gone - "
                                    f"repair it from the Blocks list", block_id=b["id"])
                elif not gone and b["status"] == "missing":
                    self.db.execute("UPDATE firewall_blocks SET status='active', last_verified=? WHERE id=?",
                                    (now, b["id"]))
                    back.append(b["id"])
                else:
                    self.db.execute("UPDATE firewall_blocks SET last_verified=? WHERE id=?", (now, b["id"]))
            return {"checked": len(rows), "missing": missing, "restored": back}

    def repair_block(self, block_id: int, username: str) -> dict:
        with self._lock:
            b = self.db.fetchone("SELECT * FROM firewall_blocks WHERE id=?", (block_id,))
            if not b:
                raise FirewallError(404, f"No Cyber Hub block #{block_id}")
            if b["status"] not in ("active", "missing"):
                raise FirewallError(409, f"Block #{block_id} is {b['status']} - create it again instead")
            self._require_modify()
            present = {r["id"] for r in self._rules(refresh=True)}
            fixed = 0
            for s in json.loads(b["specs"]):
                if s["id"] not in present:
                    self._call(self.backend.add_rule, s)
                    present.add(s["id"])
                    fixed += 1
            self.db.execute("UPDATE firewall_blocks SET status='active', last_verified=? WHERE id=?",
                            (_iso(), block_id))
            self.invalidate()
            self._sync_ids(json.loads(b["rule_ids"]))
        if fixed:
            self._event("block_repaired", "info", f"Block repaired: {b['label']}", f"{fixed} rule(s) re-created",
                        block_id=block_id, username=username)
        return self.get_block(block_id) | {"recreated": fixed}

    # ------------------------------------------------------------------ analysis + fixes
    def analyze(self, refresh: bool = False) -> dict:
        findings: list[dict] = []
        profiles = self._profiles(refresh)
        rules = _dedupe(self._rules(refresh))
        win_like = self.backend.name in ("windows", "memory")
        for p in profiles:
            nm = p["name"]
            label = "all" if nm == "all" else nm.capitalize()
            if not p["enabled"]:
                findings.append(_finding(f"profile_off:{nm}", "critical" if nm in ("public", "all") else "high",
                                         "profile", f"Firewall is OFF for {label} networks",
                                         "Every program can accept connections from the network.",
                                         {"action": "set_profile", "profile": nm, "changes": {"enabled": True}},
                                         "Turn on"))
            if p["default_inbound"] == "allow":
                findings.append(_finding(f"inbound_allow:{nm}", "high", "profile",
                                         f"{label} profile allows incoming connections by default",
                                         "Anything not explicitly blocked can reach this PC.",
                                         {"action": "set_profile", "profile": nm,
                                          "changes": {"default_inbound": "block"}}, "Block by default"))
            if win_like and not p["notify_on_listen"]:
                findings.append(_finding(f"notify_off:{nm}", "low", "profile",
                                         f"No notification when a new app is blocked ({label})",
                                         "You will not see when an unknown program tries to listen.",
                                         {"action": "set_profile", "profile": nm,
                                          "changes": {"notify_on_listen": True}}, "Turn on notifications"))
            if not p["log_blocked"]:
                findings.append(_finding(f"log_off:{nm}", "info", "profile",
                                         f"Dropped packets are not logged ({label})",
                                         "Turn on logging to see who is knocking (feeds the Firewall log graphs).",
                                         {"action": "set_profile", "profile": nm, "changes": {"log_blocked": True}},
                                         "Turn on logging"))
        orphans = []
        for r in rules:
            for f in rule_flags(r):
                if f["code"] == "orphaned":
                    if r["editable"] and not r["id"].startswith(RULE_PREFIX):
                        orphans.append(r["id"])
                    continue
                fix = ({"action": "disable_rules", "rule_ids": [r["id"]]} if self.backend.supports_toggle
                       else {"action": "delete_rules", "rule_ids": [r["id"]]}) if r["editable"] else None
                findings.append(_finding(f"{f['code']}:{r['id']}", f["severity"], "rule", f"{r['name']}",
                                         f["text"], fix, "Switch rule off" if fix and fix["action"] ==
                                         "disable_rules" else ("Delete rule" if fix else None), [r["id"]],
                                         admin=bool(fix and fix["action"] == "delete_rules")))
        if orphans:
            findings.append(_finding("orphaned_rules", "low", "rule", f"{len(orphans)} rule(s) for programs that "
                                     f"no longer exist", "Left behind by uninstalled software. Harmless but they "
                                     "clutter the list - and a new file at the same path would inherit them.",
                                     {"action": "delete_rules", "rule_ids": orphans[:200]}, "Delete them",
                                     orphans[:200], admin=True))
        for b in self.db.fetchall("SELECT id, label FROM firewall_blocks WHERE status='missing'"):
            findings.append(_finding(f"block_missing:{b['id']}", "medium", "block",
                                     f"Cyber Hub block removed outside Cyber Hub: {b['label']}",
                                     "Another program or person deleted its firewall rules.",
                                     {"action": "repair_block", "block_id": b["id"]}, "Repair"))
        if not self.backend.can_modify():
            findings.append(_finding("not_elevated", "info", "engine", "Cyber Hub can read but not change the "
                                     "firewall", "Start it with start_cyberhub_admin.bat to apply fixes and blocks.",
                                     None, None))
        findings.sort(key=lambda f: (-SEVERITIES.index(f["severity"]), f["title"].lower()))
        score = max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
        grade = ("Protected" if score >= 90 else "Good" if score >= 70 else "Needs attention" if score >= 50
                 else "At risk")
        return {"score": score, "grade": grade, "counts": counts, "findings": findings, "checked_at": _iso(),
                "rules_checked": len(rules)}

    def fix(self, finding_id: str, username: str, is_admin: bool) -> dict:
        a = self.analyze(refresh=True)
        f = next((x for x in a["findings"] if x["id"] == finding_id), None)
        if not f:
            raise FirewallError(404, "That finding is no longer present (already fixed?)")
        fx = f["fix"]
        if not fx:
            raise FirewallError(400, "This finding has no automatic fix")
        if f["fix_requires_admin"] and not is_admin:
            raise FirewallError(403, "Administrator rights required for this fix")
        done = 0
        if fx["action"] == "set_profile":
            self.set_profile(fx["profile"], fx["changes"], username)
            done = 1
        elif fx["action"] == "disable_rules":
            for rid in fx["rule_ids"]:
                self.set_rule_enabled(rid, False, username)
                done += 1
        elif fx["action"] == "delete_rules":
            self._require_modify()
            with self._lock:
                for rid in fx["rule_ids"]:
                    try:
                        self.backend.delete_rule(rid)
                        done += 1
                    except BackendError as e:
                        if e.status != 404:
                            raise FirewallError(e.status, e.message)
                self.invalidate()
                self._mark_gone(fx["rule_ids"])
            self._event("rules_deleted", "info", f"Deleted {done} firewall rule(s)", f["title"],
                        username=username)
        elif fx["action"] == "repair_block":
            self.repair_block(fx["block_id"], username)
            done = 1
        self._event("finding_fixed", "info", f"Fixed: {f['title']}", f"{done} change(s)", username=username,
                    activity=False)
        return {"fixed": f, "changes": done, "analysis": self.analyze(refresh=True)}

    # ------------------------------------------------------------------ watch
    def watch_once(self) -> dict:
        self._require_available()
        with self._lock:
            if not self._state_get("baseline_at"):
                r = self.rebaseline()
                self._state_set("last_watch", _iso())
                return {"baseline": True, "rules": r["rules"], "new": 0, "removed": 0, "changed": 0, "alerts": 0}
            cur = {r["id"]: r for r in _dedupe(self._rules(refresh=True))}
            seen = {r["rule_id"]: r for r in self.db.fetchall("SELECT * FROM firewall_rule_seen WHERE present=1")}
            known_ids = {r["rule_id"] for r in self.db.fetchall("SELECT rule_id FROM firewall_rule_seen")}
            new = [r for i, r in cur.items() if i not in seen]
            removed = [s for i, s in seen.items() if i not in cur]
            changed = [(seen[i], r) for i, r in cur.items() if i in seen and seen[i]["fingerprint"] != _fingerprint(r)]
            block_rules = self._block_of_rule()
            alerts = 0
            alert_allow = self.settings.get("firewall_alert_new_allow_rules")
            if len(new) > 50:
                self._event("rules_added", "medium", f"{len(new)} firewall rules were added outside Cyber Hub",
                            "Usually a software install, a policy import or a reset", activity=True)
                alerts += 1
            else:
                for r in new:
                    if r["id"] in known_ids and r["id"] in block_rules:
                        continue                                   # our block came back (verify handles it)
                    flags = rule_flags(r)
                    sev = "info"
                    inbound_allow = r["enabled"] and r["direction"] == "in" and r["action"] == "allow"
                    if inbound_allow and alert_allow:
                        sev = "medium"
                        for f in flags:
                            if f["code"] != "orphaned":
                                sev = _sev_max(sev, f["severity"])
                    what = f"{r['action']} {r['direction']}" + (f", {r['program']}" if r.get("program") else "") + (
                        f", ports {r['local_ports']}" if r.get("local_ports") not in (None, "any") else "")
                    self._event("rule_added", sev, f"New firewall rule: {r['name']}",
                                what + ("; " + "; ".join(f["text"] for f in flags) if flags else ""),
                                rule_id=r["id"], activity=sev != "info")
                    alerts += sev != "info"
            for s in removed:
                if s["rule_id"] in block_rules:
                    continue                                       # reported by verify_blocks
                self._event("rule_removed", "info", f"Firewall rule removed: {s['name']}",
                            f"{s['action']} {s['direction']}", rule_id=s["rule_id"], activity=False)
            for old, r in changed:
                sev, what = "info", "settings changed"
                if bool(old["enabled"]) != r["enabled"]:
                    what = "switched on" if r["enabled"] else "switched off"
                    if (r["action"] == "block" and not r["enabled"]) or (
                            r["enabled"] and r["direction"] == "in" and r["action"] == "allow" and alert_allow):
                        sev = "medium"
                elif old["action"] != r["action"]:
                    what = f"changed from {old['action']} to {r['action']}"
                    sev = "medium" if r["action"] == "allow" else "info"
                if r["id"] in block_rules:
                    sev = _sev_max(sev, "medium")
                self._event("rule_changed", sev, f"Firewall rule {what} outside Cyber Hub: {r['name']}",
                            f"{r['action']} {r['direction']}", rule_id=r["id"], block_id=block_rules.get(r["id"]),
                            activity=sev != "info")
                alerts += sev != "info"
            self._mark_seen(list(cur.values()))
            self._mark_gone([s["rule_id"] for s in removed])
            prof_changes = self._watch_profiles()
            alerts += prof_changes["alerts"]
            v = self.verify_blocks()
            self._state_set("last_watch", _iso())
        return {"baseline": False, "rules": len(cur), "new": len(new), "removed": len(removed),
                "changed": len(changed), "alerts": alerts + len(v["missing"]), "profile_changes":
                prof_changes["changes"], "blocks_missing": v["missing"]}

    def _watch_profiles(self) -> dict:
        old = self._state_get("profiles", {}) or {}
        now = {p["name"]: p for p in self._profiles(refresh=True)}
        changes, alerts = [], 0
        for name, p in now.items():
            o = old.get(name)
            if not o:
                continue
            label = "all networks" if name == "all" else f"{name.capitalize()} networks"
            if o["enabled"] and not p["enabled"]:
                self._event("firewall_off", "critical", f"Firewall was turned OFF for {label} outside Cyber Hub",
                            "If you did not do this, turn it back on and run a Full scan")
                alerts += 1
            elif not o["enabled"] and p["enabled"]:
                self._event("firewall_on", "info", f"Firewall turned on for {label}", None, activity=False)
            if o["default_inbound"] == "block" and p["default_inbound"] == "allow":
                self._event("profile_changed", "high", f"{label} now allow incoming connections by default",
                            "Changed outside Cyber Hub")
                alerts += 1
            if not o["allow_inbound_rules"] and p["allow_inbound_rules"]:
                self._event("shields_up", "low", f"Block all incoming connections was switched off for {label}",
                            "Changed outside Cyber Hub")
            diff = [k for k in PROFILE_KEYS if o.get(k) != p.get(k)]
            if diff:
                changes.append({"profile": name, "changed": diff})
        self._state_set("profiles", now)
        return {"changes": changes, "alerts": alerts}

    # ------------------------------------------------------------------ events & summary
    def events(self, after_id: int = 0, severity: str | None = None, kind: str | None = None,
               unacknowledged: bool = False, limit: int = 100, offset: int = 0) -> dict:
        where, params = ["id > ?"], [after_id]
        if severity:
            where.append("severity=?"); params.append(severity)
        if kind:
            where.append("kind=?"); params.append(kind)
        if unacknowledged:
            where.append("acknowledged=0")
        clause = "WHERE " + " AND ".join(where)
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM firewall_events {clause}", tuple(params))["n"]
        items = self.db.fetchall(f"SELECT * FROM firewall_events {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                                 tuple(params) + (limit, offset))
        last = self.db.fetchone("SELECT COALESCE(MAX(id),0) AS m FROM firewall_events")["m"]
        return {"total": total, "items": [dict(i, acknowledged=bool(i["acknowledged"])) for i in items],
                "last_id": last}

    def acknowledge(self, ids: list[int] | None = None) -> int:
        if ids:
            q = ",".join("?" * len(ids))
            return self.db.execute(f"UPDATE firewall_events SET acknowledged=1 WHERE id IN ({q})", tuple(ids)).rowcount
        return self.db.execute("UPDATE firewall_events SET acknowledged=1 WHERE acknowledged=0").rowcount

    def summary(self, days: int = 14) -> dict:
        since = _iso(datetime.now(timezone.utc) - timedelta(days=days))
        days_list = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days - 1, -1, -1)]
        ev = self.db.fetchall("SELECT substr(ts,1,10) AS day, severity, COUNT(*) AS n FROM firewall_events WHERE "
                              "ts >= ? GROUP BY day, severity", (since,))
        per_day = {d: {"day": d, **{s: 0 for s in SEVERITIES}, "blocks_created": 0} for d in days_list}
        for r in ev:
            if r["day"] in per_day:
                per_day[r["day"]][r["severity"]] += r["n"]
        for r in self.db.fetchall("SELECT substr(created_at,1,10) AS day, COUNT(*) AS n FROM firewall_blocks WHERE "
                                  "created_at >= ? AND status != 'pending' GROUP BY day", (since,)):
            if r["day"] in per_day:
                per_day[r["day"]]["blocks_created"] = r["n"]
        by_kind = {r["kind"]: r["n"] for r in self.db.fetchall(
            "SELECT kind, COUNT(*) AS n FROM firewall_events WHERE ts >= ? GROUP BY kind ORDER BY n DESC", (since,))}
        out: dict[str, Any] = {"days": days, "per_day": list(per_day.values()), "events_by_kind": by_kind,
                               "blocks": self._block_counts(), "rules": None, "score": None, "error": None}
        out["blocks"]["ended_in_period"] = {r["status"]: r["n"] for r in self.db.fetchall(
            "SELECT status, COUNT(*) AS n FROM firewall_blocks WHERE ended_at >= ? GROUP BY status", (since,))}
        out["top_blocked"] = [self._public_block(b) for b in self.db.fetchall(
            "SELECT * FROM firewall_blocks WHERE status IN ('active','missing') ORDER BY id DESC LIMIT 10")]
        if self.available():
            try:
                rules = self._rules()
                out["rules"] = _rule_counts(rules) | {"flagged": sum(1 for r in rules if rule_flags(r))}
                a = self.analyze()
                out["score"], out["grade"] = a["score"], a["grade"]
            except FirewallError as e:
                out["error"] = e.message
        return out

    # ------------------------------------------------------------------ packet log
    def log_path(self) -> str | None:
        custom = (self.settings.get("firewall_log_path") or "").strip()
        if custom:
            return os.path.expandvars(custom)
        try:
            for p in self._profiles():
                if p.get("log_file") and (p["log_blocked"] or p["log_allowed"]):
                    return os.path.expandvars(p["log_file"])
        except FirewallError:
            pass
        return self.backend.default_log_path()

    def log_summary(self, hours: int = 24, recent: int = 50) -> dict:
        path = self.log_path()
        if not path:
            raise FirewallError(404, "This firewall has no packet log")
        logging_on = None
        try:
            logging_on = any(p["log_blocked"] for p in self._profiles())
        except FirewallError:
            pass
        max_bytes = int(self.settings.get("firewall_log_max_mb")) * 1024 * 1024
        try:
            lines = fwlog.read_tail(path, max_bytes)
        except FileNotFoundError:
            raise FirewallError(404, "No firewall log yet - turn on logging of dropped packets first "
                                     "(Fix: 'Dropped packets are not logged')")
        except PermissionError:
            raise FirewallError(403, "Reading the firewall log needs administrator rights - start Cyber Hub with "
                                     "start_cyberhub_admin.bat")
        except OSError as e:
            raise FirewallError(500, f"Could not read the firewall log: {e}")
        return {"path": path, "logging_enabled": logging_on, **fwlog.summarize(lines, hours, recent=recent)}

    # ------------------------------------------------------------------ snapshots / reset
    def _snap_public(self, s: dict) -> dict:
        return dict(s, auto=bool(s["auto"]), exists=os.path.isfile(self.snap_dir / s["file"]))

    def snapshots(self) -> list[dict]:
        return [self._snap_public(s) for s in self.db.fetchall("SELECT * FROM firewall_snapshots ORDER BY id DESC")]

    def create_snapshot(self, username: str, note: str | None = None, auto: bool = False) -> dict:
        self._require_available()
        if not self.backend.supports_snapshots:
            raise FirewallError(501, f"{self.backend.label} policy snapshots are not supported")
        self._require_modify()
        ext = "wfw" if self.backend.name == "windows" else "json"
        name = f"firewall-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}.{ext}"
        path = self.snap_dir / name
        with self._lock:
            self._call(self.backend.export_policy, path)
            if not path.is_file():
                raise FirewallError(502, "The firewall did not write the export file")
            data = path.read_bytes()
            try:
                n_rules = len(self._rules())
            except FirewallError:
                n_rules = None
            cur = self.db.execute(
                "INSERT INTO firewall_snapshots(file, backend, note, size, sha256, rules, auto, created_by) "
                "VALUES (?,?,?,?,?,?,?,?)", (name, self.backend.name, note, len(data),
                                             hashlib.sha256(data).hexdigest(), n_rules, int(auto), username))
            sid = cur.lastrowid
            self._prune_snapshots()
        self._event("snapshot_created", "info", f"Firewall policy snapshot #{sid} saved", note, username=username,
                    activity=not auto)
        return self._snap_public(self.db.fetchone("SELECT * FROM firewall_snapshots WHERE id=?", (sid,)))

    def _prune_snapshots(self) -> None:
        keep = int(self.settings.get("firewall_snapshot_keep"))
        old = self.db.fetchall("SELECT * FROM firewall_snapshots WHERE auto=1 ORDER BY id DESC LIMIT -1 OFFSET ?",
                               (keep,))
        for s in old:
            self._delete_snapshot_row(s)

    def _delete_snapshot_row(self, s: dict) -> None:
        try:
            (self.snap_dir / s["file"]).unlink()
        except OSError:
            pass
        self.db.execute("DELETE FROM firewall_snapshots WHERE id=?", (s["id"],))

    def delete_snapshot(self, snap_id: int) -> None:
        s = self.db.fetchone("SELECT * FROM firewall_snapshots WHERE id=?", (snap_id,))
        if not s:
            raise FirewallError(404, f"No snapshot #{snap_id}")
        self._delete_snapshot_row(s)

    def restore_snapshot(self, snap_id: int, username: str) -> dict:
        s = self.db.fetchone("SELECT * FROM firewall_snapshots WHERE id=?", (snap_id,))
        if not s:
            raise FirewallError(404, f"No snapshot #{snap_id}")
        if s["backend"] != self.backend.name:
            raise FirewallError(409, f"Snapshot #{snap_id} was taken from {s['backend']}, not {self.backend.name}")
        path = self.snap_dir / s["file"]
        if not path.is_file():
            raise FirewallError(404, f"The file for snapshot #{snap_id} is missing")
        if hashlib.sha256(path.read_bytes()).hexdigest() != s["sha256"]:
            raise FirewallError(409, f"Snapshot #{snap_id} was modified after it was saved - refusing to import it")
        before = self.create_snapshot(username, f"Automatic - before restoring #{snap_id}", auto=True)
        with self._lock:
            self._call(self.backend.import_policy, path)
            self.invalidate()
            self.rebaseline()
            v = self.verify_blocks(quiet=True)
        self._event("snapshot_restored", "medium", f"Firewall policy restored from snapshot #{snap_id}",
                    s["note"], username=username)
        return {"restored": snap_id, "safety_snapshot": before["id"], "blocks": v}

    def reset_defaults(self, username: str) -> dict:
        self._require_available()
        self._require_modify()
        before = self.create_snapshot(username, "Automatic - before reset to defaults", auto=True) \
            if self.backend.supports_snapshots else None
        with self._lock:
            self._call(self.backend.reset)
            self.invalidate()
            ended = self.db.execute("UPDATE firewall_blocks SET status='removed', ended_at=?, ended_by=? WHERE "
                                    "status IN ('active','missing')", (_iso(), f"{username} (reset)")).rowcount
            self.rebaseline()
        self._event("policy_reset", "high", "Firewall reset to default settings",
                    f"{ended} Cyber Hub block(s) ended; safety snapshot #{before['id'] if before else '-'}",
                    username=username)
        return {"reset": True, "blocks_ended": ended, "safety_snapshot": before["id"] if before else None}


# ====================================================================== module helpers
def _dedupe(rules: list[dict]) -> list[dict]:
    seen, out = set(), []
    for r in rules:
        if r["id"] not in seen:
            seen.add(r["id"])
            out.append(r)
    return out


def _rule_counts(rules: list[dict]) -> dict:
    en = [r for r in rules if r["enabled"]]
    return {"total": len(rules), "enabled": len(en), "disabled": len(rules) - len(en),
            "inbound_allow": sum(1 for r in en if r["direction"] == "in" and r["action"] == "allow"),
            "inbound_block": sum(1 for r in en if r["direction"] == "in" and r["action"] == "block"),
            "outbound_allow": sum(1 for r in en if r["direction"] == "out" and r["action"] == "allow"),
            "outbound_block": sum(1 for r in en if r["direction"] == "out" and r["action"] == "block"),
            "cyberhub": sum(1 for r in rules if r["id"].startswith(RULE_PREFIX)),
            "policy_managed": sum(1 for r in rules if r.get("source") == "group_policy")}


def _finding(fid: str, severity: str, category: str, title: str, detail: str, fix: dict | None,
             fix_label: str | None, rule_ids: list[str] | None = None, admin: bool = False) -> dict:
    return {"id": fid, "severity": severity, "category": category, "title": title, "detail": detail,
            "rule_ids": rule_ids or [], "fix": fix, "fix_label": fix_label,
            "fix_requires_admin": bool(fix) and admin}


def _dir_text(direction: str) -> str:
    return {"in": "incoming", "out": "outgoing", "both": "incoming + outgoing"}.get(direction, direction)


async def firewall_loop(svc: FirewallService, settings, tick: float = 30, first_delay: float = 20) -> None:
    """Every 30 s: end expired blocks. Every N minutes: rule / profile watch + block verification."""
    if not svc.available():
        log.info("Firewall watch not started: %s", svc.backend.available()[1])
        return
    log.info("Firewall watch started (%s)", svc.backend.label)
    await asyncio.sleep(first_delay)
    last: float | None = None             # None = run the first watch straight away (even right after boot)
    while True:
        try:
            await asyncio.to_thread(svc.expire_due)
            interval = int(settings.get("firewall_watch_interval_minutes")) * 60
            if settings.get("firewall_watch_enabled") and (last is None or time.monotonic() - last >= interval):
                last = time.monotonic()
                await asyncio.to_thread(svc.watch_once)
        except Exception as e:                                   # never let the loop die
            log.warning("Firewall watch failed: %s", getattr(e, "message", e))
        await asyncio.sleep(tick)
