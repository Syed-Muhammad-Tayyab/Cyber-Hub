"""
Cyber Hub Backend - Network Monitor & Wi-Fi service (Part 10)
Developed by Syed Muhammad Tayyab

What the Network section does with it:

  * Connections - every TCP / UDP connection with the program that owns it,
                  local / LAN / internet scope, incoming vs outgoing, service
                  names, explainable risk flags (red-flag remote ports such as
                  Metasploit / Tor / mining pools, PowerShell & other LOLBins
                  online, programs in Temp / Downloads, fake system names,
                  someone on the internet using your Remote Desktop / SMB),
                  grouped per program, plus scan-like behaviour (many SYN_SENT,
                  very many distinct internet hosts).
  * Listening   - open ports with exposure (this PC only / network) and the
                  Part 9 firewall's real verdict for each (blocked / allowed by
                  rule X / open), so "port 3389 is open" becomes "port 3389 is
                  open AND the firewall lets the internet in".
  * Findings    - one 0-100 network score with findings and one-click fixes
                  (block the remote address / the port / the program through
                  Part 9's guarded block functions).
  * Wi-Fi       - current connection rating (Open / WEP / WPA / WPA2-TKIP /
                  WPA2 / WPA3 / Enhanced Open), evil-twin check (same name,
                  weaker security nearby), saved networks that auto-join open
                  hotspots, nearby networks, connection history.
  * LAN         - devices on your network from the ARP table, and an opt-in
                  scan (private subnets only, fixed port list) that adds open
                  ports, NetBIOS names, vendors and a device-type guess; new
                  device alerts on networks you mark as Home; router hardware
                  address change / duplicate = ARP spoofing alert.
  * Watch       - background check every N minutes: new listening ports,
                  suspicious connections, gateway changes, new devices, insecure
                  Wi-Fi; plus traffic-shape samples for the graphs.

Reusable later: connections() by Part 15 (IOC matching), analyze()["score"]
by Part 18, events by Part 17 notifications.
"""
from __future__ import annotations

import asyncio
import concurrent.futures as cf
import hashlib
import ipaddress
import json
import os
import socket
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

import psutil

from ..database import Database
from ..logger import get_logger
from . import netprobe as npb
from . import threat_flags as tf
from .platform_tools import IS_LINUX, IS_WINDOWS

log = get_logger("network")

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_MAX_BYTES = 16 * 1024 * 1024
LOLBINS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
           "regsvcs.exe", "msiexec.exe", "wmic.exe", "forfiles.exe", "hh.exe"}

# connection flag -> (weight, text)
CONN_FLAGS: dict[str, tuple[int, str]] = {
    "suspicious_port":     (35, "Connects to an internet port commonly used by {what}"),
    "script_host":         (30, "A command shell / script host is talking to the internet"),
    "suspicious_location": (40, "The program runs from a Temp, Downloads or Public folder"),
    "masquerade":          (60, "Uses a Windows system name but runs from the wrong folder"),
    "bad_signature":       (50, "The program's digital signature is broken"),
    "exposed_in_use":      (60, "Someone on the internet is connected to your {what}"),
    "blocked_target":      (0,  "This address is blocked by a Cyber Hub firewall block (connection opened earlier)"),
}

WIFI_RATING: dict[str, tuple[str, str, str]] = {
    "wpa3":            ("excellent", "info", "WPA3 - the strongest Wi-Fi protection available"),
    "wpa3-enterprise": ("excellent", "info", "WPA3-Enterprise - per-user sign-in with the strongest encryption"),
    "wpa2-enterprise": ("good", "info", "WPA2-Enterprise - per-user sign-in, strong encryption"),
    "wpa2/wpa3":       ("good", "info", "WPA2/WPA3 mixed mode - strong; switch the router to WPA3-only when all "
                                        "your devices support it"),
    "wpa2":            ("good", "info", "WPA2 with AES - secure with a long, unique password; WPA3 is better if "
                                        "your router offers it"),
    "owe":             ("fair", "low", "Enhanced Open - traffic is encrypted but anyone can join; treat it as "
                                       "public Wi-Fi"),
    "wpa":             ("weak", "high", "WPA (first generation) can be cracked - switch the router to WPA2 or "
                                        "WPA3"),
    "wep":             ("insecure", "critical", "WEP can be cracked in minutes - anyone nearby can read and "
                                                "join this network; switch the router to WPA2 or WPA3 now"),
    "open":            ("open", "high", "No encryption - anyone nearby can see unencrypted traffic and pretend "
                                        "to be this network. Use a VPN and HTTPS only, and set it as Public"),
    "unknown":         ("unknown", "info", "Security type could not be read"),
}
AUTH_STRENGTH = {"open": 0, "owe": 1, "wep": 1, "wpa": 2, "unknown": 3, "wpa2": 3, "wpa2/wpa3": 4,
                 "wpa2-enterprise": 4, "wpa3": 5, "wpa3-enterprise": 5}

DEVICE_PORT_FLAGS: dict[int, tuple[str, str]] = {
    23:   ("high", "Telnet is open - the favourite target of IoT botnets (Mirai). Turn Telnet off or update / "
                   "replace the device"),
    554:  ("medium", "Camera stream port (RTSP) is open - make sure the camera has a strong, non-default "
                     "password and recent firmware"),
    5900: ("medium", "VNC remote control is open - anyone on your network can try to log in"),
    21:   ("low", "FTP file transfer is open - it sends passwords unencrypted"),
    1883: ("low", "MQTT (smart-home messaging) is open without encryption"),
    3389: ("low", "Remote Desktop is open on your network"),
}


class NetworkError(Exception):
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


def _fid(key: str) -> str:
    return "n" + hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:12]


def is_ephemeral(port: int) -> bool:
    return port >= 49152 or (IS_LINUX and 32768 <= port <= 60999)


def _risky_ports() -> dict[int, str]:
    from .firewall import RISKY_PORTS              # one list for Part 9 + Part 10
    return RISKY_PORTS


class NetworkService:
    ANALYZE_TTL = 10.0
    WIFI_TTL = 20.0

    def __init__(self, db: Database, settings, activity, processes=None, firewall=None,
                 probe: npb.NetProbe | None = None):
        self.db, self.settings, self.activity = db, settings, activity
        self.processes, self.firewall = processes, firewall
        self.probe = probe or npb.pick_probe()
        self._lock = threading.RLock()
        self._proc_cache: dict[int, dict] = {}
        self._analyze_cache: tuple[float, dict | None] = (0.0, None)
        self._wifi_cache: tuple[float, dict | None] = (0.0, None)
        self._dns_cache: dict[str, tuple[float, str | None]] = {}
        self._dns_pool = cf.ThreadPoolExecutor(max_workers=8, thread_name_prefix="ch-dns")
        self._oui: dict[str, str] | None = None
        self._scan_lock = threading.Lock()
        self._scan: dict[str, Any] = {"state": "idle"}
        self._scan_thread: threading.Thread | None = None
        self._scan_cancel = threading.Event()
        self.self_pid = os.getpid()

    # ================================================================== plumbing
    def _state_get(self, key: str, default: Any = None) -> Any:
        row = self.db.fetchone("SELECT value FROM network_state WHERE key=?", (key,))
        return json.loads(row["value"]) if row else default

    def _state_set(self, key: str, value: Any) -> None:
        self.db.execute("INSERT INTO network_state(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET "
                        "value=excluded.value", (key, json.dumps(value)))

    def _event(self, kind: str, severity: str, title: str, detail: str | None = None, key: str | None = None,
               username: str | None = None, data: dict | None = None) -> dict:
        cur = self.db.execute(
            "INSERT INTO network_events(kind, severity, title, detail, ref, username, data, acknowledged) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (kind, severity, title, detail, key, username, json.dumps(data) if data else None,
             0 if SEVERITIES.index(severity) >= 2 else 1))
        who = f" (by {username})" if username else ""
        try:
            self.activity.record("network", title, ((detail or "") + who) or None, severity=severity,
                                 source="network")
        except Exception:                                             # pragma: no cover
            pass
        return self._event_row(self.db.fetchone("SELECT * FROM network_events WHERE id=?", (cur.lastrowid,)))

    @staticmethod
    def _event_row(r: dict | None) -> dict | None:
        if r is None:
            return None
        r = dict(r)
        r["data"] = json.loads(r["data"]) if r.get("data") else None
        r["acknowledged"] = bool(r["acknowledged"])
        return r

    def _once(self, key: str, hours: float) -> bool:
        """True the first time `key` is seen in `hours` (alert throttling)."""
        with self._lock:
            seen = self._state_get("alerted", {})
            now = time.time()
            last = seen.get(key)
            if last and now - last < hours * 3600:
                return False
            seen[key] = now
            if len(seen) > 600:                                        # keep the newest 400
                seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-400:])
            self._state_set("alerted", seen)
            return True

    def invalidate(self) -> None:
        self._analyze_cache = (0.0, None)
        self._wifi_cache = (0.0, None)

    # ================================================================== processes
    def _proc(self, pid: int | None) -> dict:
        """name / exe / create_time + Part 4 style risk flags for one PID (cached per process instance)."""
        if not pid:
            return {"pid": pid, "name": "System" if pid == 4 else None, "exe": None, "create_time": None,
                    "flags": [], "protected": pid in (0, 4), "user": None}
        hit = self._proc_cache.get(pid)
        try:
            p = psutil.Process(pid)
            ct = p.create_time()
            if hit and hit["create_time"] == ct:
                return hit
            with p.oneshot():
                name = p.name()
                try:
                    exe = p.exe() or None
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    exe = None
                try:
                    user = p.username()
                except (psutil.AccessDenied, OSError):
                    user = None
        except psutil.NoSuchProcess:
            return {"pid": pid, "name": None, "exe": None, "create_time": None, "flags": [], "protected": False,
                    "user": None, "gone": True}
        except (psutil.AccessDenied, OSError):
            return {"pid": pid, "name": None, "exe": None, "create_time": None, "flags": [], "protected": False,
                    "user": None, "access_denied": True}
        flags = list(tf.path_flags(exe))
        if tf.is_masquerading(name, exe):
            flags.append("masquerade")
        if (name or "").lower() in LOLBINS:
            flags.append("script_host")
        sig = None
        if self.processes is not None and exe:
            try:
                sig = self.processes.sigs.cached(exe)
            except Exception:                                          # pragma: no cover
                sig = None
        if sig and sig.get("status") in ("tampered", "untrusted"):
            flags.append("bad_signature")
        prot = None
        if self.processes is not None:
            try:
                prot = self.processes.protection(pid, name, exe)
            except Exception:                                          # pragma: no cover
                prot = None
        own = pid == self.self_pid or (self.processes is not None and pid in getattr(self.processes, "guarded", ()))
        info = {"pid": pid, "name": name, "exe": exe, "create_time": ct, "user": user,
                "flags": [] if own else flags, "protected": bool(prot), "cyberhub": own,
                "signature": {"status": sig["status"], "publisher": sig.get("publisher")} if sig else None}
        self._proc_cache[pid] = info
        return info

    # ================================================================== connections
    def _extra_ports(self) -> dict[int, str]:
        out = {}
        for x in self.settings.get("network_extra_suspicious_ports") or []:
            s = str(x).strip()
            if s.isdigit() and 1 <= int(s) <= 65535:
                out[int(s)] = "a port on your own watch list"
        return out

    def _blocked_lookup(self):
        nets: list = []
        if self.firewall is not None:
            try:
                nets = self.firewall.blocked_networks()
            except Exception:                                          # never let Part 9 break Part 10
                nets = []

        def find(ip: str) -> int | None:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for n, bid in nets:
                if isinstance(n, tuple):
                    if n[0] == a.version and n[1] <= int(a) <= n[2]:
                        return bid
                elif n.version == a.version and a in n:
                    return bid
            return None
        return find

    def _snapshot(self) -> list[dict]:
        """Raw, normalised connection rows (no flags yet)."""
        try:
            raw = self.probe.connections()
        except psutil.AccessDenied:
            raise NetworkError(403, "Access denied listing connections - run Cyber Hub as administrator")
        rows = []
        live_pids = set()
        for c in raw:
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            fam = 6 if c.family == socket.AF_INET6 else 4
            lip = npb.unwrap_ip(c.laddr.ip) if c.laddr else None
            lport = c.laddr.port if c.laddr else None
            rip = npb.unwrap_ip(c.raddr.ip) if c.raddr else None
            rport = c.raddr.port if c.raddr else None
            status = (c.status or "NONE").upper()
            if proto == "udp":
                status = "CONNECTED" if rip else "BOUND"
            live_pids.add(c.pid)
            rows.append({"proto": proto, "family": fam, "local_ip": lip, "local_port": lport, "remote_ip": rip,
                         "remote_port": rport, "status": status, "pid": c.pid})
        for pid in [p for p in self._proc_cache if p not in live_pids]:
            self._proc_cache.pop(pid, None)
        listen_keys = {(r["proto"], r["local_port"]) for r in rows if r["status"] in ("LISTEN",)}
        for r in rows:
            if r["status"] == "LISTEN":
                r["direction"], scope_ip = "listening", r["local_ip"]
            elif r["status"] == "BOUND":
                r["direction"], scope_ip = "bound", r["local_ip"]
            elif r["remote_ip"] and (r["proto"], r["local_port"]) in listen_keys:
                r["direction"], scope_ip = "incoming", r["remote_ip"]
            else:
                r["direction"], scope_ip = "outgoing", r["remote_ip"]
            sc = npb.ip_scope(scope_ip) if scope_ip else "unspecified"
            if r["direction"] in ("listening", "bound"):
                sc = "local" if sc == "local" else "network"
            r["scope"] = sc
            port_for_service = r["local_port"] if r["direction"] in ("listening", "bound", "incoming") \
                else r["remote_port"]
            r["service"] = npb.service_name(port_for_service)
            r["id"] = (f"{r['proto']}:{r['local_ip']}:{r['local_port']}>{r['remote_ip'] or '*'}:"
                       f"{r['remote_port'] or '*'}:{r['pid'] or 0}")
        return rows

    def _annotate(self, r: dict, blocked, suspicious: dict[int, str], risky: dict[int, str]) -> dict:
        p = self._proc(r["pid"])
        r["process"] = p.get("name") or ("System" if r["pid"] == 4 else None)
        r["exe"], r["create_time"] = p.get("exe"), p.get("create_time")
        r["protected"], r["cyberhub"] = p.get("protected", False), p.get("cyberhub", False)
        flags: list[str] = []
        what = None
        if r["scope"] == "internet" and r["direction"] in ("outgoing", "incoming"):
            flags += [f for f in p.get("flags", []) if f in CONN_FLAGS]
            if r["direction"] == "outgoing" and r["remote_port"] in suspicious and not p.get("cyberhub"):
                flags.append("suspicious_port")
                what = suspicious[r["remote_port"]]
            if r["direction"] == "incoming" and r["status"] == "ESTABLISHED" and r["local_port"] in risky:
                flags.append("exposed_in_use")
                what = risky[r["local_port"]]
        bid = blocked(r["remote_ip"]) if r.get("remote_ip") and r["scope"] in ("internet", "lan") else None
        if bid:
            flags.append("blocked_target")
        r["blocked_by"] = bid
        flags = list(dict.fromkeys(flags))
        total = min(100, sum(CONN_FLAGS[f][0] for f in flags))
        r["flags"] = flags
        r["reasons"] = [CONN_FLAGS[f][1].format(what=what or "risky services") for f in flags]
        r["risk_score"] = total
        r["risk_level"] = "high" if total >= 60 else "medium" if total >= 30 else "low" if total > 0 else "none"
        return r

    def _annotated(self) -> list[dict]:
        rows = self._snapshot()
        blocked = self._blocked_lookup()
        suspicious = dict(npb.SUSPICIOUS_REMOTE_PORTS)
        suspicious.update(self._extra_ports())
        risky = _risky_ports()
        return [self._annotate(r, blocked, suspicious, risky) for r in rows]

    def _resolve(self, ips: list[str], budget: float = 1.5) -> dict[str, str | None]:
        now = time.monotonic()
        out: dict[str, str | None] = {}
        todo = []
        for ip in dict.fromkeys(ips):
            hit = self._dns_cache.get(ip)
            if hit and now - hit[0] < 3600:
                out[ip] = hit[1]
            elif len(todo) < 40:
                todo.append(ip)
        futs = {self._dns_pool.submit(self.probe.reverse_dns, ip): ip for ip in todo}
        done, _ = cf.wait(futs, timeout=budget)
        for f in done:
            ip = futs[f]
            try:
                name = f.result()
            except Exception:
                name = None
            self._dns_cache[ip] = (time.monotonic(), name)
            out[ip] = name
        if len(self._dns_cache) > 5000:
            self._dns_cache.clear()
        return out

    @staticmethod
    def _counts(rows: list[dict]) -> dict:
        c = {"total": len(rows), "tcp": 0, "udp": 0, "established": 0, "listening": 0, "bound": 0,
             "syn_sent": 0, "time_wait": 0, "incoming": 0, "outgoing": 0, "internet": 0, "lan": 0, "local": 0,
             "flagged": 0, "processes": len({r["pid"] for r in rows if r["pid"]}),
             "remote_hosts": len({r["remote_ip"] for r in rows if r.get("remote_ip") and r["scope"] == "internet"})}
        for r in rows:
            c[r["proto"]] += 1
            st = r["status"]
            if st == "ESTABLISHED":
                c["established"] += 1
            elif st == "LISTEN":
                c["listening"] += 1
            elif st == "BOUND":
                c["bound"] += 1
            elif st == "SYN_SENT":
                c["syn_sent"] += 1
            elif st == "TIME_WAIT":
                c["time_wait"] += 1
            if r["direction"] in ("incoming", "outgoing"):
                c[r["direction"]] += 1
                if r["scope"] in ("internet", "lan", "local"):
                    c[r["scope"]] += 1
            if r.get("risk_level") in ("medium", "high"):
                c["flagged"] += 1
        return c

    def connections(self, search: str | None = None, state: str | None = None, proto: str | None = None,
                    scope: str | None = None, direction: str | None = None, pid: int | None = None,
                    flagged: bool = False, include_listening: bool = False, resolve: bool | None = None,
                    sort: str = "risk", limit: int = 500, offset: int = 0) -> dict:
        rows = self._annotated()
        counts = self._counts(rows)

        def keep(r: dict) -> bool:
            if not include_listening and r["direction"] in ("listening", "bound"):
                return False
            if state and r["status"].lower() != state.lower():
                return False
            if proto and r["proto"] != proto:
                return False
            if scope and r["scope"] != scope:
                return False
            if direction and r["direction"] != direction:
                return False
            if pid is not None and r["pid"] != pid:
                return False
            if flagged and r["risk_level"] not in ("medium", "high"):
                return False
            if search:
                s = search.lower()
                hay = " ".join(str(r.get(k) or "") for k in ("process", "exe", "remote_ip", "local_ip", "service",
                                                              "remote_port", "local_port")).lower()
                if s not in hay:
                    return False
            return True
        items = [r for r in rows if keep(r)]
        keyf = {"risk": lambda r: (-r["risk_score"], (r["process"] or "~").lower(), r["remote_ip"] or ""),
                "process": lambda r: ((r["process"] or "~").lower(), r["remote_ip"] or ""),
                "remote": lambda r: (r["remote_ip"] or "~", r["remote_port"] or 0),
                "port": lambda r: (r["local_port"] or 0,)}[sort]
        items.sort(key=keyf)
        total = len(items)
        page = items[offset:offset + limit]
        if resolve if resolve is not None else self.settings.get("network_resolve_hostnames"):
            names = self._resolve([r["remote_ip"] for r in page if r.get("remote_ip") and r["scope"] == "internet"])
            for r in page:
                r["remote_host"] = names.get(r.get("remote_ip"))
        return {"total": total, "limit": limit, "offset": offset, "counts": counts, "items": page}

    def _proc_groups(self, rows: list[dict]) -> list[dict]:
        groups: dict[Any, dict] = {}
        for r in rows:
            key = (r["pid"], r.get("create_time"))
            g = groups.get(key)
            if g is None:
                g = groups[key] = {"pid": r["pid"], "process": r["process"], "exe": r["exe"],
                                   "create_time": r.get("create_time"), "protected": r.get("protected"),
                                   "cyberhub": r.get("cyberhub"), "connections": 0, "established": 0,
                                   "listening": [], "syn_sent": 0, "internet": 0, "lan": 0, "remote_hosts": set(),
                                   "remote_ports": {}, "risk_score": 0, "flags": set()}
            g["connections"] += 1
            if r["status"] == "ESTABLISHED":
                g["established"] += 1
            if r["status"] == "SYN_SENT":
                g["syn_sent"] += 1
            if r["direction"] == "listening" or (r["direction"] == "bound" and not is_ephemeral(r["local_port"] or 0)):
                g["listening"].append(f"{r['proto']}/{r['local_port']}")
            if r["scope"] == "internet" and r["direction"] in ("incoming", "outgoing"):
                g["internet"] += 1
                g["remote_hosts"].add(r["remote_ip"])
                g["remote_ports"][r["remote_port"]] = g["remote_ports"].get(r["remote_port"], 0) + 1
            elif r["scope"] == "lan":
                g["lan"] += 1
            g["risk_score"] = max(g["risk_score"], r["risk_score"])
            g["flags"].update(f for f in r["flags"] if f != "blocked_target")
        many = int(self.settings.get("network_many_hosts"))
        out = []
        for g in groups.values():
            extra = []
            if not g["cyberhub"] and g["syn_sent"] >= 30:
                extra.append({"code": "scan_like", "severity": "high",
                              "text": f"Trying to open {g['syn_sent']} connections at once - typical of port "
                                      f"scanners and worms spreading"})
            if not g["cyberhub"] and len(g["remote_hosts"]) >= many:
                extra.append({"code": "many_hosts", "severity": "medium",
                              "text": f"Talking to {len(g['remote_hosts'])} different internet addresses"})
            g["behaviour"] = extra
            g["remote_hosts"] = len(g["remote_hosts"])
            g["top_remote_ports"] = sorted(g["remote_ports"].items(), key=lambda kv: -kv[1])[:5]
            del g["remote_ports"]
            g["listening"] = sorted(set(g["listening"]))
            g["flags"] = sorted(g["flags"])
            lvl_score = max(g["risk_score"], 60 if any(e["severity"] == "high" for e in extra) else
                            30 if extra else 0)
            g["risk_level"] = "high" if lvl_score >= 60 else "medium" if lvl_score >= 30 else \
                "low" if lvl_score > 0 else "none"
            out.append(g)
        out.sort(key=lambda g: (-SEVERITIES.index({"none": "info"}.get(g["risk_level"], g["risk_level"])),
                                -g["connections"], (g["process"] or "~").lower()))
        return out

    def by_process(self) -> dict:
        rows = self._annotated()
        return {"counts": self._counts(rows), "items": self._proc_groups(rows)}

    # ================================================================== listening ports
    def _fw_verdict(self, port: int, proto: str, exe: str | None) -> dict:
        if self.firewall is None:
            return {"verdict": "unknown", "rule": None, "scope": None, "reason": "Firewall module not loaded"}
        try:
            if not self.firewall.available():
                return {"verdict": "unknown", "rule": None, "scope": None,
                        "reason": self.firewall.backend.available()[1] or "No supported firewall"}
            return self.firewall.inbound_verdict(port, proto, exe)
        except Exception as e:                                         # never let Part 9 break Part 10
            return {"verdict": "unknown", "rule": None, "scope": None, "reason": getattr(e, "message", str(e))}

    def _listeners(self, rows: list[dict], include_ephemeral: bool = False) -> list[dict]:
        risky = _risky_ports()
        merged: dict[tuple, dict] = {}
        for r in rows:
            if r["direction"] not in ("listening", "bound"):
                continue
            if r["proto"] == "udp" and is_ephemeral(r["local_port"] or 0) and not include_ephemeral:
                continue
            key = (r["proto"], r["local_port"], r["pid"])
            m = merged.get(key)
            if m is None:
                m = merged[key] = {"proto": r["proto"], "port": r["local_port"], "addresses": [], "pid": r["pid"],
                                   "process": r["process"], "exe": r["exe"], "create_time": r.get("create_time"),
                                   "protected": r.get("protected"), "cyberhub": r.get("cyberhub"),
                                   "service": r["service"], "exposure": "local", "proc_flags": set()}
            if r["local_ip"] not in m["addresses"]:
                m["addresses"].append(r["local_ip"])
            sc = npb.ip_scope(r["local_ip"])
            if sc == "unspecified":
                m["exposure"] = "all"
            elif sc != "local" and m["exposure"] == "local":
                m["exposure"] = "network"
            p = self._proc_cache.get(r["pid"]) if r["pid"] else None
            if p:
                m["proc_flags"].update(f for f in p.get("flags", []) if f in ("suspicious_location", "masquerade",
                                                                              "bad_signature"))
        out = []
        for m in merged.values():
            m["proc_flags"] = sorted(m["proc_flags"])
            m["ephemeral"] = is_ephemeral(m["port"] or 0)
            m["risky_service"] = risky.get(m["port"])
            if m["exposure"] == "local":
                m["firewall"] = {"verdict": "not_needed", "rule": None, "scope": None,
                                 "reason": "Only this computer can reach it"}
            else:
                m["firewall"] = self._fw_verdict(m["port"], m["proto"], m["exe"])
            sev, why = self._listener_severity(m)
            m["severity"], m["reasons"] = sev, why
            out.append(m)
        out.sort(key=lambda m: (-SEVERITIES.index(m["severity"]), m["proto"], m["port"] or 0))
        return out

    @staticmethod
    def _listener_severity(m: dict) -> tuple[str, list[str]]:
        if m["exposure"] == "local" or m.get("cyberhub"):
            return "info", (["Only this computer can connect"] if m["exposure"] == "local" else
                            ["Cyber Hub engine"])
        v = m["firewall"]["verdict"]
        reachable = v in ("open", "allowed")
        public = m["firewall"].get("profile") == "public"
        sev, why = "info", []
        if m["proc_flags"]:
            sev = "high"
            why.append("A program from a Temp / Downloads folder, or with a fake system name, is accepting "
                       "network connections")
        if m["risky_service"]:
            if reachable:
                s = "high" if public or m["firewall"].get("scope") == "any" and v == "open" else "medium"
                sev = _sev_max(sev, s)
                why.append(f"{m['risky_service']} is open and the firewall lets other computers in "
                           f"({m['firewall']['reason']})")
            elif v == "blocked":
                sev = _sev_max(sev, "low")
                why.append(f"{m['risky_service']} is listening - only the firewall keeps it closed "
                           f"({m['firewall']['reason']})")
            else:
                sev = _sev_max(sev, "medium")
                why.append(f"{m['risky_service']} is listening and the firewall state is unknown")
        elif reachable:
            why.append(f"Reachable from other devices ({m['firewall']['reason']})")
        else:
            why.append(m["firewall"].get("reason") or "Not reachable from other devices")
        return sev, why

    def listening(self, exposed_only: bool = False, include_ephemeral: bool = False) -> dict:
        rows = self._annotated()
        items = self._listeners(rows, include_ephemeral)
        if exposed_only:
            items = [m for m in items if m["exposure"] != "local"]
        counts = {"total": len(items), "exposed": sum(1 for m in items if m["exposure"] != "local"),
                  "reachable": sum(1 for m in items if m["firewall"]["verdict"] in ("open", "allowed")),
                  "risky": sum(1 for m in items if m["severity"] in ("medium", "high", "critical"))}
        return {"counts": counts, "items": items}

    # ================================================================== Wi-Fi
    @staticmethod
    def rate_wifi(auth: str, cipher: str | None) -> dict:
        rating, sev, text = WIFI_RATING.get(auth, WIFI_RATING["unknown"])
        if auth in ("wpa2", "wpa2/wpa3", "wpa2-enterprise") and cipher == "tkip":
            rating, sev, text = "weak", "medium", ("WPA2 with the old TKIP cipher - switch the router to AES "
                                                   "(CCMP) or WPA3")
        score = {"excellent": 100, "good": 85, "fair": 60, "weak": 35, "unknown": 50, "open": 10,
                 "insecure": 5}[rating]
        return {"rating": rating, "severity": sev, "text": text, "score": score}

    def wifi(self, refresh: bool = False) -> dict:
        ts, data = self._wifi_cache
        if data is not None and not refresh and time.monotonic() - ts < self.WIFI_TTL:
            return data
        w = self.probe.wifi
        ok, why = w.available()
        out: dict[str, Any] = {"available": ok, "backend": {"name": w.name, "label": w.label}, "error": why,
                               "interfaces": [], "current": None, "nearby": [], "nearby_count": 0, "saved": [],
                               "findings": []}
        if not ok:
            self._wifi_cache = (time.monotonic(), out)
            return out
        try:
            ifs = w.interfaces()
            nearby = w.nearby()
            saved = w.profiles()
        except Exception as e:                                         # pragma: no cover
            ifs, nearby, saved = [], [], []
            out["error"] = f"Wi-Fi query failed: {e}"
        out["error"] = out["error"] or getattr(w, "last_error", None)
        for i in ifs:
            if i.get("connected"):
                i["assessment"] = self.rate_wifi(i["auth"], i.get("cipher"))
        out["interfaces"] = ifs
        cur = next((i for i in ifs if i.get("connected")), None)
        out["current"] = cur
        findings: list[dict] = []
        if cur:
            a = cur["assessment"]
            if SEVERITIES.index(a["severity"]) >= 1:
                findings.append(_finding(f"wifi:current:{cur.get('ssid')}", a["severity"], "wifi",
                                         f"Wi-Fi '{cur.get('ssid') or 'hidden'}' is {a['rating']}", a["text"]))
            # evil twin: same name nearby but weaker security than what we joined
            mine = AUTH_STRENGTH.get(cur["auth"], 3)
            for n in nearby:
                if (n["ssid"] and n["ssid"] == cur.get("ssid") and n.get("bssid") != cur.get("bssid")
                        and AUTH_STRENGTH.get(n["auth"], 3) < mine and AUTH_STRENGTH.get(n["auth"], 3) <= 1):
                    findings.append(_finding(
                        f"wifi:twin:{n.get('bssid')}", "high", "wifi",
                        f"Possible fake copy of '{n['ssid']}' nearby",
                        f"Another access point ({n.get('bssid')}) uses the same name with "
                        f"{n['auth'].upper()} security instead of {cur['auth'].upper()}. This is how 'evil twin' "
                        f"attacks steal logins - never type passwords on a page it shows; forget and re-add the "
                        f"network if your PC switches to it.", data={"bssid": n.get("bssid")}))
        for s in saved:
            if s.get("auth") in ("open", "owe") and s.get("auto_connect"):
                findings.append(_finding(
                    f"wifi:saved:{s['name']}", "medium", "wifi", f"Auto-joins open network '{s['name']}'",
                    "Your PC connects by itself to any network with this name - an attacker can create one "
                    "with the same name anywhere. Turn off 'Connect automatically' or forget it.",
                    data={"profile": s["name"]}))
            elif s.get("auth") in ("wep", "wpa"):
                findings.append(_finding(
                    f"wifi:saved:{s['name']}", "low", "wifi", f"Saved network '{s['name']}' uses {s['auth'].upper()}",
                    "This saved network uses outdated security that can be cracked.", data={"profile": s["name"]}))
        # nearby: one row per network name (strongest signal), hidden ones grouped
        best: dict[str, dict] = {}
        for n in nearby:
            k = n["ssid"] or f"(hidden) {n.get('bssid')}"
            n["assessment"] = self.rate_wifi(n["auth"], n.get("cipher"))
            n["connected"] = bool(cur and n.get("bssid") and n.get("bssid") == cur.get("bssid"))
            if k not in best or (n.get("signal") or 0) > (best[k].get("signal") or 0):
                best[k] = dict(n, access_points=best.get(k, {}).get("access_points", 0))
            best[k]["access_points"] = best[k].get("access_points", 0) + 1
        out["nearby"] = sorted(best.values(), key=lambda n: -(n.get("signal") or 0))
        out["nearby_count"] = len(out["nearby"])
        out["nearby_open"] = sum(1 for n in out["nearby"] if n["auth"] in ("open", "wep"))
        out["saved"] = [dict(s, assessment=self.rate_wifi(s.get("auth") or "unknown", s.get("cipher")))
                        for s in saved]
        out["findings"] = findings
        self._wifi_cache = (time.monotonic(), out)
        self._record_wifi(cur)
        return out

    def _record_wifi(self, cur: dict | None) -> None:
        last = self._state_get("wifi_last")
        key = f"{cur.get('ssid')}|{cur.get('bssid')}" if cur else None
        if key == (last or {}).get("key"):
            if cur:
                self.db.execute("UPDATE wifi_connections SET last_seen=? WHERE id=?", (_iso(), last["id"]))
            return
        if not cur:
            self._state_set("wifi_last", {"key": None, "id": None})
            return
        a = cur.get("assessment") or self.rate_wifi(cur["auth"], cur.get("cipher"))
        rid = self.db.execute(
            "INSERT INTO wifi_connections(ssid, bssid, auth, cipher, rating, signal, channel, band, interface) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (cur.get("ssid"), cur.get("bssid"), cur["auth"], cur.get("cipher"), a["rating"], cur.get("signal"),
             cur.get("channel"), cur.get("band"), cur.get("interface"))).lastrowid
        self._state_set("wifi_last", {"key": key, "id": rid})
        self.db.execute("DELETE FROM wifi_connections WHERE id NOT IN (SELECT id FROM wifi_connections "
                        "ORDER BY id DESC LIMIT 1000)")
        if a["severity"] in ("high", "critical") and self.settings.get("wifi_alert_insecure"):
            self._event("insecure_wifi", a["severity"], f"Connected to {a['rating']} Wi-Fi '{cur.get('ssid')}'",
                        a["text"], key=f"wifi:{cur.get('ssid')}")

    def wifi_history(self, limit: int = 100) -> list[dict]:
        return self.db.fetchall("SELECT * FROM wifi_connections ORDER BY id DESC LIMIT ?", (limit,))

    # ================================================================== vendors (OUI)
    def _load_oui(self) -> dict[str, str]:
        if self._oui is None:
            self._oui = {r["prefix"]: r["vendor"] for r in self.db.fetchall("SELECT prefix, vendor FROM oui_vendors")}
        return self._oui

    def vendor(self, mac: str | None) -> str | None:
        if not mac:
            return None
        if npb.mac_is_randomized(mac):
            return "Private (randomized) address"
        p = mac.replace(":", "")[:6]
        return self._load_oui().get(p) or npb.BUILTIN_OUI.get(p)

    def oui_status(self) -> dict:
        n = self.db.fetchone("SELECT COUNT(*) AS n FROM oui_vendors")["n"]
        return {"imported": n, "builtin": len(npb.BUILTIN_OUI), "source": self._state_get("oui_source"),
                "updated_at": self._state_get("oui_updated_at"), "default_url": OUI_URL}

    def import_oui(self, text: str, source: str, username: str) -> dict:
        data = npb.parse_oui_text(text)
        if len(data) < 1:
            raise NetworkError(422, "No MAC vendor entries found (expected IEEE oui.csv / oui.txt or Wireshark "
                                    "manuf format)")
        with self.db.tx() as c:
            c.execute("DELETE FROM oui_vendors")
            c.executemany("INSERT INTO oui_vendors(prefix, vendor) VALUES (?,?)", list(data.items()))
        self._oui = None
        self._state_set("oui_source", source[:300])
        self._state_set("oui_updated_at", _iso())
        self._refresh_vendors()
        self.activity.record("network", "MAC vendor list updated", f"{len(data):,} vendors from {source[:120]} "
                                                                   f"(by {username})", source="network")
        return self.oui_status()

    def update_oui(self, username: str, url: str = OUI_URL) -> dict:
        if not url.lower().startswith("https://"):
            raise NetworkError(400, "Only https:// download links are accepted")
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "CyberHub/0.10"}),
                                        timeout=60) as r:
                raw = r.read(OUI_MAX_BYTES + 1)
        except Exception as e:
            raise NetworkError(502, f"Download failed: {e}")
        if len(raw) > OUI_MAX_BYTES:
            raise NetworkError(413, "The vendor list is larger than 16 MB")
        return self.import_oui(raw.decode("utf-8", errors="replace"), url, username)

    def _refresh_vendors(self) -> None:
        for d in self.db.fetchall("SELECT id, mac FROM lan_devices"):
            self.db.execute("UPDATE lan_devices SET vendor=? WHERE id=?", (self.vendor(d["mac"]), d["id"]))

    # ================================================================== LAN
    def _current_iface(self) -> tuple[dict | None, dict | None]:
        ifaces = self.probe.interfaces()
        gws = self.probe.gateways()
        for g in gws:
            for i in ifaces:
                if g.get("interface") and i["name"] == g["interface"]:
                    return i, g
            for i in ifaces:                                   # interface name differs: match by subnet
                try:
                    if ipaddress.ip_address(g["ip"]) in ipaddress.ip_network(i["network"]):
                        return i, g
                except ValueError:
                    continue
        real = [i for i in ifaces if not i["virtual"] and npb.is_scannable_network(ipaddress.ip_network(i["network"]))]
        return (real[0] if real else None), None

    def current_network(self, neighbours: list[dict] | None = None) -> dict | None:
        iface, gw = self._current_iface()
        if iface is None:
            return None
        wifi_cur = None
        try:
            wifi_cur = next((i for i in self.probe.wifi.interfaces() if i.get("connected")
                             and (not i.get("interface") or i["interface"] == iface["name"])), None) \
                if self.probe.wifi.available()[0] else None
        except Exception:                                              # pragma: no cover
            wifi_cur = None
        ssid = wifi_cur.get("ssid") if wifi_cur else None
        kind = "wifi" if wifi_cur else "wired"
        key = hashlib.sha1(f"{ssid or 'wired'}|{iface['network']}".encode()).hexdigest()[:16]
        neigh = neighbours if neighbours is not None else self.probe.neighbours()
        gw_mac = next((n["mac"] for n in neigh if gw and n["ip"] == gw["ip"]), None)
        row = self.db.fetchone("SELECT * FROM lan_networks WHERE key=?", (key,))
        now = _iso()
        if row is None:
            nid = self.db.execute(
                "INSERT INTO lan_networks(key, name, kind, ssid, subnet, gateway_ip, gateway_mac, interface, "
                "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (key, ssid or f"Wired network {iface['network']}", kind, ssid, iface["network"],
                 gw["ip"] if gw else None, gw_mac, iface["name"], now, now)).lastrowid
            row = self.db.fetchone("SELECT * FROM lan_networks WHERE id=?", (nid,))
        else:
            self.db.execute("UPDATE lan_networks SET last_seen=?, interface=?, gateway_ip=COALESCE(?, gateway_ip) "
                            "WHERE id=?", (now, iface["name"], gw["ip"] if gw else None, row["id"]))
            if row["gateway_mac"] is None and gw_mac:
                self.db.execute("UPDATE lan_networks SET gateway_mac=? WHERE id=?", (gw_mac, row["id"]))
            row = self.db.fetchone("SELECT * FROM lan_networks WHERE id=?", (row["id"],))
        out = self._network_public(row)
        out.update({"interface": iface, "gateway": {"ip": gw["ip"] if gw else None, "mac": gw_mac,
                                                    "vendor": self.vendor(gw_mac)},
                    "scannable": npb.is_scannable_network(ipaddress.ip_network(iface["network"]))})
        return out

    @staticmethod
    def _network_public(row: dict) -> dict:
        r = dict(row)
        r["home"] = bool(r["home"])
        return r

    def networks(self) -> list[dict]:
        rows = self.db.fetchall(
            "SELECT n.*, (SELECT COUNT(*) FROM lan_devices d WHERE d.network_id=n.id) AS devices "
            "FROM lan_networks n ORDER BY n.last_seen DESC")
        return [self._network_public(r) for r in rows]

    def _device_public(self, d: dict, online_macs: set[str], gw_ip: str | None) -> dict:
        d = dict(d)
        d["open_ports"] = json.loads(d["open_ports"]) if d.get("open_ports") else []
        d["trusted"], d["randomized_mac"] = bool(d["trusted"]), bool(d["randomized_mac"])
        d["online"] = d["mac"] in online_macs
        d["is_gateway"] = bool(gw_ip and d["ip"] == gw_ip)
        d["services"] = [{"port": p, "service": npb.service_name(p)} for p in d["open_ports"]]
        d["flags"] = self._device_flags(d)
        d["severity"] = max((f["severity"] for f in d["flags"]), key=SEVERITIES.index, default="info")
        return d

    @staticmethod
    def _device_flags(d: dict) -> list[dict]:
        flags = []
        for port, (sev, text) in DEVICE_PORT_FLAGS.items():
            if port in d["open_ports"]:
                flags.append({"code": f"port_{port}", "severity": sev, "text": text, "port": port})
        if d.get("is_gateway") and 80 in d["open_ports"] and 443 not in d["open_ports"]:
            flags.append({"code": "router_http", "severity": "low", "port": 80,
                          "text": "The router's admin page only uses unencrypted HTTP - use a strong admin "
                                  "password and never open it on public Wi-Fi"})
        return flags

    @staticmethod
    def guess_type(ports: list[int], vendor: str | None, nb_name: str | None, is_gateway: bool,
                   randomized: bool) -> str:
        v = (vendor or "").lower()
        p = set(ports)
        if is_gateway:
            return "router"
        if "virtual machine" in v:
            return "virtual machine"
        if p & {9100, 631, 515}:
            return "printer"
        if 554 in p:
            return "camera / video recorder"
        if 62078 in p:
            return "iPhone / iPad"
        if p & {8008, 8009}:
            return "Chromecast / smart TV"
        if 5000 in p and p & {139, 445}:
            return "NAS storage"
        if p & {3389, 445, 139} or nb_name:
            return "Windows PC"
        if "raspberry" in v:
            return "Raspberry Pi"
        if 22 in p:
            return "Linux / network device"
        if 1883 in p:
            return "smart-home hub"
        if randomized:
            return "phone / laptop (private address)"
        return "unknown"

    def _upsert_devices(self, network: dict, seen: list[dict], source: str) -> list[dict]:
        """seen = [{ip, mac, hostname?, nb_name?, open_ports?}] -> new device rows."""
        new = []
        now = _iso()
        for s in seen:
            mac = s["mac"]
            row = self.db.fetchone("SELECT * FROM lan_devices WHERE network_id=? AND mac=?", (network["id"], mac))
            is_gw = bool(network.get("gateway_ip") and s["ip"] == network["gateway_ip"])
            ports = s.get("open_ports")
            if row is None:
                vendor = self.vendor(mac)
                did = self.db.execute(
                    "INSERT INTO lan_devices(network_id, mac, ip, hostname, nb_name, vendor, device_type, open_ports, "
                    "randomized_mac, first_seen, last_seen, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (network["id"], mac, s["ip"], s.get("hostname"), s.get("nb_name"), vendor,
                     self.guess_type(ports or [], vendor, s.get("nb_name"), is_gw, npb.mac_is_randomized(mac)),
                     json.dumps(ports) if ports is not None else None, int(npb.mac_is_randomized(mac)), now, now,
                     source)).lastrowid
                new.append(self.db.fetchone("SELECT * FROM lan_devices WHERE id=?", (did,)))
            else:
                ports = ports if ports is not None else (json.loads(row["open_ports"]) if row["open_ports"] else None)
                host = s.get("hostname") or row["hostname"]
                nb = s.get("nb_name") or row["nb_name"]
                vendor = self.vendor(mac)
                self.db.execute(
                    "UPDATE lan_devices SET ip=?, hostname=?, nb_name=?, vendor=?, device_type=?, open_ports=?, "
                    "last_seen=? WHERE id=?",
                    (s["ip"], host, nb, vendor,
                     self.guess_type(ports or [], vendor, nb, is_gw, npb.mac_is_randomized(mac)),
                     json.dumps(ports) if ports is not None else None, now, row["id"]))
        if new:
            # Quiet the first time: the first passive look, and the first full scan of a network (which finds
            # the devices the ARP table had not seen yet) build the baseline instead of raising alerts.
            first = network.get("baseline_at") is None or (source == "scan" and not network.get("last_scan"))
            if not first and self.settings.get("lan_alert_new_devices"):
                sev = "medium" if network.get("home") else "low"
                for d in new:
                    label = d["nb_name"] or d["hostname"] or d["vendor"] or "Unknown device"
                    self._event("new_device", sev, f"New device on {network['name']}: {label}",
                                f"{d['ip']} · {d['mac']}" + (" · private (randomized) address"
                                                              if d["randomized_mac"] else ""),
                                key=f"dev:{d['id']}", data={"device_id": d["id"], "network_id": network["id"]})
        if network.get("baseline_at") is None:
            self.db.execute("UPDATE lan_networks SET baseline_at=? WHERE id=?", (now, network["id"]))
            network["baseline_at"] = now
        return new

    def _check_gateway(self, network: dict, neigh: list[dict]) -> None:
        """ARP-spoofing signals: the router's hardware address changed, or another IP claims it."""
        if not self.settings.get("lan_arp_watch") or not network.get("gateway_ip"):
            return
        gw_ip = network["gateway_ip"]
        cur = next((n["mac"] for n in neigh if n["ip"] == gw_ip), None)
        if not cur:
            return
        known = network.get("gateway_mac")
        if known and cur != known:
            if network.get("gateway_alert_mac") != cur:
                self.db.execute("UPDATE lan_networks SET gateway_alert_mac=?, gateway_alert_at=? WHERE id=?",
                                (cur, _iso(), network["id"]))
                network["gateway_alert_mac"] = cur
                self._event("gateway_changed", "high", f"Router address changed on {network['name']}",
                            f"The router {gw_ip} used to be {known} and now answers as {cur}. If you did not "
                            f"replace the router, another device may be intercepting your traffic (ARP spoofing).",
                            key=f"gw:{network['id']}", data={"network_id": network["id"], "old": known, "new": cur})
        elif known and cur == known and network.get("gateway_alert_mac"):
            self.db.execute("UPDATE lan_networks SET gateway_alert_mac=NULL, gateway_alert_at=NULL WHERE id=?",
                            (network["id"],))
            network["gateway_alert_mac"] = None
            self._event("gateway_restored", "info", f"Router address back to normal on {network['name']}",
                        f"{gw_ip} answers as {known} again", key=f"gw:{network['id']}")
        dup = sorted({n["ip"] for n in neigh if n["mac"] == cur and n["ip"] != gw_ip})
        if dup and self._once(f"gwdup:{network['id']}:{cur}:{','.join(dup)}", 6):
            self._event("gateway_conflict", "medium", f"Another device shares the router's address on "
                                                      f"{network['name']}",
                        f"{', '.join(dup[:5])} use the router's hardware address {cur}. Some mesh / repeater "
                        f"setups do this; otherwise it is a sign of ARP spoofing.", key=f"gwdup:{network['id']}",
                        data={"network_id": network["id"], "ips": dup})

    def lan(self, network_id: int | None = None) -> dict:
        neigh = self.probe.neighbours()
        cur = self.current_network(neigh)
        if network_id is not None:
            row = self.db.fetchone("SELECT * FROM lan_networks WHERE id=?", (network_id,))
            if not row:
                raise NetworkError(404, "Network not found")
            net = self._network_public(row)
            live = cur is not None and cur["id"] == network_id
        else:
            net, live = cur, cur is not None
        if net is None:
            return {"network": None, "devices": [], "counts": {"total": 0, "online": 0}, "scan": self.scan_status(),
                    "networks": self.networks()}
        online: set[str] = set()
        if live:
            in_net = [n for n in neigh if _in_subnet(n["ip"], net["subnet"])]
            online = {n["mac"] for n in in_net}
            with self._lock:
                self._upsert_devices(net, [{"ip": n["ip"], "mac": n["mac"]} for n in in_net], "passive")
                self._check_gateway(net, neigh)
            net = dict(cur, **self._network_public(self.db.fetchone("SELECT * FROM lan_networks WHERE id=?",
                                                                     (net["id"],))))
        rows = self.db.fetchall("SELECT * FROM lan_devices WHERE network_id=? ORDER BY last_seen DESC", (net["id"],))
        devices = [self._device_public(d, online, net.get("gateway_ip")) for d in rows]
        if live and cur and cur.get("interface"):
            me = cur["interface"]
            devices.insert(0, {"id": None, "this_pc": True, "ip": me["ip"], "mac": me.get("mac"),
                               "hostname": socket.gethostname(), "nb_name": None, "vendor": self.vendor(me.get("mac")),
                               "device_type": "this computer", "open_ports": [], "services": [], "online": True,
                               "trusted": True, "label": "This PC", "flags": [], "severity": "info",
                               "is_gateway": False, "randomized_mac": bool(me.get("mac") and
                                                                           npb.mac_is_randomized(me["mac"]))})
        day_ago = _iso(datetime.now(timezone.utc) - timedelta(days=1))
        counts = {"total": len(devices), "online": sum(1 for d in devices if d["online"]),
                  "new_24h": sum(1 for d in devices if d.get("first_seen") and d["first_seen"] >= day_ago),
                  "untrusted": sum(1 for d in devices if not d["trusted"]),
                  "risky": sum(1 for d in devices if d["severity"] in ("medium", "high", "critical"))}
        return {"network": net, "live": live, "devices": devices, "counts": counts, "scan": self.scan_status(),
                "networks": self.networks()}

    def get_device(self, device_id: int) -> dict:
        d = self.db.fetchone("SELECT * FROM lan_devices WHERE id=?", (device_id,))
        if not d:
            raise NetworkError(404, "Device not found")
        n = self.db.fetchone("SELECT gateway_ip FROM lan_networks WHERE id=?", (d["network_id"],))
        return self._device_public(d, set(), n["gateway_ip"] if n else None)

    def update_device(self, device_id: int, label: str | None, trusted: bool | None, notes: str | None) -> dict:
        self.get_device(device_id)
        if label is not None:
            self.db.execute("UPDATE lan_devices SET label=? WHERE id=?", (label.strip() or None, device_id))
        if trusted is not None:
            self.db.execute("UPDATE lan_devices SET trusted=? WHERE id=?", (int(trusted), device_id))
        if notes is not None:
            self.db.execute("UPDATE lan_devices SET notes=? WHERE id=?", (notes.strip() or None, device_id))
        self.invalidate()
        return self.get_device(device_id)

    def forget_device(self, device_id: int) -> bool:
        self.get_device(device_id)
        self.db.execute("DELETE FROM lan_devices WHERE id=?", (device_id,))
        self.invalidate()
        return True

    def set_home(self, network_id: int, home: bool, name: str | None = None) -> dict:
        if not self.db.fetchone("SELECT id FROM lan_networks WHERE id=?", (network_id,)):
            raise NetworkError(404, "Network not found")
        self.db.execute("UPDATE lan_networks SET home=?, name=COALESCE(?, name) WHERE id=?",
                        (int(home), (name or "").strip() or None, network_id))
        self.invalidate()
        return self._network_public(self.db.fetchone("SELECT * FROM lan_networks WHERE id=?", (network_id,)))

    def accept_gateway(self, network_id: int, username: str) -> dict:
        n = self.db.fetchone("SELECT * FROM lan_networks WHERE id=?", (network_id,))
        if not n:
            raise NetworkError(404, "Network not found")
        if not n["gateway_alert_mac"]:
            raise NetworkError(409, "There is no router address change to accept")
        self.db.execute("UPDATE lan_networks SET gateway_mac=gateway_alert_mac, gateway_alert_mac=NULL, "
                        "gateway_alert_at=NULL WHERE id=?", (network_id,))
        self._event("gateway_accepted", "info", f"New router address accepted on {n['name']}",
                    f"{n['gateway_mac']} -> {n['gateway_alert_mac']}", key=f"gw:{network_id}", username=username)
        self.invalidate()
        return self._network_public(self.db.fetchone("SELECT * FROM lan_networks WHERE id=?", (network_id,)))

    # ------------------------------------------------------------------ LAN scan job
    def scan_status(self) -> dict:
        with self._scan_lock:
            return dict(self._scan)

    def start_scan(self, username: str, ports: bool = True) -> dict:
        net = self.current_network()
        if net is None:
            raise NetworkError(409, "Not connected to a network")
        if not net["scannable"]:
            raise NetworkError(400, f"{net['subnet']} is not a private home / office network - Cyber Hub only "
                                    f"scans private networks you are connected to")
        with self._scan_lock:
            if self._scan.get("state") == "running":
                raise NetworkError(409, "A network scan is already running")
            subnet, hosts = npb.scan_hosts(net["interface"]["ip"], ipaddress.ip_network(net["subnet"]))
            self._scan_cancel.clear()
            self._scan = {"state": "running", "phase": "discover", "percent": 0, "network_id": net["id"],
                          "network": net["name"], "subnet": str(subnet), "hosts": len(hosts), "found": 0,
                          "new": 0, "started_at": _iso(), "finished_at": None, "started_by": username,
                          "error": None}
            self._scan_thread = threading.Thread(target=self._run_scan, args=(net, hosts, ports, username),
                                                 name="ch-lan-scan", daemon=True)
            self._scan_thread.start()
            return dict(self._scan)

    def cancel_scan(self) -> dict:
        with self._scan_lock:
            if self._scan.get("state") != "running":
                raise NetworkError(409, "No network scan is running")
        self._scan_cancel.set()
        return self.scan_status()

    def _scan_set(self, **kw) -> None:
        with self._scan_lock:
            self._scan.update(kw)

    def _run_scan(self, net: dict, hosts: list[str], ports: bool, username: str) -> None:
        try:
            self.probe.nudge(hosts)
            for _ in range(15):                               # ~1.5 s for ARP replies
                if self._scan_cancel.wait(0.1):
                    break
            self.probe.refresh_neighbours()
            neigh = self.probe.neighbours()
            alive = {n["ip"]: n["mac"] for n in neigh if _in_subnet(n["ip"], net["subnet"])}
            self._scan_set(phase="identify", percent=30, found=len(alive))
            results: dict[str, dict] = {ip: {"ip": ip, "mac": mac} for ip, mac in alive.items()}
            done = 0

            def probe_host(ip: str) -> dict:
                out: dict[str, Any] = {}
                if self._scan_cancel.is_set():
                    return out
                if ports:
                    with cf.ThreadPoolExecutor(max_workers=10) as ex:
                        st = dict(zip(npb.LAN_PORTS, ex.map(lambda p: self.probe.tcp_probe(ip, p), npb.LAN_PORTS)))
                    out["open_ports"] = sorted(p for p, s in st.items() if s == "open")
                nb = self.probe.nbns_name(ip)
                if nb and nb.get("name"):
                    out["nb_name"] = nb["name"]
                h = self.probe.reverse_dns(ip)
                if h:
                    out["hostname"] = h
                return out
            with cf.ThreadPoolExecutor(max_workers=16, thread_name_prefix="ch-lan") as ex:
                futs = {ex.submit(probe_host, ip): ip for ip in results}
                for f in cf.as_completed(futs):
                    try:
                        results[futs[f]].update(f.result())
                    except Exception as e:                    # pragma: no cover
                        log.debug("LAN probe of %s failed: %s", futs[f], e)
                    done += 1
                    self._scan_set(percent=30 + int(65 * done / max(1, len(results))))
            if self._scan_cancel.is_set():
                self._scan_set(state="cancelled", phase="cancelled", finished_at=_iso())
                return
            with self._lock:
                fresh = self._network_public(self.db.fetchone("SELECT * FROM lan_networks WHERE id=?", (net["id"],)))
                new = self._upsert_devices(fresh, list(results.values()), "scan")
                self._check_gateway(fresh, neigh)
                self.db.execute("UPDATE lan_networks SET last_scan=? WHERE id=?", (_iso(), net["id"]))
            self.invalidate()
            self._event("scan_done", "info", f"Network scan of {net['name']} finished",
                        f"{len(results)} devices ({len(new)} new) in {self._scan.get('subnet')}", username=username,
                        data={"network_id": net["id"], "devices": len(results), "new": len(new)})
            self._scan_set(state="done", phase="done", percent=100, found=len(results), new=len(new),
                           finished_at=_iso())
        except Exception as e:
            log.warning("LAN scan failed: %s", e)
            self._scan_set(state="failed", phase="failed", error=str(e)[:300], finished_at=_iso())

    # ================================================================== analysis
    def analyze(self, refresh: bool = False) -> dict:
        ts, data = self._analyze_cache
        if data is not None and not refresh and time.monotonic() - ts < self.ANALYZE_TTL:
            return data
        findings: list[dict] = []
        try:
            rows = self._annotated()
        except NetworkError:
            rows = []
        # connections
        for r in rows:
            if r["risk_level"] in ("medium", "high") and r["scope"] in ("internet", "lan"):
                sev = "high" if r["risk_level"] == "high" else "medium"
                fix = {"action": "block_remote_ip", "ip": r["remote_ip"]} if r["scope"] == "internet" else None
                findings.append(_finding(
                    f"conn:{r['exe'] or r['process']}:{r['remote_ip']}:{r['remote_port']}", sev, "connection",
                    f"{r['process'] or 'Unknown program'} -> {r['remote_ip']}:{r['remote_port']}",
                    "; ".join(x for x in r["reasons"] if x), fix=fix,
                    fix_label="Block this address" if fix else None,
                    data={"pid": r["pid"], "create_time": r.get("create_time"), "exe": r["exe"],
                          "remote_ip": r["remote_ip"], "remote_port": r["remote_port"], "flags": r["flags"]}))
        for g in self._proc_groups(rows):
            for b in g["behaviour"]:
                fix = ({"action": "block_program", "pid": g["pid"], "create_time": g["create_time"]}
                       if g["exe"] and not g["protected"] else None)
                findings.append(_finding(f"proc:{b['code']}:{g['exe'] or g['process']}", b["severity"], "behaviour",
                                         f"{g['process'] or 'Unknown program'}: {b['code'].replace('_', ' ')}",
                                         b["text"], fix=fix, fix_label="Block this program's network" if fix else None,
                                         data={"pid": g["pid"], "exe": g["exe"]}))
        # listening ports
        for m in self._listeners(rows):
            if SEVERITIES.index(m["severity"]) >= 1:
                fix = {"action": "block_port", "port": m["port"], "protocol": m["proto"]}
                findings.append(_finding(
                    f"listen:{m['proto']}:{m['port']}:{m['exe'] or m['process']}", m["severity"], "listening",
                    f"{m['proto'].upper()} {m['port']} open ({m['service'] or m['process'] or 'unknown'})",
                    "; ".join(m["reasons"]), fix=fix, fix_label=f"Block incoming {m['proto'].upper()} {m['port']}",
                    data={"pid": m["pid"], "exe": m["exe"], "port": m["port"], "proto": m["proto"],
                          "firewall": m["firewall"]["verdict"]}))
        # Wi-Fi
        try:
            findings += self.wifi()["findings"]
        except Exception as e:                                         # pragma: no cover
            log.debug("Wi-Fi analysis failed: %s", e)
        # LAN
        try:
            cur = self.current_network()
        except Exception:                                              # pragma: no cover
            cur = None
        if cur:
            if cur.get("gateway_alert_mac"):
                findings.append(_finding(
                    f"lan:gateway:{cur['id']}", "high", "lan", "Router hardware address changed",
                    f"{cur['gateway_ip']} was {cur['gateway_mac']} and is now {cur['gateway_alert_mac']}. If you "
                    f"did not change the router, disconnect and investigate (possible ARP spoofing).",
                    fix={"action": "accept_gateway", "network_id": cur["id"]}, fix_label="It's my new router",
                    admin=True, data={"network_id": cur["id"]}))
            for d in self.db.fetchall("SELECT * FROM lan_devices WHERE network_id=? AND trusted=0", (cur["id"],)):
                pub = self._device_public(d, set(), cur.get("gateway_ip"))
                for f in pub["flags"]:
                    if f["severity"] in ("medium", "high"):
                        findings.append(_finding(
                            f"lan:dev:{d['id']}:{f['code']}", f["severity"], "lan",
                            f"{pub['label'] or pub['nb_name'] or pub['hostname'] or pub['vendor'] or pub['ip']}: "
                            f"{npb.service_name(f['port']) or f['code']}", f["text"],
                            data={"device_id": d["id"], "ip": d["ip"], "port": f["port"]}))
        dedup: dict[str, dict] = {}
        for f in findings:
            dedup.setdefault(f["id"], f)
        findings = sorted(dedup.values(), key=lambda f: (-SEVERITIES.index(f["severity"]), f["category"]))
        counts = {s: 0 for s in SEVERITIES}
        for f in findings:
            counts[f["severity"]] += 1
        penalty = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)
        score = max(0, 100 - penalty)
        grade = ("Protected" if score >= 90 else "Good" if score >= 70 else "Needs attention" if score >= 50
                 else "At risk")
        out = {"score": score, "grade": grade, "counts": counts, "findings": findings, "checked_at": _iso()}
        self._analyze_cache = (time.monotonic(), out)
        return out

    def fix(self, finding_id: str, username: str, is_admin: bool) -> dict:
        f = next((x for x in self.analyze(refresh=True)["findings"] if x["id"] == finding_id), None)
        if f is None:
            raise NetworkError(404, "That finding is gone - refresh the list")
        fx = f.get("fix")
        if not fx:
            raise NetworkError(400, "This finding has no one-click fix")
        if f.get("fix_requires_admin") and not is_admin:
            raise NetworkError(403, "Administrator rights required for this fix")
        from .firewall import FirewallError
        act = fx["action"]
        try:
            if act == "accept_gateway":
                result = self.accept_gateway(fx["network_id"], username)
            elif self.firewall is None:
                raise NetworkError(501, "The firewall module is not available")
            elif act == "block_remote_ip":
                result = self.firewall.block_ip([fx["ip"]], username, "both", None,
                                                f"Network monitor: {f['title']}")
            elif act == "block_port":
                result = self.firewall.block_port(str(fx["port"]), username, fx["protocol"], "in", None,
                                                  f"Network monitor: {f['title']}")
            elif act == "block_program":
                result = self.firewall.block_process(fx["pid"], username, fx.get("create_time"), "both", None,
                                                     f"Network monitor: {f['title']}")
            else:                                                      # pragma: no cover
                raise NetworkError(400, f"Unknown fix '{act}'")
        except FirewallError as e:
            raise NetworkError(e.status, e.message)
        self.invalidate()
        self._event("fix_applied", "info", f"Fixed: {f['title']}", f.get("fix_label"), key=f["id"],
                    username=username)
        return {"finding": f, "result": result}

    # ================================================================== watch
    def watch_once(self) -> dict:
        with self._lock:
            out = {"new_listeners": 0, "suspicious": 0, "devices_new": 0, "sampled": False}
            rows = self._annotated()
            c = self._counts(rows)
            self.db.execute(
                "INSERT INTO network_samples(established, listening, internet, lan, local, udp, syn_sent, processes, "
                "remote_hosts, flagged) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (c["established"], c["listening"], c["internet"], c["lan"], c["local"], c["udp"], c["syn_sent"],
                 c["processes"], c["remote_hosts"], c["flagged"]))
            out["sampled"] = True
            # listening ports baseline
            listeners = self._listeners(rows)
            now = _iso()
            first = self._state_get("listeners_baseline_at") is None
            seen = {r["key"] for r in self.db.fetchall("SELECT key FROM network_listeners_seen")}
            present = set()
            for m in listeners:
                if m["exposure"] == "local":
                    continue
                if m["proto"] == "udp" and not (m["port"] < 1024 or m["risky_service"]):
                    continue
                key = f"{m['proto']}|{m['port']}|{(m['exe'] or m['process'] or '?').lower()}"
                present.add(key)
                if key in seen:
                    self.db.execute("UPDATE network_listeners_seen SET last_seen=?, present=1 WHERE key=?",
                                    (now, key))
                    continue
                self.db.execute("INSERT INTO network_listeners_seen(key, proto, port, program, first_seen, last_seen) "
                                "VALUES (?,?,?,?,?,?)", (key, m["proto"], m["port"], m["exe"] or m["process"], now,
                                                         now))
                if first or m.get("cyberhub") or not self.settings.get("network_alert_new_listeners"):
                    continue
                sev = m["severity"] if m["severity"] != "info" else (
                    "low" if m["firewall"]["verdict"] == "blocked" else "medium")
                self._event("new_listener", sev,
                            f"{m['process'] or 'A program'} started accepting connections on "
                            f"{m['proto'].upper()} {m['port']}",
                            "; ".join(m["reasons"]), key=f"listen:{key}",
                            data={"pid": m["pid"], "exe": m["exe"], "port": m["port"], "proto": m["proto"]})
                out["new_listeners"] += 1
            if seen - present:
                self.db.execute(f"UPDATE network_listeners_seen SET present=0 WHERE key IN "
                                f"({','.join('?' * len(seen - present))})", tuple(seen - present))
            if first:
                self._state_set("listeners_baseline_at", now)
            # suspicious connections + behaviour
            if self.settings.get("network_alert_suspicious"):
                for r in rows:
                    if r["risk_level"] in ("medium", "high") and r["scope"] == "internet":
                        k = f"conn:{(r['exe'] or r['process'] or '?').lower()}:{r['remote_ip']}:{r['remote_port']}"
                        if self._once(k, 24):
                            self._event("suspicious_connection", "high" if r["risk_level"] == "high" else "medium",
                                        f"Suspicious connection: {r['process'] or 'unknown program'} -> "
                                        f"{r['remote_ip']}:{r['remote_port']}", "; ".join(r["reasons"]), key=k,
                                        data={"pid": r["pid"], "exe": r["exe"], "remote_ip": r["remote_ip"],
                                              "remote_port": r["remote_port"], "flags": r["flags"]})
                            out["suspicious"] += 1
                for g in self._proc_groups(rows):
                    for b in g["behaviour"]:
                        k = f"proc:{b['code']}:{(g['exe'] or g['process'] or '?').lower()}"
                        if self._once(k, 6):
                            self._event(b["code"], b["severity"], f"{g['process'] or 'A program'}: "
                                                                  f"{b['code'].replace('_', ' ')}", b["text"], key=k,
                                        data={"pid": g["pid"], "exe": g["exe"]})
                            out["suspicious"] += 1
            # LAN (passive) + gateway
            try:
                neigh = self.probe.neighbours()
                net = self.current_network(neigh)
                if net:
                    in_net = [n for n in neigh if _in_subnet(n["ip"], net["subnet"])]
                    out["devices_new"] = len(self._upsert_devices(net, [{"ip": n["ip"], "mac": n["mac"]}
                                                                        for n in in_net], "passive"))
                    self._check_gateway(net, neigh)
            except Exception as e:
                log.debug("LAN watch failed: %s", e)
            # Wi-Fi (records history + insecure alert; evil-twin alert)
            try:
                w = self.wifi(refresh=True)
                for f in w["findings"]:
                    if f["id"].startswith("n") and f["severity"] == "high" and "twin" in f.get("key", ""):
                        if self._once(f["key"], 24):
                            self._event("evil_twin", "high", f["title"], f["detail"], key=f["key"])
            except Exception as e:                                     # pragma: no cover
                log.debug("Wi-Fi watch failed: %s", e)
            # housekeeping
            days = int(self.settings.get("network_sample_retention_days"))
            self.db.execute("DELETE FROM network_samples WHERE ts < ?",
                            (_iso(datetime.now(timezone.utc) - timedelta(days=days)),))
            self.db.execute("DELETE FROM network_events WHERE id NOT IN (SELECT id FROM network_events "
                            "ORDER BY id DESC LIMIT 5000)")
            self._state_set("last_watch", _iso())
            self.invalidate()
            return out

    # ================================================================== events / graphs / status
    def events(self, after_id: int = 0, severity: str | None = None, kind: str | None = None,
               unacknowledged: bool = False, limit: int = 100) -> dict:
        where, params = ["id > ?"], [after_id]
        if severity:
            where.append("severity=?")
            params.append(severity)
        if kind:
            where.append("kind=?")
            params.append(kind)
        if unacknowledged:
            where.append("acknowledged=0")
        rows = self.db.fetchall(f"SELECT * FROM network_events WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
                                tuple(params) + (limit,))
        last = self.db.fetchone("SELECT COALESCE(MAX(id),0) AS m FROM network_events")["m"]
        return {"items": [self._event_row(r) for r in rows], "last_id": last,
                "unacknowledged": self.db.fetchone("SELECT COUNT(*) AS n FROM network_events WHERE acknowledged=0")["n"]}

    def acknowledge(self, ids: list[int] | None = None) -> int:
        if ids:
            return self.db.execute(f"UPDATE network_events SET acknowledged=1 WHERE id IN ({','.join('?' * len(ids))})",
                                   tuple(ids)).rowcount
        return self.db.execute("UPDATE network_events SET acknowledged=1 WHERE acknowledged=0").rowcount

    def clear_events(self) -> int:
        return self.db.execute("DELETE FROM network_events").rowcount

    def summary(self, hours: int = 24, days: int = 14) -> dict:
        since = _iso(datetime.now(timezone.utc) - timedelta(hours=hours))
        rows = self.db.fetchall("SELECT * FROM network_samples WHERE ts >= ? ORDER BY ts", (since,))
        bucket = 5 if hours <= 6 else 15 if hours <= 48 else 60
        series: dict[str, dict] = {}
        for r in rows:
            dt = _parse_iso(r["ts"])
            if not dt:
                continue
            b = dt.replace(minute=(dt.minute // bucket) * bucket if bucket < 60 else 0, second=0, microsecond=0)
            k = _iso(b)
            s = series.setdefault(k, {"ts": k, "n": 0, "established": 0, "listening": 0, "internet": 0, "lan": 0,
                                      "remote_hosts": 0, "flagged": 0, "processes": 0})
            s["n"] += 1
            for f in ("established", "listening", "internet", "lan", "remote_hosts", "flagged", "processes"):
                s[f] = max(s[f], r[f])
        ev_since = _iso(datetime.now(timezone.utc) - timedelta(days=days))
        by_day = self.db.fetchall(
            "SELECT substr(ts,1,10) AS day, severity, COUNT(*) AS n FROM network_events WHERE ts >= ? "
            "GROUP BY day, severity ORDER BY day", (ev_since,))
        by_kind = self.db.fetchall("SELECT kind, COUNT(*) AS n FROM network_events WHERE ts >= ? GROUP BY kind "
                                   "ORDER BY n DESC", (ev_since,))
        try:
            ann = self._annotated()
        except NetworkError:
            ann = []
        groups = self._proc_groups(ann)
        ports: dict[int, int] = {}
        for r in ann:
            if r["direction"] == "outgoing" and r["remote_port"] and r["scope"] in ("internet", "lan"):
                ports[r["remote_port"]] = ports.get(r["remote_port"], 0) + 1
        return {
            "hours": hours, "bucket_minutes": bucket, "series": list(series.values()),
            "events_by_day": by_day, "events_by_kind": by_kind, "now": self._counts(ann),
            "top_processes": [{"process": g["process"], "pid": g["pid"], "connections": g["connections"],
                               "internet": g["internet"], "remote_hosts": g["remote_hosts"],
                               "risk_level": g["risk_level"]} for g in
                              sorted(groups, key=lambda g: -g["connections"])[:10]],
            "top_remote_ports": [{"port": p, "service": npb.service_name(p), "connections": n}
                                 for p, n in sorted(ports.items(), key=lambda kv: -kv[1])[:10]],
            "by_scope": {k: v for k, v in self._counts(ann).items() if k in ("internet", "lan", "local")},
            "by_state": self._state_counts(ann),
        }

    @staticmethod
    def _state_counts(rows: list[dict]) -> dict:
        out: dict[str, int] = {}
        for r in rows:
            if r["proto"] == "tcp":
                out[r["status"]] = out.get(r["status"], 0) + 1
        return out

    def live_brief(self) -> dict:
        """Cheap numbers for the WebSocket (no firewall / Wi-Fi calls)."""
        try:
            rows = self._annotated()
        except NetworkError:
            rows = []
        c = self._counts(rows)
        return {k: c[k] for k in ("total", "established", "listening", "incoming", "outgoing", "internet", "lan",
                                  "syn_sent", "processes", "remote_hosts", "flagged")}

    def status(self) -> dict:
        out: dict[str, Any] = {"backend": {"probe": self.probe.label, "wifi": self.probe.wifi.label,
                                           "firewall": None, "elevated": None},
                               "connections": {}, "wifi": None, "lan": None, "score": None, "grade": None,
                               "findings": {}, "unacknowledged_alerts": 0, "last_watch": self._state_get("last_watch"),
                               "scan": self.scan_status(), "error": None}
        if self.firewall is not None:
            try:
                out["backend"]["firewall"] = self.firewall.backend.label if self.firewall.available() else None
            except Exception:                                          # pragma: no cover
                pass
        try:
            from .processes import is_elevated
            out["backend"]["elevated"] = is_elevated()
        except Exception:                                              # pragma: no cover
            pass
        try:
            rows = self._annotated()
            out["connections"] = self._counts(rows)
        except NetworkError as e:
            out["error"] = e.message
        w = self.wifi()
        cur = w.get("current")
        out["wifi"] = {"available": w["available"], "connected": bool(cur), "ssid": cur.get("ssid") if cur else None,
                       "auth": cur.get("auth") if cur else None, "signal": cur.get("signal") if cur else None,
                       "rating": cur["assessment"]["rating"] if cur else None,
                       "nearby": w.get("nearby_count", 0), "error": w.get("error")}
        try:
            net = self.current_network()
        except Exception:                                              # pragma: no cover
            net = None
        if net:
            devs = self.db.fetchall("SELECT first_seen, trusted FROM lan_devices WHERE network_id=?", (net["id"],))
            day_ago = _iso(datetime.now(timezone.utc) - timedelta(days=1))
            out["lan"] = {"network_id": net["id"], "name": net["name"], "subnet": net["subnet"], "home": net["home"],
                          "gateway": net["gateway"], "devices": len(devs),
                          "new_24h": sum(1 for d in devs if d["first_seen"] >= day_ago),
                          "last_scan": net.get("last_scan"), "router_alert": bool(net.get("gateway_alert_mac"))}
        a = self.analyze()
        out["score"], out["grade"], out["findings"] = a["score"], a["grade"], a["counts"]
        out["unacknowledged_alerts"] = self.db.fetchone(
            "SELECT COUNT(*) AS n FROM network_events WHERE acknowledged=0")["n"]
        return out

    def shutdown(self) -> None:
        self._scan_cancel.set()
        t = self._scan_thread
        if t and t.is_alive():
            t.join(timeout=5)
        self._dns_pool.shutdown(wait=False, cancel_futures=True)


# ====================================================================== helpers
def _in_subnet(ip: str, subnet: str | None) -> bool:
    if not subnet:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet)
    except ValueError:
        return False


def _finding(key: str, severity: str, category: str, title: str, detail: str, fix: dict | None = None,
             fix_label: str | None = None, admin: bool = False, data: dict | None = None) -> dict:
    return {"id": _fid(key), "key": key, "severity": severity, "category": category, "title": title,
            "detail": detail, "fix": fix, "fix_label": fix_label, "fix_requires_admin": bool(fix) and admin,
            "data": data or {}}


async def network_loop(svc: NetworkService, settings, tick: float = 20, first_delay: float = 25) -> None:
    """Every N minutes: connection sample + listener / connection / LAN / Wi-Fi watch.
    Optional automatic LAN scan of Home networks (lan_auto_scan_minutes, minimum 15)."""
    log.info("Network watch started (%s, Wi-Fi: %s)", svc.probe.label, svc.probe.wifi.label)
    await asyncio.sleep(first_delay)
    last: float | None = None
    while True:
        try:
            interval = int(settings.get("network_watch_interval_minutes")) * 60
            if settings.get("network_watch_enabled") and (last is None or time.monotonic() - last >= interval):
                last = time.monotonic()
                await asyncio.to_thread(svc.watch_once)
            auto = int(settings.get("lan_auto_scan_minutes"))
            if auto > 0 and svc.scan_status().get("state") != "running":
                net = await asyncio.to_thread(svc.current_network)
                if net and net["home"] and net["scannable"]:
                    ls = _parse_iso(net.get("last_scan"))
                    if ls is None or datetime.now(timezone.utc) - ls >= timedelta(minutes=max(15, auto)):
                        await asyncio.to_thread(svc.start_scan, "scheduler")
        except Exception as e:                                         # never let the loop die
            log.warning("Network watch failed: %s", getattr(e, "message", e))
        await asyncio.sleep(tick)
