"""
Cyber Hub Backend - Firewall backends (Part 9)
Developed by Syed Muhammad Tayyab

One small interface over the platform firewall, so the service layer
(firewall.py) never cares which one it is talking to:

  * WindowsFirewall - Windows Defender Firewall through the NetSecurity
    PowerShell module (Get/Set/New/Remove-NetFirewall*) and netsh advfirewall
    for export / import / reset. Every user-chosen value (program path, IP,
    port, rule id) reaches PowerShell through environment variables
    ($env:CH_*) - never by formatting it into the script text.
  * UfwFirewall    - Linux ufw (status / numbered rules / deny / delete /
    default policy / logging / reset). No per-program rules (ufw cannot).
  * MemoryFirewall - an in-memory Windows-like firewall used by the tests and
    by the UI developer when CYBERHUB_FIREWALL_BACKEND=memory.
  * NoFirewall     - nothing supported here; status says why.

Every backend returns the same normalised shapes:

profile = {name, enabled, default_inbound: block|allow, default_outbound,
           allow_inbound_rules (False = "block all incoming connections"),
           notify_on_listen, log_allowed, log_blocked, log_file, log_max_kb}
rule    = {id, name, description, group, enabled, direction: in|out,
           action: allow|block, profiles[], program, service, package,
           protocol, local_ports, remote_ports, local_addresses,
           remote_addresses, source, editable}
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Callable

from ..logger import get_logger
from .platform_tools import IS_LINUX, IS_WINDOWS, run_cmd_full, run_powershell_json

log = get_logger("firewall")

WIN_PROFILES = ["domain", "private", "public"]
NEEDS_ADMIN = ("Windows Firewall can only be changed by an administrator - start Cyber Hub with "
               "start_cyberhub_admin.bat (Run as administrator) and try again")


class BackendError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ====================================================================== helpers
def _gbool(v: Any, default: bool) -> bool:
    """GpoBoolean / bool / 'True' / 'NotConfigured' -> bool."""
    if isinstance(v, bool):
        return v
    s = str(v or "").strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    return default


def _action(v: Any, default: str = "block") -> str:
    s = str(v or "").strip().lower()
    return s if s in ("allow", "block") else default


def _any(v: Any) -> str:
    """'' / None / 'Any' / '*' -> 'any', otherwise the trimmed text."""
    s = str(v if v is not None else "").strip()
    return "any" if s.lower() in ("", "any", "*") else s


def norm_profiles(v: Any) -> list[str]:
    """'Any' | 'Domain, Private' | ['private'] | 7 (flags) -> sorted list of profile names."""
    if isinstance(v, int):
        out = [n for bit, n in ((1, "domain"), (2, "private"), (4, "public")) if v & bit]
        return out or list(WIN_PROFILES)
    items = v if isinstance(v, list) else re.split(r"[,\s]+", str(v or "any"))
    out = set()
    for it in items:
        s = str(it).strip().lower()
        if s in ("", "any", "all"):
            return list(WIN_PROFILES)
        if s in WIN_PROFILES:
            out.add(s)
    return [p for p in WIN_PROFILES if p in out] or list(WIN_PROFILES)


def win_profile_arg(profiles: list[str]) -> str:
    if not profiles or set(profiles) >= set(WIN_PROFILES):
        return "Any"
    return ",".join(p.capitalize() for p in profiles)


def _source(v: Any) -> str:
    s = str(v or "local").strip().lower()
    return {"grouppolicy": "group_policy", "mdm": "group_policy", "local": "local", "dynamic": "dynamic",
            "generated": "generated", "hardcoded": "system", "defaultstore": "local"}.get(s, s or "local")


def normalize_win_rule(r: dict) -> dict:
    src = _source(r.get("store"))
    prog = r.get("program")
    prog = None if _any(prog) == "any" else str(prog)
    svc = r.get("service")
    svc = None if _any(svc) == "any" else str(svc)
    pkg = r.get("package")
    pkg = str(pkg) if pkg and str(pkg).strip() and str(pkg).lower() != "any" else None
    proto = _any(r.get("protocol")).lower()
    return {
        "id": str(r.get("id") or ""),
        "name": str(r.get("name") or r.get("id") or ""),
        "description": (str(r.get("description")) if r.get("description") else None),
        "group": (str(r.get("group")) if r.get("group") else None),
        "enabled": _gbool(r.get("enabled"), False),
        "direction": "out" if str(r.get("direction") or "").lower().startswith("out") else "in",
        "action": _action(r.get("action"), "allow"),
        "profiles": norm_profiles(r.get("profile")),
        "program": prog, "service": svc, "package": pkg,
        "protocol": proto,
        "local_ports": _any(r.get("lport")), "remote_ports": _any(r.get("rport")),
        "local_addresses": _any(r.get("laddr")), "remote_addresses": _any(r.get("raddr")),
        "source": src,
        "editable": src not in ("group_policy", "system"),
    }


def normalize_win_profile(p: dict) -> dict:
    return {
        "name": str(p.get("name") or "").lower(),
        "enabled": _gbool(p.get("enabled"), True),
        "default_inbound": _action(p.get("inbound"), "block"),
        "default_outbound": _action(p.get("outbound"), "allow"),
        "allow_inbound_rules": _gbool(p.get("allow_inbound_rules"), True),
        "notify_on_listen": _gbool(p.get("notify"), True),
        "log_allowed": _gbool(p.get("log_allowed"), False),
        "log_blocked": _gbool(p.get("log_blocked"), False),
        "log_file": p.get("log_file") or None,
        "log_max_kb": int(p.get("log_max_kb") or 4096) if str(p.get("log_max_kb") or "").isdigit() else 4096,
    }


def _category(cat: Any) -> str:
    s = str(cat or "").lower()
    return "domain" if s.startswith("domain") else ("private" if s.startswith("private") else "public")


# ====================================================================== interface
class FirewallBackend:
    name = "none"
    label = "No firewall"
    profile_names: list[str] = []
    supports_programs = False
    supports_toggle = False
    supports_snapshots = False
    supports_ranges = False

    def available(self) -> tuple[bool, str | None]:
        return False, "No supported firewall was found on this computer"

    def can_modify(self) -> bool:
        return False

    def profiles(self) -> list[dict]:
        raise BackendError(501, self.available()[1] or "Not supported")

    def networks(self) -> list[dict]:
        return []

    def rules(self) -> list[dict]:
        raise BackendError(501, self.available()[1] or "Not supported")

    def set_profile(self, names: list[str], changes: dict) -> None:
        raise BackendError(501, "Not supported")

    def add_rule(self, spec: dict) -> None:
        raise BackendError(501, "Not supported")

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        raise BackendError(501, "Not supported")

    def delete_rule(self, rule_id: str) -> None:
        raise BackendError(501, "Not supported")

    def export_policy(self, path: Path) -> None:
        raise BackendError(501, "Not supported")

    def import_policy(self, path: Path) -> None:
        raise BackendError(501, "Not supported")

    def reset(self) -> None:
        raise BackendError(501, "Not supported")

    def default_log_path(self) -> str | None:
        return None

    def info(self) -> dict:
        ok, why = self.available()
        return {"name": self.name, "label": self.label, "available": ok, "reason": why,
                "can_modify": bool(ok and self.can_modify()), "profiles": list(self.profile_names),
                "supports": {"programs": self.supports_programs, "toggle_rules": self.supports_toggle,
                             "snapshots": self.supports_snapshots, "address_ranges": self.supports_ranges}}


class NoFirewall(FirewallBackend):
    pass


# ====================================================================== Windows
_PS_HEAD = "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n$ErrorActionPreference = 'Stop'\ntry {\n"
_PS_TAIL = ("\n} catch { ConvertTo-Json -InputObject @{ ok = $false; error = [string]$_.Exception.Message } "
            "-Compress }\n")

PS_PROFILES = _PS_HEAD + r"""
$p = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [pscustomobject]@{
  name = [string]$_.Name; enabled = [string]$_.Enabled
  inbound = [string]$_.DefaultInboundAction; outbound = [string]$_.DefaultOutboundAction
  allow_inbound_rules = [string]$_.AllowInboundRules; notify = [string]$_.NotifyOnListen
  log_allowed = [string]$_.LogAllowed; log_blocked = [string]$_.LogBlocked
  log_file = [string]$_.LogFileName; log_max_kb = [string]$_.LogMaxSizeKilobytes } })
$n = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{
  name = [string]$_.Name; interface = [string]$_.InterfaceAlias
  category = [string]$_.NetworkCategory; ipv4 = [string]$_.IPv4Connectivity } })
ConvertTo-Json -InputObject @{ ok = $true; profiles = $p; networks = $n } -Compress -Depth 4
""" + _PS_TAIL

# Filters are fetched once with -All and joined by InstanceID - per-rule lookups take minutes.
PS_RULES = _PS_HEAD + r"""
$pf = @{}; Get-NetFirewallPortFilter -All -PolicyStore ActiveStore | ForEach-Object { $pf[$_.InstanceID] = $_ }
$af = @{}; Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore | ForEach-Object { $af[$_.InstanceID] = $_ }
$xf = @{}; Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore | ForEach-Object { $xf[$_.InstanceID] = $_ }
$sf = @{}; Get-NetFirewallServiceFilter -All -PolicyStore ActiveStore | ForEach-Object { $sf[$_.InstanceID] = $_ }
$r = @(Get-NetFirewallRule -PolicyStore ActiveStore | ForEach-Object {
  $k = $_.InstanceID; $p = $pf[$k]; $a = $af[$k]; $x = $xf[$k]; $s = $sf[$k]
  [pscustomobject]@{
    id = [string]$_.Name; name = [string]$_.DisplayName; description = [string]$_.Description
    group = [string]$_.DisplayGroup; enabled = [string]$_.Enabled; direction = [string]$_.Direction
    action = [string]$_.Action; profile = [string]$_.Profile; store = [string]$_.PolicyStoreSourceType
    program = [string]$x.Program; package = [string]$x.Package; service = [string]$s.Service
    protocol = [string]$p.Protocol; lport = (@($p.LocalPort) -join ','); rport = (@($p.RemotePort) -join ',')
    laddr = (@($a.LocalAddress) -join ','); raddr = (@($a.RemoteAddress) -join ',') } })
ConvertTo-Json -InputObject @{ ok = $true; rules = $r } -Compress -Depth 4
""" + _PS_TAIL

PS_SET_PROFILE = _PS_HEAD + r"""
$a = @{ Profile = @($env:CH_PROFILE -split ',') }
if ($env:CH_ENABLED) { $a.Enabled = $env:CH_ENABLED }
if ($env:CH_IN) { $a.DefaultInboundAction = $env:CH_IN }
if ($env:CH_OUT) { $a.DefaultOutboundAction = $env:CH_OUT }
if ($env:CH_AIR) { $a.AllowInboundRules = $env:CH_AIR }
if ($env:CH_NOTIFY) { $a.NotifyOnListen = $env:CH_NOTIFY }
if ($env:CH_LOGB) { $a.LogBlocked = $env:CH_LOGB }
if ($env:CH_LOGA) { $a.LogAllowed = $env:CH_LOGA }
Set-NetFirewallProfile @a
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

PS_ADD_RULE = _PS_HEAD + r"""
$a = @{ Name = $env:CH_ID; DisplayName = $env:CH_NAME; Group = $env:CH_GROUP; Direction = $env:CH_DIR
        Action = $env:CH_ACTION; Enabled = 'True'; Profile = $env:CH_PROFILES }
if ($env:CH_DESC) { $a.Description = $env:CH_DESC }
if ($env:CH_PROGRAM) { $a.Program = $env:CH_PROGRAM }
if ($env:CH_PROTO) { $a.Protocol = $env:CH_PROTO }
if ($env:CH_LPORT) { $a.LocalPort = @($env:CH_LPORT -split ',') }
if ($env:CH_RPORT) { $a.RemotePort = @($env:CH_RPORT -split ',') }
if ($env:CH_RADDR) { $a.RemoteAddress = @($env:CH_RADDR -split ',') }
New-NetFirewallRule @a | Out-Null
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

PS_TOGGLE_RULE = _PS_HEAD + r"""
Set-NetFirewallRule -Name $env:CH_ID -Enabled $env:CH_ENABLED
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

PS_DELETE_RULE = _PS_HEAD + r"""
Remove-NetFirewallRule -Name $env:CH_ID
ConvertTo-Json -InputObject @{ ok = $true } -Compress
""" + _PS_TAIL

_DENIED = re.compile(r"access is denied|0x80070005|permissiondenied|requested operation requires elevation|"
                     r"administrator", re.I)
_NOT_FOUND = re.compile(r"no msft_netfirewallrule objects found|not found|objectnotfound", re.I)


class WindowsFirewall(FirewallBackend):
    name = "windows"
    label = "Windows Defender Firewall"
    profile_names = list(WIN_PROFILES)
    supports_programs = supports_toggle = supports_snapshots = supports_ranges = True

    def __init__(self, ps: Callable[..., Any] | None = None,
                 cmd: Callable[..., tuple[int, str, str]] | None = None,
                 elevated: Callable[[], bool] | None = None):
        self._ps = ps or run_powershell_json
        self._cmd = cmd or run_cmd_full
        if elevated is None:
            from .processes import is_elevated
            elevated = is_elevated
        self._elevated = elevated

    def available(self) -> tuple[bool, str | None]:
        if self._ps is run_powershell_json and not IS_WINDOWS:            # pragma: no cover
            return False, "Windows Firewall is only available on Windows"
        return True, None

    def can_modify(self) -> bool:
        return bool(self._elevated())

    def _run(self, script: str, env: dict | None = None, timeout: float = 30.0) -> dict:
        data = self._ps(script, timeout=timeout, env=env or {})
        if not isinstance(data, dict):
            raise BackendError(502, "Windows Firewall did not answer (PowerShell NetSecurity module unavailable?)")
        if not data.get("ok"):
            msg = str(data.get("error") or "Windows Firewall refused the change").strip()
            if _DENIED.search(msg):
                raise BackendError(403, NEEDS_ADMIN)
            if _NOT_FOUND.search(msg):
                raise BackendError(404, "That firewall rule no longer exists")
            raise BackendError(400, msg[:400])
        return data

    def _profile_data(self) -> dict:
        return self._run(PS_PROFILES, timeout=25)

    def profiles(self) -> list[dict]:
        out = [normalize_win_profile(p) for p in (self._profile_data().get("profiles") or [])]
        return [p for p in out if p["name"] in WIN_PROFILES]

    def networks(self) -> list[dict]:
        try:
            nets = self._profile_data().get("networks") or []
        except BackendError:
            return []
        return [{"name": n.get("name"), "interface": n.get("interface"), "profile": _category(n.get("category")),
                 "internet": str(n.get("ipv4") or "").lower() == "internet"} for n in nets]

    def rules(self) -> list[dict]:
        data = self._run(PS_RULES, timeout=120)
        return [normalize_win_rule(r) for r in (data.get("rules") or []) if r.get("id")]

    def set_profile(self, names: list[str], changes: dict) -> None:
        env = {"CH_PROFILE": ",".join(n.capitalize() for n in names)}
        m = {"enabled": "CH_ENABLED", "allow_inbound_rules": "CH_AIR", "notify_on_listen": "CH_NOTIFY",
             "log_blocked": "CH_LOGB", "log_allowed": "CH_LOGA"}
        for k, var in m.items():
            if k in changes:
                env[var] = "True" if changes[k] else "False"
        if "default_inbound" in changes:
            env["CH_IN"] = changes["default_inbound"].capitalize()
        if "default_outbound" in changes:
            env["CH_OUT"] = changes["default_outbound"].capitalize()
        self._run(PS_SET_PROFILE, env)

    def add_rule(self, spec: dict) -> None:
        env = {"CH_ID": spec["id"], "CH_NAME": spec["name"], "CH_GROUP": spec.get("group") or "Cyber Hub",
               "CH_DIR": "Outbound" if spec["direction"] == "out" else "Inbound",
               "CH_ACTION": spec["action"].capitalize(), "CH_PROFILES": win_profile_arg(spec.get("profiles") or []),
               "CH_DESC": spec.get("description") or ""}
        if spec.get("program"):
            env["CH_PROGRAM"] = spec["program"]
        if spec.get("protocol") and spec["protocol"] != "any":
            env["CH_PROTO"] = spec["protocol"].upper() if spec["protocol"] in ("tcp", "udp") else spec["protocol"]
        for key, var in (("local_ports", "CH_LPORT"), ("remote_ports", "CH_RPORT"),
                         ("remote_addresses", "CH_RADDR")):
            if spec.get(key):
                env[var] = ",".join(spec[key])
        self._run(PS_ADD_RULE, env)

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        self._run(PS_TOGGLE_RULE, {"CH_ID": rule_id, "CH_ENABLED": "True" if enabled else "False"})

    def delete_rule(self, rule_id: str) -> None:
        self._run(PS_DELETE_RULE, {"CH_ID": rule_id})

    def _netsh(self, *args: str) -> None:
        rc, out, err = self._cmd(["netsh", "advfirewall", *args], 90)
        if rc != 0:
            msg = (out + " " + err).strip()
            if _DENIED.search(msg) or "elevation" in msg.lower():
                raise BackendError(403, NEEDS_ADMIN)
            raise BackendError(502, f"netsh advfirewall {args[0]} failed: {msg[:300] or rc}")

    def export_policy(self, path: Path) -> None:
        self._netsh("export", str(path))

    def import_policy(self, path: Path) -> None:
        self._netsh("import", str(path))

    def reset(self) -> None:
        self._netsh("reset")

    def default_log_path(self) -> str | None:
        root = os.environ.get("SystemRoot", r"C:\Windows")
        return str(Path(root) / "System32" / "LogFiles" / "Firewall" / "pfirewall.log")


# ====================================================================== Linux ufw
_UFW_LINE = re.compile(r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+?)"
                       r"(?:\s+#\s*(.*))?$")
_UFW_PORT = re.compile(r"^\d[\d:,]*(/(tcp|udp))?$|^(\d[\d:,]*)?/(tcp|udp)$")


def _ufw_side(text: str) -> tuple[str, str, str, bool]:
    """'203.0.113.5 445/tcp (v6)' -> (address, ports, proto, v6)."""
    v6 = "(v6)" in text
    text = text.replace("(v6)", "").replace("(out)", "").strip()
    text = re.sub(r"\s+on\s+\S+", "", text)                 # "Anywhere on eth0"
    addr, port, proto = "any", "any", "any"
    for tok in text.split():
        if tok.lower() == "anywhere":
            continue
        if _UFW_PORT.match(tok):
            p, _, pr = tok.partition("/")
            port = p.replace(":", "-") or "any"
            proto = pr or proto
        else:
            addr = tok
    return addr, port, proto, v6


def parse_ufw_numbered(text: str) -> list[dict]:
    rules = []
    for line in text.splitlines():
        m = _UFW_LINE.match(line.rstrip())
        if not m:
            continue
        num, to, act, direction, frm, comment = m.groups()
        direction = (direction or "IN").lower()
        if direction == "fwd":
            continue
        t_addr, t_port, t_proto, v6a = _ufw_side(to)
        f_addr, f_port, f_proto, v6b = _ufw_side(frm)
        proto = t_proto if t_proto != "any" else f_proto
        core = re.sub(r"^\[\s*\d+\]\s+", "", line.strip())
        rid = comment.strip() if comment else "ufw:" + hashlib.sha1(core.encode()).hexdigest()[:12]
        r = {"id": rid, "number": int(num),
             "name": comment.strip() if comment else f"{act.title()} {direction} {to.strip()} from {frm.strip()}",
             "description": None, "group": "Cyber Hub" if rid.startswith("CyberHub-") else None, "enabled": True,
             "direction": "out" if direction == "out" else "in",
             "action": "allow" if act in ("ALLOW", "LIMIT") else "block", "profiles": ["all"],
             "program": None, "service": None, "package": None, "protocol": proto,
             "source": "local", "editable": True, "v6": v6a or v6b}
        if r["direction"] == "in":
            r.update(local_ports=t_port, local_addresses=t_addr, remote_ports=f_port, remote_addresses=f_addr)
        else:
            r.update(local_ports=f_port, local_addresses=f_addr, remote_ports=t_port, remote_addresses=t_addr)
        rules.append(r)
    return rules


def parse_ufw_verbose(text: str) -> dict:
    st = re.search(r"Status:\s*(\w+)", text)
    lg = re.search(r"Logging:\s*(\w+)", text)
    df = re.search(r"Default:\s*(\w+)\s*\(incoming\),\s*(\w+)\s*\(outgoing\)", text)
    return {"name": "all", "enabled": bool(st and st.group(1).lower() == "active"),
            "default_inbound": "allow" if df and df.group(1).lower() == "allow" else "block",
            "default_outbound": "block" if df and df.group(2).lower() in ("deny", "reject") else "allow",
            "allow_inbound_rules": True, "notify_on_listen": False, "log_allowed": False,
            "log_blocked": bool(lg and lg.group(1).lower() == "on"), "log_file": "/var/log/ufw.log",
            "log_max_kb": None}


class UfwFirewall(FirewallBackend):
    name = "ufw"
    label = "Uncomplicated Firewall (ufw)"
    profile_names = ["all"]
    supports_snapshots = True

    def __init__(self, cmd: Callable[..., tuple[int, str, str]] | None = None, root: Callable[[], bool] | None = None,
                 rules_dir: Path = Path("/etc/ufw")):
        self._cmd = cmd or run_cmd_full
        self._root = root or (lambda: hasattr(os, "geteuid") and os.geteuid() == 0)
        self.rules_dir = rules_dir

    def available(self) -> tuple[bool, str | None]:
        if self._cmd is run_cmd_full and not shutil.which("ufw"):
            return False, "ufw is not installed"
        return True, None

    def can_modify(self) -> bool:
        return bool(self._root())

    def _ufw(self, *args: str) -> str:
        rc, out, err = self._cmd(["ufw", *args], 30)
        if rc != 0:
            msg = (err or out).strip()
            if "root" in msg.lower() or "permission" in msg.lower():
                raise BackendError(403, "ufw can only be used as root - start Cyber Hub with sudo")
            raise BackendError(400, f"ufw: {msg[:300] or rc}")
        return out

    def profiles(self) -> list[dict]:
        return [parse_ufw_verbose(self._ufw("status", "verbose"))]

    def rules(self) -> list[dict]:
        return parse_ufw_numbered(self._ufw("status", "numbered"))

    def set_profile(self, names: list[str], changes: dict) -> None:
        for k in ("allow_inbound_rules", "notify_on_listen", "log_allowed"):
            if k in changes:
                raise BackendError(501, f"ufw has no '{k}' setting")
        if "enabled" in changes:
            self._ufw("--force", "enable" if changes["enabled"] else "disable")
        if "default_inbound" in changes:
            self._ufw("default", "allow" if changes["default_inbound"] == "allow" else "deny", "incoming")
        if "default_outbound" in changes:
            self._ufw("default", "allow" if changes["default_outbound"] == "allow" else "deny", "outgoing")
        if "log_blocked" in changes:
            self._ufw("logging", "on" if changes["log_blocked"] else "off")

    def add_rule(self, spec: dict) -> None:
        if spec.get("program"):
            raise BackendError(501, "ufw filters by address and port only - blocking a single program "
                                    "needs Windows Firewall")
        addrs = spec.get("remote_addresses") or ["any"]
        if any("-" in a for a in addrs):
            raise BackendError(400, "ufw does not accept address ranges - use CIDR notation (e.g. 10.0.0.0/24)")
        proto = spec.get("protocol") if spec.get("protocol") in ("tcp", "udp") else None
        verb = "allow" if spec["action"] == "allow" else "deny"
        ports = (spec.get("local_ports") if spec["direction"] == "in" else spec.get("remote_ports")) or []
        port = ",".join(p.replace("-", ":") for p in ports) if ports else None
        if port and not proto and (":" in port or "," in port):
            raise BackendError(400, "ufw needs a protocol (tcp or udp) for port ranges and lists")
        has_rules = bool(self.rules())
        for addr in addrs:
            args = (["insert", "1"] if has_rules else []) + [verb, spec["direction"]]
            if spec["direction"] == "in":
                args += ["from", addr, "to", "any"]
            else:
                args += ["to", addr]
            if port:
                args += ["port", port]
            if proto:
                args += ["proto", proto]
            args += ["comment", spec["id"]]
            self._ufw(*args)
            has_rules = True

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        raise BackendError(501, "ufw rules cannot be switched off - delete the rule instead")

    def delete_rule(self, rule_id: str) -> None:
        nums = sorted((r["number"] for r in self.rules() if r["id"] == rule_id), reverse=True)
        if not nums:
            raise BackendError(404, "That firewall rule no longer exists")
        for n in nums:
            self._ufw("--force", "delete", str(n))

    def export_policy(self, path: Path) -> None:
        data = {}
        for n in ("user.rules", "user6.rules"):
            f = self.rules_dir / n
            try:
                data[n] = f.read_text(encoding="utf-8")
            except PermissionError:
                raise BackendError(403, "Reading ufw rules needs root")
            except OSError:
                pass
        path.write_text(json.dumps({"ufw": data}), encoding="utf-8")

    def import_policy(self, path: Path) -> None:
        data = json.loads(path.read_text(encoding="utf-8")).get("ufw") or {}
        try:
            for n, text in data.items():
                if n in ("user.rules", "user6.rules"):
                    (self.rules_dir / n).write_text(text, encoding="utf-8")
        except PermissionError:
            raise BackendError(403, "Restoring ufw rules needs root")
        self._ufw("reload")

    def reset(self) -> None:
        self._ufw("--force", "reset")

    def default_log_path(self) -> str | None:
        return "/var/log/ufw.log"


# ====================================================================== in-memory simulator
def _seed_rules() -> list[dict]:
    def r(id_, name, direction, action, enabled, protocol="any", lport="any", raddr="any", program=None,
          profiles=None, group=None, source="local", service=None):
        return {"id": id_, "name": name, "description": None, "group": group, "enabled": enabled,
                "direction": direction, "action": action, "profiles": profiles or list(WIN_PROFILES),
                "program": program, "service": service, "package": None, "protocol": protocol,
                "local_ports": lport, "remote_ports": "any", "local_addresses": "any",
                "remote_addresses": raddr, "source": source, "editable": source not in ("group_policy", "system")}
    sysroot = r"%SystemRoot%\system32"
    return [
        r("CoreNet-DHCP-In", "Core Networking - DHCP (DHCP-In)", "in", "allow", True, "udp", "68",
          program=sysroot + r"\svchost.exe", group="Core Networking", service="dhcp"),
        r("CoreNet-DNS-Out-UDP", "Core Networking - DNS (UDP-Out)", "out", "allow", True, "udp",
          program=sysroot + r"\svchost.exe", group="Core Networking", service="dnscache"),
        r("RemoteDesktop-UserMode-In-TCP", "Remote Desktop - User Mode (TCP-In)", "in", "allow", False, "tcp",
          "3389", program=sysroot + r"\svchost.exe", group="Remote Desktop", service="termservice"),
        r("FPS-SMB-In-TCP", "File and Printer Sharing (SMB-In)", "in", "allow", False, "tcp", "445",
          raddr="LocalSubnet", profiles=["private"], program="System", group="File and Printer Sharing"),
        r("CorpPolicy-Block-Telnet", "Company policy - block Telnet", "in", "block", True, "tcp", "23",
          source="group_policy", group="Company policy"),
    ]


def _default_profiles() -> dict[str, dict]:
    return {n: {"name": n, "enabled": True, "default_inbound": "block", "default_outbound": "allow",
                "allow_inbound_rules": True, "notify_on_listen": True, "log_allowed": False,
                "log_blocked": False, "log_file": None, "log_max_kb": 4096} for n in WIN_PROFILES}


class MemoryFirewall(FirewallBackend):
    """Behaves like Windows Firewall, in memory. CYBERHUB_FIREWALL_BACKEND=memory selects it."""
    name = "memory"
    label = "Simulated firewall (developer mode)"
    profile_names = list(WIN_PROFILES)
    supports_programs = supports_toggle = supports_snapshots = supports_ranges = True

    def __init__(self, elevated: bool = True):
        self.elevated = elevated
        self.fail: BackendError | None = None      # tests: next call raises this
        self.calls: list[str] = []
        self._profiles = _default_profiles()
        self._rules: dict[str, dict] = {r["id"]: r for r in _seed_rules()}
        self.network = [{"name": "HomeWiFi", "interface": "Wi-Fi", "profile": "private", "internet": True}]

    def available(self) -> tuple[bool, str | None]:
        return True, None

    def can_modify(self) -> bool:
        return self.elevated

    def _tick(self, what: str, write: bool = False) -> None:
        self.calls.append(what)
        if self.fail:
            e, self.fail = self.fail, None
            raise e
        if write and not self.elevated:
            raise BackendError(403, NEEDS_ADMIN)

    def profiles(self) -> list[dict]:
        self._tick("profiles")
        return [dict(self._profiles[n]) for n in WIN_PROFILES]

    def networks(self) -> list[dict]:
        return [dict(n) for n in self.network]

    def rules(self) -> list[dict]:
        self._tick("rules")
        return [dict(r) for r in self._rules.values()]

    def set_profile(self, names: list[str], changes: dict) -> None:
        self._tick("set_profile", True)
        for n in names:
            self._profiles[n].update(changes)

    def add_rule(self, spec: dict) -> None:
        self._tick("add_rule", True)
        if spec["id"] in self._rules:
            raise BackendError(400, "A rule with that name already exists")
        self._rules[spec["id"]] = {
            "id": spec["id"], "name": spec["name"], "description": spec.get("description"),
            "group": spec.get("group"), "enabled": spec.get("enabled", True), "direction": spec["direction"],
            "action": spec["action"], "profiles": norm_profiles(spec.get("profiles") or "any"),
            "program": spec.get("program"), "service": spec.get("service"), "package": None,
            "protocol": spec.get("protocol") or "any",
            "local_ports": ",".join(spec.get("local_ports") or []) or "any",
            "remote_ports": ",".join(spec.get("remote_ports") or []) or "any", "local_addresses": "any",
            "remote_addresses": ",".join(spec.get("remote_addresses") or []) or "any",
            "source": spec.get("source", "local"), "editable": spec.get("source", "local") != "group_policy"}

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        self._tick("set_rule_enabled", True)
        if rule_id not in self._rules:
            raise BackendError(404, "That firewall rule no longer exists")
        self._rules[rule_id]["enabled"] = enabled

    def delete_rule(self, rule_id: str) -> None:
        self._tick("delete_rule", True)
        if self._rules.pop(rule_id, None) is None:
            raise BackendError(404, "That firewall rule no longer exists")

    def export_policy(self, path: Path) -> None:
        self._tick("export", True)
        path.write_text(json.dumps({"profiles": self._profiles, "rules": self._rules}), encoding="utf-8")

    def import_policy(self, path: Path) -> None:
        self._tick("import", True)
        d = json.loads(path.read_text(encoding="utf-8"))
        self._profiles, self._rules = d["profiles"], d["rules"]

    def reset(self) -> None:
        self._tick("reset", True)
        self._profiles = _default_profiles()
        self._rules = {r["id"]: r for r in _seed_rules()}

    def snapshot_state(self) -> dict:
        return copy.deepcopy({"profiles": self._profiles, "rules": self._rules})


def pick_backend() -> FirewallBackend:
    """CYBERHUB_FIREWALL_BACKEND = windows | ufw | memory | none, else auto-detect."""
    forced = os.environ.get("CYBERHUB_FIREWALL_BACKEND", "").strip().lower()
    if forced == "memory":
        return MemoryFirewall()
    if forced == "none":
        return NoFirewall()
    if forced == "ufw" or (not forced and IS_LINUX and shutil.which("ufw")):
        return UfwFirewall()
    if forced == "windows" or (not forced and IS_WINDOWS):
        return WindowsFirewall()
    return NoFirewall()
