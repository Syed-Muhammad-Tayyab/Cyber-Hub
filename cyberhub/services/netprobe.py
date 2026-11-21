"""
Cyber Hub Backend - Network probes (Part 10)
Developed by Syed Muhammad Tayyab

The platform layer under the Network Monitor & Wi-Fi section. Everything
that touches the OS lives here, so network.py only sees normalised shapes:

  * connections()  - psutil.net_connections + the owning process
  * interfaces()   - IPv4 adapters that are up, with their subnet
  * gateways()     - default routes  (Windows: Get-NetRoute, Linux: /proc/net/route)
  * neighbours()   - the ARP table    (Windows: Get-NetNeighbor / arp -a, Linux: /proc/net/arp)
  * nudge()        - one empty UDP datagram per address, which makes the OS
                     ARP for it (how the LAN scan finds devices without ping)
  * tcp_probe()    - open / closed / filtered for one fixed port
  * nbns_name()    - NetBIOS node-status query (UDP 137) -> Windows PC name
  * Wi-Fi          - WindowsWifi (netsh wlan), NmcliWifi (Linux), MemoryWifi
                     (tests / UI dev). Saved Wi-Fi passwords are NEVER read
                     (no 'key=clear').

CYBERHUB_NETWORK_BACKEND=memory swaps in MemoryNet: a simulated home LAN +
Wi-Fi so the UI and tests run anywhere. Connections stay real unless a test
puts fake rows into MemoryNet.fake_connections.
"""
from __future__ import annotations

import ipaddress
import os
import re
import secrets
import shutil
import socket
import struct
import time
from typing import Any

import psutil

from ..logger import get_logger
from .platform_tools import IS_LINUX, IS_WINDOWS, run_cmd_full, run_powershell_json

log = get_logger("network")

# ====================================================================== reference data
SERVICE_NAMES: dict[int, str] = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP mail", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3 mail", 123: "NTP time", 135: "Windows RPC", 137: "NetBIOS name",
    138: "NetBIOS datagram", 139: "NetBIOS / SMB", 143: "IMAP mail", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB file sharing", 465: "SMTP mail (TLS)", 500: "VPN (IKE)", 514: "Syslog", 515: "Printer (LPD)",
    548: "Apple file sharing", 554: "RTSP camera stream", 587: "SMTP mail (submission)", 631: "Printer (IPP)",
    636: "LDAP (TLS)", 853: "DNS over TLS", 993: "IMAP mail (TLS)", 995: "POP3 mail (TLS)", 1080: "SOCKS proxy",
    1194: "OpenVPN", 1433: "SQL Server", 1434: "SQL Browser", 1723: "PPTP VPN", 1883: "MQTT (IoT)",
    1900: "UPnP / SSDP", 2049: "NFS", 2375: "Docker API", 3306: "MySQL", 3389: "Remote Desktop",
    3478: "STUN (calls)", 5000: "UPnP / NAS web", 5222: "XMPP chat", 5353: "mDNS (Bonjour)", 5355: "LLMNR",
    5432: "PostgreSQL", 5900: "VNC remote control", 5985: "WinRM", 5986: "WinRM (TLS)", 6379: "Redis",
    7680: "Windows Update delivery", 8008: "HTTP (alt)", 8009: "Chromecast", 8080: "HTTP (alt)",
    8443: "HTTPS (alt)", 9100: "Printer (raw)", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 62078: "iPhone / iPad sync",
}

# Remote ports that are a red flag for an outgoing connection to the internet.
SUSPICIOUS_REMOTE_PORTS: dict[int, str] = {
    4444: "Metasploit / remote-access tools (default handler port)",
    1337: "hacking tools and backdoors", 31337: "backdoors (Back Orifice)",
    6666: "IRC (old botnet command channels)", 6667: "IRC (old botnet command channels)",
    6668: "IRC (old botnet command channels)", 6669: "IRC (old botnet command channels)",
    6697: "IRC over TLS (botnet command channels)",
    9001: "Tor relays", 9030: "Tor directory", 9050: "Tor proxy", 9150: "Tor Browser proxy",
    3333: "crypto-mining pools (stratum)", 5555: "crypto-mining pools (stratum)",
    7777: "crypto-mining pools (stratum)", 14433: "crypto-mining pools (stratum)",
    14444: "crypto-mining pools (stratum)",
    1080: "SOCKS proxies (traffic tunnelling)",
}

# Fixed list for the LAN scan (never user-supplied) -> device type hints.
LAN_PORTS = [21, 22, 23, 53, 80, 139, 443, 445, 515, 554, 631, 1883, 3389, 5000, 5900, 8008, 8009, 8080, 9100,
             62078]

# MAC prefixes known with certainty. Import the full IEEE list (POST /api/network/oui/import or /update)
# for every vendor.
BUILTIN_OUI: dict[str, str] = {
    "000C29": "VMware (virtual machine)", "005056": "VMware (virtual machine)", "000569": "VMware",
    "001C14": "VMware", "080027": "VirtualBox (virtual machine)", "00155D": "Microsoft Hyper-V (virtual machine)",
    "00163E": "Xen (virtual machine)", "525400": "QEMU / KVM (virtual machine)",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi", "D83ADD": "Raspberry Pi",
    "00000C": "Cisco",
}

LAN_RANGES = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
SCOPE_LAN = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                 "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10")]
MAX_SCAN_HOSTS = 1024
VIRTUAL_HINTS = ("vmware", "virtualbox", "vbox", "hyper-v", "vethernet", "docker", "veth", "br-", "virbr",
                 "wsl", "tailscale", "zerotier", "tun", "tap", "loopback", "npcap", "vmnet", "wg")


# ====================================================================== small helpers
def norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    h = re.sub(r"[^0-9a-fA-F]", "", str(mac))
    if len(h) != 12:
        return None
    h = h.upper()
    if h in ("000000000000", "FFFFFFFFFFFF"):
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def mac_is_multicast(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 0x01)


def mac_is_randomized(mac: str) -> bool:
    """Locally administered bit: phones / laptops use random 'private' addresses per network."""
    return bool(int(mac[:2], 16) & 0x02)


def unwrap_ip(ip: str) -> str:
    """'::ffff:1.2.3.4' -> '1.2.3.4', strips %zone."""
    ip = str(ip or "").split("%")[0]
    try:
        a = ipaddress.ip_address(ip)
        if a.version == 6 and a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(a)
    except ValueError:
        return ip


def ip_scope(ip: str) -> str:
    """local | lan | multicast | unspecified | internet | invalid"""
    try:
        a = ipaddress.ip_address(unwrap_ip(ip))
    except ValueError:
        return "invalid"
    if a.is_loopback:
        return "local"
    if a.is_unspecified:
        return "unspecified"
    if a.is_multicast or (a.version == 4 and str(a) == "255.255.255.255"):
        return "multicast"
    if any(a.version == n.version and a in n for n in SCOPE_LAN):
        return "lan"
    return "internet"


def service_name(port: int | None) -> str | None:
    return SERVICE_NAMES.get(port) if port else None


def is_scannable_network(net: ipaddress.IPv4Network) -> bool:
    """Only directly-connected private home / office ranges may be swept - never the internet."""
    return net.version == 4 and any(net.subnet_of(n) for n in LAN_RANGES)


def scan_hosts(own_ip: str, net: ipaddress.IPv4Network) -> tuple[ipaddress.IPv4Network, list[str]]:
    """Hosts to sweep: the whole subnet up to 1024 hosts, otherwise the /24 around this PC."""
    if net.num_addresses - 2 > MAX_SCAN_HOSTS:
        net = ipaddress.ip_network(f"{own_ip}/24", strict=False)
    hosts = [str(h) for h in net.hosts() if str(h) != own_ip]
    return net, hosts


# ====================================================================== NetBIOS node status
def _nbns_query(tid: int) -> bytes:
    name = b"*" + b"\x00" * 15
    enc = bytes(c for b in name for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F)))
    return struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + b"\x20" + enc + b"\x00" + struct.pack(">HH", 0x21, 1)


def parse_nbns_response(data: bytes, tid: int | None = None) -> dict | None:
    """-> {name, group, mac} from a node-status reply (RFC 1002 4.2.18)."""
    try:
        if len(data) < 57 or (tid is not None and struct.unpack(">H", data[:2])[0] != tid):
            return None
        off = 12
        if data[off] & 0xC0 == 0xC0:              # compressed name pointer
            off += 2
        else:
            while data[off] != 0:
                off += data[off] + 1
            off += 1
        off += 2 + 2 + 4                          # type, class, ttl
        rdlen = struct.unpack(">H", data[off:off + 2])[0]
        off += 2
        end = min(len(data), off + rdlen)
        count = data[off]
        off += 1
        name = group = None
        for _ in range(count):
            if off + 18 > end:
                break
            raw, suffix = data[off:off + 15], data[off + 15]
            flags = struct.unpack(">H", data[off + 16:off + 18])[0]
            off += 18
            text = raw.decode("ascii", errors="replace").strip()
            if suffix == 0x00 and not flags & 0x8000 and not name:
                name = text
            elif suffix == 0x00 and flags & 0x8000 and not group:
                group = text
        mac = norm_mac(data[off:off + 6].hex()) if off + 6 <= end else None
        return {"name": name, "group": group, "mac": mac} if name or group else None
    except (IndexError, struct.error):
        return None


# ====================================================================== OUI parsing
_OUI_LINE = re.compile(r"^\s*([0-9A-Fa-f]{2})[:\-]?([0-9A-Fa-f]{2})[:\-]?([0-9A-Fa-f]{2})(?:\s*\(hex\))?[\s,\t]+(.+?)\s*$")


def parse_oui_text(text: str) -> dict[str, str]:
    """IEEE oui.csv | IEEE oui.txt | Wireshark manuf | 'AABBCC Vendor' lines -> {AABBCC: vendor}."""
    out: dict[str, str] = {}
    lines = text.splitlines()
    if lines and lines[0].lower().startswith("registry,assignment"):
        import csv
        for row in csv.reader(lines[1:]):
            if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1].strip()):
                out[row[1].strip().upper()] = row[2].strip()[:120]
        return out
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#") or "(base 16)" in line:
            continue
        head = line.split()[0] if line.split() else ""
        if "/" in head:                            # /28 and /36 blocks - not a 24-bit OUI
            continue
        m = _OUI_LINE.match(line)
        if not m:
            continue
        vendor = m.group(4)
        if "\t" in vendor:                         # manuf: short<TAB>long name
            parts = [p.strip() for p in vendor.split("\t") if p.strip()]
            vendor = parts[-1] if parts else vendor
        out[(m.group(1) + m.group(2) + m.group(3)).upper()] = vendor.strip(" ,\"")[:120]
    return out


# ====================================================================== Wi-Fi normalisation
def norm_auth(auth: str | None, cipher: str | None = None) -> str:
    """Windows / nmcli wording -> open | owe | wep | wpa | wpa2 | wpa3 | wpa2-enterprise | wpa3-enterprise |
    wpa2/wpa3 | unknown"""
    a = (auth or "").strip().lower()
    c = (cipher or "").strip().lower()
    if not a or a in ("--", "none"):
        return "wep" if c == "wep" else "open"
    if "owe" in a or "enhanced open" in a:
        return "owe"
    if a == "open":
        return "wep" if c == "wep" else "open"
    if "wep" in a or a == "shared":
        return "wep"
    ent = "enterprise" in a or "802.1x" in a
    if "wpa3" in a or "sae" in a:
        if "wpa2" in a or "transition" in a:
            return "wpa2/wpa3"
        return "wpa3-enterprise" if ent else "wpa3"
    if "wpa2" in a or "rsna" in a:
        return "wpa2-enterprise" if ent else "wpa2"
    if "wpa" in a:
        return "wpa"
    return "unknown"


def norm_cipher(cipher: str | None) -> str:
    c = (cipher or "").strip().lower()
    if not c or c in ("none", "--"):
        return "none"
    for k in ("gcmp", "ccmp", "tkip", "wep"):
        if k in c:
            return k
    if "aes" in c:
        return "ccmp"
    return c[:20]


def _kv_lines(text: str) -> list[tuple[int, str, str]]:
    """'   Key    : value' -> (indent, key lower, value). Values keep their own colons (BSSIDs)."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^(\s*)([^:]+?)\s+:\s?(.*)$", line)
        if m:
            out.append((len(m.group(1)), m.group(2).strip().lower(), m.group(3).strip()))
    return out


def _pct(v: str | None) -> int | None:
    m = re.search(r"(\d+)", v or "")
    return int(m.group(1)) if m else None


def parse_netsh_interfaces(text: str) -> list[dict]:
    """`netsh wlan show interfaces` (English) -> one dict per Wi-Fi adapter."""
    out: list[dict] = []
    cur: dict | None = None
    for _, k, v in _kv_lines(text):
        if k == "name":
            cur = {"interface": v, "state": None, "ssid": None, "bssid": None, "auth_raw": None, "cipher_raw": None,
                   "signal": None, "radio": None, "band": None, "channel": None, "profile": None, "rx_mbps": None,
                   "tx_mbps": None, "description": None, "mac": None}
            out.append(cur)
        elif cur is None:
            continue
        elif k == "description":
            cur["description"] = v
        elif k in ("physical address",):
            cur["mac"] = norm_mac(v)
        elif k == "state":
            cur["state"] = v.lower()
        elif k == "ssid":
            cur["ssid"] = v
        elif k in ("bssid", "ap bssid"):
            cur["bssid"] = norm_mac(v)
        elif k == "authentication":
            cur["auth_raw"] = v
        elif k == "cipher":
            cur["cipher_raw"] = v
        elif k == "signal":
            cur["signal"] = _pct(v)
        elif k == "radio type":
            cur["radio"] = v
        elif k == "band":
            cur["band"] = v
        elif k == "channel":
            cur["channel"] = _pct(v)
        elif k == "profile":
            cur["profile"] = v
        elif k.startswith("receive rate"):
            cur["rx_mbps"] = _pct(v)
        elif k.startswith("transmit rate"):
            cur["tx_mbps"] = _pct(v)
    for c in out:
        c["connected"] = c["state"] == "connected" and bool(c["ssid"] is not None)
        c["auth"] = norm_auth(c["auth_raw"], c["cipher_raw"])
        c["cipher"] = norm_cipher(c["cipher_raw"])
    return out


def parse_netsh_networks(text: str) -> list[dict]:
    """`netsh wlan show networks mode=bssid` -> one dict per access point (BSSID)."""
    out: list[dict] = []
    net: dict | None = None
    ap: dict | None = None
    for line in text.splitlines():
        m = re.match(r"^SSID\s+\d+\s*:\s?(.*)$", line.strip())
        if m:
            net = {"ssid": m.group(1).strip(), "auth_raw": None, "cipher_raw": None}
            ap = None
            continue
        kv = re.match(r"^(\s*)([^:]+?)\s+:\s?(.*)$", line)
        if not kv or net is None:
            continue
        k, v = kv.group(2).strip().lower(), kv.group(3).strip()
        if k == "authentication":
            net["auth_raw"] = v
        elif k == "encryption":
            net["cipher_raw"] = v
        elif re.match(r"^bssid\s+\d+$", k):
            ap = {"ssid": net["ssid"], "hidden": not net["ssid"], "bssid": norm_mac(v), "signal": None,
                  "radio": None, "band": None, "channel": None,
                  "auth": norm_auth(net["auth_raw"], net["cipher_raw"]), "cipher": norm_cipher(net["cipher_raw"]),
                  "auth_raw": net["auth_raw"]}
            out.append(ap)
        elif ap is not None:
            if k == "signal":
                ap["signal"] = _pct(v)
            elif k == "radio type":
                ap["radio"] = v
            elif k == "band":
                ap["band"] = v
            elif k == "channel":
                ap["channel"] = _pct(v)
    return out


def parse_netsh_profile_names(text: str) -> list[str]:
    names = []
    for line in text.splitlines():
        m = re.match(r"^\s*(?:All User Profile|User Profile)\s+:\s?(.*)$", line)
        if m and m.group(1).strip() and m.group(1).strip() not in names:
            names.append(m.group(1).strip())
    return names


def parse_netsh_profile(text: str) -> dict:
    """`netsh wlan show profile name=X` (without key=clear) -> auth / cipher / auto-connect."""
    d: dict[str, Any] = {"auth_raw": None, "cipher_raw": None, "auto_connect": None, "non_broadcast": None}
    for _, k, v in _kv_lines(text):
        if k == "authentication" and d["auth_raw"] is None:
            d["auth_raw"] = v
        elif k == "cipher" and d["cipher_raw"] is None:
            d["cipher_raw"] = v
        elif k == "connection mode":
            d["auto_connect"] = "auto" in v.lower()
        elif k == "network broadcast":
            d["non_broadcast"] = "even if" in v.lower()
    d["auth"] = norm_auth(d["auth_raw"], d["cipher_raw"])
    d["cipher"] = norm_cipher(d["cipher_raw"])
    return d


def split_nmcli(line: str) -> list[str]:
    """nmcli -t -e yes output: fields split on ':' that is not escaped with '\\'."""
    out, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def nmcli_auth(sec: str) -> str:
    """nmcli SECURITY column ('', 'WPA2', 'WPA1 WPA2', 'WPA2 WPA3', 'WPA3', 'WPA2 802.1X', 'OWE', 'WEP')."""
    s = (sec or "").upper()
    if not s or s == "--":
        return "open"
    if "OWE" in s:
        return "owe"
    if "WEP" in s:
        return "wep"
    ent = "802.1X" in s
    if "WPA3" in s or "SAE" in s:
        if ent:
            return "wpa3-enterprise"
        return "wpa2/wpa3" if "WPA2" in s else "wpa3"
    if "WPA2" in s:
        return "wpa2-enterprise" if ent else "wpa2"
    if "WPA" in s:
        return "wpa"
    return "unknown"


def parse_nmcli_wifi(text: str) -> list[dict]:
    """IN-USE,SSID,BSSID,SECURITY,SIGNAL,CHAN,FREQ,DEVICE"""
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        f = split_nmcli(line)
        if len(f) < 8:
            continue
        sec = f[3].strip()
        auth = nmcli_auth(sec)
        out.append({"in_use": f[0].strip() == "*", "ssid": f[1], "hidden": not f[1], "bssid": norm_mac(f[2]),
                    "auth": auth, "auth_raw": sec or "open", "cipher": "ccmp" if auth.startswith(("wpa2", "wpa3"))
                    else ("tkip" if auth == "wpa" else "wep" if auth == "wep" else "none"),
                    "signal": _pct(f[4]), "channel": _pct(f[5]), "band": ("5 GHz" if (_pct(f[6]) or 0) >= 4900
                                                                          and (_pct(f[6]) or 0) < 5925 else
                                                                          "6 GHz" if (_pct(f[6]) or 0) >= 5925 else
                                                                          "2.4 GHz"), "radio": None,
                    "device": f[7] or None})
    return out


# ====================================================================== Wi-Fi backends
LOCATION_HINT = ("Windows needs Location permission before it shows Wi-Fi details to apps: Settings > "
                 "Privacy & security > Location > turn on Location services (and 'Let desktop apps access "
                 "your location')")


class WifiBackend:
    name, label = "none", "No Wi-Fi adapter support"

    def available(self) -> tuple[bool, str | None]:
        return False, "Wi-Fi checks are not supported on this system"

    def interfaces(self) -> list[dict]:
        return []

    def nearby(self) -> list[dict]:
        return []

    def profiles(self) -> list[dict]:
        return []


class WindowsWifi(WifiBackend):
    name, label = "windows", "Windows WLAN (netsh)"

    def __init__(self):
        self.last_error: str | None = None

    def _netsh(self, *args: str, timeout: float = 10) -> str | None:
        rc, out, err = run_cmd_full(["netsh", "wlan", *args], timeout=timeout)
        text = (out or "") + (err or "")
        if "location permission" in text.lower() or "location services" in text.lower():
            self.last_error = LOCATION_HINT
            return None
        if rc != 0:
            if "wireless autoconfig service" in text.lower() or "wlansvc" in text.lower():
                self.last_error = "The WLAN AutoConfig service is not running (no Wi-Fi adapter?)"
            elif rc == -1:
                self.last_error = "netsh is not available"
            else:
                self.last_error = (text.strip().splitlines() or ["netsh wlan failed"])[0][:200]
            return None
        self.last_error = None
        return out

    def available(self) -> tuple[bool, str | None]:
        if not shutil.which("netsh"):
            return False, "netsh is not available"
        return True, None

    def interfaces(self) -> list[dict]:
        out = self._netsh("show", "interfaces")
        return parse_netsh_interfaces(out) if out else []

    def nearby(self) -> list[dict]:
        out = self._netsh("show", "networks", "mode=bssid")
        return parse_netsh_networks(out) if out else []

    def profiles(self) -> list[dict]:
        out = self._netsh("show", "profiles")
        if not out:
            return []
        res = []
        for name in parse_netsh_profile_names(out)[:40]:
            # The name is one argv item (no shell) - and 'key=clear' is never passed, so no password is read.
            detail = self._netsh("show", "profile", f"name={name}", timeout=6)
            d = parse_netsh_profile(detail) if detail else {"auth": "unknown", "cipher": "unknown",
                                                            "auto_connect": None, "auth_raw": None}
            res.append({"name": name, **{k: d.get(k) for k in ("auth", "cipher", "auto_connect", "auth_raw")}})
        return res


class NmcliWifi(WifiBackend):
    name, label = "nmcli", "NetworkManager (nmcli)"

    def __init__(self):
        self.last_error: str | None = None

    def available(self) -> tuple[bool, str | None]:
        return (True, None) if shutil.which("nmcli") else (False, "nmcli (NetworkManager) is not installed")

    def _list(self) -> list[dict]:
        rc, out, err = run_cmd_full(["nmcli", "-t", "-e", "yes", "-f", "IN-USE,SSID,BSSID,SECURITY,SIGNAL,CHAN,FREQ,"
                                     "DEVICE", "dev", "wifi", "list", "--rescan", "no"], timeout=10)
        if rc != 0:
            self.last_error = (err or "nmcli failed").strip()[:200]
            return []
        self.last_error = None
        return parse_nmcli_wifi(out)

    def interfaces(self) -> list[dict]:
        cur = [n for n in self._list() if n["in_use"]]
        return [{"interface": n["device"], "state": "connected", "connected": True, "ssid": n["ssid"],
                 "bssid": n["bssid"], "auth": n["auth"], "auth_raw": n["auth_raw"], "cipher": n["cipher"],
                 "cipher_raw": n["cipher"], "signal": n["signal"], "channel": n["channel"], "band": n["band"],
                 "radio": None, "profile": n["ssid"], "rx_mbps": None, "tx_mbps": None, "description": None,
                 "mac": None} for n in cur]

    def nearby(self) -> list[dict]:
        return [{k: v for k, v in n.items() if k not in ("in_use", "device")} for n in self._list()]

    def profiles(self) -> list[dict]:
        rc, out, _ = run_cmd_full(["nmcli", "-t", "-e", "yes", "-f", "NAME,TYPE,AUTOCONNECT", "con", "show"],
                                  timeout=8)
        if rc != 0:
            return []
        res = []
        for line in out.splitlines():
            f = split_nmcli(line)
            if len(f) < 3 or "wireless" not in f[1]:
                continue
            rc2, o2, _ = run_cmd_full(["nmcli", "-t", "-g", "802-11-wireless-security.key-mgmt", "con", "show",
                                       f[0]], timeout=5)
            km = (o2 or "").strip().lower() if rc2 == 0 else None
            auth = ("unknown" if km is None else "open" if not km else "owe" if km == "owe" else
                    "wpa3" if km == "sae" else "wpa2-enterprise" if "eap" in km else "wep" if km == "none" else "wpa2")
            res.append({"name": f[0], "auth": auth, "cipher": None, "auto_connect": f[2] == "yes", "auth_raw": km})
            if len(res) >= 40:
                break
        return res


class MemoryWifi(WifiBackend):
    """Simulated Wi-Fi for tests / UI work. Change .current / .networks / .saved freely."""
    name, label = "memory", "Simulated Wi-Fi (developer mode)"

    def __init__(self):
        self.last_error: str | None = None
        self.current: dict | None = {"interface": "Wi-Fi", "state": "connected", "connected": True,
                                     "ssid": "HomeWiFi", "bssid": "A4:2B:B0:11:22:33", "auth_raw": "WPA2-Personal",
                                     "cipher_raw": "CCMP", "signal": 86, "radio": "802.11ax", "band": "5 GHz",
                                     "channel": 44, "profile": "HomeWiFi", "rx_mbps": 866, "tx_mbps": 866,
                                     "description": "Simulated Wi-Fi 6 adapter", "mac": "3C:A9:F4:10:20:30"}
        self.networks: list[dict] = [
            {"ssid": "HomeWiFi", "bssid": "A4:2B:B0:11:22:33", "auth_raw": "WPA2-Personal", "cipher_raw": "CCMP",
             "signal": 86, "channel": 44, "band": "5 GHz", "radio": "802.11ax"},
            {"ssid": "Neighbour_5G", "bssid": "10:7B:44:AA:BB:01", "auth_raw": "WPA3-Personal", "cipher_raw": "GCMP",
             "signal": 41, "channel": 149, "band": "5 GHz", "radio": "802.11ax"},
            {"ssid": "CoffeeShop", "bssid": "F0:9F:C2:00:00:07", "auth_raw": "Open", "cipher_raw": "None",
             "signal": 22, "channel": 6, "band": "2.4 GHz", "radio": "802.11n"},
        ]
        self.saved: list[dict] = [
            {"name": "HomeWiFi", "auth_raw": "WPA2-Personal", "cipher_raw": "CCMP", "auto_connect": True},
            {"name": "Airport_Free_WiFi", "auth_raw": "Open", "cipher_raw": "None", "auto_connect": True},
        ]
        self.supported = True

    def available(self) -> tuple[bool, str | None]:
        return (True, None) if self.supported else (False, "No Wi-Fi adapter")

    def interfaces(self) -> list[dict]:
        if not self.current:
            return [{"interface": "Wi-Fi", "state": "disconnected", "connected": False, "ssid": None, "bssid": None,
                     "auth": "unknown", "cipher": "none", "auth_raw": None, "cipher_raw": None, "signal": None,
                     "radio": None, "band": None, "channel": None, "profile": None, "rx_mbps": None,
                     "tx_mbps": None, "description": None, "mac": None}]
        c = dict(self.current)
        c["auth"], c["cipher"] = norm_auth(c.get("auth_raw"), c.get("cipher_raw")), norm_cipher(c.get("cipher_raw"))
        c["bssid"] = norm_mac(c.get("bssid"))
        return [c]

    def nearby(self) -> list[dict]:
        return [dict(n, hidden=not n["ssid"], bssid=norm_mac(n["bssid"]), auth=norm_auth(n["auth_raw"],
                                                                                          n["cipher_raw"]),
                     cipher=norm_cipher(n["cipher_raw"])) for n in self.networks]

    def profiles(self) -> list[dict]:
        return [{"name": s["name"], "auth": norm_auth(s["auth_raw"], s["cipher_raw"]),
                 "cipher": norm_cipher(s["cipher_raw"]), "auto_connect": s["auto_connect"],
                 "auth_raw": s["auth_raw"]} for s in self.saved]


def pick_wifi() -> WifiBackend:
    forced = os.environ.get("CYBERHUB_WIFI_BACKEND", "").strip().lower()
    if forced == "memory" or (not forced and os.environ.get("CYBERHUB_NETWORK_BACKEND", "").lower() == "memory"):
        return MemoryWifi()
    if forced == "none":
        return WifiBackend()
    if forced == "windows" or (not forced and IS_WINDOWS):
        return WindowsWifi()
    if forced == "nmcli" or (not forced and IS_LINUX and shutil.which("nmcli")):
        return NmcliWifi()
    return WifiBackend()


# ====================================================================== OS probes
PS_ROUTES_NEIGHBOURS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric |
       Select-Object NextHop, InterfaceIndex, InterfaceAlias, RouteMetric)
$n = @(Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.LinkLayerAddress } |
       Select-Object IPAddress, LinkLayerAddress, InterfaceAlias, @{n='State';e={"$($_.State)"}})
@{ routes = $r; neighbors = $n } | ConvertTo-Json -Depth 3 -Compress
"""


def parse_arp_a(text: str) -> list[dict]:
    """Windows `arp -a` / BSD `arp -an` fallback (language-independent: matches IP + MAC shapes)."""
    out = []
    iface = None
    for line in text.splitlines():
        m_if = re.match(r"^\S.*?(\d+\.\d+\.\d+\.\d+)\s+---", line)
        if m_if:
            iface = m_if.group(1)
            continue
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", line)
        if m:
            parts = re.split(r"[:-]", m.group(2))
            mac = norm_mac("".join(p.zfill(2) for p in parts))
            if mac:
                out.append({"ip": m.group(1), "mac": mac, "interface": iface, "state": "reachable"})
    return out


def parse_proc_arp(text: str) -> list[dict]:
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[2] != "0x0":
            mac = norm_mac(f[3])
            if mac:
                out.append({"ip": f[0], "mac": mac, "interface": f[5], "state": "reachable"})
    return out


def parse_proc_route(text: str) -> list[dict]:
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 8 and f[1] == "00000000" and f[7] == "00000000":
            try:
                gw = socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
            except (ValueError, struct.error):
                continue
            if gw != "0.0.0.0":
                out.append({"ip": gw, "interface": f[0], "metric": int(f[6]) if f[6].isdigit() else 0})
    return sorted(out, key=lambda g: g["metric"])


class NetProbe:
    name, label = "system", "This computer"

    def __init__(self):
        self.wifi: WifiBackend = pick_wifi()
        self._win_cache: tuple[float, dict | None] = (0.0, None)

    # ---------------------------------------------------------------- sockets
    def connections(self) -> list[Any]:
        return psutil.net_connections(kind="inet")

    def interfaces(self) -> list[dict]:
        out = []
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
        except Exception:                                       # pragma: no cover
            return out
        for name, items in addrs.items():
            st = stats.get(name)
            if st is not None and not st.isup:
                continue
            mac = next((norm_mac(a.address) for a in items if a.family == psutil.AF_LINK), None)
            for a in items:
                if a.family != socket.AF_INET or not a.netmask:
                    continue
                try:
                    itf = ipaddress.ip_interface(f"{a.address}/{a.netmask}")
                except ValueError:
                    continue
                if itf.ip.is_loopback:
                    continue
                out.append({"name": name, "ip": str(itf.ip), "prefix": itf.network.prefixlen,
                            "network": str(itf.network), "mac": mac,
                            "virtual": any(h in name.lower() for h in VIRTUAL_HINTS),
                            "speed_mbps": getattr(st, "speed", None) or None})
        return out

    # ---------------------------------------------------------------- routes / ARP
    def _windows_tables(self) -> dict:
        ts, data = self._win_cache
        if data is not None and time.monotonic() - ts < 5:
            return data
        raw = run_powershell_json(PS_ROUTES_NEIGHBOURS, timeout=15) or {}
        routes = raw.get("routes") or []
        neigh = raw.get("neighbors") or []
        routes = routes if isinstance(routes, list) else [routes]
        neigh = neigh if isinstance(neigh, list) else [neigh]
        data = {
            "gateways": [{"ip": r.get("NextHop"), "interface": r.get("InterfaceAlias"),
                          "metric": r.get("RouteMetric") or 0} for r in routes
                         if r.get("NextHop") and r.get("NextHop") != "0.0.0.0"],
            "neighbours": [{"ip": n.get("IPAddress"), "mac": norm_mac(n.get("LinkLayerAddress")),
                            "interface": n.get("InterfaceAlias"), "state": str(n.get("State") or "").lower()}
                           for n in neigh if n.get("IPAddress")],
        }
        if not raw:                                              # PowerShell missing / failed -> arp -a
            rc, out, _ = run_cmd_full(["arp", "-a"], timeout=8)
            data["neighbours"] = parse_arp_a(out) if rc == 0 else []
        self._win_cache = (time.monotonic(), data)
        return data

    def gateways(self) -> list[dict]:
        if IS_WINDOWS:
            return self._windows_tables()["gateways"]
        try:
            with open("/proc/net/route", encoding="ascii") as f:
                return parse_proc_route(f.read())
        except OSError:
            return []

    def neighbours(self) -> list[dict]:
        if IS_WINDOWS:
            rows = self._windows_tables()["neighbours"]
        else:
            try:
                with open("/proc/net/arp", encoding="ascii") as f:
                    rows = parse_proc_arp(f.read())
            except OSError:
                rc, out, _ = run_cmd_full(["arp", "-an"], timeout=8)
                rows = parse_arp_a(out) if rc == 0 else []
        keep = []
        for r in rows:
            mac = r.get("mac")
            if not mac or mac_is_multicast(mac) or r.get("state") in ("unreachable", "incomplete"):
                continue
            if ip_scope(r["ip"]) in ("multicast", "invalid", "unspecified") or r["ip"].endswith(".255"):
                continue
            keep.append(r)
        return keep

    def refresh_neighbours(self) -> None:
        self._win_cache = (0.0, None)

    # ---------------------------------------------------------------- active probes (LAN scan only)
    def nudge(self, hosts: list[str]) -> None:
        """An empty UDP datagram to the discard port makes the OS resolve each address with ARP."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setblocking(False)
            for h in hosts:
                try:
                    s.sendto(b"", (h, 9))
                except OSError:
                    pass
        finally:
            s.close()

    def tcp_probe(self, ip: str, port: int, timeout: float = 0.4) -> str:
        """open | closed (answered with a reset) | filtered (no answer)."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return "open"
        except ConnectionRefusedError:
            return "closed"
        except OSError:
            return "filtered"
        finally:
            s.close()

    def nbns_name(self, ip: str, timeout: float = 0.6, port: int = 137) -> dict | None:
        tid = secrets.randbelow(0xFFFF)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(_nbns_query(tid), (ip, port))
            data, _ = s.recvfrom(2048)
            return parse_nbns_response(data, tid)
        except OSError:
            return None
        finally:
            s.close()

    def reverse_dns(self, ip: str) -> str | None:
        try:
            name = socket.gethostbyaddr(ip)[0]
            return name if name and name != ip else None
        except (OSError, UnicodeError):
            return None


class MemoryNet(NetProbe):
    """Simulated home network: router + a few devices; LAN scan 'finds' the quiet ones."""
    name, label = "memory", "Simulated network (developer mode)"

    def __init__(self):
        super().__init__()
        self.wifi = MemoryWifi()
        self.fake_connections: list | None = None
        self.ifaces = [{"name": "Wi-Fi", "ip": "192.168.50.23", "prefix": 24, "network": "192.168.50.0/24",
                        "mac": "3C:A9:F4:10:20:30", "virtual": False, "speed_mbps": 866}]
        self.gws = [{"ip": "192.168.50.1", "interface": "Wi-Fi", "metric": 25}]
        self.table: dict[str, str] = {"192.168.50.1": "A4:2B:B0:00:00:01", "192.168.50.10": "B8:27:EB:12:34:56"}
        self.hidden: dict[str, str] = {"192.168.50.31": "DA:11:22:33:44:55", "192.168.50.40": "00:0C:29:AB:CD:EF",
                                       "192.168.50.77": "00:00:0C:01:02:03"}
        self.ports: dict[str, dict[int, str]] = {"192.168.50.1": {80: "open", 443: "open", 53: "open"},
                                                  "192.168.50.10": {22: "open"},
                                                  "192.168.50.40": {445: "open", 139: "open", 3389: "open"},
                                                  "192.168.50.77": {23: "open", 554: "open", 80: "open"}}
        self.names: dict[str, dict] = {"192.168.50.40": {"name": "DESKTOP-SYED", "group": "WORKGROUP", "mac": None}}
        self.dns: dict[str, str] = {"192.168.50.1": "router.home"}
        self.nudged: list[str] = []

    def connections(self) -> list[Any]:
        return list(self.fake_connections) if self.fake_connections is not None else super().connections()

    def interfaces(self) -> list[dict]:
        return [dict(i) for i in self.ifaces]

    def gateways(self) -> list[dict]:
        return [dict(g) for g in self.gws]

    def neighbours(self) -> list[dict]:
        return [{"ip": ip, "mac": norm_mac(mac), "interface": "Wi-Fi", "state": "reachable"}
                for ip, mac in self.table.items()]

    def nudge(self, hosts: list[str]) -> None:
        self.nudged += hosts
        for h in hosts:
            if h in self.hidden:
                self.table[h] = self.hidden[h]

    def tcp_probe(self, ip: str, port: int, timeout: float = 0.4) -> str:
        return self.ports.get(ip, {}).get(port, "closed" if ip in self.table else "filtered")

    def nbns_name(self, ip: str, timeout: float = 0.6, port: int = 137) -> dict | None:
        return self.names.get(ip)

    def reverse_dns(self, ip: str) -> str | None:
        return self.dns.get(ip)


def pick_probe() -> NetProbe:
    return MemoryNet() if os.environ.get("CYBERHUB_NETWORK_BACKEND", "").strip().lower() == "memory" else NetProbe()
