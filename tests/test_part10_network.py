"""
Cyber Hub Backend - Part 10 tests: Network Monitor & Wi-Fi
Developed by Syed Muhammad Tayyab

Connections are REAL (sockets opened by the test show up with this process),
plus fake psutil rows fed through MemoryNet.fake_connections for the red-flag
cases (Metasploit / Tor ports, someone on the internet in your RDP, port-scan
behaviour). Those fake rows point at real child processes, so the program /
path / LOLBin checks run on real files. LAN + Wi-Fi use the simulators
(CYBERHUB_NETWORK_BACKEND=memory); the Windows netsh / arp / route and Linux
nmcli / proc parsers are tested with real-shaped output. The firewall is the
Part 9 in-memory simulator, so every one-click fix is real firewall state.
"""
import asyncio
import os
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from collections import namedtuple

import psutil
import pytest
from fastapi.testclient import TestClient

from cyberhub.config import Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import netprobe as npb
from cyberhub.services.firewall_backends import BackendError
from cyberhub.services.network import NetworkService, network_loop
from cyberhub.services.platform_tools import CACHE

PW = "Cyb3r!Hub#2026"

# Same shape as psutil's own connection tuples (their module moved between psutil 5 / 6 / 7).
addr = namedtuple("addr", "ip port")
sconn = namedtuple("sconn", "fd family type laddr raddr status pid")


@pytest.fixture()
def env(tmp_path, monkeypatch):
    for d in ("quick", "full", "watched"):
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
    return tmp_path


def _login(cl, user="syed"):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": user, "display_name": "Syed", "password": PW})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": user, "password": PW})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture()
def c(env):
    CACHE.clear()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        yield cl


def net(c) -> NetworkService:
    return c.app.state.network


def mem(c) -> npb.MemoryNet:
    return c.app.state.network.probe


def as_standard(c):
    c.post("/api/account/users", json={"username": "kid", "display_name": "K", "password": PW, "role": "standard"})
    admin = c.headers["X-CyberHub-Session"]
    r = c.post("/api/account/login", json={"username": "kid", "password": PW})
    c.headers["X-CyberHub-Session"] = r.json()["session_token"]

    def back():
        c.headers["X-CyberHub-Session"] = admin
    return back


@pytest.fixture()
def procs(tmp_path):
    """Real child processes: a clean one (/usr/bin/sleep) and a 'powershell.exe' in a Downloads folder."""
    started = []
    sleep = shutil.which("sleep")

    def spawn(name: str | None = None, folder: str | None = None):
        exe = sleep
        if name:
            d = tmp_path / (folder or "bin")
            d.mkdir(parents=True, exist_ok=True)
            exe = str(d / name)
            shutil.copy(sleep, exe)
            os.chmod(exe, 0o755)
        p = subprocess.Popen([exe, "60"])
        started.append(p)
        for _ in range(50):                      # wait until /proc shows the new image
            try:
                if psutil.Process(p.pid).exe() == os.path.realpath(exe):
                    break
            except psutil.Error:
                pass
            time.sleep(0.02)
        return p
    yield spawn
    for p in started:
        p.kill()
        p.wait()


def tcp(pid, lip, lport, rip=None, rport=None, status="ESTABLISHED", family=socket.AF_INET):
    return sconn(-1, family, socket.SOCK_STREAM, addr(lip, lport), addr(rip, rport) if rip else (), status, pid)


def udp(pid, lip, lport, rip=None, rport=None):
    return sconn(-1, socket.AF_INET, socket.SOCK_DGRAM, addr(lip, lport), addr(rip, rport) if rip else (), "NONE",
                 pid)


# ====================================================================== parsers (Windows / Linux output)
NETSH_IF = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 1b2c3d4e-0000-1111-2222-333344445555
    Physical address       : 3c:a9:f4:10:20:30
    Interface type         : Primary
    State                  : connected
    SSID                   : Syed Home
    AP BSSID               : a4:2b:b0:11:22:33
    Band                   : 5 GHz
    Channel                : 44
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
    Signal                 : 92%
    Profile                : Syed Home
    QoS MSCS Configured         : 0

    Hosted network status  : Not available
"""

NETSH_NETS = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : Syed Home
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : a4:2b:b0:11:22:33
         Signal             : 92%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 44
    BSSID 2                 : a4:2b:b0:11:22:34
         Signal             : 60%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6

SSID 2 :
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 10:7b:44:aa:bb:01
         Signal             : 30%
         Channel            : 149

SSID 3 : Cafe
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : f0:9f:c2:00:00:07
         Signal             : 20%
         Channel            : 1
"""

NETSH_PROFILES = """
Profiles on interface Wi-Fi:

Group policy profiles (read only)
---------------------------------
    <None>

User profiles
-------------
    All User Profile     : Syed Home
    All User Profile     : Airport Free WiFi
"""

NETSH_PROFILE = """
Profile Airport Free WiFi on interface Wi-Fi:
=======================================================================

Applied: All User Profile

Profile information
-------------------
    Version                : 1
    Type                   : Wireless LAN
    Name                   : Airport Free WiFi
    Control options        :
        Connection mode    : Connect automatically
        Network broadcast  : Connect only if this network is broadcasting

Security settings
-----------------
    Authentication         : Open
    Cipher                 : None
    Security key           : Absent
"""


def test_parse_netsh_interfaces():
    [i] = npb.parse_netsh_interfaces(NETSH_IF)
    assert i["interface"] == "Wi-Fi" and i["connected"] and i["ssid"] == "Syed Home"
    assert i["bssid"] == "A4:2B:B0:11:22:33" and i["mac"] == "3C:A9:F4:10:20:30"   # colons inside values kept
    assert (i["auth"], i["cipher"], i["signal"], i["channel"], i["rx_mbps"]) == ("wpa2", "ccmp", 92, 44, 1201)
    assert i["band"] == "5 GHz" and i["profile"] == "Syed Home"
    dis = npb.parse_netsh_interfaces("    Name : Wi-Fi\n    State : disconnected\n")
    assert dis[0]["connected"] is False


def test_parse_netsh_networks_and_profiles():
    aps = npb.parse_netsh_networks(NETSH_NETS)
    assert len(aps) == 4
    assert [a["bssid"] for a in aps[:2]] == ["A4:2B:B0:11:22:33", "A4:2B:B0:11:22:34"]
    assert aps[1]["band"] == "2.4 GHz" and aps[1]["signal"] == 60
    assert aps[2]["hidden"] and aps[2]["ssid"] == ""
    assert aps[3]["auth"] == "open" and aps[3]["cipher"] == "none"
    assert npb.parse_netsh_profile_names(NETSH_PROFILES) == ["Syed Home", "Airport Free WiFi"]
    p = npb.parse_netsh_profile(NETSH_PROFILE)
    assert p["auth"] == "open" and p["auto_connect"] is True


def test_windows_wifi_never_reads_keys_and_reports_location_permission(monkeypatch):
    calls = []

    def fake(args, timeout=5.0, env=None):
        calls.append(args)
        if args[2:4] == ["show", "interfaces"]:
            return 1, "Network shell commands need location permission to access WLAN information.", ""
        if args[2:4] == ["show", "profiles"]:
            return 0, NETSH_PROFILES, ""
        if args[2:4] == ["show", "profile"]:
            return 0, NETSH_PROFILE, ""
        return 0, NETSH_NETS, ""
    monkeypatch.setattr(npb, "run_cmd_full", fake)
    w = npb.WindowsWifi()
    assert w.interfaces() == [] and "Location" in w.last_error
    saved = w.profiles()
    assert {s["name"] for s in saved} == {"Syed Home", "Airport Free WiFi"}
    assert ["netsh", "wlan", "show", "profile", "name=Airport Free WiFi"] in calls     # one argv item, no shell
    assert not any("key=clear" in " ".join(a) for a in calls)                         # never reads passwords


def test_parse_nmcli():
    out = ("*:Syed\\:Home:A4\\:2B\\:B0\\:11\\:22\\:33:WPA2 WPA3:88:36:5180 MHz:wlan0\n"
           " :Cafe:F0\\:9F\\:C2\\:00\\:00\\:07::20:1:2412 MHz:wlan0\n"
           " :Corp:00\\:11\\:22\\:33\\:44\\:55:WPA2 802.1X:50:11:2462 MHz:wlan0\n")
    rows = npb.parse_nmcli_wifi(out)
    assert rows[0]["ssid"] == "Syed:Home" and rows[0]["bssid"] == "A4:2B:B0:11:22:33" and rows[0]["in_use"]
    assert [r["auth"] for r in rows] == ["wpa2/wpa3", "open", "wpa2-enterprise"]
    assert rows[0]["band"] == "5 GHz" and rows[1]["band"] == "2.4 GHz"
    assert npb.split_nmcli("a\\:b:c\\\\d:") == ["a:b", "c\\d", ""]


@pytest.mark.parametrize("auth,cipher,expect", [
    ("Open", "None", "open"), ("Open", "WEP", "wep"), ("Shared", "WEP", "wep"), ("WPA-Personal", "TKIP", "wpa"),
    ("WPA2-Personal", "CCMP", "wpa2"), ("WPA2-Enterprise", "CCMP", "wpa2-enterprise"),
    ("WPA3-Personal", "GCMP", "wpa3"), ("WPA3-Enterprise", "GCMP-256", "wpa3-enterprise"),
    ("WPA3-Personal Transition", "CCMP", "wpa2/wpa3"), ("OWE", "CCMP", "owe"), ("", "", "open"),
])
def test_norm_auth(auth, cipher, expect):
    assert npb.norm_auth(auth, cipher) == expect


def test_parse_arp_route_tables():
    win = """
Interface: 192.168.50.23 --- 0xb
  Internet Address      Physical Address      Type
  192.168.50.1          a4-2b-b0-00-00-01     dynamic
  192.168.50.10         b8-27-eb-12-34-56     dynamic
  192.168.50.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
    rows = npb.parse_arp_a(win)
    assert rows[0] == {"ip": "192.168.50.1", "mac": "A4:2B:B0:00:00:01", "interface": "192.168.50.23",
                       "state": "reachable"}
    assert len(rows) == 3                                # ff:ff... dropped by norm_mac, multicast kept for later filter
    mac_os = "? (192.168.1.1) at 0:11:22:a:b:c on en0 ifscope [ethernet]"
    assert npb.parse_arp_a(mac_os)[0]["mac"] == "00:11:22:0A:0B:0C"
    proc_arp = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n"
                "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n")
    assert npb.parse_proc_arp(proc_arp) == [{"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF", "interface": "wlan0",
                                             "state": "reachable"}]
    route = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
             "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
             "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n")
    assert npb.parse_proc_route(route) == [{"ip": "192.168.1.1", "interface": "wlan0", "metric": 600}]


def test_neighbour_filter_drops_multicast_broadcast_and_dead_entries():
    rows = [{"ip": "224.0.0.22", "mac": "01:00:5E:00:00:16", "state": "reachable"},
            {"ip": "192.168.50.255", "mac": "AA:00:00:00:00:01", "state": "reachable"},
            {"ip": "192.168.50.9", "mac": "AA:00:00:00:00:02", "state": "incomplete"},
            {"ip": "192.168.50.8", "mac": "AA:00:00:00:00:03", "state": "stale"}]
    p = npb.NetProbe()
    p._windows_tables = lambda: {"gateways": [], "neighbours": rows}
    import cyberhub.services.netprobe as mod
    old = mod.IS_WINDOWS
    mod.IS_WINDOWS = True
    try:
        assert [r["ip"] for r in p.neighbours()] == ["192.168.50.8"]
    finally:
        mod.IS_WINDOWS = old


def test_ip_scope_and_scan_limits():
    assert npb.ip_scope("127.0.0.1") == "local" and npb.ip_scope("::1") == "local"
    assert npb.ip_scope("192.168.1.4") == "lan" and npb.ip_scope("fe80::1%eth0") == "lan"
    assert npb.ip_scope("100.101.102.103") == "lan"          # CGNAT / Tailscale
    assert npb.ip_scope("::ffff:8.8.8.8") == "internet" and npb.ip_scope("0.0.0.0") == "unspecified"
    assert npb.ip_scope("239.255.255.250") == "multicast"
    import ipaddress
    assert npb.is_scannable_network(ipaddress.ip_network("192.168.0.0/24"))
    assert not npb.is_scannable_network(ipaddress.ip_network("8.8.8.0/24"))
    assert not npb.is_scannable_network(ipaddress.ip_network("100.64.0.0/24"))   # carrier NAT is not your LAN
    net, hosts = npb.scan_hosts("10.1.2.3", ipaddress.ip_network("10.0.0.0/8"))
    assert str(net) == "10.1.2.0/24" and len(hosts) == 253 and "10.1.2.3" not in hosts
    net, hosts = npb.scan_hosts("192.168.4.7", ipaddress.ip_network("192.168.4.0/22"))
    assert len(hosts) == 1021


def test_oui_parsers():
    csv_text = ("Registry,Assignment,Organization Name,Organization Address\n"
                "MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",\"No.388 Ning Qiao Road\"\n"
                "MA-L,08EA44,Extreme Networks Headquarters,\"2121 RDU Center Drive\"\n")
    assert npb.parse_oui_text(csv_text) == {"286FB9": "Nokia Shanghai Bell Co., Ltd.",
                                            "08EA44": "Extreme Networks Headquarters"}
    txt = ("OUI/MA-L                                                    Organization\n"
           "28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd.\n"
           "286FB9     (base 16)\t\tNokia Shanghai Bell Co., Ltd.\n")
    assert npb.parse_oui_text(txt) == {"286FB9": "Nokia Shanghai Bell Co., Ltd."}
    manuf = ("# Wireshark manuf\n00:00:0C\tCisco\tCisco Systems, Inc\n00:1B:C5:00:00/36\tConverging\tConv\n"
             "B8:27:EB\tRaspberr\tRaspberry Pi Foundation\n")
    assert npb.parse_oui_text(manuf) == {"00000C": "Cisco Systems, Inc", "B827EB": "Raspberry Pi Foundation"}


def test_nbns_query_against_a_real_udp_responder():
    """Build a genuine NBSTAT reply on 127.0.0.1 and read the PC name + workgroup + MAC back."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def answer():
        q, who = srv.recvfrom(1024)
        tid = q[:2]
        assert q[12] == 0x20 and q[13:15] == b"CK"            # '*' encoded
        names = [(b"DESKTOP-SYED".ljust(15), 0x00, 0x0400), (b"WORKGROUP".ljust(15), 0x00, 0x8400),
                 (b"DESKTOP-SYED".ljust(15), 0x20, 0x0400)]
        rdata = bytes([len(names)]) + b"".join(n + bytes([s]) + struct.pack(">H", f) for n, s, f in names) + \
            bytes.fromhex("3ca9f4102030") + b"\x00" * 40
        resp = tid + b"\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" + q[12:46] + struct.pack(">HHIH", 0x21, 1, 0,
                                                                                            len(rdata)) + rdata
        srv.sendto(resp, who)
    t = threading.Thread(target=answer)
    t.start()
    r = npb.NetProbe().nbns_name("127.0.0.1", timeout=2, port=port)
    t.join()
    srv.close()
    assert r == {"name": "DESKTOP-SYED", "group": "WORKGROUP", "mac": "3C:A9:F4:10:20:30"}
    assert npb.parse_nbns_response(b"\x00" * 10) is None


def test_tcp_probe_real_sockets():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    p = npb.NetProbe()
    assert p.tcp_probe("127.0.0.1", s.getsockname()[1]) == "open"
    port = s.getsockname()[1]
    s.close()
    assert p.tcp_probe("127.0.0.1", port) == "closed"


def test_mac_helpers():
    assert npb.norm_mac("a4-2b-b0-0-0-1") is None and npb.norm_mac("a42bb0000001") == "A4:2B:B0:00:00:01"
    assert npb.mac_is_randomized("DA:11:22:33:44:55") and not npb.mac_is_randomized("A4:2B:B0:00:00:01")
    assert npb.mac_is_multicast("01:00:5E:00:00:16")


# ====================================================================== real connections & listening ports
def test_real_connections_show_this_process(c):
    srv = socket.socket()
    srv.bind(("0.0.0.0", 0))
    srv.listen()
    port = srv.getsockname()[1]
    cli = socket.create_connection(("127.0.0.1", port))
    acc, _ = srv.accept()
    try:
        r = c.get(f"/api/network/connections?pid={os.getpid()}&include_listening=true&limit=5000").json()
        mine = [x for x in r["items"] if port in (x["local_port"], x["remote_port"])]
        kinds = {x["direction"] for x in mine}
        assert {"listening", "incoming", "outgoing"} <= kinds
        x = next(m for m in mine if m["direction"] == "listening")
        assert x["process"] == psutil.Process().name() and x["create_time"] and x["cyberhub"] is True
        assert x["scope"] == "network" and x["flags"] == []
        assert r["counts"]["listening"] >= 1 and r["counts"]["established"] >= 2
        # default view hides listeners; search works on the port
        r2 = c.get(f"/api/network/connections?search={port}").json()
        assert r2["total"] == 2 and all(i["direction"] != "listening" for i in r2["items"])
        lst = c.get("/api/network/listening").json()
        me = next(m for m in lst["items"] if m["port"] == port)
        assert me["exposure"] == "all" and me["firewall"]["verdict"] == "blocked"
        assert "default" in me["firewall"]["reason"]
        assert c.get("/api/network/listening?exposed_only=true").json()["counts"]["exposed"] >= 1
        g = c.get("/api/network/connections/by-process").json()
        row = next(i for i in g["items"] if i["pid"] == os.getpid())
        assert f"tcp/{port}" in row["listening"] and row["connections"] >= 3
    finally:
        for s in (acc, cli, srv):
            s.close()


def test_loopback_listener_needs_no_firewall(c):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    try:
        me = next(m for m in c.get("/api/network/listening").json()["items"] if m["port"] == srv.getsockname()[1])
        assert me["exposure"] == "local" and me["firewall"]["verdict"] == "not_needed" and me["severity"] == "info"
    finally:
        srv.close()


def test_firewall_verdict_follows_part9_rules(c, procs):
    """allowed by an 'allow app' rule -> risky listener = medium + fix; fix = Part 9 port block -> blocked."""
    p = procs()
    exe = psutil.Process(p.pid).exe()
    mem(c).fake_connections = [tcp(p.pid, "0.0.0.0", 3389, status="LISTEN")]
    li = c.get("/api/network/listening").json()["items"][0]
    assert li["risky_service"] == "Remote Desktop" and li["firewall"]["verdict"] == "blocked"
    assert li["severity"] == "low"                                   # only the firewall keeps it closed
    c.post("/api/firewall/allow/app", json={"path": exe, "profiles": ["private"]})
    li = c.get("/api/network/listening").json()["items"][0]
    assert li["firewall"]["verdict"] == "allowed" and li["firewall"]["profile"] == "private"
    assert li["severity"] == "medium"
    f = next(x for x in c.get("/api/network/findings?refresh=true").json()["findings"] if x["category"] == "listening")
    assert f["fix"] == {"action": "block_port", "port": 3389, "protocol": "tcp"}
    r = c.post(f"/api/network/findings/{f['id']}/fix")
    assert r.status_code == 200 and r.json()["result"]["kind"] == "port"
    block_id = r.json()["result"]["id"]
    li = c.get("/api/network/listening").json()["items"][0]
    assert li["firewall"]["verdict"] == "blocked" and "Block" in li["firewall"]["reason"]
    # firewall off for the active profile -> open; the most exposed active profile decides
    fw = c.app.state.firewall
    fw.backend._profiles["private"]["enabled"] = False
    fw.invalidate()
    li = c.get("/api/network/listening").json()["items"][0]
    assert li["firewall"]["verdict"] == "open" and li["severity"] == "high"         # firewall off + RDP = high
    fw.backend.network = [{"name": "Cafe", "interface": "Wi-Fi", "profile": "public", "internet": True}]
    fw.backend._profiles["public"]["default_inbound"] = "allow"
    fw.invalidate()
    li = c.get("/api/network/listening").json()["items"][0]
    assert li["firewall"]["verdict"] == "blocked"                 # the Cyber Hub port block covers every profile
    assert c.delete(f"/api/firewall/blocks/{block_id}").status_code == 200
    li = c.get("/api/network/listening").json()["items"][0]
    assert li["firewall"]["profile"] == "public" and li["severity"] == "high"


def test_inbound_verdict_unit(c):
    fw = c.app.state.firewall
    assert fw.inbound_verdict(445, "tcp", None)["verdict"] == "blocked"               # SMB rule is disabled
    fw.backend._rules["FPS-SMB-In-TCP"]["enabled"] = True
    fw.invalidate()
    v = fw.inbound_verdict(445, "tcp", None)                                          # kernel listener (System)
    assert v["verdict"] == "allowed" and v["scope"] == "limited" and v["program_known"] is False
    assert fw.inbound_verdict(445, "udp", None)["verdict"] == "blocked"               # protocol must match
    assert fw.inbound_verdict(445, "tcp", "/usr/bin/sleep")["verdict"] == "blocked"   # 'System' rule != program
    assert fw.inbound_verdict(23, "tcp", None)["verdict"] == "blocked"                # group-policy block rule
    fw.backend._profiles["private"]["allow_inbound_rules"] = False                   # shields up
    fw.invalidate()
    assert "Block all incoming" in fw.inbound_verdict(445, "tcp", None)["reason"]


# ====================================================================== red-flag connections (fake rows, real processes)
def test_suspicious_connection_flags_and_fix(c, procs):
    clean = procs()
    bad = procs("powershell.exe", "Downloads")
    mem(c).fake_connections = [
        tcp(clean.pid, "192.168.50.23", 50001, "203.0.113.5", 4444),           # Metasploit port
        tcp(clean.pid, "192.168.50.23", 50002, "203.0.113.6", 443),            # normal HTTPS
        tcp(bad.pid, "192.168.50.23", 50003, "198.51.100.7", 443),             # LOLBin in Downloads online
        tcp(clean.pid, "192.168.50.23", 50004, "192.168.50.10", 4444),         # LAN: no port flag
    ]
    r = c.get("/api/network/connections").json()
    by = {i["local_port"]: i for i in r["items"]}
    assert by[50001]["flags"] == ["suspicious_port"] and "Metasploit" in by[50001]["reasons"][0]
    assert by[50001]["risk_level"] == "medium" and by[50001]["service"] is None
    assert by[50002]["flags"] == [] and by[50002]["service"] == "HTTPS"
    assert set(by[50003]["flags"]) == {"suspicious_location", "script_host"} and by[50003]["risk_level"] == "high"
    assert by[50003]["process"] == "powershell.exe"
    assert by[50004]["scope"] == "lan" and by[50004]["flags"] == []
    assert r["counts"]["flagged"] == 2 and r["counts"]["internet"] == 3 and r["counts"]["lan"] == 1
    assert [i["local_port"] for i in c.get("/api/network/connections?flagged=true").json()["items"]] == [50003, 50001]
    assert c.get("/api/network/connections?scope=lan").json()["total"] == 1
    # findings + one-click block of the remote address through Part 9
    fs = c.get("/api/network/findings?refresh=true").json()
    f = next(x for x in fs["findings"] if x["data"].get("remote_port") == 4444)
    assert f["severity"] == "medium" and f["fix"] == {"action": "block_remote_ip", "ip": "203.0.113.5"}
    assert fs["score"] < 100
    res = c.post(f"/api/network/findings/{f['id']}/fix").json()["result"]
    assert res["kind"] == "ip" and res["target"] == "203.0.113.5" and res["status"] == "active"
    assert "Network monitor" in res["reason"]
    # the connection is now marked as covered by that block
    after = {i["local_port"]: i for i in c.get("/api/network/connections").json()["items"]}
    assert "blocked_target" in after[50001]["flags"] and after[50001]["blocked_by"] == res["id"]
    assert c.post("/api/network/findings/nbogus/fix").status_code == 404


def test_extra_watch_ports_setting(c, procs):
    p = procs()
    mem(c).fake_connections = [tcp(p.pid, "192.168.50.23", 50010, "203.0.113.8", 8888)]
    assert c.get("/api/network/connections").json()["items"][0]["flags"] == []
    assert c.patch("/api/settings", json={"network_extra_suspicious_ports": ["abc"]}).status_code == 422
    assert c.patch("/api/settings", json={"network_extra_suspicious_ports": ["8888"]}).status_code == 200
    item = c.get("/api/network/connections").json()["items"][0]
    assert item["flags"] == ["suspicious_port"] and "watch list" in item["reasons"][0]


def test_someone_on_the_internet_in_your_rdp(c, procs):
    p = procs()
    mem(c).fake_connections = [tcp(p.pid, "0.0.0.0", 3389, status="LISTEN"),
                               tcp(p.pid, "192.168.50.23", 3389, "203.0.113.66", 51515)]
    r = c.get("/api/network/connections").json()["items"][0]
    assert r["direction"] == "incoming" and r["service"] == "Remote Desktop"
    assert r["flags"] == ["exposed_in_use"] and r["risk_level"] == "high"
    assert "Remote Desktop" in r["reasons"][0]


def test_scan_like_behaviour_and_block_program_fix(c, procs):
    p = procs()
    mem(c).fake_connections = [tcp(p.pid, "192.168.50.23", 40000 + i, f"203.0.113.{i}", 445, status="SYN_SENT")
                               for i in range(1, 36)]
    g = next(i for i in c.get("/api/network/connections/by-process").json()["items"] if i["pid"] == p.pid)
    assert g["syn_sent"] == 35 and g["behaviour"][0]["code"] == "scan_like" and g["risk_level"] == "high"
    f = next(x for x in c.get("/api/network/findings?refresh=true").json()["findings"] if x["category"] == "behaviour")
    assert f["severity"] == "high" and f["fix"]["action"] == "block_program"
    res = c.post(f"/api/network/findings/{f['id']}/fix").json()["result"]
    assert res["kind"] == "app" and res["target"] == psutil.Process(p.pid).exe()


def test_many_hosts_threshold(c, procs):
    p = procs()
    mem(c).fake_connections = [tcp(p.pid, "192.168.50.23", 41000 + i, f"198.51.100.{i}", 443) for i in range(1, 31)]
    assert c.patch("/api/settings", json={"network_many_hosts": 25}).status_code == 200
    g = next(i for i in c.get("/api/network/connections/by-process").json()["items"] if i["pid"] == p.pid)
    assert g["remote_hosts"] == 30 and [b["code"] for b in g["behaviour"]] == ["many_hosts"]


def test_own_engine_is_never_flagged(c):
    mem(c).fake_connections = [tcp(os.getpid(), "192.168.50.23", 50020, "203.0.113.5", 4444)]
    assert c.get("/api/network/connections").json()["items"][0]["flags"] == []


def test_udp_and_ipv6_rows(c, procs):
    p = procs()
    mem(c).fake_connections = [
        udp(p.pid, "0.0.0.0", 5353), udp(p.pid, "0.0.0.0", 61000), udp(p.pid, "192.168.50.23", 55000, "8.8.8.8", 53),
        tcp(p.pid, "::", 8080, status="LISTEN", family=socket.AF_INET6),
        tcp(p.pid, "::ffff:192.168.50.23", 50030, "::ffff:203.0.113.5", 443, family=socket.AF_INET6),
    ]
    lst = c.get("/api/network/listening").json()["items"]
    assert {(m["proto"], m["port"]) for m in lst} == {("udp", 5353), ("tcp", 8080)}       # ephemeral UDP hidden
    assert len(c.get("/api/network/listening?include_ephemeral=true").json()["items"]) == 3
    con = {i["local_port"]: i for i in c.get("/api/network/connections?include_listening=true").json()["items"]}
    assert con[55000]["status"] == "CONNECTED" and con[55000]["service"] == "DNS"
    assert con[50030]["remote_ip"] == "203.0.113.5" and con[50030]["scope"] == "internet"
    assert con[5353]["status"] == "BOUND" and con[5353]["service"] == "mDNS (Bonjour)"


def test_reverse_dns_is_opt_in_and_cached(c, procs):
    p = procs()
    mem(c).fake_connections = [tcp(p.pid, "192.168.50.23", 50040, "203.0.113.5", 443)]
    mem(c).dns["203.0.113.5"] = "edge.example.net"
    assert "remote_host" not in c.get("/api/network/connections").json()["items"][0]
    assert c.get("/api/network/connections?resolve=true").json()["items"][0]["remote_host"] == "edge.example.net"
    mem(c).dns["203.0.113.5"] = "changed.example.net"                                  # cached for 1 h
    assert c.get("/api/network/connections?resolve=true").json()["items"][0]["remote_host"] == "edge.example.net"


# ====================================================================== Wi-Fi
def test_wifi_good_network(c):
    w = c.get("/api/network/wifi").json()
    assert w["available"] and w["current"]["ssid"] == "HomeWiFi"
    assert w["current"]["assessment"]["rating"] == "good" and w["current"]["assessment"]["severity"] == "info"
    assert w["nearby_count"] == 3 and w["nearby_open"] == 1
    assert next(n for n in w["nearby"] if n["ssid"] == "HomeWiFi")["connected"] is True
    titles = [f["title"] for f in w["findings"]]
    assert titles == ["Auto-joins open network 'Airport_Free_WiFi'"]
    s = c.get("/api/network/status").json()
    assert s["wifi"]["ssid"] == "HomeWiFi" and s["wifi"]["rating"] == "good"


@pytest.mark.parametrize("auth,cipher,rating,sev", [
    ("Open", "None", "open", "high"), ("WEP", "WEP", "insecure", "critical"), ("WPA-Personal", "TKIP", "weak", "high"),
    ("WPA2-Personal", "TKIP", "weak", "medium"), ("WPA3-Personal", "GCMP", "excellent", "info"),
    ("OWE", "CCMP", "fair", "low"),
])
def test_wifi_ratings(c, auth, cipher, rating, sev):
    mem(c).wifi.current.update(auth_raw=auth, cipher_raw=cipher)
    a = c.get("/api/network/wifi?refresh=true").json()["current"]["assessment"]
    assert (a["rating"], a["severity"]) == (rating, sev)


def test_insecure_wifi_event_once_per_connection(c):
    w = mem(c).wifi
    w.current.update(ssid="CoffeeShop", bssid="F0:9F:C2:00:00:07", auth_raw="Open", cipher_raw="None")
    c.post("/api/network/watch")
    c.post("/api/network/watch")
    ev = c.get("/api/network/events?kind=insecure_wifi").json()["items"]
    assert len(ev) == 1 and ev[0]["severity"] == "high" and "CoffeeShop" in ev[0]["title"]
    hist = c.get("/api/network/wifi/history").json()
    assert hist[0]["ssid"] == "CoffeeShop" and hist[0]["rating"] == "open"
    f = c.get("/api/network/findings?refresh=true").json()
    assert any(x["category"] == "wifi" and x["severity"] == "high" for x in f["findings"])


def test_evil_twin_detection(c):
    mem(c).wifi.networks.append({"ssid": "HomeWiFi", "bssid": "66:66:66:66:66:66", "auth_raw": "Open",
                                 "cipher_raw": "None", "signal": 70, "channel": 6, "band": "2.4 GHz", "radio": None})
    w = c.get("/api/network/wifi?refresh=true").json()
    twin = next(f for f in w["findings"] if "fake copy" in f["title"])
    assert twin["severity"] == "high" and twin["data"]["bssid"] == "66:66:66:66:66:66"
    c.post("/api/network/watch")
    c.post("/api/network/watch")
    assert len(c.get("/api/network/events?kind=evil_twin").json()["items"]) == 1


def test_wifi_disconnected_and_unsupported(c):
    mem(c).wifi.current = None
    w = c.get("/api/network/wifi?refresh=true").json()
    assert w["current"] is None and w["interfaces"][0]["connected"] is False
    mem(c).wifi.supported = False
    w = c.get("/api/network/wifi?refresh=true").json()
    assert w["available"] is False and w["error"]
    assert c.get("/api/network/status").status_code == 200


# ====================================================================== LAN
def _scan(c, **body):
    r = c.post("/api/network/lan/scan", json=body)
    assert r.status_code == 202, r.text
    for _ in range(200):
        s = c.get("/api/network/lan/scan").json()
        if s["state"] != "running":
            return s
        time.sleep(0.03)
    raise AssertionError("scan did not finish")


def test_lan_passive_then_scan(c):
    lan = c.get("/api/network/lan").json()
    assert lan["network"]["name"] == "HomeWiFi" and lan["network"]["kind"] == "wifi" and lan["live"]
    assert lan["network"]["gateway"] == {"ip": "192.168.50.1", "mac": "A4:2B:B0:00:00:01", "vendor": None}
    assert lan["devices"][0]["this_pc"] and lan["counts"]["total"] == 3          # this PC + router + Pi
    s = _scan(c)
    assert s["state"] == "done" and s["found"] == 5 and s["new"] == 3 and s["subnet"] == "192.168.50.0/24"
    assert set(mem(c).nudged) >= {"192.168.50.31", "192.168.50.254"} and "192.168.50.23" not in mem(c).nudged
    devs = {d["ip"]: d for d in c.get("/api/network/lan").json()["devices"]}
    assert devs["192.168.50.1"]["device_type"] == "router" and devs["192.168.50.1"]["is_gateway"]
    assert devs["192.168.50.10"]["vendor"] == "Raspberry Pi" and devs["192.168.50.10"]["open_ports"] == [22]
    assert devs["192.168.50.40"]["device_type"] == "virtual machine" and devs["192.168.50.40"]["nb_name"] == "DESKTOP-SYED"
    assert devs["192.168.50.31"]["randomized_mac"] and devs["192.168.50.31"]["device_type"].startswith("phone")
    cam = devs["192.168.50.77"]
    assert cam["device_type"] == "camera / video recorder" and cam["severity"] == "high"
    assert {f["code"] for f in cam["flags"]} == {"port_23", "port_554"}
    assert devs["192.168.50.1"]["hostname"] == "router.home"
    # first scan builds the baseline quietly
    assert c.get("/api/network/events?kind=new_device").json()["items"] == []
    fs = c.get("/api/network/findings?refresh=true").json()["findings"]
    assert any(f["category"] == "lan" and "Telnet" in f["title"] for f in fs)
    # new device after the baseline -> alert (medium on a Home network)
    nid = c.get("/api/network/lan").json()["network"]["id"]
    assert c.post(f"/api/network/lan/networks/{nid}/home", json={"home": True, "name": "Syed Home"}).json()["home"]
    mem(c).table["192.168.50.99"] = "AC:DE:48:00:11:22"
    c.post("/api/network/watch")
    ev = c.get("/api/network/events?kind=new_device").json()["items"]
    assert len(ev) == 1 and ev[0]["severity"] == "medium" and "Syed Home" in ev[0]["title"]
    st = c.get("/api/network/status").json()["lan"]
    assert st["home"] and st["new_24h"] == 6 and st["name"] == "Syed Home"


def test_scan_refuses_public_ranges_and_runs_once(c):
    m = mem(c)
    m.ifaces[0].update(ip="203.0.113.23", network="203.0.113.0/24")
    m.gws[0]["ip"] = "203.0.113.1"
    r = c.post("/api/network/lan/scan", json={})
    assert r.status_code == 400 and "private" in r.json()["detail"]
    m.ifaces[0].update(ip="192.168.50.23", network="192.168.50.0/24")
    m.gws[0]["ip"] = "192.168.50.1"
    gate = threading.Event()
    orig = m.nudge
    m.nudge = lambda hosts: (gate.wait(5), orig(hosts))
    assert c.post("/api/network/lan/scan", json={}).status_code == 202
    assert c.post("/api/network/lan/scan", json={}).status_code == 409
    assert c.post("/api/network/lan/scan/cancel").json()["state"] == "running"
    gate.set()
    for _ in range(200):
        if c.get("/api/network/lan/scan").json()["state"] != "running":
            break
        time.sleep(0.03)
    assert c.get("/api/network/lan/scan").json()["state"] == "cancelled"
    assert c.post("/api/network/lan/scan/cancel").status_code == 409
    s = _scan(c, ports=False)
    assert s["state"] == "done"
    assert all(d["open_ports"] == [] for d in c.get("/api/network/lan").json()["devices"] if not d.get("this_pc"))


def test_no_network(c):
    mem(c).ifaces.clear()
    mem(c).gws.clear()
    lan = c.get("/api/network/lan").json()
    assert lan["network"] is None and lan["devices"] == []
    assert c.post("/api/network/lan/scan", json={}).status_code == 409
    assert c.get("/api/network/status").json()["lan"] is None


def test_gateway_change_arp_spoofing(c):
    lan = c.get("/api/network/lan").json()
    nid = lan["network"]["id"]
    assert lan["network"]["gateway_mac"] == "A4:2B:B0:00:00:01"
    mem(c).table["192.168.50.1"] = "66:77:88:99:AA:BB"                    # someone answers for the router
    c.post("/api/network/watch")
    c.post("/api/network/watch")
    ev = c.get("/api/network/events?kind=gateway_changed").json()["items"]
    assert len(ev) == 1 and ev[0]["severity"] == "high" and "66:77:88:99:AA:BB" in ev[0]["detail"]
    f = next(x for x in c.get("/api/network/findings?refresh=true").json()["findings"] if x["category"] == "lan"
             and "Router" in x["title"])
    assert f["fix"]["action"] == "accept_gateway" and f["fix_requires_admin"]
    assert c.get("/api/network/status").json()["lan"]["router_alert"] is True
    # it goes back by itself -> cleared
    mem(c).table["192.168.50.1"] = "A4:2B:B0:00:00:01"
    c.post("/api/network/watch")
    assert c.get("/api/network/events?kind=gateway_restored").json()["items"]
    assert c.post(f"/api/network/lan/networks/{nid}/accept-gateway").status_code == 409
    # changes again -> admin accepts the new router
    mem(c).table["192.168.50.1"] = "66:77:88:99:AA:BB"
    c.post("/api/network/watch")
    back = as_standard(c)
    assert c.post(f"/api/network/lan/networks/{nid}/accept-gateway").status_code == 403
    f = next(x for x in c.get("/api/network/findings?refresh=true").json()["findings"] if "Router" in x["title"])
    assert c.post(f"/api/network/findings/{f['id']}/fix").status_code == 403
    back()
    r = c.post(f"/api/network/findings/{f['id']}/fix")
    assert r.status_code == 200 and r.json()["result"]["gateway_mac"] == "66:77:88:99:AA:BB"
    assert c.get("/api/network/status").json()["lan"]["router_alert"] is False


def test_gateway_duplicate_mac(c):
    c.get("/api/network/lan")
    mem(c).table["192.168.50.66"] = "A4:2B:B0:00:00:01"
    c.post("/api/network/watch")
    c.post("/api/network/watch")
    ev = c.get("/api/network/events?kind=gateway_conflict").json()["items"]
    assert len(ev) == 1 and "192.168.50.66" in ev[0]["detail"]


def test_device_management_permissions(c):
    _scan(c)
    dev = next(d for d in c.get("/api/network/lan").json()["devices"] if d["ip"] == "192.168.50.77")
    back = as_standard(c)
    assert c.patch(f"/api/network/lan/devices/{dev['id']}", json={"label": "Garage camera"}).json()["label"] == \
        "Garage camera"
    assert c.patch(f"/api/network/lan/devices/{dev['id']}", json={"trusted": True}).status_code == 403
    assert c.delete(f"/api/network/lan/devices/{dev['id']}").status_code == 403
    nid = c.get("/api/network/lan").json()["network"]["id"]
    assert c.post(f"/api/network/lan/networks/{nid}/home", json={"home": True}).status_code == 200
    assert c.post(f"/api/network/lan/networks/{nid}/home", json={"home": False}).status_code == 403
    assert c.delete("/api/network/events").status_code == 403
    assert c.post("/api/network/oui/import", json={"text": "x"}).status_code == 403
    assert c.patch("/api/settings", json={"network_watch_enabled": False}).status_code == 403
    back()
    assert c.patch(f"/api/network/lan/devices/{dev['id']}", json={"trusted": True}).json()["trusted"] is True
    fs = c.get("/api/network/findings?refresh=true").json()["findings"]
    assert not any(f["data"].get("device_id") == dev["id"] for f in fs)                # trusted -> no findings
    assert c.get(f"/api/network/lan/devices/{dev['id']}").json()["label"] == "Garage camera"
    assert c.delete(f"/api/network/lan/devices/{dev['id']}").json()["deleted"]
    assert c.get(f"/api/network/lan/devices/{dev['id']}").status_code == 404
    assert len(c.get("/api/network/lan/networks").json()) == 1


def test_oui_import_and_update(c, tmp_path, monkeypatch):
    _scan(c)
    csv_text = ("Registry,Assignment,Organization Name,Organization Address\n"
                "MA-L,A42BB0,Example Router Co,Somewhere\nMA-L,ACDE48,Private,x\n")
    r = c.post("/api/network/oui/import", json={"text": csv_text})
    assert r.status_code == 200 and r.json()["imported"] == 2
    devs = {d["ip"]: d for d in c.get("/api/network/lan").json()["devices"]}
    assert devs["192.168.50.1"]["vendor"] == "Example Router Co"
    assert devs["192.168.50.10"]["vendor"] == "Raspberry Pi"                         # built-in still used
    f = tmp_path / "manuf"
    f.write_text("A4:2B:B0\tExample\tExample Router Company Ltd\n")
    assert c.post("/api/network/oui/import", json={"path": str(f)}).json()["source"] == "manuf"
    assert c.post("/api/network/oui/import", json={"text": "nothing useful"}).status_code == 422
    assert c.post("/api/network/oui/import", json={}).status_code == 422
    assert c.post("/api/network/oui/update", json={"url": "http://insecure.example/oui.csv"}).status_code == 400

    class Resp:
        def __init__(self, data):
            self.data = data

        def read(self, n):
            return self.data[:n]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    import cyberhub.services.network as nmod
    monkeypatch.setattr(nmod.urllib.request, "urlopen", lambda req, timeout: Resp(csv_text.encode()))
    st = c.post("/api/network/oui/update").json()
    assert st["imported"] == 2 and st["source"].startswith("https://standards-oui.ieee.org")
    assert c.get("/api/network/oui").json()["builtin"] >= 10


# ====================================================================== watch, events, graphs, status
def test_watch_new_listener_after_baseline(c):
    c.post("/api/network/watch")                                                      # baseline (silent)
    assert c.get("/api/network/events?kind=new_listener").json()["items"] == []
    p = subprocess.Popen([sys.executable, "-c", "import socket,time;s=socket.socket();s.bind(('0.0.0.0',0));"
                                                "s.listen();print(s.getsockname()[1],flush=True);time.sleep(60)"],
                         stdout=subprocess.PIPE, text=True)
    try:
        port = int(p.stdout.readline())
        assert c.post("/api/network/watch").json()["new_listeners"] == 1
        ev = c.get("/api/network/events?kind=new_listener").json()["items"]
        assert len(ev) == 1 and f"TCP {port}" in ev[0]["title"] and ev[0]["severity"] == "low"   # firewall blocks it
        assert c.post("/api/network/watch").json()["new_listeners"] == 0                       # only once
    finally:
        p.kill()
        p.wait()


def test_watch_suspicious_connection_throttled(c, procs):
    p = procs()
    mem(c).fake_connections = [tcp(p.pid, "192.168.50.23", 50001, "203.0.113.5", 9050)]
    assert c.post("/api/network/watch").json()["suspicious"] == 1
    assert c.post("/api/network/watch").json()["suspicious"] == 0
    ev = c.get("/api/network/events?kind=suspicious_connection").json()
    assert len(ev["items"]) == 1 and "Tor" in ev["items"][0]["detail"] and ev["unacknowledged"] >= 1
    assert c.patch("/api/settings", json={"network_alert_suspicious": False}).status_code == 200
    mem(c).fake_connections = [tcp(p.pid, "192.168.50.23", 50002, "203.0.113.9", 4444)]
    assert c.post("/api/network/watch").json()["suspicious"] == 0
    act = c.get("/api/activity?category=network").json()["items"]
    assert any("Suspicious connection" in a["title"] for a in act)


def test_events_ack_after_id_and_clear(c):
    n = net(c)
    a = n._event("x", "high", "one")
    b = n._event("x", "info", "two")
    ev = c.get(f"/api/network/events?after_id={a['id']}").json()
    assert [e["id"] for e in ev["items"]] == [b["id"]] and ev["last_id"] == b["id"]
    assert c.get("/api/network/events?unacknowledged=true").json()["items"][0]["id"] == a["id"]
    assert c.post("/api/network/events/ack", json={"ids": [a["id"]]}).json()["acknowledged"] == 1
    assert c.get("/api/network/status").json()["unacknowledged_alerts"] == 0
    assert c.delete("/api/network/events").json()["deleted"] == 2


def test_summary_graphs(c, procs):
    p = procs()
    mem(c).fake_connections = [tcp(p.pid, "192.168.50.23", 50001 + i, "203.0.113.5", 443) for i in range(3)] + \
        [tcp(p.pid, "0.0.0.0", 8080, status="LISTEN")]
    c.post("/api/network/watch")
    s = c.get("/api/network/summary?hours=6").json()
    assert s["bucket_minutes"] == 5 and s["series"][-1]["established"] == 3 and s["series"][-1]["listening"] == 1
    assert s["top_remote_ports"][0] == {"port": 443, "service": "HTTPS", "connections": 3}
    assert s["top_processes"][0]["pid"] == p.pid and s["by_scope"]["internet"] == 3
    assert s["by_state"] == {"ESTABLISHED": 3, "LISTEN": 1}


def test_status_card(c):
    s = c.get("/api/network/status").json()
    assert s["backend"]["probe"].startswith("Simulated") and s["backend"]["firewall"].startswith("Simulated")
    assert s["connections"]["total"] >= 0 and 0 <= s["score"] <= 100 and s["grade"]
    assert s["lan"]["subnet"] == "192.168.50.0/24" and s["scan"]["state"] == "idle"


def test_samples_retention(c):
    db = c.app.state.db
    db.execute("INSERT INTO network_samples(ts) VALUES ('2000-01-01T00:00:00.000Z')")
    c.post("/api/network/watch")
    assert db.fetchone("SELECT COUNT(*) AS n FROM network_samples WHERE ts < '2001'")["n"] == 0


# ====================================================================== isolation: one part cannot break another
def test_firewall_failure_does_not_break_network(c, procs):
    p = procs()
    mem(c).fake_connections = [tcp(p.pid, "0.0.0.0", 3389, status="LISTEN")]
    fw = c.app.state.firewall
    fw.invalidate()
    fw.backend.fail = BackendError(500, "PowerShell crashed")
    li = c.get("/api/network/listening").json()["items"][0]
    assert li["firewall"]["verdict"] == "unknown" and li["severity"] == "medium"
    assert c.get("/api/network/status").status_code == 200
    net(c).firewall = None                                         # firewall module missing entirely
    assert c.get("/api/network/listening").json()["items"][0]["firewall"]["verdict"] == "unknown"
    f = next(x for x in c.get("/api/network/findings?refresh=true").json()["findings"] if x["category"] == "listening")
    assert c.post(f"/api/network/findings/{f['id']}/fix").status_code == 501


def test_firewall_guard_errors_pass_through(c, procs):
    p = procs()
    mem(c).fake_connections = [tcp(p.pid, "192.168.50.23", 50001, "203.0.113.5", 4444)]
    f = next(x for x in c.get("/api/network/findings?refresh=true").json()["findings"] if x["category"] == "connection")
    c.app.state.firewall.backend.elevated = False                  # engine not elevated -> Part 9 says 403
    r = c.post(f"/api/network/findings/{f['id']}/fix")
    assert r.status_code == 403 and "administrator" in r.json()["detail"]


def test_wifi_and_probe_failures_are_contained(c):
    def boom():
        raise RuntimeError("driver crashed")
    mem(c).wifi.nearby = boom
    assert c.get("/api/network/status").status_code == 200
    assert c.post("/api/network/watch").status_code == 200
    mem(c).neighbours = boom
    assert c.post("/api/network/watch").status_code == 200        # LAN part fails, the rest still runs


def test_access_denied_listing_connections(c):
    def denied():
        raise psutil.AccessDenied()
    mem(c).connections = denied
    r = c.get("/api/network/connections")
    assert r.status_code == 403 and "administrator" in r.json()["detail"]
    assert c.get("/api/network/status").json()["error"]


def test_parts_1_to_9_still_answer(c):
    for path in ("/api/system/info", "/api/monitor/overview", "/api/processes?limit=5", "/api/scan/summary",
                 "/api/quarantine", "/api/realtime/status", "/api/rules/status", "/api/firewall/status"):
        assert c.get(path).status_code == 200, path
    info = c.get("/api/info").json()
    assert info["build_part"] >= 10 and info["progress_percent"] >= 50 and "network" in info["available_modules"]
    assert c.get("/api/health").json()["schema_version"] >= 11


def test_requires_session(env):
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
        assert cl.get("/api/network/status").status_code == 401
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        assert cl.get("/api/network/status").status_code == 401        # no token at all


# ====================================================================== WebSocket, loop, migration
def test_websocket_stream(c, procs):
    from starlette.websockets import WebSocketDisconnect
    tok, ses = c.headers["X-CyberHub-Token"], c.headers["X-CyberHub-Session"]
    p = procs()
    mem(c).fake_connections = [tcp(p.pid, "192.168.50.23", 50001, "203.0.113.5", 443)]
    with c.websocket_connect(f"/api/network/stream?token={tok}&session={ses}") as ws:
        first = ws.receive_json()
        assert first["type"] == "network" and first["live"]["established"] == 1 and first["scan"]["state"] == "idle"
        net(c)._event("test", "high", "pushed live")
        nxt = ws.receive_json()
        assert nxt["events"][0]["title"] == "pushed live" and nxt["unacknowledged"] >= 1
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect("/api/network/stream?token=wrong&session=x") as ws:
            ws.receive_json()
    assert e.value.code == 4401


def test_background_loop_runs_first_watch_immediately(c):
    s = c.app.state.settings_store

    async def run():
        t = asyncio.create_task(network_loop(net(c), s, tick=0.05, first_delay=0))
        await asyncio.sleep(0.6)
        t.cancel()
    asyncio.run(run())
    assert c.get("/api/network/status").json()["last_watch"]


def test_background_loop_auto_scans_home_network_and_survives_errors(c):
    s = c.app.state.settings_store
    nid = c.get("/api/network/lan").json()["network"]["id"]
    c.post(f"/api/network/lan/networks/{nid}/home", json={"home": True})
    s.update({"lan_auto_scan_minutes": 30})
    calls = {"n": 0}
    orig = net(c).watch_once

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return orig()
    net(c).watch_once = flaky

    async def run():
        t = asyncio.create_task(network_loop(net(c), s, tick=0.05, first_delay=0))
        await asyncio.sleep(0.8)
        t.cancel()
    s.update({"network_watch_interval_minutes": 1})
    asyncio.run(run())
    for _ in range(100):
        if net(c).scan_status()["state"] != "running":
            break
        time.sleep(0.03)
    assert net(c).scan_status()["started_by"] == "scheduler"
    assert c.get("/api/network/lan").json()["network"]["last_scan"]


def test_migration_from_part9_database_keeps_data(env):
    from cyberhub.config import Settings as S
    cfg = S()
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    db._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, description TEXT, "
                     "applied_at TEXT)")
    for v, d, sql in MIGRATIONS:
        if v <= 10:
            db._conn.executescript("BEGIN;" + sql + "COMMIT;")
            db._conn.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (v, d))
    db.execute("INSERT INTO firewall_blocks(kind, target, target_key, direction) VALUES ('ip','203.0.113.1',"
               "'203.0.113.1','both')")
    assert db.schema_version() == 10
    db.close()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        assert cl.get("/api/health").json()["schema_version"] >= 11
        assert cl.app.state.db.fetchone("SELECT COUNT(*) AS n FROM firewall_blocks")["n"] == 1
        con = sqlite3.connect(str(cfg.db_path))
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        con.close()
        assert {"network_events", "lan_devices", "lan_networks", "oui_vendors", "wifi_connections"} <= tables
