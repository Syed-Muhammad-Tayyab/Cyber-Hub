"""
Cyber Hub Backend - System information service
Developed by Syed Muhammad Tayyab

Static device info (OS, CPU, RAM, disks, network adapters) and live usage
stats (CPU %, memory %, disk %, network throughput, uptime). Works on
Windows, Linux and macOS through psutil.
"""
from __future__ import annotations

import getpass
import platform
import socket
import time
from datetime import datetime, timezone

import psutil

_last_net: tuple[float, int, int] | None = None   # (time, sent, recv) for throughput


def _gb(n: int) -> float:
    return round(n / (1024 ** 3), 2)


def _system_drive() -> str:
    if platform.system() == "Windows":
        import os
        return os.environ.get("SystemDrive", "C:") + "\\"
    return "/"


def device_info() -> dict:
    vm = psutil.virtual_memory()
    boot = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
    freq = psutil.cpu_freq()

    disks = []
    for p in psutil.disk_partitions(all=False):
        if platform.system() == "Windows" and "cdrom" in p.opts:
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
        except (PermissionError, OSError):
            continue
        disks.append({
            "device": p.device, "mount": p.mountpoint, "fs": p.fstype,
            "total_gb": _gb(u.total), "used_gb": _gb(u.used), "free_gb": _gb(u.free),
            "percent": u.percent,
        })

    adapters = []
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        ipv4 = [a.address for a in addrs if a.family == socket.AF_INET]
        mac = [a.address for a in addrs if getattr(psutil, "AF_LINK", None) == a.family]
        st = stats.get(name)
        adapters.append({
            "name": name, "ipv4": ipv4, "mac": mac[0] if mac else None,
            "is_up": bool(st and st.isup), "speed_mbps": st.speed if st else 0,
        })

    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"

    return {
        "hostname": socket.gethostname(),
        "user": user,
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "edition": _windows_edition(),
            "architecture": platform.machine(),
        },
        "cpu": {
            "model": _cpu_model(),
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "max_mhz": round(freq.max, 0) if freq and freq.max else None,
        },
        "memory": {"total_gb": _gb(vm.total)},
        "disks": disks,
        "network_adapters": adapters,
        "boot_time": boot.isoformat(),
        "python": platform.python_version(),
    }


def live_stats() -> dict:
    """Snapshot used by dashboard rings/gauges. Call every 1-2 s."""
    global _last_net
    now = time.time()
    io = psutil.net_io_counters()
    up_bps = down_bps = 0.0
    if _last_net:
        dt = max(now - _last_net[0], 1e-6)
        up_bps = max(io.bytes_sent - _last_net[1], 0) / dt
        down_bps = max(io.bytes_recv - _last_net[2], 0) / dt
    _last_net = (now, io.bytes_sent, io.bytes_recv)

    vm = psutil.virtual_memory()
    du = psutil.disk_usage(_system_drive())
    battery = None
    try:
        b = psutil.sensors_battery()
        if b:
            battery = {"percent": round(b.percent, 1), "plugged_in": b.power_plugged}
    except Exception:
        pass

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "cpu_per_core": psutil.cpu_percent(interval=None, percpu=True),
        "memory_percent": vm.percent,
        "memory_used_gb": _gb(vm.used),
        "memory_total_gb": _gb(vm.total),
        "disk_percent": du.percent,
        "disk_free_gb": _gb(du.free),
        "net_upload_kbps": round(up_bps / 1024, 2),
        "net_download_kbps": round(down_bps / 1024, 2),
        "net_total_sent_mb": round(io.bytes_sent / 1024 ** 2, 2),
        "net_total_recv_mb": round(io.bytes_recv / 1024 ** 2, 2),
        "process_count": len(psutil.pids()),
        "uptime_seconds": int(now - psutil.boot_time()),
        "battery": battery,
    }


def _cpu_model() -> str:
    name = platform.processor()
    if platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("model name"):
                        return line.split(":", 1)[1].strip()
        except OSError:
            pass
    elif platform.system() == "Windows":
        try:
            import winreg  # type: ignore
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            return winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
        except Exception:
            pass
    return name or "Unknown CPU"


def _windows_edition() -> str | None:
    if platform.system() != "Windows":
        return None
    try:
        import winreg  # type: ignore
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        product = winreg.QueryValueEx(k, "ProductName")[0]
        try:
            build = int(winreg.QueryValueEx(k, "CurrentBuildNumber")[0])
            if build >= 22000:                      # registry still says "Windows 10" on 11
                product = product.replace("Windows 10", "Windows 11")
        except Exception:
            pass
        return product
    except Exception:
        return None
