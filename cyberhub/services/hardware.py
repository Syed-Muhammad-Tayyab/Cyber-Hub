"""
Cyber Hub Backend - GPU, temperature and fan sensors (Part 3)
Developed by Syed Muhammad Tayyab

Sensors differ a lot between machines, so every probe is best-effort and
reports where its numbers came from ("source") or why they are missing
("note"). Order of preference:

GPU
  1. nvidia-smi              (NVIDIA: usage, VRAM, temperature, power, fan)
  2. Windows perf counters   (any GPU: 3D engine usage + dedicated memory)
  3. Linux sysfs             (AMD/Intel: gpu_busy_percent, VRAM)
Temperatures
  1. psutil sensors          (Linux / BSD)
  2. LibreHardwareMonitor / OpenHardwareMonitor WMI (Windows, if the user runs it)
  3. Windows thermal zones   (ACPI - motherboard zone, no admin needed)
  4. GPU temperature from nvidia-smi
"""
from __future__ import annotations

import glob
import os

import psutil

from .platform_tools import CACHE, IS_LINUX, IS_WINDOWS, run_cmd, run_powershell_json

GPU_TTL = 4.0
TEMP_TTL = 8.0

_VENDORS = {"0x10de": "NVIDIA", "0x1002": "AMD", "0x8086": "Intel"}

# ---------------------------------------------------------------- GPU
_NVSMI_FIELDS = ["index", "name", "utilization.gpu", "memory.used", "memory.total",
                 "temperature.gpu", "power.draw", "fan.speed", "driver_version"]


def _num(v: str):
    v = (v or "").strip()
    try:
        f = float(v)
        return int(f) if f.is_integer() else round(f, 1)
    except ValueError:
        return None


def parse_nvidia_smi(text: str) -> list[dict]:
    gpus = []
    for line in (text or "").strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < len(_NVSMI_FIELDS):
            continue
        d = dict(zip(_NVSMI_FIELDS, parts))
        used, total = _num(d["memory.used"]), _num(d["memory.total"])
        gpus.append({
            "index": _num(d["index"]),
            "name": d["name"],
            "vendor": "NVIDIA",
            "usage_percent": _num(d["utilization.gpu"]),
            "memory_used_mb": used,
            "memory_total_mb": total,
            "memory_percent": round(used / total * 100, 1) if used is not None and total else None,
            "temperature_c": _num(d["temperature.gpu"]),
            "power_w": _num(d["power.draw"]),
            "fan_percent": _num(d["fan.speed"]),
            "driver": d["driver_version"],
            "source": "nvidia-smi",
        })
    return gpus


def _nvidia() -> list[dict]:
    out = run_cmd(["nvidia-smi", f"--query-gpu={','.join(_NVSMI_FIELDS)}",
                   "--format=csv,noheader,nounits"], timeout=4)
    return parse_nvidia_smi(out) if out else []


_WIN_GPU_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$ad = @(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM,DriverVersion,AdapterCompatibility)
$u = (Get-Counter '\GPU Engine(*engtype_3D)\Utilization Percentage').CounterSamples | Measure-Object CookedValue -Sum
$m = (Get-Counter '\GPU Adapter Memory(*)\Dedicated Usage').CounterSamples | Measure-Object CookedValue -Sum
[pscustomobject]@{adapters=$ad; util=$u.Sum; dedicated=$m.Sum} | ConvertTo-Json -Depth 3 -Compress
"""


def parse_windows_gpu(j: dict | None) -> list[dict]:
    if not j:
        return []
    adapters = j.get("adapters") or []
    if isinstance(adapters, dict):
        adapters = [adapters]
    util = j.get("util")
    used = j.get("dedicated")
    out = []
    for i, a in enumerate(adapters):
        name = (a.get("Name") or "GPU").strip()
        if "Basic Display" in name or "Remote Display" in name:
            continue
        ram = a.get("AdapterRAM")
        out.append({
            "index": i, "name": name,
            "vendor": (a.get("AdapterCompatibility") or "").replace("Advanced Micro Devices, Inc.", "AMD") or None,
            # counters are machine-wide, so they are reported on the first real adapter
            "usage_percent": round(min(float(util), 100.0), 1) if util is not None and not out else None,
            "memory_used_mb": round(float(used) / 1024 ** 2) if used and not out else None,
            # Win32_VideoController.AdapterRAM is 32-bit, so it caps at 4 GB
            "memory_total_mb": round(ram / 1024 ** 2) if ram and ram > 0 else None,
            "memory_percent": None,
            "temperature_c": None, "power_w": None, "fan_percent": None,
            "driver": a.get("DriverVersion"),
            "source": "windows-perf-counters",
        })
    return out


def _linux_drm() -> list[dict]:
    out = []
    for card in sorted(glob.glob("/sys/class/drm/card[0-9]")):
        dev = os.path.join(card, "device")

        def rd(name):
            try:
                with open(os.path.join(dev, name), encoding="utf-8") as f:
                    return f.read().strip()
            except OSError:
                return None
        vendor = _VENDORS.get(rd("vendor") or "", None)
        if vendor is None:
            continue
        busy, used, total = _num(rd("gpu_busy_percent") or ""), _num(rd("mem_info_vram_used") or ""), \
            _num(rd("mem_info_vram_total") or "")
        temp = None
        for t in glob.glob(os.path.join(dev, "hwmon", "hwmon*", "temp1_input")):
            try:
                with open(t, encoding="utf-8") as f:
                    v = _num(f.read())
            except OSError:
                v = None
            temp = round(v / 1000, 1) if v is not None else None
        out.append({
            "index": len(out), "name": f"{vendor} GPU ({os.path.basename(card)})", "vendor": vendor,
            "usage_percent": busy,
            "memory_used_mb": round(used / 1024 ** 2) if used else None,
            "memory_total_mb": round(total / 1024 ** 2) if total else None,
            "memory_percent": round(used / total * 100, 1) if used and total else None,
            "temperature_c": temp, "power_w": None, "fan_percent": None, "driver": None,
            "source": "linux-sysfs",
        })
    return out


def _probe_gpus() -> dict:
    gpus = _nvidia()
    if IS_WINDOWS:
        win = parse_windows_gpu(run_powershell_json(_WIN_GPU_PS, timeout=10))
        names = {g["name"] for g in gpus}
        if gpus and win:                          # nvidia-smi already covers its cards
            win = [g for g in win if g["name"] not in names and "NVIDIA" not in g["name"]]
            for g in win:
                g["usage_percent"] = g["memory_used_mb"] = None   # counters already include NVIDIA load
        gpus += win
    elif IS_LINUX and not gpus:
        gpus = _linux_drm()
    for i, g in enumerate(gpus):
        g["index"] = i
    usage = [g["usage_percent"] for g in gpus if g["usage_percent"] is not None]
    return {
        "available": bool(gpus),
        "gpus": gpus,
        "max_usage_percent": max(usage) if usage else None,
        "note": None if gpus else "No GPU sensors found (install the GPU driver; NVIDIA cards need nvidia-smi).",
    }


def gpu_info(ttl: float = GPU_TTL) -> dict:
    return CACHE.get("gpu", ttl, _probe_gpus)


# ---------------------------------------------------------------- temperatures
_WIN_TEMP_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$hw = @(Get-CimInstance -Namespace root/LibreHardwareMonitor -ClassName Sensor | Where-Object SensorType -eq 'Temperature' | Select-Object Name,Identifier,Value)
$src = 'LibreHardwareMonitor'
if ($hw.Count -eq 0) { $hw = @(Get-CimInstance -Namespace root/OpenHardwareMonitor -ClassName Sensor | Where-Object SensorType -eq 'Temperature' | Select-Object Name,Identifier,Value); $src='OpenHardwareMonitor' }
$tz = @(Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation | Select-Object Name,HighPrecisionTemperature,Temperature)
[pscustomobject]@{hw=$hw; hw_source=$src; zones=$tz} | ConvertTo-Json -Depth 3 -Compress
"""

_CPU_HINTS = ("package", "tctl", "tdie", "cpu", "core")


def _sensor(group: str, label: str, value, high=None, critical=None, source="") -> dict | None:
    try:
        v = round(float(value), 1)
    except (TypeError, ValueError):
        return None
    if not -40 < v < 150:                         # filter garbage readings
        return None
    return {"group": group, "label": label or group, "celsius": v,
            "high": high, "critical": critical, "source": source}


def parse_windows_temps(j: dict | None) -> list[dict]:
    if not j:
        return []
    out = []
    hw = j.get("hw") or []
    if isinstance(hw, dict):
        hw = [hw]
    for s in hw:
        ident = (s.get("Identifier") or "").lower()
        group = "cpu" if "cpu" in ident else "gpu" if "gpu" in ident else \
            "storage" if ("hdd" in ident or "nvme" in ident or "ssd" in ident) else "board"
        r = _sensor(group, s.get("Name"), s.get("Value"), source=j.get("hw_source") or "hardware-monitor")
        if r:
            out.append(r)
    zones = j.get("zones") or []
    if isinstance(zones, dict):
        zones = [zones]
    for z in zones:
        hp = z.get("HighPrecisionTemperature")
        kelvin = hp / 10 if hp else z.get("Temperature")
        if kelvin:
            r = _sensor("acpi", (z.get("Name") or "Thermal zone").split("\\")[-1], kelvin - 273.15,
                        source="windows-thermal-zone")
            if r:
                out.append(r)
    return out


def _psutil_temps() -> list[dict]:
    if not hasattr(psutil, "sensors_temperatures"):
        return []
    try:
        data = psutil.sensors_temperatures()
    except Exception:
        return []
    out = []
    for chip, entries in (data or {}).items():
        group = "cpu" if chip in ("coretemp", "k10temp", "zenpower", "cpu_thermal", "cpu-thermal") else \
            "storage" if chip in ("nvme", "drivetemp") else "gpu" if chip in ("amdgpu", "nouveau", "radeon") \
            else "acpi" if chip.startswith("acpi") else "board"
        for e in entries:
            r = _sensor(group, e.label or chip, e.current, e.high, e.critical, f"psutil:{chip}")
            if r:
                out.append(r)
    return out


def pick_cpu_temp(sensors: list[dict]) -> float | None:
    """Best single 'CPU temperature' number for the gauge."""
    cpu = [s for s in sensors if s["group"] == "cpu"]
    for hint in ("package", "tctl", "tdie"):
        for s in cpu:
            if hint in s["label"].lower():
                return s["celsius"]
    if cpu:
        return max(s["celsius"] for s in cpu)
    acpi = [s["celsius"] for s in sensors if s["group"] == "acpi"]
    return max(acpi) if acpi else None


def _probe_temps() -> dict:
    sensors = _psutil_temps()
    if IS_WINDOWS and not sensors:
        sensors = parse_windows_temps(run_powershell_json(_WIN_TEMP_PS, timeout=10))
    for g in gpu_info()["gpus"]:
        if g.get("temperature_c") is not None and not any(s["group"] == "gpu" for s in sensors):
            sensors.append(_sensor("gpu", g["name"], g["temperature_c"], source=g["source"]))
    fans = []
    if hasattr(psutil, "sensors_fans"):
        try:
            for chip, entries in (psutil.sensors_fans() or {}).items():
                fans += [{"label": e.label or chip, "rpm": e.current} for e in entries]
        except Exception:
            pass
    sensors = [s for s in sensors if s]
    note = None
    if not sensors:
        note = ("No temperature sensors exposed. On Windows, run LibreHardwareMonitor (free) "
                "in the background and Cyber Hub will read its sensors automatically.") if IS_WINDOWS \
            else "No temperature sensors exposed by this system."
    hottest = max(sensors, key=lambda s: s["celsius"]) if sensors else None
    return {
        "available": bool(sensors),
        "cpu_celsius": pick_cpu_temp(sensors),
        "gpu_celsius": next((s["celsius"] for s in sensors if s["group"] == "gpu"), None),
        "hottest": hottest,
        "sensors": sensors,
        "fans": fans,
        "note": note,
    }


def temperatures(ttl: float = TEMP_TTL) -> dict:
    return CACHE.get("temps", ttl, _probe_temps)
