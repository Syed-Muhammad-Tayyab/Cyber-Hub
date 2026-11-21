"""
Cyber Hub Backend - Live System Monitor sampler (Part 3)
Developed by Syed Muhammad Tayyab

Computes rates (CPU %, disk MB/s, IOPS, network KB/s, per-process CPU and
disk I/O) from counter deltas kept in one shared Sampler, so the REST API,
the WebSocket stream and the alert engine all see consistent numbers
without fighting over psutil's global cpu_percent() state.
"""
from __future__ import annotations

import platform
import threading
import time
from datetime import datetime, timezone

import psutil

from . import hardware
from .platform_tools import IS_LINUX

MIN_INTERVAL = 0.5          # never compute rates over less than this many seconds
_MB = 1024 ** 2
_GB = 1024 ** 3


def _r(x: float, n: int = 1) -> float:
    return round(x, n)


def _cpu_total(t) -> float:
    tot = sum(t)
    if IS_LINUX:                                   # guest time is already inside user time
        tot -= getattr(t, "guest", 0) + getattr(t, "guest_nice", 0)
    return tot


def _cpu_busy(t) -> float:
    return _cpu_total(t) - t.idle - getattr(t, "iowait", 0)


def _cpu_pct(a, b) -> float:
    dt = _cpu_total(b) - _cpu_total(a)
    if dt <= 0:
        return 0.0
    return max(0.0, min(100.0, (_cpu_busy(b) - _cpu_busy(a)) / dt * 100))


def _partitions() -> list[dict]:
    out = []
    for p in psutil.disk_partitions(all=False):
        if platform.system() == "Windows" and ("cdrom" in p.opts or not p.fstype):
            continue
        if p.mountpoint.startswith(("/snap", "/boot/efi")) or p.fstype in ("squashfs", "overlay"):
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
        except (PermissionError, OSError):
            continue
        out.append({"device": p.device, "mount": p.mountpoint, "fs": p.fstype,
                    "total_gb": _r(u.total / _GB, 2), "used_gb": _r(u.used / _GB, 2),
                    "free_gb": _r(u.free / _GB, 2), "percent": u.percent})
    return out


class Sampler:
    def __init__(self):
        self._lock = threading.RLock()
        self._prev: dict | None = None             # raw counters of the previous sample
        self._last: dict | None = None             # last computed result (fast sample)
        self._procs: dict[tuple[int, float], psutil.Process] = {}
        self._proc_io: dict[tuple[int, float], tuple[float, int]] = {}
        self._proc_t: float = 0.0
        self._rows: tuple[float, list[dict]] | None = None   # cached process table

    # ------------------------------------------------------------ raw counters
    @staticmethod
    def _raw() -> dict:
        try:
            disks = psutil.disk_io_counters(perdisk=True) or {}
        except Exception:                          # some VMs/containers have no disk counters
            disks = {}
        try:
            stats = psutil.cpu_stats()
        except Exception:
            stats = None
        return {
            "t": time.monotonic(),
            "cpu": psutil.cpu_times(),
            "cores": psutil.cpu_times(percpu=True),
            "stats": stats,
            "disks": disks,
            "nics": psutil.net_io_counters(pernic=True) or {},
        }

    # ------------------------------------------------------------ sample
    def sample(self) -> dict:
        """Fast sample: CPU, memory, disk I/O, network. Cached for MIN_INTERVAL seconds."""
        with self._lock:
            now = time.monotonic()
            if self._last and now - self._prev["t"] < MIN_INTERVAL:
                return self._last
            if self._prev is None:                  # first call: take a short baseline
                self._prev = self._raw()
                time.sleep(0.3)
            cur = self._raw()
            result = self._compute(self._prev, cur)
            self._prev, self._last = cur, result
            return result

    def _compute(self, a: dict, b: dict) -> dict:
        dt = max(b["t"] - a["t"], 1e-6)
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interval_seconds": _r(dt, 2),
            "cpu": self._cpu(a, b, dt),
            "memory": self._memory(),
            "disk_io": self._disk_io(a, b, dt),
            "network": self._network(a, b, dt),
        }

    @staticmethod
    def _cpu(a: dict, b: dict, dt: float) -> dict:
        per_core = [_r(_cpu_pct(x, y)) for x, y in zip(a["cores"], b["cores"])]
        total_delta = max(_cpu_total(b["cpu"]) - _cpu_total(a["cpu"]), 1e-9)
        breakdown = {f: _r(max(getattr(b["cpu"], f) - getattr(a["cpu"], f), 0) / total_delta * 100)
                     for f in b["cpu"]._fields if f not in ("guest", "guest_nice")}
        freqs = []
        try:
            fr = psutil.cpu_freq(percpu=True) or []
            freqs = [_r(f.current, 0) for f in fr]
        except Exception:
            pass
        rates = {}
        if a["stats"] and b["stats"]:
            for f in ("ctx_switches", "interrupts", "soft_interrupts", "syscalls"):
                rates[f + "_per_sec"] = int(max(getattr(b["stats"], f) - getattr(a["stats"], f), 0) / dt)
        try:
            load = [_r(x, 2) for x in psutil.getloadavg()]
        except Exception:
            load = None
        return {
            "percent": _r(_cpu_pct(a["cpu"], b["cpu"])),
            "per_core": per_core,
            "logical_cores": len(per_core),
            "physical_cores": psutil.cpu_count(logical=False),
            "busiest_core": max(range(len(per_core)), key=per_core.__getitem__) if per_core else None,
            "frequency_mhz": freqs[0] if len(freqs) == 1 else (_r(sum(freqs) / len(freqs), 0) if freqs else None),
            "per_core_mhz": freqs if len(freqs) > 1 else None,
            "times_percent": breakdown,
            "load_average": load,
            **rates,
        }

    @staticmethod
    def _memory() -> dict:
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
        mem = {
            "percent": vm.percent,
            "total_gb": _r(vm.total / _GB, 2),
            "used_gb": _r(vm.used / _GB, 2),
            "available_gb": _r(vm.available / _GB, 2),
            "free_gb": _r(vm.free / _GB, 2),
        }
        for f in ("cached", "buffers", "shared"):
            if hasattr(vm, f):
                mem[f + "_gb"] = _r(getattr(vm, f) / _GB, 2)
        mem["swap"] = {                          # = page file on Windows
            "percent": sw.percent, "total_gb": _r(sw.total / _GB, 2),
            "used_gb": _r(sw.used / _GB, 2), "free_gb": _r(sw.free / _GB, 2),
        }
        return mem

    @staticmethod
    def _disk_io(a: dict, b: dict, dt: float) -> dict:
        disks = []
        tot = {"read_mb_s": 0.0, "write_mb_s": 0.0, "read_iops": 0.0, "write_iops": 0.0}
        for name, y in b["disks"].items():
            x = a["disks"].get(name)
            if not x or name.startswith(("loop", "ram", "zram", "dm-", "sr")):
                continue
            rb, wb = max(y.read_bytes - x.read_bytes, 0) / dt, max(y.write_bytes - x.write_bytes, 0) / dt
            ri, wi = max(y.read_count - x.read_count, 0) / dt, max(y.write_count - x.write_count, 0) / dt
            busy = None
            if hasattr(y, "busy_time"):
                busy = min(100.0, max(y.busy_time - x.busy_time, 0) / (dt * 1000) * 100)
            elif hasattr(y, "read_time"):
                busy = min(100.0, max((y.read_time + y.write_time) - (x.read_time + x.write_time), 0)
                           / (dt * 1000) * 100)
            d = {"disk": name, "read_mb_s": _r(rb / _MB, 2), "write_mb_s": _r(wb / _MB, 2),
                 "read_iops": _r(ri), "write_iops": _r(wi),
                 "active_percent": _r(busy) if busy is not None else None,
                 "total_read_gb": _r(y.read_bytes / _GB, 2), "total_written_gb": _r(y.write_bytes / _GB, 2)}
            disks.append(d)
            tot["read_mb_s"] += rb / _MB
            tot["write_mb_s"] += wb / _MB
            tot["read_iops"] += ri
            tot["write_iops"] += wi
        return {**{k: _r(v, 2) for k, v in tot.items()}, "disks": disks, "partitions": _partitions()}

    @staticmethod
    def _network(a: dict, b: dict, dt: float) -> dict:
        stats = psutil.net_if_stats()
        nics, up, down = [], 0.0, 0.0
        for name, y in b["nics"].items():
            x = a["nics"].get(name)
            if not x:
                continue
            s, r = max(y.bytes_sent - x.bytes_sent, 0) / dt, max(y.bytes_recv - x.bytes_recv, 0) / dt
            st = stats.get(name)
            loop = name.lower().startswith(("lo", "loopback"))
            nics.append({"name": name, "is_up": bool(st and st.isup), "speed_mbps": st.speed if st else 0,
                         "upload_kbps": _r(s / 1024, 2), "download_kbps": _r(r / 1024, 2),
                         "errors": y.errin + y.errout, "drops": y.dropin + y.dropout, "loopback": loop})
            if not loop:
                up, down = up + s, down + r
        nics.sort(key=lambda n: (n["loopback"], not n["is_up"], -(n["upload_kbps"] + n["download_kbps"])))
        return {"upload_kbps": _r(up / 1024, 2), "download_kbps": _r(down / 1024, 2), "interfaces": nics}

    # ------------------------------------------------------------ top processes
    def top_processes(self, by: str = "cpu", limit: int = 10) -> dict:
        """Top resource users. cpu = % of whole machine, memory = MB, disk = MB/s read+write."""
        with self._lock:
            if self._rows and time.monotonic() - self._rows[0] < 1.0:
                rows = self._rows[1]
            else:
                rows = self._collect()
                self._rows = (time.monotonic(), rows)
        key_fn = {"cpu": lambda r: r["cpu_percent"], "memory": lambda r: r["memory_mb"],
                  "disk": lambda r: r["disk_mb_s"] or 0.0}[by]
        ranked = sorted(rows, key=key_fn, reverse=True)
        return {"by": by, "process_count": len(rows), "items": ranked[:limit]}

    def _collect(self) -> list[dict]:
        ncpu = psutil.cpu_count() or 1
        first = not self._procs
        now = time.monotonic()
        alive: dict[tuple[int, float], psutil.Process] = {}
        for p in psutil.process_iter(["pid", "create_time"]):
            key = (p.info["pid"], p.info["create_time"] or 0.0)
            proc = self._procs.get(key) or p
            if key not in self._procs:
                try:
                    proc.cpu_percent(None)                       # prime
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            alive[key] = proc
        self._procs = alive
        if first:
            time.sleep(0.4)
        rows = []
        dt_io = now - self._proc_t if self._proc_t else 0
        new_io: dict[tuple[int, float], tuple[float, int]] = {}
        for key, proc in alive.items():
            pid = key[0]
            if pid == 0:                                         # "System Idle Process"
                continue
            try:
                with proc.oneshot():
                    cpu = proc.cpu_percent(None) / ncpu
                    mem = proc.memory_info().rss
                    name = proc.name()
                    try:
                        user = proc.username()
                    except (psutil.AccessDenied, KeyError):
                        user = None
                    try:
                        io = proc.io_counters()
                        io_total = io.read_bytes + io.write_bytes
                    except (psutil.AccessDenied, AttributeError, NotImplementedError):
                        io_total = None
                    threads = proc.num_threads()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            disk_rate = None
            if io_total is not None:
                prev = self._proc_io.get(key)
                if prev and dt_io > 0:
                    disk_rate = max(io_total - prev[1], 0) / dt_io / _MB
                new_io[key] = (now, io_total)
            rows.append({"pid": pid, "name": name, "user": user, "cpu_percent": _r(cpu),
                         "memory_mb": _r(mem / _MB), "disk_mb_s": _r(disk_rate, 2) if disk_rate is not None else None,
                         "threads": threads})
        self._proc_io, self._proc_t = new_io, now
        total_mem = psutil.virtual_memory().total
        for r in rows:
            r["memory_percent"] = _r(r["memory_mb"] * _MB / total_mem * 100, 2)
        return rows


SAMPLER = Sampler()


# ---------------------------------------------------------------- health / status
def _status(value, warn, crit) -> str:
    if value is None:
        return "unknown"
    return "critical" if value >= crit else "warning" if value >= warn else "ok"


def health(sample: dict, gpu: dict, temps: dict, thresholds: dict) -> dict:
    """Traffic-light status per resource for the monitor's summary cards."""
    worst_disk = max((p["percent"] for p in sample["disk_io"]["partitions"]), default=None)
    t = thresholds
    items = {
        "cpu": (sample["cpu"]["percent"], t["alert_cpu_percent"] - 15, t["alert_cpu_percent"]),
        "memory": (sample["memory"]["percent"], t["alert_memory_percent"] - 15, t["alert_memory_percent"]),
        "disk_space": (worst_disk, t["alert_disk_percent"] - 10, t["alert_disk_percent"]),
        "gpu": (gpu.get("max_usage_percent"), t["alert_gpu_percent"] - 15, t["alert_gpu_percent"]),
        "temperature": (temps.get("cpu_celsius"), t["alert_temperature_c"] - 10, t["alert_temperature_c"]),
    }
    out = {k: {"value": v, "status": _status(v, w, c), "threshold": c} for k, (v, w, c) in items.items()}
    order = ["ok", "unknown", "warning", "critical"]
    overall = max((x["status"] for x in out.values()), key=order.index)
    out["overall"] = "ok" if overall == "unknown" else overall
    return out


def overview(thresholds: dict, top: int = 5) -> dict:
    """Everything the Live Monitor page needs in one call."""
    s = SAMPLER.sample()
    gpu = hardware.gpu_info()
    temps = hardware.temperatures()
    return {
        **s,
        "gpu": gpu,
        "temperatures": temps,
        "health": health(s, gpu, temps, thresholds),
        "process_count": len(psutil.pids()),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "top_cpu": SAMPLER.top_processes("cpu", top)["items"] if top else [],
        "top_memory": SAMPLER.top_processes("memory", top)["items"] if top else [],
    }


def readings(sample: dict, gpu: dict, temps: dict) -> list[tuple[str, str, float | None]]:
    """(metric, target, value) tuples for the alert engine."""
    out = [("cpu", "cpu", sample["cpu"]["percent"]), ("memory", "memory", sample["memory"]["percent"])]
    out += [("disk_space", p["mount"], p["percent"]) for p in sample["disk_io"]["partitions"]]
    out.append(("gpu", "gpu", gpu.get("max_usage_percent")))
    out.append(("temperature", "cpu", temps.get("cpu_celsius")))
    return out
