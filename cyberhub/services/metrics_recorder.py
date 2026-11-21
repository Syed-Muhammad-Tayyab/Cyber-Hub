"""
Cyber Hub Backend - Background metrics recorder
Developed by Syed Muhammad Tayyab

Stores a system snapshot once a minute so the dashboard can draw
CPU / RAM / disk / network history graphs (last hour, day, week).
Part 3 adds swap, disk read/write MB/s, GPU % and CPU temperature, plus
a bucketed history query so week-long charts stay light.
"""
from __future__ import annotations

import asyncio
import threading
import time

import psutil

from ..database import Database
from ..logger import get_logger
from . import hardware
from .settings_store import SettingsStore
from .system_info import _system_drive

log = get_logger("metrics")

_disk_lock = threading.Lock()
_last_disk: tuple[float, int, int] | None = None     # (time, read_bytes, write_bytes) between snapshots


def _disk_rates() -> tuple[float | None, float | None]:
    global _last_disk
    try:
        io = psutil.disk_io_counters()
    except Exception:
        io = None
    if not io:
        return None, None
    now = time.monotonic()
    with _disk_lock:
        prev, _last_disk = _last_disk, (now, io.read_bytes, io.write_bytes)
    if not prev:
        return None, None
    dt = max(now - prev[0], 1e-6)
    return (round(max(io.read_bytes - prev[1], 0) / dt / 1024 ** 2, 3),
            round(max(io.write_bytes - prev[2], 0) / dt / 1024 ** 2, 3))


def take_snapshot(db: Database) -> dict:
    io = psutil.net_io_counters()
    read_mbs, write_mbs = _disk_rates()
    gpu = temp = None
    try:
        gpu = hardware.gpu_info().get("max_usage_percent")
        temp = hardware.temperatures().get("cpu_celsius")
    except Exception as e:                         # sensors are optional
        log.debug("Sensor read failed: %s", e)
    row = (
        psutil.cpu_percent(interval=0.3),
        psutil.virtual_memory().percent,
        psutil.disk_usage(_system_drive()).percent,
        io.bytes_sent,
        io.bytes_recv,
        psutil.swap_memory().percent,
        read_mbs, write_mbs, gpu, temp,
    )
    cur = db.execute(
        "INSERT INTO metric_snapshots(cpu, memory, disk, net_sent, net_recv, swap, disk_read_mbs, "
        "disk_write_mbs, gpu, cpu_temp) VALUES (?,?,?,?,?,?,?,?,?,?)", row
    )
    return db.fetchone("SELECT * FROM metric_snapshots WHERE id=?", (cur.lastrowid,))


def history(db: Database, hours: int = 24) -> list[dict]:
    return db.fetchall(
        "SELECT ts, cpu, memory, disk, net_sent, net_recv FROM metric_snapshots "
        "WHERE ts >= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?) ORDER BY ts",
        (f"-{hours} hours",),
    )


def history_buckets(db: Database, hours: int = 24, bucket_minutes: int | None = None) -> dict:
    """Averaged (and peak) values per time bucket for the monitor's line charts.
    Default bucket keeps every chart around ~120 points."""
    if not bucket_minutes:
        bucket_minutes = max(1, round(hours * 60 / 120))
    secs = bucket_minutes * 60
    rows = db.fetchall(
        f"""
        SELECT strftime('%Y-%m-%dT%H:%M:%SZ', (CAST(strftime('%s', ts) AS INTEGER) / {secs}) * {secs},
                        'unixepoch') AS ts,
               ROUND(AVG(cpu),1) cpu, ROUND(MAX(cpu),1) cpu_peak,
               ROUND(AVG(memory),1) memory, ROUND(AVG(swap),1) swap, ROUND(AVG(disk),1) disk,
               ROUND(AVG(disk_read_mbs),3) disk_read_mbs, ROUND(AVG(disk_write_mbs),3) disk_write_mbs,
               ROUND(AVG(gpu),1) gpu, ROUND(AVG(cpu_temp),1) cpu_temp, ROUND(MAX(cpu_temp),1) cpu_temp_peak,
               MIN(net_sent) s0, MAX(net_sent) s1, MIN(net_recv) r0, MAX(net_recv) r1, COUNT(*) samples
        FROM metric_snapshots
        WHERE ts >= strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)
        GROUP BY 1 ORDER BY 1
        """,
        (f"-{hours} hours",),
    )
    for r in rows:   # network volume inside the bucket (counters reset on reboot -> clamp at 0)
        r["net_sent_mb"] = round(max(r.pop("s1") - r.pop("s0"), 0) / 1024 ** 2, 2)
        r["net_recv_mb"] = round(max(r.pop("r1") - r.pop("r0"), 0) / 1024 ** 2, 2)
    return {"hours": hours, "bucket_minutes": bucket_minutes, "points": rows}


def prune(db: Database, days: int) -> int:
    return db.execute(
        "DELETE FROM metric_snapshots WHERE ts < strftime('%Y-%m-%dT%H:%M:%fZ','now', ?)", (f"-{days} days",)
    ).rowcount


async def recorder_loop(db: Database, settings: SettingsStore, interval: int = 60) -> None:
    log.info("Metrics recorder started (every %ss)", interval)
    while True:
        try:
            if settings.get("metrics_history_enabled"):
                await asyncio.to_thread(take_snapshot, db)
                prune(db, settings.get("metrics_retention_days"))
        except Exception as e:                       # never let the loop die
            log.warning("Snapshot failed: %s", e)
        await asyncio.sleep(interval)
