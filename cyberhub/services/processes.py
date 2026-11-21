"""
Cyber Hub Backend - Process manager (Part 4)
Developed by Syed Muhammad Tayyab

Task-Manager-style process list and tree with risk flags, per-process
details (command line, parent/children, handles, files, connections,
signature, SHA-256), and safe actions: end task / end tree / force kill,
suspend, resume and priority change.

Safety rules
  * Critical OS processes, Cyber Hub itself and its launcher are protected.
  * Every action may carry the `create_time` the UI saw, so a PID that has
    been recycled by Windows is never killed by mistake (HTTP 409).
  * Every action is written to the process_actions table + activity log.
"""
from __future__ import annotations

import ctypes
import os
import time
from datetime import datetime, timezone

import psutil

from ..database import Database
from ..logger import get_logger
from . import threat_flags as tf
from .monitor import SAMPLER
from .platform_tools import IS_WINDOWS
from .signatures import SignatureService, sha256_file

log = get_logger("processes")

_MB = 1024 ** 2

PROTECTED_WINDOWS = {
    "system", "registry", "memory compression", "secure system", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "fontdrvhost.exe",
    "dwm.exe", "svchost.exe", "msmpeng.exe", "securityhealthservice.exe", "system idle process",
}
PROTECTED_POSIX = {"systemd", "init", "kthreadd", "launchd", "kernel_task", "loginwindow"}

PRIORITIES = ["idle", "below_normal", "normal", "above_normal", "high"]   # no "realtime": can freeze the PC
_NICE = {"idle": 19, "below_normal": 10, "normal": 0, "above_normal": -5, "high": -10}


class ProcessError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def is_elevated() -> bool:
    """True when the engine runs as Administrator (Windows) / root (POSIX)."""
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())   # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:
        return False


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None


def _priority_name(p: psutil.Process) -> str | None:
    try:
        n = p.nice()
    except (psutil.Error, OSError):
        return None
    if IS_WINDOWS:
        table = {psutil.IDLE_PRIORITY_CLASS: "idle", psutil.BELOW_NORMAL_PRIORITY_CLASS: "below_normal",
                 psutil.NORMAL_PRIORITY_CLASS: "normal", psutil.ABOVE_NORMAL_PRIORITY_CLASS: "above_normal",
                 psutil.HIGH_PRIORITY_CLASS: "high", psutil.REALTIME_PRIORITY_CLASS: "realtime"}
        return table.get(n, str(n))
    if n >= 15: return "idle"            # noqa: E701
    if n > 0: return "below_normal"      # noqa: E701
    if n == 0: return "normal"           # noqa: E701
    return "above_normal" if n > -10 else "high"


class ProcessService:
    def __init__(self, db: Database, signatures: SignatureService, activity):
        self.db, self.sigs, self.activity = db, signatures, activity
        me = psutil.Process()
        self.self_pid = me.pid
        self.guarded = {me.pid}
        try:                                           # our launcher (uvicorn reloader / the .exe bootloader)
            parent = me.parent()
            if parent and parent.pid > 4 and "python" in parent.name().lower() or (
                    parent and "cyberhub" in parent.name().lower()):
                self.guarded.add(parent.pid)
        except psutil.Error:
            pass

    # ================================================================== protection
    def protection(self, pid: int, name: str | None, exe: str | None) -> str | None:
        """Reason this process must not be touched, or None."""
        if pid in (0, 4) or (not IS_WINDOWS and pid in (1, 2)):
            return "Core operating-system process"
        if pid == self.self_pid:
            return "This is the Cyber Hub engine itself"
        if pid in self.guarded:
            return "This process is running Cyber Hub"
        n = (name or "").lower()
        if IS_WINDOWS and n in PROTECTED_WINDOWS:
            windir = (os.environ.get("SystemRoot") or r"C:\Windows").lower()
            always = {"system", "registry", "memory compression", "secure system", "system idle process",
                      "msmpeng.exe", "securityhealthservice.exe"}
            if not exe or exe.lower().startswith(windir) or n in always:
                return "Critical Windows process - ending it would crash or log off the PC"
        if not IS_WINDOWS and n in PROTECTED_POSIX:
            return "Critical system process"
        return None

    # ================================================================== list
    def _raw_rows(self) -> list[dict]:
        live = {r["pid"]: r for r in SAMPLER.top_processes("cpu", 100_000)["items"]}
        rows = []
        attrs = ["pid", "ppid", "name", "exe", "status", "create_time", "username", "cmdline"]
        for p in psutil.process_iter(attrs):
            i = p.info
            pid = i["pid"]
            if pid == 0 and IS_WINDOWS:
                continue
            cmd = i.get("cmdline") or []
            cmdline = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            stats = live.get(pid, {})
            rows.append({
                "pid": pid, "ppid": i.get("ppid"), "name": i.get("name") or "?", "exe": i.get("exe") or None,
                "status": i.get("status"), "user": i.get("username"),
                "create_time": i.get("create_time"), "started_at": _iso(i.get("create_time")),
                "cmdline": cmdline[:600] if cmdline else None,
                "cpu_percent": stats.get("cpu_percent", 0.0), "memory_mb": stats.get("memory_mb", 0.0),
                "memory_percent": stats.get("memory_percent", 0.0), "disk_mb_s": stats.get("disk_mb_s"),
                "threads": stats.get("threads"),
            })
        names = {r["pid"]: (r["name"] or "").lower() for r in rows}
        for r in rows:
            r["parent_name"] = names.get(r["ppid"])
        return rows

    def _annotate(self, r: dict, with_signature: bool, sig_map: dict | None = None) -> dict:
        flags: list[str] = []
        flags += tf.path_flags(r["exe"])
        if tf.is_masquerading(r["name"], r["exe"]):
            flags.append("masquerade")
        flags += [f for f in tf.command_flags(r["cmdline"]) if f in ("encoded_command", "hidden_window")]
        if (r["name"] or "").lower() in tf.SCRIPT_HOSTS and (r.get("parent_name") or "") in tf.OFFICE_PARENTS:
            flags.append("office_child_shell")
        if r["exe"] and r["exe"].endswith(" (deleted)"):
            flags.append("missing_file")
        sig = None
        if r["exe"]:
            sig = (sig_map or {}).get(r["exe"]) if with_signature else self.sigs.cached(r["exe"])
        flags += tf.signature_flags(sig)
        r["signature"] = ({"status": sig["status"], "publisher": sig.get("publisher")} if sig else None)
        r.update(tf.score(flags))
        reason = self.protection(r["pid"], r["name"], r["exe"])
        r["protected"], r["protected_reason"] = bool(reason), reason
        return r

    def list(self, search: str | None = None, sort: str = "cpu", order: str = "desc", limit: int = 200,
             offset: int = 0, user: str | None = None, flagged_only: bool = False,
             with_signatures: bool = False) -> dict:
        rows = self._raw_rows()
        if search:
            s = search.lower()
            rows = [r for r in rows if s in r["name"].lower() or s in (r["exe"] or "").lower()
                    or s == str(r["pid"]) or s in (r["user"] or "").lower()]
        if user:
            rows = [r for r in rows if (r["user"] or "").lower().endswith(user.lower())]
        sig_map = None
        if with_signatures and IS_WINDOWS:
            sig_map = self.sigs.check_many([r["exe"] for r in rows if r["exe"]])
        rows = [self._annotate(r, with_signatures, sig_map) for r in rows]
        if flagged_only:
            rows = [r for r in rows if r["flags"]]
        key = {"cpu": lambda r: r["cpu_percent"] or 0, "memory": lambda r: r["memory_mb"] or 0,
               "disk": lambda r: r["disk_mb_s"] or 0, "name": lambda r: r["name"].lower(),
               "pid": lambda r: r["pid"], "threads": lambda r: r["threads"] or 0,
               "risk": lambda r: r["risk_score"], "started": lambda r: r["create_time"] or 0}[sort]
        rows.sort(key=key, reverse=(order == "desc"))
        return {
            "total": len(rows), "limit": limit, "offset": offset,
            "summary": self._summary(rows),
            "items": rows[offset:offset + limit],
        }

    @staticmethod
    def _summary(rows: list[dict]) -> dict:
        levels = {"none": 0, "low": 0, "medium": 0, "high": 0}
        for r in rows:
            levels[r["risk_level"]] += 1
        statuses: dict[str, int] = {}
        for r in rows:
            statuses[r["status"] or "unknown"] = statuses.get(r["status"] or "unknown", 0) + 1
        sig = {"signed": 0, "unsigned": 0, "other": 0, "unchecked": 0}
        for r in rows:
            s = (r.get("signature") or {}).get("status")
            sig["unchecked" if s is None else s if s in ("signed", "unsigned") else "other"] += 1
        return {"processes": len(rows), "threads": sum(r["threads"] or 0 for r in rows),
                "flagged": sum(1 for r in rows if r["flags"]), "by_risk": levels, "by_status": statuses,
                "signatures": sig, "suspended": statuses.get("stopped", 0)}

    # ================================================================== tree
    def tree(self, with_signatures: bool = False) -> dict:
        rows = {r["pid"]: self._annotate(r, False) for r in self._raw_rows()}
        children: dict[int, list[int]] = {}
        roots = []
        for pid, r in rows.items():
            pp = r["ppid"]
            if pp in rows and pp != pid:
                children.setdefault(pp, []).append(pid)
            else:
                roots.append(pid)

        def build(pid: int, seen: set[int]) -> dict:
            seen.add(pid)
            r = rows[pid]
            kids = [build(c, seen) for c in sorted(children.get(pid, []), key=lambda c: rows[c]["name"].lower())
                    if c not in seen]
            node = {k: r[k] for k in ("pid", "ppid", "name", "exe", "user", "status", "cpu_percent", "memory_mb",
                                      "risk_level", "flags", "protected", "create_time")}
            node["children"] = kids
            node["subtree_cpu_percent"] = round(r["cpu_percent"] + sum(k["subtree_cpu_percent"] for k in kids), 1)
            node["subtree_memory_mb"] = round(r["memory_mb"] + sum(k["subtree_memory_mb"] for k in kids), 1)
            node["descendants"] = len(kids) + sum(k["descendants"] for k in kids)
            return node

        seen: set[int] = set()
        tree = [build(p, seen) for p in sorted(roots)]
        for pid in rows:                       # parent cycles (rare, PID reuse) -> still listed
            if pid not in seen:
                tree.append(build(pid, seen))
        return {"total": len(rows), "roots": len(tree), "tree": tree}

    # ================================================================== details
    def _get(self, pid: int, create_time: float | None = None) -> psutil.Process:
        try:
            p = psutil.Process(pid)
            ct = p.create_time()
        except psutil.NoSuchProcess:
            raise ProcessError(404, f"No process with PID {pid}")
        except psutil.AccessDenied:
            raise ProcessError(403, "Access denied - run Cyber Hub as administrator to manage this process")
        if create_time is not None and abs(ct - create_time) > 0.01:
            raise ProcessError(409, f"PID {pid} now belongs to a different process - refresh the list")
        return p

    def details(self, pid: int, with_hash: bool = False) -> dict:
        p = self._get(pid)
        info: dict = {"pid": pid}

        def safe(key: str, fn, default=None):
            try:
                info[key] = fn()
            except (psutil.AccessDenied, psutil.ZombieProcess, NotImplementedError, OSError, AttributeError):
                info[key] = default
            except psutil.NoSuchProcess:
                raise ProcessError(404, f"Process {pid} has exited")

        safe("name", p.name)
        safe("exe", p.exe)
        safe("cmdline", lambda: " ".join(p.cmdline()))
        safe("cwd", p.cwd)
        safe("user", p.username)
        safe("status", p.status)
        safe("create_time", p.create_time)
        info["started_at"] = _iso(info["create_time"])
        info["running_for_seconds"] = int(time.time() - info["create_time"]) if info["create_time"] else None
        safe("ppid", p.ppid)
        safe("parent", lambda: (lambda q: {"pid": q.pid, "name": q.name()} if q else None)(p.parent()))
        safe("children", lambda: [{"pid": c.pid, "name": c.name()} for c in p.children()], [])
        safe("threads", p.num_threads)
        safe("handles", lambda: p.num_handles() if IS_WINDOWS else p.num_fds())
        safe("priority", lambda: _priority_name(p))
        safe("memory", lambda: (lambda m: {"rss_mb": round(m.rss / _MB, 1), "vms_mb": round(m.vms / _MB, 1)}
                                )(p.memory_info()))
        safe("cpu_times", lambda: (lambda t: {"user_s": round(t.user, 1), "system_s": round(t.system, 1)}
                                   )(p.cpu_times()))
        safe("io", lambda: (lambda io: {"read_mb": round(io.read_bytes / _MB, 1),
                                        "write_mb": round(io.write_bytes / _MB, 1)})(p.io_counters()))
        safe("open_files", lambda: [f.path for f in p.open_files()][:50], [])
        safe("connections", lambda: [
            {"local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
             "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
             "status": c.status, "type": "tcp" if c.type == 1 else "udp"}
            for c in (p.net_connections() if hasattr(p, "net_connections") else p.connections())][:50], [])
        live = {r["pid"]: r for r in SAMPLER.top_processes("cpu", 100_000)["items"]}.get(pid, {})
        info["cpu_percent"] = live.get("cpu_percent", 0.0)
        info["disk_mb_s"] = live.get("disk_mb_s")

        sig = self.sigs.check(info["exe"]) if info["exe"] else None
        info["signature"] = sig
        info["sha256"] = sha256_file(info["exe"]) if with_hash and info["exe"] else None
        flags = tf.path_flags(info["exe"])
        if tf.is_masquerading(info["name"], info["exe"]):
            flags.append("masquerade")
        flags += [f for f in tf.command_flags(info["cmdline"]) if f in ("encoded_command", "hidden_window")]
        parent_name = ((info.get("parent") or {}).get("name") or "").lower()
        if (info["name"] or "").lower() in tf.SCRIPT_HOSTS and parent_name in tf.OFFICE_PARENTS:
            flags.append("office_child_shell")
        flags += tf.signature_flags(sig)
        info.update(tf.score(flags))
        reason = self.protection(pid, info["name"], info["exe"])
        info["protected"], info["protected_reason"] = bool(reason), reason
        info["actions"] = {"end": not reason, "suspend": not reason, "priority": not reason}
        return info

    # ================================================================== actions
    def _guard(self, p: psutil.Process) -> tuple[str, str | None]:
        try:
            name, exe = p.name(), None
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
        except psutil.NoSuchProcess:
            raise ProcessError(404, f"Process {p.pid} has exited")
        except psutil.AccessDenied:
            raise ProcessError(403, "Access denied - run Cyber Hub as administrator to manage this process")
        reason = self.protection(p.pid, name, exe)
        if reason:
            raise ProcessError(403, f"Protected: {reason}")
        return name, exe

    def _log(self, username: str, action: str, pid: int, name: str, exe: str | None, result: str,
             severity: str = "low") -> None:
        self.db.execute("INSERT INTO process_actions(username, action, pid, name, exe, result) VALUES (?,?,?,?,?,?)",
                        (username, action, pid, name, exe, result))
        self.activity.record("process", f"Process {action}: {name} (PID {pid})", result, severity, source="processes")

    def end(self, pid: int, username: str, create_time: float | None = None, tree: bool = False,
            force: bool = False, wait_seconds: float = 3.0) -> dict:
        root = self._get(pid, create_time)
        name, exe = self._guard(root)
        targets: list[psutil.Process] = []
        if tree:
            try:
                kids = root.children(recursive=True)
            except psutil.Error:
                kids = []
            for k in kids:
                try:
                    if self.protection(k.pid, k.name(), None):
                        raise ProcessError(403, f"Protected child process in tree: {k.name()} (PID {k.pid})")
                except psutil.NoSuchProcess:
                    continue
            targets.extend(reversed(kids))            # deepest first
        targets.append(root)

        ended, failed = [], []
        for t in targets:
            try:
                (t.kill if force else t.terminate)()
            except psutil.NoSuchProcess:
                ended.append(t.pid)
            except psutil.AccessDenied:
                failed.append({"pid": t.pid, "error": "access denied"})
        alive = [t for t in targets if t.pid not in ended and t.pid not in {f["pid"] for f in failed}]
        gone, still = psutil.wait_procs(alive, timeout=wait_seconds)
        ended += [g.pid for g in gone]
        if still and not force:                       # graceful end refused -> report, UI may retry with force
            still_pids = [s.pid for s in still]
        else:
            still_pids = []
            if still:
                for s in still:
                    try:
                        s.kill()
                    except psutil.Error:
                        pass
                gone2, still2 = psutil.wait_procs(still, timeout=2)
                ended += [g.pid for g in gone2]
                still_pids = [s.pid for s in still2]
        if failed and not ended:
            raise ProcessError(403, "Access denied - run Cyber Hub as administrator to end this process")
        result = ("ended" if not still_pids and not failed else
                  "partially_ended" if ended else "still_running")
        action = ("force-killed" if force else "ended") + (" (tree)" if tree else "")
        self._log(username, action, pid, name, exe, f"{result}; {len(ended)} process(es) stopped",
                  "medium" if force or tree else "low")
        return {"pid": pid, "name": name, "result": result, "ended": sorted(set(ended)),
                "still_running": still_pids, "failed": failed,
                "hint": "Use force=true to kill it" if still_pids and not force else None}

    def suspend(self, pid: int, username: str, create_time: float | None = None) -> dict:
        return self._toggle_run(pid, username, create_time, suspend=True)

    def resume(self, pid: int, username: str, create_time: float | None = None) -> dict:
        return self._toggle_run(pid, username, create_time, suspend=False)

    def _toggle_run(self, pid: int, username: str, create_time: float | None, suspend: bool) -> dict:
        p = self._get(pid, create_time)
        name, exe = self._guard(p)
        try:
            p.suspend() if suspend else p.resume()
            for _ in range(20):                       # the OS applies the signal asynchronously
                status = p.status()
                if (status == psutil.STATUS_STOPPED) == suspend:
                    break
                time.sleep(0.025)
        except psutil.NoSuchProcess:
            raise ProcessError(404, f"Process {pid} has exited")
        except psutil.AccessDenied:
            raise ProcessError(403, "Access denied - run Cyber Hub as administrator to manage this process")
        self._log(username, "suspended" if suspend else "resumed", pid, name, exe, status)
        return {"pid": pid, "name": name, "status": status, "suspended": suspend}

    def set_priority(self, pid: int, level: str, username: str, create_time: float | None = None) -> dict:
        if level not in PRIORITIES:
            raise ProcessError(422, f"priority must be one of {', '.join(PRIORITIES)}")
        p = self._get(pid, create_time)
        name, exe = self._guard(p)
        try:
            if IS_WINDOWS:
                value = {"idle": psutil.IDLE_PRIORITY_CLASS, "below_normal": psutil.BELOW_NORMAL_PRIORITY_CLASS,
                         "normal": psutil.NORMAL_PRIORITY_CLASS, "above_normal": psutil.ABOVE_NORMAL_PRIORITY_CLASS,
                         "high": psutil.HIGH_PRIORITY_CLASS}[level]
            else:
                value = _NICE[level]
            p.nice(value)
        except psutil.NoSuchProcess:
            raise ProcessError(404, f"Process {pid} has exited")
        except (psutil.AccessDenied, PermissionError):
            raise ProcessError(403, "Access denied - raising priority needs administrator / root rights")
        self._log(username, f"priority -> {level}", pid, name, exe, "ok", "info")
        return {"pid": pid, "name": name, "priority": _priority_name(p)}

    def history(self, limit: int = 50) -> list[dict]:
        return self.db.fetchall("SELECT * FROM process_actions ORDER BY id DESC LIMIT ?", (limit,))
