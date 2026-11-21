"""
Cyber Hub Backend - YARA rules engine + file inspector (Part 8)
Developed by Syed Muhammad Tayyab

RulesEngine
    YARA rule sets live in SQLite (yara_rule_sets): the built-in pack shipped
    in cyberhub/rules/*.yar plus anything you add, paste or import (.yar /
    .yara files, folders or .zip bundles such as the YARA-Forge packs).
    Every set is validated on its own, so one broken file never switches the
    others off. Backend: yara-python (libyara) when it is installed, otherwise
    the pure-Python engine in yara_lite.py (set CYBERHUB_YARA_BACKEND=lite /
    native to force one). Rules can use the external variables filename,
    filepath and extension. Rule meta understood: threat_name, severity
    (low / medium / high / critical), description.

Inspector
    The scanner's second opinion for files no hash signature knows: runs the
    YARA rules and the heuristic engine, turns the strongest finding into one
    verdict per file, and remembers it per (SHA-256, file name) together with
    the rules + heuristics version - unchanged files are never re-analysed.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from ..database import Database
from ..logger import get_logger
from . import yara_lite
from .heuristics import SENSITIVITY, HeuristicEngine, entropy

log = get_logger("rules")

try:                                                             # optional native engine
    import yara as _yara                                         # type: ignore
except Exception:                                                # pragma: no cover - depends on the PC
    _yara = None

BUILTIN_DIR = Path(__file__).resolve().parent.parent / "rules"
EXTERNALS = {"filename": "", "filepath": "", "extension": ""}
SEVERITIES = ("low", "medium", "high", "critical")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES, 1)}
MAX_SET_BYTES = 2 * 1024 * 1024
MAX_SETS = 1000
MATCH_TIMEOUT = 20
RULE_EXT = (".yar", ".yara", ".rule", ".rules")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


class RulesError(Exception):
    def __init__(self, status: int, message: str, line: int | None = None):
        super().__init__(message)
        self.status, self.message, self.line = status, message, line


def _line_of(msg: str) -> int | None:
    import re
    m = re.search(r"line (\d+)", msg)
    return int(m.group(1)) if m else None


def pick_backend(requested: str | None = None) -> str:
    want = (requested or os.environ.get("CYBERHUB_YARA_BACKEND") or "auto").lower()
    if want == "lite" or _yara is None:
        return "lite"
    return "native"


class RulesEngine:
    def __init__(self, db: Database, activity=None, backend: str | None = None):
        self.db, self.activity = db, activity
        self.backend = pick_backend(backend)
        self._lock = threading.RLock()
        self._compiled = None
        self._ns: dict[str, dict] = {}                   # namespace -> {id, name}
        self.version = "none"
        self.rule_count = 0
        self.compiled_at: str | None = None
        self._seed_builtin()
        self.reload()

    # ------------------------------------------------------------ backend info
    def backend_info(self) -> dict:
        if self.backend == "native":
            return {"name": "native", "label": "YARA (libyara)", "version": getattr(_yara, "__version__", None),
                    "libyara": getattr(_yara, "YARA_VERSION", None), "modules": True}
        return {"name": "lite", "label": "Cyber Hub YARA-lite (pure Python)", "version": "1.0",
                "modules": False, "native_available": _yara is not None,
                "note": "Install yara-python for modules (pe, math, hash...), for-loops and xor/base64 strings"}

    # ------------------------------------------------------------ compile helpers
    def _check(self, text: str) -> tuple[str, str | None]:
        """-> (status ok|error|unsupported, error message)."""
        if not text.strip():
            return "error", "The rule set is empty"
        if self.backend == "native":
            try:
                _yara.compile(source=text, externals=EXTERNALS)
                return "ok", None
            except _yara.SyntaxError as e:
                return "error", str(e)
            except _yara.Error as e:                              # pragma: no cover
                return "error", str(e)
        try:
            yara_lite.compile_sources({"check": text}, EXTERNALS)
            return "ok", None
        except yara_lite.LiteUnsupported as e:
            return "unsupported", f"{e} - needs native YARA (pip install yara-python)"
        except yara_lite.LiteError as e:
            return "error", str(e)

    def validate(self, text: str) -> dict:
        status, err = self._check(text)
        names = yara_lite.rule_names(text)
        return {"valid": status == "ok", "status": status, "error": err, "line": _line_of(err or ""),
                "rules": names, "rule_count": len(names), "backend": self.backend}

    def reload(self) -> dict:
        """Re-validate every set and compile the enabled, valid ones into one ruleset."""
        with self._lock:
            rows = self.db.fetchall("SELECT * FROM yara_rule_sets ORDER BY origin='builtin' DESC, name")
            sources, ns = {}, {}
            for r in rows:
                status, err = self._check(r["source"])
                names = yara_lite.rule_names(r["source"])
                if (status, err, len(names)) != (r["status"], r["error"], r["rule_count"]):
                    self.db.execute("UPDATE yara_rule_sets SET status=?, error=?, rule_count=?, rule_names=? "
                                    "WHERE id=?", (status, err, len(names), json.dumps(names[:2000]), r["id"]))
                if r["enabled"] and status == "ok":
                    key = f"set{r['id']}"
                    sources[key] = r["source"]
                    ns[key] = {"id": r["id"], "name": r["name"], "origin": r["origin"], "rules": len(names)}
            compiled = None
            if sources:
                try:
                    if self.backend == "native":
                        compiled = _yara.compile(sources=sources, externals=EXTERNALS)
                    else:
                        compiled = yara_lite.compile_sources(sources, EXTERNALS)
                except Exception as e:                            # pragma: no cover - each set compiled alone first
                    log.error("Combined rule compile failed: %s", e)
                    compiled = None
            h = hashlib.sha256(self.backend.encode())
            for k in sorted(sources):
                h.update(k.encode() + b"\0" + hashlib.sha256(sources[k].encode()).digest())
            self._compiled, self._ns = compiled, ns
            self.version = h.hexdigest()[:16] if sources else "none"
            self.rule_count = sum(v["rules"] for v in ns.values())
            self.compiled_at = _now()
            return {"version": self.version, "sets": len(ns), "rules": self.rule_count}

    @property
    def available(self) -> bool:
        return self._compiled is not None

    # ------------------------------------------------------------ built-in pack
    def _seed_builtin(self) -> None:
        if not BUILTIN_DIR.is_dir():                              # pragma: no cover
            return
        for f in sorted(BUILTIN_DIR.glob("*.yar")):
            text = f.read_text(encoding="utf-8")
            name = "builtin/" + f.stem.split("_", 1)[-1]
            sha = hashlib.sha256(text.encode()).hexdigest()
            row = self.db.fetchone("SELECT id, sha256 FROM yara_rule_sets WHERE name=?", (name,))
            if row is None:
                self.db.execute("INSERT INTO yara_rule_sets(name, origin, source, sha256, created_by) "
                                "VALUES (?, 'builtin', ?, ?, 'Cyber Hub')", (name, text, sha))
            elif row["sha256"] != sha:                            # app update ships newer built-in rules
                self.db.execute("UPDATE yara_rule_sets SET source=?, sha256=?, updated_at=?, status=NULL "
                                "WHERE id=? AND origin='builtin'", (text, sha, _now(), row["id"]))

    # ------------------------------------------------------------ matching
    @staticmethod
    def externals_for(name: str, path: str | None = None) -> dict:
        base = os.path.basename((name or "").replace("\\", "/"))
        return {"filename": base, "filepath": path or name or "",
                "extension": os.path.splitext(base)[1].lower()}

    def match(self, data: bytes, name: str, path: str | None = None) -> list[dict]:
        compiled, ns = self._compiled, self._ns
        if compiled is None:
            return []
        ext = self.externals_for(name, path)
        hits = []
        if self.backend == "native":
            try:
                raw = compiled.match(data=data, externals=ext, timeout=MATCH_TIMEOUT)
            except _yara.TimeoutError:                            # pragma: no cover
                log.warning("YARA timed out on %s", name)
                return []
            for m in raw:
                strs = []
                for s in getattr(m, "strings", [])[:40]:
                    if hasattr(s, "instances"):                  # yara-python >= 4.3
                        for inst in s.instances[:10]:
                            strs.append((s.identifier, inst.offset, inst.matched_length, bytes(inst.matched_data)[:64]))
                    else:                                         # pragma: no cover - old tuple API
                        strs.append((s[1], s[0], len(s[2]), s[2][:64]))
                hits.append(self._hit(m.rule, m.namespace, list(m.tags), dict(m.meta), strs, ns))
        else:
            for m in compiled.match(data, ext):
                hits.append(self._hit(m.rule, m.namespace, m.tags, m.meta, m.strings, ns))
        return hits

    @staticmethod
    def _hit(rule, namespace, tags, meta, strs, ns) -> dict:
        sev = str(meta.get("severity", "")).lower()
        if sev not in SEVERITIES:
            sev = "medium"
        info = ns.get(namespace, {})
        return {"rule": rule, "set_id": info.get("id"), "set": info.get("name"), "tags": tags,
                "threat_name": str(meta.get("threat_name") or f"YARA:{rule}")[:120], "severity": sev,
                "description": str(meta.get("description") or "")[:300],
                "strings": [{"id": sid, "offset": off, "length": ln,
                             "preview": raw.decode("latin-1").encode("unicode_escape").decode()[:80]}
                            for sid, off, ln, raw in strs[:25]]}

    # ------------------------------------------------------------ rule set management
    def _row(self, set_id: int) -> dict:
        r = self.db.fetchone("SELECT * FROM yara_rule_sets WHERE id=?", (set_id,))
        if not r:
            raise RulesError(404, "Rule set not found")
        return r

    @staticmethod
    def _view(r: dict, with_source: bool = False) -> dict:
        out = {k: v for k, v in r.items() if k != "source"}
        out["enabled"] = bool(out["enabled"])
        out["rule_names"] = json.loads(out.get("rule_names") or "[]")
        out["active"] = out["enabled"] and out["status"] == "ok"
        out["size"] = len(r["source"])
        if with_source:
            out["source"] = r["source"]
        return out

    def list_sets(self) -> list[dict]:
        rows = self.db.fetchall("SELECT * FROM yara_rule_sets ORDER BY origin='builtin' DESC, name")
        hits = {r["sid"]: r for r in self.db.fetchall(
            "SELECT json_extract(details,'$.set_id') AS sid, COUNT(*) AS n, MAX(detected_at) AS last "
            "FROM scan_detections WHERE method='yara' GROUP BY sid")}
        out = []
        for r in rows:
            v = self._view(r)
            h = hits.get(r["id"])
            v["detections"], v["last_detection"] = (h["n"], h["last"]) if h else (0, None)
            out.append(v)
        return out

    def get_set(self, set_id: int) -> dict:
        return self._view(self._row(set_id), with_source=True)

    def _clean_name(self, name: str) -> str:
        name = " ".join((name or "").split())[:80]
        if not name:
            raise RulesError(422, "Give the rule set a name")
        if name.lower().startswith("builtin/"):
            raise RulesError(422, "Names starting with builtin/ are reserved")
        return name

    def add_set(self, name: str, source: str, username: str, origin: str = "user", enabled: bool = True,
                replace: bool = False) -> dict:
        name = self._clean_name(name)
        if len(source.encode()) > MAX_SET_BYTES:
            raise RulesError(413, "Rule set is too large (2 MB max) - split it into several files")
        chk = self.validate(source)
        if chk["status"] == "error":
            raise RulesError(422, f"Rule error: {chk['error']}", chk["line"])
        sha = hashlib.sha256(source.encode()).hexdigest()
        old = self.db.fetchone("SELECT * FROM yara_rule_sets WHERE name=? COLLATE NOCASE", (name,))
        if old:
            if not replace:
                raise RulesError(409, f"A rule set called '{name}' already exists")
            if old["origin"] == "builtin":                        # pragma: no cover - blocked by _clean_name
                raise RulesError(403, "Built-in rule sets can't be replaced")
            self.db.execute("UPDATE yara_rule_sets SET source=?, sha256=?, enabled=?, origin=?, updated_at=?, "
                            "updated_by=?, status=NULL WHERE id=?",
                            (source, sha, int(enabled), origin, _now(), username, old["id"]))
            sid = old["id"]
        else:
            if self.db.fetchone("SELECT COUNT(*) AS n FROM yara_rule_sets")["n"] >= MAX_SETS:
                raise RulesError(409, f"Too many rule sets (max {MAX_SETS})")
            sid = self.db.execute("INSERT INTO yara_rule_sets(name, origin, source, sha256, enabled, created_by) "
                                  "VALUES (?,?,?,?,?,?)", (name, origin, source, sha, int(enabled), username)).lastrowid
        self.reload()
        if self.activity:
            self.activity.record("rules", "YARA rules added" if not old else "YARA rules updated",
                                 f"{name}: {chk['rule_count']} rule(s)" +
                                 (" - needs native YARA" if chk["status"] == "unsupported" else ""),
                                 severity="low", source="rules")
        return self.get_set(sid)

    def update_set(self, set_id: int, username: str, enabled: bool | None = None, name: str | None = None,
                   source: str | None = None) -> dict:
        r = self._row(set_id)
        if r["origin"] == "builtin" and (name is not None or source is not None):
            raise RulesError(403, "Built-in rule sets can be switched off but not edited - copy one into a new set")
        sets, params = [], []
        if name is not None:
            nm = self._clean_name(name)
            dup = self.db.fetchone("SELECT id FROM yara_rule_sets WHERE name=? COLLATE NOCASE AND id != ?",
                                   (nm, set_id))
            if dup:
                raise RulesError(409, f"A rule set called '{nm}' already exists")
            sets.append("name=?"); params.append(nm)
        if source is not None:
            if len(source.encode()) > MAX_SET_BYTES:
                raise RulesError(413, "Rule set is too large (2 MB max)")
            chk = self.validate(source)
            if chk["status"] == "error":
                raise RulesError(422, f"Rule error: {chk['error']}", chk["line"])
            sets += ["source=?", "sha256=?", "status=NULL"]
            params += [source, hashlib.sha256(source.encode()).hexdigest()]
        if enabled is not None:
            sets.append("enabled=?"); params.append(int(enabled))
        if not sets:
            return self.get_set(set_id)
        sets += ["updated_at=?", "updated_by=?"]
        params += [_now(), username, set_id]
        self.db.execute(f"UPDATE yara_rule_sets SET {', '.join(sets)} WHERE id=?", tuple(params))
        self.reload()
        if self.activity:
            what = "switched off" if enabled is False else "switched on" if enabled else "edited"
            self.activity.record("rules", f"YARA rule set {what}", r["name"],
                                 severity="medium" if enabled is False else "low", source="rules")
        return self.get_set(set_id)

    def delete_set(self, set_id: int) -> int:
        r = self._row(set_id)
        if r["origin"] == "builtin":
            raise RulesError(403, "Built-in rule sets can be switched off but not deleted")
        n = self.db.execute("DELETE FROM yara_rule_sets WHERE id=?", (set_id,)).rowcount
        self.reload()
        if self.activity:
            self.activity.record("rules", "YARA rule set deleted", r["name"], severity="low", source="rules")
        return n

    def import_path(self, path: str, username: str, prefix: str | None = None, replace: bool = True) -> dict:
        """Import a .yar file, a folder of them, or a .zip bundle. Each file becomes one rule set."""
        p = os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
        if not os.path.exists(p):
            raise RulesError(404, "Not found")
        files: list[tuple[str, str]] = []
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    if n.lower().endswith(RULE_EXT):
                        fp = os.path.join(root, n)
                        if os.path.getsize(fp) <= MAX_SET_BYTES:
                            files.append((os.path.relpath(fp, p), open(fp, encoding="utf-8", errors="replace").read()))
                if len(files) > 500:
                    break
        elif zipfile.is_zipfile(p):
            if os.path.getsize(p) > 64 * 1024 * 1024:
                raise RulesError(413, "Rule bundle is too large (64 MB max)")
            with zipfile.ZipFile(p) as z:
                for i in z.infolist():
                    if not i.is_dir() and i.filename.lower().endswith(RULE_EXT) and i.file_size <= MAX_SET_BYTES \
                            and not i.flag_bits & 0x1:
                        files.append((i.filename, z.read(i).decode("utf-8", errors="replace")))
                    if len(files) > 500:
                        break
        elif p.lower().endswith(RULE_EXT) or os.path.getsize(p) <= MAX_SET_BYTES:
            if os.path.getsize(p) > MAX_SET_BYTES:
                raise RulesError(413, "Rule file is too large (2 MB max)")
            files.append((os.path.basename(p), open(p, encoding="utf-8", errors="replace").read()))
        else:
            raise RulesError(422, "Choose a .yar / .yara file, a folder of them or a .zip bundle")
        if not files:
            raise RulesError(422, "No .yar / .yara rule files found")
        prefix = (prefix or os.path.splitext(os.path.basename(p.rstrip("/\\")))[0])[:40]
        imported, failed = [], []
        for rel, text in files[:500]:
            stem = os.path.splitext(rel.replace("\\", "/"))[0]
            name = f"{prefix}/{stem}"[:80] if len(files) > 1 else (prefix if prefix else stem)[:80]
            try:
                s = self.add_set(name, text, username, origin="import", replace=replace)
                imported.append({"id": s["id"], "name": s["name"], "rules": s["rule_count"], "status": s["status"]})
            except RulesError as e:
                failed.append({"file": rel, "error": e.message, "line": e.line})
        return {"imported": imported, "failed": failed, "files": len(files),
                "rules": sum(i["rules"] for i in imported)}

    def summary(self) -> dict:
        rows = self.db.fetchall("SELECT origin, enabled, status, COUNT(*) AS sets, SUM(rule_count) AS rules "
                                "FROM yara_rule_sets GROUP BY origin, enabled, status")
        by_status: dict[str, int] = {}
        for r in rows:
            k = r["status"] if r["enabled"] else "disabled"
            by_status[k] = by_status.get(k, 0) + r["sets"]
        return {"backend": self.backend_info(), "version": self.version, "compiled_at": self.compiled_at,
                "active_rules": self.rule_count, "active_sets": len(self._ns),
                "sets_total": sum(r["sets"] for r in rows), "sets_by_status": by_status,
                "rules_total": sum(r["rules"] or 0 for r in rows)}


# ====================================================================== inspector
class Inspector:
    """Runs YARA + heuristics for the scanner, real-time protection and the Analyze page."""

    def __init__(self, db: Database, settings, rules: RulesEngine, heuristics: HeuristicEngine | None = None,
                 signatures=None):
        self.db, self.settings, self.rules = db, settings, rules
        self.heuristics = heuristics or HeuristicEngine()
        self.signatures = signatures
        self.stats = {"analysed": 0, "cache_hits": 0, "yara_hits": 0, "heuristic_hits": 0}

    def options(self) -> dict:
        g = self.settings.get
        return {"yara": bool(g("yara_enabled")), "heuristics": bool(g("heuristics_enabled")),
                "sensitivity": g("heuristics_sensitivity"), "max_bytes": g("rules_max_file_mb") * 1024 * 1024,
                "archives": bool(g("rules_scan_archives"))}

    def version(self, o: dict) -> str:
        return (f"{self.rules.version if o['yara'] else 'off'}|"
                f"{self.heuristics.version + ':' + o['sensitivity'] if o['heuristics'] else 'off'}|{o['max_bytes']}")

    def enabled(self, o: dict | None = None) -> bool:
        o = o or self.options()
        return (o["yara"] and self.rules.available) or o["heuristics"]

    # ------------------------------------------------------------ cache
    def _cached(self, sha256: str, name_key: str, version: str) -> list[dict] | None:
        r = self.db.fetchone("SELECT version, result FROM rule_verdict_cache WHERE sha256=? AND name_key=?",
                             (sha256, name_key))
        if r and r["version"] == version:
            return json.loads(r["result"])
        return None

    def _store(self, sha256: str, name_key: str, version: str, verdicts: list[dict]) -> None:
        self.db.execute("INSERT INTO rule_verdict_cache(sha256, name_key, version, result, checked_at) "
                        "VALUES (?,?,?,?,?) ON CONFLICT(sha256, name_key) DO UPDATE SET version=excluded.version, "
                        "result=excluded.result, checked_at=excluded.checked_at",
                        (sha256, name_key, version, json.dumps(verdicts), _now()))

    def clear_cache(self) -> int:
        return self.db.execute("DELETE FROM rule_verdict_cache").rowcount

    def cache_size(self) -> int:
        return self.db.fetchone("SELECT COUNT(*) AS n FROM rule_verdict_cache")["n"]

    # ------------------------------------------------------------ verdicts
    def inspect(self, sha256: str, name: str, size: int, data: bytes | None = None, path: str | None = None,
                o: dict | None = None) -> list[dict]:
        """One verdict (or none) for a file. `data` may be None - it is read from `path` only on a cache miss."""
        o = o or self.options()
        if not self.enabled(o):
            return []
        name_key = os.path.basename((name or "").replace("\\", "/")).lower()[:255]
        version = self.version(o)
        hit = self._cached(sha256, name_key, version)
        if hit is not None:
            self.stats["cache_hits"] += 1
            return hit
        partial = size > o["max_bytes"]
        if data is None and path:
            try:
                with open(path, "rb") as f:
                    data = f.read(65536 if partial else o["max_bytes"] + 1)
            except OSError:
                return []
        data = data or b""
        if len(data) > o["max_bytes"]:
            partial, data = True, data[:65536]
        verdicts = self._decide(data, name, size, partial, o, path)
        self._store(sha256, name_key, version, verdicts)
        self.stats["analysed"] += 1
        return verdicts

    def _decide(self, data: bytes, name: str, size: int, partial: bool, o: dict, path: str | None) -> list[dict]:
        if o["yara"] and not partial and self.rules.available:
            hits = self.rules.match(data, name, path)
            if hits:
                self.stats["yara_hits"] += 1
                best = max(hits, key=lambda h: SEV_ORDER.get(h["severity"], 0))
                return [{"threat_name": best["threat_name"], "severity": best["severity"], "method": "yara",
                         "signature_source": f"yara:{best['set']}",
                         "details": {"rule": best["rule"], "set": best["set"], "set_id": best["set_id"],
                                     "description": best["description"], "tags": best["tags"],
                                     "strings": best["strings"][:10],
                                     "also_matched": [h["rule"] for h in hits if h is not best][:20]}}]
        if o["heuristics"]:
            rep = self.heuristics.analyze(data, name, size, partial)
            v = self.heuristics.verdict(rep, o["sensitivity"])
            if v and rep.get("pe", {}).get("has_certificate") and self.signatures is not None and path:
                sig = self.signatures.cached(path)                # Windows: a valid publisher signature wins
                if sig and sig.get("signed"):
                    return []
            if v:
                self.stats["heuristic_hits"] += 1
                return [v]
        return []

    # ------------------------------------------------------------ analyze page
    def analyze_file(self, path: str) -> dict:
        """Full, uncached report for one file: hashes, type, PE details, every YARA hit, every heuristic flag."""
        o = self.options()
        st = os.stat(path)
        partial = st.st_size > o["max_bytes"]
        h256, h1, h5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
        data = bytearray()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h256.update(chunk); h1.update(chunk); h5.update(chunk)
                if len(data) < (65536 if partial else o["max_bytes"]):
                    data += chunk
        data = bytes(data[:65536] if partial else data)
        rep = self.analyze_bytes(data, os.path.basename(path), st.st_size, partial, path)
        rep.update(path=path, sha256=h256.hexdigest(), sha1=h1.hexdigest(), md5=h5.hexdigest())
        return rep

    def analyze_bytes(self, data: bytes, name: str, size: int | None = None, partial: bool = False,
                      path: str | None = None) -> dict:
        o = self.options()
        size = len(data) if size is None else size
        hits = self.rules.match(data, name, path) if (not partial and self.rules.available) else []
        rep = self.heuristics.analyze(data, name, size, partial)
        threshold = SENSITIVITY.get(o["sensitivity"], 60)
        hv = self.heuristics.verdict(rep, o["sensitivity"])
        yv = max(hits, key=lambda h: SEV_ORDER.get(h["severity"], 0)) if hits else None
        verdict = None
        if yv and o["yara"]:
            verdict = {"threat_name": yv["threat_name"], "severity": yv["severity"], "method": "yara"}
        elif hv and o["heuristics"]:
            verdict = {k: hv[k] for k in ("threat_name", "severity", "method")}
        return {"name": name, "size": size, "partial": partial, "file_type": rep["file_type"],
                "entropy": round(entropy(data[:4 * 1024 * 1024]), 3),
                "verdict": verdict, "malicious": verdict is not None,
                "yara": {"enabled": o["yara"], "backend": self.rules.backend, "matches": hits},
                "heuristics": {"enabled": o["heuristics"], "score": rep["score"], "level": rep["level"],
                               "threshold": threshold, "sensitivity": o["sensitivity"], "category": rep["category"],
                               "flags": rep["flags"]},
                **({"pe": rep["pe"]} if "pe" in rep else {})}

    def self_test(self) -> dict:
        marker = b"CYBERHUB-RULES-" + b"ENGINE-TEST-STRING"
        y = self.rules.match(b"hello " + marker + b"\n", "rules-test.txt") if self.rules.available else []
        heur = self.heuristics.analyze(b"MZ" + b"\x00" * 62, "invoice.pdf.exe", 64)
        clean = self.heuristics.analyze(b"just some notes\n" * 20, "notes.txt")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("photo.jpg.scr", b"MZ" + b"\x00" * 100)
        arch = self.heuristics.analyze(buf.getvalue(), "photos.zip")
        checks = {
            "yara_rules_loaded": self.rules.available and self.rules.rule_count > 0,
            "yara_match": any(h["rule"] == "CyberHub_RulesEngine_TestFile" for h in y),
            "heuristic_double_extension": any(f["id"] == "double_extension" for f in heur["flags"]),
            "heuristic_archive_check": any(f["id"] == "archive_double_extension" for f in arch["flags"]),
            "clean_file_passes": clean["score"] == 0,
        }
        return {"passed": all(checks.values()), "checks": checks, "backend": self.rules.backend_info(),
                "rules": self.rules.rule_count}
