"""
Cyber Hub Backend - Rules engine, heuristics & online lookup routes (Part 8)
Developed by Syed Muhammad Tayyab

/api/rules   YARA rule sets (built-in pack + your own), validation, file analysis,
             heuristic checks, verdict cache, detections found by rules / heuristics
/api/lookup  VirusTotal / MalwareBazaar hash reputation (opt-in, hashes only)

Anyone signed in can view rules, analyse a file and validate rule text.
Adding / changing / switching off rules, API keys and caches needs a
Cyber Hub administrator.
"""
from __future__ import annotations

import base64
import binascii
import os
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..security import CurrentUser, require_admin, require_session, require_token
from ..services.cloud_lookup import PROVIDERS, CloudError
from ..services.heuristics import SENSITIVITY
from ..services.rules_engine import RulesError

router = APIRouter(prefix="/api/rules", tags=["rules"], dependencies=[Depends(require_token), Depends(require_session)])
lookup_router = APIRouter(prefix="/api/lookup", tags=["lookup"],
                          dependencies=[Depends(require_token), Depends(require_session)])

MAX_SAMPLE = 20 * 1024 * 1024


def _rules(request: Request):
    return request.app.state.rules


def _insp(request: Request):
    return request.app.state.inspector


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except RulesError as e:
        raise HTTPException(e.status, {"message": e.message, "line": e.line} if e.line else e.message)


def _path(p: str) -> str:
    return os.path.abspath(os.path.expandvars(os.path.expanduser(p.strip())))


# ================================================================== overview
@router.get("/status")
def rules_status(request: Request):
    """Engine backend, active rules, settings, cache size and hit counters - the Rules page header."""
    g = request.app.state.settings_store.get
    insp = _insp(request)
    det = request.app.state.db.fetchall(
        "SELECT method, status, COUNT(*) AS n FROM scan_detections WHERE method IN ('yara','heuristic','cloud') "
        "GROUP BY method, status")
    by = {}
    for r in det:
        by.setdefault(r["method"], {})[r["status"]] = r["n"]
    return {**_rules(request).summary(),
            "settings": {"yara_enabled": g("yara_enabled"), "heuristics_enabled": g("heuristics_enabled"),
                         "heuristics_sensitivity": g("heuristics_sensitivity"),
                         "heuristics_threshold": SENSITIVITY[g("heuristics_sensitivity")],
                         "heuristics_auto_quarantine": g("heuristics_auto_quarantine"),
                         "rules_max_file_mb": g("rules_max_file_mb"), "rules_scan_archives": g("rules_scan_archives")},
            "verdict_cache": insp.cache_size(), "session_stats": dict(insp.stats), "detections": by}


@router.get("/summary")
def rules_summary(request: Request, days: int = Query(30, ge=1, le=365)):
    """Charts: detections per day by method, top rules / heuristic categories, file types."""
    db = request.app.state.db
    since = f"-{days} days"
    per_day = db.fetchall(
        "SELECT substr(detected_at,1,10) AS day, method, COUNT(*) AS n FROM scan_detections "
        "WHERE method IN ('yara','heuristic','cloud') AND detected_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?) "
        "GROUP BY day, method ORDER BY day", (since,))
    top = db.fetchall(
        "SELECT threat_name, method, severity, COUNT(*) AS n, MAX(detected_at) AS last FROM scan_detections "
        "WHERE method IN ('yara','heuristic','cloud') AND detected_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?) "
        "GROUP BY threat_name, method ORDER BY n DESC LIMIT 15", (since,))
    sev = db.fetchall(
        "SELECT severity, COUNT(*) AS n FROM scan_detections WHERE method IN ('yara','heuristic','cloud') "
        "AND detected_at >= strftime('%Y-%m-%dT%H:%M:%fZ','now',?) GROUP BY severity", (since,))
    return {"days": days, "per_day": per_day, "top_threats": top, "by_severity": {r["severity"]: r["n"] for r in sev}}


@router.post("/self-test")
def rules_self_test(request: Request):
    """YARA test marker, double-extension and archive heuristics, clean file - all in memory."""
    return _insp(request).self_test()


@router.get("/heuristics")
def heuristic_checks(request: Request):
    """Every heuristic check with its weight and category, and the sensitivity thresholds."""
    h = _insp(request).heuristics
    return {"engine": h.version, "thresholds": SENSITIVITY,
            "sensitivity": request.app.state.settings_store.get("heuristics_sensitivity"), "checks": h.checks()}


@router.get("/detections")
def rule_detections(request: Request, method: Literal["yara", "heuristic", "cloud", "all"] = "all",
                    status: str = Query("all", max_length=20), limit: int = Query(100, ge=1, le=1000),
                    offset: int = Query(0, ge=0)):
    """Detections made by rules, heuristics or online lookup, with the reason (details) for each."""
    import json
    db = request.app.state.db
    where = ["method IN ('yara','heuristic','cloud')" if method == "all" else "method=?"]
    params: list = [] if method == "all" else [method]
    if status != "all":
        where.append("status=?"); params.append(status)
    clause = " AND ".join(where)
    total = db.fetchone(f"SELECT COUNT(*) AS n FROM scan_detections WHERE {clause}", tuple(params))["n"]
    items = db.fetchall(f"SELECT * FROM scan_detections WHERE {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                        tuple(params) + (limit, offset))
    for i in items:
        i["details"] = json.loads(i["details"]) if i.get("details") else None
    return {"total": total, "items": items}


# ================================================================== analyse
class AnalyzeIn(BaseModel):
    path: str | None = Field(None, max_length=4096)
    content_base64: str | None = Field(None, max_length=MAX_SAMPLE * 4 // 3 + 16,
                                       description="Or: the file bytes, base64 encoded (max 20 MB)")
    name: str = Field("sample.bin", max_length=255, description="File name to use with content_base64")
    lookup: bool = Field(False, description="Also show the cached online reputation of the hash")


@router.post("/analyze")
def analyze(request: Request, body: AnalyzeIn):
    """Deep-dive one file without recording anything: hashes, file type, entropy, PE details
    (sections, entropy, imports, packer), every YARA match with matched strings, every heuristic flag."""
    insp = _insp(request)
    if bool(body.path) == bool(body.content_base64):
        raise HTTPException(422, "Send either 'path' or 'content_base64'")
    if body.path:
        p = _path(body.path)
        if not os.path.exists(p):
            raise HTTPException(404, "File not found")
        if os.path.isdir(p):
            raise HTTPException(422, "That is a folder - choose a file")
        try:
            rep = insp.analyze_file(p)
        except PermissionError:
            raise HTTPException(403, "Access denied - run Cyber Hub as administrator to read this file")
        except OSError as e:
            raise HTTPException(409, f"Can't read the file: {e.strerror or e}")
    else:
        try:
            data = base64.b64decode(body.content_base64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(422, "content_base64 is not valid base64")
        if len(data) > MAX_SAMPLE:
            raise HTTPException(413, "Sample is too large (20 MB max)")
        import hashlib
        rep = insp.analyze_bytes(data, os.path.basename(body.name) or "sample.bin")
        rep.update(sha256=hashlib.sha256(data).hexdigest(), sha1=hashlib.sha1(data).hexdigest(),
                   md5=hashlib.md5(data).hexdigest(), path=None)
    sig = request.app.state.malware_db.lookup(sha256=rep["sha256"], sha1=rep["sha1"], md5=rep["md5"])
    rep["signature_match"] = sig
    if sig:
        rep["verdict"] = {"threat_name": sig["name"], "severity": sig["severity"], "method": "hash"}
        rep["malicious"] = True
    if body.lookup:
        rep["reputation"] = request.app.state.db.fetchall(
            "SELECT provider, verdict, malicious, total, threat_label, permalink, checked_at FROM hash_reputation "
            "WHERE hash IN (?,?,?)", (rep["sha256"], rep["sha1"], rep["md5"]))
    return rep


# ================================================================== rule sets
class RuleSetIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    source: str = Field(..., min_length=1, max_length=2 * 1024 * 1024)
    enabled: bool = True
    replace: bool = False


class RuleSetPatch(BaseModel):
    enabled: bool | None = None
    name: str | None = Field(None, min_length=1, max_length=80)
    source: str | None = Field(None, min_length=1, max_length=2 * 1024 * 1024)


class ValidateIn(BaseModel):
    source: str = Field(..., min_length=1, max_length=2 * 1024 * 1024)


class ImportIn(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096,
                      description="A .yar / .yara file, a folder of them, or a .zip bundle (e.g. YARA-Forge)")
    prefix: str | None = Field(None, max_length=40, description="Name prefix, defaults to the file / folder name")
    replace: bool = True


@router.get("")
def list_rule_sets(request: Request):
    return {"items": _rules(request).list_sets(), "backend": _rules(request).backend_info()}


@router.get("/{set_id}")
def get_rule_set(request: Request, set_id: int):
    return _run(_rules(request).get_set, set_id)


@router.post("/validate")
def validate_rules(request: Request, body: ValidateIn):
    """Check rule text without saving it (live editor feedback: error + line number)."""
    return _rules(request).validate(body.source)


@router.post("", status_code=201)
def add_rule_set(request: Request, body: RuleSetIn, cu: CurrentUser = Depends(require_admin)):
    return _run(_rules(request).add_set, body.name, body.source, cu.user["username"], "user", body.enabled,
                body.replace)


@router.post("/import")
def import_rule_sets(request: Request, body: ImportIn, cu: CurrentUser = Depends(require_admin)):
    res = _run(_rules(request).import_path, body.path, cu.user["username"], body.prefix, body.replace)
    request.app.state.activity.record("rules", "YARA rules imported",
                                      f"{len(res['imported'])} set(s), {res['rules']} rule(s)"
                                      + (f", {len(res['failed'])} failed" if res["failed"] else ""),
                                      severity="low", source="rules")
    return res


@router.patch("/{set_id}")
def patch_rule_set(request: Request, set_id: int, body: RuleSetPatch, cu: CurrentUser = Depends(require_admin)):
    return _run(_rules(request).update_set, set_id, cu.user["username"], body.enabled, body.name, body.source)


@router.delete("/{set_id}")
def delete_rule_set(request: Request, set_id: int, cu: CurrentUser = Depends(require_admin)):
    return {"deleted": _run(_rules(request).delete_set, set_id)}


@router.post("/reload")
def reload_rules(request: Request, cu: CurrentUser = Depends(require_admin)):
    return _rules(request).reload()


@router.delete("/cache/verdicts")
def clear_verdict_cache(request: Request, cu: CurrentUser = Depends(require_admin)):
    """Forget remembered rule / heuristic verdicts - files are analysed again on the next scan."""
    return {"deleted": _insp(request).clear_cache()}


# ================================================================== online lookup
def _cloud(request: Request):
    return request.app.state.cloud


def _crun(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except CloudError as e:
        headers = {"Retry-After": str(e.retry_after)} if e.retry_after else None
        raise HTTPException(e.status, e.message, headers=headers)


class KeysIn(BaseModel):
    virustotal: str | None = Field(None, max_length=256, description="Empty string removes the key")
    malwarebazaar: str | None = Field(None, max_length=256, description="abuse.ch Auth-Key; empty removes it")


class LookupIn(BaseModel):
    hash: str = Field(..., min_length=32, max_length=64)
    providers: list[Literal["virustotal", "malwarebazaar"]] | None = None
    force: bool = Field(False, description="Ignore the cache and ask again")


class LookupFileIn(BaseModel):
    path: str = Field(..., min_length=1, max_length=4096)
    providers: list[Literal["virustotal", "malwarebazaar"]] | None = None
    force: bool = False


@lookup_router.get("/status")
def lookup_status(request: Request):
    """On / off, providers (key set? requests today / limits), background queue, cache - never the keys."""
    return _cloud(request).status()


@lookup_router.put("/keys")
def put_keys(request: Request, body: KeysIn, cu: CurrentUser = Depends(require_admin)):
    """Save / remove API keys. Stored encrypted with the vault master key; only a hint is ever returned."""
    sent = body.model_dump(exclude_unset=True)
    if not sent:
        raise HTTPException(422, "Send virustotal and / or malwarebazaar")
    for p in PROVIDERS:
        if p in sent:
            _crun(_cloud(request).set_key, p, sent[p] or None, cu.user["username"])
    return _cloud(request).status()


@lookup_router.post("/hash")
def lookup_hash(request: Request, body: LookupIn):
    """Is this MD5 / SHA-1 / SHA-256 known malware online? Cached; rate-limited per provider."""
    return _crun(_cloud(request).lookup, body.hash, body.providers, body.force)


@lookup_router.post("/file")
def lookup_file(request: Request, body: LookupFileIn):
    """Hash a file on this PC and look the hash up (the file itself is never uploaded)."""
    from ..services.signatures import sha256_file
    p = _path(body.path)
    if not os.path.isfile(p):
        raise HTTPException(404, "File not found")
    h = sha256_file(p)
    if h is None:
        raise HTTPException(409, "Can't read the file (locked, access denied or over 1 GB)")
    res = _crun(_cloud(request).lookup, h, body.providers, body.force)
    res["path"] = p
    request.app.state.activity.record("scan", "Online lookup", f"{p}: {res['verdict']}",
                                      severity="high" if res["verdict"] == "malicious" else "info", source="cloud")
    return res


@lookup_router.post("/test")
def test_keys(request: Request, cu: CurrentUser = Depends(require_admin)):
    """Checks each saved key with a lookup of the EICAR test file hash (known to both services)."""
    cl = _cloud(request)
    out = {}
    for p in cl.ready_providers():
        try:
            r = cl.lookup("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", [p], force=True,
                          require_enabled=False)
            out[p] = {"ok": True, "verdict": r["verdict"]}
        except CloudError as e:
            out[p] = {"ok": False, "status": e.status, "error": e.message}
    if not out:
        raise HTTPException(409, "No provider is ready - add an API key and select the provider")
    return out


@lookup_router.get("/history")
def lookup_history(request: Request, verdict: Literal["malicious", "suspicious", "clean", "unknown"] | None = None,
                   limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    return _cloud(request).history(verdict, limit, offset)


@lookup_router.post("/queue/run")
def run_queue(request: Request, cu: CurrentUser = Depends(require_admin)):
    """Process queued background lookups now (normally done automatically)."""
    return {"processed": _cloud(request).process_queue_once(), "remaining": _cloud(request).queue_depth()}


@lookup_router.delete("/cache")
def clear_lookup_cache(request: Request, cu: CurrentUser = Depends(require_admin)):
    return {"deleted": _cloud(request).clear_cache()}
