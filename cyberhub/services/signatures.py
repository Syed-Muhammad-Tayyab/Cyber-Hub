"""
Cyber Hub Backend - Digital signature checks (Part 4)
Developed by Syed Muhammad Tayyab

Answers "is this program signed, and by whom?" for processes and startup
items. On Windows it asks Authenticode (Get-AuthenticodeSignature) in
batches; results are cached in SQLite keyed by path + size + modified time,
so a binary is only re-checked after it changes on disk.

Paths are handed to PowerShell as JSON in an environment variable - never
formatted into the script - so a crafted file name cannot inject commands.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from ..database import Database
from ..logger import get_logger
from .platform_tools import IS_WINDOWS, run_powershell_json

log = get_logger("signatures")

BATCH = 40                     # paths per PowerShell call (env var limit is 32 KB)
MAX_HASH_BYTES = 1024 ** 3     # don't hash files over 1 GB on demand

# Authenticode status -> Cyber Hub status
_STATUS = {
    "Valid": "signed",
    "NotSigned": "unsigned",
    "HashMismatch": "tampered",          # signed, but the file was modified afterwards
    "NotTrusted": "untrusted",           # signed with a certificate Windows does not trust
    "NotSupportedFileFormat": "unsupported",
    "Incompatible": "unsupported",
    "UnknownError": "error",
}

_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$paths = $env:CYBERHUB_SIG_PATHS | ConvertFrom-Json
$out = foreach ($p in $paths) {
  $s = Get-AuthenticodeSignature -LiteralPath $p
  $c = $s.SignerCertificate
  [pscustomobject]@{
    path       = $p
    status     = [string]$s.Status
    subject    = if ($c) { $c.Subject } else { $null }
    issuer     = if ($c) { $c.Issuer } else { $null }
    thumbprint = if ($c) { $c.Thumbprint } else { $null }
    not_after  = if ($c) { $c.NotAfter.ToUniversalTime().ToString('o') } else { $null }
    is_os      = [bool]$s.IsOSBinary
    sig_type   = [string]$s.SignatureType
  }
}
ConvertTo-Json -InputObject @($out) -Compress -Depth 3
"""

_CN = re.compile(r"(?:^|,\s*)CN=(\"[^\"]+\"|[^,]+)")
_O = re.compile(r"(?:^|,\s*)O=(\"[^\"]+\"|[^,]+)")


def publisher_from_subject(subject: str | None) -> str | None:
    """'CN=Google LLC, O=Google LLC, L=Mountain View, ...' -> 'Google LLC'."""
    if not subject:
        return None
    m = _O.search(subject) or _CN.search(subject)
    return m.group(1).strip().strip('"') if m else subject[:120]


def parse_ps_result(row: dict) -> dict:
    status = _STATUS.get(row.get("status") or "", "error")
    return {
        "status": status,
        "signed": status == "signed",
        "publisher": publisher_from_subject(row.get("subject")),
        "issuer": publisher_from_subject(row.get("issuer")),
        "thumbprint": row.get("thumbprint"),
        "cert_expires": row.get("not_after"),
        "is_os_binary": bool(row.get("is_os")),
    }


def _stat(path: str) -> tuple[int, float] | None:
    try:
        st = os.stat(path)
        return st.st_size, round(st.st_mtime, 3)
    except OSError:
        return None


class SignatureService:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------ public
    def check(self, path: str | None) -> dict:
        if not path:
            return {"status": "unknown", "signed": False, "publisher": None, "path": None}
        return self.check_many([path])[path]

    def check_many(self, paths: list[str]) -> dict[str, dict]:
        """Signature info for every path. Uses the cache; checks the rest in batches."""
        out: dict[str, dict] = {}
        todo: list[tuple[str, tuple[int, float]]] = []
        for p in dict.fromkeys(p for p in paths if p):
            st = _stat(p)
            if st is None:
                out[p] = {"status": "not_found", "signed": False, "publisher": None, "path": p}
                continue
            if not IS_WINDOWS:
                out[p] = {"status": "unsupported", "signed": False, "publisher": None, "path": p,
                          "note": "Authenticode signatures are a Windows feature"}
                continue
            row = self.db.fetchone("SELECT * FROM file_signatures WHERE path=?", (p,))
            if row and row["size"] == st[0] and abs(row["mtime"] - st[1]) < 0.01:
                out[p] = self._row_to_info(row)
            else:
                todo.append((p, st))
        for i in range(0, len(todo), BATCH):
            chunk = todo[i:i + BATCH]
            results = self._authenticode([p for p, _ in chunk])
            for p, st in chunk:
                info = results.get(p.lower())
                if info is None:
                    out[p] = {"status": "error", "signed": False, "publisher": None, "path": p}
                    continue
                self._store(p, st, info)
                out[p] = dict(info, path=p)
        return out

    def cached(self, path: str | None) -> dict | None:
        """Cache-only lookup (never launches PowerShell) - used by fast list views."""
        if not path or not IS_WINDOWS:
            return None
        st = _stat(path)
        row = self.db.fetchone("SELECT * FROM file_signatures WHERE path=?", (path,))
        if row and st and row["size"] == st[0] and abs(row["mtime"] - st[1]) < 0.01:
            return self._row_to_info(row)
        return None

    def stats(self) -> dict:
        rows = self.db.fetchall("SELECT status, COUNT(*) AS n FROM file_signatures GROUP BY status")
        return {r["status"]: r["n"] for r in rows}

    # ------------------------------------------------------------ internals
    def _authenticode(self, paths: list[str]) -> dict[str, dict]:
        data = run_powershell_json(_PS_SCRIPT, timeout=30 + 2 * len(paths),
                                   env={"CYBERHUB_SIG_PATHS": json.dumps(paths)})
        if data is None:
            return {}
        if isinstance(data, dict):
            data = [data]
        return {str(r.get("path", "")).lower(): parse_ps_result(r) for r in data if isinstance(r, dict)}

    def _store(self, path: str, st: tuple[int, float], info: dict) -> None:
        self.db.execute(
            "INSERT INTO file_signatures(path, size, mtime, status, publisher, issuer, thumbprint, "
            "cert_expires, is_os_binary, checked_at) VALUES (?,?,?,?,?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
            "ON CONFLICT(path) DO UPDATE SET size=excluded.size, mtime=excluded.mtime, status=excluded.status, "
            "publisher=excluded.publisher, issuer=excluded.issuer, thumbprint=excluded.thumbprint, "
            "cert_expires=excluded.cert_expires, is_os_binary=excluded.is_os_binary, checked_at=excluded.checked_at",
            (path, st[0], st[1], info["status"], info["publisher"], info["issuer"], info["thumbprint"],
             info["cert_expires"], int(info["is_os_binary"])),
        )

    @staticmethod
    def _row_to_info(row: dict) -> dict:
        return {"path": row["path"], "status": row["status"], "signed": row["status"] == "signed",
                "publisher": row["publisher"], "issuer": row["issuer"], "thumbprint": row["thumbprint"],
                "cert_expires": row["cert_expires"], "is_os_binary": bool(row["is_os_binary"]),
                "checked_at": row["checked_at"]}


def sha256_file(path: str | Path) -> str | None:
    """SHA-256 of a file (streamed). None if unreadable or larger than MAX_HASH_BYTES."""
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None
