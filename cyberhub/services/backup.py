"""
Cyber Hub Backend - Backup, restore & settings export (Part 19)
Developed by Syed Muhammad Tayyab

A backup is one `.chbackup` file: a zip (manifest + a consistent snapshot of the database taken with SQLite's
online-backup API + optionally the encrypted quarantine files) sealed with Part 13's authenticated `.chx`
container (AES-256-GCM in 1 MiB chunks, every chunk verified on restore).

    password mode   scrypt + HKDF from a backup password you choose. Restorable on ANY PC: the vault master key
                    (which Windows keeps sealed to your account) travels inside the backup, wrapped a second
                    time under the same password, and is re-sealed for the new PC on restore.
    device mode     no password; the key is derived from this PC's vault key (Vault.derive_subkey("backup-v1")).
                    Restorable only on this Windows account - protects against a damaged database, a bad
                    update or an accidental delete. Used by scheduled backups.

What a backup holds: settings, history, signatures, schedules, the password vault (still encrypted under its
own master password), platform accounts and - if asked - quarantined files (still encrypted).
What it never holds: the API token, sessions, logs, reports.

Restore is two-step so a running database is never swapped under the engine:
    1. restore() opens and verifies the backup (wrong password / damaged file -> nothing changes), checks the
       database inside it and stages everything in <data>/restore_pending/.
    2. the next start moves the current data to <data>/pre-restore-<time>/ (kept as a safety copy), puts the
       staged files in place, runs the schema migrations (older backups are upgraded) and signs everyone out.

Settings can also be exported / imported as plain JSON (no secrets in there) to copy preferences between PCs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import secrets
import shutil
import sqlite3
import stat
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import APP_NAME, APP_VERSION
from ..database import MIGRATIONS, Database
from ..logger import get_logger
from . import file_crypto as fc
from .settings_store import DEFAULTS

log = get_logger("backup")

EXT = ".chbackup"
PENDING = "restore_pending"
MANIFEST = "manifest.json"
DB_NAME = "cyberhub.db"
_SKIP_TABLES = ("sessions",)                 # never useful on another start


class BackupError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _iso(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _size(n: int | float | None) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "0 B"                                                     # pragma: no cover


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _wrap_master(master: bytes, password: str) -> dict:
    """The vault master key, encrypted under the backup password (its own salt, same scrypt cost as .chx files)."""
    kdf = fc.kdf_params()
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=kdf["n"], r=kdf["r"], p=kdf["p"], dklen=32,
                         maxmem=1024 * 1024 * 1024)
    ct = AESGCM(key).encrypt(nonce, master, b"cyberhub-backup-master-v1")
    return {"kdf": kdf, "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
            "key": base64.b64encode(ct).decode()}


def _unwrap_master(w: dict, password: str) -> bytes:
    kdf = w["kdf"]
    if not (isinstance(kdf.get("n"), int) and 2 <= kdf["n"] <= 2 ** 22 and kdf.get("r") in range(1, 33)
            and kdf.get("p") in range(1, 17)):
        raise BackupError(422, "Backup key parameters are not valid")
    key = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(w["salt"]), n=kdf["n"], r=kdf["r"],
                         p=kdf["p"], dklen=32, maxmem=1024 * 1024 * 1024)
    try:
        return AESGCM(key).decrypt(base64.b64decode(w["nonce"]), base64.b64decode(w["key"]),
                                   b"cyberhub-backup-master-v1")
    except InvalidTag as e:
        raise BackupError(403, "Wrong backup password") from e


class BackupService:
    def __init__(self, db: Database, settings, activity, data_dir: Path, vault=None, *, notifications=None,
                 strength=None):
        self.db, self.settings, self.activity = db, settings, activity
        self.data_dir = Path(data_dir)
        self.vault, self.notifications = vault, notifications
        self.strength = strength                         # password_tools.strength (Part 12) - optional
        self.default_dir = self.data_dir / "backups"
        self.default_dir.mkdir(parents=True, exist_ok=True)

    def _g(self, key: str) -> Any:
        return self.settings.get(key)

    # ------------------------------------------------------------------ helpers
    def folder(self) -> Path:
        custom = (self._g("backup_dir") or "").strip()
        if custom:
            p = Path(os.path.expandvars(os.path.expanduser(custom)))
            if p.is_absolute():
                try:
                    p.mkdir(parents=True, exist_ok=True)
                    return p
                except OSError as e:
                    log.warning("Backup folder %s is not usable (%s) - using the default", p, e)
        return self.default_dir

    def _keys(self, mode: str, password: str | None) -> fc.KeySource:
        if mode == "password":
            return fc.KeySource(fc.MODE_PASSWORD, password=password)
        if self.vault is None or not self.vault.available:
            raise BackupError(503, "This PC's vault key can't be opened, so a device backup can't be made or read - "
                                   "use a password backup")
        return fc.KeySource(fc.MODE_DEVICE, device_key=self.vault.derive_subkey("backup-v1"))

    def _check_password(self, password: str | None, username: str | None) -> None:
        if not password or len(password) < 10:
            raise BackupError(422, "Choose a backup password of at least 10 characters")
        if len(password) > 256:
            raise BackupError(422, "Backup password is too long")
        if self.strength is not None:
            try:
                s = self.strength(password, [username] if username else None)
                if int(s.get("score", 4)) < 3:
                    hint = s.get("warning") or "use four random words or a generated password"
                    raise BackupError(422, f"That backup password is too easy to guess - {hint}")
            except BackupError:
                raise
            except Exception as e:                                   # pragma: no cover - meter problems never block
                log.debug("Strength check failed: %s", e)

    def _public(self, r: dict) -> dict:
        out = dict(r)
        out["quarantine"] = bool(r["quarantine"])
        out["size_text"] = _size(r["size"])
        out["exists"] = os.path.isfile(r["file_path"])
        out["portable"] = r["mode"] == "password"
        return out

    def _row(self, bid: int) -> dict:
        r = self.db.fetchone("SELECT * FROM backups WHERE id=?", (bid,))
        if not r:
            raise BackupError(404, "Backup not found")
        return r

    # ------------------------------------------------------------------ create
    def create(self, cu, mode: str = "device", password: str | None = None, include_quarantine: bool | None = None,
               destination: str | None = None, note: str | None = None, source: str = "manual") -> dict:
        if mode not in ("password", "device"):
            raise BackupError(422, "mode must be password or device")
        username = cu.user["username"] if cu else "scheduler"
        if mode == "password":
            self._check_password(password, cu.user["username"] if cu else None)
        keys = self._keys(mode, password)
        include_quarantine = bool(self._g("backup_include_quarantine")) if include_quarantine is None \
            else bool(include_quarantine)
        folder = self.folder()
        if destination:
            folder = Path(os.path.expandvars(os.path.expanduser(destination.strip())))
            if not folder.is_absolute():
                raise BackupError(422, "Use a full folder path for the destination")
            if not folder.is_dir():
                raise BackupError(404, f"Folder not found: {folder}")
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        name = f"CyberHub_{stamp}{EXT}"
        n = 1
        while (folder / name).exists():
            n += 1
            name = f"CyberHub_{stamp}_{n}{EXT}"
        final = folder / name
        work = Path(tempfile.mkdtemp(prefix="backup-", dir=str(self.default_dir)))
        try:
            snap = work / DB_NAME
            self._snapshot_db(snap)
            manifest = {
                "format": 1, "app": APP_NAME, "app_version": APP_VERSION, "created_at": _iso(),
                "schema_version": self.db.schema_version(), "mode": mode, "created_by": username,
                "db_sha256": _sha256_file(snap), "db_size": snap.stat().st_size,
                "quarantine_files": 0, "vault_key": None, "note": (note or "")[:200] or None,
                "computer": platform.node() or None,
            }
            if mode == "password" and self.vault is not None and self.vault.available:
                manifest["vault_key"] = _wrap_master(self.vault.export_master(), password)   # type: ignore[arg-type]
            plain = work / "payload.zip"
            with zipfile.ZipFile(plain, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                zf.write(snap, DB_NAME)
                if include_quarantine and self.vault is not None:
                    for f in sorted(self.vault.dir.glob("*.chq")):
                        zf.write(f, f"quarantine/{f.name}", compress_type=zipfile.ZIP_STORED)
                        manifest["quarantine_files"] += 1
                zf.writestr(MANIFEST, json.dumps(manifest, indent=1))
            tmp_out = final.with_suffix(final.suffix + ".part")
            try:
                fc.encrypt_file(str(plain), str(tmp_out), keys)
                check = fc.decrypt_stream(str(tmp_out), keys)        # read it back before trusting it
                if check["sha256"] != _sha256_file(plain):
                    raise BackupError(500, "The backup did not verify after writing - nothing was kept")
                os.replace(tmp_out, final)
            except BaseException:
                try:
                    tmp_out.unlink(missing_ok=True)
                except OSError:
                    pass
                raise
        except (OSError, fc.CryptoError, sqlite3.Error) as e:
            raise BackupError(500, f"Backup failed: {e}") from e
        finally:
            keys.wipe()
            shutil.rmtree(work, ignore_errors=True)
        size = final.stat().st_size
        cur = self.db.execute(
            "INSERT INTO backups(file_path, file_name, size, sha256, mode, quarantine, schema_version, app_version, "
            "source, note, created_by, verified_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(final), name, size, _sha256_file(final), mode, int(include_quarantine), manifest["schema_version"],
             APP_VERSION, source, manifest["note"], username, _iso()))
        self.activity.record("report", "Backup created", f"{name} ({_size(size)}, {mode} mode)", source="backup")
        if source == "schedule":
            self._prune()
        return self._public(self._row(cur.lastrowid))

    def _snapshot_db(self, dest: Path) -> None:
        """Consistent copy of the live database (WAL included) without stopping the engine."""
        out = sqlite3.connect(str(dest))
        try:
            with self.db._lock:
                self.db._conn.backup(out)
            for t in _SKIP_TABLES:
                out.execute(f"DELETE FROM {t}")
            out.commit()
            out.execute("VACUUM")
            out.commit()
        finally:
            out.close()

    def _prune(self) -> int:
        """Keep the newest backup_keep automatic backups (manual ones are the user's to delete)."""
        keep = int(self._g("backup_keep"))
        old = self.db.fetchall("SELECT * FROM backups WHERE source='schedule' ORDER BY id DESC LIMIT -1 OFFSET ?",
                               (keep,))
        for r in old:
            try:
                Path(r["file_path"]).unlink(missing_ok=True)
            except OSError:
                continue
            self.db.execute("DELETE FROM backups WHERE id=?", (r["id"],))
        return len(old)

    # ------------------------------------------------------------------ list / verify / delete
    def list(self) -> dict:
        rows = [self._public(r) for r in self.db.fetchall("SELECT * FROM backups ORDER BY id DESC")]
        return {"items": rows, "total": len(rows), "folder": str(self.folder()),
                "bytes": sum(r["size"] for r in rows if r["exists"]),
                "size_text": _size(sum(r["size"] for r in rows if r["exists"])),
                "pending_restore": self.pending()}

    def status(self) -> dict:
        lst = self.list()
        last = lst["items"][0] if lst["items"] else None
        age = None
        if last:
            try:
                age = (datetime.now(timezone.utc) - datetime.strptime(last["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                    tzinfo=timezone.utc)).days
            except ValueError:                                       # pragma: no cover
                pass
        return {"backups": lst["total"], "size_text": lst["size_text"], "folder": lst["folder"], "last": last,
                "days_since_last": age, "device_key_available": bool(self.vault and self.vault.available),
                "pending_restore": lst["pending_restore"], "extension": EXT,
                "settings": {k: self._g(k) for k in ("backup_dir", "backup_keep", "backup_include_quarantine")}}

    def _resolve(self, backup_id: int | None, path: str | None) -> Path:
        if backup_id is not None:
            p = Path(self._row(backup_id)["file_path"])
        elif path:
            p = Path(os.path.expandvars(os.path.expanduser(path.strip())))
            if not p.is_absolute():
                raise BackupError(422, "Use the full path of the backup file")
        else:
            raise BackupError(422, "Give a backup id or the path of a .chbackup file")
        if not p.is_file():
            raise BackupError(404, f"Backup file not found: {p}")
        if not fc.is_chx(str(p)):
            raise BackupError(422, "That is not a Cyber Hub backup file")
        return p

    def _open(self, p: Path, password: str | None, work: Path) -> tuple[dict, Path, str]:
        """Decrypt + authenticate a backup into `work`. Returns (manifest, extracted folder, mode)."""
        try:
            with open(p, "rb") as f:
                head = fc.read_header(f)
        except (OSError, fc.CryptoError) as e:
            raise BackupError(422, f"Backup file is damaged: {e}") from e
        mode = "password" if head["mode"] == fc.MODE_PASSWORD else "device"
        if mode == "password" and not password:
            raise BackupError(428, "This backup is protected with a password - enter it to continue")
        keys = self._keys(mode, password)
        plain = work / "payload.zip"
        try:
            fc.decrypt_file(str(p), str(plain), keys)
        except fc.WrongKey as e:
            raise BackupError(403, "Wrong backup password" if mode == "password" else
                              "This backup was made on another PC or Windows account (device mode) and can't be "
                              "opened here") from e
        except fc.CryptoError as e:
            raise BackupError(422, f"Backup file is damaged: {e}") from e
        finally:
            keys.wipe()
        out = work / "x"
        out.mkdir()
        try:
            with zipfile.ZipFile(plain) as zf:
                names = zf.namelist()
                if MANIFEST not in names or DB_NAME not in names:
                    raise BackupError(422, "Backup is incomplete (manifest or database missing)")
                if sum(i.file_size for i in zf.infolist()) > 64 * 1024 ** 3:
                    raise BackupError(413, "Backup is unreasonably large")
                for info in zf.infolist():
                    n = info.filename
                    ok = n in (MANIFEST, DB_NAME) or (n.startswith("quarantine/") and n.count("/") == 1
                                                      and n.endswith(".chq") and ".." not in n and "\\" not in n)
                    if ok:
                        zf.extract(info, out)
                manifest = json.loads((out / MANIFEST).read_text(encoding="utf-8"))
        except (zipfile.BadZipFile, ValueError, KeyError) as e:
            raise BackupError(422, f"Backup contents are damaged: {e}") from e
        finally:
            plain.unlink(missing_ok=True)
        if manifest.get("app") != APP_NAME or manifest.get("format") != 1:
            raise BackupError(422, "This backup was not made by Cyber Hub (or by a newer format)")
        if _sha256_file(out / DB_NAME) != manifest.get("db_sha256"):
            raise BackupError(422, "The database inside the backup does not match its checksum")
        return manifest, out, mode

    def _inspect_db(self, db_path: Path) -> dict:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            ok = con.execute("PRAGMA integrity_check").fetchone()[0]
            if ok != "ok":
                raise BackupError(422, f"The database inside the backup is damaged: {ok}")
            ver = con.execute("SELECT COALESCE(MAX(version),0) FROM schema_version").fetchone()[0]
            users = [r[0] for r in con.execute("SELECT username FROM users ORDER BY id")]
            counts = {}
            for t in ("activity_log", "scan_detections", "quarantine_items", "pv_items", "platform_accounts",
                      "schedules", "malware_signatures"):
                try:
                    counts[t] = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                except sqlite3.Error:
                    counts[t] = None
            return {"schema_version": ver, "users": users, "rows": counts}
        except sqlite3.DatabaseError as e:
            raise BackupError(422, f"The database inside the backup can't be read: {e}") from e
        finally:
            con.close()

    def verify(self, backup_id: int | None = None, path: str | None = None, password: str | None = None) -> dict:
        """Open a backup completely (every chunk authenticated) and describe it. Changes nothing."""
        p = self._resolve(backup_id, path)
        work = Path(tempfile.mkdtemp(prefix="verify-", dir=str(self.default_dir)))
        try:
            manifest, out, mode = self._open(p, password, work)
            info = self._inspect_db(out / DB_NAME)
            newest = MIGRATIONS[-1][0]
            if backup_id is not None:
                self.db.execute("UPDATE backups SET verified_at=? WHERE id=?", (_iso(), backup_id))
            return {"ok": True, "file": str(p), "size_text": _size(p.stat().st_size), "mode": mode,
                    "created_at": manifest.get("created_at"), "app_version": manifest.get("app_version"),
                    "schema_version": info["schema_version"], "computer": manifest.get("computer"),
                    "created_by": manifest.get("created_by"), "note": manifest.get("note"),
                    "users": info["users"], "rows": info["rows"],
                    "quarantine_files": manifest.get("quarantine_files", 0),
                    "has_vault_key": bool(manifest.get("vault_key")),
                    "restorable": info["schema_version"] <= newest,
                    "reason": None if info["schema_version"] <= newest else
                    "This backup comes from a newer Cyber Hub - update Cyber Hub first"}
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def delete(self, cu, bid: int) -> dict:
        r = self._row(bid)
        try:
            Path(r["file_path"]).unlink(missing_ok=True)
        except OSError as e:
            raise BackupError(409, f"The backup file is in use: {e}")
        self.db.execute("DELETE FROM backups WHERE id=?", (bid,))
        self.activity.record("report", "Backup deleted", f"{r['file_name']} by {cu.user['username']}", severity="low",
                             source="backup")
        return {"deleted": True, "id": bid}

    # ------------------------------------------------------------------ restore (stage now, apply at next start)
    def pending(self) -> dict | None:
        marker = self.data_dir / PENDING / "restore.json"
        if not marker.is_file():
            return None
        try:
            return json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"damaged": True}

    def cancel_restore(self) -> dict:
        d = self.data_dir / PENDING
        had = d.exists()
        shutil.rmtree(d, ignore_errors=True)
        return {"cancelled": had}

    def restore(self, cu, backup_id: int | None = None, path: str | None = None, password: str | None = None,
                confirm: bool = False) -> dict:
        p = self._resolve(backup_id, path)
        if not confirm:
            raise BackupError(428, "Restoring replaces ALL current Cyber Hub data (settings, history, vaults) with the "
                                   "backup's - send again with confirm=true. Your current data is kept as a safety copy.")
        pend = self.data_dir / PENDING
        shutil.rmtree(pend, ignore_errors=True)
        work = Path(tempfile.mkdtemp(prefix="restore-", dir=str(self.default_dir)))
        try:
            manifest, out, mode = self._open(p, password, work)
            info = self._inspect_db(out / DB_NAME)
            if info["schema_version"] > MIGRATIONS[-1][0]:
                raise BackupError(409, "This backup comes from a newer Cyber Hub - update Cyber Hub, then restore")
            if not info["users"]:
                raise BackupError(422, "The backup contains no Cyber Hub account")
            stage = work / "stage"
            stage.mkdir()
            shutil.move(str(out / DB_NAME), str(stage / DB_NAME))
            key_note = "kept (same PC)"
            if mode == "password" and manifest.get("vault_key") and self.vault is not None:
                master = _unwrap_master(manifest["vault_key"], password or "")
                self.vault.write_key_file(stage / "vault.key", master)
                key_note = "restored from the backup and sealed for this Windows account"
            elif mode == "password":
                key_note = "not in this backup - quarantined files and device-encrypted data from it stay locked"
            qdir = out / "quarantine"
            nq = 0
            if qdir.is_dir():
                (stage / "quarantine").mkdir()
                for f in qdir.glob("*.chq"):
                    shutil.move(str(f), str(stage / "quarantine" / f.name))
                    nq += 1
            marker = {"staged_at": _iso(), "by": cu.user["username"], "backup_file": p.name,
                      "backup_created_at": manifest.get("created_at"), "schema_version": info["schema_version"],
                      "app_version": manifest.get("app_version"), "users": info["users"], "mode": mode,
                      "has_vault_key": (stage / "vault.key").exists(), "quarantine_files": nq,
                      "includes_quarantine": bool(manifest.get("quarantine_files") is not None and qdir.is_dir())}
            (stage / "restore.json").write_text(json.dumps(marker, indent=1), encoding="utf-8")
            os.replace(stage, pend)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        self.activity.record("report", "Backup restore prepared",
                             f"{p.name} - will be applied when Cyber Hub restarts (by {cu.user['username']})",
                             severity="medium", source="backup")
        return {"staged": True, "restart_required": True, "backup": marker, "vault_key": key_note,
                "message": "Restart Cyber Hub to finish restoring. Your current data will be kept in a "
                           "'pre-restore' folder next to it."}

    # ------------------------------------------------------------------ settings export / import
    def export_settings(self) -> dict:
        cur = self.settings.all()
        return {"app": APP_NAME, "kind": "settings", "version": APP_VERSION, "exported_at": _iso(),
                "settings": cur, "changed": {k: v for k, v in cur.items() if DEFAULTS.get(k) != v}}

    def import_settings(self, cu, payload: dict, only_changed: bool = False) -> dict:
        if not isinstance(payload, dict) or payload.get("app") != APP_NAME or payload.get("kind") != "settings":
            raise BackupError(422, "That is not a Cyber Hub settings file")
        incoming = payload.get("changed" if only_changed else "settings")
        if not isinstance(incoming, dict):
            raise BackupError(422, "The settings file has no settings in it")
        applied, skipped = {}, []
        current = self.settings.all()
        for k, v in incoming.items():
            if k not in DEFAULTS:
                skipped.append({"key": k, "reason": "unknown in this version"})
                continue
            if current.get(k) == v:
                continue
            try:
                self.settings.update({k: v})
                applied[k] = v
            except (KeyError, TypeError, ValueError) as e:
                skipped.append({"key": k, "reason": str(e).strip("'\"")})
        self.activity.record("settings", "Settings imported", f"{len(applied)} changed, {len(skipped)} skipped "
                             f"(by {cu.user['username']})", severity="low", source="backup")
        return {"applied": applied, "applied_count": len(applied), "skipped": skipped}


# ====================================================================== applied at start-up (before the DB opens)
def apply_pending_restore(data_dir: Path) -> dict | None:
    """Called first thing at start-up. Returns the marker when a staged restore was applied."""
    data_dir = Path(data_dir)
    pend = data_dir / PENDING
    marker_file = pend / "restore.json"
    if not pend.is_dir():
        return None
    if not marker_file.is_file() or not (pend / DB_NAME).is_file():
        shutil.rmtree(pend, ignore_errors=True)                      # half-staged: ignore it
        return None
    try:
        marker = json.loads(marker_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        shutil.rmtree(pend, ignore_errors=True)
        return None
    safety = data_dir / ("pre-restore-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    safety.mkdir(parents=True, exist_ok=True)
    moved: list[tuple[Path, Path]] = []
    try:
        for name in (DB_NAME, DB_NAME + "-wal", DB_NAME + "-shm"):
            src = data_dir / name
            if src.exists():
                shutil.move(str(src), str(safety / name))
                moved.append((safety / name, src))
        if (pend / "vault.key").is_file():
            if (data_dir / "vault.key").exists():
                shutil.move(str(data_dir / "vault.key"), str(safety / "vault.key"))
                moved.append((safety / "vault.key", data_dir / "vault.key"))
            shutil.move(str(pend / "vault.key"), str(data_dir / "vault.key"))
            try:
                os.chmod(data_dir / "vault.key", stat.S_IRUSR | stat.S_IWUSR)
            except OSError:                                          # pragma: no cover
                pass
        if (pend / "quarantine").is_dir():
            q = data_dir / "quarantine"
            if q.exists():
                shutil.move(str(q), str(safety / "quarantine"))
                moved.append((safety / "quarantine", q))
            shutil.move(str(pend / "quarantine"), str(q))
        shutil.move(str(pend / DB_NAME), str(data_dir / DB_NAME))
    except OSError as e:
        log.error("Restore could not be applied (%s) - putting the previous data back", e)
        for src, dst in reversed(moved):
            try:
                if dst.exists():
                    if dst.is_dir():
                        shutil.rmtree(dst, ignore_errors=True)
                    else:
                        dst.unlink()
                shutil.move(str(src), str(dst))
            except OSError:
                pass
        shutil.rmtree(pend, ignore_errors=True)
        return None
    shutil.rmtree(pend, ignore_errors=True)
    marker["applied_at"] = _iso()
    marker["safety_copy"] = str(safety)
    (data_dir / "restore_applied.json").write_text(json.dumps(marker, indent=1), encoding="utf-8")
    return marker


def finish_restore(db: Database, activity, data_dir: Path) -> dict | None:
    """After migrations: sign everyone out and log what happened (once)."""
    f = Path(data_dir) / "restore_applied.json"
    if not f.is_file():
        return None
    try:
        marker = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        marker = {}
    db.execute("DELETE FROM sessions")
    activity.record("report", "Backup restored",
                    f"{marker.get('backup_file', 'backup')} from {marker.get('backup_created_at', '?')} - previous "
                    f"data kept in {marker.get('safety_copy', 'a pre-restore folder')}", severity="medium",
                    source="backup")
    try:
        f.unlink()
    except OSError:                                                  # pragma: no cover
        pass
    return marker
