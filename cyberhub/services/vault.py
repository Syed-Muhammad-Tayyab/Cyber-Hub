"""
Cyber Hub Backend - Encrypted quarantine vault (Part 6)
Developed by Syed Muhammad Tayyab

Quarantined files are never kept as runnable copies. Each one is encrypted
with its own random AES-256 key using AES-GCM in a chunked "STREAM" layout,
so files of any size are processed in 1 MiB pieces and every piece is
authenticated:

    header  = b"CHQV" | version (1) | chunk size (4, big-endian) | nonce prefix (7)
    chunk i = AES-GCM(item_key, nonce = prefix | i (4) | last-flag (1),
                      data, aad = header + item id)

* Changing, re-ordering, swapping or truncating any chunk makes decryption fail.
* The item key is itself encrypted ("wrapped") with the vault master key and
  stored in the database - the .chq file alone is useless. Deleting an item
  wipes its wrapped key, so the data is unrecoverable even from a backup.
* The master key lives in the data folder. On Windows it is sealed with DPAPI
  (CryptProtectData), so only the same Windows user on the same PC can open it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path
from typing import BinaryIO, Callable, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..logger import get_logger
from .platform_tools import IS_WINDOWS

log = get_logger("vault")

MAGIC = b"CHQV"
VERSION = 1
CHUNK = 1024 * 1024
TAG = 16
HEADER_LEN = len(MAGIC) + 1 + 4 + 7
KEY_FILE = "vault.key"
_ENTROPY = b"CyberHub-quarantine-vault-v1"


class VaultError(Exception):
    """Vault file is damaged / tampered or the key can't be opened."""


# ====================================================================== DPAPI (Windows)
def _dpapi(data: bytes, protect: bool) -> bytes:                    # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(b: bytes):
        buf = ctypes.create_string_buffer(b, len(b))
        return BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    inp, _keep1 = blob(data)
    ent, _keep2 = blob(_ENTROPY)
    out = BLOB()
    UI_FORBIDDEN = 0x1
    if protect:
        ok = crypt32.CryptProtectData(ctypes.byref(inp), ctypes.c_wchar_p("Cyber Hub quarantine key"),
                                      ctypes.byref(ent), None, None, UI_FORBIDDEN, ctypes.byref(out))
    else:
        ok = crypt32.CryptUnprotectData(ctypes.byref(inp), None, ctypes.byref(ent), None, None,
                                        UI_FORBIDDEN, ctypes.byref(out))
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


class KeyProtector:
    """How the master key is stored. 'dpapi' on Windows, 'file' (owner-only permissions) elsewhere."""
    def __init__(self, name: str, seal: Callable[[bytes], bytes], unseal: Callable[[bytes], bytes]):
        self.name, self.seal, self.unseal = name, seal, unseal


FILE_PROTECTOR = KeyProtector("file", lambda b: b, lambda b: b)


def default_protector() -> KeyProtector:
    if IS_WINDOWS:                                                  # pragma: no cover
        return KeyProtector("dpapi", lambda b: _dpapi(b, True), lambda b: _dpapi(b, False))
    return FILE_PROTECTOR


# ====================================================================== helpers
def _nonce(prefix: bytes, i: int, last: bool) -> bytes:
    return prefix + i.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def _read_full(f: BinaryIO, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        b = f.read(n - len(out))
        if not b:
            break
        out += b
    return bytes(out)


# ====================================================================== the vault
class Vault:
    def __init__(self, data_dir: Path, protector: KeyProtector | None = None):
        self.dir = Path(data_dir) / "quarantine"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.key_path = Path(data_dir) / KEY_FILE
        self.protector = protector or default_protector()
        self._master: bytes | None = None
        self.key_protection: str | None = None
        self.key_error: str | None = None
        try:
            self._master = self._load_or_create_key()
        except VaultError as e:
            self.key_error = str(e)
            log.error("Quarantine vault key unavailable: %s", e)

    # ------------------------------------------------------------ master key
    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            try:
                meta = json.loads(self.key_path.read_text(encoding="utf-8"))
                sealed = base64.b64decode(meta["key"])
                prot = meta.get("protection", "file")
            except (ValueError, KeyError, TypeError) as e:
                raise VaultError(f"Vault key file is damaged ({type(e).__name__}) - "
                                 "existing quarantine items can't be opened") from e
            if prot == "file":
                key = sealed
            elif prot == self.protector.name:
                try:
                    key = self.protector.unseal(sealed)
                except Exception as e:                              # pragma: no cover - Windows only
                    raise VaultError("Vault key is sealed to a different Windows user or PC") from e
            else:
                raise VaultError(f"Vault key uses '{prot}' protection, which isn't available here")
            if len(key) != 32:
                raise VaultError("Vault key has the wrong length")
            self.key_protection = prot
            return key
        # never overwrite an existing key - that would make every item unreadable
        key = secrets.token_bytes(32)
        prot = self.protector.name
        try:
            sealed = self.protector.seal(key)
        except Exception as e:                                      # pragma: no cover
            log.warning("DPAPI unavailable (%s) - vault key stored with file permissions only", e)
            sealed, prot = key, "file"
        tmp = self.key_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"v": 1, "protection": prot, "key": base64.b64encode(sealed).decode()}),
                       encoding="utf-8")
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:                                             # pragma: no cover
            pass
        os.replace(tmp, self.key_path)
        self.key_protection = prot
        log.info("Created quarantine vault key (%s protection)", prot)
        return key

    @property
    def available(self) -> bool:
        return self._master is not None

    def _require(self) -> bytes:
        if self._master is None:
            raise VaultError(self.key_error or "Vault key unavailable")
        return self._master

    def wrap_key(self, item_key: bytes, item_id: str) -> str:
        n = secrets.token_bytes(12)
        ct = AESGCM(self._require()).encrypt(n, item_key, b"cyberhub-qkey:" + item_id.encode())
        return base64.b64encode(n + ct).decode()

    def unwrap_key(self, wrapped: str | None, item_id: str) -> bytes:
        if not wrapped:
            raise VaultError("This item's key has been destroyed")
        raw = base64.b64decode(wrapped)
        try:
            return AESGCM(self._require()).decrypt(raw[:12], raw[12:], b"cyberhub-qkey:" + item_id.encode())
        except InvalidTag as e:
            raise VaultError("Item key doesn't match this vault") from e

    def derive_subkey(self, label: str) -> bytes:
        """Part 12: a 32-byte key for another module, derived from (never revealing) the master key.
        Ties that module's data to this Windows user on this PC, like the vault itself."""
        return hmac.new(self._require(), b"cyberhub-subkey:" + label.encode(), hashlib.sha256).digest()

    # ------------------------------------------------------------ Part 19: backup / restore of the master key
    def export_master(self) -> bytes:
        """The raw master key. ONLY for Part 19's password-protected backups, which wrap it again under the
        backup password before it is written anywhere - never log it, never hand it to the UI."""
        return self._require()

    def write_key_file(self, dest: Path, master: bytes) -> None:
        """Write `master` as a vault.key file at `dest`, sealed for this Windows user like a fresh key would be
        (used when a backup from another PC is restored). The running vault is not changed."""
        if len(master) != 32:
            raise VaultError("Vault key has the wrong length")
        prot = self.protector.name
        try:
            sealed = self.protector.seal(master)
        except Exception as e:                                      # pragma: no cover
            log.warning("DPAPI unavailable (%s) - restored vault key stored with file permissions only", e)
            sealed, prot = master, "file"
        dest = Path(dest)
        dest.write_text(json.dumps({"v": 1, "protection": prot, "key": base64.b64encode(sealed).decode()}),
                        encoding="utf-8")
        try:
            os.chmod(dest, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:                                             # pragma: no cover
            pass

    # ------------------------------------------------------------ files
    def path_for(self, item_id: str) -> Path:
        if not (len(item_id) == 32 and all(c in "0123456789abcdef" for c in item_id)):
            raise VaultError("Bad item id")
        return self.dir / f"{item_id}.chq"

    def encrypt_file(self, src_path: str, item_id: str, item_key: bytes, checkpoint=None) -> dict:
        """Encrypt src_path into the vault. Returns {sha256, md5, size, stored_size}. Atomic: the
        .chq only appears once fully written and flushed to disk."""
        dst = self.path_for(item_id)
        tmp = dst.with_suffix(".part")
        aes = AESGCM(item_key)
        prefix = secrets.token_bytes(7)
        header = MAGIC + bytes([VERSION]) + CHUNK.to_bytes(4, "big") + prefix
        aad = header + item_id.encode()
        h256, h5, size, i = hashlib.sha256(), hashlib.md5(), 0, 0
        try:
            with open(src_path, "rb") as src, open(tmp, "wb") as out:
                out.write(header)
                cur = _read_full(src, CHUNK)
                while True:
                    nxt = _read_full(src, CHUNK) if len(cur) == CHUNK else b""
                    last = not nxt
                    h256.update(cur); h5.update(cur); size += len(cur)
                    out.write(aes.encrypt(_nonce(prefix, i, last), cur, aad))
                    if last:
                        break
                    cur, i = nxt, i + 1
                    if checkpoint:
                        checkpoint()
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, dst)
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        return {"sha256": h256.hexdigest(), "md5": h5.hexdigest(), "size": size,
                "stored_size": dst.stat().st_size}

    def decrypt_chunks(self, item_id: str, item_key: bytes) -> Iterator[bytes]:
        """Yield the original file's bytes, 1 MiB at a time. Raises VaultError on any tampering."""
        p = self.path_for(item_id)
        if not p.exists():
            raise VaultError("Vault file is missing")
        with open(p, "rb") as f:
            header = _read_full(f, HEADER_LEN)
            if len(header) != HEADER_LEN or header[:4] != MAGIC or header[4] != VERSION:
                raise VaultError("Not a Cyber Hub vault file")
            chunk = int.from_bytes(header[5:9], "big")
            if not 1024 <= chunk <= 64 * CHUNK:
                raise VaultError("Vault file header is damaged")
            prefix, aad = header[9:16], header + item_id.encode()
            aes = AESGCM(item_key)
            cur, i = _read_full(f, chunk + TAG), 0
            while True:
                nxt = _read_full(f, chunk + TAG) if len(cur) == chunk + TAG else b""
                last = not nxt
                if len(cur) < TAG:
                    raise VaultError("Vault file is truncated")
                try:
                    yield aes.decrypt(_nonce(prefix, i, last), cur, aad)
                except InvalidTag as e:
                    raise VaultError(f"Vault file failed its integrity check at block {i} "
                                     "(damaged or tampered)") from e
                if last:
                    return
                cur, i = nxt, i + 1

    def decrypt_to(self, item_id: str, item_key: bytes, dest: str, expected_sha256: str) -> int:
        """Decrypt into dest atomically (temp file in the same folder, verified, then renamed)."""
        d = os.path.dirname(dest)
        tmp = os.path.join(d, f".{os.path.basename(dest)}.{secrets.token_hex(4)}.chrestore")
        h, n = hashlib.sha256(), 0
        try:
            with open(tmp, "wb") as out:
                for b in self.decrypt_chunks(item_id, item_key):
                    out.write(b); h.update(b); n += len(b)
                out.flush()
                os.fsync(out.fileno())
            if h.hexdigest() != expected_sha256:
                raise VaultError("Restored data doesn't match the original SHA-256")
            os.replace(tmp, dest)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return n

    def verify(self, item_id: str, item_key: bytes, expected_sha256: str) -> dict:
        h, n = hashlib.sha256(), 0
        for b in self.decrypt_chunks(item_id, item_key):
            h.update(b); n += len(b)
        return {"ok": h.hexdigest() == expected_sha256, "size": n, "sha256": h.hexdigest()}

    def remove(self, item_id: str) -> bool:
        try:
            self.path_for(item_id).unlink()
            return True
        except FileNotFoundError:
            return False

    def files(self) -> dict[str, int]:
        """item id -> encrypted size, for every .chq in the vault folder."""
        out = {}
        for e in os.scandir(self.dir):
            if e.is_file() and e.name.endswith(".chq") and len(e.name) == 36:
                out[e.name[:-4]] = e.stat().st_size
        return out

    def info(self) -> dict:
        files = self.files()
        return {"location": str(self.dir), "available": self.available, "key_protection": self.key_protection,
                "key_error": self.key_error, "cipher": "AES-256-GCM, 1 MiB authenticated chunks, per-item keys",
                "files": len(files), "disk_bytes": sum(files.values())}
