"""
Cyber Hub Backend - File & folder encryption format (Part 13)
Developed by Syed Muhammad Tayyab

A .chx file holds one encrypted file. Same chunked AES-256-GCM "STREAM"
design as the Part 6 quarantine vault, so files of any size are processed in
1 MiB pieces and every piece is authenticated (re-ordering, swapping,
editing or truncating anything makes decryption fail):

    header (56 bytes) = b"CHXF" | version 1 | mode | log2(N) | r | p
                        | kdf salt (16) | file salt (16) | nonce prefix (7) | chunk size (4) | meta length (4)
    meta              = AES-GCM(file key, nonce = prefix | FFFFFFFF | 02, json {name, size, mtime}, aad = header)
    chunk i           = AES-GCM(file key, nonce = prefix | i (4) | last-flag (1), data, aad = header)

Two modes:
* password (1) - portable: any PC with Cyber Hub can open it with the password.
      scrypt(password, kdf salt, N, r, p) -> HKDF(salt = file salt) -> file key
  A folder job derives scrypt once (shared kdf salt); every file still gets its
  own key through its random file salt, so no key / nonce pair is ever reused.
* device (2)   - no password: tied to this Windows user on this PC.
      HKDF(Vault.derive_subkey("file-encryption-v1"), salt = file salt) -> file key
  (Part 6's DPAPI-sealed vault.key). Lost if Windows is reinstalled - the API says so.

The original file name lives only inside the encrypted meta block, so
"hide names" outputs (random .chx names) reveal nothing about the content.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from dataclasses import dataclass
from typing import BinaryIO, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"CHXF"
VERSION = 1
MODE_PASSWORD, MODE_DEVICE = 1, 2
MODES = {MODE_PASSWORD: "password", MODE_DEVICE: "device"}
CHUNK = 1024 * 1024
TAG = 16
HEADER_LEN = 4 + 1 + 1 + 3 + 16 + 16 + 7 + 4 + 4
EXT = ".chx"
DEVICE_LABEL = "file-encryption-v1"
MAX_META = 16 * 1024
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


class CryptoError(Exception):
    """Damaged / not a .chx file."""


class WrongKey(CryptoError):
    """Password (or this PC's device key) doesn't open the file."""


def kdf_params() -> dict:
    """scrypt cost for password-mode files (~128 MB, ~0.4 s once per job). Tests lower it with CYBERHUB_DP_KDF_N."""
    try:
        n = int(os.environ.get("CYBERHUB_DP_KDF_N", str(2 ** 17)))
    except ValueError:
        n = 2 ** 17
    if not (2 ** 10 <= n <= 2 ** 20) or n & (n - 1):
        n = 2 ** 17
    return {"n": n, "r": 8, "p": 1}


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _nonce(prefix: bytes, i: int, last: bool) -> bytes:
    return prefix + i.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def _meta_nonce(prefix: bytes) -> bytes:
    return prefix + b"\xff\xff\xff\xff" + b"\x02"


def _read_full(f: BinaryIO, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        b = f.read(n - len(out))
        if not b:
            break
        out += b
    return bytes(out)


def safe_name(name: str | None, fallback: str) -> str:
    """The name stored inside a .chx comes from another PC - never let it escape the target folder."""
    n = (name or "").replace("\x00", "").strip()
    n = os.path.basename(n.replace("\\", "/"))
    if not n or n in (".", "..") or len(n) > 255 or any(c in n for c in '<>:"|?*') or any(ord(c) < 32 for c in n):
        n = fallback
    if os.path.splitext(n)[0].lower().rstrip(". ") in _RESERVED:
        n = "_" + n
    return n.rstrip(". ") or fallback


# ====================================================================== keys
@dataclass
class KeySource:
    """What opens / creates files in one job. password mode caches scrypt output per (salt, params)."""
    mode: int
    password: str | None = None
    device_key: bytes | None = None
    kdf: dict | None = None
    kdf_salt: bytes | None = None

    def __post_init__(self):
        self._cache: dict[tuple, bytes] = {}
        self._lock = threading.Lock()
        if self.mode == MODE_PASSWORD:
            if not self.password:
                raise ValueError("password required")
            self.kdf = self.kdf or kdf_params()
            self.kdf_salt = self.kdf_salt or secrets.token_bytes(16)
        elif self.mode == MODE_DEVICE:
            if not self.device_key or len(self.device_key) != 32:
                raise ValueError("device key required")
            self.kdf, self.kdf_salt = {"n": 0, "r": 0, "p": 0}, bytes(16)
        else:
            raise ValueError("bad mode")

    def _root(self, kdf: dict, kdf_salt: bytes) -> bytes:
        if self.mode == MODE_DEVICE:
            return self.device_key                                    # type: ignore[return-value]
        k = (kdf["n"], kdf["r"], kdf["p"], kdf_salt)
        with self._lock:
            hit = self._cache.get(k)
            if hit is None:
                hit = hashlib.scrypt(self.password.encode("utf-8"), salt=kdf_salt, n=kdf["n"], r=kdf["r"],   # type: ignore[union-attr]
                                     p=kdf["p"], dklen=32, maxmem=1024 * 1024 * 1024)
                if len(self._cache) > 32:
                    self._cache.clear()
                self._cache[k] = hit
            return hit

    def file_key(self, kdf: dict, kdf_salt: bytes, file_salt: bytes) -> bytes:
        info = b"cyberhub-chx-v1:" + MODES[self.mode].encode()
        return _hkdf(self._root(kdf, kdf_salt), file_salt, info)

    def wipe(self) -> None:
        with self._lock:
            self._cache.clear()
        self.password = None


# ====================================================================== header
def _pack_header(mode: int, kdf: dict, kdf_salt: bytes, file_salt: bytes, prefix: bytes, meta_len: int) -> bytes:
    logn = kdf["n"].bit_length() - 1 if kdf["n"] else 0
    return (MAGIC + bytes([VERSION, mode, logn, kdf["r"], kdf["p"]]) + kdf_salt + file_salt + prefix
            + CHUNK.to_bytes(4, "big") + meta_len.to_bytes(4, "big"))


def read_header(f: BinaryIO) -> dict:
    h = _read_full(f, HEADER_LEN)
    if len(h) != HEADER_LEN or h[:4] != MAGIC:
        raise CryptoError("Not a Cyber Hub encrypted file (.chx)")
    if h[4] != VERSION:
        raise CryptoError(f"Made by a newer Cyber Hub (format v{h[4]}) - update Cyber Hub to open it")
    mode = h[5]
    if mode not in MODES:
        raise CryptoError("Encrypted file header is damaged")
    logn, r, p = h[6], h[7], h[8]
    if mode == MODE_PASSWORD and not (10 <= logn <= 22 and 1 <= r <= 32 and 1 <= p <= 16):
        raise CryptoError("Encrypted file header is damaged (key settings)")
    chunk = int.from_bytes(h[48:52], "big")
    meta_len = int.from_bytes(h[52:56], "big")
    if not 1024 <= chunk <= 64 * CHUNK or not TAG < meta_len <= MAX_META:
        raise CryptoError("Encrypted file header is damaged")
    return {"raw": h, "mode": mode, "mode_name": MODES[mode],
            "kdf": {"n": (1 << logn) if mode == MODE_PASSWORD else 0, "r": r, "p": p},
            "kdf_salt": h[9:25], "file_salt": h[25:41], "prefix": h[41:48], "chunk": chunk, "meta_len": meta_len}


def inspect(path: str, keys: KeySource | None = None) -> dict:
    """Header facts; with keys also the original name / size (WrongKey if they don't fit)."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        h = read_header(f)
        out = {"format": "Cyber Hub encrypted file", "version": VERSION, "mode": h["mode_name"],
               "needs_password": h["mode"] == MODE_PASSWORD, "encrypted_size": size,
               "cipher": "AES-256-GCM, 1 MiB authenticated chunks",
               "kdf": (f"scrypt N=2^{h['kdf']['n'].bit_length() - 1}, r={h['kdf']['r']}, p={h['kdf']['p']}"
                       if h["mode"] == MODE_PASSWORD else "this PC's device key (DPAPI)")}
        if keys is not None:
            meta, _key = _open_meta(f, h, keys)
            out.update({"name": meta.get("name"), "size": meta.get("size"), "mtime": meta.get("mtime")})
    return out


def _open_meta(f: BinaryIO, h: dict, keys: KeySource) -> tuple[dict, bytes]:
    if keys.mode != h["mode"]:
        raise WrongKey("This file was encrypted for this PC only (device mode) - no password is needed"
                       if h["mode"] == MODE_DEVICE else "This file needs its password")
    key = keys.file_key(h["kdf"], h["kdf_salt"], h["file_salt"])
    ct = _read_full(f, h["meta_len"])
    if len(ct) != h["meta_len"]:
        raise CryptoError("Encrypted file is truncated")
    try:
        meta = json.loads(AESGCM(key).decrypt(_meta_nonce(h["prefix"]), ct, h["raw"]))
    except InvalidTag as e:
        raise WrongKey("Wrong password" if h["mode"] == MODE_PASSWORD else
                       "This file was encrypted on another PC or Windows account (device mode)") from e
    except ValueError as e:
        raise CryptoError("Encrypted file is damaged (meta)") from e
    if not isinstance(meta, dict) or not isinstance(meta.get("size"), int):
        raise CryptoError("Encrypted file is damaged (meta)")
    return meta, key


# ====================================================================== encrypt / decrypt
def encrypt_file(src: str, dst: str, keys: KeySource, checkpoint: Callable[[int], None] | None = None) -> dict:
    """Encrypt src into dst (dst is written directly - callers pass a temp name and rename after verify).
    Returns {sha256, size}. checkpoint(bytes_done) may raise to cancel."""
    st = os.stat(src)
    meta = json.dumps({"name": os.path.basename(src), "size": st.st_size, "mtime": st.st_mtime},
                      ensure_ascii=False).encode("utf-8")
    file_salt, prefix = secrets.token_bytes(16), secrets.token_bytes(7)
    key = keys.file_key(keys.kdf, keys.kdf_salt, file_salt)                    # type: ignore[arg-type]
    header = _pack_header(keys.mode, keys.kdf, keys.kdf_salt, file_salt, prefix, len(meta) + TAG)  # type: ignore[arg-type]
    aes = AESGCM(key)
    h, size, i = hashlib.sha256(), 0, 0
    with open(src, "rb") as fin, open(dst, "wb") as out:
        out.write(header)
        out.write(aes.encrypt(_meta_nonce(prefix), meta, header))
        cur = _read_full(fin, CHUNK)
        while True:
            nxt = _read_full(fin, CHUNK) if len(cur) == CHUNK else b""
            last = not nxt
            h.update(cur)
            size += len(cur)
            out.write(aes.encrypt(_nonce(prefix, i, last), cur, header))
            if checkpoint:
                checkpoint(size)
            if last:
                break
            cur, i = nxt, i + 1
        out.flush()
        os.fsync(out.fileno())
    if size != st.st_size:
        raise CryptoError("The file changed while it was being encrypted - try again when it is not in use")
    return {"sha256": h.hexdigest(), "size": size}


def decrypt_stream(path: str, keys: KeySource, sink: Callable[[bytes], None] | None = None,
                   checkpoint: Callable[[int], None] | None = None) -> dict:
    """Authenticate + decrypt every chunk, handing plain bytes to sink. Returns {meta, sha256, size}.
    Raises WrongKey / CryptoError - nothing a caller wrote should be kept on error."""
    h256, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        h = read_header(f)
        meta, key = _open_meta(f, h, keys)
        aes, chunk = AESGCM(key), h["chunk"]
        cur, i = _read_full(f, chunk + TAG), 0
        while True:
            nxt = _read_full(f, chunk + TAG) if len(cur) == chunk + TAG else b""
            last = not nxt
            if len(cur) < TAG:
                raise CryptoError("Encrypted file is truncated")
            try:
                plain = aes.decrypt(_nonce(h["prefix"], i, last), cur, h["raw"])
            except InvalidTag as e:
                raise CryptoError(f"Encrypted file failed its integrity check at block {i} (damaged or tampered)") from e
            h256.update(plain)
            n += len(plain)
            if sink:
                sink(plain)
            if checkpoint:
                checkpoint(n)
            if last:
                break
            cur, i = nxt, i + 1
    if n != meta["size"]:
        raise CryptoError("Encrypted file is incomplete (size mismatch)")
    return {"meta": meta, "sha256": h256.hexdigest(), "size": n}


def decrypt_file(path: str, tmp_dst: str, keys: KeySource, checkpoint=None) -> dict:
    """Decrypt into tmp_dst (removed again on any error). Caller renames it into place."""
    try:
        with open(tmp_dst, "wb") as out:
            res = decrypt_stream(path, keys, out.write, checkpoint)
            out.flush()
            os.fsync(out.fileno())
        return res
    except BaseException:
        try:
            os.unlink(tmp_dst)
        except OSError:
            pass
        raise


def is_chx(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == MAGIC
    except OSError:
        return False
