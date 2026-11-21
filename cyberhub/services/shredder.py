"""
Cyber Hub Backend - Secure shredder (Part 13)
Developed by Syed Muhammad Tayyab

Overwrites a file's bytes in place before deleting it, so undelete tools
can't bring it back:

    zero     1 pass of 0x00
    random   1 pass of cryptographic random data (default - enough for any modern drive)
    dod3     DoD 5220.22-M style: 0x00, 0xFF, random
    random3  3 random passes

Each pass is written in 1 MiB blocks and flushed to the disk (fsync). The last
pass can be read back and checked. Then the file is truncated to 0 bytes,
renamed to a random name (so the old name leaves the directory entry) and
deleted. Symbolic links / junctions are removed, never followed. Files with
several hard links are refused (overwriting would wipe the other names too)
unless asked for.

Honest limit (shown in the UI): on SSDs / flash drives, wear-levelling may keep
old copies of blocks that no program can reach - full-disk encryption
(BitLocker) is the real protection there. media_type() tells the UI which
kind of drive a path is on.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
from typing import Callable

from ..logger import get_logger
from .platform_tools import CACHE, IS_WINDOWS, run_powershell_json

log = get_logger("shredder")

BLOCK = 1024 * 1024
METHODS: dict[str, list[bytes | None]] = {        # None = random pass
    "zero": [b"\x00"],
    "random": [None],
    "dod3": [b"\x00", b"\xff", None],
    "random3": [None, None, None],
}
METHOD_LABELS = {"zero": "1 pass of zeros (fast)", "random": "1 random pass (recommended)",
                 "dod3": "DoD 5220.22-M 3 passes (0x00, 0xFF, random)", "random3": "3 random passes"}
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
REPARSE_TAG_SYMLINK = 0xA000000C
REPARSE_TAG_MOUNT_POINT = 0xA0000003                # junction


class ShredError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def is_link(path: str, st: os.stat_result | None = None) -> bool:
    """Symlink, or a Windows junction / other reparse point (never follow those)."""
    try:
        st = st or os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    # Only symlinks and junctions / mount points count. Other reparse points (OneDrive / cloud placeholders,
    # dedup, WSL files) are real files and must not be "unlinked" as if they were shortcuts.
    if getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT and \
            getattr(st, "st_reparse_tag", 0) in (REPARSE_TAG_SYMLINK, REPARSE_TAG_MOUNT_POINT):
        return True
    isj = getattr(os.path, "isjunction", None)
    return bool(isj and isj(path))


def _rand_name(path: str) -> str:
    d = os.path.dirname(path)
    for _ in range(20):
        cand = os.path.join(d, secrets.token_hex(6) + ".shred")
        if not os.path.lexists(cand):
            return cand
    raise ShredError("error", "Could not pick a temporary name")


def _make_writable(path: str) -> None:
    try:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)                 # clears the Windows read-only attribute
    except OSError:
        pass


def shred_file(path: str, method: str = "random", verify: bool = True, allow_hardlinks: bool = False,
               checkpoint: Callable[[int], None] | None = None) -> dict:
    """Overwrite + delete one file. Returns {result: shredded | link_removed, bytes, passes, verified}.
    Raises ShredError(code) with code in missing | not_a_file | hardlinked | in_use | access_denied |
    verify_failed | error. checkpoint(bytes_written) may raise to cancel (the file is then left partly
    overwritten but not deleted - re-run the shred)."""
    if method not in METHODS:
        raise ShredError("error", f"Unknown method '{method}'")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise ShredError("missing", "The file no longer exists")
    except OSError as e:
        raise ShredError("error", str(e)[:200])
    if is_link(path, st):
        try:
            if os.path.isdir(path) and not stat.S_ISLNK(st.st_mode):
                os.rmdir(path)                                       # junction: removes the link only
            else:
                os.unlink(path)
        except OSError as e:
            raise ShredError("in_use" if isinstance(e, PermissionError) else "error", f"Could not remove link: {e}")
        return {"result": "link_removed", "bytes": 0, "passes": 0, "verified": False}
    if not stat.S_ISREG(st.st_mode):
        raise ShredError("not_a_file", "Not a regular file")
    if st.st_nlink > 1 and not allow_hardlinks:
        raise ShredError("hardlinked", f"This file has {st.st_nlink} hard links - overwriting it would also wipe "
                                       "the other names. Shred with allow_hardlinks to do it anyway")
    size = st.st_size
    if not os.access(path, os.W_OK):
        _make_writable(path)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except PermissionError:
        raise ShredError("in_use" if IS_WINDOWS else "access_denied",
                         "The file is open in another program" if IS_WINDOWS else "Access denied")
    except OSError as e:
        raise ShredError("error", str(e)[:200])
    passes = METHODS[method]
    verified = False
    written_total = 0
    try:
        for pi, pat in enumerate(passes):
            os.lseek(fd, 0, os.SEEK_SET)
            h = hashlib.sha256()
            left = size
            while left > 0:
                n = min(BLOCK, left)
                buf = secrets.token_bytes(n) if pat is None else pat * n
                if pi == len(passes) - 1 and verify:
                    h.update(buf)
                view = memoryview(buf)
                while view:
                    w = os.write(fd, view)
                    view = view[w:]
                left -= n
                written_total += n
                if checkpoint:
                    checkpoint(written_total)
            os.fsync(fd)
            if pi == len(passes) - 1 and verify and size:
                os.lseek(fd, 0, os.SEEK_SET)
                rh, left = hashlib.sha256(), size
                while left > 0:
                    b = os.read(fd, min(BLOCK, left))
                    if not b:
                        break
                    rh.update(b)
                    left -= len(b)
                if rh.digest() != h.digest():
                    raise ShredError("verify_failed", "Read-back check failed - the drive did not keep the "
                                                      "overwrite (file left in place)")
                verified = True
        os.ftruncate(fd, 0)
        os.fsync(fd)
    finally:
        os.close(fd)
    cur = path
    try:
        for _ in range(2):                                            # scrub the old name from the directory
            nxt = _rand_name(cur)
            os.replace(cur, nxt)
            cur = nxt
    except OSError:
        pass
    try:
        os.unlink(cur)
    except OSError as e:
        raise ShredError("in_use" if isinstance(e, PermissionError) else "error",
                         f"Overwritten, but could not delete it: {e}")
    return {"result": "shredded", "bytes": size, "passes": len(passes), "verified": verified}


def remove_dir(path: str) -> bool:
    """Remove an (empty) folder after renaming it, so its name is scrubbed too."""
    try:
        tmp = _rand_name(path.rstrip("/\\"))
        os.rename(path, tmp)
        path = tmp
    except OSError:
        pass
    try:
        os.rmdir(path)
        return True
    except OSError:
        return False


def iter_tree(root: str, limit: int = 2_000_000):
    """Yield (kind, path, size) bottom-up: 'file' / 'link' entries, then 'dir' after its contents.
    Never descends into links / junctions."""
    stack: list[tuple[str, bool]] = [(root, False)]
    n = 0
    while stack:
        d, done = stack.pop()
        if done:
            yield "dir", d, 0
            continue
        stack.append((d, True))
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:
            continue
        for e in entries:
            n += 1
            if n > limit:
                return
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if is_link(e.path, st):
                yield "link", e.path, 0
            elif stat.S_ISDIR(st.st_mode):
                stack.append((e.path, False))
            elif stat.S_ISREG(st.st_mode):
                yield "file", e.path, st.st_size
            else:
                yield "other", e.path, 0


def media_type(path: str) -> str:
    """'ssd' | 'hdd' | 'unknown' for the drive holding path (cached 10 min)."""
    try:
        if IS_WINDOWS:                                                # pragma: no cover - Windows only
            drive = os.path.splitdrive(os.path.abspath(path))[0].rstrip(":")[:1].upper()
            if not drive.isalpha():
                return "unknown"

            def probe():
                script = ("$ErrorActionPreference='Stop'; try { $p = Get-Partition -DriveLetter $env:CH_DRIVE; "
                          "$d = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq [string]$p.DiskNumber }; "
                          "@{m = [string]$d.MediaType} | ConvertTo-Json } catch { @{m='Unspecified'} | ConvertTo-Json }")
                r = run_powershell_json(script, timeout=10, env={"CH_DRIVE": drive})
                m = str((r or {}).get("m", "")).lower()
                return "ssd" if m in ("ssd", "4", "scm") else ("hdd" if m in ("hdd", "3") else "unknown")
            return CACHE.get(f"media:{drive}", 600, probe)
        dev = os.stat(path).st_dev
        major, minor = os.major(dev), os.minor(dev)
        base = os.path.realpath(f"/sys/dev/block/{major}:{minor}")
        for cand in (base, os.path.dirname(base)):
            rot = os.path.join(cand, "queue", "rotational")
            if os.path.exists(rot):
                with open(rot) as f:
                    return "hdd" if f.read().strip() == "1" else "ssd"
    except (OSError, ValueError):
        pass
    return "unknown"
