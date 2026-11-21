"""
Cyber Hub Backend - Privacy cleaner (Part 13)
Developed by Syed Muhammad Tayyab

Finds and removes the traces Windows and browsers leave behind. Every
category is a list of fixed locations under the user's own folders - the
cleaner never deletes anything outside them, never follows links / junctions,
and only removes temp files older than dp_cleaner_temp_min_age_hours (so a
running installer is never broken).

System:   Temporary files · Recycle Bin · Thumbnail cache · Recent files list ·
          Error reports & crash dumps · DNS cache (Windows: ipconfig /flushdns)
Browsers: Chrome · Edge · Brave · Vivaldi · Opera · Chromium · Firefox (every profile)
          - cache (safe), history (incl. download list), cookies (signs you out)

Browser data is skipped while that browser is running (its files are locked
and it would rewrite them on exit) - the analysis says "close Chrome first".
Firefox history is cleared inside places.sqlite with SQL so bookmarks stay.

Layouts: 'windows' (LOCALAPPDATA / APPDATA / TEMP) and 'linux' (~/.cache,
~/.config, ~/.mozilla, ~/.local/share). Tests point CYBERHUB_CLEANER_HOME at a
fake home and may force CYBERHUB_CLEANER_LAYOUT=windows.
"""
from __future__ import annotations

import configparser
import os
import sqlite3
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import psutil

from ..logger import get_logger
from .platform_tools import IS_WINDOWS, run_cmd
from .shredder import ShredError, is_link, shred_file

log = get_logger("cleaner")

MAX_FILES_PER_CATEGORY = 200_000

CHROMIUM = {
    # id: (label, windows LOCALAPPDATA-relative user-data dir ('/' works on Windows too), linux ~/.config dir, process names)
    "chrome": ("Google Chrome", "Google/Chrome/User Data", "google-chrome", {"chrome.exe", "chrome"}),
    "edge": ("Microsoft Edge", "Microsoft/Edge/User Data", "microsoft-edge", {"msedge.exe", "msedge", "microsoft-edge"}),
    "brave": ("Brave", "BraveSoftware/Brave-Browser/User Data", "BraveSoftware/Brave-Browser", {"brave.exe", "brave"}),
    "vivaldi": ("Vivaldi", "Vivaldi/User Data", "vivaldi", {"vivaldi.exe", "vivaldi-bin", "vivaldi"}),
    "chromium": ("Chromium", "Chromium/User Data", "chromium", {"chromium.exe", "chromium", "chromium-browser"}),
}
OPERA = ("Opera", {"opera.exe", "opera"})
FIREFOX = ("Mozilla Firefox", {"firefox.exe", "firefox", "firefox-bin"})
CHROMIUM_CACHE_DIRS = ("Cache", "Code Cache", "GPUCache", "Media Cache", "Service Worker/CacheStorage",
                       "Service Worker/ScriptCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache")
CHROMIUM_ROOT_CACHE = ("ShaderCache", "GrShaderCache", "GraphiteDawnCache")
CHROMIUM_HISTORY = ("History", "History-journal", "Visited Links", "Top Sites", "Top Sites-journal", "Shortcuts",
                    "Shortcuts-journal", "Network Action Predictor", "Network Action Predictor-journal")
CHROMIUM_COOKIES = ("Network/Cookies", "Network/Cookies-journal", "Cookies", "Cookies-journal")
FIREFOX_COOKIES = ("cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm")
WARNINGS = {"cookies": "Signs you out of every website in this browser.",
            "history": "Removes the browsing history and the download list (bookmarks and passwords stay).",
            "recycle_bin": "Files in the Recycle Bin can no longer be restored.",
            "recent": "Clears the Quick access / Jump List recent files (the files themselves stay)."}


@dataclass
class Target:
    root: str                                       # everything removed is inside this folder
    files: tuple[str, ...] = ()                     # specific files (relative to root); empty = whole contents
    contents: bool = False                          # delete everything under root (root itself stays)
    glob: str | None = None                         # only names matching this pattern (top level)
    min_age_hours: float = 0


@dataclass
class Category:
    id: str
    group: str                                      # system | browser
    label: str
    description: str
    targets: list[Target] = field(default_factory=list)
    browser: str | None = None
    processes: set[str] = field(default_factory=set)
    special: str | None = None                      # recycle_bin | dns | firefox_history
    warning: str | None = None
    needs_confirm: bool = False
    extra: dict = field(default_factory=dict)


class Layout:
    """Where things live for one user."""
    def __init__(self):
        home = os.environ.get("CYBERHUB_CLEANER_HOME")
        forced = os.environ.get("CYBERHUB_CLEANER_LAYOUT")
        self.kind = forced or ("windows" if IS_WINDOWS else "linux")
        self.fake = bool(home)
        self.home = Path(home) if home else Path.home()
        if self.kind == "windows":
            env = {} if self.fake else os.environ
            self.local = Path(env.get("LOCALAPPDATA") or self.home / "AppData" / "Local")
            self.roaming = Path(env.get("APPDATA") or self.home / "AppData" / "Roaming")
            self.temp = Path(env.get("TEMP") or self.local / "Temp")
        else:
            self.local = self.home / ".cache"
            self.roaming = self.home / ".config"
            self.temp = self.home / "tmp" if self.fake else Path(tempfile.gettempdir())


def _chromium_profiles(user_data: Path) -> list[Path]:
    out = []
    try:
        for e in os.scandir(user_data):
            if e.is_dir(follow_symlinks=False) and (e.name == "Default" or e.name.startswith(("Profile ", "Guest"))) \
                    and (Path(e.path) / "Preferences").exists():
                out.append(Path(e.path))
    except OSError:
        pass
    return sorted(out)


def _firefox_profiles(base: Path) -> list[Path]:
    """Profiles from profiles.ini (relative or absolute), plus any *.default* folder."""
    found: list[Path] = []
    ini = base / "profiles.ini"
    if ini.exists():
        cp = configparser.ConfigParser(interpolation=None)
        try:
            cp.read(ini, encoding="utf-8")
            for s in cp.sections():
                if s.startswith("Profile") and cp.has_option(s, "Path"):
                    p = cp.get(s, "Path")
                    rel = cp.get(s, "IsRelative", fallback="1") == "1"
                    found.append((base / p) if rel else Path(p))
        except (configparser.Error, OSError):
            pass
    for sub in (base, base / "Profiles"):
        try:
            for e in os.scandir(sub):
                if e.is_dir(follow_symlinks=False) and ".default" in e.name:
                    found.append(Path(e.path))
        except OSError:
            pass
    uniq, seen = [], set()
    for p in found:
        k = os.path.normcase(str(p.resolve())) if p.exists() else None
        if k and k not in seen and ((p / "prefs.js").exists() or (p / "places.sqlite").exists()):
            seen.add(k)
            uniq.append(p)
    return uniq


def build_categories(L: Layout, min_age_hours: float) -> list[Category]:
    cats: list[Category] = []
    win = L.kind == "windows"
    # ------------------------------------------------------------------ system
    temps = [Target(str(L.temp), contents=True, min_age_hours=min_age_hours)]
    if win and not L.fake:                                            # pragma: no cover - Windows only
        temps.append(Target(str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp"), contents=True,
                            min_age_hours=min_age_hours))
    cats.append(Category("temp", "system", "Temporary files",
                         f"Leftovers from installers and programs (older than {min_age_hours:g} h).", temps))
    if win:
        rb = Category("recycle_bin", "system", "Recycle Bin", "Deleted files waiting in the Recycle Bin.",
                      special="recycle_bin", warning=WARNINGS["recycle_bin"], needs_confirm=True)
        if L.fake:                                                    # tests: a folder stands in for the bin
            rb.special, rb.targets = None, [Target(str(L.home / "RecycleBin"), contents=True)]
        cats.append(rb)
        exp = L.local / "Microsoft" / "Windows" / "Explorer"
        cats.append(Category("thumbnails", "system", "Thumbnail cache",
                             "Small pictures of your photos / videos Windows keeps (rebuilt automatically).",
                             [Target(str(exp), glob="thumbcache_*.db"), Target(str(exp), glob="iconcache_*.db")]))
        rec = L.roaming / "Microsoft" / "Windows" / "Recent"
        cats.append(Category("recent", "system", "Recent files list",
                             "Shortcuts to the documents you opened recently (Quick access, Jump Lists).",
                             [Target(str(rec), glob="*.lnk"), Target(str(rec / "AutomaticDestinations"), contents=True),
                              Target(str(rec / "CustomDestinations"), contents=True)], warning=WARNINGS["recent"]))
        cats.append(Category("error_reports", "system", "Error reports & crash dumps",
                             "Windows Error Reporting files and program crash dumps (can contain memory contents).",
                             [Target(str(L.local / "Microsoft" / "Windows" / "WER" / "ReportArchive"), contents=True),
                              Target(str(L.local / "Microsoft" / "Windows" / "WER" / "ReportQueue"), contents=True),
                              Target(str(L.local / "CrashDumps"), contents=True)]))
        cats.append(Category("dns_cache", "system", "DNS cache", "The list of websites' addresses Windows remembers.",
                             special="dns"))
    else:
        cats.append(Category("recycle_bin", "system", "Trash", "Deleted files waiting in the Trash.",
                             [Target(str(L.home / ".local" / "share" / "Trash" / "files"), contents=True),
                              Target(str(L.home / ".local" / "share" / "Trash" / "info"), contents=True)],
                             warning=WARNINGS["recycle_bin"], needs_confirm=True))
        cats.append(Category("thumbnails", "system", "Thumbnail cache", "Small pictures of your photos / videos.",
                             [Target(str(L.local / "thumbnails"), contents=True)]))
        cats.append(Category("recent", "system", "Recent files list", "The list of documents you opened recently.",
                             [Target(str(L.home / ".local" / "share"), files=("recently-used.xbel",))],
                             warning=WARNINGS["recent"]))
    # ------------------------------------------------------------------ Chromium browsers
    for bid, (label, win_rel, lin_rel, procs) in CHROMIUM.items():
        ud = (L.local / win_rel) if win else (L.roaming / lin_rel)
        profiles = _chromium_profiles(ud)
        if not profiles:
            continue
        cache_t = [Target(str(ud / d), contents=True) for d in CHROMIUM_ROOT_CACHE]
        hist_t, cook_t = [], []
        for p in profiles:
            cache_t += [Target(str(p / d), contents=True) for d in CHROMIUM_CACHE_DIRS]
            if not win:                                               # Linux keeps the big cache in ~/.cache
                lc = L.local / lin_rel / p.name
                cache_t += [Target(str(lc / d), contents=True) for d in ("Cache", "Code Cache")]
            hist_t.append(Target(str(p), files=CHROMIUM_HISTORY))
            cook_t.append(Target(str(p), files=CHROMIUM_COOKIES))
        extra = {"profiles": [p.name for p in profiles]}
        cats.append(Category(f"{bid}_cache", "browser", f"{label} - cache", "Saved copies of pages and pictures.",
                             cache_t, bid, procs, extra=extra))
        cats.append(Category(f"{bid}_history", "browser", f"{label} - history", "Visited sites, searches typed in the "
                             "address bar and the download list.", hist_t, bid, procs, warning=WARNINGS["history"],
                             extra=extra))
        cats.append(Category(f"{bid}_cookies", "browser", f"{label} - cookies", "Website sign-ins and trackers.",
                             cook_t, bid, procs, warning=WARNINGS["cookies"], needs_confirm=True, extra=extra))
    # ------------------------------------------------------------------ Opera (single profile)
    op = (L.roaming / "Opera Software" / "Opera Stable") if win else (L.roaming / "opera")
    if (op / "Preferences").exists():
        opc = (L.local / "Opera Software" / "Opera Stable") if win else (L.local / "opera")
        cats.append(Category("opera_cache", "browser", "Opera - cache", "Saved copies of pages and pictures.",
                             [Target(str(opc / "Cache"), contents=True), Target(str(op / "Code Cache"), contents=True),
                              Target(str(op / "GPUCache"), contents=True)], "opera", OPERA[1]))
        cats.append(Category("opera_history", "browser", "Opera - history", "Visited sites and the download list.",
                             [Target(str(op), files=CHROMIUM_HISTORY)], "opera", OPERA[1], warning=WARNINGS["history"]))
        cats.append(Category("opera_cookies", "browser", "Opera - cookies", "Website sign-ins and trackers.",
                             [Target(str(op), files=CHROMIUM_COOKIES)], "opera", OPERA[1],
                             warning=WARNINGS["cookies"], needs_confirm=True))
    # ------------------------------------------------------------------ Firefox
    ffbase = (L.roaming / "Mozilla" / "Firefox") if win else (L.home / ".mozilla" / "firefox")
    ffprofiles = _firefox_profiles(ffbase)
    if ffprofiles:
        cache_t, cook_t = [], []
        for p in ffprofiles:
            cache_t.append(Target(str(p / "cache2"), contents=True))
            cache_t.append(Target(str(p / "startupCache"), contents=True))
            if win:
                cache_t.append(Target(str(L.local / "Mozilla" / "Firefox" / "Profiles" / p.name / "cache2"), contents=True))
            else:
                cache_t.append(Target(str(L.local / "mozilla" / "firefox" / p.name / "cache2"), contents=True))
            cook_t.append(Target(str(p), files=FIREFOX_COOKIES))
        extra = {"profiles": [p.name for p in ffprofiles], "places": [str(p / "places.sqlite") for p in ffprofiles]}
        cats.append(Category("firefox_cache", "browser", "Firefox - cache", "Saved copies of pages and pictures.",
                             cache_t, "firefox", FIREFOX[1], extra=extra))
        cats.append(Category("firefox_history", "browser", "Firefox - history",
                             "Visited sites, typed addresses and the download list (bookmarks stay).",
                             [], "firefox", FIREFOX[1], special="firefox_history", warning=WARNINGS["history"],
                             extra=extra))
        cats.append(Category("firefox_cookies", "browser", "Firefox - cookies", "Website sign-ins and trackers.",
                             cook_t, "firefox", FIREFOX[1], warning=WARNINGS["cookies"], needs_confirm=True, extra=extra))
    return cats


def _inside(p: str, root: str) -> bool:
    a, b = os.path.normcase(os.path.abspath(p)), os.path.normcase(os.path.abspath(root))
    return a == b or a.startswith(b.rstrip(os.sep) + os.sep)


def iter_target_files(t: Target, now: float | None = None, old_dirs: set | None = None):
    """Yield (path, size, is_link) for every removable entry of one target. Never leaves t.root."""
    now = now or time.time()
    root = t.root
    try:
        rst = os.lstat(root)
    except OSError:
        return
    if is_link(root, rst) or not stat.S_ISDIR(rst.st_mode):
        return
    old_enough = (lambda st: now - st.st_mtime >= t.min_age_hours * 3600) if t.min_age_hours else (lambda st: True)
    if t.files:
        for rel in t.files:
            p = os.path.join(root, *rel.split("/"))
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if _inside(p, root) and stat.S_ISREG(st.st_mode) and not is_link(p, st):
                yield p, st.st_size, False
        return
    if t.glob:
        import fnmatch
        try:
            with os.scandir(root) as it:
                for e in it:
                    if fnmatch.fnmatch(e.name.lower(), t.glob.lower()):
                        st = e.stat(follow_symlinks=False)
                        if stat.S_ISREG(st.st_mode) and old_enough(st):
                            yield e.path, st.st_size, False
        except OSError:
            return
        return
    if t.contents:
        stack, n = [root], 0
        while stack:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    entries = list(it)
            except OSError:
                continue
            for e in entries:
                n += 1
                if n > MAX_FILES_PER_CATEGORY:
                    return
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if is_link(e.path, st):
                    yield e.path, 0, True                             # the link goes, its target is never touched
                elif stat.S_ISDIR(st.st_mode):
                    stack.append(e.path)
                    if old_dirs is not None and old_enough(st):
                        old_dirs.add(e.path)                          # may be removed once emptied
                elif stat.S_ISREG(st.st_mode) and old_enough(st):
                    yield e.path, st.st_size, False


def _prune_empty_dirs(root: str, allowed: set) -> int:
    """Remove folders left empty by the clean - only ones that were already old before it (young folders stay,
    a program may be about to use them). Never root itself."""
    n = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=False, followlinks=False):
        if os.path.normcase(dirpath) == os.path.normcase(root) or dirpath not in allowed:
            continue
        try:
            if not os.listdir(dirpath) and not is_link(dirpath):
                os.rmdir(dirpath)
                n += 1
        except OSError:
            pass
    return n


# ====================================================================== Windows specials
def recycle_bin_info() -> dict:                                      # pragma: no cover - Windows only
    import ctypes

    class SHQUERYRBINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_ulong), ("i64Size", ctypes.c_longlong), ("i64NumItems", ctypes.c_longlong)]
    info = SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(info)
    if ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info)) != 0:
        return {"files": 0, "bytes": 0}
    return {"files": int(info.i64NumItems), "bytes": int(info.i64Size)}


def empty_recycle_bin() -> bool:                                     # pragma: no cover - Windows only
    import ctypes
    flags = 0x1 | 0x2 | 0x4                                          # NOCONFIRMATION | NOPROGRESSUI | NOSOUND
    hr = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags)
    return hr in (0, -2147418113)                                    # S_OK or E_UNEXPECTED (already empty)


def flush_dns() -> bool:
    if IS_WINDOWS:                                                    # pragma: no cover
        return run_cmd(["ipconfig", "/flushdns"], timeout=15) is not None
    return run_cmd(["resolvectl", "flush-caches"], timeout=10) is not None


def clear_firefox_history(places: str) -> dict:
    """Visits, typed input and download annotations go; bookmarked places stay."""
    if not os.path.exists(places):
        return {"ok": True, "rows": 0}
    con = sqlite3.connect(f"file:{places}?mode=rw", uri=True, timeout=2)
    rows = 0
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        with con:
            for sql, t in (("DELETE FROM moz_historyvisits", "moz_historyvisits"),
                           ("DELETE FROM moz_inputhistory", "moz_inputhistory"),
                           ("DELETE FROM moz_annos WHERE anno_attribute_id IN (SELECT id FROM moz_anno_attributes "
                            "WHERE name LIKE 'downloads/%')", "moz_annos"),
                           ("UPDATE moz_places SET visit_count=0, last_visit_date=NULL", "moz_places")):
                if t in tables:
                    rows += con.execute(sql).rowcount or 0
            if "moz_places" in tables:
                cols = {r[1] for r in con.execute("PRAGMA table_info(moz_places)")}
                if "foreign_count" in cols:                           # not bookmarked / not referenced
                    rows += con.execute("DELETE FROM moz_places WHERE foreign_count=0").rowcount or 0
        con.execute("VACUUM")
    finally:
        con.close()
    return {"ok": True, "rows": rows}


# ====================================================================== cleaner
class PrivacyCleaner:
    def __init__(self, process_names: Callable[[], set[str]] | None = None, exclude: list[str] | None = None):
        self.process_names = process_names or self._running_names
        self.exclude = [os.path.normcase(os.path.abspath(x)) for x in (exclude or [])]   # Cyber Hub's own folders

    def _files(self, t: Target, old_dirs: set | None = None):
        for p, sz, link in iter_target_files(t, old_dirs=old_dirs):
            n = os.path.normcase(os.path.abspath(p))
            if any(n == e or n.startswith(e.rstrip(os.sep) + os.sep) for e in self.exclude):
                continue
            yield p, sz, link

    @staticmethod
    def _running_names() -> set[str]:
        out = set()
        for p in psutil.process_iter(["name"]):
            n = p.info.get("name")
            if n:
                out.add(n.lower())
        return out

    def categories(self, min_age_hours: float) -> list[Category]:
        return build_categories(Layout(), min_age_hours)

    def analyze(self, min_age_hours: float, checkpoint: Callable[[], None] | None = None) -> list[dict]:
        running = self.process_names()
        out = []
        for c in self.categories(min_age_hours):
            files, size, sample = 0, 0, []
            if c.special == "recycle_bin":
                try:
                    i = recycle_bin_info()
                    files, size = i["files"], i["bytes"]
                except Exception:                                    # pragma: no cover
                    pass
            elif c.special == "firefox_history":
                for p in c.extra.get("places", []):
                    try:
                        files += 1
                        size += os.path.getsize(p)
                    except OSError:
                        pass
            elif c.special != "dns":
                for t in c.targets:
                    for p, sz, _link in self._files(t):
                        files += 1
                        size += sz
                        if len(sample) < 3:
                            sample.append(os.path.basename(p))
                    if checkpoint:
                        checkpoint()
            is_running = bool(c.processes and c.processes & running)
            out.append({"id": c.id, "group": c.group, "label": c.label, "description": c.description,
                        "browser": c.browser, "files": files, "bytes": size, "warning": c.warning,
                        "needs_confirm": c.needs_confirm, "browser_running": is_running,
                        "action_only": c.special == "dns",
                        "profiles": c.extra.get("profiles"),
                        "note": f"Close {c.label.split(' - ')[0]} first" if is_running else None})
        return out

    def clean(self, ids: list[str], min_age_hours: float, secure: bool = False,
              checkpoint: Callable[[int, str], None] | None = None) -> list[dict]:
        cats = {c.id: c for c in self.categories(min_age_hours)}
        running = self.process_names()
        results = []
        for cid in ids:
            c = cats.get(cid)
            if c is None:
                results.append({"id": cid, "status": "not_found", "files": 0, "bytes": 0})
                continue
            r = {"id": cid, "label": c.label, "status": "done", "files": 0, "bytes": 0, "in_use": 0, "errors": 0,
                 "note": None}
            if c.processes and c.processes & running:
                r.update(status="skipped", note=f"Close {c.label.split(' - ')[0]} first")
                results.append(r)
                continue
            try:
                if c.special == "recycle_bin":                       # pragma: no cover - Windows only
                    before = recycle_bin_info()
                    ok = empty_recycle_bin()
                    r.update(status="done" if ok else "failed", files=before["files"], bytes=before["bytes"],
                             note="Secure overwrite isn't applied to the Recycle Bin" if secure else None)
                elif c.special == "dns":
                    r.update(status="done" if flush_dns() else "failed", note="DNS cache flushed")
                elif c.special == "firefox_history":
                    for p in c.extra.get("places", []):
                        try:
                            size = os.path.getsize(p)
                            res = clear_firefox_history(p)
                            r["files"] += 1
                            r["bytes"] += size
                            r["note"] = f"{res['rows']} history rows removed, bookmarks kept"
                        except sqlite3.Error as e:
                            r["errors"] += 1
                            r["note"] = f"places.sqlite is busy ({e}) - close Firefox"
                else:
                    for t in c.targets:
                        old_dirs: set = set()
                        for p, sz, link in self._files(t, old_dirs):
                            if not _inside(p, t.root):                # belt and braces
                                continue
                            try:
                                if secure and not link:
                                    shred_file(p, "random", verify=False)
                                else:
                                    os.unlink(p)
                                r["files"] += 1
                                r["bytes"] += sz
                            except ShredError as e:
                                r["in_use" if e.code in ("in_use", "access_denied") else "errors"] += 1
                            except PermissionError:
                                r["in_use"] += 1
                            except FileNotFoundError:
                                pass
                            except OSError:
                                r["errors"] += 1
                            if checkpoint and r["files"] % 50 == 0:
                                checkpoint(r["bytes"], c.label)
                        if t.contents:
                            _prune_empty_dirs(t.root, old_dirs)
                    if r["in_use"] and not r["files"]:
                        r["status"] = "in_use"
            except Exception as e:                                    # one category never stops the others
                log.warning("Cleaning %s failed: %s", cid, e)
                r.update(status="failed", note=str(e)[:200])
            if checkpoint:
                checkpoint(r["bytes"], c.label)
            results.append(r)
        return results
