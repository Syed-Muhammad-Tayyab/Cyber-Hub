"""
Cyber Hub Backend - Browser & code-editor extension audit (Part 16)
Developed by Syed Muhammad Tayyab

Reads (never changes) the extensions installed for this Windows / Linux user:
  Chrome / Edge / Brave / Vivaldi / Chromium  <profile>/Extensions/<id>/<version>/manifest.json (+ Preferences /
                                              Secure Preferences for "unpacked" / disabled state)
  Firefox                                     <profile>/extensions.json
  VS Code / Insiders / VSCodium / Cursor / Windsurf   ~/.<editor>/extensions/extensions.json + package.json

Each extension gets an explainable 0-100 risk score from what it is allowed to do (read / change every site,
cookies, intercept traffic, run native programs, debugger ...) and where it came from (store vs side-loaded /
unpacked / unsigned). Browser profile folders are found exactly like Part 13's privacy cleaner (same Layout, so
CYBERHUB_CLEANER_HOME / CYBERHUB_CLEANER_LAYOUT work in tests too).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import privacy_cleaner as pc

MAX_PER_SOURCE = 400
ALL_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/"}
PERM_POINTS = {
    "debugger": (35, "Can attach the debugger to any tab (read and change everything on the page)"),
    "nativeMessaging": (20, "Can start and talk to programs installed on the PC"),
    "proxy": (25, "Can send all your browsing through another server"),
    "webRequestBlocking": (20, "Can intercept and change web requests"),
    "webRequest": (12, "Can watch every web request"),
    "cookies": (15, "Can read your cookies (website sign-ins)"),
    "management": (20, "Can switch other extensions on / off"),
    "clipboardRead": (15, "Can read the clipboard"),
    "history": (10, "Can read your browsing history"),
    "privacy": (10, "Can change privacy settings"),
    "scripting": (8, "Can run scripts in pages"),
    "desktopCapture": (15, "Can capture the screen"),
    "tabCapture": (12, "Can capture tab audio / video"),
    "declarativeNetRequestWithHostAccess": (8, "Can redirect / modify requests"),
    "downloads": (5, "Can start and read downloads"),
    "webNavigation": (5, "Sees every page you visit"),
    "contentSettings": (8, "Can change site permissions (camera, location...)"),
    "geolocation": (6, "Can ask for your location"),
    "identity": (5, "Can sign in to services as you"),
    "<all_urls>": (0, ""),
}
BUILTIN_IDS = {"nmmhkkegccagdldgiimedpiccmgmieda", "ghbmnnjooekpmoecnnnilnnbdlolhkhi"}   # Web Store Payments, Docs Offline
STORE_UPDATE_HOSTS =("clients2.google.com", "edge.microsoft.com", "extensionwebstorebase.edgesv.net")
EDITORS = {
    "vscode": ("VS Code", ".vscode"), "vscode_insiders": ("VS Code Insiders", ".vscode-insiders"),
    "vscodium": ("VSCodium", ".vscode-oss"), "cursor": ("Cursor", ".cursor"), "windsurf": ("Windsurf", ".windsurf"),
}
STORE_PAGES = {"chrome": "https://chromewebstore.google.com/detail/{id}",
               "edge": "https://microsoftedge.microsoft.com/addons/detail/{id}",
               "brave": "https://chromewebstore.google.com/detail/{id}",
               "vivaldi": "https://chromewebstore.google.com/detail/{id}",
               "chromium": "https://chromewebstore.google.com/detail/{id}",
               "firefox": "https://addons.mozilla.org/firefox/addon/{id}/",
               "vscode": "https://marketplace.visualstudio.com/items?itemName={id}",
               "vscode_insiders": "https://marketplace.visualstudio.com/items?itemName={id}",
               "vscodium": "https://open-vsx.org/extension/{slash}", "cursor": "https://open-vsx.org/extension/{slash}",
               "windsurf": "https://open-vsx.org/extension/{slash}"}
REMOVE_HOW = {"chrome": "chrome://extensions", "edge": "edge://extensions", "brave": "brave://extensions",
              "vivaldi": "vivaldi://extensions", "chromium": "chrome://extensions", "firefox": "about:addons"}


def _f(code: str, points: int, text: str) -> dict:
    return {"code": code, "points": points, "text": text}


def level(score: int) -> str:
    return "high" if score >= 60 else "medium" if score >= 35 else "low" if score >= 15 else "none"


def _read_json(p: Path, limit: int = 8 * 1024 * 1024) -> dict | list | None:
    try:
        if not p.is_file() or p.stat().st_size > limit:
            return None
        return json.loads(p.read_text(encoding="utf-8-sig", errors="replace"))
    except (OSError, ValueError):
        return None


def _msg(ext_dir: Path, manifest: dict, value: str | None) -> str | None:
    """Resolve __MSG_name__ from _locales/<default_locale>/messages.json."""
    if not value or not value.startswith("__MSG_") or not value.endswith("__"):
        return value
    key = value[6:-2].lower()
    for loc in filter(None, (manifest.get("default_locale"), "en", "en_US")):
        msgs = _read_json(ext_dir / "_locales" / loc / "messages.json", 1024 * 1024)
        if isinstance(msgs, dict):
            for k, v in msgs.items():
                if k.lower() == key and isinstance(v, dict) and v.get("message"):
                    return str(v["message"])[:120]
    return None


def score_browser(perms: list[str], hosts: list[str], content_all: bool, mv: int | None, source: str,
                  enabled: bool) -> tuple[int, list[dict]]:
    out = []
    ps = set(perms)
    all_hosts = bool(set(hosts) & ALL_HOSTS) or "<all_urls>" in ps
    if all_hosts:
        out.append(_f("all_sites", 25, "Can read and change everything on every website"))
    elif len(hosts) > 20:
        out.append(_f("many_sites", 10, f"Can read and change data on {len(hosts)} sites"))
    if content_all and not all_hosts:
        out.append(_f("content_all", 20, "Injects its own script into every website"))
    for p, (pts, text) in PERM_POINTS.items():
        if p in ps and pts:
            out.append(_f(f"perm_{p}", pts, text))
    if all_hosts and ps & {"cookies", "webRequest", "webRequestBlocking"}:
        out.append(_f("combo", 10, "Can see sign-in cookies / traffic on every site together"))
    if source == "unpacked":
        out.append(_f("unpacked", 30, "Loaded unpacked (developer mode) - not checked by any store"))
    elif source == "sideloaded":
        out.append(_f("sideloaded", 25, "Installed from outside the official store"))
    elif source == "unsigned":
        out.append(_f("unsigned", 35, "Not signed by Mozilla"))
    if mv == 2:
        out.append(_f("mv2", 5, "Old Manifest V2 extension (no longer maintained in Chrome)"))
    score = min(100, sum(f["points"] for f in out))
    if not enabled:
        score = score // 2
    return score, sorted(out, key=lambda f: -f["points"])


# ====================================================================== Chromium browsers
def _chromium_settings(profile: Path) -> dict:
    out: dict = {}
    for name in ("Secure Preferences", "Preferences"):
        d = _read_json(profile / name)
        if isinstance(d, dict):
            for k, v in ((d.get("extensions") or {}).get("settings") or {}).items():
                if isinstance(v, dict):
                    out.setdefault(k, {}).update(v)
    return out


def _chromium(bid: str, label: str, profile: Path) -> list[dict]:
    items = []
    settings = _chromium_settings(profile)
    root = profile / "Extensions"
    seen = set()
    try:
        ids = sorted(e.name for e in os.scandir(root) if e.is_dir(follow_symlinks=False))
    except OSError:
        ids = []
    unpacked = [(k, v) for k, v in settings.items() if v.get("location") == 4 and v.get("path")]
    cands = [(i, None) for i in ids] + [(k, Path(v["path"])) for k, v in unpacked]
    for ext_id, direct in cands[:MAX_PER_SOURCE]:
        if ext_id in seen:
            continue
        seen.add(ext_id)
        if direct is None:
            try:
                versions = sorted((e for e in os.scandir(root / ext_id) if e.is_dir(follow_symlinks=False)),
                                  key=lambda e: e.stat().st_mtime, reverse=True)
            except OSError:
                continue
            if not versions:
                continue
            ext_dir = Path(versions[0].path)
        else:
            ext_dir = direct if direct.is_absolute() else profile / direct
        man = _read_json(ext_dir / "manifest.json", 2 * 1024 * 1024)
        if not isinstance(man, dict):
            continue
        st = settings.get(ext_id, {})
        if st.get("location") in (5, 10) or man.get("key") and not man.get("name"):     # component / external policy
            continue
        if ext_id in BUILTIN_IDS and st.get("was_installed_by_default", True):
            continue                                                       # Google's own pre-installed helpers
        perms = [p for p in (man.get("permissions") or []) if isinstance(p, str)]
        hosts = [p for p in perms if "://" in p or p == "<all_urls>"]
        hosts += [p for p in (man.get("host_permissions") or []) + (man.get("optional_host_permissions") or [])
                  if isinstance(p, str)]
        perms = [p for p in perms if "://" not in p]
        content_all = any(set(cs.get("matches") or []) & ALL_HOSTS for cs in (man.get("content_scripts") or [])
                          if isinstance(cs, dict))
        upd = str(man.get("update_url") or "")
        if st.get("location") == 4 or direct is not None:
            source = "unpacked"
        elif st.get("from_webstore") or any(h in upd for h in STORE_UPDATE_HOSTS):
            source = "store"
        elif upd:
            source = "sideloaded"
        else:
            source = "store" if st.get("was_installed_by_default") else "sideloaded"
        enabled = not st.get("disable_reasons") and st.get("state", 1) != 0
        mv = man.get("manifest_version")
        score, findings = score_browser(perms, hosts, content_all, mv if isinstance(mv, int) else None, source,
                                        enabled)
        name = _msg(ext_dir, man, man.get("name")) or ext_id
        items.append({"key": f"{bid}:{profile.name}:{ext_id}", "app": bid, "app_label": label,
                      "profile": profile.name, "id": ext_id, "name": name[:120],
                      "version": str(man.get("version") or "")[:40], "enabled": enabled, "source": source,
                      "permissions": sorted(set(perms))[:40], "hosts": sorted(set(hosts))[:20],
                      "all_sites": any(f["code"] == "all_sites" for f in findings), "score": score,
                      "level": level(score), "findings": findings, "path": str(ext_dir),
                      "store_url": STORE_PAGES[bid].format(id=ext_id) if source == "store" else None,
                      "remove_at": REMOVE_HOW.get(bid)})
    return items


# ====================================================================== Firefox
def _firefox(profile: Path) -> list[dict]:
    d = _read_json(profile / "extensions.json", 32 * 1024 * 1024)
    items = []
    for a in (d or {}).get("addons", [])[:MAX_PER_SOURCE] if isinstance(d, dict) else []:
        if not isinstance(a, dict) or a.get("type") != "extension" or a.get("location") != "app-profile":
            continue
        up = a.get("userPermissions") or {}
        perms = [p for p in up.get("permissions") or [] if isinstance(p, str)]
        hosts = [p for p in up.get("origins") or [] if isinstance(p, str)]
        signed = a.get("signedState")
        source = "unsigned" if isinstance(signed, int) and signed <= 0 else "store"
        enabled = bool(a.get("active")) and not a.get("userDisabled")
        score, findings = score_browser(perms, hosts, False, None, source, enabled)
        loc = a.get("defaultLocale") or {}
        ext_id = str(a.get("id") or "")[:200]
        items.append({"key": f"firefox:{profile.name}:{ext_id}", "app": "firefox", "app_label": "Mozilla Firefox",
                      "profile": profile.name, "id": ext_id, "name": str(loc.get("name") or ext_id)[:120],
                      "version": str(a.get("version") or "")[:40], "enabled": enabled, "source": source,
                      "permissions": sorted(set(perms))[:40], "hosts": sorted(set(hosts))[:20],
                      "all_sites": any(f["code"] == "all_sites" for f in findings), "score": score,
                      "level": level(score), "findings": findings, "path": str(a.get("path") or ""),
                      "store_url": None, "remove_at": REMOVE_HOW["firefox"]})
    return items


# ====================================================================== VS Code family
def _editor(eid: str, label: str, root: Path) -> list[dict]:
    meta = _read_json(root / "extensions.json")
    by_dir: dict[str, dict] = {}
    if isinstance(meta, list):
        for m in meta:
            if isinstance(m, dict) and isinstance(m.get("identifier"), dict):
                rel = m.get("relativeLocation") or Path(str((m.get("location") or {}).get("path") or "")).name
                if rel:
                    by_dir[rel] = m
    items = []
    try:
        dirs = sorted(e.name for e in os.scandir(root) if e.is_dir(follow_symlinks=False) and not e.name.startswith("."))
    except OSError:
        return []
    obsolete = _read_json(root / ".obsolete") or {}
    for dname in dirs[:MAX_PER_SOURCE]:
        if isinstance(obsolete, dict) and obsolete.get(dname):
            continue
        pkg = _read_json(root / dname / "package.json", 4 * 1024 * 1024)
        if not isinstance(pkg, dict) or not pkg.get("name") or not pkg.get("publisher"):
            continue
        ext_id = f"{pkg['publisher']}.{pkg['name']}".lower()[:200]
        m = by_dir.get(dname) or {}
        md = m.get("metadata") or {}
        src = md.get("source")
        findings = [_f("full_rights", 10, "Runs with your full user rights (files, network, terminals)")]
        if src == "vsix" or (not md and not src):
            findings.append(_f("sideloaded", 25 if src == "vsix" else 15,
                               "Installed from a .vsix file, not the marketplace" if src == "vsix" else
                               "Install source unknown (not recorded as a marketplace install)"))
        acts = [a for a in pkg.get("activationEvents") or [] if isinstance(a, str)]
        if "*" in acts:
            findings.append(_f("always_on", 10, "Starts with every window (activation '*')"))
        if md.get("isPreReleaseVersion"):
            findings.append(_f("prerelease", 5, "Pre-release version"))
        if pkg.get("main") and not (root / dname / str(pkg["main"]).lstrip("./")).exists() and \
                not (root / dname / (str(pkg["main"]).lstrip("./") + ".js")).exists():
            findings.append(_f("main_missing", 5, "Its main script is missing (damaged install)"))
        name = str(pkg.get("displayName") or pkg["name"])
        if name.startswith("%"):
            nls = _read_json(root / dname / "package.nls.json", 512 * 1024)
            name = str((nls or {}).get(name.strip("%")) or pkg["name"]) if isinstance(nls, dict) else pkg["name"]
        score = min(100, sum(f["points"] for f in findings))
        pub_ok = md.get("publisherDisplayName")
        items.append({"key": f"{eid}:{ext_id}", "app": eid, "app_label": label, "profile": None, "id": ext_id,
                      "name": name[:120], "version": str(pkg.get("version") or "")[:40], "enabled": True,
                      "source": "store" if src == "gallery" else (src or "unknown"),
                      "publisher": pub_ok or pkg.get("publisher"), "permissions": [], "hosts": [], "all_sites": False,
                      "score": score, "level": level(score), "findings": sorted(findings, key=lambda f: -f["points"]),
                      "path": str(root / dname),
                      "store_url": STORE_PAGES[eid].format(id=ext_id, slash=ext_id.replace(".", "/", 1)),
                      "remove_at": f"{label}: Extensions view > gear > Uninstall"})
    return items


# ====================================================================== entry point
def audit() -> dict:
    L = pc.Layout()
    win = L.kind == "windows"
    items: list[dict] = []
    apps: list[dict] = []
    for bid, (label, win_rel, lin_rel, _procs) in pc.CHROMIUM.items():
        ud = (L.local / win_rel) if win else (L.roaming / lin_rel)
        profiles = pc._chromium_profiles(ud)
        if profiles:
            apps.append({"app": bid, "label": label, "kind": "browser", "profiles": [p.name for p in profiles]})
        for p in profiles:
            items += _chromium(bid, label, p)
    ffbase = (L.roaming / "Mozilla" / "Firefox") if win else (L.home / ".mozilla" / "firefox")
    ffp = pc._firefox_profiles(ffbase)
    if ffp:
        apps.append({"app": "firefox", "label": "Mozilla Firefox", "kind": "browser", "profiles": [p.name for p in ffp]})
    for p in ffp:
        items += _firefox(p)
    for eid, (label, folder) in EDITORS.items():
        root = L.home / folder / "extensions"
        if root.is_dir():
            got = _editor(eid, label, root)
            apps.append({"app": eid, "label": label, "kind": "editor", "profiles": None})
            items += got
    items.sort(key=lambda x: (-x["score"], x["app"], x["name"].lower()))
    counts = {lv: sum(1 for i in items if i["level"] == lv) for lv in ("high", "medium", "low", "none")}
    return {"apps": apps, "items": items, "total": len(items), "by_level": counts,
            "all_sites": sum(1 for i in items if i["all_sites"] and i["enabled"])}
