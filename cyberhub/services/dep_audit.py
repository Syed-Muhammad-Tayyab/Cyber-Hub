"""
Cyber Hub Backend - Dependency auditor (Part 14)
Developed by Syed Muhammad Tayyab

Finds the libraries a project uses and checks them against the OSV vulnerability database
(osv.dev - GitHub Security Advisories, PyPA, npm, Packagist, malicious-package reports).

* Lockfiles (exact versions): package-lock.json / npm-shrinkwrap.json (v1, v2, v3), yarn.lock (classic + berry),
  pnpm-lock.yaml (v5-v9), Pipfile.lock, poetry.lock, uv.lock, composer.lock, requirements*.txt (== pins).
  Without a lockfile, package.json / composer.json ranges are read as "approximate" (lowest allowed version).
* Version comparison: npm / Packagist semver rules, PyPI PEP 440 (packaging, with a built-in fallback).
* OSV matching: OSV's own range algorithm (introduced / fixed / last_affected), so an offline copy of the
  database (imported from OSV's per-ecosystem all.zip) gives the same answers as the online API.
* Severity: GitHub advisory rating, else a CVSS 3.x base score computed from the vector, MAL-* = critical.

Only package names + versions are ever sent online (never code or file names), and only when
web_dep_online is on.
"""
from __future__ import annotations

import json
import math
import os
import re
import urllib.error
import urllib.request
import zipfile
from typing import Any, Iterator

ECOSYSTEMS = ("npm", "PyPI", "Packagist")
SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "venv", ".venv", "env", ".env", "__pycache__", ".tox", ".nox",
             "dist", "build", "vendor", ".next", ".nuxt", "bower_components", "site-packages", ".idea", ".vscode",
             "coverage", ".cache", "target", "bin", "obj", ".pytest_cache", ".mypy_cache", ".gradle", ".terraform",
             ".svelte-kit", ".parcel-cache", ".turbo", "out", "storage"}
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
PY_LOCKS = ("Pipfile.lock", "poetry.lock", "uv.lock")
MAX_MANIFEST = 30 * 1024 * 1024
MAX_DEPS = 20000
OSV_URL = "https://api.osv.dev"
OSV_DUMP = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"


class DepError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


# ====================================================================== versions
def norm_name(eco: str, name: str) -> str:
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco == "Packagist":
        return name.lower()
    return name


_SEMVER = re.compile(r"^[vV=]?\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[-.]?((?:alpha|beta|rc|pre|dev|a|b|p|patch|"
                     r"[0-9A-Za-z])[0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]+)?$")


def _semver_key(v: str) -> tuple | None:
    m = _SEMVER.match(str(v).strip())
    if not m:
        return None
    nums = tuple(int(x or 0) for x in m.group(1, 2, 3, 4))
    pre = m.group(5)
    if not pre:
        return nums + ((1,),)                               # a release sorts after its pre-releases
    ids = []
    for part in re.split(r"[.-]", pre):
        ids.append((0, int(part), "") if part.isdigit() else (1, 0, part.lower()))
    return nums + ((0, tuple(ids)),)


def _pep440_fallback(v: str) -> tuple | None:
    m = re.match(r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?"
                 r"(?:[-_.]?(post|rev|r)[-_.]?(\d*)|-(\d+))?(?:[-_.]?dev[-_.]?(\d*))?(?:\+.*)?$", v.strip().lower())
    if not m:
        return None
    epoch = int(m.group(1) or 0)
    rel = tuple(int(x) for x in m.group(2).split("."))
    rel = rel + (0,) * (6 - len(rel)) if len(rel) < 6 else rel
    pre = m.group(3)
    pre_k = ({"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}[pre], int(m.group(4) or 0)) \
        if pre else (3, 0)
    post = m.group(6) if m.group(5) else m.group(7)
    post_k = int(post or 0) if (m.group(5) or m.group(7)) else -1
    dev = m.group(8)
    dev_k = int(dev or 0) if dev is not None and m.group(0).find("dev") >= 0 else 1 << 30
    if dev is not None and not pre and post_k < 0:
        pre_k = (-1, 0)                                     # 1.0.dev1 < 1.0a1
    return (epoch, rel, pre_k, post_k, dev_k)


def version_key(eco: str, v: str):
    if eco == "PyPI":
        try:
            from packaging.version import InvalidVersion, Version
            try:
                return (0, Version(v))
            except InvalidVersion:
                return None
        except ImportError:                                 # pragma: no cover - packaging ships with pip
            k = _pep440_fallback(v)
            return (1, k) if k else None
    k = _semver_key(v)
    return k


def vcmp(eco: str, a: str, b: str) -> int | None:
    ka, kb = version_key(eco, a), version_key(eco, b)
    if ka is None or kb is None:
        return None
    try:
        return (ka > kb) - (ka < kb)
    except TypeError:                                       # pragma: no cover
        return None


# ====================================================================== OSV matching
def _in_range(eco: str, version: str, events: list[dict]) -> bool:
    def key(e: dict) -> tuple:
        val = next(iter(e.values()), "0")
        if val == "0":
            return (0,)
        k = version_key(eco, str(val))
        return (1, k) if k is not None else (2,)
    evs = [e for e in events if isinstance(e, dict) and e]
    try:
        evs.sort(key=key)
    except TypeError:                                       # pragma: no cover
        pass
    affected = False
    for e in evs:
        if "introduced" in e:
            c = 0 if e["introduced"] == "0" else vcmp(eco, version, e["introduced"])
            if e["introduced"] == "0" or (c is not None and c >= 0):
                affected = True
        elif "fixed" in e:
            c = vcmp(eco, version, e["fixed"])
            if c is not None and c >= 0:
                affected = False
        elif "last_affected" in e:
            c = vcmp(eco, version, e["last_affected"])
            if c is not None and c > 0:
                affected = False
        elif "limit" in e:
            c = vcmp(eco, version, e["limit"])
            if c is not None and c >= 0:
                affected = False
    return affected


def _matching(vuln: dict, eco: str, name: str) -> list[dict]:
    n = norm_name(eco, name)
    return [a for a in vuln.get("affected") or [] if (a.get("package") or {}).get("ecosystem", "").split(":")[0] == eco
            and norm_name(eco, (a.get("package") or {}).get("name", "")) == n]


def is_affected(vuln: dict, eco: str, name: str, version: str) -> bool:
    for a in _matching(vuln, eco, name):
        if version in (a.get("versions") or []):
            return True
        for r in a.get("ranges") or []:
            if r.get("type") in ("SEMVER", "ECOSYSTEM") and _in_range(eco, version, r.get("events") or []):
                return True
    return False


def fixed_in(vuln: dict, eco: str, name: str, version: str) -> str | None:
    """Smallest fixed version above the installed one, if OSV knows it."""
    cands = []
    for a in _matching(vuln, eco, name):
        for r in a.get("ranges") or []:
            for e in r.get("events") or []:
                if "fixed" in e:
                    c = vcmp(eco, e["fixed"], version)
                    if c is not None and c > 0:
                        cands.append(e["fixed"])
    if not cands:
        return None
    best = cands[0]
    for c in cands[1:]:
        if (vcmp(eco, c, best) or 0) < 0:
            best = c
    return best


# ---------------------------------------------------------------- severity
_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
      "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """CVSS 3.0 / 3.1 base score from a vector string (FIRST specification)."""
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + expl), 10)) if scope_changed else _roundup(min(impact + expl, 10))


def rating(score: float | None) -> str | None:
    if score is None:
        return None
    if score == 0:
        return "info"
    return "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 else "critical"


def vuln_severity(v: dict) -> tuple[str, float | None]:
    """(severity, cvss score or None)."""
    if str(v.get("id", "")).startswith("MAL-"):
        return "critical", None
    score = None
    for s in v.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_score(s.get("score", ""))
            if score is not None:
                break
    ds = str((v.get("database_specific") or {}).get("severity") or "").upper()
    label = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}.get(ds)
    if not label:
        for a in v.get("affected") or []:
            es = str(((a.get("ecosystem_specific") or {}).get("severity")) or "").upper()
            label = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium",
                     "LOW": "low"}.get(es)
            if label:
                break
    return label or rating(score) or "medium", score


def compact(v: dict, ecosystems: tuple[str, ...] = ECOSYSTEMS) -> dict:
    """What Cyber Hub keeps of an OSV record (enough to match offline and explain the finding)."""
    sev, score = vuln_severity(v)
    aff = []
    for a in v.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("ecosystem", "").split(":")[0] not in ecosystems:
            continue
        aff.append({"package": {"ecosystem": pkg.get("ecosystem", "").split(":")[0], "name": pkg.get("name", "")},
                    "ranges": [{"type": r.get("type"), "events": r.get("events") or []}
                               for r in a.get("ranges") or [] if r.get("type") in ("SEMVER", "ECOSYSTEM")],
                    "versions": (a.get("versions") or [])[:3000]})
    refs = [r.get("url") for r in v.get("references") or [] if r.get("url")]
    advisory = next((u for u in refs if "github.com/advisories/" in u or "osv.dev" in u), None)
    return {"id": v.get("id"), "summary": (v.get("summary") or (v.get("details") or "").split("\n")[0])[:300],
            "details": (v.get("details") or "")[:800], "aliases": (v.get("aliases") or [])[:20],
            "severity": sev, "cvss": score, "published": v.get("published"), "modified": v.get("modified"),
            "references": refs[:6], "url": advisory or f"https://osv.dev/vulnerability/{v.get('id')}",
            "withdrawn": v.get("withdrawn"), "affected": aff}


# ====================================================================== OSV online
class OSVClient:
    def __init__(self, base: str | None = None, timeout: float = 20.0):
        self.base = (base or os.environ.get("CYBERHUB_OSV_URL") or OSV_URL).rstrip("/")
        self.timeout = timeout

    def _req(self, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method="POST" if data else "GET",
                                     headers={"Content-Type": "application/json", "Accept": "application/json",
                                              "User-Agent": "CyberHub-DependencyAudit/0.14"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read(64 * 1024 * 1024).decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise DepError(404, "Not found")
            raise DepError(502, f"OSV answered HTTP {e.code}")
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise DepError(503, f"Could not reach the OSV vulnerability service ({getattr(e, 'reason', e)})")
        except ValueError:
            raise DepError(502, "OSV sent an unreadable answer")

    def query_batch(self, pkgs: list[tuple[str, str, str]]) -> list[list[str]]:
        """Vulnerability ids for each (ecosystem, name, version)."""
        out: list[list[str]] = []
        for i in range(0, len(pkgs), 500):
            chunk = pkgs[i:i + 500]
            res = self._req("/v1/querybatch", {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v}
                                                           for e, n, v in chunk]})
            rows = res.get("results") or []
            for j in range(len(chunk)):
                r = rows[j] if j < len(rows) else {}
                out.append([x["id"] for x in (r.get("vulns") or []) if x.get("id")])
        return out

    def vuln(self, vid: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{3,80}", vid):
            raise DepError(400, "Invalid vulnerability id")
        return self._req(f"/v1/vulns/{vid}")


def iter_osv_zip(path: str, ecosystems: tuple[str, ...] = ECOSYSTEMS) -> Iterator[dict]:
    """OSV records from an all.zip export (or a .json file / folder of .json files)."""
    def load(b: bytes) -> dict | None:
        try:
            v = json.loads(b.decode("utf-8"))
            return v if isinstance(v, dict) and v.get("id") else None
        except (ValueError, UnicodeDecodeError):
            return None
    if os.path.isdir(path):
        for root, _d, files in os.walk(path):
            for f in files:
                if f.endswith(".json"):
                    with open(os.path.join(root, f), "rb") as fh:
                        v = load(fh.read(16 * 1024 * 1024))
                    if v:
                        yield v
        return
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.filename.endswith(".json") and info.file_size < 16 * 1024 * 1024:
                    v = load(z.read(info))
                    if v:
                        yield v
        return
    with open(path, "rb") as fh:
        data = fh.read(64 * 1024 * 1024)
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise DepError(422, "Not an OSV .zip / .json file")
    for v in obj if isinstance(obj, list) else [obj]:
        if isinstance(v, dict) and v.get("id"):
            yield v


# ====================================================================== manifests
def _dep(eco: str, name: str, version: str | None, file: str, direct: bool | None = None, dev: bool = False,
         approx: bool = False) -> dict:
    return {"ecosystem": eco, "name": name.strip(), "version": (version or "").strip() or None, "file": file,
            "direct": direct, "dev": dev, "approx": approx}


def _read(path: str) -> str:
    if os.path.getsize(path) > MAX_MANIFEST:
        raise DepError(413, f"{os.path.basename(path)} is too large")
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8", "replace")


def parse_package_lock(text: str, file: str) -> list[dict]:
    data = json.loads(text)
    out: list[dict] = []
    pk = data.get("packages")
    if isinstance(pk, dict) and pk:
        root = pk.get("") or {}
        direct = set(root.get("dependencies") or {}) | set(root.get("devDependencies") or {}) | \
            set(root.get("optionalDependencies") or {})
        for key, info in pk.items():
            if not key or not isinstance(info, dict) or info.get("link") or "node_modules/" not in key:
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[1]
            top = key == f"node_modules/{name}"
            out.append(_dep("npm", name, info.get("version"), file, top and name in direct,
                            bool(info.get("dev") or info.get("devOptional"))))
        return out

    def walk(deps: dict, depth: int) -> None:
        for name, info in (deps or {}).items():
            if not isinstance(info, dict):
                continue
            v = info.get("version") or ""
            if v and not re.match(r"^\d", v):               # git / file / link entries
                v = ""
            out.append(_dep("npm", name, v or None, file, depth == 0, bool(info.get("dev"))))
            if depth < 50:
                walk(info.get("dependencies") or {}, depth + 1)
    walk(data.get("dependencies") or {}, 0)
    return out


def parse_yarn_lock(text: str, file: str) -> list[dict]:
    out: list[dict] = []
    names: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            spec = line.rstrip()[:-1].split(",")[0].strip().strip('"')
            if spec.startswith("__metadata"):
                names = []
                continue
            at = spec.rfind("@")
            name = spec[:at] if at > 0 else spec
            rest = spec[at + 1:] if at > 0 else ""
            names = [] if ("@workspace:" in spec or rest.startswith(("workspace:", "link:", "portal:", "file:"))) \
                else [name]
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if m and names:
            out.append(_dep("npm", names[0], m.group(1), file))
            names = []
    return out


_PNPM = re.compile(r"""^  ['"]?/?((?:@[^/\s'"@]+/)?[^@/\s'"(]+)[@/](\d[^\s'"():_]*)""")


def parse_pnpm_lock(text: str, file: str) -> list[dict]:
    out: list[dict] = []
    seen = set()
    section = None
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t")):
            section = line.split(":", 1)[0].strip()
            continue
        if section not in ("packages", "snapshots"):
            continue
        m = _PNPM.match(line)
        if m and (m.group(1), m.group(2)) not in seen:
            seen.add((m.group(1), m.group(2)))
            out.append(_dep("npm", m.group(1), m.group(2), file))
    return out


def _approx(rng: str) -> str | None:
    r = str(rng).strip()
    if not r or r in ("*", "latest", "x") or re.match(r"(?i)^(git|github:|file:|link:|workspace:|https?:|npm:|dev-)", r):
        return None
    r = r.split("||")[-1].strip() if "||" in r else r
    m = re.search(r"(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(-[0-9A-Za-z.-]+)?", r)
    if not m:
        return None
    parts = [m.group(1), m.group(2) or "0", m.group(3) or "0"]
    parts = ["0" if p in ("x", "*") else p for p in parts]
    return ".".join(parts) + (m.group(4) or "")


def parse_package_json(text: str, file: str) -> list[dict]:
    data = json.loads(text)
    out = []
    for sect, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
        for name, rng in (data.get(sect) or {}).items():
            v = _approx(rng)
            out.append(_dep("npm", name, v, file, True, dev, approx=True))
    return out


_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(===?|~=|>=|<=|!=|>|<)?\s*([^\s;,#]*)")


def parse_requirements(path: str, file: str, depth: int = 0) -> tuple[list[dict], list[str]]:
    """(pinned deps, unpinned package names). Follows -r includes inside the same project."""
    out: list[dict] = []
    loose: list[str] = []
    text = _read(path)
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ")) and depth < 3:
            inc = line.split(None, 1)[1].strip()
            p = os.path.normpath(os.path.join(os.path.dirname(path), inc))
            if os.path.isfile(p) and line.startswith(("-r", "--requirement")):
                o2, l2 = parse_requirements(p, os.path.join(os.path.dirname(file), inc), depth + 1)
                out += o2
                loose += l2
            continue
        if line.startswith("-") or "://" in line or line.startswith((".", "/")):
            continue
        m = _REQ.match(line)
        if not m:
            continue
        name, op, ver = m.group(1), m.group(2), m.group(3)
        if op in ("==", "===") and ver and "*" not in ver:
            out.append(_dep("PyPI", name, ver, file, True))
        else:
            loose.append(name)
    return out, loose


def parse_pipfile_lock(text: str, file: str) -> list[dict]:
    data = json.loads(text)
    out = []
    for sect, dev in (("default", False), ("develop", True)):
        for name, info in (data.get(sect) or {}).items():
            v = str((info or {}).get("version") or "").lstrip("=")
            if v:
                out.append(_dep("PyPI", name, v, file, None, dev))
    return out


def parse_toml_lock(text: str, file: str) -> list[dict]:
    """poetry.lock / uv.lock: [[package]] blocks with name / version (the project itself is skipped)."""
    out = []
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        n = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
        v = re.search(r'(?m)^version\s*=\s*"([^"]+)"', block)
        if not n or not v:
            continue
        if re.search(r'(?m)^source\s*=\s*\{\s*(?:editable|virtual)\s*=', block):
            continue
        cat = re.search(r'(?m)^category\s*=\s*"([^"]+)"', block)
        out.append(_dep("PyPI", n.group(1), v.group(1), file, None, bool(cat and cat.group(1) == "dev")))
    return out


def parse_composer_lock(text: str, file: str) -> list[dict]:
    data = json.loads(text)
    out = []
    for sect, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(sect) or []:
            v = str(p.get("version") or "")
            if v.startswith("dev-") or not p.get("name"):
                continue
            out.append(_dep("Packagist", p["name"], v.lstrip("vV"), file, None, dev))
    return out


def parse_composer_json(text: str, file: str) -> list[dict]:
    data = json.loads(text)
    out = []
    for sect, dev in (("require", False), ("require-dev", True)):
        for name, rng in (data.get(sect) or {}).items():
            if "/" not in name:                             # php, ext-* platform packages
                continue
            out.append(_dep("Packagist", name, _approx(rng), file, True, dev, approx=True))
    return out


def find_manifests(root: str, max_depth: int = 6, max_files: int = 60) -> list[str]:
    """Manifest / lockfile paths under a project folder (dependency folders skipped)."""
    names = set(NPM_LOCKS) | set(PY_LOCKS) | {"package.json", "composer.lock", "composer.json"}
    found: list[str] = []
    root = os.path.abspath(root)
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        if dirpath.count(os.sep) - base_depth >= max_depth:
            dirnames[:] = []
        for f in sorted(filenames):
            if f in names or re.fullmatch(r"requirements[\w.-]*\.txt", f):
                found.append(os.path.join(dirpath, f))
                if len(found) >= max_files:
                    return found
    return found


def collect(root: str, paths: list[str] | None = None) -> dict:
    """{deps[], files[{file, ecosystem, kind, count}], unpinned[], no_lockfile[], errors[]} for a project."""
    root = os.path.abspath(root)
    paths = paths if paths is not None else find_manifests(root)
    by_dir: dict[str, set[str]] = {}
    for p in paths:
        by_dir.setdefault(os.path.dirname(p), set()).add(os.path.basename(p))
    deps: list[dict] = []
    files: list[dict] = []
    unpinned: list[str] = []
    no_lock: list[str] = []
    errors: list[dict] = []

    def rel(p: str) -> str:
        r = os.path.relpath(p, root)
        return os.path.basename(p) if r.startswith("..") else r.replace(os.sep, "/")

    for d, fnames in sorted(by_dir.items()):
        jobs: list[tuple[str, str]] = []
        npm_lock = next((f for f in NPM_LOCKS if f in fnames), None)
        if npm_lock:
            jobs.append((npm_lock, "lock"))
        elif "package.json" in fnames:
            jobs.append(("package.json", "approx"))
        py = [f for f in PY_LOCKS if f in fnames]
        jobs += [(f, "lock") for f in py]
        if not py:
            jobs += [(f, "lock") for f in sorted(fnames) if re.fullmatch(r"requirements[\w.-]*\.txt", f)]
        if "composer.lock" in fnames:
            jobs.append(("composer.lock", "lock"))
        elif "composer.json" in fnames:
            jobs.append(("composer.json", "approx"))
        for fname, kind in jobs:
            p = os.path.join(d, fname)
            r = rel(p)
            try:
                if fname in ("package-lock.json", "npm-shrinkwrap.json"):
                    got, eco = parse_package_lock(_read(p), r), "npm"
                elif fname == "yarn.lock":
                    got, eco = parse_yarn_lock(_read(p), r), "npm"
                elif fname == "pnpm-lock.yaml":
                    got, eco = parse_pnpm_lock(_read(p), r), "npm"
                elif fname == "package.json":
                    got, eco = parse_package_json(_read(p), r), "npm"
                    if got:
                        no_lock.append(r)
                elif fname == "Pipfile.lock":
                    got, eco = parse_pipfile_lock(_read(p), r), "PyPI"
                elif fname in ("poetry.lock", "uv.lock"):
                    got, eco = parse_toml_lock(_read(p), r), "PyPI"
                elif fname == "composer.lock":
                    got, eco = parse_composer_lock(_read(p), r), "Packagist"
                elif fname == "composer.json":
                    got, eco = parse_composer_json(_read(p), r), "Packagist"
                    if got:
                        no_lock.append(r)
                else:
                    got, loose = parse_requirements(p, r)
                    eco = "PyPI"
                    unpinned += [f"{n} ({r})" for n in loose]
            except (ValueError, DepError, OSError) as e:
                errors.append({"file": r, "error": getattr(e, "message", None) or f"Could not read it ({e})"})
                continue
            files.append({"file": r, "ecosystem": eco, "kind": kind, "count": len(got)})
            deps += got
            if len(deps) > MAX_DEPS:
                errors.append({"file": r, "error": f"More than {MAX_DEPS} packages - the rest were skipped"})
                break
    # one row per (ecosystem, name, version); remember every file it came from
    merged: dict[tuple, dict] = {}
    for x in deps:
        k = (x["ecosystem"], norm_name(x["ecosystem"], x["name"]), x["version"])
        m = merged.get(k)
        if m is None:
            m = merged[k] = dict(x, files=[x["file"]])
        else:
            if x["file"] not in m["files"]:
                m["files"].append(x["file"])
            m["direct"] = bool(m["direct"]) or bool(x["direct"])
            m["dev"] = m["dev"] and x["dev"]
            m["approx"] = m["approx"] and x["approx"]
    return {"deps": list(merged.values())[:MAX_DEPS], "files": files, "unpinned": unpinned[:200],
            "no_lockfile": no_lock, "errors": errors}


# ====================================================================== project settings
_GITIGNORE_ENV = re.compile(r"(?m)^\s*/?(?:\.env\*?|\.env\.\*|\*\.env|\.env[\w.*-]*)\s*$")


def config_checks(root: str) -> list[dict]:
    """Risky project settings (findings in the web_checks format)."""
    from .web_checks import F
    out: list[dict] = []
    root = os.path.abspath(root)
    envs = [f for f in (".env", ".env.production", ".env.local", ".env.prod") if os.path.isfile(os.path.join(root, f))]
    gi_path = os.path.join(root, ".gitignore")
    is_repo = os.path.isdir(os.path.join(root, ".git"))
    if envs and is_repo:
        gi = ""
        if os.path.isfile(gi_path):
            try:
                gi = _read(gi_path)
            except (OSError, DepError):
                gi = ""
        if not _GITIGNORE_ENV.search(gi):
            out.append(F("env_not_ignored", "config", "high", ".env is not in .gitignore",
                         f"{', '.join(envs)} would be committed with `git add .` - secrets end up on GitHub, where "
                         "bots find them within minutes.",
                         "Add .env* to .gitignore (keep a .env.example without real values). If it was ever pushed, "
                         "rotate every key in it.", ", ".join(envs)))
    env_text = ""
    for f in envs:
        try:
            env_text += _read(os.path.join(root, f)) + "\n"
        except (OSError, DepError):
            pass
    if re.search(r"(?mi)^\s*APP_DEBUG\s*=\s*true\s*$", env_text) and \
            re.search(r"(?mi)^\s*APP_ENV\s*=\s*prod(uction)?\s*$", env_text):
        out.append(F("laravel_debug_prod", "config", "high", "Laravel production settings with APP_DEBUG=true",
                     "APP_ENV=production but APP_DEBUG=true: every error page shows code and environment values.",
                     "Set APP_DEBUG=false for production", "APP_DEBUG=true"))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        if dirpath.count(os.sep) - root.count(os.sep) > 4:
            dirnames[:] = []
        rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
        if "settings.py" in filenames:
            try:
                t = _read(os.path.join(dirpath, "settings.py"))
            except (OSError, DepError):
                t = ""
            if re.search(r"(?m)^DEBUG\s*=\s*True\b", t):
                out.append(F("django_debug_setting", "config", "low", "Django settings have DEBUG = True",
                             f"{rel}/settings.py turns debug on. Fine on your PC - deadly in production.",
                             "Read it from the environment: DEBUG = os.environ.get('DJANGO_DEBUG') == '1'",
                             f"{rel}/settings.py"))
            if re.search(r"(?m)^SECRET_KEY\s*=\s*['\"](?!django-insecure-)[^'\"]{20,}['\"]", t):
                out.append(F("django_secret_in_code", "config", "medium", "Django SECRET_KEY is written in the code",
                             "Anyone with the source code can forge sessions and password-reset links.",
                             "Load SECRET_KEY from an environment variable", f"{rel}/settings.py"))
        if ".npmrc" in filenames:
            try:
                t = _read(os.path.join(dirpath, ".npmrc"))
            except (OSError, DepError):
                t = ""
            if re.search(r"_authToken\s*=\s*(?!\$\{)[A-Za-z0-9_-]{10,}", t):
                out.append(F("npmrc_token", "config", "high", "npm access token saved in .npmrc",
                             "A publish token in the project lets anyone with the code publish packages as you.",
                             "Use ${NPM_TOKEN} in .npmrc and keep the real token in an environment variable",
                             f"{rel}/.npmrc"))
        for f in filenames:
            if f.endswith(".py") and f in ("app.py", "main.py", "run.py", "wsgi.py", "server.py"):
                try:
                    t = _read(os.path.join(dirpath, f))
                except (OSError, DepError):
                    continue
                if re.search(r"\.run\([^)]*debug\s*=\s*True", t):
                    out.append(F("flask_debug_run", "config", "medium", "Flask app starts with debug=True",
                                 f"{rel}/{f} runs the Werkzeug debugger - if this is ever reachable from the network "
                                 "anyone gets a Python console.", "Use debug only through FLASK_DEBUG on your PC",
                                 f"{rel}/{f}"))
                    break
    return out
