"""
Cyber Hub Backend - Heuristic analysis (Part 8)
Developed by Syed Muhammad Tayyab

Finds NEW malware that no signature knows yet by looking at how a file is
built instead of what it exactly is. Every check is explainable: it adds a
flag with a weight, the weights add up to a 0-100 suspicion score, and the
file is reported once the score reaches the threshold for the chosen
sensitivity (low 80 / medium 60 / high 45).

    file name   double extensions (invoice.pdf.exe), padded extensions,
                right-to-left override tricks, executables posing as documents
    programs    own PE parser - packer section names (UPX, MPRESS, Themida...),
                high-entropy (encrypted / packed) code, writable+executable
                sections, entry point outside code, tiny import tables,
                process-injection / keylogger / downloader API combinations,
                high-entropy overlay, embedded Authenticode certificate (lowers score)
    scripts     long base64 blobs, char-code building, string-split obfuscation,
                dynamic execution (IEX / eval), download-and-run, Defender
                tampering, backup deletion, hidden windows
    documents   OOXML / OLE macros, auto-run macros, macros that start programs,
                remote template injection
    shortcuts   .lnk files that start script hosts with hidden / encoded arguments
    archives    password-protected archives hiding programs, double extensions inside
    web pages   HTML smuggling (file built in the browser and auto-saved)

No dependency besides the standard library - works on every PC.
"""
from __future__ import annotations

import io
import math
import os
import re
import struct
import zipfile
from collections import Counter
from datetime import datetime, timezone

VERSION = "h1.0"

SENSITIVITY = {"low": 80, "medium": 60, "high": 45}

# id -> (weight, category, explanation)
CHECKS: dict[str, tuple[int, str, str]] = {
    # ---- names
    "double_extension":        (55, "DoubleExtension", "Hides a program behind a document extension (e.g. invoice.pdf.exe)"),
    "padded_extension":        (25, "DoubleExtension", "Pads the name with spaces so the real extension is pushed out of view"),
    "rtlo_name":               (70, "NameSpoofing", "Uses a right-to-left override character to reverse how the name is displayed"),
    "disguised_executable":    (65, "DisguisedExecutable", "Program code inside a file named like a document, picture or text file"),
    # ---- programs (PE)
    "packer_section":          (30, "PackedExecutable", "Packed / protected with a known packer"),
    "high_entropy_code":       (25, "PackedExecutable", "Executable code is encrypted or compressed (very high entropy)"),
    "rwx_section":             (25, "PackedExecutable", "Has a section that is both writable and executable"),
    "entry_outside_code":      (20, "PackedExecutable", "Starts running from outside its normal code section"),
    "few_imports":             (15, "PackedExecutable", "Imports almost no Windows functions (typical of packed / loader code)"),
    "dynamic_loader_only":     (15, "PackedExecutable", "Only resolves functions at run time (LoadLibrary + GetProcAddress)"),
    "injection_apis":          (35, "ProcessInjector", "Can write code into other programs and start it (process injection)"),
    "keylogger_apis":          (35, "Keylogger", "Hooks or polls the keyboard (key-logging pattern)"),
    "downloader_apis":         (20, "Downloader", "Downloads files from the internet and runs programs"),
    "anti_debug":              (10, "PackedExecutable", "Checks whether it is being debugged / analysed"),
    "overlay_high_entropy":    (15, "PackedExecutable", "Carries a large encrypted blob appended after the program"),
    "bad_timestamp":           (5, "PackedExecutable", "Build date is in the future or zeroed"),
    "embedded_signature":      (-20, "", "Carries an Authenticode certificate (not verified here)"),
    # ---- scripts
    "script_long_base64":      (30, "ObfuscatedScript", "Contains a long base64-encoded blob"),
    "script_char_codes":       (25, "ObfuscatedScript", "Builds text from character codes to hide it"),
    "script_concat":           (20, "ObfuscatedScript", "Splits strings into many small pieces to hide words"),
    "script_long_line":        (15, "ObfuscatedScript", "Has an extremely long single line"),
    "script_dynamic_exec":     (20, "ObfuscatedScript", "Runs code built at run time (IEX / eval / Execute)"),
    "script_download_exec":    (35, "Downloader", "Downloads something and runs it"),
    "script_av_tamper":        (50, "DefenseEvasion", "Turns off or bypasses antivirus protection"),
    "script_backup_delete":    (60, "RansomwarePrep", "Deletes shadow copies / backups or disables recovery"),
    "script_hidden":           (10, "ObfuscatedScript", "Asks for a hidden window"),
    "script_high_entropy":     (15, "ObfuscatedScript", "Text looks encrypted / packed (very high entropy)"),
    # ---- documents
    "office_macros":           (25, "MaliciousMacro", "Document contains macros"),
    "office_autoexec":         (30, "MaliciousMacro", "Macro runs automatically when the document opens"),
    "office_macro_exec":       (25, "MaliciousMacro", "Macro can start programs or download files"),
    "office_remote_template":  (45, "MaliciousMacro", "Loads a template from the internet when opened (template injection)"),
    "pdf_autorun_js":          (20, "MaliciousDocument", "PDF runs JavaScript automatically when opened"),
    "pdf_launch":              (35, "MaliciousDocument", "PDF tries to launch a program"),
    # ---- shortcuts
    "lnk_script_host":         (45, "MaliciousShortcut", "Shortcut starts a script host / LOLBin (PowerShell, mshta, cmd...)"),
    "lnk_long_args":           (20, "MaliciousShortcut", "Shortcut passes very long arguments"),
    "lnk_hidden":              (10, "MaliciousShortcut", "Shortcut runs minimised / hidden"),
    "url_remote_exec":         (40, "MaliciousShortcut", "Internet shortcut points at a program on a remote share or file URL"),
    # ---- archives
    "archive_encrypted_exec":  (45, "SuspiciousArchive", "Password-protected archive hiding a program or script"),
    "archive_double_extension": (45, "SuspiciousArchive", "Archive contains a file with a double extension"),
    "archive_single_exec":     (15, "SuspiciousArchive", "Archive holds a single program / script and nothing else"),
    # ---- web
    "html_smuggling":          (45, "HTMLSmuggling", "Web page builds a file in the browser and saves it automatically"),
}

EXEC_EXT = {".exe", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".dll", ".sys", ".reg", ".appref-ms",
            ".application", ".gadget", ".msc", ".inf", ".sct", ".iso", ".img", ".vhd", ".vhdx"}
DOC_EXT = {".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".rtf", ".txt", ".csv",
           ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".mp3", ".mp4", ".avi", ".mkv",
           ".mov", ".wav", ".zip", ".rar", ".7z", ".html", ".htm", ".odt", ".ods", ".xml", ".json", ".svg",
           ".heic", ".eml", ".msg", ".one"}
NOT_EXEC_EXT = DOC_EXT - {".zip", ".rar", ".7z", ".one", ".html", ".htm", ".svg"} | {".log", ".ini", ".dat"}
SCRIPT_EXT = {".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".bat", ".cmd",
              ".sh", ".py", ".pl", ".php", ".sct"}
OFFICE_EXT = {".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".xlam", ".ppt",
              ".pptx", ".pptm", ".ppam", ".potm"}
HTML_EXT = {".html", ".htm", ".xhtml", ".svg", ".shtml"}

_BIDI = re.compile("[‪-‮⁦-⁩‎‏]")
_PACKERS = {
    b"UPX0": "UPX", b"UPX1": "UPX", b"UPX2": "UPX", b".MPRESS1": "MPRESS", b".MPRESS2": "MPRESS",
    b".aspack": "ASPack", b".adata": "ASPack", b".themida": "Themida", b".winlice": "WinLicense",
    b".vmp0": "VMProtect", b".vmp1": "VMProtect", b".vmp2": "VMProtect", b".petite": "Petite",
    b".nsp0": "NsPack", b".nsp1": "NsPack", b"nsp0": "NsPack", b"nsp1": "NsPack", b"PEC2": "PECompact",
    b"PEC2TO": "PECompact", b"pec1": "PECompact", b".enigma1": "Enigma", b".enigma2": "Enigma",
    b"MEW": "MEW", b".kkrunchy": "kkrunchy", b"FSG!": "FSG", b".packed": "Unknown packer",
    b".perplex": "Perplex", b".spack": "Simple Pack", b".yP": "Y0da Protector", b".ccg": "CCG",
    b".Upack": "Upack", b"ByDwing": "Upack", b".boom": "Boomerang", b".taz": "PESpin", b".MaskPE": "MaskPE",
}
_INJECTION = ({"virtualallocex", "virtualalloc2"}, {"writeprocessmemory", "ntwritevirtualmemory"},
              {"createremotethread", "createremotethreadex", "ntcreatethreadex", "queueuserapc", "rtlcreateuserthread",
               "setthreadcontext"})
_KEYLOG = ({"setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeyboardstate",
            "registerrawinputdevices"},
           {"getforegroundwindow", "getwindowtexta", "getwindowtextw", "callnexthookex", "getkeystate",
            "mapvirtualkeya", "mapvirtualkeyw", "getrawinputdata"})
_DOWNLOAD = ({"urldownloadtofilea", "urldownloadtofilew", "internetopenurla", "internetopenurlw",
              "winhttpopenrequest", "internetreadfile", "httpopenrequesta", "httpopenrequestw"},
             {"winexec", "shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw", "createprocessa",
              "createprocessw"})
_ANTIDEBUG = {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa"}

# ---- script patterns (bytes, case-insensitive)
_B64 = re.compile(rb"[A-Za-z0-9+/]{400,}={0,2}")
_CHARCODE = re.compile(rb"\[char\]\s*\d{2,3}|fromcharcode\s*\(|\bchrw?\s*\(\s*\d{2,3}|\\x[0-9a-f]{2}\\x[0-9a-f]{2}"
                       rb"|\\u00[0-9a-f]{2}", re.I)
_CONCAT = re.compile(rb"""["']\s*(\+|&|\.)\s*["']""")
_DYN_EXEC = re.compile(rb"\biex\b|invoke-expression|\beval\s*\(|\bexecute(global)?\s*[\( ]|\[scriptblock\]::create"
                       rb"|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|frombase64string", re.I)
_DL = re.compile(rb"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|net\.webclient"
                 rb"|msxml2\.xmlhttp|winhttp\.winhttprequest|microsoft\.xmlhttp|start-bitstransfer|\bcurl\s+-|"
                 rb"\bwget\s+http|urldownloadtofile|-urlcache", re.I)
_RUN = re.compile(rb"\biex\b|invoke-expression|start-process|\.run\s*[\( ]|shellexecute|\.exec\s*\(|\bcmd(\.exe)?\s+/c"
                  rb"|\|\s*(ba)?sh\b|\bsh\s+-c|\beval\s*\(|rundll32|regsvr32|createobject\(.wscript\.shell", re.I)
_AV = re.compile(rb"set-mppreference\s[^\r\n]{0,80}-disable|add-mppreference\s[^\r\n]{0,80}-exclusion|"
                 rb"disableantispyware|amsiutils|amsiinitfailed|amsiscanbuffer", re.I)
_BACKUP = re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|wbadmin(\.exe)?\s+delete|"
                     rb"recoveryenabled\s+no|win32_shadowcopy", re.I)
_HIDDEN = re.compile(rb"-w(indowstyle)?\s+h(idden)?\b|\bvbhide\b|windowstyle\s*=\s*['\"]?hidden|"
                     rb"\.run\s*\(?[^,\r\n]+,\s*0\b", re.I)
_AUTOEXEC = re.compile(rb"auto_?open|document_open|workbook_open|autoexec|auto_close|document_close|"
                       rb"workbook_beforeclose|document_new", re.I)
_MACRO_EXEC = re.compile(rb"wscript\.shell|shell\.application|powershell|urldownloadtofile|createobject|"
                         rb"cmd\.exe|\bshell\s*\(|winhttp|xmlhttp|adodb\.stream|callbyname", re.I)
_SCRIPT_HOSTS = re.compile(r"(powershell|pwsh|mshta|wscript|cscript|cmd\.exe|cmd /c|rundll32|regsvr32|certutil|"
                           r"bitsadmin|msiexec|forfiles|conhost)", re.I)
_SHEBANG = re.compile(rb"^#!\s*/(usr/)?(local/)?bin/(env\s+)?(ba|z|k|da)?sh|^#!\s*/(usr/)?bin/(env\s+)?python", re.I)

LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = constant, 8 = random)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _ext(name: str) -> str:
    return os.path.splitext(name.strip().rstrip(". "))[1].lower()


# ====================================================================== PE parser
def parse_pe(data: bytes, max_imports: int = 3000) -> dict | None:
    """Minimal, defensive PE (Windows .exe / .dll) parser. Returns None if it isn't one."""
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return None
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if lfanew <= 0 or lfanew + 24 > len(data) or data[lfanew:lfanew + 4] != b"PE\x00\x00":
            return None
        coff = lfanew + 4
        machine, nsec, timestamp, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10B, 0x20B):
            return None
        pe64 = magic == 0x20B
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        nrva_off = opt + (108 if pe64 else 92)
        dd_off = opt + (112 if pe64 else 96)
        nrva = min(struct.unpack_from("<I", data, nrva_off)[0], 16) if nrva_off + 4 <= len(data) else 0
        dirs = []
        for i in range(nrva):
            o = dd_off + i * 8
            if o + 8 > len(data):
                break
            dirs.append(struct.unpack_from("<II", data, o))
        sections = []
        sec_off = opt + opt_size
        for i in range(min(nsec, 96)):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            raw_name = data[o:o + 8].rstrip(b"\x00")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
            sch = struct.unpack_from("<I", data, o + 36)[0]
            body = data[rptr:rptr + min(rsize, 8 * 1024 * 1024)] if rptr < len(data) else b""
            sections.append({
                "name": raw_name.decode("latin-1"), "raw_name": raw_name, "virtual_address": va,
                "virtual_size": vsize, "raw_size": rsize, "raw_pointer": rptr,
                "executable": bool(sch & 0x20000000) or bool(sch & 0x20),
                "writable": bool(sch & 0x80000000), "readable": bool(sch & 0x40000000),
                "entropy": round(entropy(body), 3) if body else 0.0,
            })

        def rva_to_off(rva: int) -> int | None:
            for s in sections:
                span = max(s["virtual_size"], s["raw_size"])
                if s["virtual_address"] <= rva < s["virtual_address"] + span:
                    off = rva - s["virtual_address"] + s["raw_pointer"]
                    return off if off < len(data) else None
            return rva if rva < len(data) and not sections else None

        def cstr(off: int | None, limit: int = 256) -> str:
            if off is None:
                return ""
            end = data.find(b"\x00", off, off + limit)
            return data[off:end if end >= 0 else off + limit].decode("latin-1", "replace")

        imports: dict[str, list[str]] = {}
        n_funcs = 0
        if len(dirs) > 1 and dirs[1][0]:
            off = rva_to_off(dirs[1][0])
            seen = 0
            while off is not None and off + 20 <= len(data) and seen < 256:
                oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
                if not (oft or name_rva or ft):
                    break
                dll = cstr(rva_to_off(name_rva), 128).lower() or "?"
                funcs = imports.setdefault(dll, [])
                toff = rva_to_off(oft or ft)
                step, flag = (8, 1 << 63) if pe64 else (4, 1 << 31)
                k = 0
                while toff is not None and toff + step <= len(data) and k < 4096 and n_funcs < max_imports:
                    v = struct.unpack_from("<Q" if pe64 else "<I", data, toff)[0]
                    if not v:
                        break
                    if v & flag:
                        funcs.append(f"#{v & 0xFFFF}")
                    else:
                        funcs.append(cstr((rva_to_off(v & 0x7FFFFFFF) or -2) + 2, 128))
                    n_funcs += 1
                    toff += step
                    k += 1
                off += 20
                seen += 1
        cert_off, cert_size = dirs[4] if len(dirs) > 4 else (0, 0)
        is_dotnet = len(dirs) > 14 and dirs[14][0] != 0
        end_of_sections = max((s["raw_pointer"] + s["raw_size"] for s in sections if s["raw_size"]), default=0)
        overlay_end = len(data)
        if cert_size and cert_off >= end_of_sections:
            overlay_end = min(overlay_end, cert_off)
        overlay = max(0, overlay_end - end_of_sections)
        ep_sec = next((s for s in sections if s["virtual_address"] <= entry <
                       s["virtual_address"] + max(s["virtual_size"], s["raw_size"])), None)
        return {
            "machine": {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C4: "ARM"}.get(machine, hex(machine)),
            "pe64": pe64, "dll": bool(chars & 0x2000), "timestamp": timestamp,
            "compiled_at": datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if 0 < timestamp < 4102444800 else None,
            "entry_point": entry, "entry_section": ep_sec["name"] if ep_sec else None,
            "entry_section_executable": bool(ep_sec and ep_sec["executable"]),
            "entry_in_last_section": bool(ep_sec and sections and ep_sec is sections[-1] and len(sections) > 1),
            "sections": [{k: v for k, v in s.items() if k != "raw_name"} for s in sections],
            "raw_section_names": [s["raw_name"] for s in sections],
            "imports": imports, "import_count": n_funcs, "dll_count": len(imports),
            "has_certificate": bool(cert_size), "dotnet": is_dotnet,
            "overlay_size": overlay, "overlay_offset": end_of_sections if overlay else None,
        }
    except (struct.error, ValueError, OverflowError, IndexError):
        return None


# ====================================================================== the analyser
class HeuristicEngine:
    """Stateless - safe to share between scan threads."""

    version = VERSION

    @staticmethod
    def checks() -> list[dict]:
        return [{"id": k, "weight": w, "category": c, "description": d} for k, (w, c, d) in CHECKS.items()]

    def analyze(self, data: bytes | None, name: str, size: int | None = None, partial: bool = False) -> dict:
        """data = whole file (or its first bytes when partial=True). Returns the full report."""
        data = data or b""
        size = len(data) if size is None else size
        flags: dict[str, str | None] = {}
        info: dict = {"file_type": self.file_type(data, name)}

        def flag(fid: str, detail: str | None = None):
            if fid not in flags:
                flags[fid] = detail

        self._name_checks(name, data, flag)
        ft = info["file_type"]
        if ft == "pe":
            pe = parse_pe(data) if not partial else parse_pe(data, max_imports=0)
            if pe:
                info["pe"] = {k: v for k, v in pe.items() if k not in ("raw_section_names", "imports")}
                info["pe"]["imports"] = {k: v[:200] for k, v in list(pe["imports"].items())[:64]}
                if not partial:
                    self._pe_checks(pe, data, flag)
        elif ft == "script":
            self._script_checks(data, name, flag)
        elif ft in ("ooxml", "ole"):
            self._office_checks(data, ft, flag)
        elif ft == "lnk":
            self._lnk_checks(data, flag)
        elif ft == "zip":
            self._zip_checks(data, flag)
        elif ft == "pdf":
            self._pdf_checks(data, flag)
        elif ft == "html":
            self._html_checks(data, flag)
        elif ft == "url":
            self._url_checks(data, flag)
        out = []
        total = 0
        for fid, detail in flags.items():
            w, cat, desc = CHECKS[fid]
            total += w
            out.append({"id": fid, "weight": w, "category": cat, "description": desc, "detail": detail})
        score = max(0, min(100, total))
        positive = [f for f in out if f["weight"] > 0]
        top = max(positive, key=lambda f: f["weight"], default=None)
        level = "high" if score >= 80 else "medium" if score >= 45 else "low" if score > 0 else "none"
        return {"score": score, "level": level, "flags": out, "category": top["category"] if top else None,
                "file_type": ft, "partial": partial, "size": size, "engine": VERSION, **info}

    def verdict(self, report: dict, sensitivity: str = "medium") -> dict | None:
        threshold = SENSITIVITY.get(sensitivity, 60)
        if report["score"] < threshold or not report["category"]:
            return None
        sev = "high" if report["score"] >= 90 else "medium"
        return {"threat_name": f"Heuristic:Suspicious.{report['category']}", "severity": sev, "method": "heuristic",
                "signature_source": "heuristics",
                "details": {"score": report["score"], "threshold": threshold, "sensitivity": sensitivity,
                            "flags": [{"id": f["id"], "weight": f["weight"], "description": f["description"],
                                       **({"detail": f["detail"]} if f["detail"] else {})} for f in report["flags"]]}}

    # ------------------------------------------------------------ file type
    @staticmethod
    def file_type(data: bytes, name: str) -> str:
        ext = _ext(name)
        if data[:2] == b"MZ":
            return "pe"
        if data[:4] == b"\x7fELF":
            return "elf"
        if data.startswith(LNK_MAGIC):
            return "lnk"
        if data[:8] == OLE_MAGIC:
            return "ole"
        if data[:4] == b"PK\x03\x04":
            head = data[:65536]
            if b"[Content_Types].xml" in head or ext in OFFICE_EXT:
                return "ooxml"
            return "zip"
        if data[:5] == b"%PDF-":
            return "pdf"
        if ext in HTML_EXT:
            return "html"
        if ext == ".url":
            return "url"
        if ext in SCRIPT_EXT or _SHEBANG.match(data[:200]):
            return "script"
        return "other"

    # ------------------------------------------------------------ names
    @staticmethod
    def _name_checks(name: str, data: bytes, flag) -> None:
        base = os.path.basename(name.replace("\\", "/"))
        if _BIDI.search(base):
            flag("rtlo_name", repr(base))
        clean = _BIDI.sub("", base)
        parts = clean.lower().split(".")
        if len(parts) >= 3:
            last = "." + parts[-1].strip()
            prev = "." + parts[-2].strip()
            if last in EXEC_EXT and prev in DOC_EXT:
                flag("double_extension", f"{prev} + {last}")
                if re.search(r"\s{3,}\.[^.]+$", clean) or re.search(r"[_\-]{8,}\.[^.]+$", clean):
                    flag("padded_extension")
        ext = _ext(clean)
        is_prog = (data[:2] == b"MZ" and b"PE\x00\x00" in data[:1024]) or data[:4] == b"\x7fELF"
        if ext in NOT_EXEC_EXT and is_prog:
            flag("disguised_executable", f"named {ext} but is a program")

    # ------------------------------------------------------------ programs
    @staticmethod
    def _pe_checks(pe: dict, data: bytes, flag) -> None:
        packers = sorted({_PACKERS[n] for n in pe["raw_section_names"] if n in _PACKERS})
        if packers:
            flag("packer_section", ", ".join(packers))
        exec_secs = [s for s in pe["sections"] if s["executable"] and s["raw_size"] > 1024]
        hot = [s for s in exec_secs if s["entropy"] >= 7.2]
        if hot:
            flag("high_entropy_code", ", ".join(f"{s['name'] or '?'} {s['entropy']:.2f}" for s in hot[:4]))
        rwx = [s["name"] or "?" for s in pe["sections"] if s["executable"] and s["writable"]]
        if rwx:
            flag("rwx_section", ", ".join(rwx[:4]))
        if pe["sections"] and pe["entry_point"] and not pe["dll"] and \
                (not pe["entry_section_executable"] or pe["entry_in_last_section"]) and not pe["dotnet"]:
            flag("entry_outside_code", pe["entry_section"] or "outside every section")
        funcs = {f.lower() for fs in pe["imports"].values() for f in fs if f and not f.startswith("#")}
        if not pe["dotnet"] and not pe["dll"]:
            if pe["import_count"] <= 4 and pe["sections"]:
                flag("few_imports", f"{pe['import_count']} imported function(s)")
            if funcs and funcs <= {"loadlibrarya", "loadlibraryw", "getprocaddress", "loadlibraryexa",
                                   "loadlibraryexw", "virtualprotect", "virtualalloc", "exitprocess",
                                   "getmodulehandlea", "getmodulehandlew"} and \
                    {"getprocaddress"} <= funcs:
                flag("dynamic_loader_only")
        if all(funcs & g for g in _INJECTION):
            flag("injection_apis", ", ".join(sorted(funcs & set().union(*_INJECTION))[:6]))
        if all(funcs & g for g in _KEYLOG):
            flag("keylogger_apis", ", ".join(sorted(funcs & set().union(*_KEYLOG))[:6]))
        if all(funcs & g for g in _DOWNLOAD):
            flag("downloader_apis", ", ".join(sorted(funcs & set().union(*_DOWNLOAD))[:6]))
        if len(funcs & _ANTIDEBUG) >= 2:
            flag("anti_debug", ", ".join(sorted(funcs & _ANTIDEBUG)))
        if pe["overlay_size"] > 64 * 1024 and pe["overlay_size"] > len(data) * 0.5:
            ov = data[pe["overlay_offset"]:pe["overlay_offset"] + 4 * 1024 * 1024]
            e = entropy(ov)
            if e >= 7.5:
                flag("overlay_high_entropy", f"{pe['overlay_size']:,} bytes, entropy {e:.2f}")
        now = datetime.now(timezone.utc).timestamp()
        if pe["timestamp"] == 0 or pe["timestamp"] > now + 86400 * 2:
            if not pe["dotnet"]:                                    # reproducible builds hash the stamp
                flag("bad_timestamp")
        if pe["has_certificate"]:
            flag("embedded_signature")

    # ------------------------------------------------------------ scripts
    @staticmethod
    def _script_checks(data: bytes, name: str, flag) -> None:
        text = data[:8 * 1024 * 1024]
        ext = _ext(name)
        kb = max(1.0, len(text) / 1024)
        # Large web bundles (minified libraries) legitimately use eval, char codes and fetch - only the
        # high-signal checks apply to them. Real script droppers are small.
        bundle = ext in (".js", ".mjs", ".cjs") and len(data) > 512 * 1024
        if not bundle:
            m = _B64.search(text)
            if m:
                flag("script_long_base64", f"{len(m.group(0)):,} characters")
            n = len(_CHARCODE.findall(text))
            if n >= 20 and n / kb >= 0.5:                               # density, not just a count
                flag("script_char_codes", f"{n} occurrences")
            n = len(_CONCAT.findall(text))
            if n >= 40 and n / kb >= 2:
                flag("script_concat", f"{n} string splits")
        if ext not in (".js", ".py", ".php") and any(len(line) > 4000 for line in text.splitlines()[:5000]):
            flag("script_long_line")
        python = ext == ".py" or (text[:2] == b"#!" and b"python" in text[:80])
        dyn = None if (bundle or python) else _DYN_EXEC.search(text)        # eval() is everyday Python
        if dyn:
            flag("script_dynamic_exec", dyn.group(0)[:40].decode("latin-1"))
        if not bundle and _DL.search(text) and _RUN.search(text):
            flag("script_download_exec")
        m = _AV.search(text)
        if m:
            flag("script_av_tamper", m.group(0)[:60].decode("latin-1"))
        m = _BACKUP.search(text)
        if m:
            flag("script_backup_delete", m.group(0)[:60].decode("latin-1"))
        if _HIDDEN.search(text):
            flag("script_hidden")
        if len(text) > 2048 and not bundle:
            e = entropy(text[:1024 * 1024])
            if e >= 5.9:
                flag("script_high_entropy", f"{e:.2f} bits/byte")

    # ------------------------------------------------------------ documents
    @staticmethod
    def _office_checks(data: bytes, kind: str, flag) -> None:
        vba = b""
        if kind == "ooxml":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    names = z.namelist()
                    for n in names:
                        low = n.lower()
                        if low.endswith("vbaproject.bin"):
                            info = z.getinfo(n)
                            if info.file_size <= 32 * 1024 * 1024:
                                vba += z.read(n)
                        elif low.endswith(".rels") and "settings" in low or low.endswith("document.xml.rels"):
                            info = z.getinfo(n)
                            if info.file_size <= 2 * 1024 * 1024:
                                rel = z.read(n)
                                if re.search(rb'attachedTemplate"[^>]{0,300}Target="(https?|\\\\|file:)', rel, re.I) or \
                                        re.search(rb'Target="(https?|\\\\|file:)[^"]{0,300}"[^>]{0,200}attachedTemplate',
                                                  rel, re.I):
                                    flag("office_remote_template")
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, KeyError):
                return
        else:
            if b"_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T" in data or b"\x00Attribut\x00e " in data:
                vba = data
        if not vba:
            return
        flag("office_macros")
        m = _AUTOEXEC.search(vba)
        if m:
            flag("office_autoexec", m.group(0).decode("latin-1"))
        m = _MACRO_EXEC.search(vba)
        if m:
            flag("office_macro_exec", m.group(0).decode("latin-1"))

    @staticmethod
    def _pdf_checks(data: bytes, flag) -> None:
        body = data[:16 * 1024 * 1024]
        js = re.search(rb"/(JavaScript|JS)\b", body)
        auto = re.search(rb"/(OpenAction|AA)\b", body)
        if js and auto:
            flag("pdf_autorun_js")
        if re.search(rb"/Launch\b", body) and re.search(rb"\.(exe|bat|cmd|vbs|js|ps1|hta|scr)\b|cmd\.exe|powershell",
                                                       body, re.I):
            flag("pdf_launch")

    # ------------------------------------------------------------ shortcuts
    @staticmethod
    def _lnk_strings(data: bytes) -> str:
        text = data[:256 * 1024]
        out = [m.decode("latin-1") for m in re.findall(rb"[\x20-\x7e]{4,}", text)]
        out += [m.decode("utf-16le", "ignore") for m in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", text)]
        return "\n".join(out)

    def _lnk_checks(self, data: bytes, flag) -> None:
        strings = self._lnk_strings(data)
        hosts = sorted({m.lower() for m in _SCRIPT_HOSTS.findall(strings)})
        longest = max((len(s) for s in strings.split("\n")), default=0)
        args_like = re.search(r"(\s-[a-z]{1,20}\s|/c\s|https?://|javascript:|vbscript:|iex|hidden|bypass)", strings,
                              re.I)
        if hosts and args_like:
            flag("lnk_script_host", ", ".join(hosts[:4]))
        if longest > 260:
            flag("lnk_long_args", f"{longest} characters")
        if len(data) > 0x3C + 4 and struct.unpack_from("<I", data, 0x3C)[0] in (2, 7):
            if hosts:
                flag("lnk_hidden")

    @staticmethod
    def _url_checks(data: bytes, flag) -> None:
        text = data[:64 * 1024].decode("latin-1", "replace")
        m = re.search(r"^\s*URL\s*=\s*(.+)$", text, re.I | re.M)
        if m:
            url = m.group(1).strip()
            if re.match(r"(file:|\\\\)", url, re.I) and re.search(r"\.(exe|scr|bat|cmd|hta|js|vbs|ps1|lnk|cpl|msi)\b",
                                                                  url, re.I):
                flag("url_remote_exec", url[:120])

    # ------------------------------------------------------------ archives
    @staticmethod
    def _zip_checks(data: bytes, flag) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = [i for i in z.infolist()[:5000] if not i.is_dir()]
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError):
            return
        execs = [i for i in infos if _ext(i.filename) in EXEC_EXT]
        enc = [i.filename for i in execs if i.flag_bits & 0x1]
        if enc:
            flag("archive_encrypted_exec", ", ".join(enc[:3]))
        for i in infos:
            parts = os.path.basename(i.filename).lower().split(".")
            if len(parts) >= 3 and "." + parts[-1].strip() in EXEC_EXT and "." + parts[-2].strip() in DOC_EXT:
                flag("archive_double_extension", i.filename[:120])
                break
            if _BIDI.search(i.filename):
                flag("archive_double_extension", repr(i.filename[:120]))
                break
        if len(infos) == 1 and execs and _ext(infos[0].filename) not in (".dll", ".sys", ".inf", ".reg"):
            flag("archive_single_exec", infos[0].filename[:120])

    # ------------------------------------------------------------ web pages
    @staticmethod
    def _html_checks(data: bytes, flag) -> None:
        body = data[:32 * 1024 * 1024]
        blob = re.search(rb"new\s+Blob\s*\(|msSaveOrOpenBlob", body)
        save = re.search(rb"msSaveOrOpenBlob|\.download\s*=", body)
        decode = re.search(rb"atob\s*\(|Uint8Array|charCodeAt|fromCharCode", body)
        big = re.search(rb"[A-Za-z0-9+/]{4000,}", body)
        if blob and save and decode and big:
            flag("html_smuggling", f"{len(big.group(0)):,}-character encoded payload")
