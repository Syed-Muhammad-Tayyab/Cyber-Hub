"""
Cyber Hub Backend - Sensitive-file finder detectors (Part 13)
Developed by Syed Muhammad Tayyab

Finds files that hold data a thief would want, so the user can encrypt or
shred them. Everything runs on this PC; matches are stored MASKED only
(4111 •••• •••• 1111, 35•••-•••••••-1) - never the full value.

Detectors (each explainable, with validation to keep false positives down):
    private_key       PEM / OpenSSH / PGP private keys, PuTTY .ppk, .pfx / .p12 bundles     critical
    password_export   CSV exports from password managers / browsers (header check)          critical
    api_key           AWS, GitHub, Slack, Stripe, Google, OpenAI keys + "api_key = ..."    high / medium
    password          "password: xyz" / "pwd=xyz" written in a file (placeholders ignored)  high
    credit_card       13-19 digits, known brand prefix + Luhn check                        high
    cnic              Pakistani CNIC 12345-1234567-1 (or 13 digits next to "CNIC")          high
    iban              IBAN with the ISO 7064 mod-97 check (PK, AE, SA, GB, DE ...)          medium
    ssn               US Social Security numbers next to "SSN"                             medium
    crypto_wallet     wallet.dat / *.wallet files                                          high
    contacts          10+ e-mail addresses or Pakistani mobile numbers in one file         low

Text is read from plain-text files, Office Open XML (.docx / .xlsx / .pptx),
OpenDocument (.odt / .ods / .odp), RTF and - best effort - PDF text streams.
"""
from __future__ import annotations

import io
import os
import re
import zipfile
import zlib
from typing import Callable

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DETECTORS = {
    "private_key": ("Private keys", "critical"),
    "password_export": ("Password export (plain text)", "critical"),
    "api_key": ("API keys & tokens", "high"),
    "password": ("Passwords written in files", "high"),
    "credit_card": ("Card numbers", "high"),
    "cnic": ("CNIC numbers", "high"),
    "iban": ("Bank account (IBAN)", "medium"),
    "ssn": ("US Social Security numbers", "medium"),
    "crypto_wallet": ("Crypto wallets", "high"),
    "contacts": ("Contact lists (e-mails / phones)", "low"),
}
ADVICE = {
    "private_key": "Anyone with this file can sign in as you (SSH / servers / code signing). Encrypt it, or keep it "
                   "only where it is needed with a passphrase.",
    "password_export": "A plain-text password export. Import it into the Password Vault (Part 12), then shred it.",
    "api_key": "Keys in files leak through backups, chats and Git. Move them to environment variables or a vault and "
               "rotate any key that was ever shared.",
    "password": "Passwords saved in a document. Move them into the Password Vault and shred this file.",
    "credit_card": "Card numbers. Encrypt this file, or shred it if you no longer need it.",
    "cnic": "CNIC numbers are used for SIM, bank and identity fraud. Encrypt this file.",
    "iban": "Bank account numbers. Encrypt this file if it is not meant to be shared.",
    "ssn": "Social Security numbers. Encrypt this file.",
    "crypto_wallet": "A cryptocurrency wallet file. Make sure it has a strong wallet password, keep an encrypted backup.",
    "contacts": "Lots of personal contact details. Encrypt it if it is a customer / student list.",
}

TEXT_EXT = {".txt", ".csv", ".tsv", ".md", ".log", ".json", ".xml", ".yml", ".yaml", ".ini", ".cfg", ".conf",
            ".config", ".env", ".properties", ".toml", ".sql", ".ps1", ".bat", ".cmd", ".sh", ".py", ".js", ".ts",
            ".php", ".rb", ".java", ".cs", ".go", ".html", ".htm", ".vcf", ".pem", ".key", ".crt", ".ppk", ".ovpn",
            ".rdp", ".reg", ".tex", ".rtf", ".npmrc", ".pypirc", ".netrc", ".gitconfig", ".pgpass", ".asc"}
OOXML = {".docx": ("word/document.xml", "word/header", "word/footer"),
         ".xlsx": ("xl/sharedStrings.xml", "xl/worksheets/sheet"),
         ".pptx": ("ppt/slides/slide", "ppt/notesSlides/")}
ODF = {".odt", ".ods", ".odp"}
NAME_ONLY = {".pfx": "private_key", ".p12": "private_key", ".ppk": "private_key"}
KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".env", ".npmrc", ".pypirc", ".netrc", ".pgpass"}
WALLET_NAMES = {"wallet.dat"}
SKIP_EXT = {".chx", ".chq", ".chvault", ".kdbx"}       # already encrypted
MAX_TEXT = 8 * 1024 * 1024                            # characters examined per file

# ---------------------------------------------------------------- patterns
RE_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")
RE_PPK = re.compile(r"^PuTTY-User-Key-File-\d", re.M)
API_PATTERNS = [
    ("AWS access key", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", "high", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b")),
    ("Slack token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", "critical", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b")),
    ("Google API key", "medium", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("OpenAI key", "high", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("Secret in config", "medium", re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[\"']?\s*[:=]"
        r"\s*[\"']?([A-Za-z0-9_\-\.\/+]{16,})")),
]
RE_PASSWORD = re.compile(r"(?i)\b(?:password|passwd|pass|pwd|passcode|pin\s*code)\b\s*[\"']?\s*(?:[:=]|is\b)\s*"
                         r"[\"']?([^\s\"',;<>]{4,64})")
PLACEHOLDERS = {"****", "*****", "******", "********", "xxxx", "xxxxx", "xxxxxx", "xxxxxxxx", "none", "null", "nil",
                "true", "false", "password", "your_password", "yourpassword", "<password>", "string", "required",
                "optional", "hidden", "redacted", "example", "secret", "changeit", "undefined", "empty", "self",
                "this", "value", "input", "text", "field", "type", "length"}
RE_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
RE_CNIC = re.compile(r"(?<![\d-])([1-7]\d{4})-(\d{7})-(\d)(?![\d-])")
RE_CNIC13 = re.compile(r"(?i)\b(?:cnic|nic|n\.i\.c|identity\s*card|shanakhti)\b[^0-9\n]{0,25}([1-7]\d{12})(?!\d)")
RE_IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?)\b")
IBAN_LEN = {"PK": 24, "AE": 23, "SA": 24, "GB": 22, "DE": 22, "FR": 27, "IT": 27, "ES": 24, "NL": 18, "QA": 29,
            "KW": 30, "BH": 22, "OM": 23, "TR": 26, "BE": 16, "CH": 21, "AT": 20, "IE": 22, "SE": 24, "NO": 15,
            "DK": 18, "PL": 28, "PT": 25, "JO": 30, "EG": 29, "LU": 20, "FI": 18}
RE_SSN = re.compile(r"(?i)\b(?:ssn|social\s+security(?:\s+(?:no|number|#))?)\b[^0-9\n]{0,20}"
                    r"((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,200}\.[A-Za-z]{2,24}\b")
RE_PK_PHONE = re.compile(r"(?<!\d)(?:\+92|0092|0)[ -]?3\d{2}[ -]?\d{7}(?!\d)")
CARD_PREFIXES = (("Visa", ("4",), (13, 16, 19)), ("Mastercard", tuple(str(i) for i in range(51, 56)) +
                 tuple(str(i) for i in range(2221, 2721)), (16,)), ("American Express", ("34", "37"), (15,)),
                 ("UnionPay", ("62",), (16, 17, 18, 19)), ("Discover", ("6011", "65"), (16, 19)),
                 ("JCB", tuple(str(i) for i in range(3528, 3590)), (16, 17, 18, 19)),
                 ("Diners Club", ("36", "38", "300", "301", "302", "303", "304", "305"), (14, 16)),
                 ("PayPak", ("220",), (16,)))
TEST_CARDS = {"4111111111111111", "4242424242424242", "5555555555554444", "378282246310005", "4012888888881881",
              "5105105105105100", "6011111111111117"}


def luhn(d: str) -> bool:
    s, alt = 0, False
    for ch in reversed(d):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        s += n
        alt = not alt
    return s % 10 == 0


def card_brand(d: str) -> str | None:
    for name, prefixes, lengths in CARD_PREFIXES:
        if len(d) in lengths and d.startswith(prefixes):
            return name
    return None


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "")
    if IBAN_LEN.get(s[:2]) != len(s):
        return False
    r = s[4:] + s[:4]
    num = "".join(str(int(ch, 36)) for ch in r)
    return int(num) % 97 == 1


# ---------------------------------------------------------------- masking
def mask_card(d: str) -> str:
    return "•••• " * ((len(d) - 4 + 3) // 4) + d[-4:]


def mask_cnic(a: str, b: str, c: str) -> str:
    return f"{a[:2]}•••-•••••••-{c}"


def mask_mid(s: str, keep_start: int = 4, keep_end: int = 2) -> str:
    if len(s) <= keep_start + keep_end + 2:
        return s[:1] + "•" * max(3, len(s) - 1)
    return s[:keep_start] + "…" + "•" * 4 + s[-keep_end:]


def mask_email(e: str) -> str:
    user, _, dom = e.partition("@")
    return (user[:1] + "•••@" + dom) if dom else "•••"


def mask_phone(p: str) -> str:
    d = re.sub(r"\D", "", p)
    return f"{'+92' if d.startswith('92') else '0'}3•• •••••{d[-2:]}"


# ---------------------------------------------------------------- text extraction
def _strip_xml(b: bytes) -> str:
    t = b.decode("utf-8", "replace")
    t = re.sub(r"</w:p>|</a:p>|</text:p>|<w:tab/>|</row>|<br\s*/?>", "\n", t)
    t = re.sub(r"</c>|</si>|</t>", " ", t)
    t = re.sub(r"<[^>]+>", "", t)
    return (t.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
            .replace("&apos;", "'"))


def _zip_text(data: bytes, prefixes: tuple[str, ...]) -> str:
    out, total = [], 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if not info.filename.startswith(prefixes) or not info.filename.endswith(".xml"):
                    continue
                if info.file_size > 64 * 1024 * 1024 or total > MAX_TEXT * 2:      # zip-bomb guard
                    continue
                with z.open(info) as f:
                    b = f.read(min(info.file_size, MAX_TEXT * 2))
                total += len(b)
                out.append(_strip_xml(b))
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError):
        return ""
    return "\n".join(out)


def _pdf_text(data: bytes) -> str:
    """Best effort: inflate FlateDecode streams and pull out (text) Tj / [(..)] TJ strings."""
    out, total = [], 0
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        raw = m.group(1)
        try:
            raw = zlib.decompressobj().decompress(raw, MAX_TEXT)
        except zlib.error:
            pass
        for s in re.findall(rb"\(((?:\\.|[^\\)])*)\)", raw):
            out.append(s.replace(b"\\(", b"(").replace(b"\\)", b")").decode("latin-1", "replace"))
            total += len(s)
        out.append("\n")
        if total > MAX_TEXT:
            break
    return "".join(out)


def _decode_text(b: bytes) -> str | None:
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    if b"\x00" in b[:4096]:
        return None                                           # binary
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("cp1252", "replace")


def extract_text(path: str, max_bytes: int) -> tuple[str | None, str]:
    """(text or None, how). Reads at most max_bytes of the file."""
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    try:
        size = os.path.getsize(path)
        if ext in OOXML or ext in ODF:
            if size > max_bytes:
                return None, "too_large"
            with open(path, "rb") as f:
                data = f.read()
            pre = OOXML.get(ext, ("content.xml",))
            return _zip_text(data, pre), "office"
        if ext == ".pdf":
            with open(path, "rb") as f:
                data = f.read(max_bytes)
            return _pdf_text(data), "pdf"
        if ext in TEXT_EXT or name in KEY_NAMES or ext == "" and size < 1024 * 1024:
            with open(path, "rb") as f:
                data = f.read(max_bytes)
            t = _decode_text(data)
            if t is not None and ext == ".rtf":
                t = re.sub(r"\\[a-z]+-?\d* ?|[{}]", " ", t)
            return t, "text"
    except OSError as e:
        return None, "error:" + type(e).__name__
    return None, "unsupported"


def candidate(path: str) -> bool:
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    if ext in SKIP_EXT:
        return False
    return (ext in TEXT_EXT or ext in OOXML or ext in ODF or ext == ".pdf" or ext in NAME_ONLY or
            name in KEY_NAMES or name in WALLET_NAMES or ext == ".wallet" or ext == "")


# ---------------------------------------------------------------- analysis
def _add(found: dict, kind: str, sample: str | None, severity: str | None = None, sub: str | None = None) -> None:
    f = found.setdefault(kind, {"count": 0, "samples": [], "severity": DETECTORS[kind][1], "kinds": []})
    f["count"] += 1
    if sample and len(f["samples"]) < 3 and sample not in f["samples"]:
        f["samples"].append(sample)
    if severity and SEV_ORDER[severity] > SEV_ORDER[f["severity"]]:
        f["severity"] = severity
    if sub and sub not in f["kinds"]:
        f["kinds"].append(sub)


def _is_password_export(text: str) -> bool:
    first = text.lstrip("\ufeff").split("\n", 1)[0].lower()
    cols = {c.strip().strip('"') for c in re.split(r"[,;\t]", first)}
    return "password" in cols and bool(cols & {"url", "username", "login_uri", "login_username", "name", "title",
                                               "web site", "website", "user name", "email"})


def analyze_text(text: str, types: set[str], name: str = "") -> dict:
    """{type: {count, samples[masked], severity, kinds[]}} for one file's text."""
    found: dict[str, dict] = {}
    text = text[:MAX_TEXT]
    low_name = name.lower()
    if "private_key" in types:
        for m in RE_PRIVATE_KEY.finditer(text):
            _add(found, "private_key", m.group(0).strip("-").title().replace("Begin ", ""))
        if RE_PPK.search(text):
            _add(found, "private_key", "PuTTY private key")
    if "password_export" in types and low_name.endswith((".csv", ".tsv", ".txt")) and _is_password_export(text):
        rows = max(0, text.count("\n") - 1)
        _add(found, "password_export", f"{rows} saved login(s)")
    if "api_key" in types:
        for label, sev, rx in API_PATTERNS:
            for m in rx.finditer(text):
                val = m.group(1) if m.groups() else m.group(0)
                if label == "Secret in config" and (val.lower() in PLACEHOLDERS or len(set(val)) < 6 or
                                                    val.startswith(("${", "process.env", "os.environ"))):
                    continue
                _add(found, "api_key", f"{label}: {mask_mid(val)}", sev, label)
    if "password" in types and "password_export" not in found:
        for m in RE_PASSWORD.finditer(text):
            v = m.group(1)
            vl = v.lower().strip("*")
            if (vl in PLACEHOLDERS or not vl or v.startswith(("$", "{", "%", "<", "(", "process.", "os.", "getenv"))
                    or len(set(v)) < 3 or v.endswith(("(", ")"))):
                continue
            _add(found, "password", f"password: {'•' * min(len(v), 8)} ({len(v)} characters)")
    if "credit_card" in types:
        for m in RE_CARD.finditer(text):
            raw = m.group(0)
            d = re.sub(r"[ -]", "", raw)
            if not 13 <= len(d) <= 19 or len(set(d)) < 2 or not luhn(d):
                continue
            seps = set(re.sub(r"\d", "", raw))
            if len(seps) > 1:
                continue
            brand = card_brand(d)
            if not brand:
                continue
            _add(found, "credit_card", f"{brand} {mask_card(d)}", "low" if d in TEST_CARDS else None,
                 "test card" if d in TEST_CARDS else brand)
        if "credit_card" in found and found["credit_card"]["kinds"] == ["test card"]:
            found["credit_card"]["severity"] = "low"
    if "cnic" in types:
        for m in RE_CNIC.finditer(text):
            _add(found, "cnic", mask_cnic(*m.groups()))
        for m in RE_CNIC13.finditer(text):
            d = m.group(1)
            _add(found, "cnic", mask_cnic(d[:5], d[5:12], d[12]))
    if "iban" in types:
        for m in RE_IBAN.finditer(text):
            s = m.group(1).replace(" ", "")
            if iban_ok(s):
                _add(found, "iban", f"{s[:4]} •••• •••• {s[-4:]}", sub=s[:2])
    if "ssn" in types:
        for m in RE_SSN.finditer(text):
            _add(found, "ssn", "•••-••-" + m.group(1)[-4:])
    if "contacts" in types:
        emails = {e.lower() for e in RE_EMAIL.findall(text[:2 * 1024 * 1024])}
        phones = {re.sub(r"\D", "", p)[-10:] for p in RE_PK_PHONE.findall(text[:2 * 1024 * 1024])}
        if len(emails) >= 10 or len(phones) >= 10:
            f = found.setdefault("contacts", {"count": 0, "samples": [], "severity": "low", "kinds": []})
            f["count"] = len(emails) + len(phones)
            f["samples"] = ([f"{len(emails)} e-mail addresses"] if emails else []) + \
                           ([f"{len(phones)} mobile numbers"] if phones else [])
            if len(emails) + len(phones) >= 500:
                f["severity"] = "medium"
    return found


def analyze_file(path: str, types: set[str], max_bytes: int,
                 extract: Callable[[str, int], tuple[str | None, str]] = extract_text) -> tuple[dict, str]:
    """({type: {...}}, how). Name-based detectors first, then content."""
    found: dict[str, dict] = {}
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    if ext in NAME_ONLY and NAME_ONLY[ext] in types:
        _add(found, NAME_ONLY[ext], {".pfx": "Certificate + private key (.pfx)", ".p12": "Certificate + private key (.p12)",
                                     ".ppk": "PuTTY private key"}[ext])
        if ext != ".ppk":
            return found, "name"
    if (name in WALLET_NAMES or ext == ".wallet") and "crypto_wallet" in types:
        _add(found, "crypto_wallet", name)
        return found, "name"
    text, how = extract(path, max_bytes)
    if text:
        for k, v in analyze_text(text, types, name).items():
            if k in found:
                found[k]["count"] += v["count"]
            else:
                found[k] = v
    return found, how


def summarize(found: dict) -> tuple[str, int]:
    """(worst severity, risk points) for one file."""
    if not found:
        return "info", 0
    sev = max((v["severity"] for v in found.values()), key=lambda s: SEV_ORDER[s])
    pts = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
    return sev, max(pts[v["severity"]] for v in found.values())
