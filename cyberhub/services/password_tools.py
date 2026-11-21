"""
Cyber Hub Backend - Password tools (Part 12)
Developed by Syed Muhammad Tayyab

Stateless helpers used by the password vault and by the "check a password"
tool. Nothing here stores or logs a password.

* generate()  - random passwords, EFF-wordlist passphrases and PINs from the
                OS CSPRNG (secrets), with the exact entropy of what was asked.
* strength()  - zxcvbn (Dropbox's realistic estimator: dictionaries, l33t,
                keyboard walks, dates, repeats) + a regional word list
                (Pakistani cities, names, cricket...) and the user's own
                inputs (username, site, title). Falls back to the Part 2
                meter if zxcvbn is not installed, so nothing breaks.
* TOTP        - RFC 6238 codes from a base32 secret or an otpauth:// URI.
* BreachChecker - Have I Been Pwned "Pwned Passwords" with k-anonymity: only
                the first 5 hex characters of the SHA-1 leave the PC, the
                answer is padded (Add-Padding) so its size reveals nothing,
                and the match is done locally.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import secrets
import struct
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from pathlib import Path

from . import passwords as basic_meter

try:                                                    # pure-Python, MIT licence - see requirements.txt
    from zxcvbn import zxcvbn as _zxcvbn
except Exception:                                       # pragma: no cover - fallback path tested by monkeypatch
    _zxcvbn = None

LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
ZXCVBN_MAX = 72

# Words people in Pakistan commonly build passwords from. zxcvbn ranks them like a small dictionary,
# so "Lahore@786" or "Babar56!" are recognised instead of looking random.
REGIONAL_WORDS = [
    "pakistan", "pakistani", "islamabad", "karachi", "lahore", "rawalpindi", "peshawar", "quetta", "multan",
    "faisalabad", "sialkot", "hyderabad", "gujranwala", "bahawalpur", "sargodha", "abbottabad", "murree",
    "swat", "gilgit", "skardu", "hunza", "sukkur", "larkana", "mardan", "kashmir", "punjab", "sindh",
    "balochistan", "saraiki", "urdu", "allah", "bismillah", "mashallah", "inshallah", "alhamdulillah",
    "subhanallah", "786", "92", "0300", "jazz", "zong", "telenor", "ufone", "muhammad", "mohammad",
    "muhammed", "ahmed", "ahmad", "ali", "hassan", "hussain", "husain", "usman", "umar", "omar", "bilal",
    "hamza", "zain", "zainab", "fatima", "ayesha", "aisha", "maryam", "khadija", "sana", "hina", "sara",
    "iqra", "noor", "khan", "malik", "butt", "qureshi", "sheikh", "chaudhry", "chaudhary", "syed", "shah",
    "rana", "raja", "abbasi", "awan", "jutt", "rajput", "baloch", "mughal", "tayyab", "imran", "babar",
    "shaheen", "rizwan", "afridi", "wasim", "shoaib", "cricket", "pakarmy", "pti", "pmln", "ppp",
    "biryani", "nihari", "jinnah", "quaid", "iqbal", "azadi", "jashn", "eid", "ramzan", "ramadan",
]

AMBIGUOUS = set("Il1O0o|`'\";:,.")
SETS = {
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    "symbols": "!@#$%^&*()-_=+[]{};:,.?/~",
}
_WORDS: list[str] | None = None
_WORDS_LOCK = threading.Lock()
WORDLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "eff_large_wordlist.txt"


class ToolError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def normalize(pw: str) -> str:
    """NFC so the same password typed on two keyboards is the same bytes."""
    return unicodedata.normalize("NFC", pw)


# ====================================================================== generator
def wordlist() -> list[str]:
    """EFF large wordlist (CC BY 3.0 US, Electronic Frontier Foundation): 7,772 words = 12.9 bits each (the 4
    hyphenated ones such as t-shirt are skipped so a "-" separator stays unambiguous)."""
    global _WORDS
    with _WORDS_LOCK:
        if _WORDS is None:
            words = []
            for line in WORDLIST_PATH.read_text(encoding="utf-8").splitlines():
                w = line.strip().split()[-1] if line.strip() else ""
                if w.isalpha():
                    words.append(w.lower())
            if len(set(words)) < 7000:                                   # damaged package data
                raise ToolError(500, "Passphrase word list is damaged - reinstall Cyber Hub")
            _WORDS = sorted(set(words))
        return _WORDS


def _pool(opts: dict) -> dict[str, str]:
    excl = set(opts.get("exclude") or "")
    if opts.get("avoid_ambiguous", True):
        excl |= AMBIGUOUS
    out = {}
    for name, chars in SETS.items():
        if opts.get(name, True):
            kept = "".join(c for c in chars if c not in excl)
            if kept:
                out[name] = kept
    return out


def generate(mode: str = "password", **opts) -> dict:
    """mode password: length 4-128, lower / upper / digits / symbols, avoid_ambiguous, exclude, min_digits,
    min_symbols. mode passphrase: words 3-20, separator, capitalize, include_number. mode pin: length 4-12."""
    rnd = secrets.SystemRandom()
    if mode == "pin":
        n = int(opts.get("length") or 6)
        if not 4 <= n <= 12:
            raise ToolError(422, "PIN length must be 4-12")
        while True:
            pin = "".join(secrets.choice("0123456789") for _ in range(n))
            if len(set(pin)) > 1 and pin not in "01234567890123" and pin not in "98765432109876":
                break
        return {"mode": "pin", "password": pin, "length": n, "entropy_bits": round(n * math.log2(10), 1)}

    if mode == "passphrase":
        n = int(opts.get("words") or 5)
        if not 3 <= n <= 20:
            raise ToolError(422, "A passphrase needs 3-20 words")
        sep = opts.get("separator", "-")
        if sep is None or len(sep) > 3:
            raise ToolError(422, "Separator must be 0-3 characters")
        words = wordlist()
        chosen = [secrets.choice(words) for _ in range(n)]
        bits = n * math.log2(len(words))
        if opts.get("capitalize", True):
            chosen = [w.capitalize() for w in chosen]
        if opts.get("include_number", True):
            i = secrets.randbelow(n)
            chosen[i] += str(secrets.randbelow(10))
            bits += math.log2(10) + math.log2(n)
        pw = sep.join(chosen)
        return {"mode": "passphrase", "password": pw, "words": n, "length": len(pw),
                "entropy_bits": round(bits, 1)}

    if mode != "password":
        raise ToolError(422, "mode must be password, passphrase or pin")
    n = int(opts.get("length") or 20)
    if not 4 <= n <= 128:
        raise ToolError(422, "Length must be 4-128")
    pools = _pool(opts)
    if not pools:
        raise ToolError(422, "Choose at least one character type")
    mins = {"digits": int(opts.get("min_digits", 1) or 0), "symbols": int(opts.get("min_symbols", 1) or 0)}
    required: list[str] = []
    for name, chars in pools.items():
        k = max(1, mins.get(name, 1))
        required += [secrets.choice(chars) for _ in range(k)]
    if len(required) > n:
        raise ToolError(422, f"Length {n} is too short for the character types and minimums chosen")
    everything = "".join(pools.values())
    chars = required + [secrets.choice(everything) for _ in range(n - len(required))]
    rnd.shuffle(chars)
    return {"mode": "password", "password": "".join(chars), "length": n,
            "entropy_bits": round(n * math.log2(len(everything)), 1),
            "character_sets": sorted(pools)}


# ====================================================================== strength
def _fmt_seconds(s: float) -> str:
    if s < 1:
        return "instantly"
    for unit, size in (("century", 3153600000), ("year", 31536000), ("month", 2592000), ("day", 86400),
                       ("hour", 3600), ("minute", 60), ("second", 1)):
        if s >= size:
            v = int(s // size)
            if unit == "century" and v >= 100:
                return "centuries"
            plural = "centuries" if unit == "century" else unit + "s"
            return f"{v} {unit if v == 1 else plural}"
    return "instantly"                                                   # pragma: no cover


def strength(password: str, user_inputs: list[str] | tuple = ()) -> dict:
    """Realistic strength: score 0-4, label, guesses (log10), time to crack for 4 attack speeds, warning and
    suggestions. user_inputs = words the password should not contain (username, site, title, e-mail)."""
    password = normalize(password or "")
    inputs = [str(x).lower() for x in user_inputs if x and len(str(x)) >= 3][:30]
    for x in list(inputs):                                     # e-mail -> its parts, site -> its name
        if "@" in x:
            inputs += [p for p in x.replace(".", "@").split("@") if len(p) >= 3]
        if "." in x and "@" not in x:
            inputs += [p for p in x.replace("www.", "").split(".") if len(p) >= 3]
    if not password:
        return {"score": 0, "label": LABELS[0], "length": 0, "guesses_log10": 0.0, "entropy_bits": 0.0,
                "crack_times": {}, "warning": "Enter a password.", "suggestions": [], "engine": "none"}
    if _zxcvbn is None:
        b = basic_meter.strength(password, inputs[0] if inputs else None)
        g10 = round(b["entropy_bits"] * math.log10(2), 2)
        engine, score, warning, sugg = "basic", b["score"], (b["feedback"][0] if b["feedback"] else ""), b["feedback"][1:]
        core = "".join(ch for ch in password.lower() if ch.isalpha())
        if score > 1 and (core in basic_meter.COMMON or core in REGIONAL_WORDS or any(core == x for x in inputs)) \
                and len(password) - len(core) <= 6:
            score, warning = 1, "A common word with a few numbers or symbols added is easy to guess."
            g10 = min(g10, 5.0)
    else:
        head = password[:ZXCVBN_MAX]
        r = _zxcvbn(head, user_inputs=inputs + REGIONAL_WORDS)
        g10 = float(r["guesses_log10"])
        if len(password) > ZXCVBN_MAX:                          # the rest only adds guesses
            g10 += (len(password) - ZXCVBN_MAX) * math.log10(26)
        score = int(r["score"])
        if g10 >= 10 and score < 4:
            score = 4
        warning, sugg, engine = r["feedback"].get("warning") or "", list(r["feedback"].get("suggestions") or []), "zxcvbn"
        hit = sorted({m["matched_word"] for m in r["sequence"]
                      if m.get("pattern") == "dictionary" and m.get("dictionary_name") == "user_inputs"
                      and len(m.get("matched_word", "")) >= 3})
        if hit and not warning:
            warning = "Contains a word that is easy to guess for someone who knows you or the site."
        # "Word + a few digits / symbols" (Pakistan@123, Lahore786!, Password1) is the first rule every cracking
        # tool applies - cap it at Weak whatever the raw estimate says.
        words = [m for m in r["sequence"] if m.get("pattern") == "dictionary" and m.get("rank", 10 ** 9) <= 20000]
        if len(words) == 1 and len(head) <= 20:
            tok = words[0]["token"]
            rest = head.replace(tok, "", 1)
            if len(tok) >= 4 and len(rest) <= 6 and all(not ch.isalpha() for ch in rest) and score > 1:
                score = 1
                warning = ("A common word with a few numbers or symbols added is one of the first things "
                           "password crackers try.")
    guesses = 10 ** g10
    times = {"online_throttled": guesses / (100 / 3600), "online": guesses / 10,
             "offline_slow": guesses / 1e4, "offline_fast": guesses / 1e10}
    if len(password) < 12 and score >= 3:
        sugg = ["Use 12 or more characters for important accounts."] + sugg
    return {"score": score, "label": LABELS[score], "length": len(password), "guesses_log10": round(g10, 2),
            "entropy_bits": round(g10 * math.log2(10), 1),
            "crack_times": {k: {"seconds": round(v, 3) if v < 1e15 else 1e15, "display": _fmt_seconds(v)}
                            for k, v in times.items()},
            "warning": warning, "suggestions": sugg[:4], "engine": engine}


# ====================================================================== TOTP (RFC 6238)
TOTP_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def _b32(secret: str) -> bytes:
    s = "".join(secret.split()).replace("-", "").upper().rstrip("=")
    if not s or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in s):
        raise ToolError(422, "The 2FA secret must be base32 (letters A-Z and digits 2-7)")
    try:
        key = base64.b32decode(s + "=" * (-len(s) % 8))
    except Exception as e:
        raise ToolError(422, "The 2FA secret is not valid base32") from e
    if len(key) < 10:
        raise ToolError(422, "The 2FA secret is too short (needs 80 bits or more)")
    return key


def parse_totp(value: str) -> dict:
    """A base32 secret or an otpauth://totp/Issuer:account?secret=...&digits=6&period=30&algorithm=SHA1 URI."""
    value = (value or "").strip()
    if not value:
        raise ToolError(422, "Empty 2FA secret")
    if value.lower().startswith("otpauth://"):
        u = urllib.parse.urlparse(value)
        if u.netloc.lower() != "totp":
            raise ToolError(422, "Only time-based (TOTP) codes are supported")
        q = {k.lower(): v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        label = urllib.parse.unquote(u.path.lstrip("/"))
        issuer = q.get("issuer") or (label.split(":", 1)[0] if ":" in label else None)
        cfg = {"secret": q.get("secret", ""), "issuer": issuer, "account": label.split(":", 1)[-1] or None,
               "digits": int(q.get("digits", 6)) if str(q.get("digits", 6)).isdigit() else 0,
               "period": int(q.get("period", 30)) if str(q.get("period", 30)).isdigit() else 0,
               "algorithm": q.get("algorithm", "SHA1").upper()}
    else:
        cfg = {"secret": value, "issuer": None, "account": None, "digits": 6, "period": 30, "algorithm": "SHA1"}
    if cfg["digits"] not in (6, 7, 8):
        raise ToolError(422, "2FA codes must have 6-8 digits")
    if not 15 <= cfg["period"] <= 300:
        raise ToolError(422, "2FA period must be 15-300 seconds")
    if cfg["algorithm"] not in TOTP_ALGOS:
        raise ToolError(422, "2FA algorithm must be SHA1, SHA256 or SHA512")
    cfg["key"] = _b32(cfg["secret"])
    return cfg


def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), TOTP_ALGOS[algorithm]).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(value: str, at: float | None = None) -> dict:
    cfg = parse_totp(value)
    t = time.time() if at is None else at
    step = int(t // cfg["period"])
    return {"code": hotp(cfg["key"], step, cfg["digits"], cfg["algorithm"]), "period": cfg["period"],
            "remaining": cfg["period"] - int(t % cfg["period"]), "digits": cfg["digits"],
            "algorithm": cfg["algorithm"], "issuer": cfg["issuer"], "account": cfg["account"]}


# ====================================================================== Have I Been Pwned (k-anonymity)
HIBP_URL = "https://api.pwnedpasswords.com/range/{}"
USER_AGENT = "CyberHub/0.12 (+local security app)"


def urllib_transport(method: str, url: str, headers: dict, data: bytes | None, timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:                  # nosec - fixed https URL
            return r.status, r.read(8 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        return e.code, b""


class BreachChecker:
    """Pwned Passwords range API. Only SHA-1[:5] is sent; responses (public data) are cached for an hour."""

    def __init__(self, transport=None, cache_size: int = 512, ttl: float = 3600):
        self.transport = transport or urllib_transport          # tests swap this for a fake
        self.timeout = 15.0
        self._cache: OrderedDict[str, tuple[float, dict[str, int]]] = OrderedDict()
        self._lock = threading.Lock()
        self.cache_size, self.ttl = cache_size, ttl
        self.requests = 0

    @staticmethod
    def sha1(password: str) -> str:
        return hashlib.sha1(normalize(password).encode("utf-8")).hexdigest().upper()   # nosec - HIBP's format

    def _range(self, prefix: str) -> dict[str, int]:
        with self._lock:
            hit = self._cache.get(prefix)
            if hit and time.monotonic() - hit[0] < self.ttl:
                self._cache.move_to_end(prefix)
                return hit[1]
        try:
            status, body = self.transport("GET", HIBP_URL.format(prefix), {"Add-Padding": "true"}, None,
                                          self.timeout)
        except (OSError, ValueError) as e:
            raise ToolError(502, f"Couldn't reach Have I Been Pwned ({type(e).__name__}) - check the "
                                 "internet connection") from e
        self.requests += 1
        if status == 429:
            raise ToolError(429, "Have I Been Pwned asked us to slow down - try again in a minute")
        if status != 200:
            raise ToolError(502, f"Have I Been Pwned answered HTTP {status}")
        out: dict[str, int] = {}
        for line in body.decode("ascii", "replace").splitlines():
            suffix, _, n = line.strip().partition(":")
            if len(suffix) == 35 and n.strip().isdigit() and int(n) > 0:        # count 0 = padding
                out[suffix.upper()] = int(n)
        with self._lock:
            self._cache[prefix] = (time.monotonic(), out)
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)
        return out

    def check_sha1(self, sha1_hex: str) -> int:
        h = sha1_hex.upper()
        if len(h) != 40 or any(c not in "0123456789ABCDEF" for c in h):
            raise ToolError(422, "Not a SHA-1 hash")
        return self._range(h[:5]).get(h[5:], 0)

    def check(self, password: str) -> int:
        """How many times this password appears in known breaches (0 = not found)."""
        return self.check_sha1(self.sha1(password))
