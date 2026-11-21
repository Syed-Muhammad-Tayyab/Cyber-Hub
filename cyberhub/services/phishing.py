"""
Cyber Hub Backend - Phishing URL analysis (Part 15)
Developed by Syed Muhammad Tayyab

Explainable, offline checks of a URL / domain (no network needed):
  brand names in the wrong domain ("paypal.com.secure-login.xyz"), look-alike domains (paypa1.com, rnicrosoft,
  homoglyph / mixed-script IDNs), IP-address hosts, "@" tricks, URL shorteners, risky TLDs, dynamic DNS and free
  hosting, deep sub-domains, login / verify / wallet words, executables in the path, redirect parameters,
  encoded hosts, very long URLs, http:// for a login page.

Page checks (deep=True - Part 15's service fetches the page with Part 14's read-only web_probe Fetcher):
  password / card / OTP / CNIC forms, forms posting to another site, brand named in the title on a domain that
  isn't the brand's, assets copied from the real brand site, meta-refresh / JS redirects, obfuscated scripts,
  a brand-new certificate, a newly registered domain (RDAP).

Every finding = {code, severity, points, text}. score = min(100, sum of points), never a black box.
"""
from __future__ import annotations

import re
import unicodedata
import urllib.parse
from html.parser import HTMLParser

from . import ioc

# brand -> official registrable domains (Pakistani banks / wallets / government included)
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"), "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com",
                                                         "outlook.com", "office365.com", "sharepoint.com", "azure.com",
                                                         "windows.com", "xbox.com", "bing.com", "msn.com", "skype.com"),
    "office365": ("office.com", "office365.com", "microsoft.com"), "outlook": ("outlook.com", "live.com", "office.com"),
    "onedrive": ("live.com", "onedrive.com", "microsoft.com", "1drv.ms"),
    "apple": ("apple.com", "icloud.com", "apple.co"), "icloud": ("icloud.com", "apple.com"),
    "google": ("google.com", "gmail.com", "youtube.com", "goo.gl", "google.com.pk", "googleusercontent.com",
               "gstatic.com", "googleapis.com", "withgoogle.com", "blogger.com"),
    "gmail": ("gmail.com", "google.com"), "youtube": ("youtube.com", "youtu.be", "google.com"),
    "facebook": ("facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com", "fbcdn.net"),
    "instagram": ("instagram.com", "facebook.com", "meta.com"), "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me"),
    "meta": ("meta.com", "facebook.com"), "messenger": ("messenger.com", "facebook.com"),
    "linkedin": ("linkedin.com", "lnkd.in"), "twitter": ("twitter.com", "x.com", "t.co"),
    "tiktok": ("tiktok.com",), "snapchat": ("snapchat.com",), "telegram": ("telegram.org", "t.me", "telegram.me"),
    "netflix": ("netflix.com",), "spotify": ("spotify.com",), "amazon": ("amazon.com", "amazon.co.uk", "amazon.de",
                                                                       "amazon.in", "amazonaws.com", "aws.amazon.com", "a.co"),
    "ebay": ("ebay.com",), "aliexpress": ("aliexpress.com", "alibaba.com"), "daraz": ("daraz.pk", "daraz.com"),
    "dhl": ("dhl.com", "dhl.de"), "fedex": ("fedex.com",), "ups": ("ups.com",), "tcs": ("tcsexpress.com", "tcs.com.pk"),
    "leopards": ("leopardscourier.com",), "pakpost": ("pakpost.gov.pk",),
    "github": ("github.com", "github.io", "githubusercontent.com"), "gitlab": ("gitlab.com",),
    "dropbox": ("dropbox.com", "dropboxusercontent.com", "db.tt"), "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com",), "zoom": ("zoom.us", "zoom.com"), "steam": ("steampowered.com", "steamcommunity.com"),
    "discord": ("discord.com", "discord.gg", "discordapp.com"), "binance": ("binance.com",),
    "coinbase": ("coinbase.com",), "metamask": ("metamask.io",), "trustwallet": ("trustwallet.com",),
    "fiverr": ("fiverr.com",), "upwork": ("upwork.com",), "payoneer": ("payoneer.com",), "wise": ("wise.com",),
    "westernunion": ("westernunion.com",), "visa": ("visa.com",), "mastercard": ("mastercard.com",),
    "jazzcash": ("jazzcash.com.pk",), "easypaisa": ("easypaisa.com.pk",), "sadapay": ("sadapay.pk",),
    "nayapay": ("nayapay.com",), "hbl": ("hbl.com", "hbl.com.pk"), "meezan": ("meezanbank.com",),
    "meezanbank": ("meezanbank.com",), "ubl": ("ubldigital.com", "ubl.com.pk"), "mcb": ("mcb.com.pk",),
    "alliedbank": ("abl.com",), "bankalfalah": ("bankalfalah.com",), "askari": ("askaribank.com",),
    "faysalbank": ("faysalbank.com",), "bankislami": ("bankislami.com.pk",), "nbp": ("nbp.com.pk",),
    "sbp": ("sbp.org.pk",), "nadra": ("nadra.gov.pk",), "fbr": ("fbr.gov.pk",), "pta": ("pta.gov.pk",),
    "jazz": ("jazz.com.pk",), "telenor": ("telenor.com.pk", "telenor.com"), "zong": ("zong.com.pk",),
    "ptcl": ("ptcl.com.pk",), "chase": ("chase.com",), "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",), "hsbc": ("hsbc.com", "hsbc.co.uk"), "citibank": ("citi.com", "citibank.com"),
}
# short / generic brand words only count when they stand alone as a label (avoid "ups" in "groups")
WORD_ONLY = {"ups", "tcs", "hbl", "ubl", "mcb", "nbp", "sbp", "fbr", "pta", "visa", "wise", "meta", "zoom", "jazz",
             "zong", "ptcl", "chase", "steam", "apple", "amazon", "google"}

SUSPICIOUS_TLDS = {"zip": 30, "mov": 30, "top": 15, "xyz": 12, "tk": 20, "ml": 20, "ga": 20, "cf": 20, "gq": 20,
                   "click": 15, "country": 15, "kim": 10, "work": 10, "loan": 15, "men": 10, "date": 10,
                   "racing": 10, "review": 10, "stream": 10, "download": 15, "support": 10, "rest": 10, "cyou": 15,
                   "icu": 15, "cam": 12, "buzz": 10, "monster": 10, "sbs": 12, "cfd": 12, "bond": 12, "lol": 8,
                   "quest": 8, "help": 10, "live": 6, "online": 8, "site": 8, "website": 8, "space": 6, "fun": 6,
                   "shop": 5, "info": 5, "vip": 8, "pw": 12, "su": 12, "ru": 4, "cn": 4, "best": 8, "beauty": 8,
                   "hair": 8, "skin": 8, "makeup": 8, "autos": 8, "boats": 8, "mom": 8, "yachts": 8}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
              "shorturl.at", "rb.gy", "tiny.cc", "t.ly", "s.id", "bl.ink", "short.io", "v.gd", "qrco.de",
              "lnkd.in", "trib.al", "shorte.st", "adf.ly", "bc.vc", "ouo.io", "urlz.fr", "clck.ru", "u.to"}
DYNAMIC_DNS = ("duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "sytes.net", "serveo.net",
               "ngrok.io", "ngrok-free.app", "trycloudflare.com", "dynu.net", "freedns.afraid.org", "servebeer.com",
               "loclx.io", "localtunnel.me", "pinggy.link")
FREE_HOSTING = ("000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "firebaseapp.com", "web.app",
                "glitch.me", "repl.co", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "github.io",
                "herokuapp.com", "onrender.com", "r2.dev", "surge.sh", "godaddysites.com", "square.site",
                "webflow.io", "framer.app", "carrd.co", "sites.google.com", "forms.gle", "ipfs.io", "dweb.link",
                "azurewebsites.net", "s3.amazonaws.com", "storage.googleapis.com", "firebasestorage.googleapis.com",
                "blob.core.windows.net", "translate.goog", "jimdosite.com", "yolasite.com", "mystrikingly.com")
# Hosts where one bad URL says nothing about the rest of the host (shared / user content).
SHARED_HOSTS = {"github.com", "raw.githubusercontent.com", "gist.github.com", "gitlab.com", "bitbucket.org",
                "drive.google.com", "docs.google.com", "sites.google.com", "storage.googleapis.com",
                "firebasestorage.googleapis.com", "dropbox.com", "www.dropbox.com", "dl.dropboxusercontent.com",
                "onedrive.live.com", "1drv.ms", "sharepoint.com", "cdn.discordapp.com", "media.discordapp.net",
                "discord.com", "pastebin.com", "paste.ee", "transfer.sh", "mediafire.com", "www.mediafire.com",
                "mega.nz", "we.tl", "wetransfer.com", "s3.amazonaws.com", "ipfs.io", "cloudflare-ipfs.com",
                "bit.ly", "tinyurl.com", "t.co", "goo.gl", "t.me", "telegra.ph", "archive.org", "web.archive.org",
                "youtube.com", "www.youtube.com", "facebook.com", "www.facebook.com", "linkedin.com",
                "www.linkedin.com", "twitter.com", "x.com", "forms.gle", "docs.googleusercontent.com",
                "objects.githubusercontent.com", "codeload.github.com", "anonfiles.com", "files.catbox.moe",
                "cdn.jsdelivr.net", "unpkg.com", "pages.dev", "workers.dev", "blogspot.com", "wordpress.com"}
LOGIN_WORDS = ("login", "log-in", "signin", "sign-in", "logon", "verify", "verification", "validate", "account",
               "update", "secure", "security", "confirm", "banking", "wallet", "password", "passwd", "credential",
               "unlock", "suspend", "suspended", "recover", "recovery", "billing", "invoice", "payment", "webscr",
               "authenticate", "auth", "2fa", "otp", "kyc", "reactivate", "restore", "support-ticket", "helpdesk",
               "seed", "airdrop", "claim", "reward", "gift", "prize", "refund", "tax-refund", "bisp", "ehsaas")
LURE_WORDS = ("login", "signin", "verify", "secure", "account", "update", "support", "help", "service", "wallet",
              "recover", "unlock", "billing", "pay", "reward", "gift", "claim", "bonus", "auth", "id-", "-id", "kyc",
              "confirm", "alert", "notice", "official")
EXEC_EXT = (".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
            ".msi", ".jar", ".apk", ".dll", ".lnk", ".iso", ".img", ".vhd", ".vhdx", ".appx", ".msix", ".xll",
            ".docm", ".xlsm", ".pptm", ".one", ".reg", ".cpl", ".zip", ".rar", ".7z")
CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
                            "$": "s", "@": "a", "|": "l", "!": "i"})
HOMOGLYPHS = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
                            "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "ɡ": "g", "ο": "o",
                            "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "ε": "e", "ɑ": "a",
                            "ı": "i", "ł": "l", "ⅼ": "l", "ｍ": "m", "ꓲ": "l"})
MULTI_CONFUSABLE = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"), ("ii", "u"))


def _f(code: str, severity: str, points: int, text: str) -> dict:
    return {"code": code, "severity": severity, "points": points, "text": text}


def levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        lo = cur[0]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
            lo = min(lo, cur[j])
        if lo > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _skeleton(label: str) -> str:
    """Fold look-alike characters: digits -> letters, accents removed, rn -> m ..."""
    s = unicodedata.normalize("NFKD", label.lower().translate(HOMOGLYPHS))
    s = "".join(c for c in s if not unicodedata.combining(c)).lower().translate(CONFUSABLE)
    for a, b in MULTI_CONFUSABLE:
        s = s.replace(a, b)
    return s


def _scripts(label: str) -> set[str]:
    out = set()
    for ch in label:
        if ch.isascii():
            if ch.isalpha():
                out.add("LATIN")
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        out.add(name.split(" ")[0])
    return out


def official(brand: str, reg: str) -> bool:
    return reg in BRANDS.get(brand, ()) or any(reg == d or reg.endswith("." + d) for d in BRANDS.get(brand, ()))


def _owner_brand(reg: str) -> str | None:
    for b, doms in BRANDS.items():
        if reg in doms:
            return b
    return None


def brands_in(text: str, words_only: bool = False) -> list[str]:
    t = (text or "").lower()
    found = []
    labels = set(re.split(r"[^a-z0-9]+", t))
    squashed = re.sub(r"[^a-z0-9]", "", t)
    for b in BRANDS:
        if b in labels or (not words_only and b not in WORD_ONLY and len(b) >= 5 and b in squashed):
            found.append(b)
    return found


def analyze_host(host: str) -> list[dict]:
    """Checks that only need the host name."""
    out: list[dict] = []
    h = host.lower().rstrip(".")
    try:
        ip = ioc.norm_ip(h)
    except ValueError:
        ip = None
    if ip:
        out.append(_f("ip_host", "medium", 25, "The address is a bare IP number instead of a name - real login "
                                              "pages almost never do this"))
        return out
    reg = ioc.registrable(h)
    reg_label = reg.split(".")[0]
    tld = h.rsplit(".", 1)[-1]
    uni = ioc.unicode_host(h)
    owner = _owner_brand(reg)
    # IDN / homoglyphs
    if "xn--" in h:
        sc = set()
        for lab in uni.split("."):
            sc |= _scripts(lab)
        mixed = len(sc - {"DIGIT"}) > 1
        out.append(_f("idn", "high" if mixed else "low", 30 if mixed else 8,
                      f"International (punycode) name shown as '{uni}'" +
                      (" - it mixes alphabets, a classic look-alike trick" if mixed else "")))
        sk = _skeleton(uni.split(".")[0] if uni.count(".") >= 1 else uni)
        for b in BRANDS:
            if len(b) >= 4 and sk == b and not official(b, reg):
                out.append(_f("homoglyph", "critical", 60, f"'{uni}' is built to look like {b.title()} using "
                                                          f"look-alike letters"))
                break
    if owner:
        return out                                         # a brand's own domain - no brand / typo checks
    # brand in the wrong place
    sub = h[: -len(reg)].rstrip(".") if h != reg else ""
    for b in brands_in(sub, words_only=False) if sub else []:
        if not official(b, reg):
            out.append(_f("brand_subdomain", "high", 45, f"'{b}' appears in the sub-domain but the site really "
                                                        f"belongs to '{reg}'"))
            break
    else:
        for b in brands_in(reg_label):
            if not official(b, reg) and reg_label != b:
                out.append(_f("brand_in_domain", "medium", 30, f"The domain '{reg}' contains the brand name '{b}' "
                                                              f"but is not one of {b.title()}'s sites"))
                lure = [w for w in LURE_WORDS if w in reg_label.replace(b, " ")]
                if lure:
                    out.append(_f("brand_lure", "medium", 20, f"Brand name combined with '{lure[0]}' in the domain "
                                                              f"(e.g. brand-verify-account.com)"))
                break
    # look-alike of a brand's real domain
    if not any(f["code"] in ("homoglyph", "brand_subdomain") for f in out):
        sk = _skeleton(reg_label)
        for b, doms in BRANDS.items():
            if len(b) < 5:
                continue
            for d in doms:
                dl = d.split(".")[0]
                if len(dl) < 5 or reg_label == dl:
                    continue
                dist = levenshtein(sk, dl, 2)
                if sk == dl or dist <= (1 if len(dl) < 8 else 2):
                    out.append(_f("typosquat", "high", 50, f"'{reg}' looks like a misspelling of {d} "
                                                          f"({b.title()})"))
                    break
            else:
                continue
            break
    if tld in SUSPICIOUS_TLDS:
        p = SUSPICIOUS_TLDS[tld]
        out.append(_f("risky_tld", "medium" if p >= 15 else "low", p, f".{tld} addresses are heavily used for scams "
                                                                      f"and malware"))
    if any(h == d or h.endswith("." + d) for d in DYNAMIC_DNS):
        out.append(_f("dynamic_dns", "medium", 25, "Free dynamic-DNS / tunnel address - anyone can create one in "
                                                  "seconds, common for phishing kits and malware servers"))
    elif any(h == d or h.endswith("." + d) for d in FREE_HOSTING):
        out.append(_f("free_hosting", "low", 10, "Hosted on a free website builder / cloud storage - fine for "
                                                "hobby sites, but banks and big brands never use them for logins"))
    labels = h.split(".")
    if len(labels) >= 5:
        out.append(_f("deep_subdomains", "low", 10, f"Unusually many sub-domain levels ({len(labels)})"))
    uni_reg = ioc.unicode_host(reg).split(".")[0]
    if uni_reg.count("-") >= 2 or ioc.unicode_host(h).count("-") >= 4:
        out.append(_f("hyphens", "low", 8, "Many hyphens in the name (e.g. secure-login-account-verify)"))
    if sum(c.isdigit() for c in uni_reg) >= 4 and not uni_reg.isdigit():
        out.append(_f("digits", "low", 6, "Lots of digits in the domain name"))
    if len(h) > 60:
        out.append(_f("long_host", "low", 8, "Very long host name"))
    if h in SHORTENERS or reg in SHORTENERS:
        out.append(_f("shortener", "low", 12, "Link shortener - the real destination is hidden"))
    return out


def analyze_url(raw: str) -> dict:
    """Offline phishing analysis. {kind, host, registrable, score, level, findings, brands}."""
    c = ioc.classify(raw)
    if c["type"] == "domain":
        host, info = c["value"], {"path": "/", "query": "", "scheme": None, "userinfo": "", "raw": raw}
    elif c["type"] == "url":
        host, info = c["host"], {"path": c["path"], "query": c["query"], "scheme": c["scheme"],
                                 "userinfo": c["userinfo"], "raw": raw, "port": c["port"]}
    elif c["type"] == "email":
        host, info = c["domain"], {"path": "/", "query": "", "scheme": None, "userinfo": "", "raw": raw}
    elif c["type"] == "ip":
        host, info = c["value"], {"path": "/", "query": "", "scheme": None, "userinfo": "", "raw": raw}
    else:
        raise ioc.IOCError("Phishing checks need a URL, domain, e-mail address or IP")
    out = analyze_host(host)
    path_l = urllib.parse.unquote(info["path"] or "/").lower()
    q = urllib.parse.unquote_plus(info["query"] or "").lower()
    reg = ioc.registrable(host) if not c.get("ip") and c["type"] != "ip" else host
    if info["userinfo"] or "@" in (info.get("raw") or "").split("://", 1)[-1].split("/", 1)[0]:
        if c["type"] == "url":
            out.append(_f("at_sign", "high", 40, "The link contains '@' before the host - everything before it is "
                                                "ignored by the browser, a trick to show a fake site name"))
    words = [w for w in LOGIN_WORDS if re.search(rf"(^|[^a-z]){re.escape(w)}([^a-z]|$)", path_l + " " + q)]
    if words:
        out.append(_f("login_words", "low", min(15, 5 * len(words)), f"Words like '{', '.join(words[:4])}' in the "
                                                                     f"link"))
    brand_path = [b for b in brands_in(path_l, words_only=True) if not official(b, reg)]
    if brand_path and c["type"] == "url":
        out.append(_f("brand_in_path", "medium", 20, f"'{brand_path[0]}' is named in the path of a site that is "
                                                     f"not {brand_path[0].title()}'s"))
    if any(path_l.endswith(e) for e in EXEC_EXT):
        ext = next(e for e in EXEC_EXT if path_l.endswith(e))
        out.append(_f("exec_download", "medium" if ext in (".zip", ".rar", ".7z") else "high",
                      15 if ext in (".zip", ".rar", ".7z") else 30, f"The link downloads a '{ext}' file directly"))
    if re.search(r"(^|[?&])(url|u|redirect|redir|next|goto|target|dest|destination|continue|return|r)=(https?%3a|https?:|//)",
                 (info["query"] or "").lower()):
        out.append(_f("open_redirect", "low", 10, "The link carries another web address in a parameter (redirect "
                                                  "trick to hide the real destination)"))
    if info["scheme"] == "http" and (words or brand_path or any(f["code"].startswith("brand") for f in out)):
        out.append(_f("http_login", "medium", 15, "Asks for sign-in style actions over plain http:// (not "
                                                 "encrypted)"))
    if c["type"] == "url" and info.get("port") not in (None, 80, 443) and info["scheme"] in ("http", "https"):
        out.append(_f("odd_port", "low", 8, f"Unusual port {info['port']} for a website"))
    if c["type"] == "url" and "%" in (c.get("raw_host") or ""):
        out.append(_f("encoded_host", "high", 30, "The host name is percent-encoded to hide what it is"))
    if c["type"] == "url" and len(c["value"]) > 200:
        out.append(_f("long_url", "low", 6, f"Very long link ({len(c['value'])} characters)"))
    if re.search(r"(data:text/html|javascript:|base64,)", q):
        out.append(_f("data_uri", "high", 30, "Contains an embedded page / script in the link"))
    score = min(100, sum(f["points"] for f in out))
    return {"kind": c["type"], "host": host, "registrable": reg, "score": score, "level": level(score),
            "findings": sorted(out, key=lambda f: -f["points"]),
            "brands": sorted({b for b in brands_in(host + " " + path_l) if not official(b, reg)}),
            "official_brand": _owner_brand(reg)}


def level(score: int) -> str:
    return "high" if score >= 70 else "medium" if score >= 40 else "low" if score >= 15 else "none"


# ====================================================================== page analysis (deep check)
class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.forms: list[dict] = []
        self._form: dict | None = None
        self.inputs: list[dict] = []
        self.meta_refresh: str | None = None
        self.scripts_inline: list[str] = []
        self._in_script = False
        self._buf: list[str] = []
        self.resources: list[str] = []
        self.links: list[str] = []
        self.iframes: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag == "input":
            inp = {"type": a.get("type", "text").lower(), "name": (a.get("name") or a.get("id") or "").lower(),
                   "placeholder": a.get("placeholder", "").lower(), "autocomplete": a.get("autocomplete", "").lower()}
            self.inputs.append(inp)
            if self._form is not None:
                self._form["inputs"].append(inp)
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")
        elif tag == "script":
            if a.get("src"):
                self.resources.append(a["src"])
            else:
                self._in_script, self._buf = True, []
        elif tag in ("link", "img") and (a.get("href") or a.get("src")):
            self.resources.append(a.get("href") or a.get("src"))
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"])

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None
        elif tag == "script" and self._in_script:
            self._in_script = False
            self.scripts_inline.append("".join(self._buf)[:200000])

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._in_script:
            self._buf.append(data)


SENSITIVE_INPUT = re.compile(r"(pass|pwd|pin\b|otp|cvv|cvc|card|ccnum|cnic|ssn|seed|mnemonic|private.?key|"
                             r"security.?code|expir)", re.I)
OBFUSCATION = re.compile(r"(eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)|document\.write\s*\(\s*"
                         r"(unescape|atob)|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){40,}|_0x[0-9a-f]{4,}\s*\[)", re.I)
JS_REDIRECT = re.compile(r"(window|document|top|self)\.location(\.href)?\s*=|location\.replace\s*\(", re.I)


def analyze_page(html: bytes | str, page_url: str, final_host: str) -> dict:
    """Findings from the HTML of the page a link really opens (no scripts are run)."""
    text = html.decode("utf-8", "replace") if isinstance(html, bytes) else html
    p = _PageParser()
    try:
        p.feed(text[:1_500_000])
        p.close()
    except Exception:                                           # pragma: no cover - HTMLParser is lenient
        pass
    out: list[dict] = []
    reg = ioc.registrable(final_host) if not _is_ip(final_host) else final_host
    title = re.sub(r"\s+", " ", p.title).strip()[:200]
    title_brands = [b for b in brands_in(title, words_only=True) if not official(b, reg)]
    sens = [i for i in p.inputs if i["type"] == "password" or SENSITIVE_INPUT.search(i["name"] + " " + i["placeholder"])]
    has_pw = any(i["type"] == "password" for i in p.inputs)
    if title_brands and (has_pw or sens):
        out.append(_f("brand_login_page", "critical", 60, f"The page calls itself '{title}' and asks for sign-in "
                                                          f"details, but this site is not {title_brands[0].title()}'s"))
    elif title_brands:
        out.append(_f("brand_title", "medium", 20, f"The page title names {title_brands[0].title()} on a site that "
                                                   f"isn't theirs"))
    if has_pw:
        out.append(_f("password_form", "low", 10, "The page has a password box"))
    if any(SENSITIVE_INPUT.search(i["name"] + " " + i["placeholder"]) and i["type"] != "password" and
           re.search(r"(card|cvv|cvc|otp|cnic|seed|mnemonic|private)", i["name"] + " " + i["placeholder"], re.I)
           for i in p.inputs):
        out.append(_f("sensitive_form", "high", 25, "Asks for card numbers, OTP codes, CNIC or wallet recovery "
                                                    "words"))
    for f in p.forms:
        act = (f["action"] or "").strip()
        if not act or act.startswith("#") or act.lower().startswith("javascript"):
            continue
        tgt = urllib.parse.urljoin(page_url, act)
        try:
            th = urllib.parse.urlsplit(tgt).hostname or ""
        except ValueError:
            continue
        if th and not _is_ip(th) and ioc.registrable(th) != reg and any(
                i["type"] == "password" or SENSITIVE_INPUT.search(i["name"]) for i in f["inputs"]):
            out.append(_f("form_offsite", "high", 35, f"The sign-in form sends what you type to another site "
                                                      f"({th})"))
            break
        if tgt.startswith("http://") and has_pw:
            out.append(_f("form_http", "medium", 15, "The password form sends over unencrypted http://"))
            break
        if re.search(r"\.(php|cgi)$", urllib.parse.urlsplit(tgt).path or "") and has_pw and title_brands:
            out.append(_f("form_php", "low", 8, "Typical phishing-kit form handler (.php)"))
            break
    copied = {}
    for r in p.resources + p.links:
        try:
            rh = (urllib.parse.urlsplit(urllib.parse.urljoin(page_url, r)).hostname or "").lower()
        except ValueError:
            continue
        if not rh or _is_ip(rh):
            continue
        rr = ioc.registrable(rh)
        ob = _owner_brand(rr)
        if ob and not official(ob, reg) and ob not in ("google", "microsoft", "facebook", "amazon", "github"):
            copied[ob] = copied.get(ob, 0) + 1
        elif ob in ("microsoft", "paypal", "apple") and not official(ob, reg):
            copied[ob] = copied.get(ob, 0) + 1
    for ob, n in sorted(copied.items(), key=lambda x: -x[1]):
        if n >= 3 and (has_pw or sens):
            out.append(_f("brand_assets", "medium", 20, f"Loads {n} images / styles straight from {ob.title()}'s "
                                                         f"real site (copied login page)"))
            break
    if p.meta_refresh and "url=" in p.meta_refresh.lower():
        out.append(_f("meta_refresh", "low", 10, "The page immediately redirects somewhere else"))
    js = "\n".join(p.scripts_inline)
    if OBFUSCATION.search(js):
        out.append(_f("obfuscated_js", "medium", 20, "Contains obfuscated / encoded JavaScript"))
    if JS_REDIRECT.search(js) and len(text) < 4000:
        out.append(_f("js_redirect", "low", 8, "A tiny page whose only job is to send you elsewhere"))
    if p.iframes and len(text) < 3000:
        out.append(_f("iframe_wrapper", "low", 8, "A small page that only wraps another site in a frame"))
    if re.search(r"(your account (has been|will be) (suspended|locked|closed|limited)|unusual (sign.?in|activity)|"
                 r"verify your (identity|account) (within|immediately)|act now|within 24 hours)", text, re.I):
        out.append(_f("urgency", "low", 10, "Uses pressure wording (account suspended, verify within 24 hours ...)"))
    score = min(100, sum(f["points"] for f in out))
    return {"title": title or None, "forms": len(p.forms), "password_fields": sum(i["type"] == "password" for i in p.inputs),
            "sensitive_fields": len(sens), "score": score, "findings": sorted(out, key=lambda f: -f["points"]),
            "brands": sorted(set(title_brands))}


def _is_ip(h: str) -> bool:
    try:
        ioc.norm_ip(h)
        return True
    except ValueError:
        return False
