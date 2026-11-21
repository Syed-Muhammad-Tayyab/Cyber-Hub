"""
Cyber Hub Backend - YARA "lite" engine (Part 8)
Developed by Syed Muhammad Tayyab

A pure-Python compiler + matcher for the most used subset of the YARA rule
language. Cyber Hub prefers the real engine (yara-python, libyara); this
fallback means the rules engine still works on a PC where that package
could not be installed, and every built-in rule is written in this subset.

Supported
  * rule / private rule / global rule, tags, meta (string, integer, boolean)
  * text strings  "..."  with \\" \\\\ \\n \\r \\t \\xNN escapes
      modifiers: ascii, wide, nocase, fullword, private
  * hex strings   { 4D 5A ?? ?0 [2-4] ( 01 | 02 ) ~FF }
  * regex strings /.../is  with modifiers ascii, wide (ASCII-only), nocase, fullword
  * anonymous strings  $ = "..."
  * conditions: and / or / not, ( ), true / false, filesize, KB / MB,
      $a, $a at N, $a in (A..B), #a, #a in (A..B), @a[i], !a[i],
      any / all / none / N / N% of them | ($a, $b*),
      uint8/16/32(N) and the *be variants, int8/16/32(N),
      == != < <= > >= + - * \\ %  & | ^ << >> ~,
      contains icontains startswith istartswith endswith iendswith iequals matches,
      references to earlier rules, external variables (filename, filepath, extension)

Not supported (the rule set is reported as "needs native YARA"):
  imports / modules (pe, math, hash...), for..of loops, xor / base64 modifiers.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

MAX_MATCHES_PER_STRING = 1000
_WORD = rb"A-Za-z0-9_"


class LiteError(Exception):
    """Syntax error (line number in the message)."""


class LiteUnsupported(LiteError):
    """Valid YARA, but outside the subset this engine implements."""


class _Undef:
    def __repr__(self):
        return "UNDEFINED"


UNDEF = _Undef()


# ====================================================================== compiled objects
@dataclass
class LiteString:
    ident: str
    regex: re.Pattern
    private: bool = False
    atoms: list[tuple[bytes, bool]] | None = None     # any of these must occur (needle, case-insensitive) or None
    on_lower: bool = False                            # pattern is pre-lowered: run it on data.lower()


@dataclass
class LiteRule:
    name: str
    namespace: str
    tags: list[str]
    meta: dict
    strings: dict[str, LiteString]
    condition: object                     # AST tuple
    private: bool = False
    is_global: bool = False


@dataclass
class LiteMatch:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict
    strings: list[tuple[str, int, int, bytes]] = field(default_factory=list)   # (id, offset, length, data)


# ====================================================================== string -> bytes regex
def _escape_byte(b: int) -> bytes:
    return re.escape(bytes([b]))


def _text_to_regex(raw: bytes, wide: bool) -> bytes:
    if not wide:
        return b"".join(_escape_byte(b) for b in raw)
    return b"".join(_escape_byte(b) + b"\\x00" for b in raw)


def _fullword(pat: bytes) -> bytes:
    return b"(?<![" + _WORD + b"])(?:" + pat + b")(?![" + _WORD + b"])"


def _hex_to_regex(body: str, line: int) -> bytes:
    """Translate a YARA hex string body (between the braces) into a bytes regex."""
    toks = re.findall(r"~?[0-9A-Fa-f?]{2}|\[[^\]]*\]|[()|]|\S", body)
    out: list[bytes] = []
    depth = 0
    for t in toks:
        if t == "(":
            depth += 1
            out.append(b"(?:")
        elif t == ")":
            depth -= 1
            if depth < 0:
                raise LiteError(f"line {line}: unbalanced ) in hex string")
            out.append(b")")
        elif t == "|":
            out.append(b"|")
        elif t.startswith("["):
            inner = t[1:-1].strip()
            m = re.fullmatch(r"(\d*)\s*(?:-\s*(\d*))?", inner)
            if not m:
                raise LiteError(f"line {line}: bad jump {t}")
            lo, hi = m.group(1), m.group(2)
            if "-" not in inner:
                if not lo:
                    raise LiteError(f"line {line}: bad jump {t}")
                out.append(b".{%d}" % int(lo))
            else:
                out.append(b".{%d,%s}" % (int(lo or 0), hi.encode() if hi else b""))
        elif re.fullmatch(r"~?[0-9A-Fa-f?]{2}", t):
            neg = t.startswith("~")
            h = t[1:] if neg else t
            if h == "??":
                if neg:
                    raise LiteError(f"line {line}: ~?? is not allowed")
                out.append(b".")
                continue
            if "?" in h:
                vals = [v for v in range(256)
                        if (h[0] == "?" or (v >> 4) == int(h[0], 16)) and (h[1] == "?" or (v & 15) == int(h[1], 16))]
            else:
                vals = [int(h, 16)]
            cls = b"".join(b"\\x%02x" % v for v in vals)
            out.append((b"[^" if neg else b"[") + cls + b"]" if (neg or len(vals) > 1) else b"\\x%02x" % vals[0])
        else:
            raise LiteError(f"line {line}: unexpected '{t}' in hex string")
    if depth:
        raise LiteError(f"line {line}: unbalanced ( in hex string")
    if not out:
        raise LiteError(f"line {line}: empty hex string")
    return b"".join(out)


# ====================================================================== atoms (fast pre-filter)
# Like libyara, every string gets a short literal that MUST be present for it to match.
# A plain bytes.find() over the file rules most strings out before any regex runs.
def _hex_atom(body: str) -> bytes | None:
    toks = re.findall(r"~?[0-9A-Fa-f?]{2}|\[[^\]]*\]|[()|]|\S", body)
    best, run, depth = b"", bytearray(), 0
    for t in toks:
        fixed = depth == 0 and re.fullmatch(r"[0-9A-Fa-f]{2}", t)
        if fixed:
            run.append(int(t, 16))
            continue
        if len(run) > len(best):
            best = bytes(run)
        run = bytearray()
        if t == "(":
            depth += 1
        elif t == ")":
            depth -= 1
    if len(run) > len(best):
        best = bytes(run)
    return best if len(best) >= 2 else None


_RX_META = set("()[]{}|?*+.^$")


def _regex_atom(src: str) -> bytes | None:
    """Longest literal run at nesting depth 0 of a regex with no top-level alternation."""
    best, run, depth, i, n = "", [], 0, 0, len(src)
    while i < n:
        c = src[i]
        lit = None
        if c == "\\" and i + 1 < n:
            e = src[i + 1]
            if not e.isalnum():                       # \. \/ \( ... are literals
                lit = e
            i += 2
        elif c == "[":                                # character class - skip it
            j = i + 1
            if j < n and src[j] == "^":
                j += 1
            if j < n and src[j] == "]":
                j += 1
            while j < n and src[j] != "]":
                j += 2 if src[j] == "\\" else 1
            i = j + 1
        elif c in _RX_META:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == "|" and depth == 0:
                return None
            if c == "{":                              # quantifier body {n,m} - not literal text
                j = src.find("}", i)
                i = j + 1 if j > 0 else n
                lit = None
            else:
                i += 1
        else:
            lit = c
            i += 1
        if lit is not None and depth == 0:
            nxt = src[i:i + 1]
            if nxt in ("?", "*", "{"):
                lit = None
        if lit is not None and depth == 0:
            run.append(lit)
        else:
            if len(run) > len(best):
                best = "".join(run)
            run = []
    if len(run) > len(best):
        best = "".join(run)
    if len(best) < 3:
        return None
    try:
        return best.encode("latin-1")
    except UnicodeEncodeError:
        return None


# ====================================================================== parser
_KEYWORDS = {"and", "or", "not", "of", "them", "at", "in", "any", "all", "none", "true", "false", "filesize",
             "contains", "icontains", "startswith", "istartswith", "endswith", "iendswith", "iequals",
             "matches", "for", "entrypoint"}
_INT_FUNCS = {"uint8": ("<B", 1), "uint16": ("<H", 2), "uint32": ("<I", 4),
              "uint8be": (">B", 1), "uint16be": (">H", 2), "uint32be": (">I", 4),
              "int8": ("<b", 1), "int16": ("<h", 2), "int32": ("<i", 4),
              "int8be": (">b", 1), "int16be": (">h", 2), "int32be": (">i", 4)}
_STR_OPS = ("icontains", "contains", "istartswith", "startswith", "iendswith", "endswith", "iequals", "matches")
_CMP_OPS = ("==", "!=", "<=", ">=", "<", ">")


class _Parser:
    def __init__(self, text: str, namespace: str, externals: dict, known_rules: dict):
        self.s = text
        self.i = 0
        self.ns = namespace
        self.externals = externals
        self.known_rules = known_rules          # name -> LiteRule (earlier rules, this namespace + global)
        self.rules: list[LiteRule] = []
        self.imports: list[str] = []
        self._cur_strings: dict[str, LiteString] = {}

    # ---------------------------------------------------------- low level
    @property
    def line(self) -> int:
        return self.s.count("\n", 0, self.i) + 1

    def err(self, msg: str, cls=LiteError):
        raise cls(f"line {self.line}: {msg}")

    def ws(self) -> None:
        s, n = self.s, len(self.s)
        while self.i < n:
            c = s[self.i]
            if c in " \t\r\n":
                self.i += 1
            elif s.startswith("//", self.i):
                j = s.find("\n", self.i)
                self.i = n if j < 0 else j + 1
            elif s.startswith("/*", self.i):
                j = s.find("*/", self.i + 2)
                if j < 0:
                    self.err("unterminated comment")
                self.i = j + 2
            else:
                break

    def peek(self, tok: str) -> bool:
        self.ws()
        if not self.s.startswith(tok, self.i):
            return False
        if tok[-1].isalnum() or tok[-1] == "_":
            nxt = self.s[self.i + len(tok):self.i + len(tok) + 1]
            if nxt and (nxt.isalnum() or nxt == "_"):
                return False
        return True

    def accept(self, tok: str) -> bool:
        if self.peek(tok):
            self.i += len(tok)
            return True
        return False

    def expect(self, tok: str) -> None:
        if not self.accept(tok):
            got = self.s[self.i:self.i + 20].split("\n")[0]
            self.err(f"expected '{tok}' but found '{got or 'end of file'}'")

    def ident(self) -> str:
        self.ws()
        m = re.compile(r"[A-Za-z_][A-Za-z0-9_]*").match(self.s, self.i)
        if not m:
            self.err("expected an identifier")
        self.i = m.end()
        return m.group(0)

    def peek_ident(self) -> str | None:
        self.ws()
        m = re.compile(r"[A-Za-z_][A-Za-z0-9_]*").match(self.s, self.i)
        return m.group(0) if m else None

    def string_lit(self) -> bytes:
        self.ws()
        if self.s[self.i:self.i + 1] != '"':
            self.err("expected a quoted string")
        self.i += 1
        out = bytearray()
        while True:
            if self.i >= len(self.s):
                self.err("unterminated string")
            c = self.s[self.i]
            if c == '"':
                self.i += 1
                return bytes(out)
            if c == "\n":
                self.err("newline inside a string")
            if c == "\\":
                e = self.s[self.i + 1:self.i + 2]
                if e == "x":
                    hx = self.s[self.i + 2:self.i + 4]
                    if not re.fullmatch(r"[0-9A-Fa-f]{2}", hx):
                        self.err("bad \\x escape")
                    out.append(int(hx, 16))
                    self.i += 4
                    continue
                mp = {'"': 34, "\\": 92, "n": 10, "r": 13, "t": 9}
                if e not in mp:
                    self.err(f"unknown escape \\{e}")
                out.append(mp[e])
                self.i += 2
                continue
            out += c.encode("utf-8")
            self.i += 1

    def number(self) -> int | None:
        self.ws()
        m = re.compile(r"(0x[0-9A-Fa-f]+|0o[0-7]+|\d+)(KB|MB)?\b").match(self.s, self.i)
        if not m:
            return None
        self.i = m.end()
        v = int(m.group(1), 0)
        return v * {"KB": 1024, "MB": 1024 * 1024, None: 1}[m.group(2)]

    def regex_lit(self) -> tuple[str, str]:
        self.ws()
        if self.s[self.i:self.i + 1] != "/":
            self.err("expected a /regex/")
        j = self.i + 1
        buf = []
        while True:
            if j >= len(self.s) or self.s[j] == "\n":
                self.err("unterminated regular expression")
            c = self.s[j]
            if c == "\\":
                buf.append(self.s[j:j + 2])
                j += 2
                continue
            if c == "/":
                break
            buf.append(c)
            j += 1
        j += 1
        m = re.compile(r"[is]*").match(self.s, j)
        self.i = m.end()
        return "".join(buf), m.group(0)

    # ---------------------------------------------------------- file / rule
    def parse(self) -> list[LiteRule]:
        while True:
            self.ws()
            if self.i >= len(self.s):
                return self.rules
            if self.accept("import"):
                self.imports.append(self.string_lit().decode())
                continue
            if self.accept("include"):
                self.err("'include' is not supported - paste the included rules instead", LiteUnsupported)
            self.rule()

    def rule(self) -> None:
        private = is_global = False
        while True:
            if self.accept("private"):
                private = True
            elif self.accept("global"):
                is_global = True
            else:
                break
        self.expect("rule")
        name = self.ident()
        if name in _KEYWORDS:
            self.err(f"'{name}' is a reserved word")
        if name in self.known_rules:
            self.err(f"duplicated rule name '{name}'")
        tags: list[str] = []
        if self.accept(":"):
            while self.peek_ident() and not self.peek("{"):
                tags.append(self.ident())
        self.expect("{")
        meta: dict = {}
        self._cur_strings = {}
        if self.accept("meta"):
            self.expect(":")
            while True:
                nm = self.peek_ident()
                if nm is None or nm in ("strings", "condition"):
                    break
                self.ident()
                self.expect("=")
                self.ws()
                if self.s[self.i:self.i + 1] == '"':
                    meta[nm] = self.string_lit().decode("utf-8", "replace")
                elif self.accept("true"):
                    meta[nm] = True
                elif self.accept("false"):
                    meta[nm] = False
                else:
                    neg = self.accept("-")
                    v = self.number()
                    if v is None:
                        self.err(f"bad value for meta '{nm}'")
                    meta[nm] = -v if neg else v
        if self.accept("strings"):
            self.expect(":")
            anon = 0
            while self.peek("$"):
                self.i += 1
                m = re.compile(r"[A-Za-z0-9_]*").match(self.s, self.i)
                sid = m.group(0)
                self.i = m.end()
                if not sid:
                    anon += 1
                    sid = f"_anon{anon}"
                if sid in self._cur_strings:
                    self.err(f"duplicated string identifier ${sid}")
                self.expect("=")
                self._cur_strings[sid] = self.string_def(sid)
        self.expect("condition")
        self.expect(":")
        cond = self.expr()
        self.expect("}")
        r = LiteRule(name, self.ns, tags, meta, self._cur_strings, cond, private, is_global)
        self.rules.append(r)
        self.known_rules[name] = r

    def string_def(self, sid: str) -> LiteString:
        self.ws()
        c = self.s[self.i:self.i + 1]
        line = self.line
        if c == '"':
            raw = self.string_lit()
            mods = self.modifiers({"ascii", "wide", "nocase", "fullword", "private", "xor", "base64", "base64wide"})
            if mods & {"xor", "base64", "base64wide"}:
                self.err("xor / base64 string modifiers need native YARA", LiteUnsupported)
            if not raw:
                self.err("empty string")
            nc = "nocase" in mods
            body_raw = raw.lower() if nc else raw          # nocase: match a lowered copy of the data
            alts = []
            if "ascii" in mods or "wide" not in mods:
                alts.append(_text_to_regex(body_raw, False))
            if "wide" in mods:
                alts.append(_text_to_regex(body_raw, True))
            pat = alts[0] if len(alts) == 1 else b"(?:" + b"|".join(alts) + b")"
            if "fullword" in mods:
                pat = _fullword(pat)
            flags = re.DOTALL
            on_lower = nc
            atoms = []
            if "ascii" in mods or "wide" not in mods:
                atoms.append((raw.lower() if nc else raw, nc))
            if "wide" in mods:
                w = b"".join(bytes([b, 0]) for b in raw)
                atoms.append((w.lower() if nc else w, nc))
        elif c == "{":
            j = self.s.find("}", self.i)
            if j < 0:
                self.err("unterminated hex string")
            body = self.s[self.i + 1:j]
            body = re.sub(r"//[^\n]*|/\*.*?\*/", " ", body, flags=re.S)
            self.i = j + 1
            pat = _hex_to_regex(body, line)
            mods = self.modifiers({"private"})
            flags = re.DOTALL
            a = _hex_atom(body)
            atoms = [(a, False)] if a else None
            on_lower = False
        elif c == "/":
            src, rflags = self.regex_lit()
            mods = self.modifiers({"ascii", "wide", "nocase", "fullword", "private"})
            if "wide" in mods:
                self.err("wide regular expressions need native YARA", LiteUnsupported)
            pat = src.encode("latin-1", "backslashreplace")
            if "fullword" in mods:
                pat = _fullword(pat)
            flags = (re.IGNORECASE if ("i" in rflags or "nocase" in mods) else 0) | \
                    (re.DOTALL if "s" in rflags else 0)
            a = _regex_atom(src)
            nc = bool(flags & re.IGNORECASE)
            atoms = [(a.lower() if nc else a, nc)] if a else None
            on_lower = False
        else:
            self.err(f"bad definition for string ${sid}")
        try:
            rx = re.compile(pat, flags)
        except re.error as e:
            raise LiteError(f"line {line}: invalid pattern in ${sid}: {e}") from e
        return LiteString(sid, rx, "private" in mods, atoms, on_lower)

    def modifiers(self, allowed: set[str]) -> set[str]:
        mods = set()
        while True:
            w = self.peek_ident()
            if w in allowed:
                self.ident()
                mods.add(w)
            else:
                return mods

    # ---------------------------------------------------------- expressions
    def expr(self):
        left = self.and_expr()
        while self.accept("or"):
            left = ("or", left, self.and_expr())
        return left

    def and_expr(self):
        left = self.not_expr()
        while self.accept("and"):
            left = ("and", left, self.not_expr())
        return left

    def not_expr(self):
        if self.accept("not"):
            return ("not", self.not_expr())
        return self.cmp_expr()

    def cmp_expr(self):
        left = self.bit_or()
        for op in _CMP_OPS:
            if self.accept(op):
                return ("cmp", op, left, self.bit_or())
        for op in _STR_OPS:
            if self.accept(op):
                if op == "matches":
                    src, fl = self.regex_lit()
                    try:
                        rx = re.compile(src, (re.I if "i" in fl else 0) | (re.S if "s" in fl else 0))
                    except re.error as e:
                        self.err(f"invalid regular expression: {e}")
                    return ("matches", left, rx)
                return ("strop", op, left, self.bit_or())
        return left

    def bit_or(self):
        left = self.bit_xor()
        while self.peek("|"):
            self.i += 1
            left = ("arith", "|", left, self.bit_xor())
        return left

    def bit_xor(self):
        left = self.bit_and()
        while self.accept("^"):
            left = ("arith", "^", left, self.bit_and())
        return left

    def bit_and(self):
        left = self.shift()
        while self.accept("&"):
            left = ("arith", "&", left, self.shift())
        return left

    def shift(self):
        left = self.add()
        while True:
            if self.accept("<<"):
                left = ("arith", "<<", left, self.add())
            elif self.accept(">>"):
                left = ("arith", ">>", left, self.add())
            else:
                return left

    def add(self):
        left = self.mul()
        while True:
            self.ws()
            c = self.s[self.i:self.i + 1]
            if c in ("+", "-"):
                self.i += 1
                left = ("arith", c, left, self.mul())
            else:
                return left

    def mul(self):
        left = self.unary()
        while True:
            self.ws()
            c = self.s[self.i:self.i + 1]
            if c in ("*", "\\", "%"):
                self.i += 1
                left = ("arith", c, left, self.unary())
            else:
                return left

    def unary(self):
        self.ws()
        if self.s[self.i:self.i + 1] == "-" and not self.s.startswith("->", self.i):
            self.i += 1
            return ("neg", self.unary())
        if self.s[self.i:self.i + 1] == "~":
            self.i += 1
            return ("bnot", self.unary())
        return self.primary()

    def _range(self):
        self.expect("(")
        lo = self.add()
        self.expect("..")
        hi = self.add()
        self.expect(")")
        return lo, hi

    def _string_ref(self, sigil: str) -> str:
        m = re.compile(r"[A-Za-z0-9_]*\*?").match(self.s, self.i)
        self.i = m.end()
        sid = m.group(0)
        if sid.endswith("*"):
            self.err("wildcards are only allowed inside 'of (...)'")
        if not sid:
            self.err(f"anonymous {sigil} references are only allowed inside a for loop", LiteUnsupported)
        if sid not in self._cur_strings:
            self.err(f"undefined string identifier {sigil}{sid}")
        return sid

    def _string_set(self) -> list[str]:
        if self.accept("them"):
            if not self._cur_strings:
                self.err("'them' used but the rule has no strings")
            return list(self._cur_strings)
        self.expect("(")
        out: list[str] = []
        while True:
            self.expect("$")
            m = re.compile(r"[A-Za-z0-9_]*\*?").match(self.s, self.i)
            self.i = m.end()
            name = m.group(0)
            if name.endswith("*"):
                pre = name[:-1]
                hits = [k for k in self._cur_strings if k.startswith(pre) and not k.startswith("_anon")] \
                    if pre else list(self._cur_strings)
                if not hits:
                    self.err(f"no strings match ${name}")
                out += hits
            else:
                if name not in self._cur_strings:
                    self.err(f"undefined string identifier ${name}")
                out.append(name)
            if not self.accept(","):
                break
        self.expect(")")
        return list(dict.fromkeys(out))

    def primary(self):
        self.ws()
        s = self.s
        c = s[self.i:self.i + 1]
        if c == "(":
            self.i += 1
            e = self.expr()
            self.expect(")")
            return e
        if c == '"':
            return ("const", self.string_lit())
        if c == "$":
            self.i += 1
            sid = self._string_ref("$")
            if self.accept("at"):
                return ("at", sid, self.add())
            if self.accept("in"):
                lo, hi = self._range()
                return ("in", sid, lo, hi)
            return ("str", sid)
        if c == "#":
            self.i += 1
            sid = self._string_ref("#")
            if self.accept("in"):
                lo, hi = self._range()
                return ("count_in", sid, lo, hi)
            return ("count", sid)
        if c in ("@", "!"):
            self.i += 1
            sid = self._string_ref(c)
            idx = ("const", 1)
            if self.accept("["):
                idx = self.add()
                self.expect("]")
            return ("offset" if c == "@" else "length", sid, idx)
        if c == "/":
            self.err("a regular expression is only allowed after 'matches'")
        # quantifier "N of" / "N% of"
        save = self.i
        n = self.number()
        if n is not None:
            pct = self.accept("%")
            if self.accept("of"):
                return ("of", ("pct" if pct else "n", n), self._string_set())
            if pct:
                self.err("expected 'of' after a percentage")
            self.i = save
            return ("const", self.number())
        w = self.peek_ident()
        if w is None:
            self.err(f"unexpected '{s[self.i:self.i + 10]}'")
        if w in ("any", "all", "none"):
            self.ident()
            self.expect("of")
            return ("of", (w, 0), self._string_set())
        if w == "for":
            self.err("'for' loops need native YARA", LiteUnsupported)
        if w == "entrypoint":
            self.err("'entrypoint' is deprecated - use the pe module with native YARA", LiteUnsupported)
        self.ident()
        if w == "true":
            return ("const", True)
        if w == "false":
            return ("const", False)
        if w == "filesize":
            return ("filesize",)
        if w == "them":
            self.err("'them' must follow 'of'")
        if w in _INT_FUNCS:
            self.expect("(")
            off = self.add()
            self.expect(")")
            return ("intfn", w, off)
        if self.peek("."):
            if w in self.imports:
                self.err(f"module '{w}' needs native YARA (pip install yara-python)", LiteUnsupported)
            self.err(f"unknown module '{w}' (missing import?)")
        if w in self.known_rules:
            return ("rule", w)
        if w in self.externals:
            return ("ext", w)
        if w in self.imports:
            self.err(f"module '{w}' needs native YARA (pip install yara-python)", LiteUnsupported)
        self.err(f"undefined identifier '{w}'")


# ====================================================================== evaluation
class _Ctx:
    __slots__ = ("data", "matches", "externals", "results")

    def __init__(self, data: bytes, matches: dict, externals: dict, results: dict):
        self.data, self.matches, self.externals, self.results = data, matches, externals, results


def _truthy(v) -> bool:
    if v is UNDEF:
        return False
    if isinstance(v, bytes):
        return len(v) > 0
    return bool(v)


def _ev(n, c: _Ctx):
    op = n[0]
    if op == "const":
        return n[1]
    if op == "and":
        return _truthy(_ev(n[1], c)) and _truthy(_ev(n[2], c))
    if op == "or":
        return _truthy(_ev(n[1], c)) or _truthy(_ev(n[2], c))
    if op == "not":
        v = _ev(n[1], c)
        return UNDEF if v is UNDEF else not _truthy(v)
    if op == "str":
        return bool(c.matches[n[1]])
    if op == "at":
        off = _ev(n[2], c)
        return off is not UNDEF and any(o == off for o, _ in c.matches[n[1]])
    if op == "in":
        lo, hi = _ev(n[2], c), _ev(n[3], c)
        return UNDEF not in (lo, hi) and any(lo <= o <= hi for o, _ in c.matches[n[1]])
    if op == "count":
        return len(c.matches[n[1]])
    if op == "count_in":
        lo, hi = _ev(n[2], c), _ev(n[3], c)
        return UNDEF if UNDEF in (lo, hi) else sum(1 for o, _ in c.matches[n[1]] if lo <= o <= hi)
    if op in ("offset", "length"):
        i = _ev(n[2], c)
        lst = c.matches[n[1]]
        if i is UNDEF or not isinstance(i, int) or i < 1 or i > len(lst):
            return UNDEF
        return lst[i - 1][0 if op == "offset" else 1]
    if op == "of":
        (kind, num), ids = n[1], n[2]
        hit = sum(1 for s in ids if c.matches[s])
        if kind == "any":
            return hit >= 1
        if kind == "all":
            return hit == len(ids)
        if kind == "none":
            return hit == 0
        if kind == "pct":
            return hit * 100 >= num * len(ids)
        return hit >= num
    if op == "filesize":
        return len(c.data)
    if op == "intfn":
        off = _ev(n[2], c)
        fmt, size = _INT_FUNCS[n[1]]
        if off is UNDEF or not isinstance(off, int) or off < 0 or off + size > len(c.data):
            return UNDEF
        return struct.unpack_from(fmt, c.data, off)[0]
    if op == "rule":
        return c.results.get(n[1], False)
    if op == "ext":
        v = c.externals.get(n[1], UNDEF)
        return v.encode("utf-8", "surrogateescape") if isinstance(v, str) else v
    if op == "neg":
        v = _ev(n[1], c)
        return UNDEF if v is UNDEF else -v
    if op == "bnot":
        v = _ev(n[1], c)
        return UNDEF if v is UNDEF else ~v
    if op == "arith":
        a, b = _ev(n[2], c), _ev(n[3], c)
        if a is UNDEF or b is UNDEF or not isinstance(a, int) or not isinstance(b, int):
            return UNDEF
        o = n[1]
        try:
            return {"+": lambda: a + b, "-": lambda: a - b, "*": lambda: a * b,
                    "\\": lambda: int(a / b) if b else UNDEF, "%": lambda: a % b if b else UNDEF,
                    "&": lambda: a & b, "|": lambda: a | b, "^": lambda: a ^ b,
                    "<<": lambda: a << b if 0 <= b < 64 else 0, ">>": lambda: a >> b if 0 <= b < 64 else 0}[o]()
        except (OverflowError, ValueError):
            return UNDEF
    if op == "cmp":
        a, b = _ev(n[2], c), _ev(n[3], c)
        if a is UNDEF or b is UNDEF:
            return False
        if isinstance(a, bool):
            a = int(a)
        if isinstance(b, bool):
            b = int(b)
        if type(a) is not type(b) and not (isinstance(a, int) and isinstance(b, int)):
            return False
        o = n[1]
        return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[o]
    if op == "strop":
        a, b = _ev(n[2], c), _ev(n[3], c)
        if not isinstance(a, bytes) or not isinstance(b, bytes):
            return False
        o = n[1]
        if o.startswith("i"):
            a, b, o = a.lower(), b.lower(), o[1:]
        return {"contains": b in a, "startswith": a.startswith(b), "endswith": a.endswith(b),
                "equals": a == b}[o]
    if op == "matches":
        a = _ev(n[1], c)
        if not isinstance(a, bytes):
            return False
        return n[2].search(a.decode("utf-8", "surrogateescape")) is not None
    raise AssertionError(f"unknown node {op}")                      # pragma: no cover


# ====================================================================== public API
class LiteRules:
    """Compiled rules - same spirit as yara.Rules: .match(data=..., externals=...)."""

    def __init__(self, rules: list[LiteRule], externals: dict):
        self.rules = rules
        self.externals = dict(externals)

    def __iter__(self):
        return iter(self.rules)

    def match(self, data: bytes, externals: dict | None = None) -> list[LiteMatch]:
        ext = dict(self.externals)
        if externals:
            ext.update(externals)
        scan = _DataScan(data)
        out: list[LiteMatch] = []
        by_ns: dict[str, dict[str, bool]] = {}
        global_fail: set[str] = set()
        for r in self.rules:
            matches = _LazyMatches(r.strings, scan)
            results = by_ns.setdefault(r.namespace, {})
            ok = _truthy(_ev(r.condition, _Ctx(data, matches, ext, results)))
            results[r.name] = ok
            if r.is_global and not ok:
                global_fail.add(r.namespace)
            if ok and not r.private:
                strs = []
                for sid, ls in r.strings.items():
                    if ls.private:
                        continue
                    for off, ln in matches[sid][:20]:
                        strs.append(("$" + (sid if not sid.startswith("_anon") else ""), off, ln,
                                     data[off:off + min(ln, 64)]))
                out.append(LiteMatch(r.name, r.namespace, r.tags, r.meta, strs))
        if global_fail:
            out = [m for m in out if m.namespace not in global_fail]
        return out


class _DataScan:
    """Finds string matches on demand and remembers them for every rule that shares the string."""

    def __init__(self, data: bytes):
        self.data = data
        self._lower: bytes | None = None
        self._cache: dict[int, list[tuple[int, int]]] = {}

    @property
    def lower(self) -> bytes:
        if self._lower is None:
            self._lower = self.data.lower()
        return self._lower

    def find(self, ls: LiteString) -> list[tuple[int, int]]:
        key = id(ls.regex)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        found: list[tuple[int, int]] = []
        if ls.atoms is None or any((self.lower if nc else self.data).find(nd) >= 0 for nd, nc in ls.atoms):
            buf = self.lower if ls.on_lower else self.data
            rx, pos, n = ls.regex, 0, len(buf)
            while pos <= n and len(found) < MAX_MATCHES_PER_STRING:
                m = rx.search(buf, pos)
                if m is None:
                    break
                found.append((m.start(), m.end() - m.start()))
                pos = m.start() + 1                     # overlapping matches, like YARA
        self._cache[key] = found
        return found


class _LazyMatches:
    __slots__ = ("strings", "scan", "_got")

    def __init__(self, strings: dict[str, LiteString], scan: _DataScan):
        self.strings, self.scan, self._got = strings, scan, {}

    def __getitem__(self, sid: str) -> list[tuple[int, int]]:
        v = self._got.get(sid)
        if v is None:
            v = self._got[sid] = self.scan.find(self.strings[sid])
        return v


def compile_sources(sources: dict[str, str], externals: dict | None = None) -> LiteRules:
    """sources: {namespace: rule text}. Raises LiteError / LiteUnsupported with a line number."""
    externals = externals or {}
    all_rules: list[LiteRule] = []
    for ns, text in sources.items():
        p = _Parser(text, ns, externals, {})
        try:
            all_rules += p.parse()
        except RecursionError as e:
            raise LiteError(f"line {p.line}: expression is nested too deeply") from e
    return LiteRules(all_rules, externals)


def rule_names(text: str) -> list[str]:
    """Rule names declared in a source text (works without compiling)."""
    clean = re.sub(r"//[^\n]*|/\*.*?\*/", " ", text, flags=re.S)
    clean = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', clean)
    return re.findall(r"(?:^|[\s}])(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)", clean)
