"""
Cyber Hub Backend - Small PDF writer (Part 19)
Developed by Syed Muhammad Tayyab

Just enough PDF 1.4 to produce clean reports without any extra package: A4 pages, the two built-in Helvetica
fonts (so nothing is embedded and files stay small), text with real width measurement + wrapping, lines, filled
rectangles, score bars, bar charts and tables that continue over page breaks with a repeated header row.
Page streams are Flate-compressed. Every page gets a header band and a footer with the page number.

Text is written in WinAnsi (cp1252); characters outside it are replaced by '?'.
"""
from __future__ import annotations

import zlib
from datetime import datetime

A4 = (595.28, 841.89)

# Helvetica / Helvetica-Bold advance widths for chars 32..126 (Adobe AFM, 1/1000 em)
_W_REG = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556,
          556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278,
          500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469,
          556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500,
          278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]
_W_BOLD = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556,
           556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278,
           556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584,
           556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556,
           333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584]

Color = tuple[float, float, float]
INK: Color = (0.12, 0.15, 0.22)
MUTED: Color = (0.42, 0.47, 0.55)
LINE: Color = (0.86, 0.89, 0.93)
BRAND: Color = (0.11, 0.31, 0.85)
BAND: Color = (0.06, 0.10, 0.20)
ZEBRA: Color = (0.965, 0.973, 0.985)
SEV_COLORS: dict[str, Color] = {"critical": (0.78, 0.11, 0.11), "high": (0.92, 0.35, 0.05), "medium": (0.85, 0.60, 0.02),
                                "low": (0.15, 0.50, 0.85), "info": (0.42, 0.47, 0.55), "ok": (0.09, 0.60, 0.29)}


def score_color(score: float | None) -> Color:
    if score is None:
        return MUTED
    return SEV_COLORS["ok"] if score >= 90 else (0.35, 0.65, 0.20) if score >= 70 else SEV_COLORS["medium"] \
        if score >= 50 else SEV_COLORS["critical"]


def clean(text) -> str:
    """Anything -> one line of cp1252-safe text."""
    s = "" if text is None else str(text)
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    for a, b in (("→", "->"), ("…", "..."), ("✓", "v"), ("✕", "x"), ("‑", "-")):
        s = s.replace(a, b)
    return s.encode("cp1252", "replace").decode("cp1252")


def text_width(text: str, size: float, bold: bool = False) -> float:
    table = _W_BOLD if bold else _W_REG
    total = 0
    for ch in text:
        o = ord(ch)
        total += table[o - 32] if 32 <= o <= 126 else 556
    return total * size / 1000.0


def _split_long(word: str, size: float, width: float, bold: bool) -> list[str]:
    parts, cur = [], ""
    for ch in word:
        if cur and text_width(cur + ch, size, bold) > width:
            parts.append(cur)
            cur = ch
        else:
            cur += ch
    parts.append(cur)
    return parts


def wrap(text: str, size: float, width: float, bold: bool = False, max_lines: int = 0) -> list[str]:
    """Greedy word wrap; words longer than the line are split so long paths never overflow."""
    out: list[str] = []
    for para in str(text if text is not None else "").split("\n"):
        line = ""
        for w in clean(para).split(" "):
            pieces = [w] if text_width(w, size, bold) <= width else _split_long(w, size, width, bold)
            for piece in pieces:
                trial = (line + " " + piece) if line else piece
                if text_width(trial, size, bold) <= width:
                    line = trial
                else:
                    out.append(line)
                    line = piece
        out.append(line)
    if max_lines and len(out) > max_lines:
        out = out[:max_lines]
        last = out[-1]
        while last and text_width(last + "...", size, bold) > width:
            last = last[:-1]
        out[-1] = last + "..."
    return out


def _esc(s: str) -> bytes:
    return clean(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("cp1252", "replace")


def _n(v: float) -> str:
    return f"{v:.2f}".rstrip("0").rstrip(".")


class PDF:
    def __init__(self, title: str, subtitle: str = "", author: str = "Syed Muhammad Tayyab",
                 header_right: str = "", margin: float = 42.0):
        self.title, self.subtitle, self.author, self.header_right = clean(title), clean(subtitle), author, header_right
        self.w, self.h = A4
        self.m = margin
        self.pages: list[list[bytes]] = []
        self.y = 0.0
        self.created = datetime.now()
        self.add_page()

    # ------------------------------------------------------------ low level (PDF origin = bottom-left)
    @property
    def _ops(self) -> list[bytes]:
        return self.pages[-1]

    @property
    def content_width(self) -> float:
        return self.w - 2 * self.m

    def _fill(self, c: Color) -> None:
        self._ops.append(f"{_n(c[0])} {_n(c[1])} {_n(c[2])} rg".encode())

    def _stroke(self, c: Color) -> None:
        self._ops.append(f"{_n(c[0])} {_n(c[1])} {_n(c[2])} RG".encode())

    def rect(self, x: float, top: float, w: float, h: float, color: Color) -> None:
        """Filled rectangle; `top` is measured from the top of the page like every public coordinate here."""
        if w <= 0 or h <= 0:
            return
        self._fill(color)
        self._ops.append(f"{_n(x)} {_n(self.h - top - h)} {_n(w)} {_n(h)} re f".encode())

    def line(self, x1: float, y1: float, x2: float, y2: float, color: Color = LINE, width: float = 0.6) -> None:
        self._stroke(color)
        self._ops.append(f"{_n(width)} w {_n(x1)} {_n(self.h - y1)} m {_n(x2)} {_n(self.h - y2)} l S".encode())

    def text(self, x: float, baseline: float, s: str, size: float = 10, bold: bool = False, color: Color = INK,
             align: str = "left", width: float = 0) -> None:
        s = clean(s)
        if align != "left" and width:
            tw = text_width(s, size, bold)
            x = x + width - tw if align == "right" else x + (width - tw) / 2
        self._fill(color)
        self._ops.append(b"BT /" + (b"F2" if bold else b"F1") + f" {_n(size)} Tf {_n(x)} {_n(self.h - baseline)} Td (".encode()
                         + _esc(s) + b") Tj ET")

    # ------------------------------------------------------------ pages
    def add_page(self) -> None:
        self.pages.append([])
        self.rect(0, 0, self.w, 34, BAND)
        self.text(self.m, 22, "CYBER HUB", 11, True, (1, 1, 1))
        self.text(self.m + 78, 22, self.title, 9, False, (0.75, 0.82, 0.95))
        right = self.header_right or f"Developed by {self.author}"
        self.text(self.m, 22, right, 8, False, (0.75, 0.82, 0.95), "right", self.content_width)
        self.y = 34 + 26

    def ensure(self, height: float) -> bool:
        """Start a new page when `height` more points don't fit. Returns True when a page was added."""
        if self.y + height > self.h - 46:
            self.add_page()
            return True
        return False

    def space(self, h: float) -> None:
        self.y += h

    # ------------------------------------------------------------ blocks
    def cover(self, lines: list[tuple[str, str]]) -> None:
        self.text(self.m, self.y + 14, self.title, 22, True)
        self.y += 24
        if self.subtitle:
            self.text(self.m, self.y + 12, self.subtitle, 11, False, MUTED)
            self.y += 18
        self.line(self.m, self.y + 4, self.w - self.m, self.y + 4, BRAND, 1.4)
        self.y += 16
        for k, v in lines:
            self.text(self.m, self.y + 9, k, 9, False, MUTED)
            self.text(self.m + 110, self.y + 9, v, 9, True)
            self.y += 14
        self.y += 8

    def heading(self, s: str, level: int = 1) -> None:
        size = 14 if level == 1 else 11
        self.ensure(size + 40)
        self.y += 10 if level == 1 else 6
        if level == 1:
            self.rect(self.m, self.y, 3, size + 2, BRAND)
            self.text(self.m + 9, self.y + size - 1, s, size, True)
        else:
            self.text(self.m, self.y + size - 1, s, size, True, (0.2, 0.26, 0.38))
        self.y += size + 9

    def paragraph(self, s: str, size: float = 9.5, color: Color = INK, bold: bool = False, indent: float = 0) -> None:
        for ln in wrap(s, size, self.content_width - indent, bold):
            self.ensure(size + 4)
            self.text(self.m + indent, self.y + size, ln, size, bold, color)
            self.y += size + 3.5
        self.y += 3

    def key_values(self, pairs: list[tuple[str, object]], columns: int = 2) -> None:
        colw = self.content_width / columns
        rows = [pairs[i:i + columns] for i in range(0, len(pairs), columns)]
        for row in rows:
            self.ensure(16)
            for i, (k, v) in enumerate(row):
                x = self.m + i * colw
                self.text(x, self.y + 9, str(k), 8.5, False, MUTED)
                val = wrap(str(v if v not in (None, "") else "-"), 9, colw - 108, True, 1)[0]
                self.text(x + 100, self.y + 9, val, 9, True)
            self.y += 15
        self.y += 5

    def score_banner(self, score: int | None, grade: str | None, label: str, note: str = "") -> None:
        self.ensure(70)
        c = score_color(score)
        self.rect(self.m, self.y, self.content_width, 58, ZEBRA)
        self.rect(self.m, self.y, 5, 58, c)
        self.text(self.m + 18, self.y + 38, "-" if score is None else str(score), 30, True, c)
        self.text(self.m + 18 + text_width("-" if score is None else str(score), 30, True) + 4, self.y + 38, "/ 100", 10,
                  False, MUTED)
        self.text(self.m + 130, self.y + 24, label, 13, True)
        if grade:
            self.text(self.m + 130 + text_width(clean(label), 13, True) + 8, self.y + 24, f"Grade {grade}", 10, True, c)
        if note:
            self.text(self.m + 130, self.y + 42, wrap(note, 9, self.content_width - 150, False, 1)[0], 9, False, MUTED)
        self.y += 70

    def bars(self, items: list[tuple[str, float | None, str]], maximum: float = 100, label_width: float = 150,
             colors: list[Color] | None = None) -> None:
        """Horizontal bars: (label, value, text shown at the end)."""
        track = self.content_width - label_width - 70
        for i, (label, value, shown) in enumerate(items):
            self.ensure(17)
            self.text(self.m, self.y + 9.5, wrap(label, 9, label_width - 6, False, 1)[0], 9)
            self.rect(self.m + label_width, self.y + 2, track, 8, LINE)
            if value is not None and maximum > 0:
                c = colors[i] if colors and i < len(colors) else (score_color(value) if maximum == 100 else BRAND)
                self.rect(self.m + label_width, self.y + 2, max(1.5, track * min(value, maximum) / maximum), 8, c)
            self.text(self.m + label_width + track + 8, self.y + 9.5, shown, 9, True)
            self.y += 16
        self.y += 6

    def column_chart(self, points: list[tuple[str, float]], height: float = 90, color: Color = BRAND,
                     title: str = "") -> None:
        if not points:
            return
        self.ensure(height + 40)
        if title:
            self.text(self.m, self.y + 9, title, 9, True, MUTED)
            self.y += 16
        top = max(v for _, v in points) or 1
        n = len(points)
        gap = 3 if n <= 31 else 1
        bw = (self.content_width - gap * (n - 1)) / n
        base = self.y + height
        self.line(self.m, base, self.w - self.m, base)
        for i, (label, v) in enumerate(points):
            x = self.m + i * (bw + gap)
            bh = (height - 12) * v / top
            self.rect(x, base - bh, bw, bh, color)
            if n <= 16 and v:
                self.text(x, base - bh - 3, _n(round(v, 1)), 7, False, MUTED, "center", bw)
            if n <= 16 or i % max(1, n // 8) == 0:
                self.text(x, base + 10, label, 7, False, MUTED, "center" if n <= 16 else "left", bw)
        self.y = base + 22

    def table(self, columns: list[dict], rows: list[list], size: float = 8.5, max_lines: int = 3,
              empty: str = "Nothing to show") -> None:
        """columns: [{"title", "width" (share of the page, optional), "align", "severity": True -> coloured}]"""
        if not rows:
            self.paragraph(empty, 9, MUTED)
            return
        total = sum(c.get("width", 1) for c in columns)
        widths = [self.content_width * c.get("width", 1) / total for c in columns]
        pad = 4

        def header() -> None:
            self.rect(self.m, self.y, self.content_width, 17, (0.91, 0.93, 0.97))
            x = self.m
            for c, w in zip(columns, widths):
                self.text(x + pad, self.y + 11.5, c["title"], 8, True, (0.25, 0.3, 0.42), c.get("align", "left"),
                          w - 2 * pad)
                x += w
            self.y += 17

        self.ensure(17 + size + 12)
        header()
        for ri, row in enumerate(rows):
            cells = [wrap("" if v is None else str(v), size, w - 2 * pad, False, max_lines) for v, w in zip(row, widths)]
            rh = max(len(c) for c in cells) * (size + 2.5) + 6
            if self.ensure(rh + 2):
                header()
            if ri % 2 == 1:
                self.rect(self.m, self.y, self.content_width, rh, ZEBRA)
            x = self.m
            for c, w, lines, raw in zip(columns, widths, cells, row):
                col = SEV_COLORS.get(str(raw).lower(), INK) if c.get("severity") else INK
                for li, ln in enumerate(lines):
                    self.text(x + pad, self.y + size + 2 + li * (size + 2.5), ln, size, bool(c.get("severity")), col,
                              c.get("align", "left"), w - 2 * pad)
                x += w
            self.y += rh
            self.line(self.m, self.y, self.w - self.m, self.y, LINE, 0.4)
        self.y += 10

    # ------------------------------------------------------------ output
    def render(self) -> bytes:
        total = len(self.pages)
        stamp = self.created.strftime("%d %b %Y %H:%M")
        for i, ops in enumerate(self.pages):
            saved, self.pages = self.pages, [ops]                    # draw the footer into page i
            self.line(self.m, self.h - 36, self.w - self.m, self.h - 36)
            self.text(self.m, self.h - 24, f"Cyber Hub - Developed by {self.author}", 7.5, False, MUTED)
            self.text(self.m, self.h - 24, f"Generated {stamp}", 7.5, False, MUTED, "center", self.content_width)
            self.text(self.m, self.h - 24, f"Page {i + 1} of {total}", 7.5, False, MUTED, "right", self.content_width)
            self.pages = saved
        objs: list[bytes] = []

        def add(body: bytes) -> int:
            objs.append(body)
            return len(objs)

        add(b"<< /Type /Catalog /Pages 2 0 R >>")
        add(b"")                                                     # pages tree, filled below
        f1 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        f2 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        kids = []
        for ops in self.pages:
            data = zlib.compress(b"\n".join(ops), 9)
            cid = add(b"<< /Length " + str(len(data)).encode() + b" /Filter /FlateDecode >>\nstream\n" + data
                      + b"\nendstream")
            pid = add(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_n(self.w)} {_n(self.h)}] /Contents {cid} 0 R "
                      f"/Resources << /Font << /F1 {f1} 0 R /F2 {f2} 0 R >> >> >>".encode())
            kids.append(pid)
        objs[1] = f"<< /Type /Pages /Count {len(kids)} /Kids [{' '.join(f'{k} 0 R' for k in kids)}] >>".encode()
        info = add(b"<< /Title (" + _esc(self.title) + b") /Author (" + _esc(self.author) + b") /Creator (Cyber Hub) "
                   b"/Producer (Cyber Hub PDF writer) /CreationDate (D:" + self.created.strftime("%Y%m%d%H%M%S").encode()
                   + b") >>")
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objs, 1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objs) + 1}\n".encode() + b"0000000000 65535 f \n"
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R /Info {info} 0 R >>\nstartxref\n{xref}\n%%EOF\n").encode()
        return bytes(out)
