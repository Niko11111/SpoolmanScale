#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  SpoolmanScale – Localization (i18n)
#  fit_check.py - what a string really measures on the panel
#  Fork addition – Nanostra (Frédéric Dubus)
# ============================================================
#
# Text width on this device is not a thing to estimate. It is decided by the
# advance widths in the generated font tables, in sixteenths of a pixel, plus
# the kerning classes, and LVGL computes it with integer arithmetic that rounds
# per glyph. This reproduces that arithmetic exactly, from the same tables the
# firmware links, so a translation can be checked before it is flashed.
#
# The reference is lv_font_fmt_txt.c, lv_font_get_glyph_width():
#
#     kv     = (kvalue * kern_scale) >> 4      # 0 across a fallback boundary
#     adv_px = (adv_w + kv + 8) >> 4
#
# letter_space is 0 here: nothing in src/ sets LV_STYLE_TEXT_LETTER_SPACE, and
# the LVGL default is 0.
#
# The fallback boundary matters and is modelled: lv_font_fmt_txt.c applies
# kerning only when a letter and the next one resolve inside the same font, so
# every accented character coming from a supplement loses the kerning on both
# of its sides. The values are mostly negative, so losing them makes text
# marginally WIDER - the safe direction, but measured rather than assumed.
#
# Used as a library by lang_fr.py, and on its own:
#
#   python tools/fit_check.py --measure 16 "Étalonnage"
#   python tools/fit_check.py --grid          the chars-per-budget table
#   python tools/fit_check.py --gate          every NEVER budget in ui_budgets.tsv
# ============================================================
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FONTS = ROOT / "src" / "fonts"
BUDGETS = ROOT / "tools" / "ui_budgets.tsv"

SIZES = (10, 12, 14, 16, 18, 20, 24)
HOST = "lv_font_montserrat_ext_%d"
SUPP = "lv_font_fr_supp_%d"

_GLYPH = re.compile(
    r"\{\s*\.bitmap_index\s*=\s*(\d+)\s*,\s*\.adv_w\s*=\s*(\d+)\s*,"
    r"\s*\.box_w\s*=\s*(\d+)\s*,\s*\.box_h\s*=\s*(\d+)\s*,"
    r"\s*\.ofs_x\s*=\s*(-?\d+)\s*,\s*\.ofs_y\s*=\s*(-?\d+)\s*\}")

_CMAP = re.compile(
    r"\.range_start\s*=\s*(\d+)\s*,\s*\.range_length\s*=\s*(\d+)\s*,"
    r"\s*\.glyph_id_start\s*=\s*(\d+)\s*,"
    r"\s*\.unicode_list\s*=\s*(\w+)\s*,"
    r"\s*\.glyph_id_ofs_list\s*=\s*(\w+)\s*,"
    r"\s*\.list_length\s*=\s*(\d+)\s*,\s*\.type\s*=\s*(\w+)", re.S)


def _ints(text):
    return [int(v, 0) for v in re.findall(r"0x[0-9a-fA-F]+|-?\d+", text)]


class Font:
    """One generated LVGL font, read for measuring."""

    def __init__(self, path):
        src = path.read_text(encoding="utf-8", errors="replace")
        self.name = path.stem
        body = src.split("glyph_dsc[] = {", 1)[1] if "glyph_dsc[] = {" in src else ""
        self.adv = [int(m[1]) for m in _GLYPH.findall(body)]
        self.line_height = int(re.search(r"\.line_height\s*=\s*(\d+)", src).group(1))
        self.base_line = int(re.search(r"\.base_line\s*=\s*(-?\d+)", src).group(1))
        lists = {n: _ints(v) for n, v in re.findall(
            r"static const uint(?:8|16)_t (\w+)\[\] = \{(.*?)\};", src, re.S)}

        # code point -> glyph id
        self.cmap = {}
        for a, b, c, d, e, f, kind in _CMAP.findall(src):
            start, length, gid0 = int(a), int(b), int(c)
            if kind.endswith("FORMAT0_TINY"):
                for i in range(length):
                    self.cmap[start + i] = gid0 + i
            elif kind.endswith("FORMAT0_FULL"):
                for i, o in enumerate(lists.get(e, [])[:length]):
                    if o or i == 0:
                        self.cmap[start + i] = gid0 + o
            elif kind.endswith("SPARSE_TINY"):
                for i, off in enumerate(lists.get(d, [])):
                    self.cmap[start + off] = gid0 + i
            elif kind.endswith("SPARSE_FULL"):
                uni, ofs = lists.get(d, []), lists.get(e, [])
                for i, off in enumerate(uni):
                    self.cmap[start + off] = gid0 + (ofs[i] if i < len(ofs) else i)

        # Kerning, fast-format (classes). Absent on a font with one glyph class.
        self.kern_scale = 0
        self.left_cls = self.right_cls = []
        self.kern_vals = []
        self.right_cnt = 0
        m = re.search(r"\.kern_scale\s*=\s*(\d+)", src)
        if m:
            self.kern_scale = int(m.group(1))
        for name, attr in (("kern_left_class_mapping", "left_cls"),
                           ("kern_right_class_mapping", "right_cls")):
            mm = re.search(r"static const uint8_t %s\[\] =\s*\{(.*?)\};" % name,
                           src, re.S)
            if mm:
                setattr(self, attr, _ints(mm.group(1)))
        mm = re.search(r"static const int8_t kern_class_values\[\] =\s*\{(.*?)\};",
                       src, re.S)
        if mm:
            self.kern_vals = _ints(mm.group(1))
        mm = re.search(r"\.right_class_cnt\s*=\s*(\d+)", src)
        if mm:
            self.right_cnt = int(mm.group(1))

    def gid(self, ch):
        return self.cmap.get(ord(ch))

    def kern(self, gid_a, gid_b):
        """The raw class value between two glyphs of THIS font, 0 if none."""
        if not self.kern_vals or not self.right_cnt:
            return 0
        if gid_a >= len(self.left_cls) or gid_b >= len(self.right_cls):
            return 0
        lc, rc = self.left_cls[gid_a], self.right_cls[gid_b]
        if not lc or not rc:
            return 0
        i = (lc - 1) * self.right_cnt + (rc - 1)
        return self.kern_vals[i] if i < len(self.kern_vals) else 0


_CACHE = {}


def pair(size):
    """(host, supplement or None) for a size, read once."""
    if size not in _CACHE:
        host = Font(FONTS / ("%s.c" % (HOST % size)))
        sp = FONTS / ("%s.c" % (SUPP % size))
        _CACHE[size] = (host, Font(sp) if sp.exists() else None)
    return _CACHE[size]


def width(text, size):
    """Rendered width in whole pixels, exactly as LVGL would measure it.

    Returns (pixels, missing) where missing lists the characters no font in the
    chain can draw - each of those renders as a hollow rectangle.
    """
    host, supp = pair(size)
    missing = []
    resolved = []          # (font, gid) per character, font None when absent
    for ch in text:
        g = host.gid(ch)
        if g is not None:
            resolved.append((host, g))
            continue
        g = supp.gid(ch) if supp else None
        if g is not None:
            resolved.append((supp, g))
            continue
        missing.append(ch)
        resolved.append((None, None))

    total = 0
    for i, (font, g) in enumerate(resolved):
        if font is None:
            # lv_font.c charges the placeholder box: line_height/2 + 2
            total += host.line_height // 2 + 2
            continue
        kv = 0
        if i + 1 < len(resolved):
            nfont, ng = resolved[i + 1]
            # Kerning only inside one font: a fallback boundary drops it.
            if nfont is font:
                kv = (font.kern(g, ng) * font.kern_scale) >> 4
        total += (font.adv[g] + kv + 8) >> 4
    return total, missing


# --------------------------------------------------------------------------
#  Budgets
# --------------------------------------------------------------------------
def read_budgets():
    """tools/ui_budgets.tsv -> list of dicts.

    Lives outside src/ on purpose: it is fork bookkeeping, it is never compiled,
    and upstream never has to see a merge conflict on it.
    """
    rows = []
    if not BUDGETS.exists():
        return rows
    for n, line in enumerate(BUDGETS.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        f = line.split("\t")
        if len(f) < 4:
            print("  ui_budgets.tsv:%d malformed, skipped" % n)
            continue
        rows.append({"id": f[0].strip(), "font": int(f[1]), "budget": int(f[2]),
                     "mode": f[3].strip(), "site": f[4].strip() if len(f) > 4 else ""})
    return rows


def segments(text):
    """A string split on its hard line breaks - each is measured on its own."""
    return text.split("\\n")


def gate(strings, probe=None):
    """Every NEVER budget must hold. strings: {id: french text}.

    probe() turns a stored value into what the panel really draws - an
    {LV_SYMBOL_X} marker is seventeen characters here and one glyph there, and
    measuring the marker was good for a 140 px false alarm. lang_fr supplies it;
    without it the markers are simply dropped, which is the safe direction.
    """
    if probe is None:
        probe = lambda t: re.sub(r"\{[A-Za-z_]\w*\}", "", t)
    bad = measured = 0
    rows = read_budgets()
    if not rows:
        print("  no tools/ui_budgets.tsv yet - nothing to gate")
        return True
    for b in rows:
        if b["mode"] != "NEVER":
            continue
        # A row with no French text to measure gates nothing. Skipping it in
        # silence is how two misspelt ids once sat here under a green summary.
        if not strings.get(b["id"]):
            print("  %-34s no French text for this id - misspelt, or not translated"
                  % b["id"])
            bad += 1
            continue
        measured += 1
        for seg in segments(strings[b["id"]]):
            w, miss = width(probe(seg), b["font"])
            if miss:
                print("  %-34s missing glyph %s" % (b["id"], " ".join(miss)))
                bad += 1
            if w > b["budget"]:
                print("  %-34s %d px > %d px  (f%d)  %s"
                      % (b["id"], w, b["budget"], b["font"], b["site"]))
                bad += 1
    print("  %d NEVER budget(s) measured, %d violation(s)" % (measured, bad))
    return bad == 0


FRENCH_FREQ = "eaisnrtoulcdpmvqfbghjxyzwk"


def grid():
    """Characters that fit a budget, per font size. Rough but useful while
    writing: real checking goes through width() on the actual string."""
    budgets = (42, 46, 84, 94, 124, 132, 144, 170, 204, 228, 262, 290, 320, 360, 464)
    sample = (FRENCH_FREQ * 6)[:60]
    print("  budget ", "".join("%5d" % b for b in budgets))
    for size in SIZES:
        w, _ = width(sample, size)
        per = w / len(sample)
        print("  f%-6d" % size, "".join("%5d" % int(b / per) for b in budgets))
    print("\n  (frequency-weighted average, spaces excluded - indicative)")


def _lang_fr():
    """lang_fr, imported late: it imports this module in turn, inside check()."""
    try:
        import lang_fr
    except ImportError:
        sys.path.insert(0, str(ROOT / "tools"))
        import lang_fr
    return lang_fr


def main():
    ap = argparse.ArgumentParser(description="Measure text as LVGL would.")
    ap.add_argument("--measure", nargs=2, metavar=("SIZE", "TEXT"))
    ap.add_argument("--grid", action="store_true")
    ap.add_argument("--gate", action="store_true")
    a = ap.parse_args()
    if a.measure:
        # Written the way the working file stores it, an {LV_SYMBOL_X} marker is
        # measured as the icon it stands for, not as seventeen letters.
        size, text = int(a.measure[0]), a.measure[1]
        w, miss = width(_lang_fr().probe_text(text), size)
        print("%s  f%d  ->  %d px%s"
              % (repr(text), size, w,
                 "   MISSING: " + " ".join(miss) if miss else ""))
        return 0
    if a.grid:
        grid()
        return 0
    if a.gate:
        lang_fr = _lang_fr()
        strings = lang_fr.french_strings()
        if not lang_fr.symbol_chars() and any("{LV_SYMBOL_" in s for s in strings.values()):
            print("  LVGL is not unpacked - build the firmware once; icons would"
                  " count as zero pixels")
            return 1
        return 0 if gate(strings, lang_fr.probe_text) else 1
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
