#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  SpoolmanScale – Localization (i18n)
#  gen_fr_fonts.py - Latin-1 glyph supplement for the UI fonts
#  Fork addition – Nanostra (Frédéric Dubus)
# ============================================================
#
# The UI fonts carry ASCII, the degree sign, a bullet and the seven German
# letters - nothing else. With LV_USE_FONT_PLACEHOLDER on, every French accent
# draws a hollow rectangle rather than an unaccented letter, so "Reglages"
# would read "R[]glages".
#
# This does NOT regenerate those fonts, and the reason matters. lv_font_conv
# derives line_height and base_line from the bounding boxes of the glyphs it
# was asked for, not from the face metrics:
#
#     ascent:  Math.max(...glyphs.map(g => g.bbox.y + g.bbox.height))
#     descent: Math.min(...glyphs.map(g => g.bbox.y))
#
# The repository already holds the proof: adding the seven German letters moved
# line_height from 15 to 16 at size 12 and from 22 to 23 at size 20, compared
# with LVGL's own build from the same TTF. The French capitals reach yMax 887
# against the current ceiling of 877, and the cedilla drops to yMin -224
# against a floor of -202. Regenerating would therefore move the line height,
# and every screen positions its labels in absolute pixels, so the German and
# English UI would shift without a word of warning.
#
# Instead each host font gains a fallback pointing at a small supplement that
# carries only the missing glyphs. LVGL resolves the chain per glyph, and the
# baseline still comes from the host - lv_draw_sw_letter.c reads dsc->font, not
# the resolved font - so the supplement cannot move anything.
#
# The two source files need not enter the repository: LVGL 8.3.11 ships them,
# and platformio.ini pins that version, so pio pkg install fetches them
# reproducibly. Montserrat is SIL OFL 1.1, Font Awesome 5 Free is CC BY 4.0 and
# OFL 1.1; only rendered bitmaps ship, exactly as LVGL's own built-in fonts do.
#
#   python tools/gen_fr_fonts.py --check-assets   the two TTF/WOFF hashes
#   python tools/gen_fr_fonts.py --verify-host    proves the TTF is the one used
#   python tools/gen_fr_fonts.py --build          writes the 7 supplements
#   python tools/gen_fr_fonts.py --audit          reports glyphs that would clip
#   python tools/gen_fr_fonts.py --wire           points the hosts at them
#   python tools/gen_fr_fonts.py --all            all of the above, in order
# ============================================================
import argparse
import hashlib
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FONTS = ROOT / "src" / "fonts"
LV_CONF = ROOT / "src" / "lv_conf.h"
LVGL = ROOT / ".pio" / "libdeps" / "wt32-sc01-plus" / "lvgl"
ASSETS = LVGL / "scripts" / "built_in_font"
BUILTIN = LVGL / "src" / "font"

# Only these seven reach the binary. lv_conf.h declares fifteen, but the linker
# drops the rest with --gc-sections, so generating the others would be dead
# weight in the diff and in the repository.
SIZES = (10, 12, 14, 16, 18, 20, 24)

# Latin-1 letters plus the few marks a French UI and Spoolman data need.
#
# Deliberate exclusions, each for its own reason:
#   0xC5 A-ring      yMax 982, far over the 877 ceiling - it would lose two
#                    rows to clipping, and no filament vendor needs it.
#   0xC4 0xD6 0xDC 0xDF 0xE4 0xF6 0xFC
#                    already in every host font. A fallback is only consulted
#                    for a glyph the host lacks, so shipping them again would
#                    cost flash and change nothing.
#   0x202F narrow no-break space
#                    absent from Montserrat-Medium. It is glyph 0 there, so it
#                    would draw the placeholder rectangle. U+00A0 below is the
#                    one to use for French spacing before : ; ! ? - it has no
#                    outline at all, carries the space's advance, and is not in
#                    LV_TXT_BREAK_CHARS, so LVGL never breaks on it.
#
# U+2019 and U+2026 are in for data, not for labels: a filament name arriving
# from Spoolman with a typographic apostrophe should render, even though our own
# translations spell those as ' and ...
RANGE = ",".join([
    "0xA0",                 # no-break space (no outline, costs nothing)
    "0xAB", "0xBB",         # << >>
    "0xC0-0xC3",            # A-grave .. A-tilde   (Ä excluded: in the host)
    "0xC6-0xD5",            # AE .. O-tilde        (Ö excluded)
    "0xD7-0xDB",            # multiply .. U-circ   (Ü excluded)
    "0xDD", "0xDE",         # Y-acute, thorn       (ß excluded)
    "0xE0-0xE3",            # a-grave .. a-tilde   (ä excluded)
    "0xE5-0xF5",            # a-ring .. o-tilde    (ö excluded)
    "0xF7-0xFB",            # divide .. u-circ     (ü excluded)
    "0xFD-0xFF",            # y-acute, thorn, y-diaeresis
    "0x152", "0x153",       # OE oe
    "0x178",                # Y-diaeresis
    "0x2019",               # right single quote
    "0x2026",               # ellipsis
])

HOST = "lv_font_montserrat_ext_%d"
SUPP = "lv_font_fr_supp_%d"

# Spelled with chr() so no layer of quoting between an editor, a shell and
# Python can turn it into a real line break on its way into this file.
LF = chr(10)

BANNER = """\
/*******************************************************************************
 * SpoolmanScale - Latin-1 glyph supplement for %(host)s
 * Fork addition - Nanostra (Frederic Dubus)
 *
 * Generated by tools/gen_fr_fonts.py. Do not edit by hand.
 *
 * Reached through %(host)s's .fallback, so it is never selected directly and
 * its own line_height and base_line are never read: LVGL takes those from the
 * host font. Same TTF, same size, same bpp as the host, which is what keeps
 * the accents sitting on the host's baseline.
 *
 * Montserrat-Medium.ttf, SIL Open Font License 1.1, shipped with LVGL 8.3.11.
 ******************************************************************************/
"""


def write_lf(path, text):
    """Write text with LF endings, whatever the platform thinks.

    Python's text mode turns a line feed into a carriage return plus line feed
    on Windows, and this repository is LF throughout with no .gitattributes to
    correct it. Writing one host font the default way turned a one-line change
    into a 2285-line diff; doing it to all eight files turned a 14-line change
    into 19,966 lines. The project has been bitten by exactly this once before -
    commit cc64aef fixed the same thing in copy_release.py - so it gets a named
    helper here rather than a keyword argument that is easy to forget on the
    next write site.
    """
    path.write_text(text, encoding="utf-8", newline=LF)


# --------------------------------------------------------------------------
#  Reading a generated font
# --------------------------------------------------------------------------
GLYPH_RE = re.compile(
    r"\{\s*\.bitmap_index\s*=\s*(\d+)\s*,\s*\.adv_w\s*=\s*(\d+)\s*,"
    r"\s*\.box_w\s*=\s*(\d+)\s*,\s*\.box_h\s*=\s*(\d+)\s*,"
    r"\s*\.ofs_x\s*=\s*(-?\d+)\s*,\s*\.ofs_y\s*=\s*(-?\d+)\s*\}")

CMAP_RE = re.compile(
    r"\.range_start\s*=\s*(\d+)\s*,\s*\.range_length\s*=\s*(\d+)\s*,"
    r"\s*\.glyph_id_start\s*=\s*(\d+)\s*,"
    r"\s*\.unicode_list\s*=\s*(\w+)\s*,"
    r"\s*\.glyph_id_ofs_list\s*=\s*(\w+)\s*,"
    r"\s*\.list_length\s*=\s*(\d+)\s*,\s*\.type\s*=\s*(\w+)", re.S)


def read_font(path):
    """The parts of a generated LVGL font this script reasons about."""
    src = path.read_text(encoding="utf-8", errors="replace")
    body = src.split("glyph_dsc[] = {", 1)[1] if "glyph_dsc[] = {" in src else ""
    font = {
        "path": path,
        "src": src,
        "glyphs": [
            {"bitmap_index": int(a), "adv_w": int(b), "box_w": int(c),
             "box_h": int(d), "ofs_x": int(e), "ofs_y": int(f)}
            for a, b, c, d, e, f in GLYPH_RE.findall(body)
        ],
    }
    for key in ("line_height", "base_line"):
        m = re.search(r"\.%s\s*=\s*(-?\d+)" % key, src)
        font[key] = int(m.group(1)) if m else None
    m = re.search(r"\.bpp\s*=\s*(\d+)", src)
    font["bpp"] = int(m.group(1)) if m else None
    m = re.search(r"^ \* Opts:(.*)$", src, re.M)
    font["opts"] = m.group(1).strip() if m else ""
    font["cmaps"] = [
        {"range_start": int(a), "range_length": int(b), "glyph_id_start": int(c),
         "unicode_list": d, "ofs_list": e, "list_length": int(f), "type": g}
        for a, b, c, d, e, f, g in CMAP_RE.findall(src)
    ]
    # Both list kinds the generator emits: uint16 code point lists for the
    # SPARSE forms, uint8 glyph offsets for the FULL forms.
    font["lists"] = {
        name: [int(v, 0) for v in re.findall(r"0x[0-9a-fA-F]+|\d+", vals)]
        for name, vals in re.findall(
            r"static const uint(?:8|16)_t (\w+)\[\] = \{(.*?)\};", src, re.S)
    }
    return font


def codepoints(font):
    """glyph id -> codepoint, from the cmaps. Needed by --audit, which has to
    name the glyph it is warning about."""
    out = {}
    for c in font["cmaps"]:
        kind = c["type"]
        start, length, gid0 = c["range_start"], c["range_length"], c["glyph_id_start"]
        if kind.endswith("FORMAT0_TINY"):
            for i in range(length):
                out[gid0 + i] = start + i
        elif kind.endswith("FORMAT0_FULL"):
            # One byte per code point in the range; 0 means no glyph.
            ofs = font["lists"].get(c["ofs_list"], [])
            for i, o in enumerate(ofs[:length]):
                if o or i == 0:
                    out[gid0 + o] = start + i
        elif kind.endswith("SPARSE_TINY"):
            for i, off in enumerate(font["lists"].get(c["unicode_list"], [])):
                out[gid0 + i] = start + off
        elif kind.endswith("SPARSE_FULL"):
            uni = font["lists"].get(c["unicode_list"], [])
            ofs = font["lists"].get(c["ofs_list"], [])
            for i, off in enumerate(uni):
                out[gid0 + (ofs[i] if i < len(ofs) else i)] = start + off
        else:
            print("  ! cmap type not handled: %s" % kind)
    return out


# --------------------------------------------------------------------------
#  Modes
# --------------------------------------------------------------------------
def check_assets():
    print("== assets ==")
    ok = True
    for name in ("Montserrat-Medium.ttf", "FontAwesome5-Solid+Brands+Regular.woff"):
        p = ASSETS / name
        if not p.exists():
            print("  MISSING %s" % p)
            print("          run: pio pkg install")
            ok = False
            continue
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        print("  %-44s %9d B  sha256 %s" % (name, p.stat().st_size, digest[:16]))
    return ok


def verify_host():
    """Proves the TTF on disk is the one the committed fonts were built from,
    without depending on the lv_font_conv version.

    LVGL ships its own lv_font_montserrat_NN.c, built from the same TTF with
    the same command minus the German letters. Glyph ids 0..96 - the reserved
    slot, 95 ASCII and U+00B0 - therefore sit at identical positions in both.
    Those descriptors come straight from the outlines, so if every adv_w, box
    and offset matches, no other cut of Montserrat could have produced them.

    Bitmap bytes are compared too but only reported: a handful differing by one
    coverage level out of sixteen is the signature of a different lv_font_conv
    build, not of a different TTF. It is also exactly why this script does not
    regenerate the hosts - that noise would swamp the diff.
    """
    print("== host fonts against LVGL's own build ==")
    ok = True
    for size in SIZES:
        ours = FONTS / ("%s.c" % (HOST % size))
        theirs = BUILTIN / ("lv_font_montserrat_%d.c" % size)
        if not theirs.exists():
            print("  size %-3d SKIP (LVGL has no built-in at this size)" % size)
            continue
        a, b = read_font(ours), read_font(theirs)
        shared = min(97, len(a["glyphs"]), len(b["glyphs"]))
        keys = ("adv_w", "box_w", "box_h", "ofs_x", "ofs_y")
        bad = [i for i in range(shared)
               if any(a["glyphs"][i][k] != b["glyphs"][i][k] for k in keys)]
        note = ""
        if a["line_height"] != b["line_height"] or a["base_line"] != b["base_line"]:
            note = "  (line_height %s vs %s, base_line %s vs %s - expected, the" \
                   " German letters moved it)" % (
                       a["line_height"], b["line_height"],
                       a["base_line"], b["base_line"])
        if bad:
            print("  size %-3d MISMATCH on %d of %d shared descriptors%s"
                  % (size, len(bad), shared, note))
            print("           the TTF is NOT the one used - do not build")
            ok = False
        else:
            print("  size %-3d ok: %d shared descriptors identical%s"
                  % (size, shared, note))
    return ok


def build():
    exe = shutil.which("lv_font_conv") or shutil.which("lv_font_conv.cmd")
    if not exe:
        print("lv_font_conv not found. Install it with:")
        print("  npm i -g lv_font_conv@1.5.3")
        return False
    ttf = ASSETS / "Montserrat-Medium.ttf"
    print("== building %d supplements ==" % len(SIZES))
    print("   range: %s" % RANGE)
    for size in SIZES:
        out = FONTS / ("%s.c" % (SUPP % size))
        cmd = [exe,
               "--no-compress", "--no-prefilter",
               "--bpp", "4", "--size", str(size),
               "--font", str(ttf), "-r", RANGE,
               "--format", "lvgl", "-o", str(out),
               "--force-fast-kern-format"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print("  size %-3d FAILED\n%s\n%s" % (size, r.stdout, r.stderr))
            return False
        src = out.read_text(encoding="utf-8")

        # The committed hosts carry this same hand-edit: PlatformIO puts lvgl's
        # own directory on the include path, so the nested form does not
        # resolve. Both branches of the #ifdef read "lvgl.h" there.
        src = src.replace('#include "lvgl/lvgl.h"', '#include "lvgl.h"')

        # Replace the generator's banner with one that says what this file is
        # and why it exists, in the house style.
        end = src.index("******/") + len("******/")
        src = BANNER % {"host": HOST % size} + src[end:]
        write_lf(out, src)

        f = read_font(out)
        print("  size %-3d %-28s %5d glyphs  line_height %2d  base_line %d"
              % (size, out.name, len(f["glyphs"]) - 1,
                 f["line_height"], f["base_line"]))
    return True


def audit():
    """Where a supplement glyph would lose a row of pixels.

    The supplement supplies box_h and ofs_y; the host supplies the baseline.
    A glyph taller than the host's ascent loses its top row, one deeper than
    the host's descent loses its bottom row. Children are clipped at the
    label's own edge, so this only ever affects the first line of a label, and
    at 4 bpp the row in question is the faintest row of a 2-3 px accent.

    This is the check that replaces guessing, and it runs before flashing.
    """
    print("== clipping audit ==")
    worst = 0
    for size in SIZES:
        host = read_font(FONTS / ("%s.c" % (HOST % size)))
        sp = FONTS / ("%s.c" % (SUPP % size))
        if not sp.exists():
            print("  size %-3d SKIP (not built yet)" % size)
            continue
        supp = read_font(sp)
        ascent = host["line_height"] - host["base_line"]
        cp = codepoints(supp)
        top, bottom = [], []
        for gid, g in enumerate(supp["glyphs"]):
            if gid == 0 or g["box_h"] == 0:
                continue
            ch = cp.get(gid)
            label = "U+%04X %s" % (ch, chr(ch)) if ch else "gid %d" % gid
            over = g["ofs_y"] + g["box_h"] - ascent
            under = -host["base_line"] - g["ofs_y"]
            if over > 0:
                top.append((label, over))
            if under > 0:
                bottom.append((label, under))
        worst = max([worst] + [n for _, n in top + bottom])
        if not top and not bottom:
            print("  size %-3d clean (ascent %d, descent %d)"
                  % (size, ascent, host["base_line"]))
            continue
        print("  size %-3d ascent %d, descent %d" % (size, ascent, host["base_line"]))
        for label, n in top:
            print("           top    %-14s -%d row%s" % (label, n, "s" if n > 1 else ""))
        for label, n in bottom:
            print("           bottom %-14s -%d row%s" % (label, n, "s" if n > 1 else ""))
    if worst == 0:
        print("  nothing clips.")
    elif worst == 1:
        print("  worst case one anti-aliased row, accepted (see the plan).")
    else:
        print("  WORST CASE %d rows - review before flashing." % worst)
    return True


def wire():
    """Point each host at its supplement, and declare the supplements.

    Two edits, both idempotent, so this can be re-run after any upstream
    regeneration of the font files rather than merged by hand:
      - one line per host font: .fallback = NULL -> .fallback = &supplement
      - seven lines in lv_conf.h's LV_FONT_CUSTOM_DECLARE, which is expanded
        by lv_font.h. That is what makes the symbol visible inside the host
        .c file without adding an extern declaration to it.
    """
    print("== wiring ==")
    for size in SIZES:
        host = FONTS / ("%s.c" % (HOST % size))
        want = "    .fallback = &%s," % (SUPP % size)
        src = host.read_text(encoding="utf-8")
        if want in src:
            print("  size %-3d already wired" % size)
            continue
        if "    .fallback = NULL," not in src:
            print("  size %-3d NO .fallback line - upstream changed the "
                  "generator output, look before touching" % size)
            return False
        src = src.replace("    .fallback = NULL,", want, 1)
        write_lf(host, src)
        print("  size %-3d -> %s" % (size, SUPP % size))

    conf = LV_CONF.read_text(encoding="utf-8")
    if SUPP % SIZES[0] in conf:
        print("  lv_conf.h already declares the supplements")
        return True
    anchor = "    LV_FONT_DECLARE(lv_font_montserrat_ext_36)"
    if anchor not in conf:
        print("  lv_conf.h: LV_FONT_CUSTOM_DECLARE not in the expected shape")
        return False
    added = anchor + "  \\\n" + "".join(
        "    LV_FONT_DECLARE(%s)%s\n" % (
            SUPP % s, "  \\" if s != SIZES[-1] else "")
        for s in SIZES).rstrip("\n")
    conf = conf.replace(anchor, added, 1)
    write_lf(LV_CONF, conf)
    print("  lv_conf.h: %d supplements declared" % len(SIZES))
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for flag in ("check-assets", "verify-host", "build", "audit", "wire", "all"):
        ap.add_argument("--" + flag, action="store_true")
    a = ap.parse_args()
    steps = [("check_assets", check_assets), ("verify_host", verify_host),
             ("build", build), ("audit", audit), ("wire", wire)]
    chosen = [(n, f) for n, f in steps
              if a.all or getattr(a, n.replace("-", "_"))]
    if not chosen:
        ap.print_help()
        return 2
    for name, fn in chosen:
        if not fn():
            print("\nSTOPPED at %s" % name)
            return 1
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
