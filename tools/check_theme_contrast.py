#!/usr/bin/env python3
"""Check every theme preset for readable text.

Reads the palette straight out of src/ui/theme.{h,cpp}, so it cannot drift from
the firmware, and reports the WCAG contrast ratio for each foreground/background
pair the UI actually draws. Run it after adding a preset or changing a colour:

    python3 tools/check_theme_contrast.py
    python3 tools/check_theme_contrast.py --allow Default   # skip a known-bad preset

Exits non-zero if any checked preset has a pair below 4.5:1, so it can be wired
into CI.

Why 4.5:1 - that is the WCAG AA threshold for body text. Pairs between 3.0 and
4.5 are flagged with "!" because they are only acceptable for large text, and
most of this UI is 12-16px.

Known exception: the Default preset ships two pairs below the threshold
(TEXT_DIM on BG at 1.81, TEXT_MUTED on TILE_BG at 3.28). Those are the original
upstream colours and are deliberately left as they are - changing them would
alter the established look of the device rather than fix a bug introduced here.
Pass --allow Default to accept that, or adjust the palette if you would rather
raise it.
"""

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THEME_H = os.path.join(ROOT, "src", "ui", "theme.h")
THEME_C = os.path.join(ROOT, "src", "ui", "theme.cpp")

# Foreground/background pairs that genuinely occur on screen. Add a line here
# when a new screen draws a combination that is not already covered.
PAIRS = [
    ("TH_TEXT", "TH_BG"), ("TH_TEXT", "TH_SURFACE"), ("TH_TEXT", "TH_SURFACE_2"),
    ("TH_TEXT", "TH_SURFACE_3"), ("TH_TEXT", "TH_TILE_BG"),
    ("TH_TEXT_BRIGHT", "TH_TILE_BG"),
    ("TH_TEXT_MUTED", "TH_BG"), ("TH_TEXT_MUTED", "TH_TILE_BG"),
    ("TH_TEXT_DIM", "TH_BG"),
    ("TH_ACCENT", "TH_BG"), ("TH_ACCENT", "TH_SURFACE"),
    ("TH_ACCENT", "TH_TILE_BG"), ("TH_ACCENT", "TH_OK_BG"),
    ("TH_ON_ACCENT", "TH_ACCENT"),
    ("TH_SUCCESS_TEXT", "TH_OK_BG"), ("TH_SUCCESS_TEXT", "TH_SUCCESS_BG"),
    ("TH_WARNING", "TH_BG"), ("TH_WARNING", "TH_WARNING_BG"),
    ("TH_DANGER_TEXT", "TH_BG"), ("TH_DANGER_TEXT", "TH_DANGER_BG"),
    ("TH_TEXT", "TH_POPUP_BG"),
]

MIN_BODY = 4.5
MIN_LARGE = 3.0


def load():
    names = re.findall(r"^\s*(TH_[A-Z_0-9]+),", open(THEME_H).read(), re.M)
    src = open(THEME_C).read()
    blk = src[src.index("static const uint32_t PRESETS"):]
    blk = blk[:blk.index("};")]
    rows = [re.findall(r"0x([0-9a-fA-F]{6})", r)
            for r in re.findall(r"\{([^{}]*)\}", blk)]
    pnames = re.findall(r'"([A-Za-z]+)"',
                        src[src.index("static const char *PRESET_NAME[]"):][:300])
    return names, pnames, rows


def _lin(c):
    c /= 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(v):
    r, g, b = (v >> 16) & 255, (v >> 8) & 255, v & 255
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def contrast(a, b):
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow", action="append", default=[],
                    help="preset name to report but not fail on (repeatable)")
    args = ap.parse_args()

    names, pnames, rows = load()
    idx = {n: i for i, n in enumerate(names)}

    for i, row in enumerate(rows):
        if len(row) != len(names):
            print("preset %s has %d colours, expected %d - a short row zero-fills "
                  "silently and renders black" % (pnames[i], len(row), len(names)))
            return 2

    missing = [t for pair in PAIRS for t in pair if t not in idx]
    if missing:
        print("unknown token(s) in PAIRS: %s" % ", ".join(sorted(set(missing))))
        return 2

    print("%-32s %s" % ("pair", "".join("%-11s" % p for p in pnames)))
    failures = []
    for fg, bg in PAIRS:
        line = "%-32s" % ("%s on %s" % (fg[3:], bg[3:]))
        for pi, row in enumerate(rows):
            r = contrast(int(row[idx[fg]], 16), int(row[idx[bg]], 16))
            mark = " " if r >= MIN_BODY else ("!" if r >= MIN_LARGE else "X")
            line += "  %5.2f%s   " % (r, mark)
            if r < MIN_BODY:
                failures.append((pnames[pi], fg, bg, r))
        print(line)

    print("\n  blank >= %.1f:1 (body text)   ! %.1f-%.1f (large text only)   X < %.1f"
          % (MIN_BODY, MIN_LARGE, MIN_BODY, MIN_LARGE))

    hard = [f for f in failures if f[0] not in args.allow]
    if failures:
        print("\nbelow %.1f:1" % MIN_BODY)
        for p, fg, bg, r in sorted(failures, key=lambda x: x[3]):
            note = "  (allowed)" if p in args.allow else ""
            print("  %-9s %-16s on %-14s %.2f%s" % (p, fg[3:], bg[3:], r, note))
    if hard:
        print("\n%d pair(s) fail. Darken the foreground on a light background, or "
              "lighten it on a dark one, until it clears %.1f:1." % (len(hard), MIN_BODY))
        return 1
    print("\nall checked presets pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
