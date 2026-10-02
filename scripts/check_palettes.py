#!/usr/bin/env python3
"""The panel's palettes against the web pages' palettes.

The panel reads its colours from src/ui/theme_palette.h, one column per
palette. The web pages carry their own table, the :root blocks of the
stylesheet in src/web/web_static.cpp, written by hand. Nothing generates one
from the other, so a colour changed on one side stays as it was on the other
until someone notices. This script notices.

The two tables are not equal by design: the web was tuned for a monitor, the
panel for a display that shows less contrast in the bright range. So a pair
of tokens that mean the same thing (--ground and GROUND) may differ, but only
by a difference somebody decided on. Those stand in
scripts/palette_baseline.json with both values. What fails:

  - a palette on one side with no block on the other (keys from theme.cpp);
  - a web block that leaves out a colour :root defines: it would show the
    dark value on a light page without a word;
  - a web colour that is neither paired with a panel token nor listed as the
    web's own below;
  - a paired value that differs and is not recorded with exactly these two
    values: one side moved and the other did not;
  - a recorded difference that no longer exists: the record is stale.

    python3 scripts/check_palettes.py                  check
    python3 scripts/check_palettes.py --verbose        print every pair as well
    python3 scripts/check_palettes.py --write-baseline
        record the differences as they stand. Only after deciding that the
        web and the panel should differ there, committed with that change.

Exit 0 green, 1 a finding, 2 a table that could not be read. Standard library
only, Python 3.9.
"""

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PALETTE_H = REPO_ROOT / "src" / "ui" / "theme_palette.h"
THEME_CPP = REPO_ROOT / "src" / "ui" / "theme.cpp"
WEB_CSS = REPO_ROOT / "src" / "web" / "web_static.cpp"
BASELINE_PATH = REPO_ROOT / "scripts" / "palette_baseline.json"

# Web colour -> the panel token with the same role.
PAIRS = {
    "--ground":    "GROUND",
    "--surface":   "SURFACE",
    "--line":      "LINE",
    "--line-soft": "LINE_SOFT",
    "--ink":       "INK",
    "--ink-2":     "INK_2",
    "--ink-3":     "CAPTION",
    "--ink-4":     "RULE",
    "--ink-soft":  "INK_SOFT",
    "--accent":    "ACCENT",
    "--good":      "GOOD",
    "--warn":      "WARN",
    "--bad":       "BAD",
    "--ok-bg":     "OK_BG",
    "--bad-bg":    "BAD_BG",
}
# Web colours without a panel counterpart: hover states, the button fills of
# the pages, the second surface of a card inside a card.
WEB_ONLY = {
    "--surface-2", "--accent-dim", "--accent-line", "--hover", "--btn",
    "--btn-hover", "--quiet", "--quiet-hover", "--warn-line", "--warn-bg",
    "--bad-line", "--bad-hover",
}

HEX6 = r"0x([0-9a-fA-F]{6})"


def read_panel():
    """name -> [value per palette], and the palette keys in column order."""
    text = PALETTE_H.read_text(encoding="utf-8")
    row = re.compile(r"^UI_COLOUR\((\w+),\s*" + r",\s*".join([HEX6] * 6) + r"\)", re.M)
    panel = {m.group(1): [v.lower() for v in m.groups()[1:]] for m in row.finditer(text)}
    keys = re.findall(r'\{\s*"(\w+)",\s*(?:true|false)\s*\}', THEME_CPP.read_text(encoding="utf-8"))
    return panel, keys


def read_web():
    """palette key -> {variable: value}; :root without a selector is dark."""
    text = WEB_CSS.read_text(encoding="utf-8")
    css_part = text.split("APP_JS")[0]
    css = "".join(re.findall(r'"((?:[^"\\\n]|\\.)*)"', css_part))
    web = {}
    for blk in re.finditer(r":root(?:\[data-theme=(\w+)\])?\{([^}]*)\}", css):
        key = blk.group(1) or "dark"
        web[key] = {k: v.lower() for k, v in re.findall(r"(--[\w-]+):#([0-9a-fA-F]{6})\b", blk.group(2))}
    return web


def differences(panel, keys, web):
    """'--var/NAME' -> {palette: 'web/panel'} for every paired value that differs."""
    out = {}
    for var, name in PAIRS.items():
        for i, key in enumerate(keys):
            w = web.get(key, {}).get(var)
            p = panel.get(name, [None] * len(keys))[i]
            if w is not None and p is not None and w != p:
                out.setdefault(f"{var}/{name}", {})[key] = f"{w}/{p}"
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--write-baseline", action="store_true")
    args = ap.parse_args()

    panel, keys = read_panel()
    web = read_web()
    if len(panel) < 50 or len(keys) < 2 or "dark" not in web:
        print(f"fail: could not read the tables ({len(panel)} panel colours, "
              f"{len(keys)} palettes, {len(web)} web blocks)")
        return 2

    findings = []
    for key in keys:
        if key not in web:
            findings.append(f"palette {key}: no :root[data-theme={key}] block in web_static.cpp")
    for key in web:
        if key not in keys:
            findings.append(f"web block {key}: no such palette in theme.cpp")

    root = set(web["dark"])
    for key, vars_ in web.items():
        for var in sorted(root - set(vars_)):
            findings.append(f"web block {key}: {var} missing, the page would show the dark value")
    for var in sorted(root):
        if var not in PAIRS and var not in WEB_ONLY:
            findings.append(f"{var}: neither paired with a panel token nor listed as web-only")
    for var, name in PAIRS.items():
        if var not in root:
            findings.append(f"{var}: paired with {name} but not defined in :root")
        if name not in panel:
            findings.append(f"{name}: paired with {var} but not in theme_palette.h")

    diff = differences(panel, keys, web)
    if args.write_baseline:
        if findings:
            print("refused: fix the structural findings first")
            for f in findings:
                print("fail: " + f)
            return 1
        BASELINE_PATH.write_text(json.dumps(diff, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {BASELINE_PATH.relative_to(REPO_ROOT)}: "
              f"{sum(len(v) for v in diff.values())} recorded differences")
        return 0

    try:
        base = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"fail: {BASELINE_PATH.relative_to(REPO_ROOT)} unreadable: {e}")
        return 2

    for pair, per in sorted(diff.items()):
        for key, now in sorted(per.items()):
            rec = base.get(pair, {}).get(key)
            if rec == now:
                continue
            w, p = now.split("/")
            if rec is None:
                findings.append(f"{pair} in {key}: web #{w}, panel #{p} - a new difference")
            else:
                findings.append(f"{pair} in {key}: web #{w}, panel #{p}, recorded web/panel {rec}"
                                f" - one side changed")
    for pair, per in sorted(base.items()):
        for key in sorted(per):
            if key not in diff.get(pair, {}):
                findings.append(f"{pair} in {key}: recorded as different, now equal - stale record")

    if args.verbose:
        for var, name in PAIRS.items():
            row = " ".join(f"{k}={web.get(k, {}).get(var, '-')}/{panel.get(name, ['-'] * len(keys))[i]}"
                           for i, k in enumerate(keys))
            print(f"pair {var}/{name}: {row}")
    for f in findings:
        print("fail: " + f)
    n = sum(len(v) for v in diff.values())
    print(f"palettes: {len(keys)} palettes, {len(PAIRS)} pairs, {n} values differ by decision, "
          f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
