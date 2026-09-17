#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  SpoolmanScale – Localization (i18n)
#  lang_fr.py - the French column: working file, checks, emitter
#  Fork addition – Nanostra (Frédéric Dubus)
# ============================================================
#
# src/lang.cpp holds one row per UI string, one column per language, and the
# code reaches a row by its POSITION - STR_CANCEL is the number 0. So the table
# and the enum in lang.h must stay in lockstep, and a row inserted in the middle
# of one of them shifts every string after it.
#
# That is why the French column is not edited in src/lang.cpp by hand. The
# source of truth is tools/lang_fr.jsonl; src/lang.cpp is the PRODUCT, rebuilt
# by `emit`. src/lang.cpp is also the most edited file upstream has - 98 commits,
# a third of them rewording existing rows - so a rebase conflict on it is
# certain. With the jsonl as the source it is resolved mechanically:
#
#     git checkout upstream/dev -- src/lang.cpp   # their version, as is
#     python tools/lang_fr.py seed                # refresh DE/EN, keep French
#     python tools/lang_fr.py check               # what they added or reworded
#     python tools/lang_fr.py emit                # re-inject the third column
#
# Never --ours / --theirs there: their meaning is inverted during a rebase and
# the mistake is silent.
#
# What makes that safe is the parser, and it is proved rather than trusted:
# `roundtrip` re-emits every row from its ORIGINAL bytes and compares the whole
# file. If that is byte-identical, the segmentation lost nothing and invented
# nothing - which is the property the emitter depends on. Three shapes in the
# real file break a naive parser: braces inside string literals
# ("{v} installieren?"), escaped quotes, and cells that start with a macro
# (LV_SYMBOL_OK "  Berechnen").
#
#   python tools/lang_fr.py roundtrip   proves the parser (run this first)
#   python tools/lang_fr.py seed        (re)build the working file
#   python tools/lang_fr.py dump        the rows left, with their constraints
#   python tools/lang_fr.py apply       read {"STR_X": "french"} JSON on stdin
#   python tools/lang_fr.py check       every rule; --strict also demands French
#   python tools/lang_fr.py emit        write src/lang.cpp with three columns
#   python tools/lang_fr.py report      coverage, and the tightest rows
#
# A line break inside a string is written <NL> in an `apply` batch - see the
# comment on NL_TOKEN for why a backslash cannot be trusted through three
# layers of quoting.
# ============================================================
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LANG_H = ROOT / "src" / "lang.h"
LANG_CPP = ROOT / "src" / "lang.cpp"
WORK = ROOT / "tools" / "lang_fr.jsonl"

# Never walk from the repository root: copy_release.py leaves stale copies of
# lang.cpp under releases/*/source/, and a recursive search would find them.
SRC = ROOT / "src"

LANGS = ("de", "en", "fr")
OPEN2 = "const char* const STRINGS[][2] = {"
OPEN3 = "const char* const STRINGS[][3] = {"

# Columns for a single-line row. Past this the row is written one cell per line,
# which is what the file already does for its long rows.
LINE_MAX = 118


# --------------------------------------------------------------------------
#  Scanning C++
# --------------------------------------------------------------------------
def skip_string(s, i):
    """Index just past the string literal starting at s[i]."""
    i += 1
    while i < len(s) and s[i] != '"':
        i += 2 if s[i] == "\\" else 1
    return i + 1


def match_brace(s, i):
    """Index just past the '}' matching the '{' at s[i], strings ignored."""
    depth = 0
    while i < len(s):
        c = s[i]
        if c == '"':
            i = skip_string(s, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced brace")


def split_cells(inner):
    """Top-level commas only: a comma inside a literal or a nested brace is not
    a separator."""
    out, start, depth, i = [], 0, 0, 0
    while i < len(inner):
        c = inner[i]
        if c == '"':
            i = skip_string(inner, i)
            continue
        if c in "{[(":
            depth += 1
        elif c in "}])":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(inner[start:i])
            start = i + 1
        i += 1
    out.append(inner[start:])
    return out


TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[A-Za-z_]\w*')


def cell_value(src):
    """What a cell prints, as written.

    Adjacent literals are concatenated; escapes are kept verbatim so that \\n
    can be counted and \\" compared. A macro becomes {NAME}, because
    LV_SYMBOL_OK is a glyph we must preserve but cannot resolve here.
    """
    out = []
    for t in TOKEN.findall(src):
        out.append(t[1:-1] if t.startswith('"') else "{%s}" % t)
    return "".join(out)


ROW_TAIL = re.compile(r"\A\s*,?[ \t]*//[ \t]*(STR_\w+)[ \t]*(?=\n|\Z)")


def parse_table(src):
    """(prefix, items, suffix).

    items is a list of ('raw', text) and ('row', dict). A row dict carries
    'id', 'cells' (source text per column), 'vals' (cell_value per column) and
    'text' (the row's original bytes, comment included). Everything that is not
    a row - group comments, blank lines, indentation - stays in a 'raw' item, so
    re-emitting from 'text' reproduces the file exactly.
    """
    for opener in (OPEN3, OPEN2):
        if opener in src:
            break
    else:
        raise ValueError("STRINGS table not found")
    head = src.index(opener)
    body_start = head + len(opener)
    prefix = src[:body_start]
    # The table's closing brace: scan from body_start at depth 1.
    i, depth = body_start, 1
    while i < len(src):
        c = src[i]
        if c == '"':
            i = skip_string(src, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body, suffix = src[body_start:i], src[i:]

    items, pos = [], 0
    while True:
        b = body.find("{", pos)
        if b < 0:
            break
        end = match_brace(body, b)
        m = ROW_TAIL.match(body[end:])
        if not m:
            # A brace that is not a row. Nothing like this exists today, but
            # failing loudly beats guessing.
            raise ValueError("row at offset %d has no // STR_ comment" % b)
        row_end = end + m.end()
        if b > pos:
            items.append(("raw", body[pos:b]))
        cells = split_cells(body[b + 1:end - 1])
        items.append(("row", {
            "id": m.group(1),
            "cells": [c for c in cells],
            "vals": [cell_value(c) for c in cells],
            "text": body[b:row_end],
        }))
        pos = row_end
    if pos < len(body):
        items.append(("raw", body[pos:]))
    return prefix, items, suffix


def enum_ids():
    """The StringIDs in enum order, with the section heading above each run.

    Only the FIRST line of a comment block is the heading: several of them run
    to a paragraph, and the last line of the paragraph is not a title.
    """
    src = LANG_H.read_text(encoding="utf-8")
    body = src[src.index("enum StringID {"):src.index("STR_COUNT")]
    ids, group, in_comment = [], "", False
    for line in body.splitlines():
        s = line.strip()
        if s.startswith("//"):
            g = s[2:].strip()
            if not in_comment and g and not g.startswith("-"):
                group = g
            in_comment = True
            continue
        in_comment = False
        m = re.match(r"(STR_\w+)\s*,", s)
        if m:
            ids.append((m.group(1), group))
    return ids


def load_table():
    src = LANG_CPP.read_text(encoding="utf-8")
    prefix, items, suffix = parse_table(src)
    rows = [it[1] for it in items if it[0] == "row"]
    return src, prefix, items, suffix, rows


# --------------------------------------------------------------------------
#  Signatures a translation must preserve
# --------------------------------------------------------------------------
LV_SYMBOL_DEF = (ROOT / ".pio" / "libdeps" / "wt32-sc01-plus" / "lvgl" /
                 "src" / "font" / "lv_symbol_def.h")
_SYMBOL_CHARS = None


def symbol_chars():
    """LV_SYMBOL_X -> the character it stands for.

    Resolved from LVGL's own lv_symbol_def.h rather than guessed, because both
    checks need the real thing: a symbol is three UTF-8 bytes in a char buffer,
    not the seventeen of the "{LV_SYMBOL_CLOSE}" marker, and it occupies real
    width on the panel. Empty if LVGL is not unpacked yet: check() refuses to
    pass in that case, because every icon would count as zero bytes and zero
    pixels without a word.
    """
    global _SYMBOL_CHARS
    if _SYMBOL_CHARS is None:
        _SYMBOL_CHARS = {}
        if LV_SYMBOL_DEF.exists():
            text = LV_SYMBOL_DEF.read_text(encoding="utf-8", errors="replace")
            for name, body in re.findall(
                    r'#define\s+(LV_SYMBOL_\w+)\s+"((?:\\x[0-9A-Fa-f]{2})+)"', text):
                raw = bytes(int(b, 16) for b in re.findall(r"\\x([0-9A-Fa-f]{2})", body))
                try:
                    _SYMBOL_CHARS[name] = raw.decode("utf-8")
                except UnicodeDecodeError:
                    pass
    return _SYMBOL_CHARS


MARKER = re.compile(r"\{(LV_SYMBOL_\w+)\}")


def resolved(text):
    """The value with every {LV_SYMBOL_X} marker replaced by its character, so
    byte counts and widths are measured on what the device actually holds."""
    chars = symbol_chars()
    return MARKER.sub(lambda m: chars.get(m.group(1), ""), text)


def probe_text(text):
    """What to hand the width engine: symbols resolved, any other macro
    dropped because nothing can be known about its width from here."""
    return re.sub(r"\{[A-Za-z_]\w*\}", "", resolved(text))


CONV = re.compile(r"%(?:%|[-+ #0]*[0-9.]*(?:hh|h|ll|l|z)?[diouxXeEfgGcsp])")
BRACE = re.compile(r"\{[a-z]\}")
SYMBOL = re.compile(r"^(?:\{(LV_SYMBOL_\w+)\}\s*)+")
ENTITY = r"&[a-zA-Z]+;|&#(?:\d+|[xX][0-9A-Fa-f]+);"
TAG = re.compile(r"</?[a-zA-Z][^>]*>|" + ENTITY)
VOID_TAGS = ("br", "hr", "img", "input", "wbr")


def conversions(v):
    return [c for c in CONV.findall(v) if c != "%%"]


def signature(v):
    """Everything about a string that a translation must not change."""
    m = SYMBOL.match(v)
    return {
        "conv": conversions(v),
        "brace": sorted(BRACE.findall(v)),
        "symbols": re.findall(r"\{(LV_SYMBOL_\w+)\}", m.group(0)) if m else [],
        # The gap after each leading icon: LV_SYMBOL_OK "  Berechnen" is two
        # spaces on purpose, and SYMBOL above swallows them.
        "symbol_gaps": [len(g) for g in re.findall(r"\}(\s*)", m.group(0))] if m else [],
        "newlines": v.count("\\n"),
        # Sorted, because a sentence may legitimately put its bold word before
        # its italic one in French. Nesting is checked separately.
        "tags": sorted(TAG.findall(v)),
    }


def crossed_tags(v):
    """The first tag that closes out of order, or None.

    The tag comparison above is a multiset, so "<b>x</i>y<i>z</b>" would match
    "<b>x</b>y<i>z</i>" there. This is what catches it.
    """
    stack = []
    for full, name in re.findall(r"(</?([a-zA-Z]+)[^>]*>)", v):
        name = name.lower()
        if name in VOID_TAGS or full.endswith("/>"):
            continue
        if not full.startswith("</"):
            stack.append(name)
        elif not stack or stack.pop() != name:
            return full
    return "<%s> never closed" % stack[-1] if stack else None


# Several web strings are written into innerHTML without going through
# htmlEsc() - page_logs.cpp:88,175,178, page_tags.cpp:208,215,
# page_firmware.cpp:415, web_shell.cpp:346 - and a bare & in one of those breaks
# the markup.
#
# Listing the exact ids was the first attempt and it was worse than useless:
# the list was written from memory, half the names did not exist, and a rule
# that matches nothing reports nothing. So the check covers EVERY web string
# instead. It costs nothing to be right here - French writes "et" rather than
# "&" anyway, and a legitimate ampersand in one of these is always an HTML
# entity, which the check skips.
def reaches_innerhtml(sid):
    return sid.startswith("STR_W_")

# DRY_MAT_NAMES looks like material labels a translator would expect here, but
# it is not in this table at all: it is a C array used as an NVS key suffix
# (dry_y_%s), so translating it would reset every device's drying settings.


# --------------------------------------------------------------------------
#  Buffer budgets
# --------------------------------------------------------------------------
# The id argument is read as an expression, not a single token: a third of the
# on/off sites spell it copyT(buf, sizeof(buf), on ? STR_ON : STR_OFF), and both
# ids land in that buffer.
COPYT = re.compile(r"copyT\s*\(\s*(\w+)\s*,\s*sizeof\s*\(\s*\1\s*\)\s*,([^;]*?)\)\s*;")
COPYT_IDS = re.compile(r"\bSTR_\w+")

# A char declaration, including the shapes the tree actually uses:
#   char buf[24];
#   static char buf_title[48], buf_msg[256], buf_later[32];   (comma list)
#   char tbuf[HINT_TITLE_BUF];                                (symbolic size)
#   char unit_name[AMS_NAME_MAX + 8];                         (sum of sizes)
#   char out[32] = "";                                        (initialiser)
# Matched on code_only() text, so a declaration quoted in a comment does not
# count and a brace or semicolon inside a string cannot end one early.
CHARDECL = re.compile(r"\bchar\s+([^;]+?)\s*;")
DECLARATOR = re.compile(r"(\w+)\s*\[\s*([A-Za-z_0-9][A-Za-z_0-9\s+-]*?)\s*\]")
SIZE_TERM = re.compile(r"\s*([+-])?\s*([A-Za-z_0-9]+)")
DEFINE = re.compile(r"^\s*#define\s+(\w+)\s+\(?\s*(\d+)\s*\)?\s*(?://.*)?$", re.M)


def code_only(text):
    """Comments and the inside of string and character literals blanked out.

    Offsets are kept - every removed character becomes a space, newlines stay -
    so positions found here still order declarations against call sites.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            for k in range(i, end):
                if text[k] != "\n":
                    out[k] = " "
            i = end
        elif c in "\"'":
            k = i + 1
            while k < n and text[k] != c and text[k] != "\n":
                if text[k] == "\\":
                    out[k] = " "
                    k += 1
                out[k] = " "
                k += 1
            i = k + 1
        else:
            i += 1
    return "".join(out)


def _defines():
    """Every simple numeric #define in src/, for the buffers sized by name.

    One flat map rather than following includes: the names are unique enough in
    this tree, and a wrong answer would be caught by the emitted budget looking
    absurd rather than by silence.
    """
    out = {}
    for path in sorted(SRC.rglob("*.h")) + sorted(SRC.rglob("*.cpp")):
        for name, val in DEFINE.findall(
                path.read_text(encoding="utf-8", errors="replace")):
            out.setdefault(name, int(val))
    return out


def _size(expr, defines):
    """Bytes of a declarator size - a number, a define, or a sum of those - or
    None when any term is unknown. Never a partial sum: AMS_NAME_MAX + 8 read
    as 8 would pass a name that truncates."""
    total, pos = 0, 0
    for m in SIZE_TERM.finditer(expr):
        if m.start() != pos or (pos and not m.group(1)):
            return None
        term = m.group(2)
        n = int(term) if term.isdigit() else defines.get(term)
        if n is None:
            return None
        total += -n if m.group(1) == "-" else n
        pos = m.end()
    return total if pos == len(expr) and total > 0 else None


def buffer_budgets():
    """id -> smallest destination buffer, in usable bytes, over every copyT site.

    The size is the nearest preceding declaration of that name in the same file.
    Sites it cannot resolve are reported rather than guessed - a wrong budget is
    worse than a missing one, because it would pass a string that truncates.
    """
    defines = _defines()
    out, unresolved = {}, []
    for path in sorted(SRC.rglob("*.cpp")) + sorted(SRC.rglob("*.h")):
        text = code_only(path.read_text(encoding="utf-8", errors="replace"))
        sizes = []                     # (offset, name, bytes) in file order
        for d in CHARDECL.finditer(text):
            # Only the declarator side: an initialiser such as {0} or a call is
            # not a size.
            decls = [part.split("=")[0] for part in d.group(1).split(",")]
            for name, size in DECLARATOR.findall(",".join(decls)):
                n = _size(size, defines)
                if n:
                    sizes.append((d.start(), name, n))
        for m in COPYT.finditer(text):
            name = m.group(1)
            for sid in COPYT_IDS.findall(m.group(2)):
                best = None
                for off, dname, n in sizes:
                    if dname == name and off < m.start():
                        best = n       # nearest preceding wins
                if best is None:
                    unresolved.append((path.relative_to(ROOT).as_posix(), sid, name))
                    continue
                out[sid] = min(out.get(sid, 10 ** 6), best - 1)   # copyT terminates
    return out, unresolved


CALLSITE = re.compile(r"\b(STR_\w+)\b")


def call_sites():
    """id -> ['path:line', ...]. Includes the bare mentions, because ~163 ids
    are only ever reached through the uint16_t descriptor tables and a search
    for T(STR_X) would never find them."""
    out = {}
    for path in sorted(SRC.rglob("*.cpp")) + sorted(SRC.rglob("*.h")):
        if path.name in ("lang.cpp", "lang.h"):
            continue
        rel = path.relative_to(ROOT).as_posix()
        for n, line in enumerate(path.read_text(encoding="utf-8",
                                                errors="replace").splitlines(), 1):
            for sid in set(CALLSITE.findall(line)):
                out.setdefault(sid, []).append("%s:%d" % (rel, n))
    return out


# --------------------------------------------------------------------------
#  Working file
# --------------------------------------------------------------------------
def load_work():
    """The working file, keyed by id. Human fields only are authoritative."""
    if not WORK.exists():
        return {}
    out = {}
    for line in WORK.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            out[r["id"]] = r
    return out


def save_work(rows):
    WORK.write_text(
        "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                for r in rows),
        encoding="utf-8", newline="\n")


HUMAN = ("fr", "st", "note", "wover")


def seed():
    _, _, _, _, rows = load_table()
    ids = enum_ids()
    if [i for i, _ in ids] != [r["id"] for r in rows]:
        print("lang.cpp and the enum in lang.h are out of step - fix that first.")
        a = {r["id"] for r in rows}
        b = {i for i, _ in ids}
        for sid in sorted(b - a):
            print("  in lang.h, not in lang.cpp: %s" % sid)
        for sid in sorted(a - b):
            print("  in lang.cpp, not in lang.h: %s" % sid)
        return False

    old = load_work()
    groups = dict(ids)
    budgets, unresolved = buffer_budgets()
    sites = call_sites()

    out = []
    for r in rows:
        sid = r["id"]
        prev = old.get(sid, {})
        rec = {
            "id": sid,
            "grp": groups.get(sid, ""),
            "de": r["vals"][0],
            "en": r["vals"][1] if len(r["vals"]) > 1 else "",
            "fr": prev.get("fr", ""),
            "sig": signature(r["vals"][0]),
            "bmax": budgets.get(sid),
            "sites": sites.get(sid, [])[:4],
            "st": prev.get("st", "todo"),
            "note": prev.get("note", ""),
            "wover": prev.get("wover"),
        }
        # A German string reworded upstream invalidates the French silently:
        # the count still matches and the compiler is happy. Flag it here.
        if prev and prev.get("de") not in (None, rec["de"]) and prev.get("fr"):
            rec["st"] = "stale"
            rec["note"] = (prev.get("note", "") +
                           " | DE reworded upstream, re-read").strip(" |")
        out.append(rec)

    save_work(out)
    done = sum(1 for r in out if r["fr"])
    print("seeded %d rows -> %s" % (len(out), WORK.relative_to(ROOT).as_posix()))
    print("  French written: %d   remaining: %d" % (done, len(out) - done))
    print("  buffer budgets resolved: %d" % len(budgets))
    if unresolved:
        print("  buffer budgets UNRESOLVED (enter bmax by hand): %d"
              % len(unresolved))
        for path, sid, name in unresolved[:10]:
            print("    %-46s %-30s %s" % (path, sid, name))
    stale = [r["id"] for r in out if r["st"] == "stale"]
    if stale:
        print("  STALE - German reworded since translated: %d" % len(stale))
        for sid in stale[:10]:
            print("    %s" % sid)
    return True


def french_strings():
    """{id: french text} for fit_check --gate."""
    return {r["id"]: r["fr"] for r in load_work().values() if r["fr"]}


# A hard line break is stored the way a C string spells it: the two characters
# backslash and n, never a real newline. Writing that through a shell, a JSON
# document and Python means three layers each with their own opinion about
# backslashes, and one of them always wins. So a batch spells a line break
# <NL> and this turns it into the real thing. Built from chr(92) rather than
# written as a literal, for the same reason.
NL_TOKEN = "<NL>"
NL_ESCAPE = chr(92) + "n"


def apply_batch(stream=None):
    """Read {"STR_X": "french", ...} as JSON and write it into the working file.

    Only 'fr' and 'st' are touched, so the derived fields stay as `seed` left
    them. An unknown id is refused outright rather than silently dropped: a
    typo in an id would otherwise look like a translation that did not take.
    """
    batch = json.load(stream or sys.stdin)
    work = load_work()
    unknown = sorted(k for k in batch if k not in work)
    if unknown:
        print("unknown id(s), nothing written: %s" % ", ".join(unknown))
        return False

    normalised = 0
    for sid, text in list(batch.items()):
        before = text
        text = text.replace(NL_TOKEN, NL_ESCAPE)
        text = text.replace(chr(13) + chr(10), NL_ESCAPE).replace(chr(10), NL_ESCAPE)
        text = text.replace(chr(13), NL_ESCAPE).replace(chr(9), " ")
        if text != before:
            normalised += 1
        batch[sid] = text

    rows = []
    for sid, rec in work.items():
        if sid in batch:
            rec["fr"] = batch[sid]
            rec["st"] = "ok"
        rows.append(rec)
    # The working file keeps enum order, which is what makes a diff readable.
    order = {sid: i for i, (sid, _) in enumerate(enum_ids())}
    rows.sort(key=lambda r: order.get(r["id"], 10 ** 6))
    save_work(rows)

    done = sum(1 for r in rows if r.get("fr"))
    note = " (%d line break(s) normalised)" % normalised if normalised else ""
    print("%d row(s) written%s - %d of %d translated"
          % (len(batch), note, done, len(rows)))
    return True


# --------------------------------------------------------------------------
#  Checks
# --------------------------------------------------------------------------
def check(strict=False):
    _, _, _, _, rows = load_table()
    work = load_work()
    if not work:
        print("no working file yet - run seed")
        return False
    try:
        sys.path.insert(0, str(ROOT / "tools"))
        import fit_check
    except Exception as exc:                       # pragma: no cover
        print("fit_check unavailable (%s) - pixel widths not checked" % exc)
        fit_check = None

    ids = [i for i, _ in enum_ids()]
    errors = warnings = 0
    wider = []          # E11 envelope overflows, reported after everything else

    def err(sid, msg):
        nonlocal errors
        errors += 1
        print("  E %-34s %s" % (sid, msg))

    def warn(sid, msg):
        nonlocal warnings
        warnings += 1
        print("  w %-34s %s" % (sid, msg))

    # E1 - the table, the enum and the working file describe the same rows,
    # in the same order.
    if [r["id"] for r in rows] != ids:
        print("  E lang.cpp row order does not follow the enum in lang.h")
        errors += 1
    missing = [i for i in ids if i not in work]
    extra = [i for i in work if i not in set(ids)]
    for sid in missing:
        err(sid, "absent from the working file (run seed)")
    for sid in extra:
        err(sid, "in the working file but not in lang.h")

    # id -> every budget row naming it. An id drawn in two widgets has two rows,
    # and a dict keyed on the id alone silently kept only the last one.
    budgets = {}
    for b in (fit_check.read_budgets() if fit_check else []):
        budgets.setdefault(b["id"], []).append(b)

    # A budget naming an id that does not exist gates nothing and says nothing.
    # That has now happened twice in this fork - once in a hand-written list of
    # innerHTML ids, once here with STR_TILE_CONN for STR_TILE_CONNECTION - so
    # it gets its own check rather than another careful reading.
    for sid in sorted(set(budgets) - set(ids)):
        err(sid, "ui_budgets.tsv names an id that is not in lang.h")

    # check() reads the working file; the compiler reads src/lang.cpp. Nothing
    # was comparing the two, so a forgotten `emit` left the shipped table one
    # correction behind while every check came back green.
    #
    # A table with no third column at all is the normal state right after
    # taking upstream's lang.cpp, before `emit`. A three-column table with a
    # two-cell row is not: that row still compiles, C pads its French cell with
    # nullptr, and T() can only show the English for it.
    three = any(len(r["vals"]) > 2 for r in rows)
    for r in rows:
        want = work.get(r["id"], {}).get("fr")
        have = r["vals"][2] if len(r["vals"]) > 2 else None
        if three and have is None:
            err(r["id"], "src/lang.cpp row has no French cell - run emit")
        elif want and have is not None and want != have:
            err(r["id"], "src/lang.cpp is out of date - run emit "
                         "(shipped %r, working file %r)"
                % (have[:40], want[:40]))

    # Every icon would count as zero bytes and zero pixels, and the rows that
    # start with one are exactly the tight ones.
    if not symbol_chars() and any("{LV_SYMBOL_" in (r.get("fr") or "")
                                  for r in work.values()):
        print("  E LVGL is not unpacked (%s missing) - build the firmware once,"
              " icons cannot be measured" % LV_SYMBOL_DEF.relative_to(ROOT).as_posix())
        errors += 1

    for r in rows:
        sid = r["id"]
        rec = work.get(sid)
        if not rec:
            continue
        de, fr = r["vals"][0], rec.get("fr") or ""
        en = r["vals"][1] if len(r["vals"]) > 1 else ""

        if not fr:
            if strict and rec.get("st") != "locked":
                err(sid, "not translated")
            continue
        if rec.get("st") == "stale":
            warn(sid, "German reworded upstream since this was translated")

        sig_de, sig_fr = signature(de), signature(fr)

        # E2 / E3 - printf conversions, same specifiers IN THE SAME ORDER.
        # This is the one that crashes rather than looks wrong: C reads the
        # arguments in the order the format declares them.
        if sig_de["conv"] != sig_fr["conv"]:
            err(sid, "printf conversions differ: %s vs %s"
                     % (sig_de["conv"], sig_fr["conv"]))
        if de.count("%%") != fr.count("%%"):
            err(sid, "literal %% count differs")

        # E4 - browser-side markers, same set and never repeated: String.replace
        # with a string pattern only substitutes the first occurrence.
        if sig_de["brace"] != sig_fr["brace"]:
            err(sid, "browser markers differ: %s vs %s"
                     % (sig_de["brace"], sig_fr["brace"]))
        for b in set(sig_fr["brace"]):
            if fr.count(b) > 1:
                err(sid, "marker %s repeated - only the first is replaced" % b)

        # E5 - leading LVGL symbols, same and in the same order, with the same
        # gap before the text.
        if sig_de["symbols"] != sig_fr["symbols"]:
            err(sid, "leading LV_SYMBOL differs: %s vs %s"
                     % (sig_de["symbols"], sig_fr["symbols"]))
        elif sig_de["symbol_gaps"] != sig_fr["symbol_gaps"]:
            err(sid, "spaces after the leading LV_SYMBOL: %s, German has %s"
                     % (sig_fr["symbol_gaps"], sig_de["symbol_gaps"]))

        # E6 - hard line breaks.
        if sig_de["newlines"] != sig_fr["newlines"]:
            if signature(en)["newlines"] != sig_de["newlines"]:
                warn(sid, "\\n count %d, German %d, English %d - upstream "
                          "already disagrees, match German"
                     % (sig_fr["newlines"], sig_de["newlines"],
                        signature(en)["newlines"]))
            else:
                err(sid, "\\n count %d, German has %d"
                    % (sig_fr["newlines"], sig_de["newlines"]))

        # E7 - HTML tags and entities, and tags that close in order.
        if sig_de["tags"] != sig_fr["tags"]:
            err(sid, "HTML differs: %s vs %s" % (sig_de["tags"], sig_fr["tags"]))
        elif crossed_tags(fr) and not crossed_tags(de):
            err(sid, "HTML tags do not nest: %s" % crossed_tags(fr))

        # E8 - a bare & in a string that reaches innerHTML unescaped.
        if reaches_innerhtml(sid):
            bare = re.sub(ENTITY, "", fr)
            if "&" in bare:
                err(sid, "bare & reaches innerHTML - write \"et\"")

        # E9 - a double quote would have to be escaped in the C literal, and
        # French has proper quotation marks anyway.
        if '"' in fr.replace('\\"', ""):
            err(sid, "unescaped double quote")

        # E10 - destination buffer, in BYTES: each accent is two of them.
        if rec.get("bmax"):
            n = len(resolved(fr).encode("utf-8"))
            if n > rec["bmax"]:
                err(sid, "%d bytes > %d in the buffer" % (n, rec["bmax"]))
            elif n > rec["bmax"] - 4:
                warn(sid, "%d bytes, buffer %d - tight" % (n, rec["bmax"]))

        # E13 - a decimal comma in a row whose number arrives through printf.
        if sig_fr["conv"] and re.search(r"\d,\d", fr):
            warn(sid, "decimal comma, but the number comes from printf as a point")

        # E14 - spacing hygiene. The gap after a leading icon is two spaces on
        # purpose - the German rows write LV_SYMBOL_OK "  Berechnen" - so it is
        # not a double space to report.
        body = MACROS_ONLY.sub("", fr).lstrip()
        if "  " in body.strip() and "  " not in de:
            # A run of spaces is how some rows line their columns up -
            # "Tag:      %s" against "Spoolman: %s". If the German does it, it
            # is on purpose and the French has to do the same.
            warn(sid, "double space")
        if (fr != fr.strip() and not MACROS_ONLY.match(fr)
                and de == de.strip()):
            # Same reasoning as above: STR_DIAG_TAP really does start with two
            # spaces, because it is appended to a banner.
            warn(sid, "leading or trailing space")

        # Everything below needs the font tables. E13 and E14 above do not,
        # which is why they come first.
        if not fit_check:
            continue

        # E12 - every code point must exist in the font chain, or the screen
        # shows a hollow rectangle. Web-only strings are exempt: the browser
        # uses its own fonts. Every size carries the same glyph set, so one
        # size answers for all.
        web_only = sid.startswith("STR_W_")
        rows_b = [b for b in budgets.get(sid, []) if b["mode"] == "NEVER"]
        size = rows_b[0]["font"] if rows_b else 16
        for seg in fr.split("\\n"):
            w, miss = fit_check.width(probe_text(seg), size)
            if miss and not web_only:
                err(sid, "no glyph for %s" % " ".join(sorted(set(miss))))

        # E11 - does it fit?
        #
        # Where the real width is known it is the one to use: ui_budgets.tsv
        # carries it, and fit_check --gate turns the NEVER ones into a hard
        # failure. Everywhere else there is no width to be had, so the rule is
        # the envelope - French must not be wider than the wider of the two
        # languages upstream already made fit. That is deliberately pessimistic,
        # which is why it only warns.
        #
        # A budget describes ONE site. An id drawn in several places keeps the
        # envelope check as well: STR_WAIT_SCAN had a status-bar budget, and its
        # other widget, 58 px narrower, was ellipsising French without a word.
        #
        # Without a budget the font is not known either, and widths are rounded
        # per glyph, so two languages that tie at one size trade places by a
        # pixel at another. Every size that ships is tried and the worst kept.
        if rec.get("wover"):
            if not rec.get("note"):
                err(sid, "wover set without a note saying what proves the slack")
            continue
        if web_only:
            # The browser wraps with its own fonts: a display-font width says
            # nothing about a web page.
            continue
        de_segs, en_segs = de.split("\\n"), en.split("\\n")
        for i, seg in enumerate(fr.split("\\n")):
            for b in rows_b:
                wf, _ = fit_check.width(probe_text(seg), b["font"])
                if wf > b["budget"]:
                    err(sid, "line %d is %d px, the widget holds %d px (f%d) %s"
                        % (i + 1, wf, b["budget"], b["font"], b["site"]))
            if rows_b and len(rec.get("sites") or []) <= len(rows_b):
                continue
            sizes = (size,) if rows_b else fit_check.SIZES
            budget = rows_b[0]["budget"] if rows_b else None
            worst = None
            for s in sizes:
                wf, _ = fit_check.width(probe_text(seg), s)
                wd, _ = fit_check.width(probe_text(de_segs[i] if i < len(de_segs) else ""), s)
                we, _ = fit_check.width(probe_text(en_segs[i] if i < len(en_segs) else ""), s)
                over = wf - max(wd, we)
                if over > 0 and (worst is None or over > worst[0]):
                    worst = (over, wf, max(wd, we), s)
            if worst:
                wider.append((worst[0], sid, i + 1, worst[1], worst[2], worst[3],
                              budget is None))

    # E17 - rows where German and English are identical were usually made so on
    # purpose, to fit something narrow. Flag them so the choice is conscious.
    same = [r["id"] for r in rows
            if len(r["vals"]) > 1 and r["vals"][0] == r["vals"][1]
            and work.get(r["id"], {}).get("fr")
            and work[r["id"]]["fr"] != r["vals"][0]]
    for sid in same:
        warn(sid, "German and English are identical upstream - deliberate?")

    # E11 last and on its own, by relative overflow: hundreds of these are
    # harmless (a label that wraps, a help text that scrolls), and printed in
    # table order they buried the three that really showed an ellipsis. Sorting
    # by pixels would put every long help text first; the defects that show are
    # short labels in fixed widgets, which the ratio brings up.
    if wider:
        print("\n  Wider than both German and English - harmless where the widget"
              " wraps or has room;\n  'fonts?' means no budget names the font,"
              " so the worst of every size is shown:")
        for over, sid, line, wf, room, s, guessed in sorted(
                wider, key=lambda w: w[0] / max(w[4], 1), reverse=True):
            warn(sid, "line %d is %d px, the widest existing is %d px (+%d%%, f%d%s)"
                 % (line, wf, room, round(100 * over / max(room, 1)), s,
                    ", fonts?" if guessed else ""))

    done = sum(1 for r in work.values() if r.get("fr"))
    print("\n  %d rows, %d translated, %d error(s), %d warning(s)"
          % (len(rows), done, errors, warnings))
    return errors == 0


# --------------------------------------------------------------------------
#  Emitting
# --------------------------------------------------------------------------
def is_multiline(row):
    return "\n" in row["cells"][0] or "\n" in row["cells"][1]


def flush_run(slots, run):
    """Render a run of short rows with one column width for the whole run."""
    if not run:
        return
    pad_de = max(len(r["cells"][0].strip()) for _, r, _ in run)
    pad_en = max(len(r["cells"][1].strip()) for _, r, _ in run)
    for i, r, lit in run:
        slots[i] = render_row(r, lit, (pad_de, pad_en))
    run.clear()


def render_row(row, fr_literal, pad=(0, 0)):
    """One table row with three columns, WITHOUT its leading indentation.

    The whitespace between rows is preserved as-is by the caller, so it already
    supplies the two spaces this row sits at.

    A short row is re-laid-out on one line and aligned within its run, the way
    the file already reads. A short row the French makes too long goes onto a
    second line, from its stripped cells too: kept verbatim, it carried the
    padding of whatever file it was read from, so emitting from upstream's two
    columns and from an already emitted file gave two layouts. An already
    wrapped row keeps each cell's own source text verbatim - line splits
    included - and the French cell is added after it. Either way the German and
    English TEXT is untouched; only the padding of a short row moves, and that
    line changes anyway.
    """
    if not is_multiline(row):
        de, en = row["cells"][0].strip(), row["cells"][1].strip()
        one = "{ %s,%s %s,%s %s },  // %s" % (
            de, " " * max(0, pad[0] - len(de)),
            en, " " * max(0, pad[1] - len(en)),
            fr_literal, row["id"])
        if len(one) + 2 <= LINE_MAX:
            return one
        return "{ %s, %s,\n    %s },  // %s" % (de, en, fr_literal, row["id"])
    return "{%s,%s,\n    %s },  // %s" % (
        row["cells"][0].rstrip(), row["cells"][1].rstrip(),
        fr_literal, row["id"])


MACROS_ONLY = re.compile(r"^(?:\{LV_SYMBOL_\w+\})+")


def c_literal(text):
    """A C string literal for text already written with C escapes.

    The working file stores what the cell prints, escapes included (\\n stays
    two characters), so this only has to wrap it in quotes. A leading
    {LV_SYMBOL_X} marker becomes the macro again, outside the quotes, exactly as
    the file writes it.

    The spacing after the icon stays INSIDE the literal, because that is where
    the file puts it: LV_SYMBOL_OK "  Berechnen" is the icon followed by two
    spaces of gap. Consuming them here would glue the label to its icon.
    """
    m = MACROS_ONLY.match(text)
    if m:
        macros = re.findall(r"\{(LV_SYMBOL_\w+)\}", m.group(0))
        rest = text[m.end():]
        head = " ".join(macros)
        return (head + ' "%s"' % rest) if rest else head
    return '"%s"' % text


def emit():
    src, prefix, items, suffix, rows = load_table()
    work = load_work()
    if not work:
        print("no working file - run seed")
        return False

    # Fall back to English for anything untranslated: a null cell would be a
    # null pointer at run time, and lv_label_set_text does not survive one.
    # English also means a half-finished translation is still a usable device.
    # Rebuild the body item by item, so every group comment, blank line and bit
    # of indentation between rows survives untouched.
    #
    # Short rows are aligned within a "run" - consecutive single-line rows with
    # nothing but plain line breaks between them. A blank line, a group comment
    # or a wrapped row ends the run and starts a new column width, which is
    # exactly how the file already reads.
    def ends_run(raw):
        return "//" in raw or raw.count("\n") > 1

    slots = []            # index in `slots` of each rendered piece
    run = []              # indices into slots that belong to the current run
    for kind, it in items:
        if kind == "raw":
            if ends_run(it):
                flush_run(slots, run)
            slots.append(it)
            continue
        rec = work.get(it["id"], {})
        fr = rec.get("fr") or (it["vals"][1] if len(it["vals"]) > 1 else "")
        lit = c_literal(fr)
        if is_multiline(it):
            flush_run(slots, run)
            slots.append(render_row(it, lit))
        else:
            slots.append(None)                 # filled in by flush_run
            run.append((len(slots) - 1, it, lit))
    flush_run(slots, run)

    body = "".join(slots)
    new = prefix.replace(OPEN2, OPEN3) + body + suffix
    # The comments of the product that describe the table itself. Rewritten here
    # rather than edited by hand in lang.cpp, because the rebase recipe starts
    # from upstream's file and a hand edit would be lost every time.
    new = new.replace('// Format: { "Deutsch", "English" }',
                      '// Format: { "Deutsch", "English", "Francais" }')
    new = new.replace("//  lang.cpp - String table DE / EN\n",
                      "//  lang.cpp - String table DE / EN / FR\n")
    new = new.replace("gap onwards reads as the wrong one, in both languages, and",
                      "gap onwards reads as the wrong one, in every language, and")
    LANG_CPP.write_text(new, encoding="utf-8", newline="\n")

    # Content preservation: re-read and prove no German or English text moved.
    _, _, _, _, again = load_table()
    bad = [a["id"] for a, b in zip(again, rows)
           if a["vals"][0] != b["vals"][0] or a["vals"][1] != b["vals"][1]]
    done = sum(1 for r in work.values() if r.get("fr"))
    if bad:
        print("EMIT CHANGED German or English text on %d row(s): %s"
              % (len(bad), ", ".join(bad[:5])))
        return False
    print("emitted %d rows to src/lang.cpp (%d French, %d falling back to English)"
          % (len(rows), done, len(rows) - done))
    print("  German and English text verified byte-identical.")
    return True


def roundtrip():
    """Proves the parser: re-emit every row from its own bytes and compare."""
    src, prefix, items, suffix, rows = load_table()
    rebuilt = prefix + "".join(
        it if kind == "raw" else it["text"] for kind, it in items) + suffix
    if rebuilt == src:
        print("roundtrip OK: %d rows, %d raw segments, file identical byte for byte"
              % (len(rows), sum(1 for k, _ in items if k == "raw")))
        multi = sum(1 for r in rows if "\n" in r["text"])
        braces = [r["id"] for r in rows if re.search(r'"[^"]*\{', r["text"])]
        quotes = [r["id"] for r in rows if '\\"' in r["text"]]
        macros = [r["id"] for r in rows if SYMBOL.match(r["vals"][0])]
        print("  %d rows span several lines" % multi)
        print("  %d rows have a brace inside a literal (%s...)"
              % (len(braces), ", ".join(braces[:3])))
        print("  %d rows have an escaped quote" % len(quotes))
        print("  %d rows start with an LV_SYMBOL macro" % len(macros))
        return True
    for i, (a, b) in enumerate(zip(src, rebuilt)):
        if a != b:
            print("roundtrip FAILED at offset %d" % i)
            print("  original: %r" % src[max(0, i - 60):i + 60])
            print("  rebuilt : %r" % rebuilt[max(0, i - 60):i + 60])
            return False
    print("roundtrip FAILED: length %d vs %d" % (len(src), len(rebuilt)))
    return False


def dump(patterns, todo_only=True):
    """Print the rows to translate, with everything needed to translate them.

    One row per entry: the German it comes from, the English that settles an
    ambiguity, and the constraints - destination buffer in bytes, printf
    conversions, browser markers, leading icon, hard line breaks, HTML. A
    translator (or a script feeding `apply`) needs nothing else.

        python tools/lang_fr.py dump                       everything left
        python tools/lang_fr.py dump --group "AMS view"    one section
        python tools/lang_fr.py dump --all --group Navigation   done ones too
    """
    work = load_work()
    if not work:
        print("no working file - run seed")
        return False
    pats = [p.lower() for p in patterns]
    shown = 0
    for rec in work.values():
        if todo_only and rec.get("fr"):
            continue
        grp = (rec.get("grp") or "").lower()
        if pats and not any(p in grp or p in rec["id"].lower() for p in pats):
            continue
        s = rec["sig"]
        bits = []
        if rec.get("bmax"):
            bits.append("buffer %d bytes" % rec["bmax"])
        if s["conv"]:
            bits.append("printf " + " ".join(s["conv"]) + " (same order!)")
        if s["brace"]:
            bits.append("markers " + " ".join(s["brace"]))
        if s["symbols"]:
            bits.append("icon " + ",".join(s["symbols"]))
        if s["newlines"]:
            bits.append("%d line break(s), write them <NL>" % s["newlines"])
        if s["tags"]:
            bits.append("html " + " ".join(s["tags"]))
        print("### %s%s" % (rec["id"], ("   [" + " | ".join(bits) + "]") if bits else ""))
        print("DE: %s" % rec["de"])
        print("EN: %s" % rec["en"])
        if rec.get("fr"):
            print("FR: %s" % rec["fr"])
        shown += 1
    print("\n# %d row(s)%s" % (shown, " still to translate" if todo_only else ""))
    return True


def report():
    work = load_work()
    if not work:
        print("no working file - run seed")
        return False
    groups = {}
    for r in work.values():
        g = groups.setdefault(r["grp"] or "(no group)", [0, 0])
        g[0] += 1
        g[1] += 1 if r.get("fr") else 0
    print("%-46s %6s %6s" % ("group", "rows", "done"))
    for g in sorted(groups):
        n, d = groups[g]
        print("%-46s %6d %6d%s" % (g[:46], n, d, "  <-- complete" if n == d else ""))
    tight = sorted((r for r in work.values() if r.get("bmax")),
                   key=lambda r: r["bmax"])[:20]
    print("\ntightest buffers:")
    for r in tight:
        used = len((r.get("fr") or r["de"]).encode("utf-8"))
        print("  %-34s buffer %3d  current %3d  %s"
              % (r["id"], r["bmax"], used, (r.get("fr") or "")[:28]))
    return True


def main():
    ap = argparse.ArgumentParser(description="The French column of lang.cpp.")
    ap.add_argument("mode", choices=("roundtrip", "seed", "dump", "apply",
                                     "check", "emit", "report"))
    ap.add_argument("--strict", action="store_true",
                    help="check: every row must be translated")
    ap.add_argument("--group", action="append", default=[], metavar="TEXT",
                    help="dump: only sections or ids matching TEXT")
    ap.add_argument("--all", action="store_true",
                    help="dump: include the rows already translated")
    a = ap.parse_args()
    fn = {"roundtrip": roundtrip, "seed": seed, "apply": apply_batch,
          "emit": emit, "report": report,
          "dump": lambda: dump(a.group, not a.all),
          "check": lambda: check(a.strict)}[a.mode]
    return 0 if fn() else 1


if __name__ == "__main__":
    sys.exit(main())
