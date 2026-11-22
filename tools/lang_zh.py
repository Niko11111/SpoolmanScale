#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  SpoolmanScale – Localization (i18n)
#  lang_zh.py - Simplified Chinese (zh-CN) column: working file, checks, emitter
#  简体中文（zh-CN）词表管理、全量校验与 src/lang.cpp 生成脚本
#  Based on lang_fr.py by Nanostra (Frédéric Dubus)
# ============================================================
#
#  Usage / 用法:
#    python tools/lang_zh.py roundtrip              Proves the parser byte-identical (run first)
#                                                   验证解析器无损还原（建议优先运行）
#    python tools/lang_zh.py seed                   (Re)build tools/lang_zh.jsonl from src/lang.cpp
#                                                   从 src/lang.cpp 生成或同步词表 tools/lang_zh.jsonl
#    python tools/lang_zh.py dump                   Dump untranslated rows with their constraints
#                                                   导出尚未翻译的条目及其约束条件
#    python tools/lang_zh.py apply --file xx.json   Import {"STR_X": "中文"} JSON into lang_zh.jsonl
#                                                   将 {"STR_X": "中文"} 格式 JSON 批量导入词表
#    python tools/lang_zh.py coverage               Fails while any row has no Chinese translation
#                                                   检查翻译覆盖率（存在未翻译条目时返回非零）
#    python tools/lang_zh.py check                  Run all checks (--strict demands 100% translated)
#                                                   执行全量校验（占位符/字节/像素宽度；--strict 要求全译）
#    python tools/lang_zh.py emit                   Write src/lang.cpp with 4 columns (DE/EN/FR/ZH)
#                                                   将译文写入 src/lang.cpp（四列：德/英/法/中）
#    python tools/lang_zh.py report                 Show coverage summary and tightest budget rows
#                                                   输出覆盖率统计与最接近预算上限的条目报告
# ============================================================
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LANG_H = ROOT / "src" / "lang.h"
LANG_CPP = ROOT / "src" / "lang.cpp"
WORK = ROOT / "tools" / "lang_zh.jsonl"
WIDTH_BASELINE = ROOT / "tools" / "zh_width_baseline.txt"

# Never walk from the repository root: copy_release.py leaves stale copies of
# lang.cpp under releases/*/source/, and a recursive search would find them.
SRC = ROOT / "src"

LANGS = ("de", "en", "fr", "zh")
OPEN3 = "const char* const STRINGS[][3] = {"
OPEN4 = "const char* const STRINGS[][4] = {"

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
    """(prefix, items, suffix)."""
    for opener in (OPEN4, OPEN3):
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
    """The StringIDs in enum order, with the section heading above each run."""
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
    """LV_SYMBOL_X -> the character it stands for."""
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
    """The value with every {LV_SYMBOL_X} marker replaced by its character."""
    chars = symbol_chars()
    return MARKER.sub(lambda m: chars.get(m.group(1), ""), text)


def probe_text(text):
    """What to hand the width engine: symbols resolved, any other macro dropped."""
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
        "symbol_gaps": [len(g) for g in re.findall(r"\}(\s*)", m.group(0))] if m else [],
        "newlines": v.count("\\n"),
        "tags": sorted(TAG.findall(v)),
    }


def crossed_tags(v):
    """The first tag that closes out of order, or None."""
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


def reaches_innerhtml(sid):
    return sid.startswith("STR_W_")


# --------------------------------------------------------------------------
#  Buffer budgets
# --------------------------------------------------------------------------
COPYT = re.compile(r"copyT\s*\(\s*(\w+)\s*,\s*sizeof\s*\(\s*\1\s*\)\s*,([^;]*?)\)\s*;")
COPYT_IDS = re.compile(r"\bSTR_\w+")

CHARDECL = re.compile(r"\bchar\s+([^;]+?)\s*;")
DECLARATOR = re.compile(r"(\w+)\s*\[\s*([A-Za-z_0-9][A-Za-z_0-9\s+-]*?)\s*\]")
SIZE_TERM = re.compile(r"\s*([+-])?\s*([A-Za-z_0-9]+)")
DEFINE = re.compile(r"^\s*#define\s+(\w+)\s+\(?\s*(\d+)\s*\)?\s*(?://.*)?$", re.M)


def code_only(text):
    """Comments and the inside of string and character literals blanked out."""
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
    """Every simple numeric #define in src/, for the buffers sized by name."""
    out = {}
    for path in sorted(SRC.rglob("*.h")) + sorted(SRC.rglob("*.cpp")):
        for name, val in DEFINE.findall(
                path.read_text(encoding="utf-8", errors="replace")):
            out.setdefault(name, int(val))
    return out


def _size(expr, defines):
    """Bytes of a declarator size - a number, a define, or a sum of those."""
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
    """id -> smallest destination buffer, in usable bytes, over every copyT site."""
    defines = _defines()
    out, unresolved = {}, []
    for path in sorted(SRC.rglob("*.cpp")) + sorted(SRC.rglob("*.h")):
        text = code_only(path.read_text(encoding="utf-8", errors="replace"))
        sizes = []
        for d in CHARDECL.finditer(text):
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
                        best = n
                if best is None:
                    unresolved.append((path.relative_to(ROOT).as_posix(), sid, name))
                    continue
                out[sid] = min(out.get(sid, 10 ** 6), best - 1)
    return out, unresolved


CALLSITE = re.compile(r"\b(STR_\w+)\b")


def call_sites():
    """id -> ['path:line', ...]."""
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


def write_lf(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def save_work(rows):
    write_lf(WORK,
             "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                     for r in rows))


HUMAN = ("zh", "st", "note", "wover")


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
            "fr": r["vals"][2] if len(r["vals"]) > 2 else "",
            "zh": prev.get("zh", ""),
            "sig": signature(r["vals"][0]),
            "bmax": budgets.get(sid),
            "sites": sites.get(sid, [])[:4],
            "st": prev.get("st", "todo"),
            "note": prev.get("note", ""),
            "wover": prev.get("wover"),
        }
        if prev and prev.get("de") not in (None, rec["de"]) and prev.get("zh"):
            rec["st"] = "stale"
            rec["note"] = (prev.get("note", "") +
                           " | DE reworded upstream, re-read").strip(" |")
        out.append(rec)

    save_work(out)
    done = sum(1 for r in out if r["zh"])
    print("seeded %d rows -> %s" % (len(out), WORK.relative_to(ROOT).as_posix()))
    print("  Chinese written: %d   remaining: %d" % (done, len(out) - done))
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


def chinese_strings():
    """{id: chinese text} for fit_check --gate."""
    return {r["id"]: r["zh"] for r in load_work().values() if r["zh"]}


NL_TOKEN = "<NL>"
NL_ESCAPE = chr(92) + "n"


def apply_batch(stream=None):
    """Read {"STR_X": "中文", ...} as JSON and write it into the working file."""
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
            rec["zh"] = batch[sid]
            rec["st"] = "ok"
        rows.append(rec)
    order = {sid: i for i, (sid, _) in enumerate(enum_ids())}
    rows.sort(key=lambda r: order.get(r["id"], 10 ** 6))
    save_work(rows)

    done = sum(1 for r in rows if r.get("zh"))
    note = " (%d line break(s) normalised)" % normalised if normalised else ""
    print("%d row(s) written%s - %d of %d translated"
          % (len(batch), note, done, len(rows)))
    return True


def coverage():
    """Fails while a row has no Chinese."""
    work = load_work()
    ids = [i for i, _ in enum_ids()]
    missing = [i for i in ids if i not in work]
    todo = [i for i in ids if i in work and not work[i].get("zh")]
    stale = [i for i in ids if i in work and work[i].get("st") == "stale"]
    for sid in missing:
        print("  E %-34s not in the working file - run seed" % sid)
    for sid in todo:
        print("  E %-34s no Chinese - add it with apply" % sid)
    for sid in stale:
        print("  E %-34s German reworded since the Chinese was written" % sid)
    bad = len(missing) + len(todo) + len(stale)
    print("\n  %d rows, %d without Chinese" % (len(ids), bad))
    return bad == 0


# --------------------------------------------------------------------------
#  Checks
# --------------------------------------------------------------------------
def read_width_baseline():
    """The ids in zh_width_baseline.txt, one per line, '#' starts a comment."""
    if not WIDTH_BASELINE.exists():
        return set()
    lines = WIDTH_BASELINE.read_text(encoding="utf-8").splitlines()
    return {l.split("#")[0].strip() for l in lines} - {""}


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
    wider = []
    baseline = read_width_baseline()
    still_wider = set()

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

    budgets = {}
    for b in (fit_check.read_budgets() if fit_check else []):
        budgets.setdefault(b["id"], []).append(b)

    for sid in sorted(set(budgets) - set(ids)):
        err(sid, "ui_budgets.tsv names an id that is not in lang.h")

    four = any(len(r["vals"]) > 3 for r in rows)
    for r in rows:
        want = work.get(r["id"], {}).get("zh")
        have = r["vals"][3] if len(r["vals"]) > 3 else None
        if four and have is None:
            err(r["id"], "src/lang.cpp row has no Chinese cell - run emit")
        elif want and have is not None and want != have:
            err(r["id"], "src/lang.cpp is out of date - run emit "
                         "(shipped %r, working file %r)"
                % (have[:40], want[:40]))

    if not symbol_chars() and any("{LV_SYMBOL_" in (r.get("zh") or "")
                                  for r in work.values()):
        print("  E LVGL is not unpacked (%s missing) - build the firmware once,"
              " icons cannot be measured" % LV_SYMBOL_DEF.relative_to(ROOT).as_posix())
        errors += 1

    for r in rows:
        sid = r["id"]
        rec = work.get(sid)
        if not rec:
            continue
        de, zh = r["vals"][0], rec.get("zh") or ""
        en = r["vals"][1] if len(r["vals"]) > 1 else ""

        if not zh:
            if strict and rec.get("st") != "locked":
                err(sid, "not translated")
            continue
        if rec.get("st") == "stale":
            warn(sid, "German reworded upstream since this was translated")

        sig_de, sig_zh = signature(de), signature(zh)

        # E2 / E3 - printf conversions, same specifiers IN THE SAME ORDER.
        if sig_de["conv"] != sig_zh["conv"]:
            err(sid, "printf conversions differ: %s vs %s"
                     % (sig_de["conv"], sig_zh["conv"]))
        if de.count("%%") != zh.count("%%"):
            err(sid, "literal %% count differs")

        # E4 - browser-side markers, same set and never repeated.
        if sig_de["brace"] != sig_zh["brace"]:
            err(sid, "browser markers differ: %s vs %s"
                     % (sig_de["brace"], sig_zh["brace"]))
        for b in set(sig_zh["brace"]):
            if zh.count(b) > 1:
                err(sid, "marker %s repeated - only the first is replaced" % b)

        # E5 - leading LVGL symbols, same and in the same order, with the same gap.
        if sig_de["symbols"] != sig_zh["symbols"]:
            err(sid, "leading LV_SYMBOL differs: %s vs %s"
                     % (sig_de["symbols"], sig_zh["symbols"]))
        elif sig_de["symbol_gaps"] != sig_zh["symbol_gaps"]:
            err(sid, "spaces after the leading LV_SYMBOL: %s, German has %s"
                     % (sig_zh["symbol_gaps"], sig_de["symbol_gaps"]))

        # E6 - hard line breaks.
        if sig_de["newlines"] != sig_zh["newlines"]:
            if signature(en)["newlines"] != sig_de["newlines"]:
                warn(sid, "\\n count %d, German %d, English %d - upstream "
                          "already disagrees, match German"
                     % (sig_zh["newlines"], sig_de["newlines"],
                        signature(en)["newlines"]))
            else:
                err(sid, "\\n count %d, German has %d"
                    % (sig_zh["newlines"], sig_de["newlines"]))

        # E7 - HTML tags and entities, and tags that close in order.
        if sig_de["tags"] != sig_zh["tags"]:
            err(sid, "HTML differs: %s vs %s" % (sig_de["tags"], sig_zh["tags"]))
        elif crossed_tags(zh) and not crossed_tags(de):
            err(sid, "HTML tags do not nest: %s" % crossed_tags(zh))

        # E8 - a bare & in a string that reaches innerHTML unescaped.
        if reaches_innerhtml(sid):
            bare = re.sub(ENTITY, "", zh)
            if "&" in bare:
                err(sid, "bare & reaches innerHTML - use &amp; or 和")

        # E9 - unescaped double quote.
        if '"' in zh.replace('\\"', ""):
            err(sid, "unescaped double quote")

        # E10 - destination buffer, in BYTES (each Chinese char is 3 bytes in UTF-8).
        if rec.get("bmax"):
            n = len(resolved(zh).encode("utf-8"))
            if n > rec["bmax"]:
                err(sid, "%d bytes > %d in the buffer" % (n, rec["bmax"]))
            elif n > rec["bmax"] - 4:
                warn(sid, "%d bytes, buffer %d - tight" % (n, rec["bmax"]))

        # E13 - a decimal comma in a row whose number arrives through printf.
        if sig_zh["conv"] and re.search(r"\d,\d", zh):
            warn(sid, "decimal comma, but the number comes from printf as a point")

        # E14 - spacing hygiene.
        body = MACROS_ONLY.sub("", zh).lstrip()
        if "  " in body.strip() and "  " not in de:
            warn(sid, "double space")
        if (zh != zh.strip() and not MACROS_ONLY.match(zh)
                and de == de.strip()):
            warn(sid, "leading or trailing space")

        if not fit_check:
            continue

        # E12 - every code point must exist in the font chain.
        web_only = sid.startswith("STR_W_")
        rows_b = [b for b in budgets.get(sid, []) if b["mode"] == "NEVER"]
        size = rows_b[0]["font"] if rows_b else 16
        for seg in zh.split("\\n"):
            w, miss = fit_check.width(probe_text(seg), size)
            if miss and not web_only:
                err(sid, "no glyph for %s" % " ".join(sorted(set(miss))))

        # E11 - does it fit?
        if rec.get("wover"):
            if not rec.get("note"):
                err(sid, "wover set without a note saying what proves the slack")
            continue
        if web_only:
            continue
        de_segs, en_segs = de.split("\\n"), en.split("\\n")
        for i, seg in enumerate(zh.split("\\n")):
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
                if not rows_b:
                    if sid not in baseline:
                        err(sid, "line %d is %d px, wider than German and English "
                                 "(%d px, f%d) - shorten it or give it a budget"
                            % (i + 1, worst[1], worst[2], worst[3]))
                        continue
                    still_wider.add(sid)
                wider.append((worst[0], sid, i + 1, worst[1], worst[2], worst[3],
                              budget is None))

    # E17 - rows where German and English are identical.
    same = [r["id"] for r in rows
            if len(r["vals"]) > 1 and r["vals"][0] == r["vals"][1]
            and work.get(r["id"], {}).get("zh")
            and work[r["id"]]["zh"] != r["vals"][0]]
    for sid in same:
        warn(sid, "German and English are identical upstream - deliberate?")

    if wider:
        print("\n  Wider than both German and English - harmless where the widget"
              " wraps or has room;\n  'fonts?' means no budget names the font,"
              " so the worst of every size is shown:")
        for over, sid, line, wf, room, s, guessed in sorted(
                wider, key=lambda w: w[0] / max(w[4], 1), reverse=True):
            warn(sid, "line %d is %d px, the widest existing is %d px (+%d%%, f%d%s)"
                 % (line, wf, room, round(100 * over / max(room, 1)), s,
                    ", fonts?" if guessed else ""))

    if fit_check:
        for sid in sorted(baseline - still_wider):
            warn(sid, "fits now - remove it from %s" % WIDTH_BASELINE.name)

    done = sum(1 for r in work.values() if r.get("zh"))
    print("\n  %d rows, %d translated, %d error(s), %d warning(s)"
          % (len(rows), done, errors, warnings))
    return errors == 0


# --------------------------------------------------------------------------
#  Emitting
# --------------------------------------------------------------------------
def is_multiline(row):
    return any("\n" in c for c in row["cells"][:3])


def flush_run(slots, run):
    """Render a run of short rows with one column width for the whole run."""
    if not run:
        return
    pad_de = max(len(r["cells"][0].strip()) for _, r, _ in run)
    pad_en = max(len(r["cells"][1].strip()) for _, r, _ in run)
    pad_fr = max(len(r["cells"][2].strip()) for _, r, _ in run)
    for i, r, lit in run:
        slots[i] = render_row(r, lit, (pad_de, pad_en, pad_fr))
    run.clear()


def render_row(row, zh_literal, pad=(0, 0, 0)):
    """One table row with four columns, WITHOUT its leading indentation."""
    if not is_multiline(row):
        de = row["cells"][0].strip()
        en = row["cells"][1].strip()
        fr = row["cells"][2].strip()
        one = "{ %s,%s %s,%s %s,%s %s },  // %s" % (
            de, " " * max(0, pad[0] - len(de)),
            en, " " * max(0, pad[1] - len(en)),
            fr, " " * max(0, pad[2] - len(fr)),
            zh_literal, row["id"])
        if len(one) + 2 <= LINE_MAX:
            return one
        return "{ %s, %s, %s,\n    %s },  // %s" % (de, en, fr, zh_literal, row["id"])
    return "{%s,%s,%s,\n    %s },  // %s" % (
        row["cells"][0].rstrip(), row["cells"][1].rstrip(), row["cells"][2].rstrip(),
        zh_literal, row["id"])


MACROS_ONLY = re.compile(r"^(?:\{LV_SYMBOL_\w+\})+")


def c_literal(text):
    """A C string literal for text already written with C escapes."""
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

    def ends_run(raw):
        return "//" in raw or raw.count("\n") > 1

    slots = []
    run = []
    for kind, it in items:
        if kind == "raw":
            if ends_run(it):
                flush_run(slots, run)
            slots.append(it)
            continue
        rec = work.get(it["id"], {})
        zh = rec.get("zh") or (it["vals"][1] if len(it["vals"]) > 1 else "")
        lit = c_literal(zh)
        if is_multiline(it):
            flush_run(slots, run)
            slots.append(render_row(it, lit))
        else:
            slots.append(None)
            run.append((len(slots) - 1, it, lit))
    flush_run(slots, run)

    body = "".join(slots)
    new = prefix.replace(OPEN3, OPEN4) + body + suffix
    new = new.replace('// Format: { "Deutsch", "English", "Francais" }',
                      '// Format: { "Deutsch", "English", "Francais", "Chinese" }')
    new = new.replace("//  lang.cpp - String table DE / EN / FR\n",
                      "//  lang.cpp - String table DE / EN / FR / ZH\n")
    write_lf(LANG_CPP, new)

    # Content preservation: re-read and prove DE, EN, FR text did not move.
    _, _, _, _, again = load_table()
    bad = [a["id"] for a, b in zip(again, rows)
           if a["vals"][0] != b["vals"][0]
           or a["vals"][1] != b["vals"][1]
           or a["vals"][2] != b["vals"][2]]
    done = sum(1 for r in work.values() if r.get("zh"))
    if bad:
        print("EMIT CHANGED DE/EN/FR text on %d row(s): %s"
              % (len(bad), ", ".join(bad[:5])))
        return False
    print("emitted %d rows to src/lang.cpp (%d Chinese, %d falling back to English)"
          % (len(rows), done, len(rows) - done))
    print("  German, English and French text verified byte-identical.")
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
    """Print the rows to translate, with everything needed to translate them."""
    work = load_work()
    if not work:
        print("no working file - run seed")
        return False
    pats = [p.lower() for p in patterns]
    shown = 0
    for rec in work.values():
        if todo_only and rec.get("zh"):
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
        if rec.get("zh"):
            print("ZH: %s" % rec["zh"])
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
        g[1] += 1 if r.get("zh") else 0
    print("%-46s %6s %6s" % ("group", "rows", "done"))
    for g in sorted(groups):
        n, d = groups[g]
        print("%-46s %6d %6d%s" % (g[:46], n, d, "  <-- complete" if n == d else ""))
    tight = sorted((r for r in work.values() if r.get("bmax")),
                   key=lambda r: r["bmax"])[:20]
    print("\ntightest buffers:")
    for r in tight:
        used = len((r.get("zh") or r["de"]).encode("utf-8"))
        print("  %-34s buffer %3d  current %3d  %s"
              % (r["id"], r["bmax"], used, (r.get("zh") or "")[:28]))
    return True


def run_apply(path):
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return apply_batch(f)
    return apply_batch()


def main():
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="The Chinese column of lang.cpp.")
    ap.add_argument("mode", choices=("roundtrip", "seed", "dump", "apply",
                                     "coverage", "check", "emit", "report"))
    ap.add_argument("--strict", action="store_true",
                    help="check: every row must be translated")
    ap.add_argument("--group", action="append", default=[], metavar="TEXT",
                    help="dump: only sections or ids matching TEXT")
    ap.add_argument("--all", action="store_true",
                    help="dump: include the rows already translated")
    ap.add_argument("--file", metavar="PATH",
                    help="apply: read UTF-8 JSON from file instead of stdin")
    a = ap.parse_args()
    fn = {"roundtrip": roundtrip, "seed": seed,
          "apply": lambda: run_apply(a.file),
          "coverage": coverage,
          "emit": emit, "report": report,
          "dump": lambda: dump(a.group, not a.all),
          "check": lambda: check(a.strict)}[a.mode]
    return 0 if fn() else 1


if __name__ == "__main__":
    sys.exit(main())