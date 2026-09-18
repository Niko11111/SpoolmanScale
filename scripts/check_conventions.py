#!/usr/bin/env python3
"""Convention ratchet for the firmware sources.

Counts the house rules a grep cannot hold: what an LVGL event handler does,
where a colour is written as a number, which caption bypasses the string
table. Every number is compared with scripts/conventions_baseline.json and
may stay or fall, never rise. A few must be zero outright.

    python3 scripts/check_conventions.py                  check against the baseline
    python3 scripts/check_conventions.py --verbose        list every finding as well
    python3 scripts/check_conventions.py --write-baseline
        rewrite the baseline. Only after numbers went DOWN, committed together
        with the change that made them go down.
    python3 scripts/check_conventions.py --selftest       the scanners against fixtures

Exit 0 green, 1 a number rose, 2 no baseline or a scanner that found nothing
to scan. Standard library only, Python 3.9. The C++ side is a tokenizer plus
brace matching, not a parser: good enough for a ratchet, not a linter.
"""

import argparse
import bisect
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "scripts" / "conventions_baseline.json"

MAX_FILE_LINES = 1000
LINES_PREFIX = "lines:"
SOURCE_SUFFIXES = (".cpp", ".h", ".hpp")
# Generated glyph tables: tens of thousands of lines nobody writes by hand.
SKIP_PREFIXES = ("src/fonts/",)
# Large by construction: the string table, its enum, the vendor configuration.
FILE_SIZE_EXEMPT = {"src/lang.cpp", "src/lang.h", "src/lv_conf.h"}
# Where the panel is drawn. Colours and captions are counted here only.
UI_SCOPE = ("src/ui/", "src/app/")
# The string table carries German text by design.
GERMAN_EXEMPT = {"src/lang.cpp"}
# Routes that answer without a gate on purpose, each with its reason.
GATE_EXEMPT = {
    "src/web/web_portal.cpp": "WiFi setup portal: its own server, up only while its screen is open",
    "src/web/web_assets.cpp": "logo and favicons, asked for even by the page that says the interface is off",
    "src/web/web_static.cpp": "the shared stylesheet and script: constant text, nothing in it to protect",
}
# A function the call graph reaches that does not block after all: name -> reason.
HTTP_SAFE = {}

# Never part of a baseline. A baseline written with one of these open would
# turn the ratchet green on a real fault.
MUST_BE_ZERO = (
    "delay_in_handler",
    "strncpy_with_T_unterminated",
    "create_nested_object",
    "web_route_without_gate",
    "scanner_unbalanced_files",
)


# --------------------------------------------------------------------------
# Tokenizer
# --------------------------------------------------------------------------

TOKEN_RE = re.compile(
    r'//[^\n]*'
    r'|/\*.*?\*/'
    r'|R"([^()\\\s]{0,16})\(.*?\)\1"'
    r'|"(?:[^"\\\n]|\\.)*"'
    r"|'(?:[^'\\\n]|\\.)+'",
    re.S)
_BRACES = re.compile(r"[{}]")
_PARENS = re.compile(r"[()]")


def _blank(text):
    return re.sub(r"[^\n]", " ", text)


class Source(object):
    """One file in aligned views. code and code_str have the length of the
    original text, so an offset found in one is valid in the other and a line
    number is the count of newlines before it.

    code      comments blanked, string and char contents blanked
    code_str  comments blanked, literals kept
    comments  [(line, text)] one entry per comment line
    strings   [(start, end)] offsets of every string literal, quotes included
    """

    def __init__(self, text):
        self.text = text
        self._newlines = [m.start() for m in re.finditer("\n", text)]
        code, code_str, self.comments, self.strings = [], [], [], []
        pos = 0
        for m in TOKEN_RE.finditer(text):
            tok = m.group(0)
            gap = text[pos:m.start()]
            code.append(gap)
            code_str.append(gap)
            if tok.startswith("//") or tok.startswith("/*"):
                blank = _blank(tok)
                code.append(blank)
                code_str.append(blank)
                body = tok[2:] if tok.startswith("//") else tok[2:-2]
                first = self.line_of(m.start())
                for k, part in enumerate(body.split("\n")):
                    self.comments.append((first + k, part))
            elif tok[0] == "'":
                code.append("'" + _blank(tok[1:-1]) + "'")
                code_str.append(tok)
            else:
                head = 2 if tok[0] == "R" else 1
                code.append(tok[:head] + _blank(tok[head:-1]) + '"')
                code_str.append(tok)
                self.strings.append((m.start(), m.end()))
            pos = m.end()
        code.append(text[pos:])
        code_str.append(text[pos:])
        self.code = "".join(code)
        self.code_str = "".join(code_str)
        self._string_starts = [s for s, _ in self.strings]

    def line_of(self, offset):
        return bisect.bisect_left(self._newlines, offset) + 1

    def literals_between(self, start, end):
        """The string literals that lie wholly inside [start, end)."""
        first = bisect.bisect_left(self._string_starts, start)
        out = []
        for s, e in self.strings[first:]:
            if s >= end:
                break
            if e <= end:
                out.append(self.text[s:e])
        return out

    def balanced(self):
        c = self.code
        return c.count("{") == c.count("}") and c.count("(") == c.count(")")


def match_close(s, i, pattern, open_ch):
    """Offset of the bracket that closes the one at s[i], or -1."""
    depth = 0
    for m in pattern.finditer(s, i):
        if s[m.start()] == open_ch:
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return m.start()
    return -1


def first_top_level_comma(s, start, end):
    depth = 0
    for i in range(start, end):
        ch = s[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return i
    return -1


# --------------------------------------------------------------------------
# LVGL event handlers
# --------------------------------------------------------------------------

HANDLER_RE = re.compile(
    r'(?:\[[^\]]*\]\s*\(\s*lv_event_t\s*\*?\s*\w*\s*\)'
    r'|\bvoid\s+(\w+)\s*\(\s*lv_event_t\s*\*\s*\w*\s*\))'
    r'\s*(?:->\s*\w+\s*)?\{')


def handlers(src):
    """[(name, header_start, body_start, body_end)]. A prototype has no brace
    and does not match. A handler nested in another is listed as well."""
    out = []
    for m in HANDLER_RE.finditer(src.code):
        body_start = m.end() - 1
        body_end = match_close(src.code, body_start, _BRACES, "{")
        if body_end < 0:
            continue
        out.append((m.group(1) or "lambda", m.start(), body_start, body_end))
    return out


def _in_handlers(src, pattern, skip_body=None):
    """Lines where pattern occurs inside a handler body, each offset once."""
    seen, out = set(), []
    for name, _, b0, b1 in handlers(src):
        body = src.code[b0:b1]
        if skip_body is not None and skip_body.search(body):
            continue
        for m in pattern.finditer(src.code, b0, b1):
            if m.start() in seen:
                continue
            seen.add(m.start())
            out.append((src.line_of(m.start()), "%s  in %s" % (m.group(0).strip("( \t"), name)))
    return out


OBJ_DEL_RE = re.compile(r'\blv_obj_del\s*\(')
DELAY_RE = re.compile(r'\b(?:delay|vTaskDelay)\s*\(')
RESTART_RE = re.compile(r'\bESP\s*\.\s*restart\s*\(|\besp_restart\s*\(')


def scan_obj_del_in_handler(src):
    """lv_obj_del() while a dispatch is on the stack. lv_obj_del_async() and a
    pending flag are the safe forms and do not match."""
    return _in_handlers(src, OBJ_DEL_RE)


def scan_delay_in_handler(src):
    """A blocking wait under the finger. A handler that restarts the chip is
    exempt: nothing is left to freeze."""
    return _in_handlers(src, DELAY_RE, skip_body=RESTART_RE)


# --------------------------------------------------------------------------
# HTTP reachable from a handler
# --------------------------------------------------------------------------

HTTP_RE = re.compile(
    r'\bHTTPClient\b|\bWiFiClient(?:Secure)?\b|\besp_http_client_\w+'
    r'|\.\s*(?:GET|POST|PUT|PATCH|sendRequest)\s*\(')
_CONTAINER_RE = re.compile(
    r'\b(?:namespace|class|struct|union|enum)\b[^()=;]*$|\bextern\s*"[^"]*"\s*$')
_FUNC_TAIL_RE = re.compile(r'\)\s*(?:(?:const|noexcept|override|final)\s*)*$')
_NAME_RE = re.compile(r'([A-Za-z_~]\w*)\s*$')
_NOT_A_FUNCTION = {"if", "for", "while", "switch", "catch", "return", "sizeof"}


def _open_before(s, close_idx):
    depth = 0
    for i in range(close_idx, -1, -1):
        if s[i] == ")":
            depth += 1
        elif s[i] == "(":
            depth -= 1
            if depth == 0:
                return i
    return -1


def find_functions(code):
    """[(name, body_start, body_end)] for definitions at file, namespace or
    class level. Anything opened inside a function body is not looked at."""
    out, stack = [], []
    for m in _BRACES.finditer(code):
        i = m.start()
        if code[i] == "}":
            if stack:
                kind, name, start = stack.pop()
                if kind == "func":
                    out.append((name, start, i))
            continue
        kind, name = "other", None
        if all(k == "container" for k, _, _ in stack):
            begin = max(code.rfind(";", 0, i), code.rfind("{", 0, i), code.rfind("}", 0, i)) + 1
            head = code[begin:i]
            if _CONTAINER_RE.search(head):
                kind = "container"
            else:
                tail = _FUNC_TAIL_RE.search(head)
                if tail:
                    open_idx = _open_before(head, tail.start())
                    nm = _NAME_RE.search(head[:open_idx]) if open_idx > 0 else None
                    if nm and nm.group(1) not in _NOT_A_FUNCTION:
                        kind, name = "func", nm.group(1)
        stack.append((kind, name, i))
    return out


def _without_handler_bodies(src):
    """The code view with every handler body blanked, so that a screen builder
    does not inherit what the lambdas it registers do."""
    code, pieces, pos = src.code, [], 0
    for _, _, b0, b1 in sorted(handlers(src), key=lambda h: h[2]):
        if b0 < pos:
            continue
        pieces.append(code[pos:b0 + 1])
        pieces.append(_blank(code[b0 + 1:b1]))
        pos = b1
    pieces.append(code[pos:])
    return "".join(pieces)


def _call_re(names):
    return re.compile(r'\b(' + "|".join(sorted(re.escape(n) for n in names)) + r')\s*\(')


def scan_http_in_handler(sources):
    """A handler that talks HTTP itself, or calls a function that does, up to
    two calls deep. Deeper than that the graph reaches a third of the tree and
    says nothing. Returns {rel: [(line, detail)]}."""
    level1, bodies = set(), []
    for rel, src in sources.items():
        code = _without_handler_bodies(src)
        for name, b0, b1 in find_functions(code):
            body = code[b0:b1]
            bodies.append((name, body))
            if HTTP_RE.search(body) and name not in HTTP_SAFE:
                level1.add(name)
    level2 = set()
    if level1:
        calls1 = _call_re(level1)
        for name, body in bodies:
            if name not in level1 and name not in HTTP_SAFE and calls1.search(body):
                level2.add(name)
    calls = _call_re(level1 | level2) if level1 else None
    out = {}
    for rel, src in sources.items():
        seen = set()
        for name, h0, b0, b1 in handlers(src):
            if h0 in seen:
                continue
            body = src.code[b0:b1]
            hit = HTTP_RE.search(body)
            detail = None
            if hit:
                detail = "%s  directly in %s" % (hit.group(0).strip(), name)
            elif calls is not None:
                via = calls.search(body)
                if via:
                    depth = "one call" if via.group(1) in level1 else "two calls"
                    detail = "%s()  called from %s, HTTP %s down" % (via.group(1), name, depth)
            if detail:
                seen.add(h0)
                out.setdefault(rel, []).append((src.line_of(h0), detail))
    return out


# --------------------------------------------------------------------------
# Colours, captions, copies
# --------------------------------------------------------------------------

COLOR_RE = re.compile(r'\blv_color_hex\s*\(\s*0[xX][0-9A-Fa-f]+\s*\)')


def scan_inline_color_hex(src):
    """A colour written as a number instead of a name from ui/theme.h."""
    return [(src.line_of(m.start()), m.group(0)) for m in COLOR_RE.finditer(src.code)]


LABEL_RE = re.compile(r'\blv_label_set_text(?:_fmt|_static)?\s*\(')
PRINTF_RE = re.compile(r'%%|%[-+ 0#]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t)?[a-zA-Z]')
ESCAPE_RE = re.compile(r'\\(?:x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|.)')
LETTER_RE = re.compile(u'[A-Za-z\u00c0-\u024f]')
# Names that are the same in every language and must not be translated.
CAPTION_ALLOW = {
    "SpoolmanScale", "Ko-fi", "GitHub", "Discord", "MakerWorld",
    "Deutsch", "English", u"Fran\u00e7ais",
    "DD.MM.YYYY", "YYYY-MM-DD",
}
UNIT_RE = re.compile(u'^[-+\\d.,:/ ]*(?:g|kg|%|\u00b0C|h|min|s|ms|mm|V|dBm)?$')


def _is_caption(literal):
    body = literal[literal.index('"') + 1:-1]
    body = ESCAPE_RE.sub(" ", PRINTF_RE.sub(" ", body)).strip()
    if len(LETTER_RE.findall(body)) < 2:
        return False
    return body not in CAPTION_ALLOW and not UNIT_RE.match(body)


def label_calls(src):
    """[(offset, [literals in the text arguments])]"""
    out = []
    for m in LABEL_RE.finditer(src.code):
        open_idx = m.end() - 1
        close_idx = match_close(src.code, open_idx, _PARENS, "(")
        if close_idx < 0:
            continue
        comma = first_top_level_comma(src.code, open_idx + 1, close_idx)
        if comma < 0:
            continue
        out.append((m.start(), src.literals_between(comma, close_idx)))
    return out


def scan_label_literal_captions(src):
    """A caption written into the call instead of going through T(). One that
    reads the same in every language is no exception: it stays English on a
    French screen. Counted per call. A text formatted into a buffer first is
    out of reach."""
    out = []
    for offset, literals in label_calls(src):
        words = [lit for lit in literals if _is_caption(lit)]
        if words:
            out.append((src.line_of(offset), " ".join(words)))
    return out


STRNCPY_RE = re.compile(r'\bstrncpy\s*\(')
T_CALL_RE = re.compile(r'\bT\s*\(')
TERMINATOR_RE = re.compile(r"\[[^;]*\]\s*=\s*(?:0|0x0+|'\\0')\s*$")


def scan_strncpy_with_T(src):
    """([(line, detail)] every strncpy fed from T(), [...] those not
    terminated by the next statement). strncpy does not terminate on its own;
    copyT() and snprintf() do."""
    every, open_ones = [], []
    for m in STRNCPY_RE.finditer(src.code):
        open_idx = m.end() - 1
        close_idx = match_close(src.code, open_idx, _PARENS, "(")
        if close_idx < 0 or not T_CALL_RE.search(src.code, open_idx, close_idx):
            continue
        comma = first_top_level_comma(src.code, open_idx + 1, close_idx)
        dest = src.code[open_idx + 1:comma].strip() if comma > 0 else ""
        line = src.line_of(m.start())
        every.append((line, "strncpy(%s, ... T( ...)" % dest))
        semi = src.code.find(";", close_idx)
        nxt_end = src.code.find(";", semi + 1) if semi >= 0 else -1
        nxt = src.code_str[semi + 1:nxt_end].strip() if nxt_end > 0 else ""
        if not (dest and nxt.startswith(dest) and TERMINATOR_RE.search(nxt)):
            open_ones.append((line, "strncpy(%s, ...) and no terminator follows" % dest))
    return every, open_ones


NESTED_RE = re.compile(r'\bcreateNested(?:Object|Array)\s*\(')


def scan_create_nested_object(src):
    """The ArduinoJson 6 form. Version 7 keeps add<JsonObject>()."""
    return [(src.line_of(m.start()), m.group(0) + ")") for m in NESTED_RE.finditer(src.code)]


# --------------------------------------------------------------------------
# Web routes
# --------------------------------------------------------------------------

ROUTE_RE = re.compile(r'\b\w+\s*(?:\.|->)\s*on(?:NotFound)?\s*\(')
LAMBDA_RE = re.compile(r'\[[^\]]*\]\s*\([^)]*\)\s*(?:mutable\s*)?(?:->\s*\w+\s*)?\{')
GATE_RE = re.compile(r'\bweb(?:Require|Allowed)\s*\(')


def routes(src):
    """[(offset, path, [lambda bodies])]"""
    out = []
    for m in ROUTE_RE.finditer(src.code):
        open_idx = m.end() - 1
        close_idx = match_close(src.code, open_idx, _PARENS, "(")
        if close_idx < 0:
            continue
        bodies, pos = [], open_idx
        while True:
            lam = LAMBDA_RE.search(src.code, pos, close_idx)
            if not lam:
                break
            b0 = lam.end() - 1
            b1 = match_close(src.code, b0, _BRACES, "{")
            if b1 < 0:
                break
            bodies.append(src.code[b0:b1])
            pos = b1
        names = src.literals_between(open_idx, close_idx)
        out.append((m.start(), names[0] if names else "(no literal path)", bodies))
    return out


def scan_web_route_without_gate(src):
    """Every route checks its gate itself. The gate has to be in the body, not
    first in it: a page answers 404 before its gate, an upload gates per
    chunk. A handler passed by name cannot be seen into and counts."""
    out = []
    for offset, path, bodies in routes(src):
        if not bodies:
            out.append((src.line_of(offset), "%s  handler passed by name" % path))
        elif not all(GATE_RE.search(b) for b in bodies):
            out.append((src.line_of(offset), "%s  no webRequire() or webAllowed()" % path))
    return out


# --------------------------------------------------------------------------
# Comment language
# --------------------------------------------------------------------------

UMLAUT_RE = re.compile(u'[\u00e4\u00f6\u00fc\u00c4\u00d6\u00dc\u00df]')
WORD_RE = re.compile(u'[A-Za-z\u00c0-\u024f]+')
QUOTED_RE = re.compile(r'"[^"]*"|(?<![A-Za-z])\'[^\']*\'(?![A-Za-z])')
# Umlauts spelled in ASCII. Each stem is checked against English: "oeffn"
# rather than "oeff", which sits inside "coefficient".
GERMAN_STEMS = (
    "fuer", "ueber", "naechst", "loesch", "zurueck", "pruef", "aender",
    "waehl", "geraet", "schliess", "groess", "koenn", "muess", "oeffn",
    "haeng", "laeuft", "zaehl", "moeglich", "noetig", "spaeter", "waehrend",
    "enthaelt", "erhaelt", "gueltig", "stueck", "rueck", "hoehe", "laenge",
    "staerk", "aehnlich", "naemlich", "traeg", "faellt", "haelt",
)
# Function words. Left out because English has them too: die, den, hat, war,
# was, links, rot, tag, falls, also, an, in, so, man.
GERMAN_WORDS = frozenset("""
    nicht wird werden wurde und oder wenn dann damit weil auch noch schon nur
    nach bei mit ohne aus auf von vom zum zur das dem der ein eine einen einem
    einer kein keine ist sind sein hier jetzt immer wieder sonst beim durch
    gegen bis als wie sich kann muss soll darf dass nichts mehr neue neuer
    neues erst sobald bevor danach davor dabei dazu deshalb trotzdem aber doch
    statt zwischen unter gibt haben wir uns diese dieser dieses jede jeder
    alle alles viel ganz gleich direkt bereits sowie bzw ggf
""".split())
# Nouns of this firmware. Weaker evidence than a function word: a comment may
# name a German caption and still be English.
GERMAN_NOUNS = frozenset("""
    spule spulen gewicht waage tasten anzeige fussnote wert werte zeile zeilen
    hinweis fehler abbruch farbe farben hersteller trocknung ampel eintrag
    auswahl einstellung einstellungen bildschirm schrift rahmen knopf abstand
    breite verbindung netzwerk sprache uhrzeit helligkeit hintergrund zeit
    pfeil balken kachel karte liste seite speichern abbrechen weiter fertig
    lagerort fach schacht feld felder zustand aufruf ergebnis versuch
    wartezeit sekunden minuten stunden tage
""".split())
ENGLISH_WORDS = frozenset("""
    the a an is are was be to of and or in on for with that this it not no as
    at by from if when then so we its only which would has have can must never
    always before after into because while still here there one all each
    every same than but also until once does do
""".split())


def is_german_comment(text):
    text = QUOTED_RE.sub(" ", text)
    lowered = text.lower()
    strong = len(UMLAUT_RE.findall(text))
    strong += sum(1 for stem in GERMAN_STEMS if stem in lowered)
    weak = english = 0
    for word in WORD_RE.findall(text):
        low = word.lower()
        if low in ENGLISH_WORDS:
            english += 1
        elif word.isupper() and len(word) > 1:
            continue        # DER, MIT: an acronym, not an article
        elif low in GERMAN_WORDS:
            strong += 1
        elif low in GERMAN_NOUNS:
            weak += 1
    if strong:
        return english < 3 and english <= strong
    return weak > 0 and english == 0


def scan_german_comment_lines(src):
    """Comments are English. A heuristic: it is tuned to stay quiet on English
    and will miss German that uses none of its words."""
    return [(line, text.strip()) for line, text in src.comments if is_german_comment(text)]


# --------------------------------------------------------------------------
# Collecting
# --------------------------------------------------------------------------

def _git(*args):
    try:
        done = subprocess.run(["git"] + list(args), cwd=str(REPO_ROOT), check=False,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return None
    return done.stdout.decode("utf-8", "replace") if done.returncode == 0 else None


def source_files():
    """Tracked files plus new ones not yet added, so a file counts from the
    moment it exists. Never a directory walk: ignored copies stay out."""
    listed = _git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "src")
    if listed is None:
        return []
    out = []
    for rel in sorted(set(p for p in listed.split("\0") if p)):
        if not rel.endswith(SOURCE_SUFFIXES) or rel.startswith(SKIP_PREFIXES):
            continue
        if (REPO_ROOT / rel).is_file():
            out.append(rel)
    return out


def _read(rel):
    with open(str(REPO_ROOT / rel), encoding="utf-8", errors="replace") as handle:
        return handle.read()


def collect():
    """(metrics, findings, stats). findings maps a metric to printable lines."""
    texts = dict((rel, _read(rel)) for rel in source_files())
    sources = dict((rel, Source(text)) for rel, text in texts.items())
    names = ("inline_color_hex", "label_literal_captions", "german_comment_lines",
             "obj_del_in_handler", "strncpy_with_T", "http_in_handler") + MUST_BE_ZERO
    found = dict((name, []) for name in names)
    stats = {"files": len(sources), "handlers": 0, "routes": 0, "label calls": 0,
             "comment lines": 0}

    def add(name, rel, items):
        found[name].extend("%s:%d  %s" % (rel, line, detail) for line, detail in items)

    for rel in sorted(sources):
        src = sources[rel]
        stats["handlers"] += len(handlers(src))
        stats["comment lines"] += len(src.comments)
        if not src.balanced():
            found["scanner_unbalanced_files"].append("%s  brackets do not balance once literals are gone" % rel)
        if rel.startswith(UI_SCOPE):
            stats["label calls"] += len(label_calls(src))
            add("inline_color_hex", rel, scan_inline_color_hex(src))
            add("label_literal_captions", rel, scan_label_literal_captions(src))
        if rel not in GERMAN_EXEMPT:
            add("german_comment_lines", rel, scan_german_comment_lines(src))
        add("obj_del_in_handler", rel, scan_obj_del_in_handler(src))
        add("delay_in_handler", rel, scan_delay_in_handler(src))
        every, open_ones = scan_strncpy_with_T(src)
        add("strncpy_with_T", rel, every)
        add("strncpy_with_T_unterminated", rel, open_ones)
        add("create_nested_object", rel, scan_create_nested_object(src))
        if rel.startswith("src/web/") and rel.endswith(".cpp"):
            stats["routes"] += len(routes(src))
            if rel not in GATE_EXEMPT:
                add("web_route_without_gate", rel, scan_web_route_without_gate(src))
    for rel, items in sorted(scan_http_in_handler(sources).items()):
        add("http_in_handler", rel, items)

    metrics = dict((name, len(lines)) for name, lines in found.items())
    for rel, text in texts.items():
        if rel not in FILE_SIZE_EXEMPT and text.count("\n") > MAX_FILE_LINES:
            metrics[LINES_PREFIX + rel] = text.count("\n")
    return metrics, found, stats


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------

def load_baseline(path):
    if not path.exists():
        return None
    with open(str(path), encoding="utf-8") as handle:
        return json.load(handle).get("metrics", {})


def write_baseline(path, metrics):
    commit = (_git("rev-parse", "--short", "HEAD") or "").strip()
    payload = {"created": date.today().isoformat(), "commit": commit,
               "metrics": dict(sorted(metrics.items()))}
    with open(str(path), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=True)
        handle.write("\n")


def compare(baseline, metrics):
    """(rows, problems, warnings). A problem blocks, a warning is reported."""
    rows, problems, warnings = [], [], []
    for key in sorted(set(baseline) | set(metrics)):
        base, now = baseline.get(key), metrics.get(key)
        is_size = key.startswith(LINES_PREFIX)
        if key in MUST_BE_ZERO:
            if now:
                problems.append("%s: %d, must be zero" % (key, now))
            rows.append((key, 0, now or 0, "x +%d" % now if now else "="))
            continue
        if now is None:
            rows.append((key, base, "-", "ok gone"))
            continue
        if base is None:
            if is_size:
                problems.append("%s has %d lines, the limit for a file that was under it is %d"
                                % (key[len(LINES_PREFIX):], now, MAX_FILE_LINES))
            else:
                problems.append("%s has no baseline yet (--write-baseline)" % key)
            rows.append((key, "-", now, "x new"))
            continue
        delta = now - base
        if delta > 0 and is_size:
            warnings.append("%s grew %d -> %d (+%d)" % (key[len(LINES_PREFIX):], base, now, delta))
            mark = "! +%d" % delta
        elif delta > 0:
            problems.append("%s: %d -> %d (+%d)" % (key, base, now, delta))
            mark = "x +%d" % delta
        elif delta < 0:
            mark = "ok %d" % delta
        else:
            mark = "="
        rows.append((key, base, now, mark))
    return rows, problems, warnings


def baseline_refusal(old, metrics, force):
    """Why a baseline must not be written now, or None."""
    stuck = dict((k, metrics[k]) for k in MUST_BE_ZERO if metrics.get(k))
    if stuck:
        return "fix these first, they are never part of a baseline: %s" % stuck
    if old is None or force:
        return None
    _, problems, warnings = compare(old, metrics)
    if problems or warnings:
        return ("numbers rose, and a baseline only ever follows them down:\n  "
                + "\n  ".join(problems + warnings)
                + "\n--force is for a changed scanner, and the commit says so")
    return None


def print_report(rows, found, verbose):
    width = max([len(row[0]) for row in rows] + [6])
    print("%-*s  %6s  %6s  delta" % (width, "metric", "base", "now"))
    for key, base, now, mark in rows:
        print("%-*s  %6s  %6s  %s" % (width, key, base, now, mark))
    if verbose:
        for key in sorted(found):
            if found[key]:
                print("\n--- %s (%d) ---" % (key, len(found[key])))
                for line in found[key]:
                    print("  " + line)


def summary(stats):
    return ", ".join("%d %s" % (stats[k], k) for k in
                     ("handlers", "routes", "label calls", "files"))


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def selftest():
    failed = []

    def check(label, got, want):
        if got != want:
            failed.append("%s: got %r, want %r" % (label, got, want))

    def count(scan, text):
        return len(scan(Source(text)))

    # tokenizer
    src = Source('a = "x // y"; /* { */ b = \'{\'; c = \'"\'; d = "q\\"{"; // tail }\n')
    check("tokenizer balance", src.balanced(), True)
    check("tokenizer comments", [t.strip() for _, t in src.comments], ["{", "tail }"])
    check("tokenizer strings", len(src.strings), 2)
    check("tokenizer length", len(src.code), len(src.text))
    check("raw string", Source('x = R"js(if (a) { )js"; y();').balanced(), True)
    check("line numbers", Source("\n\n// here\n").comments[0][0], 3)

    # handlers
    lam = "lv_obj_add_event_cb(b, [](lv_event_t *e){ %s }, LV_EVENT_CLICKED, NULL);"
    check("handler found", len(handlers(Source(lam % "x();"))), 1)
    check("prototype skipped", len(handlers(Source("static void cb(lv_event_t *e);"))), 0)
    check("named handler", handlers(Source("static void on_ok(lv_event_t* e) { a(); }"))[0][0], "on_ok")
    check("del in handler", count(scan_obj_del_in_handler, lam % "lv_obj_del(scr);"), 1)
    check("del_async is safe", count(scan_obj_del_in_handler, lam % "lv_obj_del_async(scr);"), 0)
    check("del in a comment", count(scan_obj_del_in_handler, lam % "/* lv_obj_del(scr); */"), 0)
    check("del in a string", count(scan_obj_del_in_handler, lam % 'log("lv_obj_del(scr)");'), 0)
    check("del outside", count(scan_obj_del_in_handler, "void f() { lv_obj_del(scr); }"), 0)
    check("delay in handler", count(scan_delay_in_handler, lam % "delay(10);"), 1)
    check("delay before restart", count(scan_delay_in_handler, lam % "delay(10); ESP.restart();"), 0)

    # http
    fetch = "static bool fetchTag() { HTTPClient http; return http.GET() == 200; }\n"
    outer = "void doCheck() { fetchTag(); }\nvoid deep() { doCheck(); }\nvoid deeper() { deep(); }\n"

    def http(body):
        return sum(len(v) for v in scan_http_in_handler({"f.cpp": Source(fetch + outer + lam % body)}).values())

    check("http direct", http("HTTPClient h;"), 1)
    check("http one call down", http("fetchTag();"), 1)
    check("http two calls down", http("doCheck();"), 1)
    check("http three calls down", http("deeper();"), 0)
    check("http flag only", http("check_pending = true;"), 0)
    builder = "void build() { fetchTag(); " + lam % "x = 1;" + " }\n"
    check("builder does not taint its lambda",
          sum(len(v) for v in scan_http_in_handler({"f.cpp": Source(fetch + builder)}).values()), 0)
    check("functions found", [f[0] for f in find_functions("namespace n { struct S { int m() const { return 1; } }; }")], ["m"])

    # colours
    check("colour literal", count(scan_inline_color_hex, "c = lv_color_hex(0x1a3060);"), 1)
    check("colour constant", count(scan_inline_color_hex, "c = lv_color_hex(UI_COL_INK);"), 0)
    check("two on a line", count(scan_inline_color_hex, "c = on ? lv_color_hex(0x1) : lv_color_hex(0x2);"), 2)

    # captions
    lab = "lv_label_set_text(l, %s);"
    check("caption", count(scan_label_literal_captions, lab % '"Filament"'), 1)
    check("through T", count(scan_label_literal_captions, lab % "T(STR_X)"), 0)
    check("brand name", count(scan_label_literal_captions, lab % '"GitHub"'), 0)
    check("unit", count(scan_label_literal_captions, lab % '"0 g"'), 0)
    check("placeholder", count(scan_label_literal_captions, lab % '"---"'), 0)
    check("format only", count(scan_label_literal_captions, 'lv_label_set_text_fmt(l, "%d g", n);'), 0)
    check("ternary caption", count(scan_label_literal_captions, lab % 'ok ? "NFC" : "NFC!"'), 1)
    check("symbol then caption", count(scan_label_literal_captions, lab % 'LV_SYMBOL_OK " Done"'), 1)
    check("paren in a literal", count(scan_label_literal_captions, lab % '"Tare (zero)"'), 1)

    # strncpy
    every, open_ones = scan_strncpy_with_T(Source("strncpy(buf, T(STR_X), sizeof(buf) - 1);\nfoo();"))
    check("strncpy plain", (len(every), len(open_ones)), (1, 1))
    every, open_ones = scan_strncpy_with_T(Source(
        "strncpy(buf, on ? T(STR_A) : T(STR_B), sizeof(buf) - 1);\nbuf[sizeof(buf) - 1] = '\\0';"))
    check("strncpy ternary, terminated", (len(every), len(open_ones)), (1, 0))
    check("TAG is not T", len(scan_strncpy_with_T(Source("strncpy(buf, TAG(x), 4);"))[0]), 0)
    check("nested object", count(scan_create_nested_object, "f.createNestedObject();"), 1)
    check("nested object in a comment", count(scan_create_nested_object, "// createNestedObject()"), 0)

    # comments
    check("german", is_german_comment(" Spule abgenommen -> Reset fuer naechste Spule"), True)
    check("german noun only", is_german_comment(" Wert-Anzeige"), True)
    check("english", is_german_comment(" The spool was taken off, reset for the next one"), False)
    check("english naming a caption", is_german_comment(" the Ampel level for last_dried"), False)
    check("quoted city", is_german_comment(u' cuts "K\u00f6ln" on a character boundary, not in a byte'), False)
    check("acronym", is_german_comment(" DER encoded certificate"), False)

    # routes
    route = 'srv.on("/api/x", HTTP_POST, [&srv]() { %s });'
    check("gated route", count(scan_web_route_without_gate, route % 'if (!webRequire(srv, GATE_OPEN, "x")) return;'), 0)
    check("open route", count(scan_web_route_without_gate, route % "srv.send(200);"), 1)
    check("named handler", count(scan_web_route_without_gate, 'srv.on("/x", HTTP_GET, handleX);'), 1)
    upload = ('srv.on("/update", HTTP_POST, [&srv]() { if (!webRequire(srv, GATE_MAINT, "f")) return; },'
              " [&srv]() { %s });")
    check("upload, both gated", count(scan_web_route_without_gate, upload % "if (!webAllowed(GATE_MAINT)) return;"), 0)
    check("upload, chunk open", count(scan_web_route_without_gate, upload % "write();"), 1)

    # baseline
    base = {"inline_color_hex": 10, LINES_PREFIX + "src/a.cpp": 1200}
    _, problems, warnings = compare(base, {"inline_color_hex": 11, LINES_PREFIX + "src/a.cpp": 1200})
    check("risen metric", (len(problems), len(warnings)), (1, 0))
    _, problems, warnings = compare(base, {"inline_color_hex": 9, LINES_PREFIX + "src/a.cpp": 1200})
    check("fallen metric", (len(problems), len(warnings)), (0, 0))
    _, problems, warnings = compare(base, {"inline_color_hex": 10, LINES_PREFIX + "src/a.cpp": 1210})
    check("grown large file", (len(problems), len(warnings)), (0, 1))
    grown = {"inline_color_hex": 10, LINES_PREFIX + "src/a.cpp": 1200, LINES_PREFIX + "src/b.cpp": 1001}
    check("new large file", len(compare(base, grown)[1]), 1)
    check("must be zero", len(compare(base, dict(base, delay_in_handler=1))[1]), 1)
    check("refuses an open must-be-zero", baseline_refusal(None, {"delay_in_handler": 1}, True) is None, False)
    check("refuses a risen number", baseline_refusal(base, dict(base, inline_color_hex=11), False) is None, False)
    check("force lets a risen number through", baseline_refusal(base, dict(base, inline_color_hex=11), True), None)
    check("first baseline", baseline_refusal(None, base, False), None)

    for line in failed:
        print("selftest FAIL  " + line)
    print("selftest: %d failed" % len(failed) if failed else "selftest: ok")
    return 1 if failed else 0


# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Convention ratchet: countable house rules against a baseline")
    parser.add_argument("--verbose", action="store_true", help="list every finding")
    parser.add_argument("--write-baseline", action="store_true",
                        help="rewrite the baseline, only after numbers went down")
    parser.add_argument("--force", action="store_true",
                        help="with --write-baseline: accept risen numbers, for a changed scanner")
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH, help="another baseline file")
    parser.add_argument("--selftest", action="store_true", help="run the scanners against fixtures")
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    metrics, found, stats = collect()
    empty = [name for name in ("files", "handlers", "routes", "label calls", "comment lines")
             if not stats[name]]
    if empty:
        print("ratchet: scanner out of step - found no %s at all" % ", no ".join(empty))
        return 2

    baseline = load_baseline(args.baseline)
    if args.write_baseline:
        refusal = baseline_refusal(baseline, metrics, args.force)
        if refusal:
            print("ratchet: no baseline written - " + refusal)
            return 1
        kept = dict((k, v) for k, v in metrics.items() if k not in MUST_BE_ZERO)
        write_baseline(args.baseline, kept)
        print_report([(k, v, v, "=") for k, v in sorted(kept.items())], found, args.verbose)
        print("\nratchet: baseline written - " + summary(stats))
        return 0

    if baseline is None:
        print_report([(k, "-", v, "") for k, v in sorted(metrics.items())], found, args.verbose)
        print("\nratchet: no baseline at %s - run --write-baseline once" % args.baseline.name)
        return 2

    rows, problems, warnings = compare(baseline, metrics)
    print_report(rows, found, args.verbose)
    print()
    for line in warnings:
        print("warn: " + line)
    for line in problems:
        print("fail: " + line)
    if problems:
        print("ratchet: RED, %d number(s) rose - not finished" % len(problems))
        return 1
    print("ratchet: OK - " + summary(stats))
    return 0


if __name__ == "__main__":
    sys.exit(main())
