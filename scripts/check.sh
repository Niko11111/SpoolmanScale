#!/usr/bin/env bash
# House rules of this project, checked by machine instead of by memory.
# Runs locally (scripts/check.sh) and in CI on every push and pull request.
# Exit 1 on any finding. Warnings are printed but do not fail the run.
set -u
cd "$(dirname "$0")/.."

fail=0
warn=0
ok()   { printf 'ok    %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; fail=1; }
warnf(){ printf 'warn  %s\n' "$*"; warn=1; }

# Tracked text files. Notes/ and Handovers/ are not in git and stay out.
tracked() { git ls-files -z -- src platformio.ini partitions.csv copy_release.py README.md BUILDING.md .github scripts tools; }

# 1. No em-dash anywhere: it breaks Xtensa GCC 8.4.0 in comments with
#    misleading errors and renders as a box in LVGL strings.
hits=$(tracked | xargs -0 env LC_ALL=C grep -n $'\xe2\x80\x94' 2>/dev/null || true)
if [ -n "$hits" ]; then bad "em-dash (U+2014) found:"; echo "$hits" | sed 's/^/        /'; else ok "no em-dash in tracked files"; fi

# 2. T(id) is never copied with a bare strncpy: that form does not terminate.
hits=$(grep -rnE 'strncpy\s*\([^,]+,\s*T\(' src | grep -vE '^[^:]+:[0-9]+:\s*//' || true)
if [ -n "$hits" ]; then bad "strncpy(buf, T(...)) - use copyT() or snprintf():"; echo "$hits" | sed 's/^/        /'; else ok "no strncpy on T()"; fi

# 3. lv_scr_load() causes reboots; the overlay architecture replaces it.
hits=$(grep -rn 'lv_scr_load(' src | grep -vE '^[^:]+:[0-9]+:\s*//' || true)
if [ -n "$hits" ]; then bad "lv_scr_load() is banned:"; echo "$hits" | sed 's/^/        /'; else ok "no lv_scr_load()"; fi

# 4. setPassiveActivationRetries(0) locks the PN532 I2C bus (Error 263).
hits=$(grep -rnE 'setPassiveActivationRetries\s*\(\s*0(x0+)?\s*\)' src || true)
if [ -n "$hits" ]; then bad "setPassiveActivationRetries(0) is blacklisted:"; echo "$hits" | sed 's/^/        /'; else ok "no setPassiveActivationRetries(0)"; fi

# 5. The version lives in two places and they must agree. A public release
#    is never a bare "-beta": the CI guard and version_compare rank it at 0.
v_cfg=$(sed -nE 's/^#define[[:space:]]+FW_VERSION[[:space:]]+"([^"]+)".*/\1/p' src/app_config.h | head -1)
v_main=$(sed -nE 's|^//[[:space:]]+Version:[[:space:]]+(v[^[:space:]]+).*|\1|p' src/main.cpp | head -1)
if [ -z "$v_cfg" ]; then bad "FW_VERSION not found in src/app_config.h"; fi
if [ -z "$v_main" ]; then bad "Version line not found in the src/main.cpp header"; fi
if [ -n "$v_cfg" ] && [ -n "$v_main" ]; then
  if [ "$v_cfg" != "$v_main" ]; then bad "version mismatch: app_config.h says $v_cfg, main.cpp header says $v_main";
  elif ! echo "$v_cfg" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-beta\.[0-9]+)?$'; then bad "version '$v_cfg' is not vX.Y.Z or vX.Y.Z-beta.N";
  else ok "version $v_cfg in both places"; fi
fi

# 6. Every string has a German and an English text. The row count itself is a
#    static_assert in lang.cpp; this catches an empty cell, which compiles.
#    Whether every row has French is rule 10's coverage, which reads the
#    working file: the cell here holds the English for a row nobody has
#    translated, so it cannot tell. The table is
#    tokenized rather than matched by a regex, which skipped every row that
#    starts with an LV_SYMBOL macro or spans several literals and still said
#    "ok". The rows found are counted against the enum, so a parser that has
#    fallen out of step with the file fails instead of passing on nothing.
hits=$(python3 - <<'PY'
import re
TOK = re.compile(r'"(?:[^"\\]|\\.)*"|//[^\n]*|/\*.*?\*/|[A-Za-z_]\w*|[{},;]|\s+|.', re.S)
src = open("src/lang.cpp", encoding="utf-8").read()
body = src[src.index("{", src.index("STRINGS[]")) + 1:]
rows, ids, depth, cell, cells = [], [], 0, [], None
for t in TOK.findall(body):
    if t.startswith("//"):
        m = re.search(r"STR_\w+", t)
        if m and depth == 0 and len(ids) < len(rows): ids.append(m.group(0))
        continue
    if t.startswith("/*") or t.isspace(): continue
    if t == "{":
        depth += 1; cells, cell = [], []
        while len(ids) < len(rows): ids.append("?")
        continue
    if t == "}":
        if depth == 0: break
        depth -= 1; cells.append(cell); rows.append(cells); continue
    if depth == 0: continue
    if t == ",": cells.append(cell); cell = []
    else: cell.append(t)
while len(ids) < len(rows): ids.append("?")

def blank(c):
    return all(t.startswith('"') and not t[1:-1].strip() for t in c)

for sid, r in zip(ids, rows):
    if len(r) < 2 or blank(r[0]) or blank(r[1]):
        print(f"{sid}: a German or English cell is empty")
no_fr = sum(1 for r in rows if len(r) < 3 or blank(r[2]))

hdr = open("src/lang.h", encoding="utf-8").read()
enum = hdr[hdr.index("enum StringID"):]
enum = re.sub(r"//[^\n]*", "", enum[enum.index("{") + 1:enum.index("STR_COUNT")])
print(f"#rows={len(rows)}")
print(f"#enum={len(re.findall(r'STR_[A-Za-z0-9_]+', enum))}")
print(f"#nofr={no_fr}")
PY
)
rows=$(echo "$hits" | sed -n 's/^#rows=//p'); enum=$(echo "$hits" | sed -n 's/^#enum=//p'); nofr=$(echo "$hits" | sed -n 's/^#nofr=//p')
empties=$(echo "$hits" | grep -v '^#' || true)
if [ -z "$rows" ] || [ "$rows" -eq 0 ] || [ "$rows" != "$enum" ]; then bad "lang.cpp: parsed ${rows:-0} rows but the enum has ${enum:-?} - this check is out of step with the table";
elif [ -n "$empties" ]; then bad "lang.cpp has empty cells:"; echo "$empties" | sed 's/^/        /';
else ok "lang.cpp: $rows rows match the enum, no empty German or English cell, $nofr without French"; fi

# 7. Every fetch in a page has a catch: a closed gate answers 403 as text,
#    r.json() throws, and an uncaught rejection leaves an empty card.
for p in src/web/pages/*.cpp; do
  f=$(grep -o 'fetch(' "$p" | wc -l | tr -d ' '); c=$(grep -o '\.catch(' "$p" | wc -l | tr -d ' ')
  if [ "$c" -lt "$f" ]; then bad "$p: $f fetch( but only $c .catch("; else ok "$p: $f fetch, $c catch"; fi
done

# 8. Names are cut with utf8Cut(), never with %.Ns. Reported, not enforced:
#    the same form is fine on ASCII (hex colours, ISO dates, UIDs).
hits=$(grep -rnE '%\.[0-9]+s' src --include='*.cpp' | grep -vE 'iso|hex|uid|uuid|tag|rgba|color|prefix|raw \+|%\.6s|%\.2s|%\.4s' || true)
if [ -n "$hits" ]; then warnf "%.Ns on something that may carry UTF-8 (use utf8Cut for names):"; echo "$hits" | sed 's/^/        /'; else ok "no suspicious %.Ns"; fi

# 9. The JavaScript the pages emit parses. Two levels of escaping, and the
#    compiler checks only one.
if command -v node >/dev/null 2>&1; then
  if python3 scripts/check_web_js.py; then ok "web page scripts parse"; else bad "web page scripts: see above"; fi
else
  bad "node not found - needed to check the web page scripts"
fi

# 10. The French column: printf conversions in the same order as German,
#     browser placeholders, buffer sizes in bytes, glyphs the fonts carry, and
#     the hard width budgets. Both tools measure icons from LVGL's symbol
#     header, which only exists once the firmware has been built, so without
#     it this is skipped with a warning rather than failed. Rule 6 cannot say
#     how much is translated: an untranslated row is written with its English
#     text in the French cell, and only tools/lang_fr.jsonl knows the difference.
LVGL_SYMBOLS=.pio/libdeps/wt32-sc01-plus/lvgl/src/font/lv_symbol_def.h
# Coverage first and always: it needs no fonts. A new text comes with a French
# draft (lang_fr.py apply --draft); left out, the gap grew to 71 rows between
# two reviews without anyone noticing. Drafts ship and are counted, not failed.
if [ -f tools/lang_fr.py ]; then
  out=$(python3 tools/lang_fr.py coverage 2>&1); rc=$?
  sum=$(echo "$out" | grep -E '^[[:space:]]*[0-9]+ rows, ' | tail -1 | sed 's/^[[:space:]]*//')
  if [ "$rc" -ne 0 ]; then bad "French coverage: ${sum:-failed} - add drafts with tools/lang_fr.py apply --draft"; echo "$out" | grep -E '^[[:space:]]+E ' | head -20 | sed 's/^/      /';
  else ok "French coverage: ${sum:-checked}"; fi
fi
if [ ! -f tools/lang_fr.py ]; then
  ok "no French tooling in this tree - nothing to check"
elif [ ! -f "$LVGL_SYMBOLS" ]; then
  warnf "French checks skipped: $LVGL_SYMBOLS is missing, build the firmware once"
else
  out=$(python3 tools/lang_fr.py check 2>&1); rc=$?
  sum=$(echo "$out" | grep -E '^[[:space:]]*[0-9]+ rows, ' | tail -1 | sed 's/^[[:space:]]*//')
  if [ "$rc" -ne 0 ]; then bad "tools/lang_fr.py check: ${sum:-failed}"; echo "$out" | grep -E '^[[:space:]]+E ' | sed 's/^/      /';
  else ok "French column: ${sum:-checked}"; fi
  out=$(python3 tools/fit_check.py --gate 2>&1); rc=$?
  sum=$(echo "$out" | grep -E 'budget\(s\) measured' | tail -1 | sed 's/^[[:space:]]*//')
  if [ "$rc" -ne 0 ]; then bad "tools/fit_check.py --gate: ${sum:-failed}"; echo "$out" | tail -12 | sed 's/^/        /';
  else ok "French widths: ${sum:-checked}"; fi
fi

# 11. The countable conventions, held against a committed baseline: what an
#     LVGL handler does, colours written as numbers, captions past the string
#     table, German comments. A number may stay or fall, never rise. A file
#     already over 1000 lines may grow, which is reported and does not fail
#     the run; a file that crosses the limit does. The scanners are tested
#     first, so that a broken one cannot report a clean tree.
if ! python3 scripts/check_conventions.py --selftest >/dev/null 2>&1; then
  bad "conventions: the ratchet fails its own self-test (run it with --selftest)"
else
  out=$(python3 scripts/check_conventions.py 2>&1); rc=$?
  sum=$(echo "$out" | grep -E '^ratchet: ' | tail -1)
  if [ "$rc" -ne 0 ]; then
    bad "conventions ${sum:-ratchet: failed}"
    echo "$out" | grep -E '^(fail|warn): ' | sed 's/^/        /'
    echo "        python3 scripts/check_conventions.py --verbose lists every finding"
  else
    ok "conventions ${sum:-ratchet: checked}"
    grown=$(echo "$out" | grep -E '^warn: ' || true)
    if [ -n "$grown" ]; then warnf "files already over 1000 lines grew:"; echo "$grown" | sed 's/^warn: /        /'; fi
  fi
fi

# 12. The binary fits the app slot of every installed device. OTA never
#     rewrites the partition table, so whatever table new devices get, a
#     device flashed before it keeps its 3 MB slot and esp_ota_begin() refuses
#     anything larger. Only checkable once the firmware has been built.
FW_BIN=.pio/build/wt32-sc01-plus/firmware.bin
OTA_MAX_APP_BYTES=3145728
if [ ! -f "$FW_BIN" ]; then
  warnf "binary size skipped: $FW_BIN is missing, build the firmware once"
else
  size=$(wc -c < "$FW_BIN" | tr -d ' ')
  if [ "$size" -gt "$OTA_MAX_APP_BYTES" ]; then
    bad "firmware.bin is $size bytes, more than the $OTA_MAX_APP_BYTES byte app slot of installed devices"
  else
    ok "firmware.bin: $size of $OTA_MAX_APP_BYTES bytes ($(( size * 100 / OTA_MAX_APP_BYTES )) %)"
  fi
fi

echo
if [ "$fail" -ne 0 ]; then echo "check.sh: FAILED"; exit 1; fi
if [ "$warn" -ne 0 ]; then echo "check.sh: passed with warnings"; else echo "check.sh: all checks passed"; fi
exit 0
