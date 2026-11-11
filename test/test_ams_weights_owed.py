"""A weights start refused because the task of the printer before was still
busy is made up: the grams of the printer just shown must not be lost when the
user switches printers quickly. The start is anchored on the fetch that runs
after any switch or reload, never on the callback that chooses the printer, so
the test holds when the way a printer is chosen changes.

Reads the source without a compiler: comments are blanked and function bodies
found by brace matching, with the tools of the convention ratchet."""
import re
import sys
from pathlib import Path

root = Path(__file__).parents[1]
sys.path.insert(0, str(root / "scripts"))
import check_conventions as cc  # noqa: E402


def collapse(text):
    """Every run of blanks as one space."""
    return re.sub(r"\s+", " ", text).strip()


VIEW = "ui/ams_view.cpp"
OWED_LOG = "AMSWEIGHTS: start for printer %d made up after a busy task"

source = cc.Source((root / "src" / VIEW).read_text(encoding="utf-8"))
code = source.code
bodies = {}
for name, a, b in cc.find_functions(code):
    bodies[name] = collapse(code[a + 1:b])
strings = collapse(source.code_str)

problems = []


def calls_name(body, name):
    return re.search(rf"\b{re.escape(name)}\s*\(", body) is not None


def reaches(text, needle, seen=None):
    """The text holds needle, or calls a function of this file whose body does."""
    seen = set() if seen is None else seen
    if needle in text:
        return True
    for fn, body in bodies.items():
        if fn not in seen and calls_name(text, fn):
            seen.add(fn)
            if reaches(body, needle, seen):
                return True
    return False


def need(ok, text):
    if not ok:
        problems.append(f"src/{VIEW}: {text}")


# The functions of the file that start the weights (there must be one).
starters = [fn for fn, body in bodies.items() if "amsWeightsStart(" in body]
need(starters, "no function calls amsWeightsStart()")

# 1. A finished result is collected before the next start: the printer switch
#    ran fetchAndDraw() and returned before the loop collected the DONE result
#    of the printer before, so amsWeightsStart() was refused and never asked
#    again.
for fn in starters:
    body = bodies[fn]
    before = body[:body.index("amsWeightsStart(")]
    need(reaches(before, "amsWeightsTake(") and reaches(before, "AWS_DONE"),
         f"{fn}() calls amsWeightsStart() without taking a finished (AWS_DONE) result first")
fetch = bodies.get("fetchAndDraw", "")
need(reaches(fetch, "amsWeightsStart("), "fetchAndDraw() never reaches amsWeightsStart()")

# 2. The flag that says a start is owed.
flags = re.findall(r"\bstatic\s+bool\s+(s_\w*owed\w*)\s*=\s*false\s*;", code)
need(len(flags) == 1, f"expected exactly one 'static bool s_..owed.. = false;', found {flags}")
flag = flags[0] if flags else "s_weights_owed"
assign = re.compile(rf"\b{flag}\s*=\s*([^;]+);")

# 2a. Set from the busy state only: asked before the call, so the other refusals
#     (heap floor, nothing to weigh, backend, drying batch) are not retried.
for fn in starters:
    body = bodies[fn]
    first = body.index("amsWeightsStart(")
    before = body[:first]
    need(calls_name(before, "amsWeightsBusy") or "AWS_IDLE" in before,
         f"{fn}() does not ask whether the task is busy before amsWeightsStart()")
    busy_vars = re.findall(r"\bbool\s+(\w+)\s*=\s*(?:amsWeightsBusy\s*\(\s*\)|amsWeightsState\s*\(\s*\)\s*!=\s*AWS_IDLE)", before)
    values = [v.strip() for v in assign.findall(body)]
    need(any(v in busy_vars or v.startswith("amsWeightsBusy(") for v in values),
         f"{fn}() never sets {flag} from the busy state asked before the call")
    for v in values:
        need(v == "false" or v in busy_vars or v.startswith("amsWeightsBusy("),
             f"{fn}() sets {flag} = {v}, not from the busy state (only a busy task is owed)")

# 2b. Read in the loop's tick, after the fetch branch and after the result was
#     collected, under idle task, page up, valid state and the shown printer.
TICK = "handleAmsViewDeferredActions"
tick = bodies.get(TICK, "")
read_at = re.search(rf"\b{flag}\b", tick)
need(read_at, f"{TICK}() never reads {flag}")
if read_at:
    if_at = tick.rfind("if (", 0, read_at.start())
    need(if_at >= 0, f"{TICK}() reads {flag} outside an 'if'")
    # The condition by parenthesis matching, then the block behind it.
    depth, i = 1, if_at + 4
    while i < len(tick) and depth:
        depth += {"(": 1, ")": -1}.get(tick[i], 0)
        i += 1
    c = tick[if_at + 4:i - 1]
    need("s_scr" in c, f"the owed start does not check the page is still up (s_scr): if ({c})")
    need("valid" in c, f"the owed start does not check the state is valid: if ({c})")
    need("s_printer_id" in c, f"the owed start does not check the shown printer (s_printer_id): if ({c})")
    need("AWS_IDLE" in c or "!amsWeightsBusy(" in c, f"the owed start does not wait for an idle task: if ({c})")
    block_start = tick.find("{", i)
    depth, j = 1, block_start + 1
    while j < len(tick) and depth:
        depth += {"{": 1, "}": -1}.get(tick[j], 0)
        j += 1
    block = tick[block_start:j]
    need(any(calls_name(block, fn) for fn in starters), "the owed block does not start the weights again")
    fetch_branch = tick.find("if (s_fetch_pending)")
    need(0 <= fetch_branch < if_at, "the owed start is not behind the fetch branch (it could run before the printer is drawn)")
    # The collection of a finished result: AWS_DONE in the tick itself, or a
    # helper that holds both AWS_DONE and amsWeightsTake().
    collectors = [fn for fn, b in bodies.items() if fn != TICK and "AWS_DONE" in b and "amsWeightsTake(" in b]
    spots = [tick.find("AWS_DONE")] + [m.start() for fn in collectors for m in re.finditer(rf"\b{fn}\s*\(", tick)]
    spots = [p for p in spots if p >= 0]
    need(spots and min(spots) < if_at, "the owed start is not behind the collection of a finished result")

# 2c. The log line.
need(re.search(r'\blogSDf\s*\(\s*"' + re.escape(OWED_LOG) + '"', strings),
     f'no logSDf("{OWED_LOG}", ...)')

# 3. Cleared where the fetch for a newly chosen printer or a reload starts ...
fetch_clear = re.search(rf"\b{flag}\s*=\s*false\s*;", fetch)
need(fetch_clear, f"fetchAndDraw() does not clear {flag}")
if fetch_clear:
    need(fetch_clear.start() < fetch.find("backendGetAmsState("),
         f"fetchAndDraw() clears {flag} only after it has asked the backend (an error before it would keep it)")
# ... and where the page is freed ...
frees = [fn for fn, body in bodies.items() if "releaseScreen(&s_scr)" in body]
need(frees, "no function frees the page with releaseScreen(&s_scr)")
for fn in frees:
    need(re.search(rf"\b{flag}\s*=\s*false\s*;", bodies[fn]), f"{fn}() frees the page without clearing {flag}")
# ... and by no callback: the owed start is cleared where the fetch runs, so it
# stays right when the way a printer is chosen changes.
for fn, body in bodies.items():
    if fn.endswith("Cb") and re.search(rf"\b{flag}\b", body):
        problems.append(f"src/{VIEW}: the callback {fn}() touches {flag}; clear it in the fetch")

assert not problems, "\n" + "\n".join(f"  - {p}" for p in problems)
print("test_ams_weights_owed: ok")
