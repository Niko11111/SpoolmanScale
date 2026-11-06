"""A copy through the vendor and material picker keeps the spools that already
carry a tag: such a spool is the template (the roll on the shelf that is bought
again), not a conflict. The fetch filter keeps it in every copy through the
picker, active or archived, so the pass that renders the rows must not drop it
again. Before, only the archived list kept it, and the active list of a copy
lost exactly the template.

Reads the source without a compiler: comments and strings are blanked and
function bodies found by brace matching, with the tools of the convention
ratchet."""
import re
import sys
from pathlib import Path

root = Path(__file__).parents[1]
sys.path.insert(0, str(root / "scripts"))
import check_conventions as cc  # noqa: E402

FLOW = root / "src/ui/spool_flow.cpp"


def squeeze(text):
    """The text without any blank, so that a call is found however it is wrapped."""
    return re.sub(r"\s+", "", text)


def body_of(name):
    """The code between the braces of the one function called name, blanks gone."""
    code = cc.Source(FLOW.read_text(encoding="utf-8")).code
    spans = [(start, end) for found, start, end in cc.find_functions(code) if found == name]
    assert len(spans) == 1, f"src/ui/spool_flow.cpp: {name}() is not defined exactly once"
    return squeeze(code[spans[0][0] + 1:spans[0][1]])


# 1. The fetch keeps a tagged spool in every copy through the picker.
fetch = body_of("linkFilterVerdict")
assert squeeze("!copy_flow_via_list&&!link_cu_ok&&spoolHasAnyTag(spool)") in fetch, \
    "linkFilterVerdict() no longer keeps tagged spools in a copy through the picker"

# 2. The rows: a copy through the picker never skips a row, active or archived.
# Its flag is asked before the tag is, and the archived list is not asked at all.
skip = body_of("linkSpoolSkip")
assert "copy_flow_archived" not in skip, \
    "linkSpoolSkip() keeps tagged rows for the archived copy list only"
via, bound = skip.find("copy_flow_via_list"), skip.find("linkSpoolBound(")
assert 0 <= via < bound, \
    "linkSpoolSkip() does not keep every row of a copy through the picker before it looks at the tag"

print("copy list keeps tagged spools: ok")
