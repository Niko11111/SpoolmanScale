"""The Spool by ID pad reads the spool without serverReachNote() and says "No
connection to ..." for every answer but 200 and 404, so a refused key (401,
403), an inactive account (402) or a rate limit (429) reads as a server that is
down, and the popup every other flow opens for a refusal does not come. A
refusal goes to serverReachNote() like every other flow's, and the pad's card
names it with the refusal's own title; a server that is down keeps the pad's
line and no popup, as before.

Reads the source without a compiler: comments and strings are blanked and
function bodies found by brace matching, with the tools of the convention
ratchet."""
import re
import sys
from pathlib import Path

root = Path(__file__).parents[1]
sys.path.insert(0, str(root / "scripts"))
import check_conventions as cc  # noqa: E402

PAD = root / "src/ui/spool_id_pad.cpp"


def squeeze(text):
    """The text without any blank, so that a call is found however it is wrapped."""
    return re.sub(r"\s+", "", text)


def body_of(name):
    """The code between the braces of the one function called name, blanks gone."""
    code = cc.Source(PAD.read_text(encoding="utf-8")).code
    spans = [(start, end) for found, start, end in cc.find_functions(code) if found == name]
    assert len(spans) == 1, f"src/ui/spool_id_pad.cpp: {name}() is not defined exactly once"
    return squeeze(code[spans[0][0] + 1:spans[0][1]])


fetch = body_of("fetchSpool")
assert "serverRefusalOf(code)!=REFUSAL_NONE" in fetch and "serverReachNote(code,true)" in fetch, \
    "fetchSpool() does not hand a refusal to serverReachNote()"
# Only a refusal: a server that is down keeps the pad's own line and no popup.
assert fetch.count("serverReachNote(") == 1, "fetchSpool() hands more than a refusal to serverReachNote()"

column = body_of("buildColumn")
assert "serverRefusalTitleId(" in column, "buildColumn() does not name a refusal"
assert "STR_NO_CONNECTION_TO" in column, "buildColumn() lost the line for a server that is down"

print("Spool by ID pad names a refusal: ok")
