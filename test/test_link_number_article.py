"""The link by a typed spool number appends the spool as a row and asks the
list's question for it (showLinkConfirmPopup()), which compares the row with
the tag by material, colour and the article number Bambu's catalog names. The
appended row was marked "no article hit" whatever the spool carried, so for a
Bambu tag the question called the right spool "does not match", while the
warning a few lines earlier, which reads the same spool through
tagSpoolCompareTag(), found it fine. The row is judged by the tag's article
number as the list judges its rows.

Reads the source without a compiler: comments are blanked and function bodies
found by brace matching, with the tools of the convention ratchet."""
import re
import sys
from pathlib import Path

root = Path(__file__).parents[1]
sys.path.insert(0, str(root / "scripts"))
import check_conventions as cc  # noqa: E402

FLOW = root / "src/ui/spool_flow.cpp"

source = cc.Source(FLOW.read_text(encoding="utf-8"))
spans = [(a, b) for name, a, b in cc.find_functions(source.code) if name == "linkIdLookupAndPatch"]
assert len(spans) == 1, "src/ui/spool_flow.cpp: linkIdLookupAndPatch() is not defined exactly once"
# Comments blanked, string literals kept (code_str is aligned with code).
body = re.sub(r"\s+", "", source.code_str[spans[0][0] + 1:spans[0][1]])

assert "showLinkConfirmPopup(i)" in body, "linkIdLookupAndPatch() no longer asks the list's question"
assert "s.article_hit=false;" not in body, \
    "the row of a typed number never has the article hit, so the question warns for the right spool"
assert "tagSpoolTagArticle(" in body and "s.article_hit=" in body, \
    "the row of a typed number is not judged by the tag's article number"

print("link by number judges the article number: ok")
