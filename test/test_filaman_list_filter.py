"""The spool list reaches mapSpool() through a JSON filter, so a field it reads
and the filter does not name would go missing without an error: on the list
only, while the single spool still has it. Every field the mapping reads must be
named in spoolListFilter() (services/filaman_api.cpp)."""
import re
from pathlib import Path

source = (Path(__file__).parents[1] / "src/services/filaman_api.cpp").read_text(encoding="utf-8")


def between(start, end):
    a = source.index(start)
    return source[a:source.index(end, a)]


def code_only(text):
    return "\n".join(line.split("//")[0] for line in text.splitlines())


mapping = code_only(between("static const char* articleNumber(", "static void addApiKey("))
list_filter = code_only(between("static void spoolListFilter(", "int filamanGetSpoolListJson("))

TOKEN = r'"[^"]+"|FM_\w+'
named = set(re.findall(TOKEN, list_filter))
read = set()
for chain in re.finditer(rf'\b(?:src|fil|cf)((?:\[(?:{TOKEN})\])+)', mapping):
    read.update(re.findall(TOKEN, chain.group(1)))

assert len(read) > 25, f"the mapping was not found, only {sorted(read)}"
missing = sorted(read - named)
assert not missing, f"mapSpool() reads {missing}, spoolListFilter() does not name them"
print(f"ok: {len(read)} fields read, all in the filter")
