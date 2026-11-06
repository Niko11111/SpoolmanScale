"""A task that ends itself with vTaskDelete(NULL) never returns from its own
function, so the destructors of what it declares in a block that is still open
at that call never run. A WiFiClientSecure frees its ssl context only in its
destructor, an HTTPClient keeps its socket open after end() and stops it only
there, a JsonDocument or String keeps its buffer. The daily update check lost
its client, its connection and its document that way on every run. Such a task
calls a function that holds the objects and returns, and only then deletes
itself. An object in an inner block that closes before the call is destroyed
at that brace and is fine.

Reads the source without a compiler: comments and strings are blanked and
function bodies found by brace matching, with the tools of the convention
ratchet."""
import re
import sys
from pathlib import Path

root = Path(__file__).parents[1]
src = root / "src"
sys.path.insert(0, str(root / "scripts"))
import check_conventions as cc  # noqa: E402

SELF_DELETE = re.compile(r"\bvTaskDelete\(\s*(?:NULL|nullptr)\s*\)")
# The plain clients hold a socket the same way.
OWNING_TYPES = ("WiFiClientSecure", "NetworkClientSecure", "WiFiClient", "NetworkClient",
                "HTTPClient", "JsonDocument", "String")
OWNING_DECL = re.compile(r"\b(" + "|".join(OWNING_TYPES) + r")\s+([A-Za-z_]\w*)\s*[;=({\[,]")
# The scan must find the task this rule was written for, or it finds nothing.
KNOWN = ("services/update_check.cpp", "updateCheckTask")


def scope_end(body, at):
    """Where the innermost block around position at closes: the matching '}'
    of the nearest unclosed '{' before it, or the end of the function body."""
    depth = 0
    for i in range(at - 1, -1, -1):
        if body[i] == "}":
            depth += 1
        elif body[i] == "{":
            if depth == 0:
                level = 1
                for j in range(i + 1, len(body)):
                    level += {"{": 1, "}": -1}.get(body[j], 0)
                    if level == 0:
                        return j
                return len(body)
            depth -= 1
    return len(body)


errors = []
self_deleting = set()
for path in sorted(src.rglob("*")):
    if path.suffix not in (".h", ".cpp", ".hpp", ".c", ".ino"):
        continue
    source = cc.Source(path.read_text(encoding="utf-8", errors="replace"))
    if not SELF_DELETE.search(source.code):
        continue
    rel = path.relative_to(src).as_posix()
    for name, start, end in cc.find_functions(source.code):
        body = source.code[start + 1:end]
        if not SELF_DELETE.search(body):
            continue
        self_deleting.add((rel, name))
        for decl in OWNING_DECL.finditer(body):
            if not SELF_DELETE.search(body, decl.end(), scope_end(body, decl.start())):
                continue
            errors.append(f"src/{rel}:{source.line_of(start + 1 + decl.start())}: {name}() ends itself with "
                          f"vTaskDelete(NULL) while {decl.group(1)} {decl.group(2)} is in scope, "
                          "whose destructor then never runs")
if KNOWN not in self_deleting:
    errors.append(f"src/{KNOWN[0]}: the scan for self-deleting tasks did not find {KNOWN[1]}()")

if errors:
    print("\n".join(errors))
    sys.exit(1)
print(f"self-deleting tasks: {len(self_deleting)}, none deletes itself with an object in scope: ok")
