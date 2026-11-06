"""Compile the rule for the release notes the firmware page shows
(services/notes_cut.h) and check the limit and where a longer text is cut:
never inside a character of more than one byte, which would end the notes in a
broken sign. Then read github_release.cpp: it uses the rule and keeps no limit
of its own.

The limit: 32 000 bytes. The longest notes so far, v0.8.3-beta.96, have 28 859
bytes, v0.8.3 has 28 460; 8000 showed less than a third of them."""
import re
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/notes_cut.h"
#include <cassert>
#include <cstring>
#include <string>

int main() {
  static_assert(GH_NOTES_MAX == 32000, "the limit");
  static_assert(GH_NOTES_MAX > 28859, "room for the longest notes so far (v0.8.3-beta.96, 28 859 bytes)");

  // Short enough: kept whole.
  assert(notesCutLength("abc", 3, 10) == 3);
  assert(notesCutLength("abc", 3, 3) == 3);

  // Plain text: cut at the limit.
  std::string ascii(100, 'x');
  assert(notesCutLength(ascii.c_str(), ascii.size(), 50) == 50);

  // A two byte sign across the cut: the whole sign goes.
  std::string de = std::string(49, 'x') + "\xC3\xA4" + "yyy";    // a-umlaut at bytes 49 and 50
  assert(notesCutLength(de.c_str(), de.size(), 50) == 49);
  assert(notesCutLength(de.c_str(), de.size(), 51) == 51);       // ends right after it

  // Three and four byte signs.
  std::string euro = std::string(48, 'x') + "\xE2\x82\xAC" + "y"; // euro sign at 48..50
  assert(notesCutLength(euro.c_str(), euro.size(), 49) == 48);
  assert(notesCutLength(euro.c_str(), euro.size(), 50) == 48);
  assert(notesCutLength(euro.c_str(), euro.size(), 51) == 51);
  std::string emoji = std::string(10, 'x') + "\xF0\x9F\x99\x82" + "y";
  assert(notesCutLength(emoji.c_str(), emoji.size(), 12) == 10);
  assert(notesCutLength(emoji.c_str(), emoji.size(), 14) == 14);

  // A cut at the very beginning.
  assert(notesCutLength("\xC3\xA4", 2, 1) == 0);
  assert(notesCutLength("abc", 3, 0) == 0);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"),
                    str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

gh = (root / "src" / "services" / "github_release.cpp").read_text(encoding="utf-8")
assert '#include "services/notes_cut.h"' in gh, "github_release.cpp: does not include services/notes_cut.h"
assert not re.search(r"#\s*define\s+GH_NOTES_MAX\b", gh), "github_release.cpp: keeps a GH_NOTES_MAX of its own"
assert re.search(r"\bnotesCutLength\s*\(", gh), "github_release.cpp: does not cut with notesCutLength()"
print("notes cut: ok")
