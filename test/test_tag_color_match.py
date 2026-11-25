"""Compile the match of a tag's colour against a maker's colour table and read
it back: the nearest close entry lends its name, a far one does not, two
entries of different names about as close make it a guess, and the tag's
product line and weight narrow the table first
(services/tag_color_match.cpp)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]

source = r"""
#include "services/tag_color_match.h"
#include <cassert>
#include <cstring>

static ColorCandidate e(const char* hex, const char* name, const char* line = "",
                        uint16_t w = 1000, uint8_t n = 1) {
  ColorCandidate c = { hex, n, name, line, w };
  return c;
}

int main() {
  // The distance: equal is 0, black against white the far end.
  assert(tagColorDistance("F2B8C6", "F2B8C6") == 0);
  assert(tagColorDistance("#F2B8C6", "f2b8c6") == 0);
  assert(tagColorDistance("000000", "FFFFFF") == 255);
  assert(tagColorDistance("zz0000", "000000") < 0);
  // SpoolmanDB's AARRGGBB: the colour is the last six.
  assert(tagColorDistance("80F2B8C6", "F2B8C6") == 0);

  // A pink tag against a small table: the close pink wins, although the two
  // fall on either side of the red/pink edge of color_family.cpp.
  const ColorCandidate table[] = {
    e("000000", "Black"), e("FFFFFF", "White"), e("F4B9C8", "Pink"), e("D32F2F", "Red"),
  };
  ColorQuery q = { "F2B8C6", "", 1000 };
  ColorMatch m = tagColorMatch(q, table, 4);
  assert(m.verdict == CMV_SURE && m.best == 2);

  // Far from everything: no name.
  q.hex = "7E57C2";
  m = tagColorMatch(q, table, 4);
  assert(m.verdict == CMV_NONE);

  // The same pink twice under different names (PLA and PLA Matte): a guess.
  const ColorCandidate twins[] = { e("F4B9C8", "Pink"), e("F3B8C7", "Matte Pink") };
  q.hex = "F2B8C6";
  m = tagColorMatch(q, twins, 2);
  assert(m.verdict == CMV_AMBIGUOUS);
  // The same entry twice (two spool sizes listed apart) is no rival.
  const ColorCandidate dup[] = { e("F4B9C8", "Pink", "", 0), e("F4B9C8", "Pink", "", 0) };
  m = tagColorMatch(q, dup, 2);
  assert(m.verdict == CMV_SURE);

  // A rival far enough away leaves the match sure.
  const ColorCandidate apart[] = { e("F2B8C6", "Pink"), e("E91E63", "Magenta") };
  m = tagColorMatch(q, apart, 2);
  assert(m.verdict == CMV_SURE && m.best == 0);

  // The tag's weight leaves out the other sizes.
  const ColorCandidate sizes[] = { e("F4B9C8", "Pink 250g", "", 250), e("F3B8C7", "Pink", "", 1000) };
  m = tagColorMatch(q, sizes, 2);
  assert(m.verdict == CMV_SURE && m.best == 1);

  // The tag's line: the database's own, or the head of its name.
  const ColorCandidate lines[] = {
    e("F4B9C8", "Basic Pink", "basic"), e("F3B8C7", "SnapSpeed Pink", "snap-speed"),
  };
  ColorQuery snap = { "F2B8C6", "SnapSpeed", 1000 };
  m = tagColorMatch(snap, lines, 2);
  assert(m.verdict == CMV_SURE && m.best == 1);
  const ColorCandidate named[] = { e("F4B9C8", "Basic Pink"), e("F3B8C7", "SnapSpeed Pink") };
  m = tagColorMatch(snap, named, 2);
  assert(m.verdict == CMV_SURE && m.best == 1);
  assert(!tagColorLineFits(named[0], "SnapSpeed"));
  assert(tagColorLineFits(named[0], ""));

  // The verdict in words, for the log.
  {
    char text[160];
    ColorMatcher mt;
    tagColorMatchBegin(&mt, q);
    for (int i = 0; i < 2; i++) tagColorMatchAdd(&mt, twins[i], i);
    tagColorMatchText(mt, tagColorMatchEnd(mt), text, sizeof(text));
    assert(strcmp(text, "nearest colour to #F2B8C6 is Matte Pink (distance 1), too close to another, "
                        "not taken - the other is Pink") == 0);
    ColorQuery hashed = { "#F2B8C6", "", 1000 };
    tagColorMatchBegin(&mt, hashed);
    tagColorMatchAdd(&mt, apart[0], 0);
    tagColorMatchText(mt, tagColorMatchEnd(mt), text, sizeof(text));
    assert(strcmp(text, "nearest colour to #F2B8C6 is Pink (distance 0), taken") == 0);
    tagColorMatchBegin(&mt, q);
    tagColorMatchText(mt, tagColorMatchEnd(mt), text, sizeof(text));
    assert(text[0] == '\0');
  }

  // Multi colour entries and clear tags never match.
  const ColorCandidate multi[] = { e("F2B8C6", "Candy", "", 1000, 2) };
  m = tagColorMatch(q, multi, 1);
  assert(m.verdict == CMV_NONE && m.best == -1);
  ColorQuery clear = { "", "", 1000 };
  m = tagColorMatch(clear, table, 4);
  assert(m.verdict == CMV_NONE);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    "-I", str(root / "src"),
                    str(cpp), str(root / "src" / "services" / "tag_color_match.cpp"),
                    str(root / "src" / "services" / "color_family.cpp"), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
print("tag colour match: ok")
