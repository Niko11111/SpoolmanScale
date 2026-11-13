"""Compile the rule that finds readable text in a MIFARE card's data
(services/mifare_data_rules.h) and check what it makes of typical contents."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/mifare_data_rules.h"
#include <cassert>
#include <cstring>

static bool text(const char* bytes, size_t len, char* out, size_t out_len) {
  return mifareDataText(reinterpret_cast<const uint8_t*>(bytes), len, out, out_len);
}

int main() {
  char out[24];

  // A name between zero bytes, with spaces around it.
  const char named[] = "\x00\x00  ACCESS 0815  \x00\xFF\x12";
  assert(text(named, sizeof(named) - 1, out, sizeof(out)));
  assert(strcmp(out, "ACCESS 0815") == 0);

  // The longest run wins over an earlier short one.
  const char two[] = "AB\x01" "Werkstatt Tür\x02xy";
  assert(text(two, sizeof(two) - 1, out, sizeof(out)));
  assert(strcmp(out, "Werkstatt T") == 0);   // the umlaut ends the ASCII run

  // Random bytes and short runs are not text.
  const char noise[] = "\x8F\x12\x00ab\x01\xFFxyz\x7F";
  assert(!text(noise, sizeof(noise) - 1, out, sizeof(out)));
  assert(out[0] == '\0');
  const uint8_t blank[48] = {0};
  assert(!mifareDataText(blank, sizeof(blank), out, sizeof(out)));

  // Spaces alone do not count, and a run is cut to fit the buffer.
  const char spaces[] = "\x00        \x00";
  assert(!text(spaces, sizeof(spaces) - 1, out, sizeof(out)));
  const char longer[] = "0123456789ABCDEFGHIJ";
  char small[8];
  assert(text(longer, sizeof(longer) - 1, small, sizeof(small)));
  assert(strcmp(small, "0123456") == 0);

  // Nothing to read from, nowhere to write.
  assert(!mifareDataText(nullptr, 4, out, sizeof(out)));
  assert(!text(longer, sizeof(longer) - 1, nullptr, 8));
  assert(!text(longer, sizeof(longer) - 1, out, 1) && out[0] == '\0');
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", f"-I{root / 'src'}", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("mifare data: ok")
