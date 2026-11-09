"""Compile the production TSPL job assembly and check header, footer and inversion."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/tspl_printer.h"
#include <cassert>
#include <cstring>
#include <vector>

int main() {
  char h[160], f[24];

  // A 40 x 30 mm label at 203 dpi: 320 x 240 dots, 40 bytes a row.
  const TsplJob job = { 40, 30, 40, 240 };
  int n = tsplHeader(h, sizeof(h), job);
  assert(n > 0 && size_t(n) == strlen(h));
  assert(strstr(h, "SIZE 40 mm,30 mm\r\n"));
  assert(strstr(h, "GAP 3 mm,0 mm\r\n"));
  assert(strstr(h, "CLS\r\n"));
  // The BITMAP command ends in the comma after the mode: pixels follow at once.
  assert(strcmp(h + n - strlen("BITMAP 0,0,40,240,0,"), "BITMAP 0,0,40,240,0,") == 0);
  // Order matters to the printer: the size before the clear, the clear before the bitmap.
  assert(strstr(h, "SIZE") < strstr(h, "CLS") && strstr(h, "CLS") < strstr(h, "BITMAP"));

  n = tsplFooter(f, sizeof(f));
  assert(n > 0 && strcmp(f, "\r\nPRINT 1,1\r\n") == 0);

  // Too small a buffer is refused, never truncated silently.
  char small[16];
  assert(tsplHeader(small, sizeof(small), job) == -1);
  assert(tsplFooter(small, 4) == -1);

  // 1 = black in the scale's raster, 0 = black in TSPL.
  const uint8_t in[] = { 0x00, 0xFF, 0xA5, 0x0F };
  uint8_t out[4];
  tsplInvert(in, out, sizeof(in));
  assert(out[0] == 0xFF && out[1] == 0x00 && out[2] == 0x5A && out[3] == 0xF0);
  // The unused low bits of a row (zero in the raster) come out white.
  const uint8_t row[] = { 0xF8 };
  tsplInvert(row, out, 1);
  assert((out[0] & 0x07) == 0x07);
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    cpp.write_text(source)
    binary = Path(tmp) / "test"
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("TSPL job tests passed")
