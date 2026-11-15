"""Compile the production fill-level rule and check that a 0 the printer sends
for a spool without an RFID chip reads as unknown, not as empty - the external
spool entered in Bambu Studio that showed "0 %" (15.11.2026)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/ams_slots.h"
#include <cassert>

int main() {
  // Bambu's ids for a spool without a chip: 16 and 32 zeros, or nothing.
  assert(!amsChipIdReal("0000000000000000"));
  assert(!amsChipIdReal("00000000000000000000000000000000"));
  assert(!amsChipIdReal(""));
  assert(!amsChipIdReal(nullptr));
  assert(amsChipIdReal("D12461A84CE04762"));
  assert(amsChipIdReal("0000000000000001"));

  // No chip: 0 and -1 are "unknown", a real percentage stays.
  assert(amsPrinterRemain(0, false) == AMS_REMAIN_NA);
  assert(amsPrinterRemain(-1, false) == AMS_REMAIN_NA);
  assert(amsPrinterRemain(37, false) == 37);
  // A chip that reads empty is empty.
  assert(amsPrinterRemain(0, true) == 0);
  assert(amsPrinterRemain(100, true) == 100);
  // Out of range is never drawn.
  assert(amsPrinterRemain(101, true) == AMS_REMAIN_NA);
  assert(amsPrinterRemain(-5, true) == AMS_REMAIN_NA);
  return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    cpp.write_text(source)
    binary = Path(tmp) / "test"
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp),
                    "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("AMS printer fill level tests passed")
