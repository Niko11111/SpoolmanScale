"""Compile the production tare rules and read the decisions back: which level
of the chain answers, and when Spoolman's /measure may do the subtraction
(services/tare_chain.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/tare_chain.h"
#include <cassert>

int main() {
  const float zero = 0.0f, core = 250.0f, brand = 180.0f, minus = -5.0f;
  uint8_t from = 99;

  // The first level with a value answers.
  assert(tareFromChain(&core, &brand, &brand, &from) == 250.0f && from == TARE_SPOOL);
  assert(tareFromChain(nullptr, &core, &brand, &from) == 250.0f && from == TARE_FILAMENT);
  assert(tareFromChain(nullptr, nullptr, &brand, &from) == 180.0f && from == TARE_VENDOR);
  assert(tareFromChain(nullptr, nullptr, nullptr, &from) == 0.0f && from == TARE_NONE);

  // A stored 0 is a value: a refill on a filament with a 250 g tare weighs
  // 400 g net at 400 g gross, as Spoolman 0.27.1 books it, not 150 g.
  assert(tareFromChain(&zero, &core, &brand, &from) == 0.0f && from == TARE_SPOOL);
  // The same one level down: SpoolmanDB's refill entries carry a filament 0.
  assert(tareFromChain(nullptr, &zero, &brand, &from) == 0.0f && from == TARE_FILAMENT);
  assert(tareFromChain(nullptr, nullptr, &zero, &from) == 0.0f && from == TARE_VENDOR);

  // A negative number was never a weight.
  assert(tareFromChain(&minus, &core, nullptr, &from) == 250.0f && from == TARE_FILAMENT);
  // The source is optional.
  assert(tareFromChain(&core, nullptr, nullptr, nullptr) == 250.0f);

  // /measure subtracts the same number on every server version...
  assert(tareMeasureAgrees(TARE_SPOOL, 250.0f));
  assert(tareMeasureAgrees(TARE_FILAMENT, 250.0f));
  assert(tareMeasureAgrees(TARE_NONE, 0.0f));
  // ...but a brand-only tare ends at zero on older servers,
  assert(!tareMeasureAgrees(TARE_VENDOR, 180.0f));
  // and a stored 0 falls through to the filament's tare before v0.27.1.
  assert(!tareMeasureAgrees(TARE_SPOOL, 0.0f));
  assert(!tareMeasureAgrees(TARE_FILAMENT, 0.0f));
  assert(!tareMeasureAgrees(TARE_VENDOR, 0.0f));
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    binary = Path(tmp) / "test"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"),
                    str(cpp), str(root / "src/services/tare_chain.cpp"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("tare chain rules ok")
