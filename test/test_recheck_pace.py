"""Compile the production pace of the unknown tag recheck and check how long
it asks, how often, and that a server's own back-off still wins
(services/recheck_pace.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/recheck_pace.h"
#include <cassert>

int main() {
  const uint32_t MIN = 60000, FAST = 4000;

  // The first five minutes stay as they were.
  assert(recheckPacedGap(0, FAST) == FAST);
  assert(recheckPacedGap(5 * MIN - 1, FAST) == FAST);
  assert(recheckPhase(5 * MIN - 1) == RECHECK_PHASE_FAST);

  // Then once a minute.
  assert(recheckPacedGap(5 * MIN, FAST) == 60000);
  assert(recheckPacedGap(119 * MIN, FAST) == 60000);
  assert(recheckPhase(5 * MIN) == RECHECK_PHASE_SLOW);

  // After two hours not at all.
  assert(recheckPacedGap(120 * MIN - 1, FAST) == 60000);
  assert(recheckPacedGap(120 * MIN, FAST) == RECHECK_STOPPED);
  assert(recheckPacedGap(0xFFFFFFFFu, FAST) == RECHECK_STOPPED);
  assert(recheckPhase(120 * MIN) == RECHECK_PHASE_OVER);

  // A gap grown by a server that does not answer is kept in the fast phase.
  assert(recheckPacedGap(MIN, 32000) == 32000);
  assert(recheckPacedGap(10 * MIN, 120000) == 120000);

  // What a forgotten tag costs at most: 75 + 115 questions, a day of the old
  // pace was 21,600.
  uint32_t asked = 0, t = 0;
  while (true) {
    const uint32_t gap = recheckPacedGap(t, FAST);
    if (gap == RECHECK_STOPPED) break;
    t += gap;
    asked++;
  }
  assert(asked >= 180 && asked <= 195);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", f"-I{root / 'src'}", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("recheck pace: ok")
