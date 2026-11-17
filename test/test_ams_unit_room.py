"""Compile the production rule that decides which units a printer reports get
a place on the AMS view, and check that the external holder keeps its own
place when a printer has more AMS units than the view shows (an H2D takes
four AMS and up to eight AMS HT)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/ams_slots.h"
#include <cassert>

// Feed units in the order a backend reports them, the way the parsers do:
// a unit without room is left out, the loop goes on.
static int feed(AmsSlotState& s, const bool* is_ext, int n) {
  int left_out = 0;
  for (int i = 0; i < n; i++) {
    if (!amsUnitHasRoom(s, is_ext[i])) { left_out++; continue; }
    s.unit[s.unit_count].is_ext = is_ext[i];
    s.unit_count++;
  }
  return left_out;
}

int main() {
  // FilaMan, demo printer 4: four AMS, two AMS HT, the external holder last.
  {
    AmsSlotState s{};
    const bool units[] = {false, false, false, false, false, false, true};
    assert(feed(s, units, 7) == 2);
    assert(s.unit_count == AMS_UNITS_TOTAL);
    assert(s.unit[AMS_UNITS_TOTAL - 1].is_ext);   // the holder kept its place
  }
  // Four AMS and one AMS HT: before the fix the holder was the one cut.
  {
    AmsSlotState s{};
    const bool units[] = {false, false, false, false, false, true};
    assert(feed(s, units, 6) == 1);
    assert(s.unit[4].is_ext);
  }
  // The holder first: it takes its place and the four AMS still fit.
  {
    AmsSlotState s{};
    const bool units[] = {true, false, false, false, false};
    assert(feed(s, units, 5) == 0);
    assert(s.unit_count == 5);
  }
  // A small printer loses nothing, and a second holder never gets a place.
  {
    AmsSlotState s{};
    const bool units[] = {false, false, true, true};
    assert(feed(s, units, 4) == 1);
    assert(s.unit_count == 3);
  }
  return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    src = Path(tmp) / "t.cpp"
    exe = Path(tmp) / "t"
    src.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-I", str(root / "src"), str(src), "-o", str(exe)],
                   check=True)
    subprocess.run([str(exe)], check=True)
print("ams unit room: ok")
