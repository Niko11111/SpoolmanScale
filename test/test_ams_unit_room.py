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

// n units of AMS or AMS HT, then the external holder, as FilaMan sends them.
static int feedUnitsThenHolder(AmsSlotState& s, int n) {
  bool units[AMS_UNITS_TOTAL + 4] = {};
  units[n] = true;
  return feed(s, units, n + 1);
}

int main() {
  // Bambu's largest set, four AMS 2 Pro and eight AMS HT on an H2D: all fit.
  static_assert(AMS_MAX_UNITS >= 12, "the view must hold an H2D's full set");
  {
    AmsSlotState s{};
    assert(feedUnitsThenHolder(s, 12) == 0);
    assert(s.unit_count == 13);
    assert(s.unit[12].is_ext);
  }
  // More units than the view holds: the surplus goes, the holder stays.
  // Before beta.64 the holder was the one cut.
  {
    AmsSlotState s{};
    assert(feedUnitsThenHolder(s, AMS_MAX_UNITS + 2) == 2);
    assert(s.unit_count == AMS_UNITS_TOTAL);
    assert(s.unit[AMS_UNITS_TOTAL - 1].is_ext);
  }
  // The holder first: it takes its place and every unit still fits.
  {
    AmsSlotState s{};
    bool units[AMS_UNITS_TOTAL] = {};
    units[0] = true;
    assert(feed(s, units, AMS_UNITS_TOTAL) == 0);
    assert(s.unit_count == AMS_UNITS_TOTAL);
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
