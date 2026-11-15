"""Compile the production hotend helper and check which bay each hotend of a
dual-nozzle printer is loaded from and which one is active, for the shapes
BamBuddy reports in extruder_slots (device.extruder.info[].snow)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/ams_hotend.h"
#include <cassert>

// Two AMS units of four bays and the H2D's two external bays (254, 255).
static AmsSlotState h2d() {
  AmsSlotState s{};
  for (int u = 0; u < 2; u++) {
    s.unit[u].ams_id = (uint8_t)u;
    s.unit[u].tray_count = 4;
    for (int t = 0; t < 4; t++) s.unit[u].tray[t].tray_id = (uint8_t)t;
  }
  s.unit[2].ams_id = AMS_EXT_AMS_ID;
  s.unit[2].is_ext = true;
  s.unit[2].tray_count = 2;
  s.unit[2].tray[0].tray_id = 254;
  s.unit[2].tray[1].tray_id = 255;
  s.unit_count = 3;
  return s;
}

int main() {
  // Right hotend from A3, left from B1, left in use. tray_now had said A1.
  {
    AmsSlotState s = h2d();
    s.unit[0].tray[0].active = true;
    const AmsHotendFeed feed[2] = {{0, 2}, {1, 0}};
    assert(amsApplyHotends(s, feed, 2, 1));
    assert(s.unit[0].tray[2].hotend == AMS_HOTEND_RIGHT);
    assert(s.unit[1].tray[0].hotend == AMS_HOTEND_LEFT);
    assert(s.unit[1].tray[0].active);
    assert(!s.unit[0].tray[0].active);
    assert(!s.unit[0].tray[2].active);
    assert(s.unit[0].tray[0].hotend == AMS_HOTEND_NONE);
  }
  // An external spool on the left hotend: holder 254, slot 0.
  {
    AmsSlotState s = h2d();
    const AmsHotendFeed feed[2] = {{-1, -1}, {254, 0}};
    assert(amsApplyHotends(s, feed, 2, 1));
    assert(s.unit[2].tray[0].hotend == AMS_HOTEND_LEFT);
    assert(s.unit[2].tray[0].active);
    assert(s.unit[2].tray[1].hotend == AMS_HOTEND_NONE);
  }
  // The hotend in use holds nothing on this page: tray_now stays the answer.
  {
    AmsSlotState s = h2d();
    s.unit[0].tray[1].active = true;
    const AmsHotendFeed feed[2] = {{1, 3}, {-1, -1}};
    assert(amsApplyHotends(s, feed, 2, 1));
    assert(s.unit[0].tray[1].active);
    assert(s.unit[1].tray[3].hotend == AMS_HOTEND_RIGHT);
    assert(!s.unit[1].tray[3].active);
  }
  // A single-nozzle X1C sends one entry: nothing changes.
  {
    AmsSlotState s = h2d();
    s.unit[0].tray[1].active = true;
    const AmsHotendFeed feed[1] = {{0, 1}};
    assert(!amsApplyHotends(s, feed, 1, 0));
    assert(s.unit[0].tray[1].hotend == AMS_HOTEND_NONE);
    assert(s.unit[0].tray[1].active);
  }
  // A bay the page does not have is ignored rather than written past the end.
  {
    AmsSlotState s = h2d();
    const AmsHotendFeed feed[2] = {{3, 0}, {0, 9}};
    assert(amsApplyHotends(s, feed, 2, 0));
    for (int u = 0; u < s.unit_count; u++)
      for (int t = 0; t < s.unit[u].tray_count; t++)
        assert(s.unit[u].tray[t].hotend == AMS_HOTEND_NONE && !s.unit[u].tray[t].active);
  }
  // FilaMan's words; an older server sends nothing.
  assert(amsHotendFromWord("left") == AMS_HOTEND_LEFT);
  assert(amsHotendFromWord("right") == AMS_HOTEND_RIGHT);
  assert(amsHotendFromWord("") == AMS_HOTEND_NONE);
  assert(amsHotendFromWord(nullptr) == AMS_HOTEND_NONE);
  assert(amsHotendFromWord("Left") == AMS_HOTEND_NONE);
  // A cleared bay means "no hotend", so a zeroed state needs no setup.
  assert(AmsSlotTray{}.hotend == AMS_HOTEND_NONE);
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
print("AMS hotend tests passed")
