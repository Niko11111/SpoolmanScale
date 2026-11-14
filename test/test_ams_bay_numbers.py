"""Compile the production AMS bay helpers and check the model, the global bay
numbers tray_now reports and which bays an assignment accepts, against the
values of BamBuddy's utils/tray_ids.py and the H3C status of issue #91."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/ams_slots.h"
#include <cassert>

static AmsSlotUnit unit(int ams_id, AmsModel model, bool ht) {
  AmsSlotUnit u{};
  u.ams_id = (uint8_t)ams_id;
  u.model  = model;
  u.is_ht  = ht;
  return u;
}

int main() {
  // The name wins; an AMS 3H without one is told by its type or its id.
  assert(amsModelFromBambu("n10a", -1, 32) == AMS_MODEL_AMS_3H);
  assert(amsModelFromBambu("", 6, 7) == AMS_MODEL_AMS_3H);
  assert(amsModelFromBambu("", -1, 32) == AMS_MODEL_AMS_3H);
  assert(amsModelFromBambu("n3f", 6, 32) == AMS_MODEL_AMS_2_PRO);
  assert(amsModelFromBambu("", -1, 1) == AMS_MODEL_UNKNOWN);

  // Global numbers: regular ams_id * 4 + bay, AMS 3H 28 + bay, AMS HT its id.
  assert(amsGlobalTrayId(unit(0, AMS_MODEL_AMS, false), 0) == 0);
  assert(amsGlobalTrayId(unit(1, AMS_MODEL_AMS_2_PRO, false), 3) == 7);
  assert(amsGlobalTrayId(unit(32, AMS_MODEL_AMS_3H, false), 5) == 33);  // issue #91
  assert(amsGlobalTrayId(unit(32, AMS_MODEL_AMS_3H, false), 8) == 36);
  assert(amsGlobalTrayId(unit(128, AMS_MODEL_AMS_HT, true), 0) == 128);
  // The A2L's AMS Lite is stored as unit 6: 24 + bay, as Studio counts it.
  assert(amsGlobalTrayId(unit(6, AMS_MODEL_AMS_LITE, false), 2) == 26);

  // Four bays a unit, nine on the AMS 3H and the external inputs.
  assert(amsBayAssignable(0, 3));
  assert(!amsBayAssignable(0, 4));
  assert(amsBayAssignable(32, 8));
  assert(!amsBayAssignable(32, 9));
  assert(amsBayAssignable(255, 8));
  assert(amsBayAssignable(128, 0));
  assert(!amsBayAssignable(-1, 0));
  assert(!amsBayAssignable(256, 0));
  assert(!amsBayAssignable(0, -1));
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
print("AMS bay number tests passed")
