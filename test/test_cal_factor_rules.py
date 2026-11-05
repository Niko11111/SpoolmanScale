"""Compile the production factor rules and read the decisions back: an old
stored factory value moves to the new one, and a calibration never reads as
uncalibrated (services/cal_factor_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/cal_factor_rules.h"
#include <cassert>

int main() {
  // A device reset under the old firmware counts as uncalibrated again.
  assert(calFactorFromStored(CAL_FACTOR_LEGACY_DEFAULT) == CAL_FACTOR_DEFAULT);
  // Real calibrations survive the update untouched, a mirrored cell included.
  assert(calFactorFromStored(1199.085f) == 1199.085f);
  assert(calFactorFromStored(412.5f) == 412.5f);
  assert(calFactorFromStored(-1199.085f) == -1199.085f);
  assert(calFactorFromStored(CAL_FACTOR_DEFAULT) == CAL_FACTOR_DEFAULT);

  // 500000 counts over 500 g is exactly the factory value, and still a
  // calibration.
  const float measured_round = 500000.0f / 500.0f;
  assert(measured_round == CAL_FACTOR_DEFAULT);
  assert(calFactorFromMeasured(measured_round) != CAL_FACTOR_DEFAULT);
  // The step itself must be too small to matter: under 0.01 g on a 1 kg spool.
  const float moved = calFactorFromMeasured(measured_round);
  assert((moved - CAL_FACTOR_DEFAULT) / CAL_FACTOR_DEFAULT * 1000.0f < 0.011f);
  // Any other result stays as measured.
  assert(calFactorFromMeasured(1199.085f) == 1199.085f);
  assert(calFactorFromMeasured(-1000.0f) == -1000.0f);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    binary = Path(tmp) / "test"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"),
                    str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("cal factor rules ok")
