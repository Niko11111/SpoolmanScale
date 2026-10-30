"""Compile the production rule that keeps automatic weighing from filing a
spool whose tag lies on the reader without the spool on the pad, and read it
back (services/auto_weight_state.cpp)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/auto_weight_state.h"
#include <cassert>

int main() {
  // A tag alone over an empty pad: too light.
  assert(autoWeightPadTooLight(0.0f));
  assert(autoWeightPadTooLight(3.0f));
  assert(autoWeightPadTooLight(19.0f));
  // From 20 g on a spool is on the pad, whatever its stored empty weight:
  // a 140 g cardboard spool where 250 g is stored still counts.
  assert(!autoWeightPadTooLight(20.0f));
  assert(!autoWeightPadTooLight(140.0f));
  assert(!autoWeightPadTooLight(220.0f));
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"),
                    str(cpp), str(root / "src" / "services" / "auto_weight_state.cpp"), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
print("auto weight pad rule: ok")
