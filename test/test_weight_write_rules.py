"""Compile the production reading of a failed weight write and check what the
user is told for each answer (services/weight_write_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/weight_write_rules.h"
#include <cassert>

int main() {
  const int saved[] = {200, 201, 204};
  for (int code : saved) {
    assert(weightWriteProblemOf(code, true) == WEIGHT_WRITE_FINE);
    assert(weightWriteProblemOf(code, false) == WEIGHT_WRITE_FINE);
  }
  // The refusal popup says these; a second one would only stand in its way.
  const int refused[] = {401, 402, 403, 429};
  for (int code : refused) assert(weightWriteProblemOf(code, true) == WEIGHT_WRITE_FINE);

  assert(weightWriteProblemOf(409, true) == WEIGHT_WRITE_NO_TARE);
  // FilaMan and BamBuddy: a 409 says nothing about the empty weight.
  assert(weightWriteProblemOf(409, false) == WEIGHT_WRITE_NOT_SAVED);

  // No answer at all, and every other no: the weight did not arrive.
  const int lost[] = {400, 404, 422, 500, 503, 0, -1, -11};
  for (int code : lost) assert(weightWriteProblemOf(code, true) == WEIGHT_WRITE_NOT_SAVED);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    src = Path(tmp) / "t.cpp"
    exe = Path(tmp) / "t"
    src.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-I", str(root / "src"), str(src), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("weight write rules ok")
