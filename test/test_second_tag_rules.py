"""Compile the production rule for what the second tag question does with a
settled read, and check that a single refusal of the Bambu keys on a Bambu
spool no longer links the chip as a plain tag (ui/second_tag_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "ui/second_tag_rules.h"
#include <cassert>

int main() {
  // Nothing settled: wait.
  assert(tag2Step(TV_NONE, true, false) == T2S_WAIT);
  assert(tag2Step(TV_NONE, false, false) == T2S_WAIT);

  // Read as Bambu or as something else: link, on any spool.
  assert(tag2Step(TV_BAMBU, true, false) == T2S_LINK);
  assert(tag2Step(TV_OTHER, true, false) == T2S_LINK);
  assert(tag2Step(TV_OTHER, false, false) == T2S_LINK);

  // A chip that never answered: put it back, also after an earlier refusal.
  assert(tag2Step(TV_NO_ANSWER, true, false) == T2S_ASK_BACK);
  assert(tag2Step(TV_NO_ANSWER, true, true) == T2S_ASK_BACK);

  // Refused the Bambu keys on a Bambu spool: put it back the first time.
  // This linked it as a plain tag before 15.11.2026.
  assert(tag2Step(TV_REFUSED, true, false) == T2S_ASK_BACK);
  // Refused again after being put back: a plain tag after all.
  assert(tag2Step(TV_REFUSED, true, true) == T2S_LINK);
  // On a spool whose first tag was not Bambu, a refusal is no question.
  assert(tag2Step(TV_REFUSED, false, false) == T2S_LINK);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"),
                    str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("second tag rules: ok")
