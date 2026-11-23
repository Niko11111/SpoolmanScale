"""Compile the production rule for what the second tag question does with a
settled read, and check that a single refusal of the Bambu keys on a Bambu
spool no longer links the chip as a plain tag, and that a Bambu chip of another
spool is not linked at all (ui/second_tag_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "ui/second_tag_rules.h"
#include <cassert>

int main() {
  // Nothing settled: wait.
  assert(tag2Step(TV_NONE, true, false, false) == T2S_WAIT);
  assert(tag2Step(TV_NONE, false, false, false) == T2S_WAIT);

  // Read as Bambu or as something else: link, on any spool.
  assert(tag2Step(TV_BAMBU, true, false, false) == T2S_LINK);
  assert(tag2Step(TV_OTHER, true, false, false) == T2S_LINK);
  assert(tag2Step(TV_OTHER, false, false, false) == T2S_LINK);

  // A chip that never answered: put it back, also after an earlier refusal.
  assert(tag2Step(TV_NO_ANSWER, true, false, false) == T2S_ASK_BACK);
  assert(tag2Step(TV_NO_ANSWER, true, true, false) == T2S_ASK_BACK);

  // Refused the Bambu keys on a Bambu spool: put it back the first time.
  // This linked it as a plain tag before 15.11.2026.
  assert(tag2Step(TV_REFUSED, true, false, false) == T2S_ASK_BACK);
  // Refused again after being put back: a plain tag after all.
  assert(tag2Step(TV_REFUSED, true, true, false) == T2S_LINK);
  // On a spool whose first tag was not Bambu, a refusal is no question.
  assert(tag2Step(TV_REFUSED, false, false, false) == T2S_LINK);
  // A Bambu chip of another spool is not linked, on either kind of spool.
  // This linked a "PLA Tough+" chip to a PETG spool before 23.11.2026.
  assert(tag2Step(TV_BAMBU, false, false, true) == T2S_OTHER_SPOOL);
  assert(tag2Step(TV_BAMBU, true, false, true) == T2S_OTHER_SPOOL);
  // The judgement only ever concerns a Bambu read.
  assert(tag2Step(TV_OTHER, false, false, true) == T2S_LINK);
  assert(tag2Step(TV_NONE, false, false, true) == T2S_WAIT);

  // Two tray uuids decide on their own: the same spool's other chip links
  // even when the data compare would object, another spool's chip of the
  // very same filament does not.
  const char* a = "D12461A84CE0476286B4E47FD62390C3";
  const char* b = "0A0B0C0D0E0F10111213141516171819";
  assert(!tag2BambuOtherSpool(a, a, true));
  assert(tag2BambuOtherSpool(a, b, false));
  // The spool's first tag was no Bambu tag: the data compare decides.
  assert(tag2BambuOtherSpool("", a, true));
  assert(!tag2BambuOtherSpool("", a, false));
  // A cut tray uuid is no tray uuid.
  assert(!tag2BambuOtherSpool("D12461A8", a, false));
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
