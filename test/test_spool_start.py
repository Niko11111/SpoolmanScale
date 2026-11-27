"""Compile the production spool start rules and read the decisions back:
how far an empty spool weight is trusted, and what a spool created off the
pad starts with (services/spool_start.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/spool_start.h"
#include <cassert>
#include <cmath>

static bool near(float a, float b) { return std::fabs(a - b) < 0.01f; }

int main() {
  // The maker's fixed core: a stored weight that says the same figure is
  // still that figure - the scale itself files it on the brand and the
  // filament it creates, so the second Bambu spool reads it back.
  assert(spoolTareQuality(250, true, 250) == TARE_Q_DEFAULT);
  // Someone weighed the core: a measurement, whatever the tag says.
  assert(spoolTareQuality(241, true, 250) == TARE_Q_KNOWN);
  // A catalog entry without a fixed figure behind it is stored by someone.
  assert(spoolTareQuality(250, false, 250) == TARE_Q_KNOWN);
  assert(spoolTareQuality(0, true, 250) == TARE_Q_NONE);
  assert(spoolTareQuality(-5, false, 0) == TARE_Q_NONE);

  // A full Bambu spool on the fixed core keeps the label as its full weight,
  // the measured net is what is left (gross 1257 g: 1007 g of filament).
  SpoolStart s = spoolStartValues(1257.0f, 250, TARE_Q_DEFAULT, 1000);
  assert(s.verdict == START_FULL && s.initial_g == 1000 && near(s.remaining_g, 1007.0f));
  assert(near(s.net_g, 1007.0f) && s.tare_g == 250 && s.label_g == 1000);
  // The same reading against an empty spool someone stored files the
  // measured net as the full weight.
  s = spoolStartValues(1257.0f, 250, TARE_Q_KNOWN, 1000);
  assert(s.verdict == START_FULL && s.initial_g == 1007 && near(s.remaining_g, 1007.0f));
  // A default core widens the band by its slack: 1040 g net is still full
  // on the fixed core (30 g + 10 g), over the limit on a stored one.
  assert(spoolStartValues(1290.0f, 250, TARE_Q_DEFAULT, 1000).verdict == START_FULL);
  assert(spoolStartValues(1290.0f, 250, TARE_Q_KNOWN, 1000).verdict == START_OVER);
  // Used: the label stays the full weight, what is left is the reading.
  s = spoolStartValues(1180.0f, 250, TARE_Q_KNOWN, 1000);
  assert(s.verdict == START_PARTIAL && s.initial_g == 1000 && near(s.remaining_g, 930.0f));
  // More than a full spool can weigh: filed as full, and the card says so.
  s = spoolStartValues(1400.0f, 250, TARE_Q_KNOWN, 1000);
  assert(s.verdict == START_OVER && s.initial_g == 1000 && near(s.remaining_g, 1000.0f));
  assert(near(s.net_g, 1150.0f));
  // Nothing on the pad, and a spool on it with nothing to subtract.
  s = spoolStartValues(0.0f, 250, TARE_Q_KNOWN, 1000);
  assert(s.verdict == START_NOT_WEIGHED && s.initial_g == 1000 && near(s.net_g, -1.0f));
  s = spoolStartValues(1250.0f, 0, TARE_Q_NONE, 1000);
  assert(s.verdict == START_NO_TARE && s.initial_g == 1000 && near(s.remaining_g, 1000.0f));
  // No label: a full reading becomes the full weight on a default core too.
  s = spoolStartValues(1257.0f, 250, TARE_Q_DEFAULT, 0);
  assert(s.verdict == START_FULL && s.initial_g == 1007);

  // A full weight nothing names: a spool that reads as full of one size is
  // that size, anything else is taken as a used 1 kg spool, or the smallest
  // size above that holds it (Nikolai, 26.11.2026: 112 g left on a 1 kg
  // spool was filed as a 250 g one).
  assert(spoolAssumedLabelG(112.0f) == 1000);
  assert(spoolAssumedLabelG(620.0f) == 1000);
  assert(spoolAssumedLabelG(0.0f) == 1000);
  assert(spoolAssumedLabelG(-1.0f) == 1000);
  assert(spoolAssumedLabelG(10.0f) == 1000);
  assert(spoolAssumedLabelG(248.0f) == 250);
  assert(spoolAssumedLabelG(503.0f) == 500);
  assert(spoolAssumedLabelG(1007.0f) == 1000);
  assert(spoolAssumedLabelG(1035.0f) == 1000);   // 1000 + 30 band + 10 slack
  assert(spoolAssumedLabelG(1040.0f) == 1000);
  assert(spoolAssumedLabelG(1041.0f) == 2000);
  assert(spoolAssumedLabelG(265.0f) == 250);     // 250 + its 15 g band
  assert(spoolAssumedLabelG(266.0f) == 1000);
  assert(spoolAssumedLabelG(1500.0f) == 2000);
  assert(spoolAssumedLabelG(2990.0f) == 3000);
  assert(spoolAssumedLabelG(4200.0f) == 3000);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"),
                    str(cpp), str(root / "src" / "services" / "spool_start.cpp"), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
print("spool start rules: ok")
