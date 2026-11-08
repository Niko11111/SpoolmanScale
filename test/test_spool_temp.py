"""Compile the production rules for the nozzle temperature on the main screen
and on a written tag, and check them against real spools
(services/spool_temp_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/spool_temp_rules.h"
#include <cassert>
#include <string>

static std::string text(SpoolTempRange r) {
  char out[24];
  spoolTempFormat(r, out, sizeof(out));
  return out;
}

static std::string shown(int b_lo, int b_hi, int t_lo, int t_hi) {
  return text(spoolTempShown(spoolTempRange(b_lo, b_hi), spoolTempRange(t_lo, t_hi)));
}

int main() {
  // Kai's case, Discord 08.11.2026: a spool linked by UID only, the tag
  // carries nothing, Spoolman says 240. It used to read "unknown".
  assert(shown(0, 240, 0, 0) == "240 °C");

  // A range from FilaMan or BamBuddy, with nothing on the tag.
  assert(shown(220, 240, 0, 0) == "220 - 240 °C");

  // A Bambu spool the scale created: Spoolman holds the tag's upper end. The
  // tag's range stays.
  assert(shown(0, 230, 190, 230) == "190 - 230 °C");
  assert(shown(190, 230, 190, 230) == "190 - 230 °C");

  // The same spool with the user's own value: it wins, inside the tag's
  // range or not.
  assert(shown(0, 215, 190, 230) == "215 °C");
  assert(shown(0, 250, 190, 230) == "250 °C");
  assert(shown(200, 230, 190, 230) == "200 - 230 °C");

  // An NTAG the scale wrote from the old table (PETG 230 - 250), Spoolman
  // says 240 (spool 298).
  assert(shown(0, 240, 230, 250) == "240 °C");

  // No backend value: the tag's, and nothing at all is empty.
  assert(shown(0, 0, 190, 230) == "190 - 230 °C");
  assert(shown(0, 0, 0, 0).empty());

  // A tag written with one value as both ends reads as that one value.
  assert(shown(0, 240, 240, 240) == "240 °C");

  // Nonsense is dropped: a lower end above the upper, a value in Fahrenheit.
  assert(shown(260, 240, 0, 0) == "240 °C");
  assert(shown(0, 500, 190, 230) == "190 - 230 °C");
  assert(shown(0, -5, 0, 0).empty());

  // The ends a tag gets. The backend first, one value as both ends.
  const SpoolTempRange petg = {230, 250};
  SpoolTempRange e = spoolTempTagEnds(spoolTempRange(0, 240), petg);
  assert(e.lo == 240 && e.hi == 240);
  e = spoolTempTagEnds(spoolTempRange(220, 240), petg);
  assert(e.lo == 220 && e.hi == 240);
  // Nothing in the backend: the family's range, and none for no family.
  e = spoolTempTagEnds(spoolTempRange(0, 0), petg);
  assert(e.lo == 230 && e.hi == 250);
  const SpoolTempRange none = {0, 0};
  e = spoolTempTagEnds(spoolTempRange(0, 0), none);
  assert(e.lo == 0 && e.hi == 0);

  // A buffer too small is cut, never overrun.
  char tiny[4];
  spoolTempFormat(spoolTempRange(190, 230), tiny, sizeof(tiny));
  assert(std::string(tiny) == "190");
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    src = Path(tmp) / "t.cpp"
    exe = Path(tmp) / "t"
    src.write_text(source)
    subprocess.check_call(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                           f"-I{root / 'src'}", str(src), "-o", str(exe)])
    subprocess.check_call([str(exe)])

print("spool temp: ok")
