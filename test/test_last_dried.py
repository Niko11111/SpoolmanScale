"""Compile the production rule that reads a stored drying date and check the
shapes servers send (services/last_dried_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/last_dried_rules.h"
#include <cassert>
#include <string>

static std::string utc(const char* raw) {
  char out[LAST_DRIED_ISO_MAX];
  lastDriedUtc(raw, out, sizeof(out));
  return out;
}

int main() {
  // Spoolman's extra value is JSON text: the quotes go, the date stays.
  assert(utc("\"2026-10-29T11:00:00Z\"") == "2026-10-29T11:00:00Z");

  // Spooly marks a spool never dried with the JSON text null (07.11.2026).
  // Shown as a date it read "null"; it means no date.
  assert(utc("null").empty());

  // Nothing stored, and the empty value the scale writes to clear one.
  assert(utc(nullptr).empty());
  assert(utc("").empty());
  assert(utc("\"\"").empty());

  // BamBuddy writes UTC without the Z; it gets one so the local day is right.
  assert(utc("2026-10-06T22:30:00") == "2026-10-06T22:30:00Z");

  // A zone that is named stays as it is, and so does a bare date.
  assert(utc("2026-10-06T22:30:00+02:00") == "2026-10-06T22:30:00+02:00");
  assert(utc("2026-10-06") == "2026-10-06");

  // A word that only starts like null is no empty value.
  assert(utc("nullx") == "nullx");
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

print("last dried: ok")
