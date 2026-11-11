"""Compile the production pacing of the AMS presence check and check how the
wait grows while an AMS source does not answer (services/ams_presence.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/ams_presence.h"
#include <cassert>

int main() {
  // Answered: the plain five minutes.
  assert(amsPresenceWaitMs(0) == AMS_PRESENCE_INTERVAL_MS);
  // Each pass in a row without an answer doubles the wait.
  assert(amsPresenceWaitMs(1) == 2 * AMS_PRESENCE_INTERVAL_MS);
  assert(amsPresenceWaitMs(2) == 4 * AMS_PRESENCE_INTERVAL_MS);
  assert(amsPresenceWaitMs(3) == 8 * AMS_PRESENCE_INTERVAL_MS);
  // Never longer than an hour, also for a count that would overflow a shift.
  assert(amsPresenceWaitMs(4) == AMS_PRESENCE_MAX_WAIT_MS);
  assert(amsPresenceWaitMs(40) == AMS_PRESENCE_MAX_WAIT_MS);
  assert(amsPresenceWaitMs(255) == AMS_PRESENCE_MAX_WAIT_MS);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", f"-I{root / 'src'}", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("AMS presence pace: ok")
