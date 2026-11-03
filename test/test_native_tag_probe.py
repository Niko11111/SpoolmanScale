"""Compile the production reading of the native tag probe and check which
answers say yes, which say no and which say nothing, and what a link reports
after one that says nothing (services/native_tag_probe.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/native_tag_probe.h"
#include <cassert>

int main() {
  assert(nativeProbeAnswer(200) == NATIVE_PROBE_PRESENT);

  assert(nativeProbeAnswer(404) == NATIVE_PROBE_ABSENT);
  assert(nativeProbeAnswer(405) == NATIVE_PROBE_ABSENT);
  assert(nativeProbeAnswer(501) == NATIVE_PROBE_ABSENT);

  // A rate limit, a refused key, a server that is down, a timeout: no answer
  // about the feature. These must never send a link to an extra field.
  const int unsure[] = {429, 401, 403, 402, 500, 502, 503, 504, 204, 409, 0, -1, -11};
  for (int code : unsure) assert(nativeProbeAnswer(code) == NATIVE_PROBE_UNSURE);

  // The link reports the probe's code, so a server that is down is named so.
  assert(nativeProbeLinkCode(503) == 503);
  assert(nativeProbeLinkCode(429) == 429);
  assert(nativeProbeLinkCode(-11) == -11);

  // Not one that reads as something else from a link.
  assert(nativeProbeLinkCode(204) == NATIVE_PROBE_ODD_ANSWER);  // "linked"
  assert(nativeProbeLinkCode(409) == NATIVE_PROBE_ODD_ANSWER);  // "another spool holds it"
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
print("native tag probe: ok")
