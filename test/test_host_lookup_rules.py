"""Compile the production rule for names that failed to resolve and check
that a failed name is refused at once, and looked up again only in the
background and only at its pace (services/host_lookup_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/host_lookup_rules.h"
#include <cassert>

int main() {
  // A name that never failed is looked up where it is asked for.
  assert(hostLookupStep(false, 0, false) == HOST_ASK);
  assert(hostLookupStep(false, 0, true) == HOST_ASK);

  // A failed name is refused at once, never looked up in the caller again.
  assert(hostLookupStep(true, 0, false) == HOST_REFUSE);
  assert(hostLookupStep(true, HOST_RECHECK_MS - 1, false) == HOST_REFUSE);

  // Once the pace has passed, a check starts in the background.
  assert(hostLookupStep(true, HOST_RECHECK_MS, false) == HOST_REFUSE_RECHECK);
  assert(hostLookupStep(true, 0xFFFFFFFFu, false) == HOST_REFUSE_RECHECK);

  // Never a second check beside one that runs.
  assert(hostLookupStep(true, HOST_RECHECK_MS, true) == HOST_REFUSE);

  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", f"-I{root / 'src'}", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("host lookup rules: ok")
