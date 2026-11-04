"""Compile the production rule for the name the scale gives a Spoolman server
and check what it sends (services/user_agent_rules.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/user_agent_rules.h"
#include <cassert>
#include <string>

static std::string agent(const char* version) {
  char out[USER_AGENT_LEN];
  userAgentFor(version, out, sizeof(out));
  return out;
}

int main() {
  // A beta and a release, without the leading v.
  assert(agent("v0.8.4-beta.54") == "SpoolmanScale/0.8.4-beta.54");
  assert(agent("v0.9.0") == "SpoolmanScale/0.9.0");

  // A version without the v stays as it is.
  assert(agent("0.9.0") == "SpoolmanScale/0.9.0");

  // The longest version the numbering can reach fits whole.
  assert(agent("v10.10.12-beta.99") == "SpoolmanScale/10.10.12-beta.99");
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    src = Path(tmp) / "t.cpp"
    exe = Path(tmp) / "t"
    src.write_text(source)
    subprocess.check_call(["c++", "-std=c++17", f"-I{root / 'src'}", str(src), "-o", str(exe)])
    subprocess.check_call([str(exe)])

print("user agent: ok")
