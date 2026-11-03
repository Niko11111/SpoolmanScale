"""Compile the production access stamp and read back when two sets of access
count as the same and when as different: new access to the same address is
what lets go of the old account's spools (services/access_stamp.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/access_stamp.h"
#include <cassert>

int main() {
  const uint32_t key_a = accessStamp(true, 1, "", "key-a");

  // The same access is the same number: saving it again resets nothing.
  assert(accessStamp(true, 1, "", "key-a") == key_a);

  // Another key, another way of sending it, another user.
  assert(accessStamp(true, 1, "", "key-b") != key_a);
  assert(accessStamp(true, 2, "", "key-a") != key_a);
  assert(accessStamp(true, 3, "ann", "pw") != accessStamp(true, 3, "bob", "pw"));

  // User and secret stay apart: "ab" + "c" is not "a" + "bc".
  assert(accessStamp(true, 3, "ab", "c") != accessStamp(true, 3, "a", "bc"));

  // Nothing sent is one state, whatever is stored for another address.
  assert(accessStamp(false, 1, "", "key-a") == 0);
  assert(accessStamp(false, 2, "x", "key-b") == 0);
  assert(accessStamp(true, 1, "", "key-a") != accessStamp(false, 1, "", "key-a"));

  // Absent text reads as empty.
  assert(accessStamp(true, 1, nullptr, nullptr) == accessStamp(true, 1, "", ""));
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
print("access stamp: ok")
