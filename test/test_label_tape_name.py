"""Compile the production tape maker-name helper and check the short forms."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/label_tape_name.h"
#include <cassert>
#include <cstring>

static bool is(const char* in, const char* want, size_t n = 48) {
  char out[48];
  labelTapeVendor(in, out, n);
  return strcmp(out, want) == 0;
}

int main() {
  // The known long names, in the spellings backends hand over.
  assert(is("Bambu Lab", "BL"));
  assert(is("bambu lab", "BL"));
  assert(is("BAMBU LAB", "BL"));
  assert(is("BambuLab", "BL"));
  assert(is("Bambu", "BL"));

  // Whole names only: a longer one that merely starts the same stays.
  assert(is("Bambu Lab Inc", "Bambu Lab Inc"));
  assert(is("Bambu Lab PLA", "Bambu Lab PLA"));

  // Every other maker stays as written.
  assert(is("Sunlu", "Sunlu"));
  assert(is("eSun", "eSun"));
  assert(is("Elegoo", "Elegoo"));

  // Nothing in, nothing out; a short buffer cuts and terminates.
  assert(is("", ""));
  assert(is(nullptr, ""));
  assert(is("Elegoo", "Ele", 4));
  char one[1] = { 'x' };
  labelTapeVendor("Sunlu", one, 1);
  assert(one[0] == '\0');
  labelTapeVendor("Sunlu", nullptr, 8);   // no buffer: no write, no crash
  return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    cpp.write_text(source)
    binary = Path(tmp) / "test"
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp),
                    str(root / "src/services/label_tape_name.cpp"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("Label tape name tests passed")
