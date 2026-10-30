"""Compile the production rule that writes material and filament name as one
line and read it back: nothing is said twice (services/text_util.cpp)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/text_util.h"
#include <cassert>
#include <cstring>

static const char* join(const char* material, const char* name) {
  static char out[96];
  joinMaterialName(material, name, out, sizeof(out));
  return out;
}

int main() {
  // The name opens with the material: as before.
  assert(strcmp(join("PETG", "PETG HF Orange"), "PETG HF Orange") == 0);
  // The material in the middle or at the end of the name, as a whole word.
  assert(strcmp(join("PLA", "Hyper PLA Gelb"), "Hyper PLA Gelb") == 0);
  assert(strcmp(join("PLA", "Silk PLA Weiss"), "Silk PLA Weiss") == 0);
  assert(strcmp(join("PLA", "High Speed Matte PLA"), "High Speed Matte PLA") == 0);
  assert(strcmp(join("PLA", "Basic PLA+ Rot"), "Basic PLA+ Rot") == 0);
  assert(strcmp(join("pla", "Hyper PLA-CF Schwarz"), "Hyper PLA-CF Schwarz") == 0);
  // Only whole words: PLA inside another word still gets the material.
  assert(strcmp(join("PLA", "Display Rot"), "PLA Display Rot") == 0);
  assert(strcmp(join("ABS", "Gelb"), "ABS Gelb") == 0);
  // A repeated subtype is written once.
  assert(strcmp(join("PLA Tough+", "Tough+ Cyan"), "PLA Tough+ Cyan") == 0);
  assert(strcmp(join("PETG Translucent", "Translucent Gray"), "PETG Translucent Gray") == 0);
  // Missing parts.
  assert(strcmp(join("PLA", ""), "PLA") == 0);
  assert(strcmp(join("", "Weiss"), "Weiss") == 0);
  assert(strcmp(join(nullptr, nullptr), "") == 0);
  // A cut never leaves half a character: "ü" is two bytes and does not fit.
  char small[9];
  joinMaterialName("PLA", "Grün", small, 8);   // "PLA Grü" needs 9 bytes
  assert(strcmp(small, "PLA Gr") == 0);
  joinMaterialName("PLA", "Grün", small, sizeof(small));
  assert(strcmp(small, "PLA Grü") == 0);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"),
                    str(cpp), str(root / "src" / "services" / "text_util.cpp"), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
print("join material name: ok")
