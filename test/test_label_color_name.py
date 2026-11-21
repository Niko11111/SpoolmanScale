"""Compile the production colour name cut and check it on real names (services/text_util.cpp).

With the colour printed as its name, the label takes the name off the end of
the title. A miss keeps the title whole and prints the name twice; a false
hit would cut words that are not the colour, which these cases rule out.
"""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/text_util.h"
#include <cassert>
#include <string>

// The title as the label prints it.
static std::string kept(const char* name, const char* color) {
  return std::string(name, nameColorNameCut(name, color));
}

int main() {
  // BamBuddy: the scale joins material, subtype and colour name into the
  // title, the colour last (bambuddy_api.cpp, mapSpool). Issue #94's spool:
  assert(kept("PLA+ High Flow Fire Engine Red", "Fire Engine Red") == "PLA+ High Flow");
  // The shapes read from real inventories, as the join leaves them.
  assert(kept("PLA Matt Ozean", "Matt Ozean") == "PLA");
  assert(kept("PLA Tough+ White", "Tough+ White") == "PLA");
  assert(kept("PLA Basic Jade White", "Jade White") == "PLA Basic");
  // A "+" before the colour is the material's: "PLA+ Red" keeps "PLA+".
  assert(kept("PLA+ Red", "Red") == "PLA+");
  // A title that is nothing but the colour stays: a label without a title
  // would say less than one with the colour twice.
  assert(kept("ASA Jet Black", "ASA Jet Black") == "ASA Jet Black");
  assert(kept("Black", "Black") == "Black");
  // No colour name, or no title: nothing comes off.
  assert(kept("PLA+ High Flow", "") == "PLA+ High Flow");
  assert(kept("", "Black") == "");
  assert(nameColorNameCut(nullptr, "Black") == 0);
  assert(kept("PLA Black", nullptr) == "PLA Black");

  // FilaMan: the designation is the user's; the colour name comes on its own.
  // Designations from a live instance (18.11.2026):
  assert(kept("PETG HF Cream", "HF Cream") == "PETG");
  assert(kept("Matte - Charcoal (11101)", "Charcoal (11101)") == "Matte");
  assert(kept("Matte - Charcoal (11101)", "Charcoal") == "Matte");
  // A colour name shorter than the article number after it (review 20.11.2026):
  // "10200)" reads longer than "Red", the start before it shorter again.
  assert(kept("PLA Red (10200)", "Red") == "PLA");
  assert(kept("PLA Matte Cyan (12601)", "Cyan") == "PLA Matte");
  // An en dash before the colour goes with it, as a hyphen does.
  assert(kept("Matte \xe2\x80\x93 Red", "Red") == "Matte");
  // A rest without a word is no title: it stays whole.
  assert(kept("+Red", "Red") == "+Red");
  // A hex code in the name field is no name.
  assert(kept("Cyan (12601)", "009BD8") == "Cyan (12601)");

  // Case, accents and hyphens do not count.
  assert(kept("PLA Jade-White", "Jade White") == "PLA");
  assert(kept("PLA jade white", "Jade White") == "PLA");
  assert(kept("PLA Crème", "creme") == "PLA");
  assert(kept("PETG  Galaxy   Black ", "Galaxy Black") == "PETG");

  // Whole words only: "Black" is not the end of "Blackberry", nor "Red" of "Bored".
  assert(kept("PLA Blackberry", "Black") == "PLA Blackberry");
  assert(kept("PLA Bored", "Red") == "PLA Bored");
  // In the middle is not at the end: the name says something after it.
  assert(kept("Black PLA Matte", "Black") == "Black PLA Matte");
  // Another language is another word: both are printed, which is right.
  assert(kept("PLA Weiss", "White") == "PLA Weiss");
  // A colour name longer than the title cannot be its end.
  assert(kept("Red", "Fire Engine Red") == "Red");
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    cpp.write_text(source)
    binary = Path(tmp) / "test"
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp),
                    str(root / "src/services/text_util.cpp"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("Label colour name tests passed")
