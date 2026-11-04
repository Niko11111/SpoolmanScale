"""Compile the production rule for the colour name a new spool gets behind
BamBuddy's Spoolman proxy and read it back: a tag's own name, else the
filament database entry's, else none (services/tag_create.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/tag_create.h"
#include <cassert>
#include <cstdio>
#include <cstring>

int main() {
  TagCreateInput in{};
  // Nothing known: no colour name, and no garbage either.
  assert(strcmp(tagCreateSpoolColorName(in), "") == 0);

  // Picked from the filament database: the tag part is empty, the entry's
  // name is all there is. This is the spool that used to arrive without one.
  snprintf(in.db_color_name, sizeof(in.db_color_name), "%s", "Rapid-Eco Dark Green");
  assert(strcmp(tagCreateSpoolColorName(in), "Rapid-Eco Dark Green") == 0);

  // A Bambu tag's name from the catalog wins over the database's.
  snprintf(in.color_name_en, sizeof(in.color_name_en), "%s", "Jade White");
  assert(strcmp(tagCreateSpoolColorName(in), "Jade White") == 0);

  // A tag's name alone stays as before.
  in.db_color_name[0] = '\0';
  assert(strcmp(tagCreateSpoolColorName(in), "Jade White") == 0);

  // A colour that opens with the product line: the line must not go in front
  // a second time, "Translucent Translucent Gray" stood in the inventory.
  snprintf(in.subtype, sizeof(in.subtype), "%s", "Translucent");
  snprintf(in.color_name_en, sizeof(in.color_name_en), "%s", "Translucent Gray");
  assert(tagCreateColorCarriesLine(in));
  snprintf(in.color_name_en, sizeof(in.color_name_en), "%s", "Translucent");
  assert(tagCreateColorCarriesLine(in));
  // The word has to end there, and a colour of its own stays apart from it.
  snprintf(in.color_name_en, sizeof(in.color_name_en), "%s", "Translucency Blue");
  assert(!tagCreateColorCarriesLine(in));
  snprintf(in.color_name_en, sizeof(in.color_name_en), "%s", "Jade White");
  assert(!tagCreateColorCarriesLine(in));
  in.subtype[0] = '\0';
  assert(!tagCreateColorCarriesLine(in));
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"),
                    str(cpp), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
print("tag colour name: ok")
