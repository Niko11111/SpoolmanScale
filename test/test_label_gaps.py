"""Compile the production empty-field helper and check which switches print nothing."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/label_gaps.h"
#include <cassert>
#include <cstdio>

static uint32_t bit(LabelField f) { return 1u << f; }

int main() {
  // A spool with every value: nothing is empty.
  SpoolLabelData full{};
  snprintf(full.vendor, sizeof(full.vendor), "Bambu Lab");
  snprintf(full.material, sizeof(full.material), "PLA");
  snprintf(full.name, sizeof(full.name), "PLA Basic");
  snprintf(full.color, sizeof(full.color), "FFFFFF");
  snprintf(full.article, sizeof(full.article), "10100");
  snprintf(full.first_used, sizeof(full.first_used), "03.03.26");
  snprintf(full.added, sizeof(full.added), "01.03.26");
  snprintf(full.location, sizeof(full.location), "Shelf 2");
  snprintf(full.dried, sizeof(full.dried), "10.03.26");
  full.spool_weight_g = 250;
  full.net_weight_g = 1000;
  full.nozzle_max = 230;
  full.dry_temp_c = 55;
  full.dry_hours = 8;
  assert(labelEmptyFields(full, 0) == 0);

  // An empty spool: every fact field, never the id, the code, the brand or
  // the own line.
  const SpoolLabelData empty{};
  const uint32_t e = labelEmptyFields(empty, 0);
  assert(e & bit(LF_DRYING));
  assert(e & bit(LF_TEMPS));
  assert(e & bit(LF_LOCATION));
  assert(e & bit(LF_DATE));
  assert(!(e & bit(LF_SPOOL_ID)));
  assert(!(e & bit(LF_QR)));
  assert(!(e & bit(LF_BRAND)));
  assert(!(e & bit(LF_FREE_TEXT)));

  // Drying needs both numbers.
  SpoolLabelData half = full;
  half.dry_hours = 0;
  assert(labelEmptyFields(half, 0) == bit(LF_DRYING));

  // The date: the first use alone fills it, unless only the added date counts.
  SpoolLabelData first = full;
  first.added[0] = '\0';
  assert(labelEmptyFields(first, 0) == 0);
  assert(labelEmptyFields(first, 1u << LO_DATE_ADDED) == bit(LF_DATE));

  // Only FilaMan lacks a field outright, and only the temperatures.
  assert(labelBackendLacks(BACKEND_FILAMAN) == bit(LF_TEMPS));
  assert(labelBackendLacks(BACKEND_SPOOLMAN) == 0);
  assert(labelBackendLacks(BACKEND_BAMBUDDY) == 0);

  // The colour: a name alone fills it as well as the hex code.
  SpoolLabelData named = full;
  named.color[0] = '\0';
  assert(labelEmptyFields(named, 0) == bit(LF_COLOR));
  snprintf(named.color_name, sizeof(named.color_name), "Jade White");
  assert(labelEmptyFields(named, 1u << LO_COLOR_NAME) == 0);
  // Without the option the name is not printed: the line stays empty.
  assert(labelEmptyFields(named, 0) == bit(LF_COLOR));

  // Only BamBuddy and FilaMan name a colour; Spoolman keeps the hex code.
  assert(labelBackendHasColorName(BACKEND_BAMBUDDY));
  assert(labelBackendHasColorName(BACKEND_FILAMAN));
  assert(!labelBackendHasColorName(BACKEND_SPOOLMAN));
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    cpp.write_text(source)
    binary = Path(tmp) / "test"
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp),
                    str(root / "src/services/label_gaps.cpp"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("Label empty-field tests passed")
