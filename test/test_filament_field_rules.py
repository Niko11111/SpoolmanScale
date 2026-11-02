"""Compile the production rules for a filament's drying and temperature fields
and check the text they make and read, what a tag's advice may fill, and which
nozzle range FilaMan 2.0 takes (services/filament_field_rules.cpp)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/filament_field_rules.h"
#include <cassert>
#include <cstring>

int main() {
  char text[24];
  dryingFormat(55, 8, text, sizeof(text));
  assert(strcmp(text, "55 °C, 8 h") == 0);

  int temp = 0, hours = 0;
  assert(dryingParse("55 °C, 8 h", &temp, &hours) && temp == 55 && hours == 8);
  assert(!dryingParse("65 °C", &temp, &hours));
  assert(!dryingParse("no drying needed", &temp, &hours));
  assert(!dryingParse("500 °C, 8 h", &temp, &hours));
  assert(!dryingParse("55 °C, 0 h", &temp, &hours));
  assert(!dryingParse(nullptr, &temp, &hours));

  // FilaMan sends the two as floats, 55.0 and 8.0 on the live data.
  assert(dryingTextFromNumbers(55.0f, 8.0f, text, sizeof(text)));
  assert(strcmp(text, "55 °C, 8 h") == 0);
  assert(dryingParse(text, &temp, &hours) && temp == 55 && hours == 8);
  // A fraction must not read as a third number.
  assert(dryingTextFromNumbers(65.0f, 2.5f, text, sizeof(text)));
  assert(strcmp(text, "65 °C, 3 h") == 0);
  assert(!dryingTextFromNumbers(0.0f, 8.0f, text, sizeof(text)));
  assert(!dryingTextFromNumbers(55.0f, 0.0f, text, sizeof(text)));

  // Only what is empty is filled: 17 filaments on the live data have a time
  // and no temperature.
  DryingFill fill = dryingFillEmpty(false, false, 55, 8);
  assert(fill.temp_c == 55 && fill.hours == 8);
  fill = dryingFillEmpty(false, true, 55, 8);
  assert(fill.temp_c == 55 && fill.hours == 0);
  fill = dryingFillEmpty(true, false, 55, 8);
  assert(fill.temp_c == 0 && fill.hours == 8);
  fill = dryingFillEmpty(true, true, 55, 8);
  assert(fill.temp_c == 0 && fill.hours == 0);

  assert(nozzleRangeAccepted(190, 230));
  assert(nozzleRangeAccepted(220, 220));
  assert(nozzleRangeAccepted(190, 0));
  assert(nozzleRangeAccepted(0, 230));
  assert(!nozzleRangeAccepted(240, 200));
  assert(!nozzleRangeAccepted(0, 0));
  return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    main = Path(tmp) / 'main.cpp'
    binary = Path(tmp) / 'test'
    main.write_text(source)
    subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', f'-I{root / "src"}', str(main),
                    str(root / 'src/services/filament_field_rules.cpp'), '-o', str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)
print('filament field rules ok')
