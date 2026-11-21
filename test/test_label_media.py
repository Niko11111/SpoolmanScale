"""Compile the production label size rules and check which sizes print, checked or not."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/label_media.h"
#include <cassert>

int main() {
  // The M220: 20 to 75 mm across, 10 to 150 along, 203 dpi, a 648 dot row.
  const LabelMediaRange m220{ 20, 75, 10, 150, 203, 648 };

  // The rolls printed on paper are checked, the others the printer takes are not.
  assert(labelMediaStatus(m220, 40, 30) == LABEL_MEDIA_CHECKED);
  assert(labelMediaStatus(m220, 50, 30) == LABEL_MEDIA_CHECKED);
  assert(labelMediaStatus(m220, 60, 30) == LABEL_MEDIA_CHECKED);
  assert(labelMediaStatus(m220, 60, 40) == LABEL_MEDIA_UNCHECKED);
  assert(labelMediaStatus(m220, 50, 50) == LABEL_MEDIA_UNCHECKED);
  // Width and length swapped are another label: 30 x 40 is not 40 x 30.
  assert(labelMediaStatus(m220, 30, 40) == LABEL_MEDIA_UNCHECKED);

  // Outside the profile, at both ends and in both directions.
  assert(labelMediaStatus(m220, 19, 30) == LABEL_MEDIA_OUT_OF_RANGE);
  assert(labelMediaStatus(m220, 76, 30) == LABEL_MEDIA_OUT_OF_RANGE);
  assert(labelMediaStatus(m220, 40, 9) == LABEL_MEDIA_OUT_OF_RANGE);
  assert(labelMediaStatus(m220, 40, 151) == LABEL_MEDIA_OUT_OF_RANGE);
  assert(labelMediaStatus(m220, 20, 10) != LABEL_MEDIA_OUT_OF_RANGE);

  // The canvas: 70 x 80 is 559 x 639 dots (203 dpi is a little under 8 dots
  // to the millimetre), 714,402 bytes, and prints.
  assert(labelMediaDots(203, 70) == 559 && labelMediaDots(203, 80) == 639);
  assert(labelMediaDots(203, 40) == 320);
  assert(labelMediaCanvasBytes(m220, 70, 80) == 559u * 639u * 2u);
  assert(labelMediaStatus(m220, 70, 80) == LABEL_MEDIA_UNCHECKED);
  // 75 x 150 is 599 x 1199 dots, 1.44 MB: more than a label may take.
  assert(labelMediaStatus(m220, 75, 150) == LABEL_MEDIA_TOO_LARGE);

  // A roll wider than the head prints the head's width: the PM245's 108 mm
  // head is 864 dots (108 mm is 863), and a 4 x 6 inch label is too large for the memory.
  const LabelMediaRange pm245{ 25, 108, 10, 150, 203, 864 };
  assert(labelMediaCanvasBytes(pm245, 108, 30) == 863u * 240u * 2u);
  const LabelMediaRange narrow{ 25, 108, 10, 150, 203, 400 };
  assert(labelMediaCanvasBytes(narrow, 108, 30) == 400u * 240u * 2u);
  assert(labelMediaStatus(pm245, 102, 152) == LABEL_MEDIA_OUT_OF_RANGE);
  assert(labelMediaStatus(pm245, 100, 150) == LABEL_MEDIA_TOO_LARGE);

  // A 300 dpi head: 50 x 30 is 591 x 354 dots.
  const LabelMediaRange m2{ 50, 50, 10, 150, 300, 568 };
  assert(labelMediaDots(300, 50) == 591);
  assert(labelMediaCanvasBytes(m2, 50, 30) == 568u * 354u * 2u);
  assert(labelMediaStatus(m2, 50, 30) == LABEL_MEDIA_CHECKED);
  assert(labelMediaStatus(m2, 40, 30) == LABEL_MEDIA_OUT_OF_RANGE);

  // No profile: nothing prints.
  const LabelMediaRange none{};
  assert(labelMediaStatus(none, 40, 30) == LABEL_MEDIA_OUT_OF_RANGE);

  // Every suggestion is a size nobody has checked yet, and known as one.
  for (int i = 0; i < LABEL_MEDIA_SUGGESTED_COUNT; i++) {
    const LabelMediaSize& s = LABEL_MEDIA_SUGGESTED[i];
    assert(!labelMediaChecked(s.width_mm, s.length_mm));
    assert(labelMediaSuggested(s.width_mm, s.length_mm));
  }
  assert(!labelMediaSuggested(40, 30));
  assert(labelMediaSuggested(60, 40) && !labelMediaSuggested(40, 60));
}
'''
with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    cpp.write_text(source)
    binary = Path(tmp) / "test"
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp),
                    str(root / "src/services/label_media.cpp"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("Label size tests passed")
