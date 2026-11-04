"""Compile the production digit drawing and check the number a label prints in large."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r'''
#include "services/label_digits.h"
#include "services/label_layout.h"
#include <cassert>
#include <cstring>
#include <initializer_list>

static const int W = 400, H = 300;
static bool ink[H][W];

static void mark(int x, int y, int w, void*) {
  for (int i = 0; i < w; i++) {
    assert(x + i >= 0 && x + i < W && y >= 0 && y < H);
    ink[y][x + i] = true;
  }
}

static void draw(const char* digits, int height) {
  memset(ink, 0, sizeof(ink));
  labelDigitsDraw(digits, LabelDigitsAt{ 10, 10, height }, mark, nullptr);
}

// The white islands the ink closes in: how a person tells a 0 from an 8.
static int holes() {
  static bool seen[H][W];
  memset(seen, 0, sizeof(seen));
  static int stack[W * H];
  int regions = 0;
  for (int y = 0; y < H; y++)
    for (int x = 0; x < W; x++) {
      if (ink[y][x] || seen[y][x]) continue;
      regions++;
      int top = 0;
      stack[top++] = y * W + x;
      seen[y][x] = true;
      while (top) {
        const int at = stack[--top], cy = at / W, cx = at % W;
        const int ny[] = { cy - 1, cy + 1, cy, cy }, nx[] = { cx, cx, cx - 1, cx + 1 };
        for (int i = 0; i < 4; i++) {
          if (ny[i] < 0 || ny[i] >= H || nx[i] < 0 || nx[i] >= W) continue;
          if (ink[ny[i]][nx[i]] || seen[ny[i]][nx[i]]) continue;
          seen[ny[i]][nx[i]] = true;
          stack[top++] = ny[i] * W + nx[i];
        }
      }
    }
  return regions - 1;   // the one outside
}

int main() {
  // Montserrat's 4 is open at the top.
  const int want[10] = { 1, 0, 0, 0, 0, 0, 1, 0, 2, 1 };
  for (int d = 0; d < 10; d++) {
    const char s[2] = { (char)('0' + d), 0 };
    for (int height : { 40, 120, 280 }) {
      draw(s, height);
      assert(holes() == want[d]);
      // The ink reaches the height it was asked for, and stays within it.
      int top = H, bottom = -1, right = -1;
      for (int y = 0; y < H; y++)
        for (int x = 0; x < W; x++)
          if (ink[y][x]) {
            if (y < top) top = y;
            if (y > bottom) bottom = y;
            if (x > right) right = x;
          }
      assert(top >= 10 && bottom < 10 + height);
      assert(bottom - top + 1 >= height * 95 / 100);
      assert(right < 10 + labelDigitsWidth(s, height) + 1);
    }
  }
  // Wider numbers come out lower: the width decides.
  assert(labelDigitsFitHeight("68", 304, 1000) > labelDigitsFitHeight("268", 304, 1000));
  assert(labelDigitsFitHeight("268", 304, 1000) > labelDigitsFitHeight("1268", 304, 1000));
  // Whatever fits is no wider than asked, and the height cap holds.
  for (const char* s : { "1", "68", "268", "1268", "88888" }) {
    const int h = labelDigitsFitHeight(s, 304, 1000);
    assert(h > 0 && labelDigitsWidth(s, h) <= 305);
  }
  assert(labelDigitsFitHeight("1", 304, 100) == 100);
  // The share: unset means the arrangement's own, a set one stays in its range.
  assert(labelIdShareFor(0, LABEL_PRESET_BIG_ID) == LABEL_ID_SHARE_TOP);
  assert(labelIdShareFor(0, LABEL_PRESET_BIG_ID_SIDE) == LABEL_ID_SHARE_SIDE);
  assert(labelIdShareFor(45, LABEL_PRESET_BIG_ID_SIDE) == 45);
  assert(labelIdShareFor(1, LABEL_PRESET_BIG_ID) == LABEL_ID_SHARE_MIN);
  assert(labelIdShareFor(255, LABEL_PRESET_BIG_ID) == LABEL_ID_SHARE_MAX);
  assert(labelPresetIsBigId(LABEL_PRESET_BIG_ID) && labelPresetIsBigId(LABEL_PRESET_BIG_ID_SIDE));
  assert(!labelPresetIsBigId(LABEL_PRESET_TEXT_ONLY));
  // Nothing to draw: nothing fits, nothing is drawn, and no crash.
  assert(labelDigitsFitHeight("", 304, 100) == 0);
  assert(labelDigitsFitHeight("x", 304, 100) == 0);
  assert(labelDigitsFitHeight("68", 0, 100) == 0);
  assert(labelDigitsWidth("", 100) == 0);
  draw("", 100);
  assert(holes() == 0);
  labelDigitsDraw("68", LabelDigitsAt{ 0, 0, 0 }, mark, nullptr);
  labelDigitsDraw("68", LabelDigitsAt{ 0, 0, 100 }, nullptr, nullptr);
  return 0;
}
'''

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"), str(cpp),
                    str(root / "src/services/label_digits.cpp"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("label digits: ok")
