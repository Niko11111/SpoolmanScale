#include "services/label_digits.h"

#include "services/label_digits_data.h"

// More than any digit crosses on one row, an 8 at most 4.
#define LD_MAX_CROSSINGS 16

static const int LD_HEIGHT_UNITS = LD_Y_MAX - LD_Y_MIN;

static bool isDigit(char c) { return c >= '0' && c <= '9'; }

// The first ink to the last, in font units.
static int widthUnits(const char* digits) {
  int units = 0;
  const LabelDigitGlyph* last = nullptr;
  for (const char* p = digits; *p; p++) {
    if (!isDigit(*p)) continue;
    const LabelDigitGlyph& g = LD_GLYPHS[*p - '0'];
    units += last ? g.advance : g.advance - g.x_min;
    last = &g;
  }
  return last ? units - (last->advance - last->x_max) : 0;
}

int labelDigitsWidth(const char* digits, int height) {
  return (widthUnits(digits) * height + LD_HEIGHT_UNITS - 1) / LD_HEIGHT_UNITS;
}

int labelDigitsFitHeight(const char* digits, int max_w, int max_h) {
  const int units = widthUnits(digits);
  if (units <= 0 || max_w <= 0 || max_h <= 0) return 0;
  const int by_width = max_w * LD_HEIGHT_UNITS / units;
  return by_width < max_h ? by_width : max_h;
}

struct Crossing { float x; int dir; };

// Where the glyph's edges cross the font-unit height fy, sorted by x.
static int crossingsAt(const LabelDigitGlyph& g, float fy, Crossing* out) {
  int n = 0;
  for (int c = 0; c < g.contours; c++) {
    const int contour = g.first_contour + c;
    const int first = contour == g.first_contour ? g.first_point : LD_CONTOUR_ENDS[contour - 1];
    const int end = LD_CONTOUR_ENDS[contour];
    for (int i = first; i < end; i++) {
      const int16_t* a = LD_POINTS[i];
      const int16_t* b = LD_POINTS[i + 1 < end ? i + 1 : first];
      if ((a[1] <= fy) == (b[1] <= fy) || n >= LD_MAX_CROSSINGS) continue;
      const float x = a[0] + (fy - a[1]) * (b[0] - a[0]) / (float)(b[1] - a[1]);
      int at = n++;
      for (; at > 0 && out[at - 1].x > x; at--) out[at] = out[at - 1];
      out[at] = Crossing{ x, b[1] > a[1] ? 1 : -1 };
    }
  }
  return n;
}

struct DrawJob { LabelDigitRun run; void* ctx; float dots_per_unit; };

// One glyph's ink on one row of dots, by the non-zero winding rule. A dot is
// ink when its centre is. x0 is where the glyph's font-unit 0 falls.
static void drawRow(const DrawJob& job, const LabelDigitGlyph& g, float x0, int y, float fy) {
  Crossing crossings[LD_MAX_CROSSINGS];
  const int n = crossingsAt(g, fy, crossings);
  int winding = 0;
  for (int i = 0; i + 1 < n; i++) {
    winding += crossings[i].dir;
    if (winding == 0) continue;
    const int from = (int)(x0 + crossings[i].x * job.dots_per_unit + 0.5f);
    const int to = (int)(x0 + crossings[i + 1].x * job.dots_per_unit + 0.5f);
    if (to > from) job.run(from, y, to - from, job.ctx);
  }
}

void labelDigitsDraw(const char* digits, const LabelDigitsAt& at, LabelDigitRun run, void* ctx) {
  if (at.height <= 0 || !run) return;
  const DrawJob job{ run, ctx, at.height / (float)LD_HEIGHT_UNITS };
  for (int row = 0; row < at.height; row++) {
    const float fy = LD_Y_MAX - (row + 0.5f) / job.dots_per_unit;
    float pen = 0;
    bool first = true;
    for (const char* p = digits; *p; p++) {
      if (!isDigit(*p)) continue;
      const LabelDigitGlyph& g = LD_GLYPHS[*p - '0'];
      if (first) pen = -g.x_min;
      first = false;
      drawRow(job, g, at.x + pen * job.dots_per_unit, at.y + row, fy);
      pen += g.advance;
    }
  }
}
