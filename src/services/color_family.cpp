#include "color_family.h"

#include <stdlib.h>
#include <string.h>

// Lightness and saturation in HLS, 0..1. Below the black line every hue
// looks black on a spool, above the white line with little saturation it
// looks white; below the grey saturation nothing reads as a hue.
#define CF_BLACK_MAX_L         0.15f
#define CF_WHITE_MIN_L         0.85f
#define CF_WHITE_MAX_S         0.50f
// A pale grey that is nearly white: little saturation, light.
#define CF_PALE_MAX_S          0.12f
#define CF_PALE_MIN_L          0.70f
#define CF_GREY_MAX_S          0.15f
// Brown is a dark orange: these hues, below this lightness.
#define CF_BROWN_MAX_L         0.45f
#define CF_BROWN_HUE_FROM_DEG  15.0f
#define CF_BROWN_HUE_TO_DEG    50.0f
// An alpha below this is mostly see-through. Without a hue that is a clear
// filament; with one ("Translucent Red", 3CD8100C in SpoolmanDB) it stays
// with its hue, where anyone holding the spool would look for it.
#define CF_CLEAR_MAX_ALPHA     0x80

// Where each hue ends, in degrees, going round the circle from red.
struct HueBand { float to_deg; ColorFamily family; };
static const HueBand HUE_BANDS[] = {
  {  15.0f, CF_RED },
  {  45.0f, CF_ORANGE },
  {  70.0f, CF_YELLOW },
  { 165.0f, CF_GREEN },
  { 250.0f, CF_BLUE },
  { 290.0f, CF_PURPLE },
  { 345.0f, CF_PINK },
  { 361.0f, CF_RED },
};

static int hexPair(const char* p) {
  char pair[3] = { p[0], p[1], '\0' };
  char* end = nullptr;
  const long v = strtol(pair, &end, 16);
  return (end == pair + 2) ? (int)v : -1;
}

static float maxOf(float a, float b, float c) { return a > b ? (a > c ? a : c) : (b > c ? b : c); }
static float minOf(float a, float b, float c) { return a < b ? (a < c ? a : c) : (b < c ? b : c); }

// Hue in degrees, lightness and saturation as HLS has them.
static void toHls(float r, float g, float b, float* h, float* l, float* s) {
  const float hi = maxOf(r, g, b), lo = minOf(r, g, b), d = hi - lo;
  *l = (hi + lo) / 2.0f;
  *h = 0.0f;
  *s = 0.0f;
  if (d <= 0.0f) return;
  *s = *l <= 0.5f ? d / (hi + lo) : d / (2.0f - hi - lo);
  if (hi == r)      *h = (g - b) / d;
  else if (hi == g) *h = 2.0f + (b - r) / d;
  else              *h = 4.0f + (r - g) / d;
  *h *= 60.0f;
  if (*h < 0.0f) *h += 360.0f;
}

static ColorFamily familyOfHue(float h, float l) {
  if (l < CF_BROWN_MAX_L && h >= CF_BROWN_HUE_FROM_DEG && h < CF_BROWN_HUE_TO_DEG) return CF_BROWN;
  for (const HueBand& band : HUE_BANDS)
    if (h < band.to_deg) return band.family;
  return CF_RED;
}

ColorFamily colorFamilyOf(const char* hex, uint8_t ncolors) {
  if (ncolors > 1) return CF_MULTI;
  if (!hex) return CF_CLEAR;
  if (*hex == '#') hex++;
  const size_t len = strlen(hex);
  if (len != 6 && len != 8) return CF_CLEAR;
  const int r = hexPair(hex), g = hexPair(hex + 2), b = hexPair(hex + 4);
  if (r < 0 || g < 0 || b < 0) return CF_CLEAR;
  const bool see_through = len == 8 && hexPair(hex + 6) < CF_CLEAR_MAX_ALPHA;

  float h, l, s;
  toHls(r / 255.0f, g / 255.0f, b / 255.0f, &h, &l, &s);
  ColorFamily f;
  if (l < CF_BLACK_MAX_L) f = CF_BLACK;
  else if ((l > CF_WHITE_MIN_L && s < CF_WHITE_MAX_S) || (s < CF_PALE_MAX_S && l > CF_PALE_MIN_L))
    f = CF_WHITE;
  else if (s < CF_GREY_MAX_S) f = CF_GREY;
  else return familyOfHue(h, l);
  return see_through ? CF_CLEAR : f;
}

// The scale of colorFamilyTypicality().
#define CF_TYPICAL_MAX  1000

int colorFamilyTypicality(const char* hex, ColorFamily family) {
  if (!hex) return 0;
  if (*hex == '#') hex++;
  if (strlen(hex) < 6) return 0;
  const int r = hexPair(hex), g = hexPair(hex + 2), b = hexPair(hex + 4);
  if (r < 0 || g < 0 || b < 0) return 0;
  float h, l, s;
  toHls(r / 255.0f, g / 255.0f, b / 255.0f, &h, &l, &s);
  float score;
  switch (family) {
    case CF_BLACK: score = 1.0f - l; break;
    case CF_WHITE: case CF_CLEAR: score = l; break;
    case CF_GREY:  score = 1.0f - s; break;
    // A strong hue at middle lightness: neither washed out nor nearly black.
    default:       score = s * (1.0f - 2.0f * (l > 0.5f ? l - 0.5f : 0.5f - l)); break;
  }
  return (int)(score * CF_TYPICAL_MAX);
}
