#include "tag_color_match.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "color_family.h"

// Redmean distance on a scale of 0..255, about one step of one channel per
// unit. Up to this the colours read as the same on a spool and on a screen;
// a first value, to be tuned on real tags against their makers' tables
// (Notes: NeuAusTag_Formate, Farbabgleich).
#define TCM_SURE_MAX_DIST   12
// A second entry of another name within this much of the best makes the
// match a guess between the two.
#define TCM_MARGIN_DIST     8
// The longest product line compared; FilamentDB slugs run to 24 bytes.
#define TCM_LINE_MAX        32

static bool rgbOf(const char* hex, int* r, int* g, int* b) {
  if (!hex) return false;
  if (*hex == '#') hex++;
  const size_t len = strlen(hex);
  // SpoolmanDB writes see-through as AARRGGBB: the colour is the last six.
  if (len == 8) hex += 2;
  else if (len != 6) return false;
  char part[3] = { 0, 0, 0 };
  int* out[3] = { r, g, b };
  for (int i = 0; i < 3; i++) {
    part[0] = hex[2 * i];
    part[1] = hex[2 * i + 1];
    char* end = nullptr;
    *out[i] = (int)strtol(part, &end, 16);
    if (end != part + 2) return false;
  }
  return true;
}

int tagColorDistance(const char* a, const char* b) {
  int r1, g1, b1, r2, g2, b2;
  if (!rgbOf(a, &r1, &g1, &b1) || !rgbOf(b, &r2, &g2, &b2)) return -1;
  const float rmean = (r1 + r2) / 2.0f;
  const float dr = (float)(r1 - r2), dg = (float)(g1 - g2), db = (float)(b1 - b2);
  const float d2 = (2.0f + rmean / 256.0f) * dr * dr + 4.0f * dg * dg +
                   (2.0f + (255.0f - rmean) / 256.0f) * db * db;
  // The weights add up to 9 at most: divided by 3, black to white is 255.
  return (int)lroundf(sqrtf(d2) / 3.0f);
}

// Lower case letters and digits only: "Snap-Speed" and "snapspeed" agree.
static void folded(const char* in, char* out, size_t out_size) {
  size_t o = 0;
  for (; in && *in && o + 1 < out_size; in++)
    if (isalnum((unsigned char)*in)) out[o++] = (char)tolower((unsigned char)*in);
  out[o] = '\0';
}

bool tagColorLineFits(const ColorCandidate& c, const char* line) {
  if (!line || !line[0]) return true;
  char want[TCM_LINE_MAX], have[TCM_LINE_MAX];
  folded(line, want, sizeof(want));
  if (!want[0]) return true;
  if (c.line && c.line[0]) {
    folded(c.line, have, sizeof(have));
    return strcmp(want, have) == 0;
  }
  // SpoolmanDB has no line: the name opens with it, "SnapSpeed Red".
  folded(c.name, have, sizeof(have));
  return strncmp(have, want, strlen(want)) == 0;
}

// Whether the candidate is one the tag could be at all. Not by colour family:
// the families meet at hard edges, and two pinks a step apart (F2B8C6 at
// 345.5 degrees, F4B9C8 at 344.8) fall into red and pink. The tight distance
// is what keeps a match honest.
static bool counts(const ColorQuery& q, const ColorCandidate& c) {
  if (c.ncolors != 1) return false;
  if (q.weight_g > 0 && c.weight_g > 0 && c.weight_g != q.weight_g) return false;
  return tagColorLineFits(c, q.line);
}

static void keepName(char* out, const char* name) {
  snprintf(out, TCM_NAME_MAX, "%s", name ? name : "");
}

void tagColorMatchBegin(ColorMatcher* mt, const ColorQuery& q) {
  memset(mt, 0, sizeof(*mt));
  mt->q = q;
  // A tag that names no hue (clear) has nothing to compare.
  mt->hue = colorFamilyOf(q.hex, 1) != CF_CLEAR;
  mt->m = { CMV_NONE, -1, -1, -1 };
  mt->second_dist = -1;
}

bool tagColorMatchAdd(ColorMatcher* mt, const ColorCandidate& c, int index) {
  if (!mt->hue || !counts(mt->q, c)) return false;
  const int d = tagColorDistance(mt->q.hex, c.hex);
  if (d < 0) return false;
  const char* name = c.name ? c.name : "";
  ColorMatch& m = mt->m;
  if (m.best < 0 || d < m.best_dist) {
    // The old best moves down, unless it is the same filament again (two
    // spool sizes listed apart).
    if (m.best >= 0 && strcmp(mt->best_name, name) != 0) {
      m.runner_up = m.best;
      mt->second_dist = m.best_dist;
      memcpy(mt->second_name, mt->best_name, TCM_NAME_MAX);
    }
    m.best = index;
    m.best_dist = d;
    keepName(mt->best_name, name);
    return true;
  }
  if (strcmp(mt->best_name, name) != 0 && (mt->second_dist < 0 || d < mt->second_dist)) {
    m.runner_up = index;
    mt->second_dist = d;
    keepName(mt->second_name, name);
  }
  return false;
}

ColorMatch tagColorMatchEnd(const ColorMatcher& mt) {
  ColorMatch m = mt.m;
  m.verdict = CMV_NONE;
  // Too far: the nearest stays named in best, for the log, but lends nothing.
  if (m.best < 0 || m.best_dist > TCM_SURE_MAX_DIST) return m;
  const bool rival = mt.second_dist >= 0 && mt.second_dist - m.best_dist < TCM_MARGIN_DIST;
  m.verdict = rival ? CMV_AMBIGUOUS : CMV_SURE;
  return m;
}

ColorMatch tagColorMatch(const ColorQuery& q, const ColorCandidate* c, int n) {
  ColorMatcher mt;
  tagColorMatchBegin(&mt, q);
  for (int i = 0; c && i < n; i++) tagColorMatchAdd(&mt, c[i], i);
  return tagColorMatchEnd(mt);
}

void tagColorMatchText(const ColorMatcher& mt, const ColorMatch& m, char* out, size_t out_size) {
  if (!out || !out_size) return;
  out[0] = '\0';
  if (m.best < 0) return;
  const char* hex = mt.q.hex ? mt.q.hex : "";
  if (*hex == '#') hex++;
  const char* verdict = m.verdict == CMV_SURE      ? "taken"
                      : m.verdict == CMV_AMBIGUOUS ? "too close to another, not taken"
                                                   : "too far, not taken";
  const int n = snprintf(out, out_size, "nearest colour to #%s is %s (distance %d), %s", hex,
                         mt.best_name, m.best_dist, verdict);
  if (m.verdict != CMV_AMBIGUOUS || n < 0 || (size_t)n >= out_size) return;
  snprintf(out + n, out_size - n, " - the other is %s", mt.second_name);
}
