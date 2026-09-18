#include "spool_color.h"

#include <stdio.h>
#include <string.h>

static int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Two hex digits into a byte, false when either is not one.
static bool hexByte(const char* p, uint8_t* out) {
  const int hi = hexNibble(p[0]);
  if (hi < 0) return false;
  const int lo = hexNibble(p[1]);
  if (lo < 0) return false;
  *out = (uint8_t)((hi << 4) | lo);
  return true;
}

bool spoolColorParse(const char* hex, SpoolColor* out) {
  if (!out) return false;
  *out = SpoolColor{};
  if (!hex) return false;
  const char* h = (hex[0] == '#') ? hex + 1 : hex;
  const size_t len = strlen(h);
  if (len != 6 && len != 8) return false;

  uint8_t r, g, b, a = SPOOL_ALPHA_OPAQUE;
  if (!hexByte(h, &r) || !hexByte(h + 2, &g) || !hexByte(h + 4, &b)) return false;
  if (len == 8 && !hexByte(h + 6, &a)) return false;

  *out = spoolColorFromRgba(r, g, b, a);
  return true;
}

SpoolColor spoolColorFromRgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
  SpoolColor c;
  c.rgb   = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
  c.alpha = a;
  c.valid = true;
  return c;
}

bool spoolColorSeeThrough(const SpoolColor& c) {
  return c.valid && c.alpha != SPOOL_ALPHA_OPAQUE;
}

bool spoolColorNamesHue(const SpoolColor& c) {
  return c.valid && !(c.rgb == 0 && c.alpha == SPOOL_ALPHA_CLEAR);
}

void spoolColorFormatBare(const SpoolColor& c, char* out, size_t out_size) {
  if (!out || !out_size) return;
  out[0] = '\0';
  if (!c.valid) return;
  if (c.alpha == SPOOL_ALPHA_OPAQUE) snprintf(out, out_size, "%06X", (unsigned)c.rgb);
  else snprintf(out, out_size, "%06X%02X", (unsigned)c.rgb, (unsigned)c.alpha);
}

void spoolColorFormat(const SpoolColor& c, char* out, size_t out_size) {
  if (!out || !out_size) return;
  out[0] = '\0';
  if (!c.valid || out_size < 2) return;
  out[0] = '#';
  spoolColorFormatBare(c, out + 1, out_size - 1);
}

SpoolColor spoolColorResolve(const SpoolColor& tag, const SpoolColor& server) {
  if (!tag.valid) return server;
  if (spoolColorNamesHue(tag)) return tag;
  if (!spoolColorNamesHue(server)) return tag;

  SpoolColor tinted = server;
  if (!spoolColorSeeThrough(server)) tinted.alpha = SPOOL_ALPHA_CLEAR;
  return tinted;
}
