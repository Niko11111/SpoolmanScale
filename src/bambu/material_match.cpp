#include "material_match.h"

#include <Arduino.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "../bambu_blacklist.h"

bool extractBambuSubtype(const char* material, char* out_kw, size_t out_size) {
  if (!material || !material[0] || !out_kw || out_size == 0) return false;
  const char* sep = nullptr;
  for (const char* p = material; *p; p++) {
    if (*p == '-' || *p == ' ') {
      sep = p + 1;
      break;
    }
  }
  if (!sep || !*sep) return false;
  strncpy(out_kw, sep, out_size - 1);
  out_kw[out_size - 1] = '\0';
  int len = strlen(out_kw);
  while (len > 0 && out_kw[len - 1] == ' ') out_kw[--len] = '\0';
  if (len == 0) return false;

  for (int i = 0; BAMBU_PLA_SUBTYPE_BLACKLIST[i]; i++) {
    if (strcasecmp(out_kw, BAMBU_PLA_SUBTYPE_BLACKLIST[i]) == 0) return true;
  }
  return false;
}

bool isSupportMaterial(const char* material_filter) {
  return material_filter && strncasecmp(material_filter, "Support", 7) == 0;
}

bool isSupportSpoolmanMat(const char* mat) {
  if (!mat) return false;
  size_t len = strlen(mat);
  return len >= 2 && mat[len - 2] == '-' && (mat[len - 1] == 'S' || mat[len - 1] == 's');
}

bool containsIgnoreCase(const char* haystack, const char* needle) {
  if (!haystack || !needle || !needle[0]) return false;
  size_t nlen = strlen(needle);
  size_t hlen = strlen(haystack);
  if (nlen > hlen) return false;
  for (size_t i = 0; i <= hlen - nlen; i++) {
    if (strncasecmp(haystack + i, needle, nlen) == 0) return true;
  }
  return false;
}

int colorDistance(const char* hex_a, const char* hex_b) {
  if (!hex_a || strlen(hex_a) < 7 || hex_a[0] != '#') return 999;
  if (!hex_b || strlen(hex_b) < 7 || hex_b[0] != '#') return 999;
  unsigned int r1, g1, b1, r2, g2, b2;
  if (sscanf(hex_a + 1, "%02X%02X%02X", &r1, &g1, &b1) != 3) return 999;
  if (sscanf(hex_b + 1, "%02X%02X%02X", &r2, &g2, &b2) != 3) return 999;
  return (int)(abs((int)r1 - (int)r2) + abs((int)g1 - (int)g2) + abs((int)b1 - (int)b2));
}
