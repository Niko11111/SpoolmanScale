#include "material_family.h"

#include <ctype.h>
#include <stddef.h>
#include <string.h>

// Longer names first where one is a prefix of another: PLA+ before PLA, PETG
// before nothing else that starts with PET.
static const MatFamily MAT_FAMILIES[] = {
  { "PETG", 230, 250, 70,  80,  1.27f },
  { "PLA+", 200, 220, 50,  60,  1.24f },
  { "PLA",  200, 220, 50,  60,  1.24f },
  { "ABS",  240, 260, 90, 100,  1.04f },
  { "ASA",  240, 260, 90, 100,  1.07f },
  { "TPU",  210, 230, 40,  50,  1.21f },
  { "TPE",  210, 230, 40,  50,  1.21f },
  { "HIPS", 230, 245, 90, 110,  1.04f },
  { "PVA",  190, 210, 50,  60,  1.23f },
  { "PC",   260, 280, 90, 110,  1.20f },
  { "PA",   250, 270, 60,  80,  1.14f },
  { "PP",   220, 240, 60,  80,  0.90f },
};

const MatFamily* matchFamily(const char* in) {
  if (!in || !in[0]) return nullptr;
  char up[40] = {0};
  for (size_t i = 0; i < sizeof(up) - 1 && in[i]; i++)
    up[i] = toupper((unsigned char)in[i]);

  for (unsigned i = 0; i < sizeof(MAT_FAMILIES) / sizeof(MAT_FAMILIES[0]); i++) {
    const char* fam = MAT_FAMILIES[i].name;
    const size_t n = strlen(fam);
    if (strncmp(up, fam, n) != 0) continue;
    const char c = up[n];
    // End of the name, or a separator - never another letter.
    if (c == '\0' || c == '-' || c == '+' || c == ' ' || c == '_' ||
        (c >= '0' && c <= '9'))
      return &MAT_FAMILIES[i];
  }
  return nullptr;
}
