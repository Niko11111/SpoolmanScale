#pragma once

#include <stdint.h>

// Textbook print temperatures and a density per material family. Two users:
// a tag the scale writes for a spool whose backend names no temperature
// (services/tag_write.cpp), and the main screen, which shows the family's
// range as a guide value "~200 - 220 °C" when neither the backend nor the tag
// carries one (ui/main_screen_helpers.cpp). Pure logic, no Arduino, so
// test/test_spool_temp.py can hold it.
struct MatFamily {
  const char* name;
  uint16_t    et_lo, et_hi, bed_lo, bed_hi;
  float       density;
};

// The family a material name begins with, or null when none of them fits.
//
// A prefix, and it has to end at a boundary: "PC-CF" is PC, "PCTG" is not - it
// is a copolyester that would print 60 degrees too hot on PC settings. This is
// also why an unmatched name gets no temperatures at all rather than PLA's:
// before this, every material outside the list was written to the tag as "PLA"
// at 200-220 C, which is what a TPE spool on this scale did.
const MatFamily* matchFamily(const char* material);
