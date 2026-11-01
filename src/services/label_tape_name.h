#pragma once

#include <stddef.h>

// ============================================================
//  THE MAKER AS A TAPE LABEL WRITES IT
//
//  A 12 mm tape has room for a short maker's name only. A known
//  long one goes on in the form its owners write by hand
//  ("Bambu Lab" is "BL"); every other name stays as it is and
//  the renderer fits or cuts it. Pure: no LVGL, no Arduino.
// ============================================================

// The short form of a known long name, matched whole and ignoring case,
// else the name as it is. Cut to the buffer like snprintf(); empty for a
// null or empty name.
void labelTapeVendor(const char* vendor, char* out, size_t n);
