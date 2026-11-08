#pragma once

#include <stddef.h>
#include <stdio.h>

// Which nozzle temperature the main screen shows once the backend has
// answered, which ends a written tag gets, and how a range reads. Pure logic:
// no Arduino, no JSON, so a host test can run it (test/test_spool_temp.py).
//
// People enter the temperature they want to print at in the backend, so its
// value always wins over the tag's, as BamBuddy itself lets a spool's own
// value win when it fills an AMS slot. A Bambu spool the scale created in
// Spoolman therefore reads "230 °C", not the tag's "190 - 230 °C": Spoolman
// holds one value, and the screen shows what the backend says.

// Above any filament's nozzle or bed: a larger value is a typo or a unit mix-up.
#define SPOOL_TEMP_MAX_C  500

// A temperature range in °C. hi is 0 when nothing is known, lo is 0 when only
// one value is known.
struct SpoolTempRange {
  int lo;
  int hi;
};

// A range from two raw values with nonsense dropped. An upper end outside
// 1..499 leaves the range empty; a lower end counts only below the upper one,
// so 240/240 is the single value 240.
inline SpoolTempRange spoolTempRange(int lo, int hi) {
  SpoolTempRange r = {0, 0};
  if (hi <= 0 || hi >= SPOOL_TEMP_MAX_C) return r;
  r.hi = hi;
  if (lo > 0 && lo < hi) r.lo = lo;
  return r;
}

// What the main screen shows: the backend's value, the tag's only when the
// backend has none.
inline SpoolTempRange spoolTempShown(SpoolTempRange backend, SpoolTempRange tag) {
  return backend.hi ? backend : tag;
}

// The two ends a tag gets: the backend's value where there is one, the
// material family's range otherwise. A single value is written as both ends,
// a tag format has no field for "one temperature".
inline SpoolTempRange spoolTempTagEnds(SpoolTempRange backend, SpoolTempRange family) {
  const SpoolTempRange r = backend.hi ? backend : family;
  const SpoolTempRange ends = {r.lo ? r.lo : r.hi, r.hi};
  return ends;
}

// "190 - 230 °C", "240 °C", or "" when nothing is known.
inline void spoolTempFormat(SpoolTempRange r, char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  out[0] = '\0';
  if (r.hi == 0) return;
  if (r.lo > 0) snprintf(out, out_size, "%d - %d °C", r.lo, r.hi);
  else          snprintf(out, out_size, "%d °C", r.hi);
}
