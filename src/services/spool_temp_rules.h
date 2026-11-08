#pragma once

#include <stddef.h>
#include <stdio.h>

// Which nozzle temperature the main screen shows once the backend has
// answered, which ends a written tag gets, and how a range reads. Pure logic:
// no Arduino, no JSON, so a host test can run it (test/test_spool_temp.py).
//
// People enter the temperature they want to print at in the backend, so its
// value wins over the tag's. The one exception is the scale's own echo: a
// spool created from a Bambu, Creality or Snapmaker tag carries the tag's
// upper end as its single backend value, and showing "230 °C" there would
// throw away the range "190 - 230 °C" the tag still holds.

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

// Whether the backend only repeats what the tag says: the same upper end, and
// no lower end of its own or the tag's.
inline bool spoolTempEchoesTag(SpoolTempRange backend, SpoolTempRange tag) {
  if (tag.hi == 0 || backend.hi != tag.hi) return false;
  return backend.lo == 0 || backend.lo == tag.lo;
}

// What the main screen shows: the backend's value, the tag's when the backend
// has none or only echoes the tag.
inline SpoolTempRange spoolTempShown(SpoolTempRange backend, SpoolTempRange tag) {
  if (backend.hi == 0 || spoolTempEchoesTag(backend, tag)) return tag;
  return backend;
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
