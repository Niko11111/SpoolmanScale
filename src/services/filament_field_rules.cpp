#include "services/filament_field_rules.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

// The same plausibility the tag decoder applies.
#define DRYING_TEMP_MIN_C     30
#define DRYING_TEMP_MAX_C     120
#define DRYING_HOURS_MAX      48

void dryingFormat(int temp_c, int hours, char* out, size_t n) {
  snprintf(out, n, "%d °C, %d h", temp_c, hours);
}

bool dryingParse(const char* text, int* temp_c, int* hours) {
  if (!text) return false;
  int vals[2];
  int found = 0;
  for (const char* p = text; *p && found < 2; ) {
    if (*p >= '0' && *p <= '9') {
      char* end = nullptr;
      vals[found++] = (int)strtol(p, &end, 10);
      p = end;
    } else {
      p++;
    }
  }
  if (found < 2) return false;
  if (vals[0] < DRYING_TEMP_MIN_C || vals[0] > DRYING_TEMP_MAX_C) return false;
  if (vals[1] < 1 || vals[1] > DRYING_HOURS_MAX) return false;
  if (temp_c) *temp_c = vals[0];
  if (hours)  *hours  = vals[1];
  return true;
}

bool dryingTextFromNumbers(float temp_c, float hours, char* out, size_t n) {
  const int whole_temp  = (int)lroundf(temp_c);
  const int whole_hours = (int)lroundf(hours);
  if (whole_temp <= 0 || whole_hours <= 0) return false;
  dryingFormat(whole_temp, whole_hours, out, n);
  return true;
}

DryingFill dryingFillEmpty(bool has_temp, bool has_hours, int tag_temp_c, int tag_hours) {
  return { has_temp ? 0 : tag_temp_c, has_hours ? 0 : tag_hours };
}

DryingFill dryingFillFromText(bool has_temp, bool has_hours, const char* text) {
  int temp_c = 0, hours = 0;
  if (!dryingParse(text, &temp_c, &hours)) return { 0, 0 };
  return dryingFillEmpty(has_temp, has_hours, temp_c, hours);
}

bool nozzleRangeAccepted(int temp_min, int temp_max) {
  if (temp_min <= 0 && temp_max <= 0) return false;
  return temp_min <= 0 || temp_max <= 0 || temp_min <= temp_max;
}
