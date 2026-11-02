#pragma once

#include <stddef.h>

// ============================================================
//  WHAT A FILAMENT'S DRYING AND TEMPERATURE FIELDS MAY HOLD
//
//  The rules alone, no network and no JSON, so a host test can run them.
//  One text field "55 °C, 8 h" on Spoolman and on FilaMan before 2.0, two
//  numbers from FilaMan 2.0 on (drying_sync.h).
// ============================================================

// Where a mapped filament carries DRYING_NATIVE_KEY, the server has FilaMan
// 2.0's two fields: the object holds the ones already set, under these names.
#define DRYING_NATIVE_KEY    "drying_native"
#define DRYING_NATIVE_TEMP   "temp_c"
#define DRYING_NATIVE_HOURS  "hours"

// What a write fills in FilaMan's two native drying fields; 0 leaves one alone.
struct DryingFill {
  int temp_c;
  int hours;
};

// "55 °C, 8 h"
void dryingFormat(int temp_c, int hours, char* out, size_t n);

// The first two numbers in the text, temperature and hours. False when there
// are not two plausible ones.
bool dryingParse(const char* text, int* temp_c, int* hours);

// The two native numbers as the one text every reader of the drying knows.
// False when one of them says nothing. Whole numbers: a fraction would read
// as a third number to dryingParse().
bool dryingTextFromNumbers(float temp_c, float hours, char* out, size_t n);

// What a tag's advice fills: only a field that is empty, a value already there
// may be somebody's own.
DryingFill dryingFillEmpty(bool has_temp, bool has_hours, int tag_temp_c, int tag_hours);

// The same for the text an earlier scan left in custom_fields, which moves into
// the fields FilaMan 2.0 shows. It wins over the tag, it may be somebody's own.
// A text the parse cannot read fills nothing.
DryingFill dryingFillFromText(bool has_temp, bool has_hours, const char* text);

// Whether FilaMan 2.0 takes this nozzle range. It refuses the whole filament
// for one that runs backwards, and a tag can carry that. 0 means not known.
bool nozzleRangeAccepted(int temp_min, int temp_max);
