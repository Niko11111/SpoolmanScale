#pragma once

#include <stdint.h>

#include "tag_create.h"

// ============================================================
//  A TAG AND A DATABASE ENTRY FOR THE SAME FILAMENT
//
//  A tag's filament that the inventory does not have yet may still be in
//  the backend's filament database: the FilamentDB finds a Bambu spool by
//  its article number. The tag is trusted more than the entry - the
//  databases have errors (Bambu PLA Basic Black, 10101, stands at 220-220 °C
//  in the FilamentDB, the tag says 190-230) - so the entry only fills in
//  what the tag does not say, and where both say something and differ a
//  lot, the card asks which to keep. Pure logic: no network, no screen.
// ============================================================

// What counts as a large difference.
#define TAG_DB_NOZZLE_DIFF_C     15    // either end of the nozzle range
#define TAG_DB_COLOR_DIFF        48    // the largest of the three channels, 0-255
#define TAG_DB_WEIGHT_DIFF_PCT   10    // of the tag's net weight
#define TAG_DB_DIFFS_MAX          4

enum TagDbField : uint8_t { TDF_COLOR = 0, TDF_NOZZLE_MIN, TDF_NOZZLE_MAX, TDF_WEIGHT };

// One value tag and entry disagree on.
struct TagDbDiff {
  uint8_t field;       // TagDbField
  int     tag_value;   // °C or g; not used for the colour
  int     db_value;
  char    tag_hex[7];  // the colour only
  char    db_hex[7];
};

// The large differences, at most out_max. A gradient, dual colour or clear
// spool is not compared by colour: the FilamentDB keeps such a colour as
// one averaged value, which is no error.
int tagDbCompare(const TagCreateInput& in, const TagDbEntry& db, TagDbDiff* out, int out_max);

// Links the input to the entry (db_id and the database's spellings, so the
// create path and a later plan treat it as picked from the database), and
// fills in what the tag does not say: net weight, nozzle range, density,
// bed temperature. Leaves every value the tag has.
void tagDbFill(TagCreateInput* in, const TagDbEntry& db);

// Takes the entry's value for one difference, when the user chose it.
void tagDbTake(TagCreateInput* in, const TagDbDiff& diff);
