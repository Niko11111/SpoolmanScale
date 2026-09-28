#pragma once

#include <stddef.h>

#include <ArduinoJson.h>

// ============================================================
//  THE DRYING A BAMBU TAG RECOMMENDS, KEPT IN THE BACKEND
//
//  Block 6 of a Bambu tag names the drying the maker recommends for the
//  filament: 55 °C for 8 h for PLA, 65 °C for PETG, 80 °C for 12 h for PA.
//  After a Bambu tag found its spool, the scale compares that with what the
//  backend holds and writes it where it differs or is missing: one text field
//  "drying" on the filament in Spoolman and FilaMan, a "[drying:...]" marker
//  in the spool's note on BamBuddy. One field, so temperature and time can
//  never disagree. Written once per filament and value in a session; a
//  failed write is not retried on every scan.
//
//  Nothing shows it yet (Nikolai, 28.09.2026): More Info has no room, the
//  label is to follow. dryingParse() is there for both.
// ============================================================

// "55 °C, 8 h"
void dryingFormat(int temp_c, int hours, char* out, size_t n);

// The first two numbers in the text, temperature and hours. False when there
// are not two plausible ones.
bool dryingParse(const char* text, int* temp_c, int* hours);

// After a lookup has the spool, on the loop task. Only parks the write.
void dryingSyncNote(JsonObjectConst spool);

// From appLoop(): carries a parked write out.
void dryingSyncTick();
