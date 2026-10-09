#pragma once

#include <ArduinoJson.h>
#include <stdint.h>

// ============================================================
//  SPOOLMAN: THE FILAMENT DATABASE FOR THE PICKER
//
//  Fills services/filament_db.h from the database behind a server in
//  Spoolman mode, in whichever of the two forms of the inventory contract
//  (section 6.4) it offers:
//
//  - the Spoolman form, Spoolman 0.27 itself: no list of makers, only the
//    whole database (3 MB, 8120 filaments on 0.27.0) and a word search that
//    answers 100 at a time. The index reads the whole database once, element
//    by element, keeps only maker and material and lies in flash for a week;
//    a maker's list is a search for maker and material, filtered to exactly
//    those;
//  - the light form, a server with a catalogue of its own: a small index of
//    makers and materials with counts, and a complete list per maker and
//    material. Quick, so nothing is kept in flash.
//
//  Which one is probed once per backend generation, on the first call that
//  needs it. Runs on filament_db's task, through backend_api.h only; the
//  plan for a tag (spoolman_filament.cpp) asks the form and the light list
//  as well.
// ============================================================

// What the server offers. SM_FDB_UNKNOWN: it could not be asked yet, and is
// asked again on the next call.
enum SmFdbForm : uint8_t { SM_FDB_UNKNOWN = 0, SM_FDB_LIGHT, SM_FDB_SPOOLMAN, SM_FDB_NONE };
SmFdbForm spoolmanFdbForm(const char* base_url);
// The HTTP code the last probe got: 404 for a server without a database.
int spoolmanFdbProbeCode();

// Index: every maker and material of 1.75 mm, and which makers the inventory
// has. Returns the HTTP code.
int spoolmanFdbLoadIndex(const char* base_url);

// Every entry of one maker and material, 1.75 mm. Returns the HTTP code.
int spoolmanFdbLoadEntries(const char* base_url, const char* maker, const char* material);

// Light form only: every entry of one maker and material, each handed to fn
// as it is read, the list never held whole. Returns the HTTP code.
typedef void (*SpoolmanFdbEntryFn)(JsonObjectConst e, void* ctx);
int spoolmanFdbEachOf(const char* base_url, const char* maker, const char* material,
                      SpoolmanFdbEntryFn fn, void* ctx);
