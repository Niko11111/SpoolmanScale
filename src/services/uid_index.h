#pragma once

#include <ArduinoJson.h>
#include <stdint.h>

#include "services/backend_api.h"   // InventoryStamp

// ============================================================
//  EVERY IDENTIFIER THE LAST FULL SCAN SAW
//
//  An unknown tag costs two downloads of the whole inventory before the scale
//  may say "not found": the active list and the pass over the archive, 2.2 to
//  6.6 s in which the touch panel is not read. The list cache cannot shorten
//  that, it keeps no identifiers on purpose. This keeps nothing but them: a
//  hash of every value in which the scan could have found a tag.
//
//  What it is for, and what it is not:
//
//  - It can only ever say "no spool held this when the scan ran". A spool is
//    never identified from here: weights are written back to an
//    identification, and that takes the server's own word.
//  - It has to be a SUPERSET of what spoolTagRank() in ui/spoolman_lookup.cpp
//    could accept, and it gets there by leaving rules out rather than copying
//    them: every tag of the native relation and every text value in `extra`,
//    whole and comma segment by comma segment, whatever the key is called.
//    An entry too many costs one real scan. An entry too few would call a
//    bound tag unknown and invite a second binding.
//  - The one rule it has is arithmetic, not judgement: every comparison over
//    there is equality of the hex digits, so a form shorter than a four byte
//    uid or longer than a tray uuid can equal no tag. Those are left out, and
//    whoever asks must not take an answer for a tag outside that range.
//  - Built from a complete scan only: the active list whole AND the archive
//    whole. Half a scan is no index.
//  - Short lived, two minutes from the scan, not sliding. The stamp proves
//    the set of spools, not what stands in their fields.
//
//  One task builds, reads and frees: the loop. uidIndexForget() only sets a
//  flag and is safe from anywhere; spoolCacheForget() passes every reason on,
//  so whatever drops the list drops this with it.
//
//  No LVGL in here.
// ============================================================

// From the scan that filled it, however often it was asked since.
#define UID_INDEX_MAX_AGE_MS   120000UL
// Above this there is no index. Forty bound spools come to about a hundred.
#define UID_INDEX_MAX_IDS        4096
// Hex digits of the shortest and the longest identifier a tag can have: a
// four byte uid and a Bambu tray uuid.
#define UID_INDEX_ID_MIN_HEX        8
#define UID_INDEX_ID_MAX_HEX       32

// Starts a new index and throws the old one away. Loop task only, like
// everything below except uidIndexForget().
void uidIndexBegin();

// Takes in every identifier of the spools in `spools`. With `archived_only`
// the active ones are passed over: the archive request answers with both, and
// the active ones went in from their own, fuller list. Does nothing unless
// uidIndexBegin() came first. A list that would go over UID_INDEX_MAX_IDS or
// finds no PSRAM ends the build, and nothing is kept.
void uidIndexAdd(JsonArrayConst spools, bool archived_only);

// The scan is complete, the index may answer from here on. `stamp` is the
// one taken BEFORE the active list was downloaded, nullptr for a backend
// without one. A stamp that counted a different number of active spools than
// went in vouches for some other set, and nothing is kept.
void uidIndexCommit(const InventoryStamp* stamp);

// Marks the index as worthless. Only a flag, freed by the loop. `why` has to
// be a string literal - only the pointer is kept.
void uidIndexForget(const char* why = nullptr);

// Once per loop pass: frees an index that was forgotten, grew too old, or was
// begun by a lookup that left before its scan was complete.
void uidIndexTick();
