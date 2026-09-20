#pragma once

#include <ArduinoJson.h>
#include <stdint.h>
#include <time.h>

#include "services/backend_api.h"   // InventoryStamp

// ============================================================
//  THE SPOOL LIST, KEPT BETWEEN TWO LINKS
//
//  Linking a library for the first time fetched the whole inventory once per
//  spool: 176 kB and a second or more of a screen that does not answer, fifty
//  times over for fifty spools. This keeps the active list in PSRAM and hands
//  it back in the JSON shape the download would have had, so the link flow's
//  filter reads it without knowing the difference.
//
//  What it is for, and what it is not:
//
//  - It decides what a list SHOWS, never what is WRITTEN. A row that came
//    from here is read from the server again before a dialog describes it or
//    a PATCH touches it - that is the link flow's job, not this module's.
//  - It holds the unfiltered active list. The filter depends on the tag on
//    the pad, so only the raw material can be kept.
//  - A use has to be proven. backendInventoryStamp() says how many spools
//    there are and names one witness among them; a copy whose stamp no longer
//    matches is thrown away. Where the backend has no stamp the copy is blind
//    and lives two minutes instead of thirty.
//  - The stamp proves the set, not the content: a weight written elsewhere
//    moves neither number. Hence the ceiling on the age, stamp or not.
//
//  One task reads and frees the rows: the loop. spoolCacheForget() only sets
//  a flag, so it may be called from anywhere - a web job, the drying worker,
//  one day a push from the server.
//
//  No LVGL in here.
// ============================================================

// Thirty minutes from the download, however often the stamp agreed since.
#define SPOOL_CACHE_MAX_AGE_MS  1800000UL
// Without a stamp there is no proof, only the hope that little changes in
// two minutes.
#define SPOOL_CACHE_BLIND_MS     120000UL
// Above this nothing is kept. A list cut short would hide spools, and that is
// the one mistake this module must not make.
#define SPOOL_CACHE_MAX            1000

// What "bound to a tag" means is the link flow's rule and stays there; it is
// handed in, so that there is one version of it.
typedef bool (*SpoolBoundFn)(JsonObjectConst spool);

// Takes a copy of a freshly downloaded active list. `stamp` is the one the
// caller took BEFORE the download, never after: taken after, a spool added in
// between would be vouched for by a stamp whose list does not have it, and
// stay hidden until the ceiling. nullptr for a backend without one.
// Archived rows are left out. Call from the loop task only.
void spoolCacheFill(JsonArrayConst spools, SpoolBoundFn is_bound,
                    const InventoryStamp* stamp);

// Whether the copy may be used right now: same server and backend, not
// forgotten, young enough, and the stamp the caller just took equal to the
// one it was filled under. A copy filled with a stamp is not served without
// one and the other way round - one failed stamp request must not turn a
// proven copy into a blind one. Loop task only.
bool spoolCacheUsable(const InventoryStamp* stamp);

// Writes the rows into `doc` as the array of spools the download would have
// produced. A bound spool gets `bound_key` in its extra block with a
// placeholder, so the link flow's own test answers as it did for the
// original. The placeholder is not a tag and must never reach a write.
// False when there is nothing to serve or the document ran out of memory.
// Loop task only.
bool spoolCacheToJson(JsonDocument& doc, const char* bound_key);

// After a write that changed one spool, so the next list shows it without a
// download. Does nothing for an id that is not in the copy. Loop task only.
void spoolCacheSetBound(int spool_id, bool bound);
void spoolCacheSetRemaining(int spool_id, float remaining);

// Marks the copy as worthless. Only a flag: the rows are freed by the loop on
// its next pass, so this is safe from any task. `why` goes into the log line
// of the drop and has to be a string literal - only the pointer is kept.
void spoolCacheForget(const char* why = nullptr);

// Once per loop pass. Frees the rows once they are forgotten or too old, so
// forty kilobytes do not sit in PSRAM for days after one afternoon of linking.
void spoolCacheTick();

// For the log and the status line. 0 when there is no copy.
int      spoolCacheRows();
uint32_t spoolCacheAgeMs();
// Wall clock of the download, 0 when the clock was not set at the time.
time_t   spoolCacheFilledAt();
