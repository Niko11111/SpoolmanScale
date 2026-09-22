#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

// ============================================================
//  BACKEND JOB
//
//  A whole inventory is the one backend request that takes long enough to
//  matter: 14 s on FilaMan, 51 s on BamBuddy, measured on 21.09.2026. Called
//  from the loop task it held everything for that long - touch, display,
//  scale, NFC - and the AMS or location question on screen could not be
//  answered while an unknown spool was being looked up.
//
//  This runs that request on its own task, the same shape as the web jobs
//  (core 0, below the loop in priority, stack from the heap for as long as
//  it runs). The loop starts it, keeps looping, and collects the list on a
//  later pass.
//
//  Rules, each with a reason:
//  - Nothing in here touches LVGL, NVS or the lookup's state. Progress is a
//    byte count the loop reads and paints.
//  - One list at a time, device wide. The web worker's spool list for the
//    tags page shares the lock: FilaMan's "partial" flag and BamBuddy's
//    inventory mode are statics of the backend layer, and two lists running
//    side by side would overwrite each other's.
//  - A result carries the backend generation it was started under (see
//    backendGeneration() in app/backend_switch.h). One from before a switch
//    of mode or host is about another server and must be dropped.
//  - The document belongs to this module until backendJobTake(). The loop
//    reads it in place, it is never copied: an inventory is 100 to 300 kB.
// ============================================================

enum BackendJobState : uint8_t {
  BJS_IDLE = 0,
  BJS_RUNNING,
  BJS_DONE
};

struct BackendListResult {
  int      code;        // HTTP code of the last attempt, or the backend's own
  DeserializationError err;
  bool     partial;     // FilaMan stopped short, see backendLastListPartial()
  bool     archived;    // what was asked for: allow_archived
  uint8_t  attempts;    // how many were allowed
  bool     gave_up;     // the last attempt allowed ended without a 200
  uint32_t gen;         // backendGeneration() at the start
  uint32_t ms;          // how long it took, all attempts together
};

// Starts loading the spool list. `filter` is copied, its keys must be static
// storage (ArduinoJson does not copy a const char* key). With `attempts` 2 a
// failed first try is repeated once after `retry_pause_ms`, on the same terms
// the lookup always used: an HTTP error, or a stream that broke off.
// False when a list is already running, the heap is too low for a second
// task, or the task could not be created.
bool backendJobStartList(bool allow_archived, const JsonDocument* filter,
                         uint32_t timeout_ms, uint8_t attempts,
                         uint32_t retry_pause_ms);

BackendJobState backendJobState();

// True while a list is on its way, this module's or the web worker's. What
// else wants a list waits for it rather than starting a second one.
bool backendListBusy();

// Bytes read so far, for the progress line. Cheap, read it every pass.
size_t backendJobBytes();

// Valid while the state is BJS_DONE.
const BackendListResult& backendJobResult();
JsonDocument&            backendJobDoc();

// Frees the document and the slot. Once per result, after reading it.
void backendJobTake();
