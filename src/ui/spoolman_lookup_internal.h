#pragma once

// ============================================================
//  THE LOOKUP, SHARED BETWEEN ITS TWO FILES
//
//  spoolman_lookup.cpp asks the cheap questions (the tag scan, the searches,
//  the uid index) and holds the helpers that read a spool. lookup_scan.cpp
//  takes the inventory from the backend worker and reads the verdict out of
//  it. The code after the scan moved there word for word, which is why what
//  it calls is declared here instead of being static.
//
//  Nothing outside those two files includes this. The rest of the firmware
//  talks to the lookup through spoolman_lookup.h.
// ============================================================

#include <Arduino.h>
#include <ArduinoJson.h>
#include <lvgl.h>

#include "services/backend_api.h"
#include "services/backend_job.h"
#include "spoolman_lookup.h"

// Longest identifier the scale compares is a Bambu tray uuid at 32 characters.
#define TAG_UID_CMP_MAX  48

// How a spool was recognised. Lower is better, and rank 1 has to keep
// winning: every installation runs on it, and nothing added below may be able
// to cost it a match. It also decides which of two spools wins when both
// answer to the same tag, which is what the Bambu plugin's duplicates look
// like from here.
#define TAG_RANK_NONE        0
#define TAG_RANK_FIELD       1   // a tag field, or Spoolman's tag relation
#define TAG_RANK_BAMBU_EXT   2   // FilaMan external_id, bambulab:<tray uuid>
#define TAG_RANK_BAMBU_CHIP  3   // chip uid in bambu_rfid_tag_1 / _2
// Any other text extra field the server happens to keep, compared without
// knowing what it means. Last on purpose: a field this firmware writes must
// always win over a value that merely looks the same somewhere else.
#define TAG_RANK_EXTRA_OTHER 4

enum ShadowVerdict : uint8_t {
  SHADOW_NOT_ASKED,    // no scan was coming, or a rule kept the index out of it
  SHADOW_MAY_HOLD,     // it would have left the tag to the scan
  SHADOW_ABSENT,       // it would have said "unknown"
};

// What querySpoolman() settled before the inventory, and what the verdict
// after it needs. Local variables until the scan moved onto the worker; a
// lookup now outlives the loop pass that started it.
struct LookupCtx {
  char           tray[48];           // what was asked for, see s_last_query
  LookupOrigin   origin;
  bool           is_bambu_tag;
  bool           scanned_inventory;  // the document is the whole inventory
  bool           searches_answered;  // every cheap search got an answer
  bool           have_stamp;
  InventoryStamp stamp;
  bool           index_unknown;      // the uid index answered, no scan owed
};

// Where the verdict stands after the active list.
enum LookupStep : uint8_t {
  LOOKUP_DONE,             // painted, sm_found says which way
  LOOKUP_NEEDS_ARCHIVE     // not among the active spools, the archive is next
};

// ---- in spoolman_lookup.cpp ------------------------------------------------

extern bool          s_scan_deferred;
extern bool          s_verdict_unknown;
extern ShadowVerdict s_shadow;

int   spoolTagRank(JsonObjectConst spool, const char* uid);
void  captureBindings(JsonObjectConst spool);
void  filamanSyncBambuFields(int spool_id, JsonObjectConst extra, const char* tray_uuid);
void  applyLastUsed(const char* native_iso, const char* weighed_iso, int spool_id);
float resolveTare(JsonVariantConst spool, uint8_t *source);
float resolveInitial(JsonVariantConst spool);
void  setFromServerOrTag(lv_obj_t *lbl, const char *server, const char *from_tag);
void  applyServerColor(const String& sm_color, bool is_bambu_tag);
void  scheduleRescan(const char* uid, const char* format);
void  paintLookupFailure(int code, int fallback_id);
void  uidShadowReport(int spool_id, int rank, bool archived);
void  showArchivedSpool(int archived_id);

// Asks the uid index about the tag, logs what it said and sets s_shadow.
// True when the index answered "unknown" and no scan is owed.
bool  askUidIndex(const char* tray_uuid, bool searches_answered,
                  const InventoryStamp* stamp);

// ---- in lookup_scan.cpp ----------------------------------------------------

// The verdict out of the active list, or out of what a short cut found.
// `r` is the worker's result, null when the document came from a search.
LookupStep lookupResolveActive(const LookupCtx& c, JsonDocument& doc,
                               const BackendListResult* r,
                               DeserializationError err);

// The verdict after the active list said no. `doc2` and `r2` are the archive
// list, both null when the archive pass stood aside or was not owed.
void lookupResolveArchive(const LookupCtx& c, JsonDocument* doc2,
                          const BackendListResult* r2);

// Hands the lookup to the worker: the inventory, or the archive after it.
// Returns at once; lookupScanTick() carries it on.
void lookupScanBegin(const LookupCtx& c, const JsonDocument& filter);
void lookupArchiveBegin(const LookupCtx& c);
