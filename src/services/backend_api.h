#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

// ============================================================
//  BACKEND API DISPATCH
//
//  Same call surface as spoolman_api, but routed to whichever
//  backend is active. UI and state code calls only this header,
//  never spoolman_api or filaman_api directly.
//
//  In Spoolman mode every function forwards one to one, so the
//  behaviour is byte for byte the one that shipped in v0.5.12.
//  Functions with no FilaMan equivalent return BACKEND_NOT_SUPPORTED
//  there, they never silently do nothing.
//
//  Two functions from spoolman_api are deliberately absent because
//  nothing calls them: spoolmanGetJson and spoolmanIsReachable.
// ============================================================

// Runs once after the connection is up, before the first real call. Only
// BamBuddy needs it: it asks the server whether the inventory is its own or
// proxied to Spoolman, which decides the path prefix of everything that
// follows. A no-op for the other two backends.
void backendAfterConnect();

// Re-asks the server which inventory it is on. Cheap enough to run with the
// periodic health check, and necessary: switching the filament manager in
// BamBuddy does not fail loudly on our side, it silently points every read
// and write at the other database, where the same id is a different spool.
void backendRefreshMode();

// --- reading -------------------------------------------------
int  backendGetSpoolJson(const char* base_url, int spool_id, JsonDocument& doc,
       uint32_t timeout_ms = 8000, DeserializationError* out_err = nullptr);
int  backendGetSpoolListJson(const char* base_url, bool allow_archived, JsonDocument& doc,
       uint32_t timeout_ms = 8000, JsonDocument* filter = nullptr, DeserializationError* out_err = nullptr);
int  backendGetLocationsJson(const char* base_url, JsonDocument& doc,
       uint32_t timeout_ms = 8000, DeserializationError* out_err = nullptr);
int  backendGetSpoolFieldsJson(const char* base_url, JsonDocument& doc,
       uint32_t timeout_ms = 4000, DeserializationError* out_err = nullptr);
int  backendGetHealthCode(const char* base_url, uint32_t timeout_ms = 3000);
bool backendGetVersion(const char* base_url, char* out_version, size_t out_size,
       uint32_t timeout_ms = 3000);
int  backendCountActiveSpools(const char* base_url, uint32_t timeout_ms = 6000);

// Date of the last weighing, taken from FilaMan's spool event log. Spoolman
// keeps no such history and answers false, there the scale writes the date
// into last_used itself.
bool backendGetLastWeighedAt(const char* base_url, int spool_id,
       char* out_iso, size_t out_size, uint32_t timeout_ms = 6000);

// Server side tag lookup, which turns a scan into one small answer instead of
// the full inventory. Returns an array in the Spoolman shape, usually with a
// single entry. All three backends can do it, each by its own route, so there
// is no BACKEND_NOT_SUPPORTED case here any more.
// The match is not exact in any of them, so the caller must verify every hit.
int  backendFindSpoolByTag(const char* base_url, const char* tag_uuid, JsonDocument& doc,
       uint32_t timeout_ms = 8000, DeserializationError* out_err = nullptr,
       JsonDocument* filter = nullptr);

// The same search against one named tag field, by TagFieldId. Spoolman only;
// FilaMan and BamBuddy answer BACKEND_NOT_SUPPORTED because neither keeps its
// tags in a Spoolman extra field.
//
// backendFindSpoolByTag() above is this with the user's selected field. The
// explicit form is for the fallback pass, which tries the fields the user did
// not select so that switching never makes a linked spool disappear.
//
// The UID is formatted for the field before it is sent, and the field's
// presence is checked first - a filter on a field the server does not have is
// ignored, and Spoolman then answers with the whole inventory. BACKEND_NOT_
// SUPPORTED comes back for a field that is not there, so the caller moves on
// instead of paying for a full transfer that looks like a hit.
int  backendFindSpoolByTagField(uint8_t field_id, const char* base_url, const char* uid,
       JsonDocument& doc, uint32_t timeout_ms = 8000,
       DeserializationError* out_err = nullptr, JsonDocument* filter = nullptr);

// Whether the active Spoolman has a given extra field. Only answers for the
// fields the scale knows - the three tag fields and last_dried - and false for
// anything else, including every field outside Spoolman mode.
//
// One GET settles all of them and the result is cached against the base URL,
// so pointing the scale elsewhere re-probes on its own. Performs an HTTP
// request on the first call, so never call it from an LVGL event callback.
bool backendHasExtraField(const char* key);

// Drops that cache, and the native tag probe with it. Called after a field was
// created, which is the one moment the answer changes without the base URL
// changing with it.
void backendInvalidateExtraFieldCache();

// --- native tags ---------------------------------------------
// Whether this Spoolman has the tag relation of its own that master grew: one
// UID per tag, several tags per spool, no extra field involved. False on every
// released version, and on FilaMan and BamBuddy always. Probed once per base
// URL and cached; an inconclusive answer is not cached and not a no.
//
// Everything below is reached only when this is true, and each call checks it
// again rather than trusting the caller to have asked.
bool backendHasNativeTags();

// This scale's id in Spoolman's reader list, stable across reboots.
const char* backendReaderId();

// Reports a scan and resolves it in one request - see spoolmanTagScan(). A
// null match means "no native tag", so the caller must still try the extra
// field chain before calling a spool unknown.
int  backendTagScan(const char* base_url, const char* uid, const char* format,
       JsonDocument& doc, uint32_t timeout_ms = 8000,
       DeserializationError* out_err = nullptr);

// 201 links, 409 means another spool holds the UID and out_conflict_spool_id
// names it, 404 is an unknown spool.
int  backendLinkTag(const char* base_url, int spool_id, const char* uid,
       const char* format, int* out_conflict_spool_id = nullptr,
       uint32_t timeout_ms = 5000);

int  backendUnlinkTag(const char* base_url, int spool_id, const char* uid,
       uint32_t timeout_ms = 5000);

// Writes one text extra field. Spoolman only, for the same reason as
// backendFindSpoolByTagField(): nothing else has extra fields. The value is
// the finished contents - the list merge, if any, happened before this.
int  backendPatchExtraField(const char* base_url, int spool_id, const char* key,
       const char* value, uint32_t timeout_ms = 5000);

// Which tare scopes the active backend can really store. Offering one it
// cannot write gives a button that answers BACKEND_NOT_SUPPORTED, or worse
// reports success and changes nothing - BamBuddy's Spoolman proxy accepts
// core_weight and drops it. Asked by the tare popup before it is built.
bool backendCanTareSpool();
bool backendCanTareFilamentOrVendor();

// --- creating ------------------------------------------------
// Copies a spool. Both anchors are passed because the backends disagree on
// what a copy even is: Spoolman and FilaMan point the new spool at the
// template's filament_id and never create a filament, while BamBuddy has no
// filament as an object - material, brand and colour are strings on the spool,
// so it reads template_spool_id back and replicates those. Each branch uses
// the anchor it can, the other is ignored.
int  backendCreateSpool(const char* base_url, int template_spool_id, int filament_id,
       float initial_weight, float spool_weight, float remaining_weight,
       int* out_spool_id = nullptr, uint32_t timeout_ms = 8000);

// Creates a spool from what a Bambu tag carries, for the case where no
// template fits. BamBuddy only - Spoolman and FilaMan want a filament_id, and
// a tag cannot supply one. remaining_weight is the net reading of the scale.
int  backendCreateSpoolFromTag(const char* material, const char* subtype,
       const char* brand, const char* rgba, const char* color_name,
       int label_weight, int core_weight,
       float remaining_weight, int nozzle_temp_min, int nozzle_temp_max,
       int* out_spool_id = nullptr, uint32_t timeout_ms = 8000);

// Turns the colour value on a tag into a name the backend knows. Empty output
// means "no name for this colour", which is not an error.
void backendLookupColorName(const char* hex6, const char* material,
       char* out_name, size_t out_size);

// True when backendCreateSpoolFromTag() has a path on the active backend, so
// the UI can leave the button out instead of offering a dead end.
bool backendCanCreateFromTag();

int  backendCreateSpoolField(const char* base_url, const char* field_name,
       uint32_t timeout_ms = 3000);

// --- writing -------------------------------------------------
int  backendPatchSpoolTag(const char* base_url, int spool_id, const char* uuid,
       uint32_t timeout_ms = 5000);

// Weight update. The two backends want different numbers:
//   Spoolman takes the finished remaining weight
//   FilaMan takes the measured gross weight and subtracts the empty spool
//           weight itself, so passing remaining would subtract it twice
// measured_g must therefore be supplied by the caller, which is the only
// place that knows what the scale actually showed. Pass a negative value to
// let it be reconstructed as remaining + sm_spool_weight.
// tag_uuid is unused in Spoolman mode; FilaMan can identify the spool by id
// or by tag.
int  backendPatchSpoolRemaining(const char* base_url, int spool_id, float remaining,
       const char* last_used_iso = nullptr, const char* tag_uuid = nullptr,
       float measured_g = -1.0f, uint32_t timeout_ms = 5000);

int  backendPatchInitialWeight(const char* base_url, int spool_id, float initial_weight,
       uint32_t timeout_ms = 5000);
int  backendPatchArchiveSpool(const char* base_url, int spool_id, uint32_t timeout_ms = 5000);
int  backendPatchSpoolWeight(const char* base_url, int spool_id, float spool_weight,
       uint32_t timeout_ms = 5000);
int  backendPatchFilamentSpoolWeight(const char* base_url, int filament_id, float spool_weight,
       uint32_t timeout_ms = 5000);
int  backendPatchVendorEmptySpoolWeight(const char* base_url, int vendor_id, float spool_weight,
       uint32_t timeout_ms = 5000);
int  backendPatchSpoolLocation(const char* base_url, int spool_id,
       const char* location_name = nullptr, uint32_t timeout_ms = 8000);
int  backendPatchSpoolLastDried(const char* base_url, int spool_id, const char* iso_datetime,
       uint32_t timeout_ms = 5000);
