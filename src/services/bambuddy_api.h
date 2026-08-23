#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

// ============================================================
//  BAMBUDDY REST CLIENT
//
//  Same job as filaman_api: talk to one backend and hand the
//  answer back in the Spoolman JSON shape, so the UI never
//  learns there is a third backend. No LVGL, no lang.h.
//
//  Every function returns the HTTP status code, with two
//  exceptions that predate any request:
//    -1  the request could not be built (no base url, bad id)
//    -2  the answer was not parsable JSON, or a read modify
//        write was aborted rather than risk losing data
//
//  BamBuddy answers two very different questions on the same
//  server, and both are used:
//
//    /api/v1/spoolbuddy/*   the device protocol its own scale
//                           speaks. Presence, tag events, live
//                           weight, and the weight write back.
//    /api/v1/inventory/*    the spool data our own display needs.
//
//  Verified against BamBuddy 1.2.5.3 on 21.08.2026, see
//  Notes/SpoolmanScale_BamBuddy_Integration.md.
// ============================================================

// Inventory mode. BamBuddy either keeps its own database or proxies to a
// Spoolman server, and the two answer under different path prefixes while
// returning the same field names. Everything else in this module is written
// once and works in both.
enum BbInventoryMode : uint8_t {
  BB_INV_LOCAL    = 0,   // /api/v1/inventory
  BB_INV_SPOOLMAN = 1    // /api/v1/spoolman/inventory
};

// --- setup ---------------------------------------------------

// Asks GET /api/v1/settings/spoolman which mode the server runs in and
// remembers the answer, along with the Spoolman url when there is one. Call
// once after connecting; on failure the mode stays LOCAL, which is the
// default a fresh BamBuddy install runs in.
// Returns the HTTP code. 403 means the API key lacks "Read Status".
int  bbDetectInventoryMode(const char* base_url, const char* api_key,
       uint32_t timeout_ms = 5000);

BbInventoryMode bbInventoryMode();

// Path prefix of the active inventory mode, without a trailing slash.
const char* bbInventoryBase();

// Url of the Spoolman server behind BamBuddy, empty in local mode. Reported
// by BamBuddy with a trailing slash, which is stripped here. Used by the
// drying date side channel, which writes extra.last_dried straight to
// Spoolman because BamBuddy has no field for it.
const char* bbSpoolmanUrl();

// Stable device id derived from the MAC, "ssc-<12 hex>", mirroring the
// "sb-<mac>" of BamBuddy's own daemon. Needs no NVS entry.
const char* bbDeviceId();

// --- reading -------------------------------------------------

// Reachability in two steps, because BamBuddy has no /health endpoint at all
// (404 in 1.2.5.3) and everything else needs the key:
//   GET /api/v1/updates/version   public, proves the server is there
//   GET /api/v1/system/info       proves the key is accepted
// Returns 200 when both pass, 401/403 when the server answers but rejects
// the key, and the transport error otherwise. That lets the connection test
// tell a wrong key from a dead server, which neither other backend can.
int  bbGetHealthCode(const char* base_url, const char* api_key,
       uint32_t timeout_ms = 4000);

bool bbGetVersion(const char* base_url, const char* api_key,
       char* out_version, size_t out_size, uint32_t timeout_ms = 4000);

// Reads a spool exactly as BamBuddy stores it, skipping the Spoolman shaping
// mapSpool() applies. Only spool creation needs this: subtype and color_name
// are folded into filament.name by the mapping and rgba loses its alpha, so a
// copy built from the mapped form would come out poorer than its template.
int  bbGetSpoolRawJson(const char* base_url, const char* api_key, int spool_id,
       JsonDocument& doc, uint32_t timeout_ms = 8000,
       DeserializationError* out_err = nullptr);

// Single spool, translated into the Spoolman shape.
int  bbGetSpoolJson(const char* base_url, const char* api_key, int spool_id,
       JsonDocument& doc, uint32_t timeout_ms = 8000,
       DeserializationError* out_err = nullptr);

// Whole inventory as a Spoolman shaped array. BamBuddy sends no count header
// and has no page size, so this is the expensive call - the tag lookup does
// not use it.
int  bbGetSpoolListJson(const char* base_url, const char* api_key,
       bool allow_archived, JsonDocument& doc, uint32_t timeout_ms = 15000,
       DeserializationError* out_err = nullptr);

// Storage locations, as a Spoolman shaped array of names.
int  bbGetLocationsJson(const char* base_url, const char* api_key,
       JsonDocument& doc, uint32_t timeout_ms = 8000,
       DeserializationError* out_err = nullptr);

// Counts active spools by fetching the list with a filter that keeps only
// the ids. Returns the count, or a negative HTTP/parse error.
int  bbCountActiveSpools(const char* base_url, const char* api_key,
       uint32_t timeout_ms = 10000);

// Tag lookup. Goes through the device protocol rather than the inventory
// API, for three reasons: it is the only path that exists in both inventory
// modes, the server decides where to search, and it makes the BamBuddy web
// interface react to a scan on this scale.
//
// The identifier is normalised to plain hex before asking, because that is
// what BamBuddy stores. A spool tagged by an older SpoolmanScale carries
// separators in Spoolman's extra.tag and would be missed, so a failed lookup
// is retried once with the string exactly as the caller supplied it.
//
// Returns a Spoolman shaped array with one entry, or an empty array when
// nothing matched.
int  bbFindSpoolByTag(const char* base_url, const char* api_key,
       const char* tag, JsonDocument& doc, uint32_t timeout_ms = 10000,
       DeserializationError* out_err = nullptr);

// --- writing -------------------------------------------------

// The weight write back. weight_grams is the GROSS weight including the
// spool core: BamBuddy subtracts core_weight itself and derives weight_used
// from it. Handing it the remaining weight would subtract the core twice.
// Goes through the device protocol, which routes to the right inventory mode
// on the server side and works in both.
int  bbUpdateSpoolWeight(const char* base_url, const char* api_key,
       int spool_id, float gross_grams, uint32_t timeout_ms = 8000);

// Links a tag to a spool. Both identifiers must be plain uppercase hex:
// the Spoolman mode endpoint validates against ^[0-9A-Fa-f]+$ and answers
// 422 for anything with separators. Pass tray_uuid for Bambu spools (32
// chars) and tag_uid for everything else (8 to 30).
int  bbLinkTag(const char* base_url, const char* api_key, int spool_id,
       const char* tag_uid, const char* tray_uuid, uint32_t timeout_ms = 8000);

// Removes the tag from a spool. Not the link endpoint in reverse: that one
// only ever writes. Both inventory modes take an explicit null on the plain
// PATCH instead, and BamBuddy tells "sent as null" from "not sent" - an
// omitted field means "leave alone", so the nulls have to be in the body.
int  bbUnlinkTag(const char* base_url, const char* api_key, int spool_id,
       uint32_t timeout_ms = 8000);

int  bbArchiveSpool(const char* base_url, const char* api_key, int spool_id,
       uint32_t timeout_ms = 5000);

// Writes a "[dried:YYYY-MM-DD]" marker into the note field, the only free
// text BamBuddy offers. Read modify write: the rest of the note has to
// survive, so a failed read means no write at all rather than an overwrite.
// iso may be longer than the date, only the first ten characters are used.
int  bbPatchDriedNote(const char* base_url, const char* api_key, int spool_id,
       const char* iso, uint32_t timeout_ms = 8000);

// Reads extra.last_dried straight from the Spoolman server behind BamBuddy.
// Needed because the proxy does not pass extra through, and possible because
// the spool id is the same on both sides. Empty when there is none.
bool bbGetDriedFromSpoolman(int spool_id, char* out_iso, size_t out_size,
       uint32_t timeout_ms = 6000);

// Generic PATCH on the spool for the plain fields. Pass nullptr / a negative
// number to leave a field untouched. Note that BamBuddy treats null as
// "unchanged" and an empty string as "clear".
int  bbPatchSpoolFields(const char* base_url, const char* api_key, int spool_id,
       const int* label_weight, const int* core_weight, const float* weight_used,
       const char* storage_location, const char* note, uint32_t timeout_ms = 8000);

// Resolves a colour value into BamBuddy's catalogue name, e.g. F75403 plus
// "PETG HF" into "Orange". out_name is left empty when the colour is unknown,
// which is a normal answer rather than a failure.
int  bbLookupColorName(const char* base_url, const char* api_key, const char* hex6,
       const char* material, char* out_name, size_t out_size,
       uint32_t timeout_ms = 6000);

// Fields for a new spool. material is the only one BamBuddy insists on;
// everything else may stay empty or zero and is then left off the request.
struct BbNewSpool {
  const char* material        = nullptr;  // required
  const char* subtype         = nullptr;
  const char* brand           = nullptr;
  const char* color_name      = nullptr;
  const char* rgba            = nullptr;  // RRGGBBAA
  int         label_weight    = 0;
  int         core_weight     = 0;
  float       weight_used     = 0.0f;     // consumption, not remaining
  int         nozzle_temp_min = 0;
  int         nozzle_temp_max = 0;
};

// Creates a spool in whichever inventory is active.
//
// Deliberately no tag: the built-in inventory would take tag_uid and
// tray_uuid right here, but the Spoolman proxy has neither field in its
// create schema and drops them without an error - the spool would come back
// with HTTP 200 and no tag at all. Both modes therefore link afterwards
// through bbLinkTag(), the one place that already tells them apart.
int  bbCreateSpool(const char* base_url, const char* api_key,
       const BbNewSpool& spool, int* out_spool_id,
       uint32_t timeout_ms = 8000);

// --- device protocol -----------------------------------------

// Registers the scale so it shows up under Settings > SpoolBuddy. The
// calibration values are reported for display only; the answer's tare_offset
// and calibration_factor are deliberately ignored by the caller, ours are
// measured locally on the factor screen.
int  bbRegisterDevice(const char* base_url, const char* api_key,
       const char* ip, const char* firmware, int32_t tare_offset,
       float calibration_factor, uint32_t timeout_ms = 8000);

// Heartbeat. Must run at least every 30 s or BamBuddy shows the scale as
// offline (OFFLINE_THRESHOLD_SECONDS). Writes any queued command into
// out_command, which is empty when there is nothing to do. A 404 means the
// device was removed in the web interface and has to register again.
// out_write_spool_id receives the spool a queued "write_tag" command refers
// to, so that command can be declined by id. 0 when there is none.
int  bbHeartbeat(const char* base_url, const char* api_key, bool nfc_ok,
       bool scale_ok, uint32_t uptime_s, const char* ip, const char* firmware,
       char* out_command, size_t out_command_size, int* out_write_spool_id = nullptr,
       uint32_t timeout_ms = 5000);

// Reports a scanned tag and returns the spool BamBuddy matched it to, or 0
// when it knows none. This is also the tag lookup: it is the only path that
// works in both inventory modes, and it makes the web interface react to
// scans on our scale.
int  bbTagScanned(const char* base_url, const char* api_key,
       const char* tag_uid, const char* tray_uuid, int* out_spool_id,
       uint32_t timeout_ms = 8000);

int  bbTagRemoved(const char* base_url, const char* api_key,
       const char* tag_uid, uint32_t timeout_ms = 4000);

// Live weight for the web interface. Throttled by the caller: at most once a
// second and only on a change of 2 g or more.
int  bbScaleReading(const char* base_url, const char* api_key,
       float grams, bool stable, int32_t raw_adc, uint32_t timeout_ms = 4000);

// Answer to a queued "tare" command.
int  bbSetTare(const char* base_url, const char* api_key, int32_t tare_offset,
       uint32_t timeout_ms = 5000);

// Answers to the queued commands this scale cannot serve. Leaving one
// unanswered leaves BamBuddy's interface waiting, so every command gets a
// reply even when the reply is "no".
int  bbCommandResult(const char* base_url, const char* api_key,
       const char* command, bool success, const char* message,
       uint32_t timeout_ms = 5000);

int  bbDiagnosticResult(const char* base_url, const char* api_key,
       const char* diagnostic, bool success, const char* output,
       int exit_code, uint32_t timeout_ms = 5000);

int  bbWriteTagResult(const char* base_url, const char* api_key, int spool_id,
       const char* tag_uid, bool success, const char* message,
       uint32_t timeout_ms = 5000);
