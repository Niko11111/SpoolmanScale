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

// Server side tag lookup. FilaMan can filter by tag, which turns a scan into
// one small answer instead of the full inventory. Returns an array in the
// Spoolman shape, usually with a single entry.
// Spoolman has no equivalent and returns BACKEND_NOT_SUPPORTED, callers then
// keep using the existing full list scan.
int  backendFindSpoolByTag(const char* base_url, const char* tag_uuid, JsonDocument& doc,
       uint32_t timeout_ms = 8000, DeserializationError* out_err = nullptr);

// --- creating ------------------------------------------------
int  backendCreateSpool(const char* base_url, int filament_id, float initial_weight,
       float spool_weight, float remaining_weight, int* out_spool_id = nullptr,
       uint32_t timeout_ms = 8000);
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
