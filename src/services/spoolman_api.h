#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

// Called while a large response is being read, with the number of bytes so
// far. Set while something is on screen that wants to show progress, cleared
// afterwards - nothing is wrapped and nothing costs anything while it is null.
//
// The parse of a full inventory is the long pole of a link flow, and it is one
// blocking call: without a hook inside it there is no moment at which the UI
// could say anything. The hook must be cheap and must not process input.
typedef void (*SpoolmanProgressFn)(size_t bytes_read);
void spoolmanSetProgressHook(SpoolmanProgressFn fn);

int spoolmanGetJson(const char* base_url, const char* path, JsonDocument& doc,
  uint32_t timeout_ms = 8000, JsonDocument* filter = nullptr, DeserializationError* out_err = nullptr);
int spoolmanGetSpoolJson(const char* base_url, int spool_id, JsonDocument& doc,
  uint32_t timeout_ms = 8000, DeserializationError* out_err = nullptr);
int spoolmanGetSpoolListJson(const char* base_url, bool allow_archived, JsonDocument& doc,
  uint32_t timeout_ms = 8000, JsonDocument* filter = nullptr, DeserializationError* out_err = nullptr);
int spoolmanGetLocationsJson(const char* base_url, JsonDocument& doc,
  uint32_t timeout_ms = 8000, DeserializationError* out_err = nullptr);
int spoolmanGetSpoolFieldsJson(const char* base_url, JsonDocument& doc,
  uint32_t timeout_ms = 4000, DeserializationError* out_err = nullptr);
int spoolmanGetHealthCode(const char* base_url, uint32_t timeout_ms = 3000);
bool spoolmanIsReachable(const char* base_url, uint32_t timeout_ms = 3000);
bool spoolmanGetVersion(const char* base_url, char* out_version, size_t out_size, uint32_t timeout_ms = 3000);
int spoolmanCountActiveSpools(const char* base_url, uint32_t timeout_ms = 6000);
int spoolmanCreateSpool(const char* base_url, int filament_id, float initial_weight,
  float spool_weight, float remaining_weight, int* out_spool_id = nullptr, uint32_t timeout_ms = 8000);
int spoolmanCreateSpoolField(const char* base_url, const char* field_name, uint32_t timeout_ms = 3000);
// Writes one text extra field. `value` is the finished contents - for a list
// field the merge already happened in cardUidsAppend() / cardUidsRemove(), and
// for a single valued one it is the formatted UID. An empty value clears the
// field, which is what an unlink writes.
int spoolmanPatchExtraField(const char* base_url, int spool_id, const char* key,
                            const char* value, uint32_t timeout_ms = 5000);

// Server side search over one extra field. Result has the same shape as the
// spool list but usually holds a single entry, which is the entire point: at
// 268 spools this is under 1 kB instead of 176 kB.
//
// Two caveats the caller must handle, both unchanged from when this only did
// extra.tag: the match is partial and case insensitive, so every hit has to be
// verified exactly; and a server that does not know the field ignores the
// filter and answers with the whole inventory, so ask backendHasExtraField()
// first or the shortcut turns into the long way round without saying so.
//
// `value` must already be formatted for the field - see tagFieldFormat().
int spoolmanFindSpoolByExtraField(const char* base_url, const char* key, const char* value,
                                  JsonDocument& doc, uint32_t timeout_ms = 8000,
                                  JsonDocument* filter = nullptr,
                                  DeserializationError* out_err = nullptr);

int spoolmanPatchSpoolRemaining(const char* base_url, int spool_id, float remaining, const char* last_used_iso = nullptr, uint32_t timeout_ms = 5000);
int spoolmanPatchInitialWeight(const char* base_url, int spool_id, float initial_weight, uint32_t timeout_ms = 5000);
int spoolmanPatchArchiveSpool(const char* base_url, int spool_id, uint32_t timeout_ms = 5000);
int spoolmanPatchSpoolWeight(const char* base_url, int spool_id, float spool_weight, uint32_t timeout_ms = 5000);
int spoolmanPatchFilamentSpoolWeight(const char* base_url, int filament_id, float spool_weight, uint32_t timeout_ms = 5000);
int spoolmanPatchVendorEmptySpoolWeight(const char* base_url, int vendor_id, float spool_weight, uint32_t timeout_ms = 5000);
int spoolmanPatchSpoolLocation(const char* base_url, int spool_id, const char* location_name = nullptr, uint32_t timeout_ms = 8000);
int spoolmanPatchSpoolLastDried(const char* base_url, int spool_id, const char* iso_datetime, uint32_t timeout_ms = 5000);
