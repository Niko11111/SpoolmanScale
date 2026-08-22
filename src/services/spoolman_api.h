#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

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
int spoolmanPatchSpoolTag(const char* base_url, int spool_id, const char* uuid, uint32_t timeout_ms = 5000);
// Server side tag search. Result has the same shape as the spool list, but
// usually holds a single entry. The match is partial and case insensitive,
// so the caller must still verify the tag exactly. An older Spoolman ignores
// the parameter and returns everything, which the caller's own scan handles.
int spoolmanFindSpoolByTag(const char* base_url, const char* tag_uuid, JsonDocument& doc,
                           uint32_t timeout_ms = 8000, JsonDocument* filter = nullptr,
                           DeserializationError* out_err = nullptr);

// Same search against extra.card_uids, the comma separated UID list SpoolLink
// writes for the Snapmaker U1. Pass the UID in any notation, it is normalised
// to plain hex here because the stored entries carry no separators. The same
// two caveats apply: the match is partial, and a server without the field
// silently ignores the filter and answers with everything.
int spoolmanFindSpoolByCardUid(const char* base_url, const char* uid, JsonDocument& doc,
                               uint32_t timeout_ms = 8000, JsonDocument* filter = nullptr,
                               DeserializationError* out_err = nullptr);

int spoolmanPatchSpoolRemaining(const char* base_url, int spool_id, float remaining, const char* last_used_iso = nullptr, uint32_t timeout_ms = 5000);
int spoolmanPatchInitialWeight(const char* base_url, int spool_id, float initial_weight, uint32_t timeout_ms = 5000);
int spoolmanPatchArchiveSpool(const char* base_url, int spool_id, uint32_t timeout_ms = 5000);
int spoolmanPatchSpoolWeight(const char* base_url, int spool_id, float spool_weight, uint32_t timeout_ms = 5000);
int spoolmanPatchFilamentSpoolWeight(const char* base_url, int filament_id, float spool_weight, uint32_t timeout_ms = 5000);
int spoolmanPatchVendorEmptySpoolWeight(const char* base_url, int vendor_id, float spool_weight, uint32_t timeout_ms = 5000);
int spoolmanPatchSpoolLocation(const char* base_url, int spool_id, const char* location_name = nullptr, uint32_t timeout_ms = 8000);
int spoolmanPatchSpoolLastDried(const char* base_url, int spool_id, const char* iso_datetime, uint32_t timeout_ms = 5000);
