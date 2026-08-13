#include "backend_api.h"

#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/filaman_api.h"
#include "services/list_limits.h"
#include "services/spoolman_api.h"

// A missing FilaMan path must show up in the log instead of looking like a
// silent failure, but the periodic health check would repeat the same line
// every 30 seconds and bury everything else. Each call site is therefore
// logged only once per boot. The names are string literals, so comparing
// pointers is enough to tell them apart.
static int notSupported(const char* fn) {
  static const char* logged[24] = { nullptr };
  static uint8_t logged_count = 0;

  for (uint8_t i = 0; i < logged_count; i++) {
    if (logged[i] == fn) return BACKEND_NOT_SUPPORTED;
  }
  if (logged_count < (sizeof(logged) / sizeof(logged[0]))) {
    logged[logged_count++] = fn;
  }
  logSDf("Backend: %s has no FilaMan implementation yet", fn);
  return BACKEND_NOT_SUPPORTED;
}

// ============================================================
//  READING
// ============================================================

int backendGetSpoolJson(const char* base_url, int spool_id, JsonDocument& doc,
                        uint32_t timeout_ms, DeserializationError* out_err) {
  if (backendIsFilaMan()) {
    return filamanGetSpoolJson(backendBaseUrl(), filamanApiKey(), spool_id,
                               doc, timeout_ms, out_err);
  }
  return spoolmanGetSpoolJson(base_url, spool_id, doc, timeout_ms, out_err);
}

int backendGetSpoolListJson(const char* base_url, bool allow_archived, JsonDocument& doc,
                            uint32_t timeout_ms, JsonDocument* filter,
                            DeserializationError* out_err) {
  if (backendIsFilaMan()) {
    // The Spoolman JSON filter does not apply, FilaMan is translated field by
    // field and only the keys the UI reads are produced anyway.
    (void)filter;
    return filamanGetSpoolListJson(backendBaseUrl(), filamanApiKey(), allow_archived,
                                   doc, nullptr, spool_list_limit > 100 ? spool_list_limit : 100,
                                   timeout_ms, out_err);
  }
  return spoolmanGetSpoolListJson(base_url, allow_archived, doc, timeout_ms, filter, out_err);
}

int backendFindSpoolByTag(const char* base_url, const char* tag_uuid, JsonDocument& doc,
                          uint32_t timeout_ms, DeserializationError* out_err) {
  // Without a tag the search parameter would be dropped and the call would
  // quietly turn into a full inventory fetch, which callers would then treat
  // as a successful lookup.
  if (!tag_uuid || !tag_uuid[0]) return BACKEND_NOT_SUPPORTED;
  if (backendIsFilaMan()) {
    // FilaMan filters server side, so a scan costs one small answer instead
    // of the whole inventory.
    return filamanGetSpoolListJson(backendBaseUrl(), filamanApiKey(), false,
                                   doc, tag_uuid, 20, timeout_ms, out_err);
  }
  // Spoolman has no such search, the caller keeps using the full list.
  (void)tag_uuid;
  return BACKEND_NOT_SUPPORTED;
}

int backendGetLocationsJson(const char* base_url, JsonDocument& doc,
                            uint32_t timeout_ms, DeserializationError* out_err) {
  if (backendIsFilaMan()) return notSupported("GetLocationsJson");
  return spoolmanGetLocationsJson(base_url, doc, timeout_ms, out_err);
}

int backendGetSpoolFieldsJson(const char* base_url, JsonDocument& doc,
                              uint32_t timeout_ms, DeserializationError* out_err) {
  // FilaMan equivalent is /api/v1/system-extra-fields, different shape.
  if (backendIsFilaMan()) return notSupported("GetSpoolFieldsJson");
  return spoolmanGetSpoolFieldsJson(base_url, doc, timeout_ms, out_err);
}

int backendGetHealthCode(const char* base_url, uint32_t timeout_ms) {
  // FilaMan serves /health outside the /api/v1 prefix and needs no
  // credentials for it, so this works before any token is stored.
  if (backendIsFilaMan()) return filamanGetHealthCode(backendBaseUrl(), timeout_ms);
  return spoolmanGetHealthCode(base_url, timeout_ms);
}

bool backendGetVersion(const char* base_url, char* out_version, size_t out_size,
                       uint32_t timeout_ms) {
  if (backendIsFilaMan()) { notSupported("GetVersion"); return false; }
  return spoolmanGetVersion(base_url, out_version, out_size, timeout_ms);
}

int backendCountActiveSpools(const char* base_url, uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("CountActiveSpools");
  return spoolmanCountActiveSpools(base_url, timeout_ms);
}

// ============================================================
//  CREATING
// ============================================================

int backendCreateSpool(const char* base_url, int filament_id, float initial_weight,
                       float spool_weight, float remaining_weight, int* out_spool_id,
                       uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("CreateSpool");
  return spoolmanCreateSpool(base_url, filament_id, initial_weight, spool_weight,
                             remaining_weight, out_spool_id, timeout_ms);
}

int backendCreateSpoolField(const char* base_url, const char* field_name,
                            uint32_t timeout_ms) {
  // Creating system extra fields in FilaMan appears to need admin rights,
  // so this may stay unsupported on purpose. See integration doc.
  if (backendIsFilaMan()) return notSupported("CreateSpoolField");
  return spoolmanCreateSpoolField(base_url, field_name, timeout_ms);
}

// ============================================================
//  WRITING
// ============================================================

int backendPatchSpoolTag(const char* base_url, int spool_id, const char* uuid,
                         uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("PatchSpoolTag");
  return spoolmanPatchSpoolTag(base_url, spool_id, uuid, timeout_ms);
}

int backendPatchSpoolRemaining(const char* base_url, int spool_id, float remaining,
                               const char* last_used_iso, const char* tag_uuid,
                               uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("PatchSpoolRemaining");
  (void)tag_uuid;   // Spoolman identifies the spool by id only
  return spoolmanPatchSpoolRemaining(base_url, spool_id, remaining, last_used_iso, timeout_ms);
}

int backendPatchInitialWeight(const char* base_url, int spool_id, float initial_weight,
                              uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("PatchInitialWeight");
  return spoolmanPatchInitialWeight(base_url, spool_id, initial_weight, timeout_ms);
}

int backendPatchArchiveSpool(const char* base_url, int spool_id, uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("PatchArchiveSpool");
  return spoolmanPatchArchiveSpool(base_url, spool_id, timeout_ms);
}

int backendPatchSpoolWeight(const char* base_url, int spool_id, float spool_weight,
                            uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("PatchSpoolWeight");
  return spoolmanPatchSpoolWeight(base_url, spool_id, spool_weight, timeout_ms);
}

int backendPatchFilamentSpoolWeight(const char* base_url, int filament_id, float spool_weight,
                                    uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("PatchFilamentSpoolWeight");
  return spoolmanPatchFilamentSpoolWeight(base_url, filament_id, spool_weight, timeout_ms);
}

int backendPatchVendorEmptySpoolWeight(const char* base_url, int vendor_id, float spool_weight,
                                       uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("PatchVendorEmptySpoolWeight");
  return spoolmanPatchVendorEmptySpoolWeight(base_url, vendor_id, spool_weight, timeout_ms);
}

int backendPatchSpoolLocation(const char* base_url, int spool_id, const char* location_name,
                              uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("PatchSpoolLocation");
  return spoolmanPatchSpoolLocation(base_url, spool_id, location_name, timeout_ms);
}

int backendPatchSpoolLastDried(const char* base_url, int spool_id, const char* iso_datetime,
                               uint32_t timeout_ms) {
  if (backendIsFilaMan()) return notSupported("PatchSpoolLastDried");
  return spoolmanPatchSpoolLastDried(base_url, spool_id, iso_datetime, timeout_ms);
}
