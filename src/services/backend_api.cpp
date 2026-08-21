#include "backend_api.h"

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/filaman_api.h"
#include "services/list_limits.h"
#include "services/spoolman_api.h"

// A missing backend path must show up in the log instead of looking like a
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
  logSDf("Backend: %s has no %s implementation yet", fn, backendName());
  return BACKEND_NOT_SUPPORTED;
}

// ============================================================
//  READING
// ============================================================

int backendGetSpoolJson(const char* base_url, int spool_id, JsonDocument& doc,
                        uint32_t timeout_ms, DeserializationError* out_err) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanGetSpoolJson(backendBaseUrl(), filamanApiKey(), spool_id,
                                 doc, timeout_ms, out_err);
    case BACKEND_BAMBUDDY:
      return notSupported("GetSpoolJson");
    default:
      return spoolmanGetSpoolJson(base_url, spool_id, doc, timeout_ms, out_err);
  }
}

int backendGetSpoolListJson(const char* base_url, bool allow_archived, JsonDocument& doc,
                            uint32_t timeout_ms, JsonDocument* filter,
                            DeserializationError* out_err) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // The Spoolman JSON filter does not apply, FilaMan is translated field by
      // field and only the keys the UI reads are produced anyway.
      (void)filter;
      return filamanGetSpoolListJson(backendBaseUrl(), filamanApiKey(), allow_archived,
                                     doc, nullptr, spool_list_limit > 100 ? spool_list_limit : 100,
                                     timeout_ms, out_err);
    case BACKEND_BAMBUDDY:
      return notSupported("GetSpoolListJson");
    default:
      return spoolmanGetSpoolListJson(base_url, allow_archived, doc, timeout_ms, filter, out_err);
  }
}

int backendFindSpoolByTag(const char* base_url, const char* tag_uuid, JsonDocument& doc,
                          uint32_t timeout_ms, DeserializationError* out_err,
                          JsonDocument* filter) {
  // Without a tag both backends would drop the search term and answer with
  // the whole inventory, which callers would then treat as a successful
  // lookup. Spoolman is worse still: an empty value there means "spools with
  // no tag" and matches most of the library.
  if (!tag_uuid || !tag_uuid[0]) return BACKEND_NOT_SUPPORTED;

  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // FilaMan filters server side, so a scan costs one small answer instead
      // of the whole inventory. The translation only produces the keys the UI
      // reads, so the caller's field filter does not apply.
      (void)filter;
      return filamanGetSpoolListJson(backendBaseUrl(), filamanApiKey(), false,
                                     doc, tag_uuid, 20, timeout_ms, out_err);
    case BACKEND_BAMBUDDY:
      return notSupported("FindSpoolByTag");
    default:
      // Spoolman can do the same through an extra field filter. The field filter
      // is passed along because an older server ignores the query parameter and
      // answers with everything: that case still works, and this keeps it from
      // costing more memory than the normal full scan would.
      return spoolmanFindSpoolByTag(base_url, tag_uuid, doc, timeout_ms, filter, out_err);
  }
}

int backendGetLocationsJson(const char* base_url, JsonDocument& doc,
                            uint32_t timeout_ms, DeserializationError* out_err) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanGetLocationsJson(backendBaseUrl(), filamanApiKey(), doc,
                                     timeout_ms, out_err);
    case BACKEND_BAMBUDDY:
      return notSupported("GetLocationsJson");
    default:
      return spoolmanGetLocationsJson(base_url, doc, timeout_ms, out_err);
  }
}

int backendGetSpoolFieldsJson(const char* base_url, JsonDocument& doc,
                              uint32_t timeout_ms, DeserializationError* out_err) {
  // FilaMan equivalent is /api/v1/system-extra-fields, different shape.
  // BamBuddy has a fixed schema and no extra fields at all.
  if (backendIsFilaMan() || backendIsBamBuddy()) return notSupported("GetSpoolFieldsJson");
  return spoolmanGetSpoolFieldsJson(base_url, doc, timeout_ms, out_err);
}

int backendGetHealthCode(const char* base_url, uint32_t timeout_ms) {
  // FilaMan serves /health outside the /api/v1 prefix and needs no
  // credentials for it, so this works before any token is stored.
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanGetHealthCode(backendBaseUrl(), timeout_ms);
    case BACKEND_BAMBUDDY:
      return notSupported("GetHealthCode");
    default:
      return spoolmanGetHealthCode(base_url, timeout_ms);
  }
}

bool backendGetVersion(const char* base_url, char* out_version, size_t out_size,
                       uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanGetVersion(backendBaseUrl(), out_version, out_size, timeout_ms);
    case BACKEND_BAMBUDDY:
      // bool return, so there is no BACKEND_NOT_SUPPORTED to hand back.
      notSupported("GetVersion");
      return false;
    default:
      return spoolmanGetVersion(base_url, out_version, out_size, timeout_ms);
  }
}

int backendCountActiveSpools(const char* base_url, uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanCountActiveSpools(backendBaseUrl(), filamanApiKey(), timeout_ms);
    case BACKEND_BAMBUDDY:
      return notSupported("CountActiveSpools");
    default:
      return spoolmanCountActiveSpools(base_url, timeout_ms);
  }
}

bool backendGetLastWeighedAt(const char* base_url, int spool_id,
                             char* out_iso, size_t out_size, uint32_t timeout_ms) {
  if (out_iso && out_size > 0) out_iso[0] = '\0';
  if (backendIsFilaMan()) {
    return filamanGetLastMeasuredAt(backendBaseUrl(), filamanApiKey(), spool_id,
                                    out_iso, out_size, timeout_ms);
  }
  // Spoolman has no event log. In weighed mode the scale writes the date into
  // last_used on every weight update, so it is already in the spool object.
  // BamBuddy carries last_weighed_at on the spool itself, so the answer comes
  // out of the spool JSON there as well and needs no second request.
  (void)base_url; (void)spool_id; (void)timeout_ms;
  return false;
}

// ============================================================
//  CREATING
// ============================================================

int backendCreateSpool(const char* base_url, int filament_id, float initial_weight,
                       float spool_weight, float remaining_weight, int* out_spool_id,
                       uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // The tag is attached by the caller in a separate step, same as with
      // Spoolman, so the flow stays identical for both backends.
      return filamanCreateSpool(backendBaseUrl(), filamanApiKey(), filament_id,
                                initial_weight, spool_weight, remaining_weight,
                                nullptr, out_spool_id, timeout_ms);
    case BACKEND_BAMBUDDY:
      return notSupported("CreateSpool");
    default:
      return spoolmanCreateSpool(base_url, filament_id, initial_weight, spool_weight,
                                 remaining_weight, out_spool_id, timeout_ms);
  }
}

int backendCreateSpoolField(const char* base_url, const char* field_name,
                            uint32_t timeout_ms) {
  // Creating system extra fields in FilaMan appears to need admin rights,
  // so this may stay unsupported on purpose. See integration doc.
  // BamBuddy has no extra fields to create.
  if (backendIsFilaMan() || backendIsBamBuddy()) return notSupported("CreateSpoolField");
  return spoolmanCreateSpoolField(base_url, field_name, timeout_ms);
}

// ============================================================
//  WRITING
// ============================================================

int backendPatchSpoolTag(const char* base_url, int spool_id, const char* uuid,
                         uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // Both tag types go into the native rfid_uid. An empty uuid unlinks.
      return filamanPatchRfidUid(backendBaseUrl(), filamanApiKey(), spool_id, uuid, timeout_ms);
    case BACKEND_BAMBUDDY:
      return notSupported("PatchSpoolTag");
    default:
      return spoolmanPatchSpoolTag(base_url, spool_id, uuid, timeout_ms);
  }
}

int backendPatchSpoolRemaining(const char* base_url, int spool_id, float remaining,
                               const char* last_used_iso, const char* tag_uuid,
                               float measured_g, uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN: {
      // FilaMan does the arithmetic on its side. Handing it the remaining
      // weight would subtract the empty spool weight a second time.
      float gross = (measured_g >= 0.0f) ? measured_g : (remaining + sm_spool_weight);
      (void)last_used_iso;   // FilaMan stamps last_used_at itself
      return filamanReportWeight(backendBaseUrl(), filamanDeviceToken(),
                                 spool_id, tag_uuid, gross, timeout_ms);
    }
    case BACKEND_BAMBUDDY:
      // Wants the gross weight too, like FilaMan - it subtracts core_weight
      // itself. Verified against BamBuddy 1.2.5.3 on 21.08.2026.
      return notSupported("PatchSpoolRemaining");
    default:
      (void)tag_uuid;    // Spoolman identifies the spool by id only
      (void)measured_g;
      return spoolmanPatchSpoolRemaining(base_url, spool_id, remaining, last_used_iso, timeout_ms);
  }
}

int backendPatchInitialWeight(const char* base_url, int spool_id, float initial_weight,
                              uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // Both fields, like the Spoolman side does. Writing only the initial weight
      // leaves the old remaining in place, so the spool reads as full on the
      // device - which updates its copy optimistically - and as half empty on the
      // server until the next scan corrects the display back.
      return filamanPatchSpoolFloat2(backendBaseUrl(), filamanApiKey(), spool_id,
                                     "initial_total_weight_g", initial_weight,
                                     "remaining_weight_g", initial_weight, timeout_ms);
    case BACKEND_BAMBUDDY:
      return notSupported("PatchInitialWeight");
    default:
      return spoolmanPatchInitialWeight(base_url, spool_id, initial_weight, timeout_ms);
  }
}

int backendPatchArchiveSpool(const char* base_url, int spool_id, uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // Not a PATCH in FilaMan, archiving has its own endpoint.
      return filamanSetStatus(backendBaseUrl(), filamanApiKey(), spool_id, "archived", timeout_ms);
    case BACKEND_BAMBUDDY:
      return notSupported("PatchArchiveSpool");
    default:
      return spoolmanPatchArchiveSpool(base_url, spool_id, timeout_ms);
  }
}

int backendPatchSpoolWeight(const char* base_url, int spool_id, float spool_weight,
                            uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanPatchSpoolFloat(backendBaseUrl(), filamanApiKey(), spool_id,
                                    "empty_spool_weight_g", spool_weight, timeout_ms);
    case BACKEND_BAMBUDDY:
      // Only reaches the database in BamBuddy's own inventory. With Spoolman
      // behind it the proxy accepts core_weight and drops it, so that mode has
      // to keep answering "not supported" rather than reporting a false success.
      return notSupported("PatchSpoolWeight");
    default:
      return spoolmanPatchSpoolWeight(base_url, spool_id, spool_weight, timeout_ms);
  }
}

int backendPatchFilamentSpoolWeight(const char* base_url, int filament_id, float spool_weight,
                                    uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanPatchFilamentFloat(backendBaseUrl(), filamanApiKey(), filament_id,
                                       "default_spool_weight_g", spool_weight, timeout_ms);
    case BACKEND_BAMBUDDY:
      // BamBuddy has no filament type as an object, brand and material are
      // plain strings on the spool. There is nothing to patch.
      return notSupported("PatchFilamentSpoolWeight");
    default:
      return spoolmanPatchFilamentSpoolWeight(base_url, filament_id, spool_weight, timeout_ms);
  }
}

int backendPatchVendorEmptySpoolWeight(const char* base_url, int vendor_id, float spool_weight,
                                       uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // Spoolman's vendor is FilaMan's manufacturer, the field name is the same
      // apart from the unit suffix.
      return filamanPatchManufacturerFloat(backendBaseUrl(), filamanApiKey(), vendor_id,
                                           "empty_spool_weight_g", spool_weight, timeout_ms);
    case BACKEND_BAMBUDDY:
      // No vendor object either, same reason as the filament above.
      return notSupported("PatchVendorEmptySpoolWeight");
    default:
      return spoolmanPatchVendorEmptySpoolWeight(base_url, vendor_id, spool_weight, timeout_ms);
  }
}

int backendPatchSpoolLocation(const char* base_url, int spool_id, const char* location_name,
                              uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // FilaMan stores a location_id, so the name is resolved on the way out.
      return filamanPatchSpoolLocation(backendBaseUrl(), filamanApiKey(), spool_id,
                                       location_name, timeout_ms);
    case BACKEND_BAMBUDDY:
      return notSupported("PatchSpoolLocation");
    default:
      return spoolmanPatchSpoolLocation(base_url, spool_id, location_name, timeout_ms);
  }
}

int backendPatchSpoolLastDried(const char* base_url, int spool_id, const char* iso_datetime,
                               uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // The only write that needs a read first: a PATCH on custom_fields
      // replaces the whole object rather than merging.
      return filamanPatchCustomField(backendBaseUrl(), filamanApiKey(), spool_id,
                                     "last_dried", iso_datetime, timeout_ms);
    case BACKEND_BAMBUDDY:
      // BamBuddy has no field for this at all, upstream issues #2863 and #1754.
      // Phase 1 picks one of three routes from a setting.
      return notSupported("PatchSpoolLastDried");
    default:
      return spoolmanPatchSpoolLastDried(base_url, spool_id, iso_datetime, timeout_ms);
  }
}
