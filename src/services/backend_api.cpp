#include "backend_api.h"

#include <ctype.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/bambuddy_api.h"
#include "services/bambuddy_device.h"
#include "services/filaman_api.h"
#include "services/list_limits.h"
#include "services/device_name.h"
#include "services/spoolman_api.h"
#include "services/tag_field.h"
#include "services/tag_uid.h"
#include "services/user_options.h"

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

void backendRefreshMode() {
  if (backendMode() != BACKEND_BAMBUDDY) return;
  bbDetectInventoryMode(backendBaseUrl(), bambuddyApiKey(), 4000);
}

void backendAfterConnect() {
  if (backendMode() != BACKEND_BAMBUDDY) return;
  // The server on the other end may be a different one than before, so the
  // device presence starts over rather than heartbeating at a stale id.
  bambuddyDeviceReset();
  // Deliberately not cached behind a "done" flag: the address or the key can
  // change between two calls, and the answer is one small request.
  bbDetectInventoryMode(backendBaseUrl(), bambuddyApiKey());
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
      return bbGetSpoolJson(backendBaseUrl(), bambuddyApiKey(), spool_id,
                            doc, timeout_ms, out_err);
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
      // Same reason as FilaMan: the answer is rebuilt field by field, so a
      // Spoolman field filter has nothing to act on.
      (void)filter;
      return bbGetSpoolListJson(backendBaseUrl(), bambuddyApiKey(), allow_archived,
                                doc, timeout_ms, out_err);
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
    case BACKEND_FILAMAN: {
      // FilaMan filters server side, so a scan costs one small answer instead
      // of the whole inventory. The translation only produces the keys the UI
      // reads, so the caller's field filter does not apply.
      (void)filter;
      // In the notation rfid_uid actually holds. ?search= is a substring
      // match, so the colon form finds nothing in a field written as plain
      // hex - which is what FilaMan's own reader writes, what this firmware
      // writes since the notation was unified, and therefore very nearly
      // everything. Sending the raw uid here left the fast path failing on
      // every scan and the whole inventory being pulled instead.
      char hex[40];
      tagUidNormalize(tag_uuid, hex, sizeof(hex));
      return filamanGetSpoolListJson(backendBaseUrl(), filamanApiKey(), false,
                                     doc, hex[0] ? hex : tag_uuid, 20,
                                     timeout_ms, out_err);
    }
    case BACKEND_BAMBUDDY:
      // Answered through the device protocol, which is the only lookup that
      // works in both of BamBuddy's inventory modes.
      (void)filter;
      return bbFindSpoolByTag(backendBaseUrl(), bambuddyApiKey(), tag_uuid,
                              doc, timeout_ms, out_err);
    default:
      // Spoolman goes through whichever extra field the user selected. The
      // field filter is passed along because a server that ignores the query
      // parameter answers with everything: that case still works, and this
      // keeps it from costing more memory than the normal full scan would.
      return backendFindSpoolByTagField(tagFieldEffective(), base_url, tag_uuid, doc,
                                        timeout_ms, out_err, filter);
  }
}

int backendFindSpoolByTagField(uint8_t field_id, const char* base_url, const char* uid,
                               JsonDocument& doc, uint32_t timeout_ms,
                               DeserializationError* out_err, JsonDocument* filter) {
  if (!uid || !uid[0]) return BACKEND_NOT_SUPPORTED;
  // The tag field conventions are agreements between programs that write into
  // Spoolman. FilaMan has its native rfid_uid column and BamBuddy a fixed
  // schema, so there is no extra field to search there.
  if (backendMode() != BACKEND_SPOOLMAN) return notSupported("FindSpoolByTagField");

  const TagFieldSpec& spec = tagFieldSpec(field_id);

  // The gate that keeps the fast path fast. Spoolman ignores a filter on a
  // field it does not have and answers with the whole inventory - which looks
  // like a hit, costs the full transfer, and would quietly undo the entire
  // point of searching server side.
  if (!backendHasExtraField(spec.key)) return BACKEND_NOT_SUPPORTED;

  // Formatted for the field it is going to: plain hex where the field stores
  // plain hex, verbatim where it does not. Sending the colon form at a field
  // that holds none would never match the ilike.
  char value[CARD_UIDS_MAX];
  tagFieldFormat(spec, uid, value, sizeof(value));
  if (!value[0]) return BACKEND_NOT_SUPPORTED;

  return spoolmanFindSpoolByExtraField(base_url, spec.key, value, doc,
                                       timeout_ms, filter, out_err);
}

// Which of the fields the scale knows a key is, or -1 for one it never asks
// about. The probe below fills one bit per entry, so this ordering is the
// only thing tying the mask to the keys.
static int knownFieldIndex(const char* key) {
  if (!key || !key[0]) return -1;
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++)
    if (strcmp(key, tagFieldSpec(i).key) == 0) return (int)i;
  if (strcmp(key, LAST_DRIED_FIELD) == 0) return TAG_FIELD_EXTRA_COUNT;
  return -1;
}

// Cached against the URL it was probed for, so pointing the scale at another
// instance re-probes without anyone having to remember to invalidate.
static char    s_fields_probed_for[96] = {0};
static uint8_t s_fields_mask = 0;

// Every text field the server has, not just the three this firmware writes.
// A spool can carry a tag UID in any of them - active_tray gets one from
// OpenSpoolman, and people invent their own - and the full inventory scan
// compares against all of them so a spool is found whatever field it sits in.
//
// Capped rather than grown: this is read into a fixed filter and a fixed
// comparison, and a server with a hundred custom fields must not be able to
// turn one tag lookup into an unbounded one.
#define BACKEND_TEXT_FIELDS_MAX  16
#define BACKEND_FIELD_KEY_MAX    40
static char    s_text_fields[BACKEND_TEXT_FIELDS_MAX][BACKEND_FIELD_KEY_MAX] = {};
static uint8_t s_text_field_count = 0;

// Same idea for the native tag API, kept beside the field cache because both
// answer "what can this server do" and both go stale for the same reason.
static char s_tagapi_probed_for[96] = {0};
static bool s_tagapi_present = false;

void backendInvalidateExtraFieldCache() {
  s_fields_probed_for[0] = '\0';
  s_fields_mask = 0;
  s_text_field_count = 0;
  s_tagapi_probed_for[0] = '\0';
  s_tagapi_present = false;
}

bool backendHasNativeTags() {
  if (backendMode() != BACKEND_SPOOLMAN) return false;

  const char* base = backendBaseUrl();
  if (!base || !base[0]) return false;

  if (strncmp(s_tagapi_probed_for, base, sizeof(s_tagapi_probed_for) - 1) == 0)
    return s_tagapi_present;

  int code = spoolmanHasTagApi(base);
  if (code == 200) {
    s_tagapi_present = true;
  } else if (code == 404) {
    s_tagapi_present = false;
  } else {
    // Anything else says nothing about the feature - an unreachable server, a
    // proxy in the way, a timeout. Caching that as a no would keep the native
    // path off for the whole session over one bad moment.
    logSDf("native tags: probe inconclusive, code=%d", code);
    return false;
  }

  strncpy(s_tagapi_probed_for, base, sizeof(s_tagapi_probed_for) - 1);
  s_tagapi_probed_for[sizeof(s_tagapi_probed_for) - 1] = '\0';
  logSDf("native tags: %s on %s", s_tagapi_present ? "supported" : "absent", base);
  return s_tagapi_present;
}

// A stable id for this scale in Spoolman's reader list, derived from the MAC
// so it survives reboots and tells two scales apart.
const char* backendReaderId() {
  static char id[32] = {0};
  if (!id[0]) {
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(id, sizeof(id), "spoolmanscale-%02X%02X%02X", mac[3], mac[4], mac[5]);
  }
  return id;
}

int backendTagScan(const char* base_url, const char* uid, const char* format,
                   JsonDocument& doc, uint32_t timeout_ms, DeserializationError* out_err) {
  if (!backendHasNativeTags()) return notSupported("TagScan");
  // The name is what Spoolman's reader picker shows. Two scales would
  // otherwise sit there under one label, distinguishable only by the reader id
  // nobody sees, so the name the user gave this device goes out instead.
  // deviceLabel() is never empty and falls back to the product name itself.
  const char* name = deviceLabel();
  return spoolmanTagScan(base_url, uid, backendReaderId(),
                         (name && name[0]) ? name : "SpoolmanScale",
                         format, doc, timeout_ms, out_err);
}

int backendLinkTag(const char* base_url, int spool_id, const char* uid,
                   const char* format, int* out_conflict_spool_id, uint32_t timeout_ms) {
  if (!backendHasNativeTags()) return notSupported("LinkTag");
  return spoolmanLinkTag(base_url, spool_id, uid, format, out_conflict_spool_id, timeout_ms);
}

int backendUnlinkTag(const char* base_url, int spool_id, const char* uid,
                     uint32_t timeout_ms) {
  if (!backendHasNativeTags()) return notSupported("UnlinkTag");
  return spoolmanUnlinkTag(base_url, spool_id, uid, timeout_ms);
}

int backendFindSpoolByNativeTag(const char* base_url, const char* uid,
                                JsonDocument& doc, uint32_t timeout_ms,
                                JsonDocument* filter, DeserializationError* out_err) {
  if (!uid || !uid[0]) return BACKEND_NOT_SUPPORTED;
  if (!backendHasNativeTags()) return notSupported("FindSpoolByNativeTag");
  return spoolmanFindSpoolByNativeTag(base_url, uid, doc, timeout_ms, filter, out_err);
}

bool backendHasExtraField(const char* key) {
  if (backendMode() != BACKEND_SPOOLMAN) return false;

  const char* base = backendBaseUrl();
  if (!base || !base[0]) return false;

  const int idx = knownFieldIndex(key);
  if (idx < 0) return false;

  if (strncmp(s_fields_probed_for, base, sizeof(s_fields_probed_for) - 1) != 0) {
    // One GET returns every field definition, so all of them are settled at
    // once. Probing per key would cost a request each and could answer
    // inconsistently halfway through.
    //
    // Plain document on purpose: the field list holds a handful of
    // definitions, a few hundred bytes, and is nothing like the spool
    // inventory that needs PSRAM.
    JsonDocument doc;
    DeserializationError err = DeserializationError::Ok;
    int code = spoolmanGetSpoolFieldsJson(base, doc, 5000, &err);
    if (code != 200 || err) {
      // Not cached: an unreachable server now says nothing about the fields,
      // and caching a "no" here would keep them off for the whole session.
      logSDf("extra fields: probe failed, code=%d err=%s", code, err.c_str());
      return false;
    }

    uint8_t mask = 0;
    s_text_field_count = 0;
    for (JsonObjectConst f : doc.as<JsonArrayConst>()) {
      const char* key = f["key"] | "";
      const int i = knownFieldIndex(key);
      if (i >= 0) mask |= (uint8_t)(1u << i);

      // Text only, and short enough to be a field key rather than a value that
      // wandered into one. Anything longer is skipped rather than truncated:
      // a shortened key would filter on a field that does not exist.
      if (strcmp(f["field_type"] | "", "text") != 0) continue;
      if (!key[0] || strlen(key) >= BACKEND_FIELD_KEY_MAX) continue;
      if (s_text_field_count >= BACKEND_TEXT_FIELDS_MAX) continue;
      strncpy(s_text_fields[s_text_field_count], key, BACKEND_FIELD_KEY_MAX - 1);
      s_text_fields[s_text_field_count][BACKEND_FIELD_KEY_MAX - 1] = '\0';
      s_text_field_count++;
    }
    s_fields_mask = mask;
    strncpy(s_fields_probed_for, base, sizeof(s_fields_probed_for) - 1);
    s_fields_probed_for[sizeof(s_fields_probed_for) - 1] = '\0';
    logSDf("extra fields on %s: tag=%d nfc_id=%d card_uids=%d last_dried=%d",
           base,
           (mask >> TAG_FIELD_TAG)       & 1, (mask >> TAG_FIELD_NFC_ID)  & 1,
           (mask >> TAG_FIELD_CARD_UIDS) & 1, (mask >> TAG_FIELD_EXTRA_COUNT) & 1);
    logSDf("extra fields on %s: %d text field(s) to compare against",
           base, (int)s_text_field_count);
  }

  return ((s_fields_mask >> idx) & 1u) != 0;
}

uint8_t backendSpoolTextFieldCount() {
  // Extra fields are a Spoolman convention. Guarded explicitly rather than
  // left to the probe: backendHasExtraField() answers false for the other
  // backends without touching the list, so a count filled while pointed at a
  // Spoolman server would survive the switch and leak into their filters.
  if (backendMode() != BACKEND_SPOOLMAN) return 0;
  // The probe lives in backendHasExtraField(); asking it anything fills the
  // list as a side effect, so one call settles both. The key is one this
  // firmware knows, so the answer itself is not what matters here.
  (void)backendHasExtraField(tagFieldSpec(TAG_FIELD_TAG).key);
  return s_text_field_count;
}

const char* backendSpoolTextFieldKey(uint8_t index) {
  return index < s_text_field_count ? s_text_fields[index] : "";
}

int backendPatchExtraField(const char* base_url, int spool_id, const char* key,
                           const char* value, uint32_t timeout_ms) {
  if (backendMode() != BACKEND_SPOOLMAN) return notSupported("PatchExtraField");
  int code = spoolmanPatchExtraField(base_url, spool_id, key, value, timeout_ms);

  // A write that succeeds against a field the cache calls absent means the
  // cache is wrong - the field came into existence somewhere other than our
  // assistant. Left alone it would keep saying "absent" for the whole session,
  // and everything gated on it stays off: the server side search for that
  // field, and the append path. Both would fail quietly, which is the worst
  // way for them to fail.
  if (code >= 200 && code < 300 && !backendHasExtraField(key)) {
    logSDf("extra fields: '%s' accepted a write but was cached as absent, re-probing", key);
    backendInvalidateExtraFieldCache();
  }
  return code;
}

int backendGetLocationsJson(const char* base_url, JsonDocument& doc,
                            uint32_t timeout_ms, DeserializationError* out_err) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanGetLocationsJson(backendBaseUrl(), filamanApiKey(), doc,
                                     timeout_ms, out_err);
    case BACKEND_BAMBUDDY:
      return bbGetLocationsJson(backendBaseUrl(), bambuddyApiKey(), doc,
                                timeout_ms, out_err);
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
      // Two requests rather than one: BamBuddy has no /health, and the
      // second one is what tells a rejected key from an absent server.
      return bbGetHealthCode(backendBaseUrl(), bambuddyApiKey(), timeout_ms);
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
      return bbGetVersion(backendBaseUrl(), bambuddyApiKey(), out_version,
                          out_size, timeout_ms);
    default:
      return spoolmanGetVersion(base_url, out_version, out_size, timeout_ms);
  }
}

int backendCountActiveSpools(const char* base_url, uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanCountActiveSpools(backendBaseUrl(), filamanApiKey(), timeout_ms);
    case BACKEND_BAMBUDDY:
      return bbCountActiveSpools(backendBaseUrl(), bambuddyApiKey(), timeout_ms);
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

bool backendCanTareSpool() {
  if (backendMode() != BACKEND_BAMBUDDY) return true;
  // Only BamBuddy's own database keeps core_weight on the spool. Behind the
  // Spoolman proxy the field is accepted and discarded.
  return bbInventoryMode() == BB_INV_LOCAL;
}

bool backendCanTareFilamentOrVendor() {
  // BamBuddy has no filament type and no vendor as objects - brand and
  // material are plain strings on the spool, so there is nothing to write to.
  return backendMode() != BACKEND_BAMBUDDY;
}

// ============================================================
//  CREATING
// ============================================================

int backendCreateSpool(const char* base_url, int template_spool_id, int filament_id,
                       float initial_weight, float spool_weight, float remaining_weight,
                       int* out_spool_id, uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // The tag is attached by the caller in a separate step, same as with
      // Spoolman, so the flow stays identical for both backends.
      return filamanCreateSpool(backendBaseUrl(), filamanApiKey(), filament_id,
                                initial_weight, spool_weight, remaining_weight,
                                nullptr, out_spool_id, timeout_ms);
    case BACKEND_BAMBUDDY: {
      // No filament_id exists here, so the template is read back instead. Raw,
      // because the mapped form folds subtype and color_name into one name and
      // trims rgba down to six characters - a copy built from it would be
      // poorer than the spool it was copied from.
      if (template_spool_id <= 0) return notSupported("CreateSpool");

      // Plain document: this is one spool, a couple of kilobytes, nothing like
      // the inventory listing that needs PSRAM. Same reasoning as the field
      // probe above.
      JsonDocument tpl;
      int code = bbGetSpoolRawJson(backendBaseUrl(), bambuddyApiKey(), template_spool_id,
                                   tpl, timeout_ms);
      if (code != 200) {
        logSDf("BamBuddy: copy template %d unreadable (HTTP %d), nothing created",
               template_spool_id, code);
        return code;
      }

      BbNewSpool ns;
      ns.material   = tpl["material"]   | "";
      ns.subtype    = tpl["subtype"]    | "";
      ns.brand      = tpl["brand"]      | "";
      ns.color_name = tpl["color_name"] | "";
      ns.rgba       = tpl["rgba"]       | "";
      // The scale's reading wins over the template for how full the spool is,
      // the template only says how big it is.
      ns.label_weight = tpl["label_weight"] | (int)initial_weight;
      ns.core_weight  = tpl["core_weight"]  | (int)spool_weight;
      ns.weight_used  = (float)ns.label_weight - remaining_weight;
      if (ns.weight_used < 0.0f) ns.weight_used = 0.0f;

      return bbCreateSpool(backendBaseUrl(), bambuddyApiKey(), ns, out_spool_id,
                           timeout_ms);
    }
    default:
      return spoolmanCreateSpool(base_url, filament_id, initial_weight, spool_weight,
                                 remaining_weight, out_spool_id, timeout_ms);
  }
}

bool backendCanCreateFromTag() {
  return backendMode() == BACKEND_BAMBUDDY;
}

void backendLookupColorName(const char* hex6, const char* material,
                            char* out_name, size_t out_size) {
  if (out_name && out_size) out_name[0] = '\0';
  // Only BamBuddy keeps such a catalogue. The other two backends leave the
  // name empty, which their create paths do not need anyway.
  if (backendMode() != BACKEND_BAMBUDDY) return;
  bbLookupColorName(backendBaseUrl(), bambuddyApiKey(), hex6, material,
                    out_name, out_size);
}

int backendCreateSpoolFromTag(const char* material, const char* subtype,
                              const char* brand, const char* rgba,
                              const char* color_name,
                              int label_weight, int core_weight, float remaining_weight,
                              int nozzle_temp_min, int nozzle_temp_max,
                              int* out_spool_id, uint32_t timeout_ms) {
  if (out_spool_id) *out_spool_id = 0;
  if (backendMode() != BACKEND_BAMBUDDY) return notSupported("CreateSpoolFromTag");

  BbNewSpool ns;
  ns.material        = material;
  ns.subtype         = subtype;
  ns.brand           = brand;
  ns.rgba            = rgba;
  ns.color_name      = color_name;
  ns.label_weight    = label_weight;
  ns.core_weight     = core_weight;
  ns.nozzle_temp_min = nozzle_temp_min;
  ns.nozzle_temp_max = nozzle_temp_max;
  ns.weight_used = (float)label_weight - remaining_weight;
  if (ns.weight_used < 0.0f) ns.weight_used = 0.0f;

  return bbCreateSpool(backendBaseUrl(), bambuddyApiKey(), ns, out_spool_id, timeout_ms);
}

int backendCreateSpoolField(const char* base_url, const char* field_name,
                            uint32_t timeout_ms) {
  // Creating system extra fields in FilaMan appears to need admin rights,
  // so this may stay unsupported on purpose. See integration doc.
  // BamBuddy has no extra fields to create.
  if (backendIsFilaMan() || backendIsBamBuddy()) return notSupported("CreateSpoolField");
  int code = spoolmanCreateSpoolField(base_url, field_name, timeout_ms);
  // The probe cache would otherwise keep answering "absent" for the rest of
  // the session, and the field the user just created would stay unusable.
  if (code == 200 || code == 201) backendInvalidateExtraFieldCache();
  return code;
}

// ============================================================
//  WRITING
// ============================================================

int backendPatchSpoolTag(const char* base_url, int spool_id, const char* uuid,
                         uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN: {
      // Both tag types go into the native rfid_uid. An empty uuid unlinks.
      //
      // Plain hex like everywhere else. FilaMan's own reader writes it that
      // way, so the colon form this used to send was the odd one out in its
      // own database and missed the server side ?search= for anything not
      // written by this scale.
      if (!uuid || !uuid[0]) {
        return filamanPatchRfidUid(backendBaseUrl(), filamanApiKey(), spool_id, nullptr, timeout_ms);
      }
      char hex[40];
      tagUidNormalize(uuid, hex, sizeof(hex));
      return filamanPatchRfidUid(backendBaseUrl(), filamanApiKey(), spool_id, hex, timeout_ms);
    }
    case BACKEND_BAMBUDDY: {
      // An empty uuid means unlink, and that is a different request: the
      // link endpoint can only write. Without this the call fell through to
      // bbLinkTag with nothing to link and failed with -1.
      if (!uuid || !uuid[0]) {
        return bbUnlinkTag(backendBaseUrl(), bambuddyApiKey(), spool_id, timeout_ms);
      }
      // A 32 character identifier is a Bambu tray uuid, anything shorter an
      // NFC tag uid. Separators are stripped on the way: the Spoolman mode
      // endpoint validates plain hex and answers 422 otherwise.
      char hex[40];
      tagUidNormalize(uuid, hex, sizeof(hex));
      const bool is_tray = (strlen(hex) == 32);
      return bbLinkTag(backendBaseUrl(), bambuddyApiKey(), spool_id,
                       is_tray ? nullptr : hex, is_tray ? hex : nullptr, timeout_ms);
    }
    default: {
      // Whichever extra field the user picked, in that field's own notation.
      // A list field reached through here gets a one entry list, which is
      // exactly what it should hold for a spool with a single tag; the merge
      // for a second one happens in patchSpoolTag() before this is called.
      const TagFieldSpec& spec = tagFieldSelected();
      char value[CARD_UIDS_MAX];
      if (uuid && uuid[0]) tagFieldFormat(spec, uuid, value, sizeof(value));
      else                 value[0] = '\0';   // an empty value is the unlink
      return backendPatchExtraField(base_url, spool_id, spec.key, value, timeout_ms);
    }
  }
}

int backendLinkSpoolTag(const char* base_url, int spool_id, const char* uuid,
                        char* out_note, size_t note_size, uint32_t timeout_ms) {
  if (out_note && note_size) out_note[0] = '\0';
  if (backendIsFilaMan()) {
    return filamanLinkRfidUid(backendBaseUrl(), filamanApiKey(), spool_id, uuid,
                              out_note, note_size, timeout_ms);
  }
  // Only FilaMan's rfid_uid is unique. The rest take the ordinary write,
  // which already knows how to reach each backend.
  return backendPatchSpoolTag(base_url, spool_id, uuid, timeout_ms);
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
    case BACKEND_BAMBUDDY: {
      // Wants the gross weight too, like FilaMan - it subtracts core_weight
      // itself and derives weight_used. Verified against BamBuddy 1.2.5.3 on
      // 21.08.2026: 700 g gross with a core of 251 became 551 g used.
      float gross = (measured_g >= 0.0f) ? measured_g : (remaining + sm_spool_weight);
      (void)last_used_iso;   // BamBuddy stamps last_weighed_at itself
      (void)tag_uuid;        // identified by id
      return bbUpdateSpoolWeight(backendBaseUrl(), bambuddyApiKey(), spool_id,
                                 gross, timeout_ms);
    }
    default: {
      (void)tag_uuid;    // Spoolman identifies the spool by id only

      // Hand Spoolman the gross weight and let it do the arithmetic, the same
      // way FilaMan and BamBuddy already get it. That is what /measure is for,
      // it stamps first_used and last_used on its own, and it makes all three
      // backends behave alike.
      //
      // The gross value is `remaining + sm_spool_weight`, so it is exactly what
      // the pad showed. Handing it over is only safe while Spoolman resolves
      // the same tare we did, and it does for the first two levels: spool, then
      // filament. It does NOT walk up to the vendor - it falls back to zero
      // there - so a vendor-only tare would come back with the core mass booked
      // as filament. Donkie/Spoolman#1117. In that case the explicit PATCH
      // stays, where this firmware has already subtracted the right number.
      if (measured_g >= 0.0f && sm_tare_source != TARE_VENDOR) {
        int code = spoolmanMeasureSpool(base_url, spool_id, measured_g, timeout_ms);
        // 404 is the spool, 405 a server that predates the endpoint. Anything
        // in that range means "not this way", and the spool still needs its
        // weight, so fall through rather than report a failure.
        if (code != 404 && code != 405) return code;
        logSDf("measure not available (HTTP %d), falling back to PATCH", code);
      }
      return spoolmanPatchSpoolRemaining(base_url, spool_id, remaining, last_used_iso, timeout_ms);
    }
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
    case BACKEND_BAMBUDDY: {
      // Both numbers again, for the same reason as FilaMan. BamBuddy stores
      // what was consumed, so a full spool is label_weight with nothing used.
      const int   label = (int)initial_weight;
      const float used  = 0.0f;
      return bbPatchSpoolFields(backendBaseUrl(), bambuddyApiKey(), spool_id,
                                &label, nullptr, &used, nullptr, nullptr, timeout_ms);
    }
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
      return bbArchiveSpool(backendBaseUrl(), bambuddyApiKey(), spool_id, timeout_ms);
    default:
      return spoolmanPatchArchiveSpool(base_url, spool_id, timeout_ms);
  }
}

int backendReactivateSpool(const char* base_url, int spool_id, float remaining,
                           float gross, uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN: {
      // Archived is status 6 there, so coming back is a status change. "active"
      // rather than "new": the spool has been used, and saying otherwise would
      // undo what the user knows about it.
      int code = filamanSetStatus(backendBaseUrl(), filamanApiKey(), spool_id,
                                  "active", timeout_ms);
      if (code < 200 || code >= 300) return code;
      // FilaMan cleared the remaining weight when it archived (see
      // filaman_api.cpp), so the weight has to follow, and it wants gross.
      return filamanReportWeight(backendBaseUrl(), filamanDeviceToken(),
                                 spool_id, nullptr, gross, timeout_ms);
    }
    case BACKEND_BAMBUDDY: {
      int code = bbRestoreSpool(backendBaseUrl(), bambuddyApiKey(), spool_id, timeout_ms);
      if (code < 200 || code >= 300) return code;
      return bbUpdateSpoolWeight(backendBaseUrl(), bambuddyApiKey(), spool_id,
                                 gross, timeout_ms);
    }
    default:
      // One request: unarchiving and the weight belong together, and a second
      // call that fails would leave the spool back but reading as empty.
      return spoolmanReactivateSpool(base_url, spool_id, remaining, timeout_ms);
  }
}

int backendSetSpoolStatus(const char* base_url, int spool_id, const char* status_key,
                          uint32_t timeout_ms) {
  (void)base_url;
  if (backendMode() != BACKEND_FILAMAN) return notSupported("SetSpoolStatus");
  return filamanSetStatus(backendBaseUrl(), filamanApiKey(), spool_id, status_key, timeout_ms);
}

int backendPatchSpoolWeight(const char* base_url, int spool_id, float spool_weight,
                            uint32_t timeout_ms) {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanPatchSpoolFloat(backendBaseUrl(), filamanApiKey(), spool_id,
                                    "empty_spool_weight_g", spool_weight, timeout_ms);
    case BACKEND_BAMBUDDY: {
      // Only reaches the database in BamBuddy's own inventory. With Spoolman
      // behind it the proxy accepts core_weight and drops it, so that mode
      // answers "not supported" rather than reporting a false success.
      if (bbInventoryMode() == BB_INV_SPOOLMAN) return notSupported("PatchSpoolWeight");
      const int core = (int)spool_weight;
      return bbPatchSpoolFields(backendBaseUrl(), bambuddyApiKey(), spool_id,
                                nullptr, &core, nullptr, nullptr, nullptr, timeout_ms);
    }
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
      // A plain string on the spool, no id to resolve. BamBuddy creates the
      // location entry on the fly when the name is new.
      return bbPatchSpoolFields(backendBaseUrl(), bambuddyApiKey(), spool_id,
                                nullptr, nullptr, nullptr,
                                location_name ? location_name : "", nullptr, timeout_ms);
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
      // BamBuddy has no field for this at all - upstream issues #2863 and
      // #1754 are open. The user picks where it goes instead.
      switch (g_bb_dried_target) {
        case BB_DRIED_SPOOLMAN:
          // Past BamBuddy, straight into the Spoolman database behind it.
          // Only possible in that mode, and only once the url is known.
          if (bbInventoryMode() != BB_INV_SPOOLMAN || !bbSpoolmanUrl()[0]) {
            return notSupported("PatchSpoolLastDried");
          }
          return spoolmanPatchSpoolLastDried(bbSpoolmanUrl(), spool_id,
                                             iso_datetime, timeout_ms);
        case BB_DRIED_NOTE:
          return bbPatchDriedNote(backendBaseUrl(), bambuddyApiKey(), spool_id,
                                  iso_datetime, timeout_ms);
        default:
          return notSupported("PatchSpoolLastDried");
      }
    default:
      return spoolmanPatchSpoolLastDried(base_url, spool_id, iso_datetime, timeout_ms);
  }
}
