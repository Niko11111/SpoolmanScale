#include "backend_api.h"

#include <ctype.h>
#include <esp_mac.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/bambuddy_api.h"
#include "services/bambuddy_device.h"
#include "services/filaman_api.h"
#include "services/http_progress.h"
#include "services/list_limits.h"
#include "services/device_name.h"
#include "services/spoolman_api.h"
#include "services/tag_field.h"
#include "services/tag_uid.h"
#include "services/text_util.h"
#include "services/time_service.h"
#include "services/user_options.h"

// Rows per request when FilaMan lists spools. The render limit is applied by
// the caller; this used to be "spool_list_limit if above 100, else 100", and
// the limit is clamped to 100, so it was always 100.
#define FILAMAN_LIST_PAGE_ROWS  100
// Creating a missing extra field before its first write: one small POST.
#define FIELD_CREATE_TIMEOUT_MS 4000

// A missing backend path must show up in the log instead of looking like a
// silent failure, but the periodic health check would repeat the same line
// every 30 seconds and bury everything else. Each call site is therefore
// logged only once per boot. The names are string literals, so comparing
// pointers is enough to tell them apart.
static int notSupported(const char* fn) {
  static const char* logged[32] = { nullptr };
  static uint8_t logged_count = 0;
  static uint8_t logged_mode  = 0xFF;

  // Once per call site and per backend: a switch starts the table over, so a
  // support log from a user who changed backends still names the gaps of the
  // one they are on.
  if (logged_mode != (uint8_t)backendMode()) {
    logged_mode  = (uint8_t)backendMode();
    logged_count = 0;
  }
  for (uint8_t i = 0; i < logged_count; i++) {
    if (logged[i] == fn) return BACKEND_NOT_SUPPORTED;
  }
  // A full table stays quiet rather than logging every call: the health
  // check would otherwise write the same line every 30 seconds.
  if (logged_count >= (sizeof(logged) / sizeof(logged[0]))) return BACKEND_NOT_SUPPORTED;
  logged[logged_count++] = fn;
  logSDf("Backend: %s has no %s implementation yet", fn, backendName());
  return BACKEND_NOT_SUPPORTED;
}

bool backendLastListPartial() {
  return backendMode() == BACKEND_FILAMAN && filamanLastListPartial();
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
                            DeserializationError* out_err, bool archived_only) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  // Spoolman and BamBuddy have no such filter (allow_archived / include_archived
  // is all or active only): they are asked for everything.
  if (archived_only) allow_archived = true;
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      // The Spoolman JSON filter does not apply, FilaMan is translated field by
      // field and only the keys the UI reads are produced anyway.
      (void)filter;
      return filamanGetSpoolListJson(backendBaseUrl(), filamanApiKey(), allow_archived,
                                     doc, nullptr, FILAMAN_LIST_PAGE_ROWS,
                                     timeout_ms, out_err, archived_only);
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  // Probed like a tag field without being one: the companion write is gated on
  // it, and a key the probe does not know reads as absent for the whole
  // session, so the write would never happen and never say why. It would also
  // make every successful write throw the field cache away, see
  // backendPatchExtraField() below.
  if (strcmp(key, RFID_TAG_FIELD)   == 0) return TAG_FIELD_EXTRA_COUNT + 1;
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
  // FilaMan's second slot is the same kind of answer about the same server,
  // and it goes stale for the same reason. Its cache lives in filaman_api.cpp
  // because that is where the probe is, not because it is a different thing.
  filamanForgetRfidSlot2();
}

int backendNativeTagsCached() {
  if (backendMode() != BACKEND_SPOOLMAN) return 0;
  const char* base = backendBaseUrl();
  if (!base || !base[0]) return -1;
  if (strncmp(s_tagapi_probed_for, base, sizeof(s_tagapi_probed_for) - 1) != 0)
    return -1;                       // nobody has asked this server yet
  return s_tagapi_present ? 1 : 0;
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

bool backendNativeTagsAbsent() {
  if (backendMode() != BACKEND_SPOOLMAN) return false;

  const char* base = backendBaseUrl();
  if (!base || !base[0]) return false;

  // Never asked, or asked about a different server. Both mean "no answer", and
  // an answer is what this is for.
  if (strncmp(s_tagapi_probed_for, base, sizeof(s_tagapi_probed_for) - 1) != 0)
    return false;

  return !s_tagapi_present;
}

// The last answer below, for callers that must not reach the network - the
// tag page asks every three seconds from a web handler. -1 until the first.
static int8_t s_second_tag_known = -1;
int backendSecondTagKnown() { return s_second_tag_known; }

static bool secondTagAnswer();
bool backendCanHoldSecondTag() {
  const bool can = secondTagAnswer();
  s_second_tag_known = can ? 1 : 0;
  return can;
}

static bool secondTagAnswer() {
  // The structural half first, because it needs no network and rules out the
  // two cases that no server version will ever change.
  if (!tagFieldHoldsSeveral()) return false;

  // Spoolman, and the list field really is settled by the field alone: it is a
  // text field this scale writes itself, so no server version can refuse it.
  //
  // The relation is not. It arrived in v0.27, and tagFieldEffective() answers
  // "native" on every Spoolman because it is not allowed to reach the network
  // - so on an older server the source reads as selected while the endpoints
  // do not exist. Asking here is what keeps the question off a scale that
  // could not act on the answer; it was the missing half of this check.
  if (!backendIsFilaMan()) {
    if (!tagFieldIsNative()) return true;
    if (backendHasNativeTags()) return true;
    logSD("Second tag: this Spoolman has no tag relation, not asking");
    return false;
  }

  // FilaMan does need asking. The column arrived in 1.3.1, and a scale pointed
  // at an older instance must not offer a question the server refuses.
  return filamanHasRfidSlot2(backendBaseUrl(), filamanApiKey());
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

bool backendReportsScans() {
  return backendHasNativeTags() || backendMode() == BACKEND_FILAMAN;
}

int backendTagScan(const char* base_url, const char* uid, const char* alt_uid,
                   const char* format, JsonDocument& doc, uint32_t timeout_ms,
                   DeserializationError* out_err) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (backendMode() == BACKEND_FILAMAN) {
    // Not base_url: every caller here passes cfg_spoolman_base, which is the
    // Spoolman address and is empty on a FilaMan setup. Passing it on made the
    // call return -1 before it ever reached the network.
    // Same reader identity Spoolman gets, so a browser binds to this scale by
    // one name whichever backend it is talking to.
    const char* fm_name = deviceLabel();
    return filamanTagScan(backendBaseUrl(), filamanDeviceToken(), uid, alt_uid,
                          backendReaderId(),
                          (fm_name && fm_name[0]) ? fm_name : "SpoolmanScale",
                          format, doc, timeout_ms, out_err);
  }
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (!backendHasNativeTags()) return notSupported("LinkTag");
  return spoolmanLinkTag(base_url, spool_id, uid, format, out_conflict_spool_id, timeout_ms);
}

int backendUnlinkTag(const char* base_url, int spool_id, const char* uid,
                     uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (!backendHasNativeTags()) return notSupported("UnlinkTag");
  return spoolmanUnlinkTag(base_url, spool_id, uid, timeout_ms);
}

int backendFindSpoolByNativeTag(const char* base_url, const char* uid,
                                JsonDocument& doc, uint32_t timeout_ms,
                                JsonDocument* filter, DeserializationError* out_err) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
    logSDf("extra fields on %s: tag=%d nfc_id=%d card_uids=%d last_dried=%d rfid_tag=%d",
           base,
           (mask >> TAG_FIELD_TAG)       & 1, (mask >> TAG_FIELD_NFC_ID)  & 1,
           (mask >> TAG_FIELD_CARD_UIDS) & 1, (mask >> TAG_FIELD_EXTRA_COUNT) & 1,
           (mask >> (TAG_FIELD_EXTRA_COUNT + 1)) & 1);
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

// A field the scale writes is created the first time it writes to it, in
// place of the setup step that used to ask for it (Nikolai, 25.09.2026).
// Spoolman answers a PATCH on an unknown field with 400, so without this the
// first drying date or tag would simply be lost. Only when the probe answered
// and said "absent": an unreachable server gets no create, and only the keys
// the scale knows, never whatever a caller passes.
static void ensureSpoolmanField(const char* key) {
  if (backendMode() != BACKEND_SPOOLMAN || knownFieldIndex(key) < 0) return;
  if (backendHasExtraField(key)) return;
  const char* base = backendBaseUrl();
  if (!base || !base[0] ||
      strncmp(s_fields_probed_for, base, sizeof(s_fields_probed_for) - 1) != 0) return;
  const int c = backendCreateSpoolField(base, key, FIELD_CREATE_TIMEOUT_MS);
  logSDf("extra fields: '%s' was missing, created on first write, HTTP %d", key, c);
}

int backendPatchExtraField(const char* base_url, int spool_id, const char* key,
                           const char* value, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (backendMode() != BACKEND_SPOOLMAN) return notSupported("PatchExtraField");
  // Not for an empty value: clearing a field that does not exist is no reason
  // to create it.
  if (value && value[0]) ensureSpoolmanField(key);
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
  // FilaMan equivalent is /api/v1/system-extra-fields, different shape.
  // BamBuddy has a fixed schema and no extra fields at all.
  if (backendIsFilaMan() || backendIsBamBuddy()) return notSupported("GetSpoolFieldsJson");
  return spoolmanGetSpoolFieldsJson(base_url, doc, timeout_ms, out_err);
}

int backendGetHealthCode(const char* base_url, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanCountActiveSpools(backendBaseUrl(), filamanApiKey(), timeout_ms);
    case BACKEND_BAMBUDDY:
      return bbCountActiveSpools(backendBaseUrl(), bambuddyApiKey(), timeout_ms);
    default:
      return spoolmanCountActiveSpools(base_url, timeout_ms);
  }
}

int backendInventoryStamp(const char* base_url, InventoryStamp* out, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (!out) return -1;
  out->count      = -1;
  out->witness_id = 0;

  int code;
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      code = filamanInventoryStamp(backendBaseUrl(), filamanApiKey(),
                                   &out->count, &out->witness_id, timeout_ms);
      break;
    case BACKEND_BAMBUDDY:
      // Neither a count header nor a page size, see bbCountActiveSpools(): the
      // count there costs the whole list, which is what a stamp exists to
      // avoid. Answered here, without a request.
      return notSupported("InventoryStamp");
    default:
      code = spoolmanInventoryStamp(base_url, &out->count, &out->witness_id, timeout_ms);
      break;
  }
  // The server answered and had no count to give - a Spoolman from before
  // the header. Not a failure of the connection, so not one of its codes.
  // Said once: the caller asks again before every list.
  if (code == 200 && out->count < 0) {
    static bool said = false;
    if (!said) {
      said = true;
      logSDf("Backend: %s sends no spool count, no inventory stamp", backendName());
    }
    return BACKEND_NOT_SUPPORTED;
  }
  return code;
}

bool backendGetLastWeighedAt(const char* base_url, int spool_id,
                             char* out_iso, size_t out_size, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
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

bool backendGetLastUsedAt(const char* base_url, int spool_id,
                          char* out_iso, size_t out_size, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (out_iso && out_size > 0) out_iso[0] = '\0';
  if (backendIsFilaMan()) {
    return filamanGetLastUsedAt(backendBaseUrl(), filamanApiKey(), spool_id,
                                out_iso, out_size, timeout_ms);
  }
  // The other two keep a usable date on the spool itself, so there is nothing
  // to look up: Spoolman has last_used, BamBuddy stamps it when a print
  // consumes. Only FilaMan books the consumption into a log and leaves the
  // field null.
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
  switch (backendMode()) {
    case BACKEND_FILAMAN: {
      // Both tag types go into the native rfid_uid. An empty uuid unlinks.
      //
      // Plain hex like everywhere else. FilaMan's own reader writes it that
      // way, so the colon form this used to send was the odd one out in its
      // own database and missed the server side ?search= for anything not
      // written by this scale.
      if (!uuid || !uuid[0]) {
        // Both slots, not just the first. An unlink that leaves the chip on
        // the other flange behind keeps the spool answering at a printer after
        // the screen said it is gone - the half unlink the tag fields go out
        // of their way to avoid.
        return filamanClearRfidUids(backendBaseUrl(), filamanApiKey(), spool_id, timeout_ms);
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

int backendPatchSpoolTagSlot2(const char* base_url, int spool_id, const char* uuid,
                              uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  (void)base_url;   // FilaMan reads its address and key from its own module
  switch (backendMode()) {
    case BACKEND_FILAMAN: {
      if (!uuid || !uuid[0]) {
        return filamanPatchRfidUid2(backendBaseUrl(), filamanApiKey(), spool_id,
                                    nullptr, timeout_ms);
      }
      // Plain hex, same as slot one. FilaMan canonicalises to its own notation
      // on the way in since 1.3.1, but sending the colon form would still make
      // this the odd one out of everything else the scale writes.
      char hex[40];
      tagUidNormalize(uuid, hex, sizeof(hex));
      return filamanPatchRfidUid2(backendBaseUrl(), filamanApiKey(), spool_id,
                                  hex, timeout_ms);
    }
    default:
      // Spoolman appends inside patchSpoolTag() - the relation and the list
      // field both take a further tag through the ordinary write - and
      // BamBuddy has nowhere to put one. Neither should ever get here.
      return notSupported("backendPatchSpoolTagSlot2");
  }
}

int backendLinkSpoolTag(const char* base_url, int spool_id, const char* uuid,
                        char* out_note, size_t note_size, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
  switch (backendMode()) {
    case BACKEND_FILAMAN: {
      // Both fields, like the Spoolman side does. Writing only the initial weight
      // leaves the old remaining in place, so the spool reads as full on the
      // device - which updates its copy optimistically - and as half empty on the
      // server until the next scan corrects the display back.
      //
      // initial_total_weight_g is gross, filament and empty spool together
      // (spool 230: 810 = 600 + 210), and the mapping reads it back as net by
      // subtracting the empty weight. The net value went in unchanged, so a spool
      // set to 1000 g came back as 750 g with a 1000 g rest, 133 %. The empty
      // weight is read off the server, the same number the mapping subtracts.
      //
      // Without it nothing is written: a net value in the gross field is the
      // old fault again (spool 230 set to 600 g would read 390 g, 154 %), and
      // the caller reports a failure rather than a wrong number.
      float empty = 0.0f;
      {
        JsonDocument doc;
        const int rc = filamanGetSpoolJson(backendBaseUrl(), filamanApiKey(), spool_id, doc, timeout_ms);
        if (rc != 200) return rc;
        empty = doc["spool_weight"] | 0.0f;
      }
      return filamanPatchSpoolFloat2(backendBaseUrl(), filamanApiKey(), spool_id,
                                     "initial_total_weight_g", initial_weight + empty,
                                     "remaining_weight_g", initial_weight, timeout_ms);
    }
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
  (void)base_url;
  if (backendMode() != BACKEND_FILAMAN) return notSupported("SetSpoolStatus");
  return filamanSetStatus(backendBaseUrl(), filamanApiKey(), spool_id, status_key, timeout_ms);
}

int backendPatchSpoolWeight(const char* base_url, int spool_id, float spool_weight,
                            uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
  HttpStallTime stall(__func__);   // the loop stands still for this call
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
      ensureSpoolmanField(LAST_DRIED_FIELD);
      return spoolmanPatchSpoolLastDried(base_url, spool_id, iso_datetime, timeout_ms);
  }
}

// Mirrors the switch above, branch for branch, minus the request.
bool backendCanPatchLastDried() {
  switch (backendMode()) {
    case BACKEND_BAMBUDDY:
      switch (g_bb_dried_target) {
        case BB_DRIED_SPOOLMAN:
          return bbInventoryMode() == BB_INV_SPOOLMAN && bbSpoolmanUrl()[0];
        case BB_DRIED_NOTE:
          return true;
        default:
          return false;
      }
    default:
      return true;
  }
}

// ------------------------------------------------------------
//  AMS SLOTS
// ------------------------------------------------------------

bool backendHasAmsView() {
  switch (backendMode()) {
    case BACKEND_FILAMAN:
    case BACKEND_BAMBUDDY: return backendIsConfigured();
    default:               return false;
  }
}

bool backendCanAssignAmsSlot() {
  return backendMode() == BACKEND_BAMBUDDY && backendIsConfigured();
}

int backendListPrinters(AmsPrinterList& out, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanListPrinters(backendBaseUrl(), filamanApiKey(), out, timeout_ms);
    case BACKEND_BAMBUDDY:
      return bbListPrinters(backendBaseUrl(), bambuddyApiKey(), out, timeout_ms);
    default:
      // Spoolman keeps filament, not printers. location is free text about
      // shelves and nothing an AMS bay may be mapped onto.
      out = AmsPrinterList{};
      return notSupported("ListPrinters");
  }
}

int backendGetAmsState(int printer_id, AmsSlotState& out, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  switch (backendMode()) {
    case BACKEND_FILAMAN:
      return filamanGetAmsState(backendBaseUrl(), filamanApiKey(), printer_id,
                                out, timeout_ms);
    case BACKEND_BAMBUDDY:
      return bbGetAmsState(backendBaseUrl(), bambuddyApiKey(), printer_id,
                           out, timeout_ms);
    default:
      out = AmsSlotState{};
      return notSupported("GetAmsState");
  }
}

int backendAssignAmsSlot(int spool_id, int printer_id, int ams_id, int tray_id,
                         uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (backendMode() != BACKEND_BAMBUDDY) {
    // FilaMan is the interesting no here. It does have an AMS assignment,
    // but no model in which the scale names a bay and the database takes it:
    // there the scale opens a time window and the next tray to be loaded
    // wins, which is amsCommitWithWindow(). Sending anything to FilaMan from
    // this function would equate two different mechanisms.
    return notSupported("AssignAmsSlot");
  }
  return bbAssignSlot(backendBaseUrl(), bambuddyApiKey(), spool_id, printer_id,
                      ams_id, tray_id, timeout_ms);
}

int backendUnassignAmsSlot(int spool_id, int printer_id, int ams_id, int tray_id,
                           uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (backendMode() != BACKEND_BAMBUDDY) return notSupported("UnassignAmsSlot");
  return bbUnassignSlot(backendBaseUrl(), bambuddyApiKey(), spool_id, printer_id,
                        ams_id, tray_id, timeout_ms);
}

int backendFindSpoolSlot(int spool_id, int printer_id, int* out_ams,
                         int* out_tray, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (out_ams)  *out_ams  = -1;
  if (out_tray) *out_tray = -1;
  if (backendMode() != BACKEND_BAMBUDDY) return notSupported("FindSpoolSlot");
  return bbFindSpoolSlot(backendBaseUrl(), bambuddyApiKey(), spool_id, printer_id,
                         out_ams, out_tray, timeout_ms);
}

int backendFindBaySpool(int printer_id, int ams_id, int tray_id,
                        uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (backendMode() != BACKEND_BAMBUDDY) return notSupported("FindBaySpool");
  return bbFindBaySpool(backendBaseUrl(), bambuddyApiKey(), printer_id,
                        ams_id, tray_id, timeout_ms);
}

int backendFindPrinterSpools(int printer_id, AmsSlotSpool* out, uint8_t max,
                             uint8_t* out_count, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (out_count) *out_count = 0;
  if (backendMode() != BACKEND_BAMBUDDY) return notSupported("FindPrinterSpools");
  return bbFindPrinterSpools(backendBaseUrl(), bambuddyApiKey(), printer_id,
                             out, max, out_count, timeout_ms);
}

int backendFindUnitSpools(int printer_id, int ams_id, int* out_by_tray,
                          uint8_t n, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (out_by_tray) {
    for (uint8_t i = 0; i < n; i++) out_by_tray[i] = 0;
  }
  if (backendMode() != BACKEND_BAMBUDDY) return notSupported("FindUnitSpools");
  return bbFindUnitSpools(backendBaseUrl(), bambuddyApiKey(), printer_id,
                          ams_id, out_by_tray, n, timeout_ms);
}

// Copies a string out of the answer, and leaves the destination alone when
// the key is absent or empty. That is what lets the AMS state pre-fill a
// field the database has nothing for. Cut at a UTF-8 boundary: a location
// with an umlaut past the field's end used to leave half a glyph, which the
// panel draws as a box.
static void keepStr(JsonVariantConst v, char* dst, size_t n) {
  const char* s = v | (const char*)nullptr;
  if (!s || !s[0]) return;
  utf8Cut(s, n - 1, dst, n);
}

// An extra field's text, with the quoting Spoolman stores it under removed.
// Spoolman keeps extra values JSON encoded, so a text arrives as "\"...\"" and
// an empty one as "\"\""; FilaMan's and BamBuddy's mappings hand the bare
// text over. One reader for both shapes, stripping the way every other reader
// of these fields in the tree does. Empty when the key is absent.
static void extraText(JsonVariantConst v, char* out, size_t n) {
  if (!out || n == 0) return;
  out[0] = '\0';
  const char* s = v | (const char*)nullptr;
  if (!s) return;
  size_t len = strlen(s);
  if (len >= 2 && s[0] == '"' && s[len - 1] == '"') { s++; len -= 2; }
  if (len >= n) len = n - 1;
  memcpy(out, s, len);
  out[len] = '\0';
}

int backendGetSpoolDetail(int spool_id, AmsSpoolDetail& out, uint32_t timeout_ms) {
  HttpStallTime stall(__func__);   // the loop stands still for this call
  if (spool_id <= 0) return -1;

  JsonDocument doc;
  int code = backendGetSpoolJson(backendBaseUrl(), spool_id, doc, timeout_ms);
  if (code != 200) {
    logSDf("detail: spool %d not readable, code %d", spool_id, code);
    return code;
  }

  JsonObjectConst sp = doc.as<JsonObjectConst>();
  if (sp.isNull()) return -2;
  JsonObjectConst fil = sp["filament"].as<JsonObjectConst>();

  out.spool_id  = sp["id"] | spool_id;
  out.archived  = sp["archived"] | false;
  out.status_id = sp["status_id"] | 0;

  // A missing weight is not a zero weight. Spoolman sends null for a spool
  // that was never weighed, and drawing that as "0 g" would say the spool is
  // empty when the truth is that nobody knows.
  JsonVariantConst rem = sp["remaining_weight"];
  out.remaining_g = rem.isNull() ? SD_WEIGHT_NA : rem.as<float>();

  // What a full spool holds: the figure recorded on this spool, else the
  // filament's net weight. Same fallback the weighing path uses.
  JsonVariantConst init = sp["initial_weight"];
  if (!init.isNull() && init.as<float>() > 0.0f) {
    out.total_g = init.as<float>();
  } else {
    float fw = fil["weight"] | 0.0f;
    out.total_g = (fw > 0.0f) ? fw : SD_WEIGHT_NA;
  }

  keepStr(sp["location"], out.location, sizeof(out.location));
  keepStr(fil["name"], out.name, sizeof(out.name));
  keepStr(fil["vendor"]["name"], out.vendor, sizeof(out.vendor));

  // The material type alone, exactly as the server stores it.
  //
  // It used to have material_subgroup glued on, on the theory that "PETG" and
  // "hf" name one product between them. They do not: the subgroup is a slug
  // whose casing is whatever the import left behind - the test instance holds
  // "hf", "matte" and "Tough Plus" side by side - so the compound came out as
  // "PETG hf", a string that exists on no spool and in no shop. FilaMan never
  // builds it either; its own pages print the subgroup verbatim in a column of
  // its own and never next to the type.
  //
  // What the compound was there for is carried by the designation beside it:
  // "Hf - White", "Matte - Charcoal". Where a designation does not name the
  // product line - "Cyan (12601)" is a Tough+ and does not say so - the card
  // no longer shows it. That is a real loss, and the place to put it back is
  // a caption of its own, not a word stuck onto another field.
  keepStr(fil["material"], out.material, sizeof(out.material));

  // A tag of any kind counts: the card says whether this spool can be found
  // by holding it against the scale, not which field holds the binding. So
  // every extra field the scale can read a tag from is asked, plus FilaMan's
  // second slot - reading extra.tag alone missed a spool bound through nfc_id
  // or card_uids, which is what the field setting exists for.
  out.tag_linked = false;
  JsonObjectConst extra = sp["extra"].as<JsonObjectConst>();
  if (!extra.isNull()) {
    char v[48];
    for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT && !out.tag_linked; i++) {
      const TagFieldSpec& spec = tagFieldSpec(i);
      if (!spec.key) continue;
      extraText(extra[spec.key], v, sizeof(v));
      out.tag_linked = (v[0] != '\0');
    }
    if (!out.tag_linked) {
      extraText(extra["tag2"], v, sizeof(v));
      out.tag_linked = (v[0] != '\0');
    }
  }

  char iso[32];
  extraText(sp["extra"]["last_dried"], iso, sizeof(iso));
  if (iso[0]) isoDayLocal(iso, out.last_dried, sizeof(out.last_dried));
  // The same three step rule applyLastUsed() follows on the main screen, and
  // it has to be the same: a card that showed a dash where the screen behind
  // it shows a date would read as the card being broken.
  //
  // FilaMan writes last_used only when a printer reports consumption, so a
  // spool that has only ever been weighed has nothing in it - which is the
  // case for every spool on the test instance.
  char used_iso[40] = "";
  const char* used = sp["last_used"] | "";
  if (used[0]) snprintf(used_iso, sizeof(used_iso), "%s", used);

  // BamBuddy stamps the spool itself when a weight is written, so this one
  // arrives with the answer and costs nothing.
  char weighed[40];
  extraText(sp["extra"]["last_weighed"], weighed, sizeof(weighed));
  if (weighed[0]) {
    if (last_used_mode == 1 || !used_iso[0]) {
      snprintf(used_iso, sizeof(used_iso), "%s", weighed);
    }
  } else if (backendMode() == BACKEND_BAMBUDDY && last_used_mode == 1) {
    // A consumption date under a "last weighed" caption would be wrong.
    used_iso[0] = '\0';
  }

  // FilaMan keeps the history in an event log, which is a second request.
  // Paid only when there is nothing to show without it, or when the user asked
  // for the weighing date specifically. In weighed mode only a weighing will
  // do; otherwise anything that moved the weight counts, which is what makes
  // a spool printed from for weeks stop reading as never used.
  if (backendMode() == BACKEND_FILAMAN && (last_used_mode == 1 || !used_iso[0])) {
    char found[40];
    const bool ok = (last_used_mode == 1)
      ? backendGetLastWeighedAt(backendBaseUrl(), spool_id, found, sizeof(found))
      : backendGetLastUsedAt(backendBaseUrl(), spool_id, found, sizeof(found));
    if (ok) {
      snprintf(used_iso, sizeof(used_iso), "%s", found);
    } else if (last_used_mode == 1) {
      used_iso[0] = '\0';
    }
  }

  if (used_iso[0]) isoDayLocal(used_iso, out.last_used, sizeof(out.last_used));

  out.found = true;
  return 200;
}
