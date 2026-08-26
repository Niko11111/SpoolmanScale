#include "spoolman_lookup.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <lvgl.h>
#include <cstring>
#include <ctime>

#include "app_config.h"
#include "bambu/bambu_tag.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/location_state.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/filaman_api.h"
#include "services/http_progress.h"
#include "services/spoolman_api.h"
#include "services/tag_field.h"
#include "services/tag_uid.h"
#include "services/time_service.h"
#include "ui/spool_flow.h"
#include "services/user_options.h"
#include "ui/date_display.h"
#include "ui/main_screen_helpers.h"
#include "ui_common.h"

namespace {

struct SpiRamAllocator : ArduinoJson::Allocator {
  void* allocate(size_t size) override {
    void* ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
    if (!ptr) ptr = malloc(size);
    return ptr;
  }
  void deallocate(void* pointer) override { heap_caps_free(pointer); }
  void* reallocate(void* ptr, size_t new_size) override {
    void* p = heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM);
    if (!p) p = realloc(ptr, new_size);
    return p;
  }
};

}

// Does this spool carry the scanned UID?
//
// extra.tag is asked first and its comparison is byte for byte the one this
// firmware has always used. That order is deliberate: every existing
// installation runs on that path, and nothing added below may be able to cost
// it a match. card_uids is only consulted once the tag field has said no.
//
// Both server side searches are partial matches, so this runs on their results
// too, not only on the full scan.
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

// A 4 byte chip uid is 8 characters, and the plugin pads it to 16 with a
// fixed tail. Both lengths are checked rather than the tail itself: the tail
// is what the AMS reported, not something this firmware gets to define.
#define BAMBU_CHIP_UID_LEN    8
#define BAMBU_TAG_FIELD_LEN  16

// How often the inventory scan repaints its status line. Ten a second reads as
// motion and each one costs a partial flush that the transfer is waiting on.
#define SEARCH_TICK_MS  100

// Writes the progress of the full inventory load into the main screen's status
// line. Registered only for the duration of that load; the rest of the
// firmware's requests never see it.
static void searchProgress(size_t bytes_read) {
  if (!lbl_status) return;
  static unsigned long last = 0;
  const unsigned long now = millis();
  if (now - last < SEARCH_TICK_MS) return;
  last = now;

  char buf[48];
  snprintf(buf, sizeof(buf), T(STR_SEARCHING_INVENTORY_KB), (unsigned)(bytes_read / 1024));
  lv_label_set_text(lbl_status, buf);
  lv_refr_now(NULL);
}

// Whether a stored value names this uid, comparing normalised so the colon
// form and plain hex are the same thing. `is_list` picks whole entry
// comparison, because a 4 byte uid would otherwise match inside a 7 byte one
// belonging to a different spool.
static bool valueNamesUid(const char* stored, bool is_list, const char* uid) {
  if (!stored || !stored[0] || !uid || !uid[0]) return false;
  if (is_list) return cardUidsContain(stored, uid);

  String v(stored);
  v.replace("\"", "");
  v.trim();
  if (v.length() == 0) return false;
  if (v.equalsIgnoreCase(uid)) return true;

  char have[TAG_UID_CMP_MAX], want[TAG_UID_CMP_MAX];
  tagUidNormalize(v.c_str(), have, sizeof(have));
  tagUidNormalize(uid, want, sizeof(want));
  return have[0] && want[0] && strcmp(have, want) == 0;
}

// Both identities the tag on the reader can be stored under. For a Bambu tag
// that is the tray uuid AND the chip uid: somebody may have put either one
// into a field, and a spool bound by the chip must be found just as well as
// one bound by the uuid. Everywhere else the two are the same value and the
// second test costs nothing.
static bool storedNamesTag(const char* stored, bool is_list, const char* uid) {
  if (valueNamesUid(stored, is_list, uid)) return true;
  const char* chip = tagNativeUid(uid);
  return chip != uid && valueNamesUid(stored, is_list, chip);
}

// Whether a key is one of the tag conventions this firmware writes itself.
// Those are compared above, with the list handling their format needs.
static bool knownTagFieldKey(const char* key) {
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++) {
    const char* k = tagFieldSpec(i).key;
    if (k && strcmp(k, key) == 0) return true;
  }
  return false;
}

static int spoolTagRank(JsonObjectConst spool, const char* uid) {
  if (!uid || !uid[0]) return TAG_RANK_NONE;

  // Spoolman's own tag relation, which a server on master fills. Asked first
  // and separately from the extra fields, because a spool bound this way has
  // none of them set - without this the scan below would find the spool and
  // this check would then throw the match away again.
  JsonArrayConst tags = spool["tags"];
  if (!tags.isNull()) {
    char want[TAG_UID_CMP_MAX];
    tagUidNormalize(uid, want, sizeof(want));
    // A Bambu tag is linked by its chip uid, while `uid` here is the tray
    // uuid. Both are asked, so a spool linked by either is found: the chip is
    // what this firmware writes now, the tray uuid is what it wrote before.
    // For everything else tagNativeUid() answers with `uid` itself and the
    // second compare costs nothing.
    char want_chip[TAG_UID_CMP_MAX];
    tagUidNormalize(tagNativeUid(uid), want_chip, sizeof(want_chip));
    for (JsonObjectConst t : tags) {
      const char* have_raw = t["uid"] | "";
      char have[TAG_UID_CMP_MAX];
      tagUidNormalize(have_raw, have, sizeof(have));
      if (!have[0]) continue;
      if (want[0]      && strcmp(have, want)      == 0) return TAG_RANK_FIELD;
      if (want_chip[0] && strcmp(have, want_chip) == 0) return TAG_RANK_FIELD;
    }
  }

  JsonObjectConst extra = spool["extra"];
  if (extra.isNull()) return TAG_RANK_NONE;

  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++) {
    const TagFieldSpec& spec = tagFieldSpec(i);
    if (!extra.containsKey(spec.key)) continue;

    // Both identities, and in both notations: a UID written into nfc_id by
    // SpoolSense is plain hex while the scale carries it around with colons,
    // and neither is wrong. For a Bambu tag the chip uid counts too, because
    // somebody may have put that into the field rather than the tray uuid.
    const char* raw = extra[spec.key] | (const char*)nullptr;
    if (storedNamesTag(raw, spec.is_list, uid)) return TAG_RANK_FIELD;
  }

  // ---- FilaMan's Bambu Lab plugin, below everything above ----
  //
  // Both of these can name a spool that the tag fields say nothing about, and
  // both are read only: the plugin owns them, and what this scale writes back
  // into them is decided in the options screen, not here.

  // The tray uuid out of external_id. Exact, 32 characters, no notation to
  // reconcile - it is the same value the scale read off the tag.
  const char* ext = extra["bambu_ext"] | (const char*)nullptr;
  if (ext && ext[0] && strlen(uid) == 32 && strcasecmp(ext, uid) == 0) {
    return TAG_RANK_BAMBU_EXT;
  }

  // The uid of one physical chip. Only a 4 byte tag can be one, which is
  // exactly 8 characters normalised - a 7 byte NTAG uid lives in the same
  // variable and must not be tried against this field.
  char want[TAG_UID_CMP_MAX];
  tagUidNormalize(g_tag.uid_str, want, sizeof(want));
  if (strlen(want) == BAMBU_CHIP_UID_LEN) {
    for (uint8_t i = 0; i < 2; i++) {
      const char* raw = extra[i == 0 ? "bambu_tag1" : "bambu_tag2"] | (const char*)nullptr;
      if (!raw || !raw[0]) continue;
      char have[TAG_UID_CMP_MAX];
      tagUidNormalize(raw, have, sizeof(have));
      // Anchored at the front and only against the full 16 character form the
      // plugin writes. Not a substring search: a free comparison on 8
      // characters would match inside anything else that field ever holds.
      if (strlen(have) == BAMBU_TAG_FIELD_LEN &&
          strncmp(have, want, BAMBU_CHIP_UID_LEN) == 0) {
        return TAG_RANK_BAMBU_CHIP;
      }
    }
  }

  // ---- any other text extra field, below everything this firmware writes ----
  //
  // A UID can sit in a field nobody agreed on: OpenSpoolman fills active_tray
  // with the tray uuid of the spool in the AMS, and people invent their own.
  // Comparing against all of them is what lets somebody adopt a whole library
  // in one pass over the scale, whatever field they once used.
  //
  // Deliberately last, after the Bambu plugin's rules above: those name the
  // very fields this loop would otherwise walk (bambu_ext, bambu_tag1/2) and
  // give them their own, better ranks. Ranking them as "some other field"
  // here would let a plugin duplicate win a comparison it should lose.
  //
  // Only reached when everything above said no, and ranked below it, so a
  // coincidental match can never take a spool away from a real binding. The
  // comparison is exact after normalising, so a colour name or a note cannot
  // match; a field holding the very same hex still can, which is precisely
  // why this rank exists.
  for (JsonPairConst kv : extra) {
    const char* key = kv.key().c_str();
    if (!key || !key[0]) continue;
    // The known ones were asked above, with their own list handling.
    if (knownTagFieldKey(key)) continue;
    // Not a tag store, and a timestamp that normalised to hex would be a
    // match waiting to happen.
    if (strcmp(key, LAST_DRIED_FIELD) == 0) continue;
    if (!kv.value().is<const char*>()) continue;

    String val = kv.value().as<String>();
    val.replace("\"", "");
    val.trim();
    if (val.length() == 0) continue;

    // Both shapes, because an unknown field may well hold a list, and both
    // identities for the same reason as above.
    if (storedNamesTag(val.c_str(), true,  uid) ||
        storedNamesTag(val.c_str(), false, uid)) {
      logSDf("tag found in extra.%s of spool %d", key, (int)(spool["id"] | 0));
      return TAG_RANK_EXTRA_OTHER;
    }
  }

  return TAG_RANK_NONE;
}

// The rank a spool has to reach for the server side searches to be believed.
// They can only ever find what they filtered on, so anything below is a
// substring hit on a different spool.
static inline bool spoolMatchesTag(JsonObjectConst spool, const char* uid) {
  return spoolTagRank(spool, uid) == TAG_RANK_FIELD;
}

// Copies one extra field into a buffer, quote stripped and trimmed. A value
// that does not fit leaves the buffer empty rather than shortened: everything
// downstream reads these as "what the spool is bound by", and a truncated list
// would make an unlink drop whatever fell off the end.
static void captureExtraField(JsonObjectConst extra, const char* key,
                              char* out, size_t out_len, const char* what) {
  out[0] = '\0';
  if (extra.isNull() || !extra.containsKey(key)) return;

  String v = extra[key].as<String>();
  v.replace("\"", "");
  v.trim();

  if (v.length() >= out_len) {
    logSDf("%s: value of spool %d too long (%d chars), ignored",
           what, sm_id, (int)v.length());
    return;
  }

  strncpy(out, v.c_str(), out_len - 1);
  out[out_len - 1] = '\0';
}

// Keeps both stores that can bind a spool to a tag within reach of the unlink,
// which runs from an LVGL callback where an HTTP request is out of the
// question. The unlink popup needs the UID count before it opens, because that
// decides whether it gets a third button, and the unlink itself needs to know
// which of the two fields actually holds something so it can leave the other
// one alone.
//
// Filled on every lookup rather than only with the write switch on, so that
// flipping the switch while a spool sits on the scale does not land on an
// empty buffer.
static void captureBindings(JsonObjectConst spool) {
  JsonObjectConst extra = spool["extra"];
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++) {
    const TagFieldSpec& spec = tagFieldSpec(i);
    captureExtraField(extra, spec.key, sm_tag_values[i], CARD_UIDS_MAX, spec.key);
  }

  // The native relation goes into the slot next to them, as a comma separated
  // list, which is the shape the card_uids helpers already read and write. A
  // spool can hold several tags here - for a Bambu spool that is the normal
  // case, one entry per chip plus the tray uuid - and an unlink has to take
  // every one of them out. Without this list it could only ever drop the tag
  // that happened to be on the reader, and the spool would keep being found
  // by the others while the screen said it was unlinked.
  char* out = sm_tag_values[TAG_FIELD_NATIVE];
  out[0] = '\0';
  JsonArrayConst tags = spool["tags"];
  if (tags.isNull()) return;
  size_t used = 0;
  for (JsonObjectConst t : tags) {
    const char* raw = t["uid"] | "";
    if (!raw[0]) continue;
    char norm[TAG_UID_CMP_MAX];
    tagUidNormalize(raw, norm, sizeof(norm));
    if (!norm[0]) continue;
    const size_t need = strlen(norm) + (used ? 1 : 0);
    if (used + need >= CARD_UIDS_MAX) {
      logSDf("native tags: spool %d has more than fits, list truncated", sm_id);
      break;
    }
    if (used) out[used++] = ',';
    strcpy(out + used, norm);
    used += strlen(norm);
  }
}

// The tail FilaMan's Bambu Lab plugin appends to a chip uid. It is what the
// AMS reported, identical on all seven spools this was read from, and this
// firmware only reproduces it - it does not get to define it.
#define BAMBU_TAG_PAD  "00000100"

// Keeps the plugin's two fields in step with what is on the reader right now.
//
// Two writes, each behind its own switch, each only ever into an empty field.
// The data itself is the guard: a value that is already there means nothing is
// sent, so this costs a couple of comparisons per scan and a request once in
// the life of a spool.
//
// Only for a genuine Bambu tag. A four byte card that happens to be linked to
// a spool has no business in a field called "Bambu RFID Tag", and it has no
// tray uuid to put in external_id either.
static void filamanSyncBambuFields(int spool_id, JsonObjectConst extra,
                                   const char* tray_uuid) {
  if (spool_id <= 0 || !tray_uuid || strlen(tray_uuid) != 32) return;

  const char* base = backendBaseUrl();
  const char* key  = filamanApiKey();
  if (!base || !base[0] || !key || !key[0]) return;

  if (g_flm_bambu_tags) {
    // The chip uid, not the tray uuid: these two fields name one physical
    // chip each. Only a four byte tag has one, which is eight characters
    // normalised - the seven byte uid of an NTAG lives in the same variable.
    char want[TAG_UID_CMP_MAX];
    tagUidNormalize(g_tag.uid_str, want, sizeof(want));
    if (strlen(want) == BAMBU_CHIP_UID_LEN) {
      bool    present   = false;
      uint8_t free_slot = 0;
      for (uint8_t i = 0; i < 2 && !present; i++) {
        const char* raw = extra[i == 0 ? "bambu_tag1" : "bambu_tag2"] | (const char*)nullptr;
        if (!raw || !raw[0]) {
          if (!free_slot) free_slot = i + 1;
          continue;
        }
        char have[TAG_UID_CMP_MAX];
        tagUidNormalize(raw, have, sizeof(have));
        if (strncmp(have, want, BAMBU_CHIP_UID_LEN) == 0) present = true;
      }

      if (!present && free_slot) {
        char value[BAMBU_TAG_FIELD_LEN + 1];
        snprintf(value, sizeof(value), "%s%s", want, BAMBU_TAG_PAD);
        const char* field = (free_slot == 1) ? "bambu_rfid_tag_1" : "bambu_rfid_tag_2";
        int c = filamanPatchCustomField(base, key, spool_id, field, value);
        logSDf("FilaMan: spool %d %s = %s, HTTP %d", spool_id, field, value, c);
      } else if (!present) {
        // Both slots hold somebody else. Neither is touched: they say which
        // chips are stuck to that spool, and this scan disagrees with both.
        logSDf("FilaMan: spool %d has both Bambu tag slots taken, %s not written",
               spool_id, want);
      }
    }
  }

  // The plugin's duplicate check reads external_id and nothing else. Only
  // written while empty - a spoolman:<id> from the importer stays.
  if (g_flm_ext_id && !(extra["ext_set"] | false)) {
    char ext[48];
    snprintf(ext, sizeof(ext), "bambulab:%s", tray_uuid);
    int c = filamanPatchExternalId(base, key, spool_id, ext);
    logSDf("FilaMan: spool %d external_id = %s, HTTP %d", spool_id, ext, c);
  }
}

// Reduces an ISO timestamp to the day it falls on, in local time.
//
// FilaMan answers in UTC with a trailing Z. Simply cutting after ten
// characters would show the previous day for anything weighed late in the
// evening, which is exactly when spools get weighed. Spoolman's date is
// already local, written by this scale, and carries no Z, so it passes
// through unchanged.
// Epoch seconds for a UTC date and time. There is no timegm() in the ESP32
// toolchain, and mktime() would apply the local offset, which is exactly the
// error this is meant to avoid. Days from civil, after Howard Hinnant.

// Resolves the date shown next to "last used" / "last weighed" and writes it
// to sm_last_used and the label.
//
// Spoolman has a single field for both meanings, so there the mode only
// decides what the scale writes into it and the value is already in the spool
// object. FilaMan separates the two: last_used_at holds real print
// consumption and stays empty without a printer integration, while every
// weighing lands in the spool event log, including the ones this scale
// reports. native_iso is the value from the spool object, or null.
static void applyLastUsed(const char* native_iso, const char* weighed_iso, int spool_id) {
  char iso[40] = "";
  if (native_iso && native_iso[0]) {
    strncpy(iso, native_iso, sizeof(iso) - 1);
    iso[sizeof(iso) - 1] = '\0';
  }

  // BamBuddy's built-in inventory stamps the spool itself when a weight is
  // written, so the date arrives with the spool and costs no extra request.
  // The rule is the same as below: authoritative in weighed mode, a fallback
  // otherwise. Behind the Spoolman proxy the field is empty and this does
  // nothing, which is correct - there is no weighing date there.
  if (weighed_iso && weighed_iso[0]) {
    if (last_used_mode == 1 || !iso[0]) {
      strncpy(iso, weighed_iso, sizeof(iso) - 1);
      iso[sizeof(iso) - 1] = '\0';
    }
  } else if (backendIsBamBuddy() && last_used_mode == 1) {
    // Weighed mode with nothing to show beats showing a consumption date
    // under a "last weighed" label.
    iso[0] = '\0';
  }

  // In weighed mode the event log is the only correct source. In last used
  // mode it serves as a fallback, so the line is not simply empty until a
  // printer reports consumption for the first time.
  if (backendIsFilaMan() && (last_used_mode == 1 || !iso[0])) {
    char measured[40];
    if (backendGetLastWeighedAt(cfg_spoolman_base, spool_id, measured, sizeof(measured))) {
      strncpy(iso, measured, sizeof(iso) - 1);
      iso[sizeof(iso) - 1] = '\0';
    } else if (last_used_mode == 1) {
      // Showing a consumption date under a "last weighed" label would be
      // wrong, so nothing is better than the native value here.
      iso[0] = '\0';
    }
  }

  if (iso[0]) {
    char day[11];
    isoDayLocal(iso, day, sizeof(day));
    char de[12];
    isoToDe(day, de, sizeof(de));
    strncpy(sm_last_used, de, sizeof(sm_last_used) - 1);
  } else {
    strncpy(sm_last_used, "-", sizeof(sm_last_used) - 1);
  }
  sm_last_used[sizeof(sm_last_used) - 1] = '\0';

  char display[48];
  driedDisplayStr(sm_last_used, display, sizeof(display));
  lv_label_set_text(lbl_last_used, display);
}

// ============================================================
//  SPOOLMAN QUERY BY ID
//  Used after link-flow — fetches only one spool by ID.
//  Fills same globals and labels as querySpoolman().
// ============================================================

// The empty-spool weight can be recorded at three levels, and only the spool
// level was read. A blank tare is treated as zero, which counts the spool
// itself as filament -- 130 to 250 g on a nominal 1 kg spool.
//
// Both backends arrive here in the same shape: the FilaMan adapter already
// maps default_spool_weight_g onto filament.spool_weight and the manufacturer
// onto vendor.empty_spool_weight, so one chain serves both.
//
// Reports which level answered, because an inherited default can be well off a
// measured one (a Sunlu spool measured at 130 g against a 180 g brand default),
// and the difference should be visible rather than silently applied.
static float resolveTare(JsonVariantConst spool, uint8_t *source) {
  float w = spool["spool_weight"] | 0.0f;
  if (w > 0) { *source = TARE_SPOOL; return w; }

  w = spool["filament"]["spool_weight"] | 0.0f;
  if (w > 0) { *source = TARE_FILAMENT; return w; }

  w = spool["filament"]["vendor"]["empty_spool_weight"] | 0.0f;
  if (w > 0) { *source = TARE_VENDOR; return w; }

  *source = TARE_NONE;
  return 0.0f;
}

// How much filament this spool started with. The nominal weight of the
// filament TYPE is a catalogue figure; what a manufacturer actually winds onto
// an individual spool varies by a few percent, which is a few percentage
// points on the display. Once that has been measured for a spool it is a
// better number than the catalogue one, so it wins.
//
// Reading this back is what makes measuring it worth anything. Until now the
// value was written and never read, so it survived exactly until the next scan
// and then snapped back to the type nominal.
static float resolveInitial(JsonVariantConst spool) {
  float w = spool["initial_weight"] | 0.0f;
  if (w > 0) return w;                                  // measured for this spool
  w = spool["filament"]["weight"] | 0.0f;
  if (w > 0) return w;                                  // nominal for the type
  return 1000.0f;
}

static const char* tareSourceName(uint8_t s) {
  switch (s) {
    case TARE_SPOOL:    return "spool";
    case TARE_FILAMENT: return "filament";
    case TARE_VENDOR:   return "vendor";
    default:            return "none";
  }
}

void querySpoolmanById(int spool_id) {
  if (!wifi_ok) return;
  Serial.printf("querySpoolmanById: ID=%d\n", spool_id);
  logSDf("Spoolman: query by ID=%d", spool_id);
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (before byID GET)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  DynamicJsonDocument doc(8192);
  DeserializationError err = DeserializationError::Ok;
  int code = backendGetSpoolJson(cfg_spoolman_base, spool_id, doc, 8000, &err);
  if (code != 200) {
    Serial.printf("querySpoolmanById HTTP error: %d\n", code);
    logSDf("Spoolman byID: HTTP error %d", code);
    if (code == -2) {
      Serial.println("querySpoolmanById: JSON error");
      logSD("Spoolman byID: JSON error");
    }
    return;
  }
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (after byID parse)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  JsonObject spool = doc.as<JsonObject>();
  bool is_bambu_tag = (strlen(g_tag.material) > 0);

  sm_found        = true;
  sm_id           = spool["id"] | 0;
  // Found and archived is a state of its own, see app_state.h. Read here
  // because this is the one path that fetches a spool whole.
  sm_archived     = spool["archived"] | false;
  sm_filament_id  = spool["filament"]["id"] | 0;
  sm_vendor_id    = spool["filament"]["vendor"]["id"] | 0;
  sm_remaining    = spool["remaining_weight"] | 0.0f;
  sm_total        = resolveInitial(spool);
  sm_spool_weight = resolveTare(spool, &sm_tare_source);
  logSDf("Spoolman: byID OK ID=%d remaining=%.1fg tare=%.0fg (%s)",
    sm_id, sm_remaining, sm_spool_weight, tareSourceName(sm_tare_source));

  String art_nr = spool["filament"]["article_number"] | "";
  art_nr.trim();
  strncpy(sm_article_nr, art_nr.c_str(), sizeof(sm_article_nr)-1);
  sm_article_nr[sizeof(sm_article_nr)-1] = '\0';

  String fil_name = spool["filament"]["name"] | String("");
  fil_name.trim();
  strncpy(sm_filament_name, fil_name.c_str(), sizeof(sm_filament_name)-1);
  sm_filament_name[sizeof(sm_filament_name)-1] = '\0';

  // Location — Spoolman gibt location als einfachen String zurück
  sm_location_id = 0;
  sm_location_name[0] = '\0';
  if (!spool["location"].isNull() && spool["location"].is<const char*>()) {
    String loc_name = spool["location"] | String("");
    loc_name.trim();
    strncpy(sm_location_name, loc_name.c_str(), sizeof(sm_location_name)-1);
    sm_location_name[sizeof(sm_location_name)-1] = '\0';
  }

  // Spool status. Only FilaMan maps it, the others leave the key unset.
  sm_status_id = spool["status_id"] | 0;

  // last_dried
  sm_last_dried[0] = '\0';
  if (spool.containsKey("extra") && spool["extra"].containsKey("last_dried")) {
    String dried = spool["extra"]["last_dried"].as<String>();
    dried.replace("\"", "");
    // The stored value is a UTC instant; the day it belongs to is the local
    // one, exactly as for last_used above.
    char day[11];
    isoDayLocal(dried.c_str(), day, sizeof(day));
    char de_date[12];
    isoToDe(day, de_date, sizeof(de_date));
    strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
    sm_last_dried[sizeof(sm_last_dried)-1] = '\0';
  } else {
    strncpy(sm_last_dried, "-", sizeof(sm_last_dried)-1);
  }

  captureBindings(spool);

  // Material, vendor, color — only for NTAG (Bambu has it from tag itself)
  String sm_material = spool["filament"]["material"] | String("");
  sm_material.trim();
  String sm_vendor_name = "";
  if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull()) {
    sm_vendor_name = spool["filament"]["vendor"]["name"] | String("");
    sm_vendor_name.trim();
    snprintf(sm_vendor_g, sizeof(sm_vendor_g), "%s", sm_vendor_name.c_str());
  }
  String sm_color = spool["filament"]["color_hex"] | String("");
  sm_color.trim();

  bool is_ntag = !is_bambu_tag;
  if (is_ntag) {
    lv_label_set_text(lbl_material, sm_material.length() > 0 ? sm_material.c_str() : "-");
    lv_label_set_text(lbl_vendor,   sm_vendor_name.length() > 0 ? sm_vendor_name.c_str() : "-");
    strncpy(sm_material_global, sm_material.c_str(), sizeof(sm_material_global)-1);
    sm_material_global[sizeof(sm_material_global)-1] = '\0';
    strncpy(sm_color_global, sm_color.c_str(), sizeof(sm_color_global)-1);
    sm_color_global[sizeof(sm_color_global)-1] = '\0';
  } else {
    // Bambu-Tag: Material aus g_tag.material in sm_material_global schreiben
    // damit dryingAlertLevel() das Material korrekt auflösen kann
    if (g_tag.material[0]) {
      strncpy(sm_material_global, g_tag.material, sizeof(sm_material_global)-1);
      sm_material_global[sizeof(sm_material_global)-1] = '\0';
    }
  }
  if (is_ntag && sm_color.length() >= 6) {
    lv_obj_set_style_bg_color(lbl_color_swatch, swatchColorFromHex(sm_color.c_str()), 0);
  }

  // Update display labels
  char weight_str[32];
  snprintf(weight_str, sizeof(weight_str), "%.0f g", sm_remaining);
  lv_label_set_text(lbl_spoolman_weight, weight_str);
  float pct = (sm_total > 0) ? (sm_remaining / sm_total) * 100.0f : 0;
  uint32_t pct_color;
  if (pct <= 10.0f)      pct_color = 0xe04040;
  else if (pct <= 30.0f) pct_color = 0xf0b838;
  else                   pct_color = 0x28d49a;
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(pct_color), 0);

  char pct_str[16];
  snprintf(pct_str, sizeof(pct_str), "%.1f %%", pct);
  lv_label_set_text(lbl_spoolman_pct, pct_str);
  lv_obj_set_style_text_color(lbl_spoolman_pct, lv_color_hex(pct_color), 0);

  if (lbl_scale_diff) {
    int bar_w = (int)((pct / 100.0f) * (float)MAIN_BAR_W);
    if (bar_w < 0) bar_w = 0;
    if (bar_w > MAIN_BAR_W) bar_w = MAIN_BAR_W;
    lv_obj_set_width(lbl_scale_diff, bar_w);
    lv_obj_set_style_bg_color(lbl_scale_diff, lv_color_hex(pct_color), 0);
  }

  char sm_id_str[16];
  snprintf(sm_id_str, sizeof(sm_id_str), "%d", sm_id);
  lv_label_set_text(lbl_spoolman_id, sm_id_str);
  lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0x28d49a), 0);

  char dried_display[48];
  driedDisplayStr(sm_last_dried, dried_display, sizeof(dried_display));
  applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, sm_last_dried);

  lv_label_set_text(lbl_detail,        strlen(sm_article_nr)    > 0 ? sm_article_nr    : "-");
  lv_label_set_text(lbl_filament_name, strlen(sm_filament_name) > 0 ? sm_filament_name : "-");

  applyLastUsed(spool["last_used"] | (const char*)nullptr,
                spool["extra"]["last_weighed"] | (const char*)nullptr, sm_id);

  Serial.printf("querySpoolmanById OK: ID=%d %.1fg dried=%s\n", sm_id, sm_remaining, sm_last_dried);
  updateLinkButton();
}

// ============================================================
//  SPOOLMAN QUERY
//  Finds spool by tray_uuid in extra.tag field
// ============================================================
// ============================================================
//  RE-ANNOUNCING A TAG THE AUTO-LINK JUST LEARNED
//
//  The very first scan of a spool that Spoolman does not know yet can only
//  answer "unknown tag": the link is made afterwards, out of the lookup that
//  the same scan started. A paired browser therefore gets the unknown-tag
//  toast and stays put, which reads as a failure even though everything
//  worked.
//
//  One more scan fixes it, but not straight away: Spoolman broadcasts the same
//  UID from the same reader only once per DEBOUNCE_WINDOW, three seconds, so
//  an immediate repeat is swallowed. Hence the wait.
// ============================================================

static char     s_rescan_uid[40]    = {0};
static char     s_rescan_format[16] = {0};
static uint32_t s_rescan_due_ms     = 0;

static void scheduleRescan(const char* uid, const char* format) {
  if (!uid || !uid[0]) return;
  strncpy(s_rescan_uid, uid, sizeof(s_rescan_uid) - 1);
  s_rescan_uid[sizeof(s_rescan_uid) - 1] = '\0';
  strncpy(s_rescan_format, format ? format : "", sizeof(s_rescan_format) - 1);
  s_rescan_format[sizeof(s_rescan_format) - 1] = '\0';
  s_rescan_due_ms = millis() + TAG_RESCAN_DELAY_MS;
}

// What the last lookup was named by. The recheck needs exactly this value and
// cannot reconstruct it: for a Bambu tag it is the tray uuid, for an NTAG the
// plain uid, and g_tag only carries the former reliably.
static char s_last_query[48] = {0};

void spoolmanRecheckTick() {
  if (!wifi_ok || !tag_present || sm_found) return;
  if (!s_last_query[0]) return;
  if (isSpoolFlowIdInputOpen()) return;   // the user is busy picking a spool

  static uint32_t last_ms = 0;
  // Signed difference, so this survives the millis() rollover.
  if (last_ms && (int32_t)(millis() - last_ms) < (int32_t)TAG_RECHECK_MS) return;
  last_ms = millis();

  // Only the fields the verification reads. The point of this pass is that it
  // stays small: a real miss still falls through to the inventory scan in
  // querySpoolman(), and doing that every few seconds is exactly what must not
  // happen here.
  StaticJsonDocument<512> filter;
  JsonArray filter_arr = filter.to<JsonArray>();
  JsonObject f = filter_arr.createNestedObject();
  f["id"] = true;
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++)
    f["extra"][tagFieldSpec(i).key] = true;
  f["tags"][0]["uid"] = true;

  SpiRamAllocator psram_alloc;
  JsonDocument doc(&psram_alloc);
  DeserializationError err = DeserializationError::Ok;
  bool hit = false;

  // Every backend has a cheap lookup by tag, so this works for all three. The
  // one split: with Spoolman's own relation selected there is no extra field
  // to filter on, and backendFindSpoolByTag() would answer NOT_SUPPORTED.
  if (backendHasNativeTags()) {
    const char* nu = tagNativeUid(s_last_query);
    if (backendFindSpoolByNativeTag(cfg_spoolman_base, nu, doc, 5000, &filter, &err) == 200 && !err) {
      for (JsonObjectConst cand : doc.as<JsonArrayConst>())
        if (spoolMatchesTag(cand, s_last_query)) { hit = true; break; }
    }
    if (!hit) { doc.clear(); err = DeserializationError::Ok; }
  }

  if (!hit) {
    if (backendFindSpoolByTag(cfg_spoolman_base, s_last_query, doc, 5000, &err, &filter) == 200 && !err) {
      // Verified exactly: FilaMan's search is a substring match, so an
      // unverified hit would announce somebody else's spool.
      for (JsonObjectConst cand : doc.as<JsonArrayConst>())
        if (spoolMatchesTag(cand, s_last_query)) { hit = true; break; }
    }
  }

  if (!hit) return;

  // Known now. Clearing this is what the loop reads as "ask again", the same
  // thing lifting the spool off the pad does, so the normal path fetches the
  // spool and paints the screen. Nothing is duplicated here.
  logSDf("Recheck: %s resolves now, re-reading", s_last_query);
  spoolman_queried_uid[0] = '\0';
}

void spoolmanRescanTick() {
  if (!s_rescan_uid[0]) return;
  // Signed difference, so the comparison survives the millis() rollover.
  if ((int32_t)(millis() - s_rescan_due_ms) < 0) return;

  char uid[sizeof(s_rescan_uid)];
  char fmt[sizeof(s_rescan_format)];
  strcpy(uid, s_rescan_uid);
  strcpy(fmt, s_rescan_format);
  // Cleared before the request, not after: this fires once either way, and a
  // server that is down must not turn into a scan on every single loop pass.
  s_rescan_uid[0] = '\0';

  if (!wifi_ok) return;
  if (!tag_present) {
    // The spool is already off the pad. Opening it in somebody's browser now
    // would be answering a question they stopped asking.
    logSDf("Rescan: uid=%s dropped, tag no longer on the reader", uid);
    return;
  }

  JsonDocument doc;
  int code = backendTagScan(cfg_spoolman_base, uid, fmt[0] ? fmt : nullptr,
                            doc, 5000, nullptr);
  logSDf("Rescan: uid=%s re-announced, matched=%d HTTP %d",
         uid, (int)(doc["matched_spool_id"] | 0), code);
}

void querySpoolman(const char* tray_uuid) {
  if (!wifi_ok) return;
  strncpy(s_last_query, tray_uuid ? tray_uuid : "", sizeof(s_last_query) - 1);
  s_last_query[sizeof(s_last_query) - 1] = '\0';
  logSDf("Spoolman: query tray_uuid=%.16s...", tray_uuid ? tray_uuid : "");

  // Reset all Spoolman labels before new query
  lv_label_set_text(lbl_spoolman_weight, T(STR_WAIT));
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_label_set_text(lbl_spoolman_dried_val, "");
  if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
  lv_label_set_text(lbl_detail, "-");
  lv_label_set_text(lbl_filament_name, "-");
  lv_label_set_text(lbl_last_used, "-");
  if (lbl_scale_diff) lv_obj_set_width(lbl_scale_diff, 0);
  if (lbl_spoolman_dried) lv_label_set_text(lbl_spoolman_dried, "");
  if (lbl_keys) lv_label_set_text(lbl_keys, "");
  if (lbl_raw_info) lv_label_set_text(lbl_raw_info, "");
  if (lbl_bag_sm_diff) lv_label_set_text(lbl_bag_sm_diff, "");
  // bei Bambu kommen diese Felder aus dem Tag selbst (updateDisplay) nicht aus Spoolman
  bool is_bambu_tag = (strlen(g_tag.material) > 0);
  if (!is_bambu_tag) {
    lv_label_set_text(lbl_material, "-");
    lv_label_set_text(lbl_vendor, "-");
    lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(0x333333), 0);
  }
  sm_last_dried[0] = '\0';
  sm_article_nr[0] = '\0';
  sm_filament_name[0] = '\0';
  sm_material_global[0] = '\0';
  sm_color_global[0] = '\0';
  sm_last_used[0] = '\0';
  sm_location_name[0] = '\0'; sm_location_id = 0;
  sm_status_id = 0;
  sm_found = false;
  sm_archived = false;
  sm_id = 0;
  sm_dup_count = 0;
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++) sm_tag_values[i][0] = '\0';
  sm_spool_weight = 0;
  sm_remaining = 0;
  sm_total = 1000;
  lv_timer_handler();

  Serial.printf("DBG free heap: %d bytes  free PSRAM: %d bytes\n", ESP.getFreeHeap(), ESP.getFreePsram());
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (before Spoolman GET)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  // Filter: only parse needed fields — reduces RAM, works with 100+ spools
  // Filter must be Array-wrapped to match the API array response structure
  // Sized with room for every tag field AND for the server's own text fields,
  // which are only known at runtime and can be a dozen. An overflowed filter
  // silently drops keys, and a dropped tag key makes every spool come back
  // looking unbound - hence the check after it is filled rather than trust in
  // the number.
  StaticJsonDocument<2048> filter;
  JsonArray filter_arr = filter.to<JsonArray>();
  JsonObject filter_spool = filter_arr.createNestedObject();
  filter_spool["id"] = true;
  filter_spool["archived"] = true;
  filter_spool["remaining_weight"] = true;
  // Fetched so a spool that has had its real fill weight measured keeps it
  // instead of falling back to the filament type's nominal on the next scan.
  filter_spool["initial_weight"] = true;
  filter_spool["spool_weight"] = true;
  filter_spool["last_used"] = true;
  filter_spool["location"] = true;
  // Every tag field, not just the selected one: the fallback pass above reads
  // whichever one a spool is actually bound through. The keys come from the
  // static spec table and outlive this document, which matters because
  // ArduinoJson does not copy a const char* key.
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++)
    filter_spool["extra"][tagFieldSpec(i).key] = true;
  filter_spool["extra"][LAST_DRIED_FIELD] = true;
  // Plus every other text field the server keeps, so the scan below can find a
  // UID that was put somewhere nobody agreed on. The keys are static storage
  // in the capability cache, which they have to be: ArduinoJson does not copy
  // a const char* key, and a document outliving its keys reads as garbage.
  for (uint8_t i = 0; i < backendSpoolTextFieldCount(); i++)
    filter_spool["extra"][backendSpoolTextFieldKey(i)] = true;
  // Spoolman's own tag relation, so the full scan can match a natively bound
  // spool too. A filter on an array of objects describes one element.
  filter_spool["tags"][0]["uid"] = true;
  filter_spool["filament"]["id"] = true;
  filter_spool["filament"]["name"] = true;
  filter_spool["filament"]["material"] = true;
  filter_spool["filament"]["weight"] = true;
  filter_spool["filament"]["article_number"] = true;
  filter_spool["filament"]["color_hex"] = true;
  filter_spool["filament"]["vendor"]["id"] = true;
  filter_spool["filament"]["spool_weight"] = true;
  filter_spool["filament"]["vendor"]["name"] = true;
  // Fetched so a spool with no tare of its own can fall back to the
  // filament or brand default instead of being weighed as if empty.
  filter_spool["filament"]["vendor"]["empty_spool_weight"] = true;
  if (filter.overflowed())
    logSD("Spoolman: scan filter overflowed, fields will be missing");

  // Use PSRAM for this document — frees internal RAM for LVGL
  SpiRamAllocator psram_alloc;
  JsonDocument doc(&psram_alloc);
  DeserializationError err = DeserializationError::Ok;

  // Fast path: both backends can filter by tag server side, so one small
  // answer replaces the whole inventory. With 268 spools that is under 1 kB
  // instead of 176 kB.
  //
  // An empty result is not proof of absence. In FilaMan the search only
  // covers rfid_uid, not custom_fields, so spools imported from Spoolman
  // stay invisible until their UID has been migrated. In Spoolman an older
  // server ignores the filter and answers with everything. Both cases are
  // caught by requiring an exact match below and otherwise falling through
  // to the full scan.
  bool have_result = false;

  // Spoolman's native tag lookup, when the server has it. One request that
  // resolves the tag and returns the spool with it, so it replaces the filter
  // search, the verification pass and the follow-up GET in one go.
  //
  // A null match is not proof of absence: it means "no native tag", and a
  // spool bound through an extra field is invisible here. That is why the
  // chain below still runs, exactly as it does for a missed filter search.
  // An installation that never chose is moved onto the native source the first
  // time a server turns out to have it. Here rather than at boot, because the
  // probe needs the network and boot does not have it yet.
  tagFieldAutoSelect();

  if (backendHasNativeTags()) {
    JsonDocument scan(&psram_alloc);
    DeserializationError serr = DeserializationError::Ok;
    // The chip uid, not the tray uuid: Spoolman's relation keys on hardware
    // uids, and so do the phone, the ESPHome readers and Spoolman's own Add
    // tag dialog. See the identity block in tag_field.h.
    const char* scan_uid = tagNativeUid(tray_uuid);
    int scode = backendTagScan(cfg_spoolman_base, scan_uid,
                               tagFormatName(tray_uuid), scan, 8000, &serr);
    if (scode == 200 && !serr && !scan["spool"].isNull()) {
      // Reshaped into the one element array the rest of this function reads,
      // so nothing downstream has to know where the spool came from.
      doc.clear();
      JsonArray one = doc.to<JsonArray>();
      one.add(scan["spool"]);
      have_result = true;
      logSDf("Backend: native tag scan hit, uid=%s spool %d",
             scan_uid, (int)(scan["matched_spool_id"] | 0));
    } else if (scode == 200) {
      logSDf("Backend: native tag scan, no native tag for uid=%s", scan_uid);
    } else if (scode != BACKEND_NOT_SUPPORTED) {
      logSDf("Backend: native tag scan failed, code=%d err=%s", scode, serr.c_str());
    }
    if (!have_result) { doc.clear(); err = DeserializationError::Ok; }
  }

  // A Bambu tag that an earlier firmware bound natively sits in the relation
  // under its tray uuid, and the scan above no longer asks for that one. This
  // catches those with a single exact lookup instead of the whole inventory,
  // and the auto-link at the end then adds the chip uid, so a spool pays for
  // this once. Only for Bambu: everywhere else the scan already asked this
  // very uid and a second request would repeat it.
  if (!have_result && tagIsBambu(tray_uuid)) {
    int ncode = backendFindSpoolByNativeTag(cfg_spoolman_base, tray_uuid,
                                            doc, 8000, &filter, &err);
    if (ncode == 200 && !err) {
      for (JsonObjectConst cand : doc.as<JsonArrayConst>()) {
        if (spoolMatchesTag(cand, tray_uuid)) { have_result = true; break; }
      }
      if (have_result)
        logSDf("Backend: native lookup hit on the tray uuid, %d spool(s) returned",
               (int)doc.as<JsonArrayConst>().size());
    } else if (ncode != BACKEND_NOT_SUPPORTED) {
      logSDf("Backend: native tag lookup failed, code=%d err=%s", ncode, err.c_str());
    }
    if (!have_result) { doc.clear(); err = DeserializationError::Ok; }
  }

  if (!have_result) {
    int fcode = backendFindSpoolByTag(cfg_spoolman_base, tray_uuid, doc, 8000, &err, &filter);
    if (fcode == 200 && !err) {
      // The server side search is a text filter, not an exact tag match. A
      // substring hit on some other spool must not suppress the full scan,
      // otherwise a spool whose UID still lives in custom_fields would be
      // reported as unknown. Only accept the short cut on a real match.
      for (JsonObjectConst s : doc.as<JsonArrayConst>()) {
        if (spoolMatchesTag(s, tray_uuid)) { have_result = true; break; }
      }
      if (have_result) {
        // The field is in the line on purpose: it is the only way to tell from
        // a log whether the fast path ran on the selected field or whether the
        // scan below did the work.
        logSDf("Backend: %s search hit, %d spool(s) returned",
               backendMode() == BACKEND_SPOOLMAN ? tagFieldKeyName() : "backend",
               (int)doc.as<JsonArrayConst>().size());
      }
    } else if (fcode != BACKEND_NOT_SUPPORTED) {
      // Every backend has a route for this by now, so NOT_SUPPORTED is only a
      // guard. Anything else is a real failure and should not disappear.
      logSDf("Backend: tag search failed, code=%d err=%s", fcode, err.c_str());
    }
    if (!have_result) {
      doc.clear();
      err = DeserializationError::Ok;
    }
  }

  // The fallback pass: the tag fields the user did NOT select. A spool linked
  // before the choice was changed still lives in its old field, and without
  // this it would look unknown until somebody relinked it by hand.
  //
  // Still server side, so it stays cheap - one small answer per field instead
  // of the whole inventory. Each is skipped unless the server actually has
  // that field, which is what keeps an installation that uses only one of them
  // from paying for the other two: backendFindSpoolByTagField() answers
  // BACKEND_NOT_SUPPORTED without spending a request.
  // Extra fields are a Spoolman convention. Running this on the others cost
  // no request, but it logged "no implementation yet" once a boot, which
  // reads like a missing feature rather than a loop that does not apply.
  const bool extra_fields_apply = (backendMode() == BACKEND_SPOOLMAN);

  // Both identities the tag can be stored under. A Bambu tag is carried around
  // as its tray uuid, but somebody may well have written the chip uid into a
  // field instead - that is what a reader without a Bambu decoder would have
  // reported to them. The second pass only exists for Bambu, and only runs
  // when the first found nothing, so the normal case still costs one request
  // per field.
  const char* candidates[2] = { tray_uuid, tagNativeUid(tray_uuid) };
  const uint8_t candidate_count = (candidates[1] != candidates[0]) ? 2 : 1;

  for (uint8_t c = 0; extra_fields_apply && !have_result && c < candidate_count; c++) {
   for (uint8_t f = 0; !have_result && f < TAG_FIELD_EXTRA_COUNT; f++) {
    // Only in the first pass: there the selected field already went ahead of
    // this loop. In the second it has not been asked for this value yet.
    if (c == 0 && f == tagFieldEffective()) continue;

    int ccode = backendFindSpoolByTagField(f, cfg_spoolman_base, candidates[c],
                                           doc, 8000, &err, &filter);
    if (ccode == 200 && !err) {
      // Every hit is verified: the filter is an ilike, so a four byte UID
      // matches inside a seven byte one belonging to a different spool.
      // spoolTagRank() checks both identities, so the tray uuid is the right
      // thing to verify with whichever value found the spool.
      for (JsonObjectConst s : doc.as<JsonArrayConst>()) {
        if (spoolMatchesTag(s, tray_uuid)) { have_result = true; break; }
      }
      if (have_result) {
        logSDf("Backend: %s search hit on %s, %d spool(s) returned",
               tagFieldSpec(f).key, candidates[c],
               (int)doc.as<JsonArrayConst>().size());
      }
    } else if (ccode != BACKEND_NOT_SUPPORTED) {
      logSDf("Backend: %s search failed, code=%d err=%s",
             tagFieldSpec(f).key, ccode, err.c_str());
    }
    if (!have_result) {
      doc.clear();
      err = DeserializationError::Ok;
    }
   }
  }

  // The fast lookups have all missed, so the whole inventory is coming. That is
  // seconds on a large library, and until now the display kept saying "reading
  // tag" throughout - the read was long done, and a wait that says the wrong
  // thing reads as a failure.
  //
  // Painted with lv_refr_now() rather than lv_timer_handler(): this runs from
  // appLoop, and a redraw is all that is wanted here. No timers, no input.
  if (lbl_status) {
    char buf[40];
    strncpy(buf, T(STR_SEARCHING_INVENTORY), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    lv_label_set_text(lbl_status, buf);
    lv_refr_now(NULL);
  }
  // The byte counter from the loading overlay, pointed at the status line
  // instead. Whether it is still moving is the only question a wait like this
  // raises, and the answer costs nothing here.
  httpSetProgressHook(searchProgress);

  // Up to 2 attempts: first try, then 1 retry on IncompleteInput / connection issues.
  // 20s timeout is generous for large Spoolman datasets (200+ spools over WiFi).
  for (int attempt = 1; !have_result && attempt <= 2; attempt++) {
    if (attempt > 1) {
      Serial.printf("Spoolman: retry attempt %d after %s\n", attempt, err.c_str());
      logSDf("Spoolman: retry attempt %d (prev err=%s)", attempt, err.c_str());
      delay(300);  // brief pause before retry
      doc.clear();
    }

    int code = backendGetSpoolListJson(cfg_spoolman_base, false, doc, 20000, &filter, &err);
    if (code != 200) {
      Serial.printf("Spoolman HTTP error: %d (attempt %d)\n", code, attempt);
      logSDf("Spoolman: HTTP error %d (attempt %d)", code, attempt);
      if (attempt == 2) {
        lv_label_set_text(lbl_spoolman_weight, code == -2 ? T(STR_LINK_JSON_ERR) : T(STR_API_ERROR));
        return;
      }
      if (code == -2 &&
          err != DeserializationError::IncompleteInput &&
          err != DeserializationError::EmptyInput) {
        break;
      }
      continue;  // retry on HTTP or transient parse error too
    }

    // Stream directly from HTTP — avoids allocating a 40KB+ String in RAM

    if (!err) break;  // success
    // Parse failed -> retry only on transient stream issues
    if (err != DeserializationError::IncompleteInput &&
        err != DeserializationError::EmptyInput) {
      break;  // other errors are not transient -> don't retry
    }
  }

  httpSetProgressHook(nullptr);

  Serial.printf("DBG free heap after parse: %d bytes  free PSRAM: %d bytes\n", ESP.getFreeHeap(), ESP.getFreePsram());
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (after Spoolman parse)",
    ESP.getFreeHeap(), ESP.getFreePsram());
  if (err) {
    Serial.printf("Spoolman JSON error (final): %s\n", err.c_str());
    logSDf("Spoolman: JSON error final=%s", err.c_str());
    lv_label_set_text(lbl_spoolman_weight, T(STR_LINK_JSON_ERR));
    return;
  }

  JsonArray spools = doc.as<JsonArray>();

  // Which rank the best match reaches, and how many spools answer to this tag
  // at all. Both need the whole list, so they are settled before anything is
  // shown: the loop below returns on the first spool it accepts, and taking
  // the first match in list order would hand a Bambu plugin duplicate the win
  // over the record this scale linked itself. FilaMan answers id descending,
  // so the duplicate comes first.
  int best_rank = TAG_RANK_NONE;
  sm_dup_count  = 0;
  for (JsonObjectConst cand : spools) {
    int rank = spoolTagRank(cand, tray_uuid);
    if (rank == TAG_RANK_NONE) continue;
    sm_dup_count++;
    if (best_rank == TAG_RANK_NONE || rank < best_rank) best_rank = rank;
  }
  if (sm_dup_count > 1) {
    logSDf("Backend: tag %s answers %d spools, taking rank %d",
           tray_uuid, sm_dup_count, best_rank);
  }

  for (JsonObject spool : spools) {
    if (!spool.containsKey("extra")) continue;
    JsonObject extra = spool["extra"];

    int rank = spoolTagRank(spool, tray_uuid);
    if (rank == TAG_RANK_NONE || rank != best_rank) continue;

    // Read after the match, not as part of it: the FilaMan migration below
    // writes this value back and wants the tag field's own notation. A spool
    // matched through card_uids has no tag field, which leaves this empty -
    // harmless, because that migration only runs in FilaMan mode.
    String tag_val;
    if (extra.containsKey("tag")) {
      tag_val = extra["tag"].as<String>();
      tag_val.replace("\"", "");
      tag_val.trim();
    }

    // FOUND
    sm_found    = true;
    sm_id       = spool["id"] | 0;

    // One-off migration to the plain hex notation. Older firmware wrote an
    // NTAG uid into extra.tag with colons, which is the one notation the
    // server side ilike cannot find once the scale asks in plain hex - the
    // spool is still found, but only by pulling the whole inventory. Writing
    // it back once puts it on the fast path for good.
    //
    // Deliberately narrow:
    //  - only the native Spoolman backend. FilaMan has its own migration two
    //    blocks down, and BamBuddy normalised from the start.
    //  - only a match through the tag field itself. A spool found through the
    //    Bambu plugin's bookkeeping has nothing to correct here.
    //  - never a list field. card_uids holds several entries and writing one
    //    value into it would drop the rest.
    //  - only when the stored value really differs, so a correct entry is not
    //    patched on every scan.
    //
    // A failed write is remembered rather than retried. A key without write
    // permission would otherwise stall and log on every single placement, and
    // the spool is found either way - the migration is a speed-up, not a
    // requirement.
    // Both backends that store a tag in a text field are covered. BamBuddy is
    // not: it normalised from the start and its tag never reaches this loop.
    //
    // The value differs by backend but the question does not. Spoolman keeps
    // it in whichever extra field the user picked, FilaMan in the native
    // rfid_uid, which the mapping presents here as extra.tag.
    const bool notation_backend =
        (backendMode() == BACKEND_SPOOLMAN &&
         !tagFieldIsNative() && !tagFieldIsList() && tagFieldKey()) ||
        // tag_legacy has its own migration below and would double patch.
        (backendIsFilaMan() && !(spool["extra"]["tag_legacy"] | false));
    if (notation_backend && sm_id > 0 && rank == TAG_RANK_FIELD) {
      static int s_migrate_failed_id = 0;    // do not hammer a read-only key
      String stored;
      const char* key = backendIsFilaMan() ? "tag" : tagFieldKey();
      if (extra.containsKey(key)) {
        stored = extra[key].as<String>();
        stored.replace("\"", "");
        stored.trim();
      }
      char want[TAG_UID_CMP_MAX];
      tagUidNormalize(stored.c_str(), want, sizeof(want));
      if (stored.length() && want[0] && stored != want && sm_id != s_migrate_failed_id) {
        int mc = backendPatchSpoolTag(cfg_spoolman_base, sm_id, want, 4000);
        logSDf("%s: rewrote tag of spool %d to plain hex, HTTP %d",
               backendIsFilaMan() ? "FilaMan" : "Spoolman", sm_id, mc);
        s_migrate_failed_id = (mc == 200) ? 0 : sm_id;
      }
    }

    // One-off migration for spools imported from Spoolman. Their UID lives in
    // custom_fields, where FilaMan's ?search= cannot see it, so every scan
    // would pull the whole inventory. Writing it to the native rfid_uid once
    // puts the spool on the fast path for good. Silent by design, the user
    // has nothing to decide here.
    //
    // Keyed off the flag the reader set, not off which path found the spool:
    // a failed tag search also lands here, and re-patching an already correct
    // rfid_uid on every scan would be a pointless write and a needless stall.
    if (backendIsFilaMan() && sm_id > 0 && (spool["extra"]["tag_legacy"] | false)) {
      int mc = backendPatchSpoolTag(cfg_spoolman_base, sm_id, tag_val.c_str(), 4000);
      logSDf("FilaMan: migrated tag of spool %d to rfid_uid, HTTP %d", sm_id, mc);
    }

    // The same idea, one field over: a spool found through the Bambu plugin's
    // own bookkeeping has nothing in rfid_uid, so ?search= cannot see it and
    // every scan would pull the whole inventory again. Writing the tray uuid
    // there once puts it on the fast path for good.
    //
    // Only from rank 2 or 3, which is what "found through the plugin" means.
    // A rank 1 match already has the field, and re-patching it on every scan
    // would be a pointless write and a needless stall.
    if (backendIsFilaMan() && sm_id > 0 && rank > TAG_RANK_FIELD && tag_val.length() == 0) {
      int mc = backendPatchSpoolTag(cfg_spoolman_base, sm_id, tray_uuid, 4000);
      logSDf("FilaMan: spool %d found at rank %d, wrote rfid_uid, HTTP %d",
             sm_id, rank, mc);
    }

    if (backendIsFilaMan() && sm_id > 0) {
      filamanSyncBambuFields(sm_id, extra, tray_uuid);
    }

    captureBindings(spool);

    sm_filament_id = spool["filament"]["id"] | 0;
    sm_vendor_id   = spool["filament"]["vendor"]["id"] | 0;
    sm_remaining = spool["remaining_weight"] | 0.0f;
    sm_total    = resolveInitial(spool);
    sm_spool_weight = resolveTare(spool, &sm_tare_source);
    logSDf("Spoolman: found ID=%d remaining=%.1fg total=%.0fg",
      sm_id, sm_remaining, sm_total);
    logSDf("[verbose] LOC: querySpoolman id=%d shown_for=%d", sm_id, g_loc_popup_shown_for_id);
    String art_nr = spool["filament"]["article_number"] | "";
    art_nr.trim();
    strncpy(sm_article_nr, art_nr.c_str(), sizeof(sm_article_nr)-1);
    sm_article_nr[sizeof(sm_article_nr)-1] = '\0';
    String fil_name = spool["filament"]["name"] | String("");
    fil_name.trim();
    strncpy(sm_filament_name, fil_name.c_str(), sizeof(sm_filament_name)-1);
    sm_filament_name[sizeof(sm_filament_name)-1] = '\0';

    // Location — einfacher String in Spoolman
    sm_location_name[0] = '\0';
    if (!spool["location"].isNull() && spool["location"].is<const char*>()) {
      String loc = spool["location"] | String("");
      loc.trim();
      strncpy(sm_location_name, loc.c_str(), sizeof(sm_location_name)-1);
      sm_location_name[sizeof(sm_location_name)-1] = '\0';
    }

    // Spool status. Only FilaMan maps it, the others leave the key unset.
    sm_status_id = spool["status_id"] | 0;
    if (extra.containsKey("last_dried")) {
      String dried = extra["last_dried"].as<String>();
      dried.replace("\"", "");
      char day[11];
      isoDayLocal(dried.c_str(), day, sizeof(day));
      char de_date[12];
      isoToDe(day, de_date, sizeof(de_date));
      strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
      sm_last_dried[sizeof(sm_last_dried)-1] = '\0';
    } else {
      strncpy(sm_last_dried, "-", sizeof(sm_last_dried)-1);
    }

    Serial.printf("Spoolman: ID=%d, %.1fg, dried: %s\n",
      sm_id, sm_remaining, sm_last_dried);

    // Read material, vendor, color from Spoolman
    // → shown when no Bambu tag (g_tag.material empty)
    String sm_material = spool["filament"]["material"] | String("");
    sm_material.trim();
    String sm_vendor_name = "";
    if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull()) {
      sm_vendor_name = spool["filament"]["vendor"]["name"] | String("");
      sm_vendor_name.trim();
    snprintf(sm_vendor_g, sizeof(sm_vendor_g), "%s", sm_vendor_name.c_str());
    }
    String sm_color = spool["filament"]["color_hex"] | String("");
    sm_color.trim();

    // Only fill fields from Spoolman if no Bambu tag present
    bool is_ntag = !is_bambu_tag;
    logSDf("Spool %d identified: %s %s, %.0fg of %.0fg", sm_id,
           sm_vendor_name.length() ? sm_vendor_name.c_str() : "?",
           sm_material.length() ? sm_material.c_str() : "?",
           sm_remaining, sm_total);
    Serial.printf("is_ntag=%d material='%s' vendor='%s' color='%s'\n",
      is_ntag, sm_material.c_str(), sm_vendor_name.c_str(), sm_color.c_str());
    if (is_ntag) {
      lv_label_set_text(lbl_material, sm_material.length() > 0 ? sm_material.c_str() : "-");
      lv_label_set_text(lbl_vendor, sm_vendor_name.length() > 0 ? sm_vendor_name.c_str() : "-");
      strncpy(sm_material_global, sm_material.c_str(), sizeof(sm_material_global)-1);
      sm_material_global[sizeof(sm_material_global)-1] = '\0';
      strncpy(sm_color_global, sm_color.c_str(), sizeof(sm_color_global)-1);
      sm_color_global[sizeof(sm_color_global)-1] = '\0';
      // Color swatch from Spoolman color_hex (#RRGGBB or RRGGBB)
      if (sm_color.length() >= 6) {
        lv_obj_set_style_bg_color(lbl_color_swatch, swatchColorFromHex(sm_color.c_str()), 0);
        // Logs the raw server value rather than the parsed one, so a malformed
        // colour is visible in the log instead of silently reading as grey.
        Serial.printf("Color set: %s\n", sm_color.c_str());
      }
    }

    // Update display — Fix 5: color based on remaining %
    char weight_str[32];
    snprintf(weight_str, sizeof(weight_str), "%.0f g", sm_remaining);
    lv_label_set_text(lbl_spoolman_weight, weight_str);
    float pct = (sm_total > 0) ? (sm_remaining / sm_total) * 100.0f : 0;

    // Choose color: 0-10% red, 11-30% orange, 31-100% green
    uint32_t pct_color;
    if (pct <= 10.0f)       pct_color = 0xe04040;
    else if (pct <= 30.0f)  pct_color = 0xf0b838;
    else                    pct_color = 0x28d49a;

    lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(pct_color), 0);

    char pct_str[16];
    snprintf(pct_str, sizeof(pct_str), "%.1f %%", pct);
    lv_label_set_text(lbl_spoolman_pct, pct_str);
    lv_obj_set_style_text_color(lbl_spoolman_pct, lv_color_hex(pct_color), 0);

    // Update progress bar fill width (max 190px) with same color
    if (lbl_scale_diff) {
      int bar_w = (int)((pct / 100.0f) * (float)MAIN_BAR_W);
      if (bar_w < 0) bar_w = 0;
      if (bar_w > MAIN_BAR_W) bar_w = MAIN_BAR_W;
      lv_obj_set_width(lbl_scale_diff, bar_w);
      lv_obj_set_style_bg_color(lbl_scale_diff, lv_color_hex(pct_color), 0);
    }

    // Show SM-ID in green (linked)
    char sm_id_str[16];
    snprintf(sm_id_str, sizeof(sm_id_str), "%d", sm_id);
    lv_label_set_text(lbl_spoolman_id, sm_id_str);
    lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0x28d49a), 0);

    // Last drying: set value with "N days ago"
    char dried_display[48];
    driedDisplayStr(sm_last_dried, dried_display, sizeof(dried_display));
    applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, sm_last_dried);

    lv_label_set_text(lbl_detail, strlen(sm_article_nr) > 0 ? sm_article_nr : "-");
    lv_label_set_text(lbl_filament_name, strlen(sm_filament_name) > 0 ? sm_filament_name : "-");

    // last_used is directly in the spool object (not in extra!)
    applyLastUsed(spool["last_used"] | (const char*)nullptr,
                spool["extra"]["last_weighed"] | (const char*)nullptr, sm_id);

    // Bring Spoolman's relation up to what is physically on the reader. Two
    // groups of users end up here: somebody whose spools are bound through an
    // extra field, whose bindings move over on the first placement, and
    // somebody with Bambu spools, which collect one entry per side as each
    // side gets read.
    //
    // A Bambu spool ends up with up to three entries, and each earns its place:
    //   chip uid, one per side  every reader can report these, so they are
    //                           what makes the spool findable by a phone, an
    //                           ESPHome box, or Spoolman's Add tag dialog
    //   tray uuid               only a Bambu-aware reader can produce it, but
    //                           it identifies the spool from either side at
    //                           once, without waiting for both chips
    //
    // What is already linked comes from captureBindings() above, so nothing is
    // sent that Spoolman already holds and a settled spool costs no requests
    // at all.
    //
    // Only while the native source is the selected one. Somebody who picked
    // extra.nfc_id did so because another tool reads that field, and writing
    // into a store they did not choose is not this scale's call.
    //
    // Nothing is cleared here, unlike the explicit link in patchSpoolTag().
    // This runs on its own, without anybody asking for it, and a store that
    // silently empties a field the user never touched is worse than one that
    // leaves a duplicate behind.
    if (tagFieldIsNative() && sm_id > 0 && backendHasNativeTags()) {
      char* have = sm_tag_values[TAG_FIELD_NATIVE];

      struct AutoLink {
        // Whether anything was actually linked, which is what decides if the
        // tag is worth announcing a second time.
        static bool add(int spool_id, const char* uid, const char* format) {
          int conflict = 0;
          int code = backendLinkTag(cfg_spoolman_base, spool_id, uid,
                                    format, &conflict);
          if (code == 409) {
            // Nobody asked for this link, so a tag that belongs to another
            // spool is not an error to put on screen. It is worth a line in
            // the log, because it means two spools claim one identity.
            logSDf("Auto-link: uid=%s belongs to spool %d, left alone",
                   uid, conflict);
            return false;
          } else if (code >= 200 && code < 300) {
            logSDf("Auto-link: uid=%s added to spool %d", uid, spool_id);
            return true;
          }
          logSDf("Auto-link: uid=%s to spool %d failed, HTTP %d",
                 uid, spool_id, code);
          return false;
        }

        // Keeps the captured list in step with what was just linked. It was
        // read before these links existed, and an unlink straight afterwards
        // reads that same list to decide what to drop. Without this it would
        // leave the new entries behind, and a spool the user was told is
        // unlinked would still be found by them.
        static void remember(char* list, const char* uid) {
          char merged[CARD_UIDS_MAX];
          if (cardUidsAppend(list, uid, merged, sizeof(merged)) != CARD_UIDS_ADDED)
            return;
          strncpy(list, merged, CARD_UIDS_MAX - 1);
          list[CARD_UIDS_MAX - 1] = '\0';
        }
      };

      bool linked = false;
      const char* chip = tagNativeUid(tray_uuid);
      if (chip && chip[0] && !cardUidsContain(have, chip)) {
        if (AutoLink::add(sm_id, chip, tagFormatName(tray_uuid))) {
          AutoLink::remember(have, chip);
          linked = true;
        }
      }

      if (tagIsBambu(tray_uuid) && !cardUidsContain(have, tray_uuid)) {
        if (AutoLink::add(sm_id, tray_uuid, "bambu")) {
          AutoLink::remember(have, tray_uuid);
          linked = true;
        }
      }

      // OpenSpoolman reads a spool's tray uuid out of extra.tag and knows
      // nothing about Spoolman's relation yet. A spool that migrates over
       // through this path - found by a chip uid in card_uids, say - would
      // otherwise drop out of its view, and this is the very path a whole
      // library gets adopted through. The explicit link in patchSpoolTag()
      // does the same thing for the same reason.
      //
      // Only into an empty field. Filling a blank is an addition; overwriting
      // a value somebody put there would be an opinion, and this runs without
      // anybody asking for it.
      if (tagIsBambu(tray_uuid) && !sm_tag_values[TAG_FIELD_TAG][0]) {
        const TagFieldSpec& companion = tagFieldSpec(TAG_FIELD_TAG);
        if (backendHasExtraField(companion.key)) {
          char val[40];
          tagFieldFormat(companion, tray_uuid, val, sizeof(val));
          int c = backendPatchExtraField(cfg_spoolman_base, sm_id,
                                         companion.key, val);
          logSDf("Auto-link: kept tray uuid in %s='%s' of spool %d HTTP %d",
                 companion.key, val, sm_id, c);
          if (c >= 200 && c < 300) {
            strncpy(sm_tag_values[TAG_FIELD_TAG], val, CARD_UIDS_MAX - 1);
            sm_tag_values[TAG_FIELD_TAG][CARD_UIDS_MAX - 1] = '\0';
          }
        } else {
          logSDf("Auto-link: %s missing on the server, tray uuid not kept",
                 companion.key);
        }
      }

      // The scan that started this lookup went out before the link existed, so
      // any browser paired with this scale was told the tag is unknown. Say it
      // again, now that it resolves.
      if (linked && chip && chip[0])
        scheduleRescan(chip, tagFormatName(tray_uuid));
    }

    updateLinkButton();
    return;
  }

  // Not found in active spools — check if archived
  Serial.println("Spoolman: not in active spools, checking archive...");
  doc.clear();  // RAM freigeben vor zweitem Call

  // Second call with allow_archived=true.
  // DynamicJsonDocument is the deprecated v6 shim in ArduinoJson 7: the
  // capacity argument is ignored and it allocates from the internal heap
  // without limit. With a large FilaMan archive that is a way to run the
  // internal RAM dry, so this one uses PSRAM like the active list above.
  JsonDocument doc2(&psram_alloc);
  DeserializationError err2 = DeserializationError::Ok;
  StaticJsonDocument<384> filter2;
  JsonArray filter2_arr = filter2.to<JsonArray>();
  JsonObject f2 = filter2_arr.createNestedObject();
  f2["id"] = true;
  f2["archived"] = true;
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++)
    f2["extra"][tagFieldSpec(i).key] = true;
  int code2 = backendGetSpoolListJson(cfg_spoolman_base, true, doc2, 8000, &filter2, &err2);
  if (code2 == 200) {
    if (!err2) {
      JsonArray spools2 = doc2.as<JsonArray>();
      for (JsonObject spool : spools2) {
        // Only check truly archived spools (explicit bool cast needed for JsonVariant)
        bool is_archived = spool["archived"].as<bool>();
        if (!is_archived) continue;
        if (spoolTagRank(spool, tray_uuid) == TAG_RANK_NONE) continue;
        // Archived, but found. Fetching it whole rather than painting a dead
        // end here: the user has to see which spool this is before deciding to
        // bring it back, and that means name, filament and tare, none of which
        // the lean archive filter carries. querySpoolmanById() reads `archived`
        // and sets sm_archived, so everything that writes holds off.
        const int archived_id = spool["id"] | 0;
        Serial.printf("Spoolman: spool archived (ID=%d)\n", archived_id);
        logSDf("Spoolman: found ID=%d, archived", archived_id);
        doc2.clear();          // the byId fetch wants the PSRAM back
        querySpoolmanById(archived_id);

        // Said after the fetch, which has just painted the ordinary weight.
        // Zero grams is what archiving leaves behind, and showing that number
        // would read as a measurement rather than as a state.
        if (sm_archived) {
          lv_label_set_text(lbl_spoolman_weight, T(STR_ARCHIVED));
          lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x808080), 0);
          lv_label_set_text(lbl_spoolman_pct, "");
          if (lbl_scale_diff) lv_obj_set_width(lbl_scale_diff, 0);
        }
        updateLinkButton();
        return;
      }
    }
  }

  // Truly not found
  Serial.println("Spoolman: spool not found");
  logSD("Spoolman: spool not found");
  { char nb[40]; backendText(T(STR_NOT_IN_SPOOLMAN), nb, sizeof(nb)); lv_label_set_text(lbl_spoolman_weight, nb); }
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  sm_found = false;
  updateLinkButton();
}
