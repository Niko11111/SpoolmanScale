#include "spoolman_lookup.h"
#include "spoolman_lookup_internal.h"
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

// From ui/spool_flow.cpp: whether a spool of an inventory list is bound to a
// tag, through whichever of the tag fields. Handed to services/spool_cache with
// the inventory the full scan fetches, so the link flow's rule stays the only
// one. Declared here and not in spool_flow.h, which cannot include ArduinoJson:
// it is included behind lang.h elsewhere, and the T() macro breaks the
// library's templates.
bool spoolHasAnyTag(JsonObjectConst spool);

#include "services/location_state.h"
#include "services/backend.h"
#include "services/breadcrumb.h"
#include "services/backend_api.h"
#include "services/filaman_api.h"
#include "services/http_progress.h"
#include "services/server_reach.h"
#include "services/spool_cache.h"
#include "services/spoolman_actions.h"
#include "services/spoolman_api.h"
#include "services/tag_field.h"
#include "services/tag_write.h"
#include "services/tag_uid.h"
#include "services/time_service.h"
#include "services/uid_index.h"
#include "ui/spool_flow.h"
#include "services/user_options.h"
#include "ui/date_display.h"
#include "ui/main_screen_helpers.h"
#include "ui/theme.h"
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
// TAG_UID_CMP_MAX and the TAG_RANK_* ranks stand in spoolman_lookup_internal.h,
// the verdict in lookup_scan.cpp reads them too.

// A 4 byte chip uid is 8 characters, and the plugin pads it to 16 with a
// fixed tail. Both lengths are checked rather than the tail itself: the tail
// is what the AMS reported, not something this firmware gets to define.
#define BAMBU_CHIP_UID_LEN    8
#define BAMBU_TAG_FIELD_LEN  16

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

int spoolTagRank(JsonObjectConst spool, const char* uid) {
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
    if (extra[spec.key].isNull()) continue;

    // Both identities, and in both notations: a UID written into nfc_id by
    // SpoolSense is plain hex while the scale carries it around with colons,
    // and neither is wrong. For a Bambu tag the chip uid counts too, because
    // somebody may have put that into the field rather than the tray uuid.
    const char* raw = extra[spec.key] | (const char*)nullptr;
    if (storedNamesTag(raw, spec.is_list, uid)) return TAG_RANK_FIELD;
  }

  // FilaMan's second slot, which mapSpool() puts here because extra.tag holds
  // one value. Rank 1 like the first one, and not a tag field: it binds the
  // spool just as hard, the chip is simply on the other flange. Anything
  // lower would let a spool that merely mentions the same value somewhere
  // else win against a real binding.
  //
  // No spec and no list. FilaMan keeps two columns, not a list, and the key
  // exists only on a server that has the second one.
  {
    const char* raw2 = extra["tag2"] | (const char*)nullptr;
    if (storedNamesTag(raw2, false, uid)) return TAG_RANK_FIELD;
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
  if (extra[key].isNull()) return;

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
void captureBindings(JsonObjectConst spool) {
  JsonObjectConst extra = spool["extra"];
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++) {
    const TagFieldSpec& spec = tagFieldSpec(i);
    captureExtraField(extra, spec.key, sm_tag_values[i], CARD_UIDS_MAX, spec.key);
  }

  // Read here rather than in its own pass, and before the early return below:
  // a spool with no native tags leaves this function at that return, and the
  // companion field has nothing to do with the relation.
  captureExtraField(extra, RFID_TAG_FIELD, sm_hw_uid_value,
                    CARD_UIDS_MAX, RFID_TAG_FIELD);

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
void filamanSyncBambuFields(int spool_id, JsonObjectConst extra,
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
void applyLastUsed(const char* native_iso, const char* weighed_iso, int spool_id) {
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

  // In weighed mode the event log is the only correct source, and only a
  // weighing counts. In last used mode it serves as a fallback and any entry
  // that moved the weight counts, because that is what "used" means: FilaMan
  // books a print into the log and leaves last_used_at null, so asking only
  // for weighings left the line empty on a spool that had been printed from
  // all month.
  if (backendIsFilaMan() && (last_used_mode == 1 || !iso[0])) {
    char found[40];
    const bool ok = (last_used_mode == 1)
      ? backendGetLastWeighedAt(cfg_spoolman_base, spool_id, found, sizeof(found))
      : backendGetLastUsedAt(cfg_spoolman_base, spool_id, found, sizeof(found));
    if (ok) {
      strncpy(iso, found, sizeof(iso) - 1);
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
//  Used after link-flow - fetches only one spool by ID.
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
float resolveTare(JsonVariantConst spool, uint8_t *source) {
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
float resolveInitial(JsonVariantConst spool) {
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

// The server wins wherever it says anything. Where it says nothing, whatever
// the tag carried stays on screen, and only when both are empty does the field
// fall back to a dash. Before this, a spool whose filament had no material
// wiped the value the tag had just shown.
void setFromServerOrTag(lv_obj_t *lbl, const char *server, const char *from_tag) {
  if (server && server[0])      lv_label_set_text(lbl, server);
  else if (from_tag && from_tag[0]) lv_label_set_text(lbl, from_tag);
  else                          lv_label_set_text(lbl, "-");
}

// The server's colour for the spool just found. On an NTAG it is the colour,
// as it always was. On a Bambu tag it fills only what the tag leaves open -
// an unread colour block, or the tint of a clear filament - because the tag
// holds the manufacturer's value, see spoolColorResolve(). Kept in
// sm_color_global for both, so the More Info screen resolves the same way.
void applyServerColor(const String& sm_color, bool is_bambu_tag) {
  snprintf(sm_color_global, sizeof(sm_color_global), "%s", sm_color.c_str());
  SpoolColor server;
  spoolColorParse(sm_color.c_str(), &server);
  const SpoolColor shown = is_bambu_tag ? spoolColorResolve(g_tag.color, server) : server;
  if (!shown.valid) return;
  swatchPaint(lbl_color_swatch, shown);
  // The raw server value rather than the parsed one, so a malformed colour is
  // visible in the log instead of silently reading as grey.
  Serial.printf("Color set: tag %s, server '%s'\n", g_tag.color_hex, sm_color.c_str());
}

void querySpoolmanById(int spool_id) {
  if (!wifi_ok) return;
  Serial.printf("querySpoolmanById: ID=%d\n", spool_id);
  logSDf("Backend: query by ID=%d", spool_id);
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (before byID GET)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  JsonDocument doc;
  DeserializationError err = DeserializationError::Ok;
  // Reached after something the user did - a link, a copy, a reactivation -
  // so a server that is gone gets the popup every time.
  int code = serverReachNote(backendGetSpoolJson(cfg_spoolman_base, spool_id, doc, 8000, &err), true);
  if (code != 200) {
    Serial.printf("querySpoolmanById HTTP error: %d\n", code);
    logSDf("Backend byID: HTTP error %d", code);
    if (code == -2) {
      Serial.println("querySpoolmanById: JSON error");
      logSD("Backend byID: JSON error");
    }
    return;
  }
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (after byID parse)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  JsonObject spool = doc.as<JsonObject>();
  bool is_bambu_tag = (strlen(g_tag.material) > 0);

  sm_found        = true;
  sm_id           = spool["id"] | 0;
  // One spool, asked for by id: a duplicate count left over from the last
  // scan would keep the status line saying "more than one answered".
  sm_dup_count    = 0;
  // Found and archived is a state of its own, see app_state.h. Read here
  // because this is the one path that fetches a spool whole.
  sm_archived     = spool["archived"] | false;
  sm_filament_id  = spool["filament"]["id"] | 0;
  sm_vendor_id    = spool["filament"]["vendor"]["id"] | 0;
  sm_remaining    = spool["remaining_weight"] | 0.0f;
  sm_total        = resolveInitial(spool);
  sm_spool_weight = resolveTare(spool, &sm_tare_source);
  logSDf("Backend: byID OK ID=%d remaining=%.1fg tare=%.0fg (%s)",
    sm_id, sm_remaining, sm_spool_weight, tareSourceName(sm_tare_source));

  String art_nr = spool["filament"]["article_number"] | "";
  art_nr.trim();
  strncpy(sm_article_nr, art_nr.c_str(), sizeof(sm_article_nr)-1);
  sm_article_nr[sizeof(sm_article_nr)-1] = '\0';

  String fil_name = spool["filament"]["name"] | String("");
  fil_name.trim();
  strncpy(sm_filament_name, fil_name.c_str(), sizeof(sm_filament_name)-1);
  sm_filament_name[sizeof(sm_filament_name)-1] = '\0';

  // Location - Spoolman gibt location als einfachen String zurück
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
  if (!spool["extra"]["last_dried"].isNull()) {
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

  // Material and vendor only for an NTAG, a Bambu tag carries its own. The
  // colour for both, through applyServerColor().
  String sm_material = spool["filament"]["material"] | String("");
  sm_material.trim();
  String sm_vendor_name = "";
  if (!spool["filament"]["vendor"].isNull()) {
    sm_vendor_name = spool["filament"]["vendor"]["name"] | String("");
    sm_vendor_name.trim();
    snprintf(sm_vendor_g, sizeof(sm_vendor_g), "%s", sm_vendor_name.c_str());
  }
  String sm_color = spool["filament"]["color_hex"] | String("");
  sm_color.trim();

  bool is_ntag = !is_bambu_tag;
  if (is_ntag) {
    const TagInfo *ti = tagCachedInfo();
    const bool from_tag = tagCachedHasRecord();
    setFromServerOrTag(lbl_material, sm_material.c_str(), from_tag ? ti->material : "");
    setFromServerOrTag(lbl_vendor, sm_vendor_name.c_str(), from_tag ? ti->brand : "");
    strncpy(sm_material_global, sm_material.c_str(), sizeof(sm_material_global)-1);
    sm_material_global[sizeof(sm_material_global)-1] = '\0';
  } else {
    // Bambu-Tag: Material aus g_tag.material in sm_material_global schreiben
    // damit dryingAlertLevel() das Material korrekt auflösen kann
    if (g_tag.material[0]) {
      strncpy(sm_material_global, g_tag.material, sizeof(sm_material_global)-1);
      sm_material_global[sizeof(sm_material_global)-1] = '\0';
    }
  }
  applyServerColor(sm_color, is_bambu_tag);

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

void scheduleRescan(const char* uid, const char* format) {
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

// Set when a lookup skipped its inventory scan because a question was waiting
// to be answered. Declared here so the tick below and querySpoolman() share
// one flag rather than each keeping half the story.
bool s_scan_deferred = false;

// Whether the last lookup ended in a real "not in the inventory", the only
// answer that makes a later hit a binding made from outside. A lookup that
// failed on the way, or withheld its verdict over a partial list, says nothing
// about the tag: on 19.09.2026 the lookup right after the scale's own link
// failed like that, the recheck then found the spool, took the link for a
// foreign one, and wrote the tag and asked for the second tag a second time.
bool s_verdict_unknown = false;

// Whether the last lookup ended on a server it could not reach. The status
// line reads it: without it the resting text said "not in Spoolman" about a
// spool nobody had been able to ask about.
static bool s_lost_connection = false;

// The recheck's pace. The gap is measured from the END of the last probe, 0
// until the tick has seen the current lookup: measured from its start, a probe
// that took the whole 5 s connect timeout was already due again on the next
// loop pass. querySpoolman() resets both, so every lookup starts on the short
// gap and the first probe waits a full gap after the lookup itself.
static uint32_t s_recheck_end_ms = 0;
static uint32_t s_recheck_gap_ms = TAG_RECHECK_MS;

// Whether the backend knows a spool by this tag, asked the cheap way: the
// server side lookup, a handful of fields, no inventory scan and no /tag/scan,
// so nothing is announced to a paired browser. Says nothing about which spool
// it is - whoever gets a yes runs the normal lookup next.
bool spoolmanTagResolves(const char* query, bool* out_unanswered, int* out_spool_id) {
  if (out_unanswered) *out_unanswered = false;
  if (out_spool_id) *out_spool_id = 0;
  if (!query || !query[0]) return false;

  // Only the fields the verification reads. The point of this pass is that it
  // stays small: a real miss still falls through to the inventory scan in
  // querySpoolman(), and doing that every few seconds is exactly what must not
  // happen here.
  JsonDocument filter;
  JsonArray filter_arr = filter.to<JsonArray>();
  JsonObject f = filter_arr.add<JsonObject>();
  f["id"] = true;
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++)
    f["extra"][tagFieldSpec(i).key] = true;
  f["tags"][0]["uid"] = true;

  SpiRamAllocator psram_alloc;
  JsonDocument doc(&psram_alloc);
  DeserializationError err = DeserializationError::Ok;
  bool hit = false;
  int code = 0;

  // Every backend has a cheap lookup by tag, so this works for all three. The
  // one split: with Spoolman's own relation selected there is no extra field
  // to filter on, and backendFindSpoolByTag() would answer NOT_SUPPORTED.
  if (backendHasNativeTags()) {
    const char* nu = tagNativeUid(query);
    code = backendFindSpoolByNativeTag(cfg_spoolman_base, nu, doc, 5000, &filter, &err);
    if (code == 200 && !err) {
      for (JsonObjectConst cand : doc.as<JsonArrayConst>())
        if (spoolMatchesTag(cand, query)) {
          hit = true;
          if (out_spool_id) *out_spool_id = cand["id"] | 0;
          break;
        }
    }
    if (!hit) { doc.clear(); err = DeserializationError::Ok; }
  }

  // A server that did not answer the first request will not answer the second
  // either, and each of them can hold the loop for the whole connect timeout.
  if (!hit && !serverReachIsNetworkFailure(code)) {
    code = backendFindSpoolByTag(cfg_spoolman_base, query, doc, 5000, &err, &filter);
    if (code == 200 && !err) {
      // Verified exactly: FilaMan's search is a substring match, so an
      // unverified hit would announce somebody else's spool.
      for (JsonObjectConst cand : doc.as<JsonArrayConst>())
        if (spoolMatchesTag(cand, query)) {
          hit = true;
          if (out_spool_id) *out_spool_id = cand["id"] | 0;
          break;
        }
    }
  }
  if (out_unanswered) *out_unanswered = !hit && serverReachIsNetworkFailure(code);
  return hit;
}

void spoolmanRecheckTick() {
  if (!wifi_ok || !tag_present || sm_found) return;
  // The verdict is still coming, sm_found is only reset.
  if (lookupPending()) return;
  if (!s_last_query[0]) return;
  // A server marked down is asked by the health check alone, which marks it up
  // again. Probing it here as well only added more 5 s stalls to the loop.
  if (!sm_reachable) return;
  if (isSpoolFlowIdInputOpen()) return;   // the user is busy picking a spool

  // A lookup that stood aside for a question owes one full pass. Forgetting
  // the markers is how that is asked for: the scan loop then treats the tag on
  // the pad as new and runs the whole lookup, scan included. Done before the
  // cheap probe below rather than instead of it, because this costs nothing
  // and the probe costs a request.
  if (s_scan_deferred && !uiModalWaiting()) {
    s_scan_deferred = false;
    logSD("Backend: the question is gone, asking for the full lookup again");
    tagLookupForget();
    return;
  }

  // `| 1` keeps a probe that ends at millis() == 0 from reading as "not seen".
  if (!s_recheck_end_ms) { s_recheck_end_ms = millis() | 1; return; }
  // Signed difference, so this survives the millis() rollover.
  if ((int32_t)(millis() - s_recheck_end_ms) < (int32_t)s_recheck_gap_ms) return;

  bool unanswered = false;
  const bool hit = spoolmanTagResolves(s_last_query, &unanswered);
  s_recheck_end_ms = millis() | 1;
  if (unanswered) {
    // Doubled until the server answers again: a probe that gets no answer
    // costs the loop the whole connect timeout.
    s_recheck_gap_ms = s_recheck_gap_ms >= TAG_RECHECK_MAX_MS / 2
                         ? TAG_RECHECK_MAX_MS : s_recheck_gap_ms * 2;
    logSDf("Recheck: no answer from the backend, next try in %lus",
           (unsigned long)(s_recheck_gap_ms / 1000));
    return;
  }
  s_recheck_gap_ms = TAG_RECHECK_MS;
  if (!hit) return;

  // Known now. Forgetting the lookup is what the loop reads as "ask again",
  // the same thing lifting the spool off the pad does, so the normal path
  // fetches the spool and paints the screen. Nothing is duplicated here.
  //
  // Both markers, not just spoolman_queried_uid: that one is only ever read
  // in the Bambu branch, while an NTAG is judged by ntag_handled_uid. Clearing
  // half of it made this whole recheck a no-op for NTAGs - the tag resolved,
  // the log said so, and the screen kept saying "not in Spoolman".
  logSDf("Recheck: %s resolves now, re-reading", s_last_query);
  tagLookupForget();
  // Bound from outside. What a link from the scale would do next is armed
  // once the re-read has the spool. Only when the tag was known to be
  // unknown: after a failed lookup the spool was bound all along.
  if (s_verdict_unknown) spoolFlowExpectRemoteLink();
  else logSDf("Recheck: %s was not proven unknown, no follow-ups", s_last_query);
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
  // No second spelling here: the rescan only ever holds the uid it is named
  // after, and the tray notation it came from is long out of scope.
  int code = backendTagScan(cfg_spoolman_base, uid, nullptr, fmt[0] ? fmt : nullptr,
                            doc, 5000, nullptr);
  logSDf("Rescan: uid=%s re-announced, matched=%d HTTP %d",
         uid, (int)(doc["matched_spool_id"] | 0), code);
}

// The weight line when a lookup ends without an answer. It starts the lookup
// green ("wait"), and the failures used to change only the text, so "API
// Error" stood there in green. A server that could not be reached at all is
// named as such, and counts as a placement for the popup: the lookup is what
// laying a spool down starts on its own.
void paintLookupFailure(int code, int fallback_id) {
  const bool no_conn = serverReachIsNetworkFailure(serverReachNote(code, false));
  s_lost_connection = no_conn;
  lv_label_set_text(lbl_spoolman_weight, T(no_conn ? STR_NO_CONNECTION : fallback_id));
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(UI_COL_BAD_TEXT), 0);
}

// ============================================================
//  THE SPOOL FILAMAN'S SCAN NAMED
//
//  FilaMan's /tag/scan answers with the id of the matching spool but never
//  with the spool, so the lookup goes on to the search. When that search comes
//  back without the spool anyway, it failed on the way: the scan has just said
//  the spool exists and is bound by this tag. The whole inventory is the
//  worst request to try next over a connection that just failed - on
//  19.09.2026 a 15 s search miss right after a link grew into 47 s that way,
//  and ended without a spool. The named spool alone is one small request.
// ============================================================

enum ScanMatchFetch : uint8_t {
  SCAN_MATCH_FOUND,    // fetched, carries the tag; `doc` holds it
  SCAN_MATCH_OTHER,    // fetched, but not bound by this tag
  SCAN_MATCH_FAILED    // the request itself failed
};

constexpr uint32_t SCAN_MATCH_TIMEOUT_MS = 8000;

// On a hit `doc` holds the spool as the one element array the rest of
// querySpoolman() reads. Verified like every other short cut, so a spool that
// answers but does not carry the tag is left to the inventory scan.
static ScanMatchFetch fetchScanMatch(int spool_id, const char* tray_uuid,
                                     JsonDocument& doc, int* out_code) {
  SpiRamAllocator psram_alloc;
  JsonDocument one(&psram_alloc);
  DeserializationError err = DeserializationError::Ok;
  const int code = backendGetSpoolJson(cfg_spoolman_base, spool_id, one,
                                       SCAN_MATCH_TIMEOUT_MS, &err);
  *out_code = code;
  if (code != 200 || err) {
    logSDf("Backend: spool %d named by the scan, fetch failed, code=%d err=%s",
           spool_id, code, err.c_str());
    return SCAN_MATCH_FAILED;
  }
  if (!spoolMatchesTag(one.as<JsonObjectConst>(), tray_uuid)) {
    logSDf("Backend: spool %d named by the scan does not carry %s", spool_id, tray_uuid);
    return SCAN_MATCH_OTHER;
  }
  doc.clear();
  doc.to<JsonArray>().add(one.as<JsonObjectConst>());
  logSDf("Backend: spool %d named by the scan, fetched by id", spool_id);
  return SCAN_MATCH_FOUND;
}

// ============================================================
//  THE UID INDEX
//
//  Before the full scan the index left by the last one is asked. Where it
//  says that scan saw none of this tag's identifiers, the two downloads of
//  the inventory are left out and the tag is unknown after the searches
//  alone: about 0.3 s instead of 2.2 to 6.6.
//
//  UID_INDEX_LIVE 0 is the shadow it was proven in: the answer only goes into
//  the log, the scan runs regardless, and the two are compared. "DISAGREED"
//  means the index called a tag unknown that the scan then found - the one
//  mistake it must not make. A build for testers can go back to that to have
//  it looked for on libraries other than the ones it was written against.
// ============================================================

#define UID_INDEX_LIVE  1

// ShadowVerdict stands in spoolman_lookup_internal.h.
ShadowVerdict s_shadow = SHADOW_NOT_ASKED;

// What the scan found, held against what the index said. spool_id 0 for "not
// found". Says nothing unless the index was asked, and only once per lookup.
void uidShadowReport(int spool_id, int rank, bool archived) {
  const ShadowVerdict said = s_shadow;
  s_shadow = SHADOW_NOT_ASKED;
  if (said == SHADOW_NOT_ASKED) return;

  if (said == SHADOW_ABSENT) {
    if (spool_id > 0)
      logSDf("uid index: DISAGREED - scan found spool %d at rank %d%s",
             spool_id, rank, archived ? ", archived" : "");
    else
      logSD("uid index: scan agreed");
    return;
  }
  if (spool_id > 0)
    logSDf("uid index: scan found spool %d at rank %d%s, as it had to",
           spool_id, rank, archived ? ", archived" : "");
  else
    logSD("uid index: held the identifier, the scan found nothing - costs a scan, no error");
}

// An archived spool answers to the tag on the pad. Fetched whole rather than
// painted as a dead end: the user has to see which spool this is before
// deciding to bring it back, and that means name, filament and tare.
// querySpoolmanById() reads `archived` and sets sm_archived, so everything
// that writes holds off. The caller gives its own document up first - the
// fetch wants the PSRAM back - and returns after this.
void showArchivedSpool(int archived_id) {
  Serial.printf("Backend: spool archived (ID=%d)\n", archived_id);
  logSDf("Backend: found ID=%d, archived", archived_id);
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
}

// What the uid index says about the tag, asked before a scan replaces it.
// Also from lookup_scan.cpp, when a lookup waited for another one's scan and
// that scan has just filled the index.
bool askUidIndex(const char* tray_uuid, bool searches_answered,
                 const InventoryStamp* stamp) {
  bool unknown = false;
  if (!searches_answered) {
    logSD("uid index: not asked, a search did not answer");
  } else if (backendIsFilaMan() && tagIsBambu(tray_uuid)) {
    logSD("uid index: not asked, a Bambu tag on FilaMan is always scanned");
  } else {
    // Every identity spoolTagRank() compares with: the tray uuid, the chip
    // behind it, and what the reader reported. The same string three times
    // for anything but a Bambu tag.
    const char* ids[3] = { tray_uuid, tagNativeUid(tray_uuid), g_tag.uid_str };
    const UidIndexReply r = uidIndexAsk(ids, 3, stamp);
    if (r.answer == UID_INDEX_ABSENT && UID_INDEX_LIVE) {
      unknown = true;
      logSDf("Backend: not in the index of %d ids (%lu s old), scan skipped",
             r.ids, (unsigned long)r.age_s);
    } else if (r.answer == UID_INDEX_ABSENT) {
      s_shadow = SHADOW_ABSENT;
      logSDf("uid index: would answer UNKNOWN (%d ids, %lu s old)",
             r.ids, (unsigned long)r.age_s);
    } else if (r.answer == UID_INDEX_MAY_HOLD) {
      s_shadow = SHADOW_MAY_HOLD;
      logSDf("uid index: left to the scan (%s)", r.why);
    } else {
      logSDf("uid index: silent (%s)", r.why);
    }
  }
  return unknown;
}

void querySpoolman(const char* tray_uuid, LookupOrigin origin) {
  if (!wifi_ok) return;
  // A lookup still waiting for its inventory was for a tag that is no longer
  // the one being asked about. Its download runs on for cache and index.
  lookupAbandon();
  strncpy(s_last_query, tray_uuid ? tray_uuid : "", sizeof(s_last_query) - 1);
  s_last_query[sizeof(s_last_query) - 1] = '\0';
  // Only the one line below "Truly not found" sets it again.
  s_verdict_unknown = false;
  s_lost_connection = false;
  s_recheck_end_ms = 0;
  s_recheck_gap_ms = TAG_RECHECK_MS;
  // Every lookup settles for itself whether it owes a scan. Left standing from
  // the one before, the marker made spoolmanRecheckTick() order a second full
  // lookup for a tag that had just had one, inventory and archive included -
  // and "not found" after a complete scan counted as no verdict.
  s_scan_deferred = false;
  s_shadow = SHADOW_NOT_ASKED;
  // A 4-byte MIFARE tag is looked up by its UID through the same call, so
  // the log names what was actually sent.
  if (tray_uuid && strlen(tray_uuid) == 32) {
    logSDf("Backend: query tray_uuid=%.16s...", tray_uuid);
  } else {
    logSDf("Backend: query tag=%s", tray_uuid ? tray_uuid : "");
  }

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
  // An NTAG carrying a record has just put the same three fields on screen, so
  // this reset would blank them for the length of the request and, for a spool
  // the server does not know, leave them blank. is_bambu_tag itself stays what
  // it was: it decides who fills the fields further down, not who clears them.
  if (!is_bambu_tag && !tagCachedHasRecord()) {
    lv_label_set_text(lbl_material, "-");
    lv_label_set_text(lbl_vendor, "-");
    swatchPaint(lbl_color_swatch, SpoolColor{});
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
  sm_hw_uid_value[0] = '\0';
  sm_spool_weight = 0;
  sm_remaining = 0;
  sm_total = 1000;
  lv_timer_handler();

  Serial.printf("DBG free heap: %d bytes  free PSRAM: %d bytes\n", ESP.getFreeHeap(), ESP.getFreePsram());
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (before Spoolman GET)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  // Filter: only parse needed fields - reduces RAM, works with 100+ spools
  // Filter must be Array-wrapped to match the API array response structure
  // Sized with room for every tag field AND for the server's own text fields,
  // which are only known at runtime and can be a dozen. An overflowed filter
  // silently drops keys, and a dropped tag key makes every spool come back
  // looking unbound - hence the check after it is filled rather than trust in
  // the number.
  JsonDocument filter;
  JsonArray filter_arr = filter.to<JsonArray>();
  JsonObject filter_spool = filter_arr.add<JsonObject>();
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
  // Named rather than left to the sweep below. That one stops at
  // BACKEND_TEXT_FIELDS_MAX, and this field decides whether a uid is appended
  // or written over: arriving empty would make every placement look like the
  // first one and replace the chip on the other flange.
  filter_spool["extra"][RFID_TAG_FIELD] = true;
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
    logSD("Backend: scan filter overflowed, fields will be missing");

  // Use PSRAM for this document - frees internal RAM for LVGL
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

  // Telling the server which tag was just read. On Spoolman this is also the
  // lookup: one request resolves the tag and returns the spool with it, so it
  // replaces the filter search, the verification pass and the follow-up GET in
  // one go. On FilaMan only the announcement lands - it answers with the match
  // but not the spool, so the chain below still runs. Either way a browser
  // watching this reader can now follow it to the spool.
  //
  // A null match is not proof of absence: it means "no native tag", and a
  // spool bound through an extra field is invisible here. That is why the
  // chain below still runs, exactly as it does for a missed filter search.
  // An installation that never chose is moved onto the native source the first
  // time a server turns out to have it. Here rather than at boot, because the
  // probe needs the network and boot does not have it yet.
  tagFieldAutoSelect();

  // The spool a scan named without sending it, see fetchScanMatch().
  int scan_matched_id = 0;
  // Whether every search below that went out came back readable. The full
  // scan is the net under a search that failed, and the uid index must not
  // take that net away: it only knows what the scan saw, not what a search
  // would have said. BACKEND_NOT_SUPPORTED is no failure, no request went out.
  bool searches_answered = true;
  // Whether any request of this lookup got an HTTP answer at all. It proves the
  // server is there right now, which sm_reachable cannot after a backend
  // switch: that says "not known yet" until the health check has run, up to
  // 30 s later. See the stamp further down.
  bool server_answered = false;
  if (backendReportsScans()) {
    JsonDocument scan(&psram_alloc);
    DeserializationError serr = DeserializationError::Ok;
    // The chip uid, not the tray uuid: Spoolman's relation keys on hardware
    // uids, and so do the phone, the ESPHome readers and Spoolman's own Add
    // tag dialog. See the identity block in tag_field.h.
    const char* scan_uid = tagNativeUid(tray_uuid);
    // The tray notation goes along as the second spelling. A Bambu spool the
    // driver imported is on file under it, while one this scale linked is on
    // file under the chip uid, and the scale cannot know which - so it offers
    // both. Ignored by Spoolman, which keys on the hardware uid alone.
    int scode = backendTagScan(cfg_spoolman_base, scan_uid, tray_uuid,
                               tagFormatName(tray_uuid), scan, 8000, &serr);
    if (scode > 0) server_answered = true;
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
      // FilaMan always lands here: it reports the match but never embeds the
      // spool, so the chain below does the looking up and this call was the
      // announcement. On Spoolman it means the uid has no native tag.
      scan_matched_id = scan["matched_spool_id"] | 0;
      logSDf("Backend: tag scan announced, uid=%s matched=%d, no spool embedded",
             scan_uid, scan_matched_id);
      if (serr) searches_answered = false;     // 200, but nothing to read
    } else if (scode != BACKEND_NOT_SUPPORTED) {
      logSDf("Backend: native tag scan failed, code=%d err=%s", scode, serr.c_str());
      searches_answered = false;
    }
    if (!have_result) { doc.clear(); err = DeserializationError::Ok; }
  }

  // A Bambu tag that an earlier firmware bound natively sits in the relation
  // under its tray uuid, and the scan above no longer asks for that one. This
  // catches those with a single exact lookup instead of the whole inventory,
  // and the auto-link at the end then adds the chip uid, so a spool pays for
  // this once. Only for Bambu: everywhere else the scan already asked this
  // very uid and a second request would repeat it.
  // Spoolman only: the tag relation this asks for is its own. The others
  // answer BACKEND_NOT_SUPPORTED without spending a request, so the cost was
  // never the point - but they logged "has no implementation yet" once a boot,
  // which reads like a missing feature instead of a step that does not apply.
  // The search below covers the same ground for them.
  if (!have_result && tagIsBambu(tray_uuid) && backendMode() == BACKEND_SPOOLMAN) {
    int ncode = backendFindSpoolByNativeTag(cfg_spoolman_base, tray_uuid,
                                            doc, 8000, &filter, &err);
    if (ncode > 0) server_answered = true;
    if (ncode == 200 && !err) {
      for (JsonObjectConst cand : doc.as<JsonArrayConst>()) {
        if (spoolMatchesTag(cand, tray_uuid)) { have_result = true; break; }
      }
      if (have_result)
        logSDf("Backend: native lookup hit on the tray uuid, %d spool(s) returned",
               (int)doc.as<JsonArrayConst>().size());
    } else if (ncode != BACKEND_NOT_SUPPORTED) {
      logSDf("Backend: native tag lookup failed, code=%d err=%s", ncode, err.c_str());
      searches_answered = false;
    }
    if (!have_result) { doc.clear(); err = DeserializationError::Ok; }
  }

  if (!have_result) {
    int fcode = backendFindSpoolByTag(cfg_spoolman_base, tray_uuid, doc, 8000, &err, &filter);
    if (fcode > 0) server_answered = true;
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
      searches_answered = false;
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
    if (ccode > 0) server_answered = true;
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
      searches_answered = false;
    }
    if (!have_result) {
      doc.clear();
      err = DeserializationError::Ok;
    }
   }
  }

  // The scan named the spool and every search above still missed it. A failed
  // fetch ends the lookup here: the inventory would have to cross the same
  // connection, and the recheck asks again while the tag stays on the pad.
  if (!have_result && scan_matched_id > 0) {
    int mcode = 0;
    const ScanMatchFetch m = fetchScanMatch(scan_matched_id, tray_uuid, doc, &mcode);
    if (m == SCAN_MATCH_FOUND) {
      have_result = true;
    } else if (m == SCAN_MATCH_FAILED) {
      paintLookupFailure(mcode, STR_API_ERROR);
      return;
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
    copyT(buf, sizeof(buf), STR_SEARCHING_INVENTORY);
    lv_label_set_text(lbl_status, buf);
    lv_refr_now(NULL);
  }
  // The byte counter from the loading overlay, pointed at the status line
  // instead. Whether it is still moving is the only question a wait like this
  // raises, and the answer costs nothing here.
  crumbSet("inventory search");

  // The loop stops here until the whole inventory is in. Bracketed so the
  // clocks that are running - the AMS question, the location prompt - do not
  // count the wait against the user, who cannot reach a button during it.
  //
  // A scope, not two calls: the retry below returns from the middle of this
  // function, and a hand-written httpStallEnd() after the loop never ran on
  // that path. The bracket stayed open, the depth stuck at 1, and every clock
  // in the firmware then subtracted its whole elapsed time - the AMS question
  // stood at ten seconds for the rest of the boot and the location prompt
  // behind it was never asked again.
  // The inventory that is about to come in is the very list the link flow
  // fetches a few seconds later - an unknown tag is what "Link" usually
  // follows. So it is handed to the list cache further down instead of being
  // thrown away. The stamp has to be taken in front of the download, see
  // spoolCacheFill(); not from a server already known to be gone, which would
  // only add its timeout to the ones this lookup has sat through. A search of
  // this lookup that got an answer counts as known to be there: right after a
  // backend switch sm_reachable is still false, and a scan without a stamp
  // left an index the next tag had to throw away ("a stamp where there was
  // none"), so the index only started to answer at the third tag.
  //
  // Nothing about the lookup changes: it reads and decides from its own fresh
  // document as before, and never looks into the cache.
  //
  // In front of the bracket below and not inside it: the stall log names a
  // span after the first call in it, and inside, the seconds the inventory
  // takes were being blamed on this request of fifty milliseconds.
  bool scanned_inventory = false;   // doc holds the whole inventory, not one hit
  InventoryStamp stamp = { -1, 0 };
  bool have_stamp = false;
  if (!have_result && !uiModalWaiting() && (sm_reachable || server_answered))
    have_stamp = (backendInventoryStamp(cfg_spoolman_base, &stamp) == 200);

  // What the uid index says, asked before the scan below replaces it. Only
  // where a scan is coming: while a question is on screen it stands aside,
  // spoolmanRecheckTick() orders the lookup again once the question is gone,
  // and that lookup lands here.
  //
  // Two rules keep the index out altogether. A search that did not answer:
  // the scan is the net under it, and the index only knows what the last scan
  // saw, not what that search would have said. And a Bambu tag on FilaMan:
  // its Bambu plugin writes bambu_rfid_tag_1 when the AMS reads a spool, into
  // a field no search covers, so a spool taken out of the AMS and put on the
  // scale within the two minutes would be called unknown.
  bool index_unknown = false;       // the index answered, no scan is owed
  if (!have_result && !uiModalWaiting())
    index_unknown = askUidIndex(tray_uuid, searches_answered, have_stamp ? &stamp : nullptr);

  // Not while a question is waiting to be answered. This is the only part of a
  // lookup long enough to matter: 249 active spools plus 254 including the
  // archive, three pages each, six seconds in which the touch panel is not
  // read at all - which is what made the erase question impossible to answer.
  // See uiModalWaiting() for why pumping LVGL instead is not an option.
  //
  // Standing aside costs nothing that is not recovered: spoolmanRecheckTick()
  // keeps asking the cheap server side lookup every few seconds while an
  // unknown tag lies on the pad, and clears the marker on a hit.
  // Only a scan that was owed can stand aside. With a spool already found by
  // one of the fast lookups there is none to skip, and saying otherwise left
  // the marker set with nobody to clear it: spoolmanRecheckTick() does not
  // run while a spool is on screen. It then fired at the next unknown tag,
  // right after that tag's own complete lookup - 5.4 s instead of 2.4 on
  // Spoolman, 11.1 s instead of 5.5 on FilaMan, measured.
  const bool defer_scan = !have_result && uiModalWaiting();
  if (defer_scan) {
    // Remembered, not just skipped. The cheap lookup has already missed, so a
    // spool findable only by the scan - a uid in FilaMan's custom_fields, or
    // in an extra field nobody agreed on - would otherwise read as unknown
    // until the tag is lifted and put back. spoolmanRecheckTick() makes it
    // good as soon as the screen is free again.
    s_scan_deferred = true;
    logSD("Backend: full scan stood aside, a question is waiting on screen");
  }

  scanned_inventory = (!have_result && !defer_scan && !index_unknown);

  LookupCtx c;
  snprintf(c.tray, sizeof(c.tray), "%s", tray_uuid);
  c.origin            = origin;
  c.is_bambu_tag      = is_bambu_tag;
  c.scanned_inventory = scanned_inventory;
  c.searches_answered = searches_answered;
  c.have_stamp        = have_stamp;
  c.stamp             = stamp;
  c.index_unknown     = index_unknown;

  // The inventory is loaded on the backend worker, and the verdict is read
  // out of it by lookupScanTick() on a later pass. Until then the loop keeps
  // going: the touch panel is read, the AMS and location questions can be
  // answered, the weight moves. It used to stand here for the whole download,
  // 14 s on FilaMan and 51 s on BamBuddy with a large library.
  if (scanned_inventory) {
    lookupScanBegin(c, filter);
    return;
  }

  // A short cut found the spool, or no scan is owed: the verdict is read right
  // here, out of what the searches brought, the way it always was.
  if (lookupResolveActive(c, doc, nullptr, err) == LOOKUP_NEEDS_ARCHIVE)
    lookupArchiveBegin(c);
}

bool lookupLostConnection() { return s_lost_connection; }
