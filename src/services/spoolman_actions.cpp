#include "spoolman_actions.h"
#include "services/tag_field.h"
#include "services/tag_uid.h"
#include "services/user_options.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <string.h>
#include <time.h>

#include "app_config.h"
#include "app/deferred_actions.h"
#include "backend.h"
#include "backend_api.h"
#include "bambuddy_api.h"
#include "hardware/sd_logger.h"
#include "user_options.h"
#include "ui/date_display.h"
#include "lang.h"
#include "services/backend.h"
#include "ui/main_screen_helpers.h"




// Holds one tag UID on its way from extra.tag into the card_uids list. The
// longest the scale carries is a Bambu tray uuid at 32 characters, the colon
// form of a 7 byte UID is 20. Same size as sm_tag, which is where it comes from.
#define TAG_MIGRATE_MAX  48

int patchSpoolmanWeight(float remaining, bool skip_cap_check) {
  if (!wifi_ok) { Serial.println("patchSpoolmanWeight: no WiFi"); return PATCH_WEIGHT_NO_TARGET; }
  if (!sm_found || sm_id == 0) { Serial.println("patchSpoolmanWeight: no spool"); return PATCH_WEIGHT_NO_TARGET; }

  // BamBuddy's own inventory stores what was consumed and derives the rest
  // from the label weight, so it cannot represent a spool holding more than
  // the label says - the value would read as full again on the next scan.
  // Ask rather than let that happen silently. Behind Spoolman the remaining
  // weight is stored directly and there is no ceiling.
  // The tolerance keeps rounding noise on a genuinely full spool from asking.
  if (!skip_cap_check && backendIsBamBuddy() && bbInventoryMode() == BB_INV_LOCAL &&
      sm_total > 0.0f && remaining > sm_total + BB_CAP_TOLERANCE_G) {
    bb_cap_measured_g = remaining;
    bb_cap_label_g    = sm_total;
    show_bb_cap_pending = true;      // the popup is built from appLoop()
    logSDf("BamBuddy: %.0fg measured against a %.0fg label, asking first",
           remaining, sm_total);
    return PATCH_WEIGHT_ASKING;
  }

  char today[12] = "";
  if (last_used_mode == 1) {
    time_t now = time(nullptr);
    struct tm* t = localtime(&now);
    snprintf(today, sizeof(today), "%04d-%02d-%02d", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
  }
  Serial.printf("PATCH weight: %.1fg\n", remaining);
  // FilaMan wants the gross weight and subtracts the empty spool weight
  // itself. The callers computed remaining as scale minus sm_spool_weight,
  // so adding it back gives exactly what the scale showed.
  float measured = remaining + sm_spool_weight;
  int code = backendPatchSpoolRemaining(cfg_spoolman_base, sm_id, remaining,
                                        today[0] ? today : nullptr, nullptr, measured);
  logSDf("PATCH weight=%.1fg ID=%d HTTP %d", remaining, sm_id, code);
  if (code == 200) {
    sm_remaining = remaining;
    char w_str[16];
    snprintf(w_str, sizeof(w_str), "%.0f g", sm_remaining);
    lv_label_set_text(lbl_spoolman_weight, w_str);
    float pct = (sm_total > 0) ? (sm_remaining / sm_total * 100.0f) : 0;
    char p_str[16];
    snprintf(p_str, sizeof(p_str), "%.1f %%", pct);
    lv_label_set_text(lbl_spoolman_pct, p_str);
    if (last_used_mode == 1 && lbl_last_used) {
      char today_iso[12];
      time_t now = time(nullptr);
      struct tm* t = localtime(&now);
      snprintf(today_iso, sizeof(today_iso), "%04d-%02d-%02d", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
      char today_local[12];
      isoToDe(today_iso, today_local, sizeof(today_local));
      strncpy(sm_last_used, today_local, sizeof(sm_last_used) - 1);
      sm_last_used[sizeof(sm_last_used)-1] = '\0';
      char disp[48];
      driedDisplayStr(today_local, disp, sizeof(disp));
      lv_label_set_text(lbl_last_used, disp);
    }
    Serial.printf("OK: %.1fg saved\n", remaining);
  } else {
    Serial.printf("PATCH error: %d\n", code);
  }
  return code;
}

void patchArchiveSpool() {
  if (!wifi_ok) { Serial.println("patchArchiveSpool: no WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchArchiveSpool: no spool"); return; }
  Serial.printf("PATCH archive: spool ID %d\n", sm_id);
  int code = backendPatchArchiveSpool(cfg_spoolman_base, sm_id);
  logSDf("PATCH archive ID=%d HTTP %d", sm_id, code);
  if (code != 200) {
    Serial.printf("PATCH archive error: %d\n", code);
    lv_label_set_text(lbl_spoolman_weight, T(STR_ERR_SAVE));
    return;
  }

  Serial.println("Spool archived!");
  sm_remaining = 0;

  // Show the archived state straight away. Without this the labels kept the
  // values from before and only caught up when the tag was scanned again.
  // Mirrors what the scan path shows for an archived spool, so both routes
  // end up looking the same.
  char arch_buf[32];
  backendText(T(STR_ARCHIVED), arch_buf, sizeof(arch_buf));
  lv_label_set_text(lbl_spoolman_weight, arch_buf);
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x808080), 0);
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_label_set_text(lbl_spoolman_dried_val, "-");
  if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
  lv_label_set_text(lbl_last_used, "-");
  lv_label_set_text(lbl_detail, "-");
  lv_label_set_text(lbl_filament_name, "-");
  if (lbl_scale_diff)      lv_obj_set_width(lbl_scale_diff, 0);
  if (lbl_spoolman_dried)  lv_label_set_text(lbl_spoolman_dried, "");
  if (lbl_keys)            lv_label_set_text(lbl_keys, "");

  // The spool is out of the active inventory, so a further weight update or
  // dried action would target something that is no longer there.
  sm_found = false;
  updateLinkButton();
}

// Empties the field a UID was migrated out of, once it is safely in the
// selected one. Only ever in that order: the reverse can lose the binding
// altogether if the second write fails.
//
// Refused when the source is a list holding more than one UID. Clearing it
// would drop the tag on the other flange, and nobody would notice until that
// tag stopped working. The spool then stays bound through both fields, which
// the fallback search in querySpoolman() covers.
static void clearMigrationSource(int spool_id, uint8_t src, const char* value) {
  const TagFieldSpec& s = tagFieldSpec(src);
  if (s.is_list) {
    const int held = cardUidsCount(value);
    if (held > 1) {
      logSDf("MIGRATE ID=%d kept %s, it still holds %d UIDs", spool_id, s.key, held);
      return;
    }
  }
  int c = backendPatchExtraField(cfg_spoolman_base, spool_id, s.key, "");
  logSDf("MIGRATE ID=%d moved '%s' from %s to %s, cleared %s HTTP %d",
         spool_id, value ? value : "", s.key, tagFieldKeyName(), s.key, c);
}


// Drops every native tag the spool holds, taken from the list the lookup
// captured, and falls back to the one identity in hand when nothing was.
//
// Shared on purpose: there are two ways into an unlink - patchSpoolTag() with
// an empty uuid, and unlinkCardUid() - and they are reached from different
// backends. Fixing this in one of them and not the other is exactly what left
// a spool findable after the screen said it was unlinked.
static void unlinkAllNativeTags(int spool_id, const char* fallback_uid) {
  char list[CARD_UIDS_MAX];
  strncpy(list, sm_tag_values[TAG_FIELD_NATIVE], sizeof(list) - 1);
  list[sizeof(list) - 1] = '\0';

  if (!list[0]) {
    if (!fallback_uid || !fallback_uid[0]) {
      logSDf("UNLINK native ID=%d: nothing captured and no uid in hand", spool_id);
      return;
    }
    int c = backendUnlinkTag(cfg_spoolman_base, spool_id, fallback_uid);
    logSDf("UNLINK native ID=%d uuid='%s' (no list captured) HTTP %d",
           spool_id, fallback_uid, c);
    return;
  }

  char* save = nullptr;
  for (char* one = strtok_r(list, ",", &save); one;
       one = strtok_r(nullptr, ",", &save)) {
    int c = backendUnlinkTag(cfg_spoolman_base, spool_id, one);
    logSDf("UNLINK native ID=%d uuid='%s' HTTP %d", spool_id, one, c);
  }
}

bool patchSpoolTag(int spool_id, const char* uuid, const char* const* field_values) {
  if (!wifi_ok) return false;
  const bool clearing = (!uuid || !uuid[0]);
  sm_tag_conflict_spool = 0;   // stale from an earlier attempt would mislead

  const TagFieldSpec& spec = tagFieldSelected();

  // Spoolman's own tag relation, where a spool holds several tags without any
  // of the list handling below. Checked before anything reads field_values,
  // because there is no field to read for this source.
  if (spec.is_native) {
    // What this call is named by: the uid handed in, or the one the spool was
    // found under when it is an unlink and carries none.
    const char* scanned    = clearing ? g_tag.tray_uuid : uuid;
    const char* native_uid = tagNativeUid(scanned);

    if (clearing) {
      unlinkAllNativeTags(spool_id, native_uid);
      return true;
    }

    // The chip that is on the reader. Every reader can report this one, from a
    // phone to an ESPHome box to Spoolman's own Add tag dialog, so it is the
    // identity that makes the spool findable outside this firmware.
    int conflict = 0;
    int code = backendLinkTag(cfg_spoolman_base, spool_id, native_uid,
                              tagFormatName(scanned), &conflict);
    logSDf("LINK native ID=%d uuid='%s' format=%s HTTP %d%s",
           spool_id, native_uid, tagFormatName(scanned), code,
           code == 409 ? " CONFLICT" : "");

    if (code == 409) {
      // A tag belongs to exactly one spool. Saying which one holds it beats a
      // bare failure - it is the whole reason Spoolman puts the id in the body.
      sm_tag_conflict_spool = conflict;
      logSDf("LINK native: uuid='%s' already on spool %d", native_uid, conflict);
      return false;
    }
    if (code < 200 || code >= 300) return false;

    // A Bambu tag carries a second identity: the tray uuid out of its
    // contents, which both chips of the spool hold. Linked alongside, it finds
    // the spool from either side straight away, instead of only once the other
    // chip has been on the reader too. It is no substitute for the chip uid
    // above - only a reader that can decrypt Bambu contents ever sees it.
    if (tagIsBambu(scanned)) {
      int c2 = backendLinkTag(cfg_spoolman_base, spool_id, scanned, "bambu", nullptr);
      // A 409 here means another spool claims this tray uuid, which is a
      // duplicate in the library rather than something this link did wrong.
      // The chip is linked either way, so it stays a log line.
      logSDf("LINK native ID=%d tray uuid='%s' HTTP %d%s",
             spool_id, scanned, c2, c2 == 409 ? " CONFLICT" : "");
    }

    // OpenSpoolman reads a spool's tray uuid out of extra.tag, and that is how
    // it knows which spool to subtract a print from. It does not know about
    // Spoolman's tag relation yet, so a Bambu spool linked only natively would
    // stop being recognised there and the user would have to relink it by hand
    // in OpenSpoolman. Writing the value costs one PATCH on an action the user
    // asked for, and it is dropped again the day OpenSpoolman reads the
    // relation.
    //
    // This is also why the migration below skips extra.tag for a Bambu tag:
    // clearing it is exactly what would break that setup.
    const bool keep_tag_field = tagIsBambu(scanned);
    if (keep_tag_field) {
      const TagFieldSpec& companion = tagFieldSpec(TAG_FIELD_TAG);
      if (!backendHasExtraField(companion.key)) {
        logSDf("LINK native: %s missing on the server, tray uuid not kept",
               companion.key);
      } else {
        char val[40];
        tagFieldFormat(companion, scanned, val, sizeof(val));
        int c = backendPatchExtraField(cfg_spoolman_base, spool_id,
                                       companion.key, val);
        logSDf("LINK native ID=%d kept tray uuid in %s='%s' HTTP %d",
               spool_id, companion.key, val, c);
      }
    }

    // Bound natively now, so a UID left in an extra field would keep the spool
    // findable through a store nobody writes any more. Same rule as the
    // migration between fields, including the refusal to empty a list that
    // still holds somebody else's tag.
    if (field_values) {
      for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++) {
        if (keep_tag_field && i == TAG_FIELD_TAG) continue;
        if (field_values[i] && field_values[i][0])
          clearMigrationSource(spool_id, i, field_values[i]);
      }
    }
    return true;
  }
  const uint8_t eff = tagFieldEffective();
  const char* selected = (!clearing && field_values) ? field_values[eff] : nullptr;
  const bool  has_value = (selected && selected[0]);

  // Where the binding sits now, if it is not already in the selected field.
  // Moving it over is what keeps the choice meaningful: without it a spool
  // linked before the switch would stay reachable only through the fallback
  // search, and the field the user picked would never fill up.
  //
  // Spoolman only - the other backends have one place each for a tag and
  // nothing to migrate between.
  int src = -1;
  if (!clearing && !has_value && field_values && backendMode() == BACKEND_SPOOLMAN) {
    for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++) {
      if (i == eff) continue;
      if (field_values[i] && field_values[i][0]) { src = (int)i; break; }
    }
  }

  // The list path: append instead of replace. Only a field with a list format
  // can do it, and only with the switch on - see g_card_uids_write.
  const bool use_list = !clearing && spec.is_list && g_card_uids_write &&
                        backendHasExtraField(spec.key);

  if (use_list) {
    // The base is the list the spool already has. A spool bound elsewhere
    // brings that single UID along as the first entry, and a fresh one starts
    // the list off - without that seed nothing would ever write entry one.
    //
    // Only ever seeded from a single valued source. Normalising a comma
    // separated list would fuse its UIDs into one identifier that belongs to
    // no tag at all. There is only one list field today, so src can never be
    // one - but the spec table is meant to grow, and this is not a mistake
    // anything downstream could catch.
    char seeded[TAG_MIGRATE_MAX] = "";
    if (!has_value && src >= 0 && !tagFieldSpec((uint8_t)src).is_list)
      tagFieldFormat(spec, field_values[src], seeded, sizeof(seeded));
    const char* base = has_value ? selected : seeded;

    char merged[CARD_UIDS_MAX];
    CardUidsResult r = cardUidsAppend(base, uuid, merged, sizeof(merged));

    if (r == CARD_UIDS_ALREADY_PRESENT) {
      // Linking a tag the spool already carries is not a failure, it just has
      // nothing to write. Saying so beats a PATCH that changes nothing.
      logSDf("PATCH %s ID=%d uuid='%s' already in list, no write",
             spec.key, spool_id, uuid);
      return true;
    }
    if (r == CARD_UIDS_FULL) {
      // Refusing is the whole point: a shortened list would drop a tag that
      // belongs to the other flange.
      logSDf("PATCH %s ID=%d uuid='%s' REFUSED, list full ('%s')",
             spec.key, spool_id, uuid, base);
      return false;
    }

    int code = backendPatchExtraField(cfg_spoolman_base, spool_id, spec.key, merged);
    Serial.printf("PATCH %s: '%s' HTTP %d\n", spec.key, merged, code);
    logSDf("PATCH %s ID=%d uuid='%s' -> '%s' HTTP %d",
           spec.key, spool_id, uuid, merged, code);
    if (code != 200) return false;

    if (!has_value && src >= 0) clearMigrationSource(spool_id, (uint8_t)src, field_values[src]);
    return true;
  }

  // Single value. backendPatchSpoolTag() puts it where the active backend
  // keeps its tags - the selected extra field on Spoolman, rfid_uid on
  // FilaMan, the device protocol on BamBuddy - formatted for that field.
  Serial.printf("PATCH tag: '%s'%s\n", uuid ? uuid : "", clearing ? "  (UNLINK)" : "");
  int code = backendPatchSpoolTag(cfg_spoolman_base, spool_id, uuid);
  Serial.printf("patchSpoolTag: HTTP %d\n", code);
  // The uuid is part of the log line on purpose. An empty one is a valid
  // unlink and a silent disaster for a link, and the old line could not tell
  // the two apart afterwards.
  logSDf("PATCH tag ID=%d field=%s uuid='%s'%s HTTP %d",
         spool_id, backendMode() == BACKEND_SPOOLMAN ? spec.key : "native",
         uuid ? uuid : "", clearing ? " UNLINK" : "", code);

  // An unlink reports success either way: the caller has already decided the
  // binding is gone, and a failed clear is visible in the log.
  if (clearing) return true;
  if (code < 200 || code >= 300) return false;

  if (src >= 0) clearMigrationSource(spool_id, (uint8_t)src, field_values[src]);
  return true;
}

// Clears the tag field a spool is bound through, but only if it holds
// something.
//
// Writing a field that holds nothing is not harmless. Spoolman rejects an
// extra field it does not know with HTTP 400, so a user whose server never had
// that field would collect an error for a field that was never part of the
// binding. And touching data the scale did not put there is wrong even when it
// happens to work.
static bool clearBoundFieldIfSet(int spool_id, uint8_t field) {
  const char* v = sm_tag_values[field];
  if (!v[0]) return false;
  const TagFieldSpec& s = tagFieldSpec(field);
  int code = backendPatchExtraField(cfg_spoolman_base, spool_id, s.key, "");
  logSDf("UNLINK ID=%d cleared %s ('%s'), HTTP %d", spool_id, s.key, v, code);
  return true;
}

void unlinkCardUid(int spool_id, const char* uid, bool all) {
  if (!wifi_ok) return;

  // A natively bound spool keeps its tags in the relation, not in a field.
  // Everything below still runs afterwards, because a spool can carry both
  // while it is being migrated.
  if (backendHasNativeTags()) {
    // By the chip uid for a Bambu tag, because that is what the link was made
    // with. The extra fields below still go by `uid`, the tray uuid, which is
    // what they hold.
    const char* native_uid = tagNativeUid(uid);
    if (all) {
      // A Bambu spool holds up to three entries, one per chip plus the tray
      // uuid. "Unlink everything" has to mean all of them, or the spool comes
      // straight back on the next placement.
      unlinkAllNativeTags(spool_id, native_uid);
    } else {
      // Just the tag that is physically on the reader. The others stay, which
      // is the whole point of the popup's second answer.
      int c = backendUnlinkTag(cfg_spoolman_base, spool_id, native_uid);
      logSDf("UNLINK native ID=%d uuid='%s' HTTP %d", spool_id, native_uid, c);
    }
  }

  if (all) {
    // Every field that holds something has to go. Leaving one behind would
    // keep the spool findable after the user was told it is gone, and the
    // fallback search makes that more likely, not less.
    bool did = false;
    for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++)
      if (clearBoundFieldIfSet(spool_id, i)) did = true;
    if (!did) logSDf("UNLINK ID=%d nothing to clear, no field set", spool_id);
    return;
  }

  // One UID out of a list, leaving the rest of the list alone. Only a list
  // field can do that; everything else is an all-or-nothing binding.
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++) {
    const TagFieldSpec& s = tagFieldSpec(i);
    if (!s.is_list || !sm_tag_values[i][0]) continue;

    char rest[CARD_UIDS_MAX];
    if (!cardUidsRemove(sm_tag_values[i], uid, rest, sizeof(rest))) continue;

    int code = backendPatchExtraField(cfg_spoolman_base, spool_id, s.key, rest);
    logSDf("UNLINK one ID=%d uuid='%s' left %s='%s' HTTP %d",
           spool_id, uid ? uid : "", s.key, rest, code);
    return;
  }

  // The UID was in no list, so whatever brought the spool up was a single
  // valued field, if anything was.
  logSDf("UNLINK ID=%d uuid='%s' in no list", spool_id, uid ? uid : "");
  bool did = false;
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++)
    if (!tagFieldSpec(i).is_list && clearBoundFieldIfSet(spool_id, i)) { did = true; break; }
  if (!did) logSDf("UNLINK ID=%d nothing to clear, no field set", spool_id);
}

void patchInitialWeight(float initial_w) {
  if (!wifi_ok) { Serial.println("patchInitialWeight: kein WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchInitialWeight: keine Spule"); return; }
  Serial.printf("PATCH initial_weight: %.1fg\n", initial_w);
  int code = backendPatchInitialWeight(cfg_spoolman_base, sm_id, initial_w);
  if (code == 200) {
    sm_remaining = initial_w;
    sm_total = initial_w;
    Serial.printf("initial_weight OK: %.1fg\n", initial_w);
  } else {
    Serial.printf("PATCH initial_weight Fehler: %d\n", code);
  }
}

void patchSpoolWeight(float spool_w) {
  if (!wifi_ok) { Serial.println("patchSpoolWeight: no WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchSpoolWeight: no spool"); return; }
  Serial.printf("PATCH spool_weight: %.1fg\n", spool_w);
  int code = backendPatchSpoolWeight(cfg_spoolman_base, sm_id, spool_w);
  logSDf("PATCH spool_weight=%.1fg ID=%d HTTP %d", spool_w, sm_id, code);
  if (code == 200) {
    sm_spool_weight = spool_w;
    // The value now comes from this spool, so drop any inherited source.
    // Without this the details screen keeps claiming "(filament)" over a
    // number that was just measured here.
    sm_tare_source = TARE_SPOOL;
    Serial.printf("spool_weight OK: %.1fg\n", spool_w);
  } else {
    Serial.printf("PATCH spool_weight Fehler: %d\n", code);
  }
}

void patchFilamentSpoolWeight(float spool_w) {
  if (!wifi_ok) return;
  if (sm_filament_id == 0) { Serial.println("patchFilamentSpoolWeight: keine filament_id"); return; }
  Serial.printf("PATCH filament spool_weight: ID=%d %.1fg\n", sm_filament_id, spool_w);
  int code = backendPatchFilamentSpoolWeight(cfg_spoolman_base, sm_filament_id, spool_w);
  Serial.printf("patchFilamentSpoolWeight: HTTP %d\n", code);
  logSDf("PATCH filament_spool_weight=%.1fg fil_ID=%d HTTP %d", spool_w, sm_filament_id, code);
}

void patchVendorSpoolWeight(float spool_w) {
  if (!wifi_ok) return;
  if (sm_vendor_id == 0) { Serial.println("patchVendorSpoolWeight: keine vendor_id"); return; }
  Serial.printf("PATCH vendor empty_spool_weight: ID=%d %.1fg\n", sm_vendor_id, spool_w);
  int code = backendPatchVendorEmptySpoolWeight(cfg_spoolman_base, sm_vendor_id, spool_w);
  Serial.printf("patchVendorSpoolWeight: HTTP %d\n", code);
  logSDf("PATCH vendor_empty_spool=%.1fg vendor_ID=%d HTTP %d", spool_w, sm_vendor_id, code);
}
