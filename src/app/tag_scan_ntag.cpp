// The NTAG branch of the scan (7 byte UID) and the ISO 15693 branch
// (OpenPrintTag, PN7160 only). Each reads the tag once per placement,
// shows what it says, then asks the backend.

#include <Arduino.h>
#include <lvgl.h>
#include <cmath>
#include <cstring>

#include "app/app_loop.h"
#include "app/app_loop_shared.h"
#include "app/app_state.h"
#include "app/tag_scan_internal.h"
#include "hardware/display_power.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "openprinttag/opt_scan.h"
#include "openprinttag/opt_tag.h"
#include "services/location_state.h"
#include "services/tag_write.h"
#include "ui/main_screen.h"
#include "ui/main_screen_helpers.h"
#include "ui/second_tag_popup.h"
#include "ui/spool_flow.h"
#include "ui/spoolman_lookup.h"
#include "ui/tag_write_popup.h"
#include "ui/theme.h"
#include "lang.h"

void tagScanNtag(uint8_t *uid) {
  // ── NTAG detected ──────────────────────────────────────
  last_tag_seen_ms = millis();
  const bool newly_placed = !tag_present;
  tag_present = true;
  nfc_absent_count = 0;   // see the comment in tagScanMifare()
  if (newly_placed && !weightSaysSpoolStayed()) resetActivityTimer();
  // Back after it demonstrably left the pad: whatever was answered
  // for it last time was about that trip, this is a new one.
  if (newly_placed && loc_left_pad) g_loc_popup_shown_for_id = -1;
  if (newly_placed && loc_left_pad) s_beeped_uid[0] = '\0';   // back after it left
  if (newly_placed) loc_left_pad = false;

  char uid_str[24];
  snprintf(uid_str, sizeof(uid_str), "%02X:%02X:%02X:%02X:%02X:%02X:%02X",
    uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]);

  Serial.printf("NFC: NTAG UID=%s\n", uid_str);
  TagSeen::note(uid_str, "NTAG", TV_OTHER);

  // What the block below has already dealt with, which is a different
  // question from what is on screen.
  //
  // g_tag holds the display, and the display deliberately keeps a spool
  // after it is lifted: clearTagDisplay() runs from the block guarded by
  // !tag_present and NO_TAG_CLEAR_MS. Put the same tag back before that
  // and g_tag still names it, so asking g_tag whether the tag changed
  // answers no and the read below is skipped. Worse, the tag being back
  // keeps last_tag_seen_ms moving, so that block never runs at all and
  // the stale figures stand until the spool is taken off for a full
  // minute.
  //
  // spoolman_queried_uid is not the answer either: it means "asked the
  // backend about this one", and it is only written when the query
  // actually runs. With no WiFi, or with the manual id input open, it
  // stays empty and every poll would look like a new tag.
  bool uid_changed_ntag = (strcmp(uid_str, ntag_handled_uid) != 0);
  if (newly_placed || uid_changed_ntag) tagUnfinishedNotice(uid, 7, uid_str);
  beepOnNewTag(uid_str);
  if (uid_changed_ntag) {
    logSDf("NFC: NTAG UID=%s", uid_str);
    resetActivityTimer();   // a different tag is always news
  }

  lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(UI_COL_GOOD), 0);

  if (uid_changed_ntag) {
    // Marked handled straight away and unconditionally, whatever the
    // query below decides to do.
    strncpy(ntag_handled_uid, uid_str, sizeof(ntag_handled_uid)-1);
    ntag_handled_uid[sizeof(ntag_handled_uid)-1] = '\0';
    // New UID - clear old tag data
    strncpy(g_tag.uid_str, uid_str, sizeof(g_tag.uid_str)-1);
    g_tag.uid_str[sizeof(g_tag.uid_str)-1] = '\0';
    g_tag.tray_uuid[0] = '\0';
    g_tag.material[0] = '\0';
    g_tag.color = SpoolColor{};
    g_tag.color_hex[0] = '\0';
    g_tag.vendor[0] = '\0';
    spoolman_queried_uid[0] = '\0';
    lv_label_set_text(lbl_uid, uid_str);
    lv_label_set_text(lbl_tray_uuid, "-");
    lv_label_set_text(lbl_material, "-");
    lv_label_set_text(lbl_filament_name, "-");
    lv_label_set_text(lbl_vendor, "-");
    lv_label_set_text(lbl_detail, "-");
    lv_label_set_text(lbl_last_used, "-");
    lv_label_set_text(lbl_spoolman_dried_val, "-");
  if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
    mainSwatchPaint(SpoolColor{}, nullptr);
    lv_label_set_text(lbl_status, T(STR_READING_TAG));
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_GOOD), 0);

    // What the tag itself says, before anyone is asked about it. The poll
    // has the tag selected right now, so this is the one moment the pages
    // can be read without competing with it, and the lookup below blocks
    // for as long as the network takes.
    //
    // Only the display: the record is a copy from whenever it was
    // written, and the backend answer below replaces every field it
    // fills. A tag no backend knows keeps these values instead of
    // showing four dashes.
    tagReadInfoNow();
    if (tagCachedHasRecord()) showTagInfoOnDisplay(tagCachedInfo());
    lv_timer_handler();

    if (wifi_ok && !isSpoolFlowIdInputOpen() && !isSecondTagPopupOpen()) {
      querySpoolman(uid_str, LOOKUP_FROM_NTAG);
      strncpy(spoolman_queried_uid, uid_str, sizeof(spoolman_queried_uid)-1);
      spoolman_queried_uid[sizeof(spoolman_queried_uid)-1] = '\0';
      // A verdict that waits for the inventory is followed up by
      // lookupScanTick() once it is in.
      if (!lookupPending()) lookupFollowUp(LOOKUP_FROM_NTAG, uid_str);
    } else {
      lv_label_set_text(lbl_status, T(STR_TAG_FOUND));
      lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_GOOD), 0);
    }
  } else {
    // Same UID - show popup after delay if not dismissed
    // Auto-popup disabled - user uses the Link/Copy buttons in Zone 5
    (void)link_tag_first_seen_ms;
    paintTagStatus();
  }
}

void tagScanIso15693(uint8_t *uid) {
  // ── ISO 15693 (PN7160 only): OpenPrintTag ──────────────
  // As the NTAG branch: read once per placement, show what the tag says,
  // then ask the backend by UID. ntag_handled_uid is the "dealt with"
  // marker of every non-Bambu tag here, despite its name.
  last_tag_seen_ms = millis();
  const bool newly_placed = !tag_present;
  tag_present = true;
  nfc_absent_count = 0;
  if (newly_placed && !weightSaysSpoolStayed()) resetActivityTimer();
  if (newly_placed && loc_left_pad) g_loc_popup_shown_for_id = -1;
  if (newly_placed) loc_left_pad = false;
  uint8_t uid_msb[OPT_UID_BYTES];
  optUidMsbFirst(uid, uid_msb);
  char uid_str[24];
  optUidString(uid_msb, uid_str, sizeof(uid_str));
  lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(UI_COL_GOOD), 0);
  if (strcmp(uid_str, ntag_handled_uid) == 0) {
    TagSeen::note(uid_str, optTagOnReader() ? "OpenPrintTag" : "ISO 15693", TV_OTHER);
    paintTagStatus();
  } else if (optScanTag(uid, uid_str) == OPT_SCAN_RETRY) {
    lv_label_set_text(lbl_status, T(STR_READING_TAG));   // read again on the next poll
  } else {
    snprintf(ntag_handled_uid, sizeof(ntag_handled_uid), "%s", uid_str);
    spoolman_queried_uid[0] = '\0';
    TagSeen::note(uid_str, optTagOnReader() ? "OpenPrintTag" : "ISO 15693", TV_OTHER);
    resetActivityTimer();   // a different tag is always news
    // Painted at once rather than through g_tag_ready: that would paint
    // again on the next pass, over what the lookup below has shown.
    g_tag_displayed = true;
    g_tag_shown_ms = millis();
    updateDisplay();
    lv_label_set_text(lbl_last_used, "-");
    lv_label_set_text(lbl_spoolman_dried_val, "-");
    if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
    lv_timer_handler();
    if (wifi_ok && !isSpoolFlowIdInputOpen() && !isSecondTagPopupOpen()) {
      querySpoolman(uid_str, LOOKUP_FROM_UID);
      snprintf(spoolman_queried_uid, sizeof(spoolman_queried_uid), "%s", uid_str);
      if (!lookupPending()) lookupFollowUp(LOOKUP_FROM_UID, uid_str);
    }
  }
}
