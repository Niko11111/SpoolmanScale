// The MIFARE Classic branch of the scan: a 4 byte UID. Which family to try
// first (Bambu, Creality, Snapmaker, blank), the Bambu retries, the lookup
// once the read has settled, and the CFS write offers.

#include <Arduino.h>
#include <lvgl.h>
#include <cmath>
#include <cstring>

#include "app/app_loop.h"
#include "app/app_loop_shared.h"
#include "app/app_state.h"
#include "app/tag_scan_internal.h"
#include "bambu/bambu_scan.h"
#include "creality/creality_scan.h"
#include "hardware/display_power.h"
#include "hardware/sd_logger.h"
#include "services/breadcrumb.h"
#include "services/location_state.h"
#include "services/mifare_write.h"
#include "services/tag_family.h"
#include "services/tag_write.h"
#include "services/user_options.h"
#include "snapmaker/snapmaker_scan.h"
#include "ui/confirm_popup.h"
#include "ui/main_screen_helpers.h"
#include "ui/second_tag_popup.h"
#include "ui/spool_flow.h"
#include "ui/spoolman_lookup.h"
#include "ui/tag_write_popup.h"
#include "ui/theme.h"
#include "lang.h"

static unsigned long last_bambu_retry_ms = 0; // backoff between Bambu re-scans
static bool snapmaker_decoded = false;  // this placement read as a Snapmaker tag
static char cfs_checked_uid[24] = "";   // own CFS tag compared with Spoolman this placement

void tagScanMifare(uint8_t *uid, uint8_t uidLen) {
  // ── MIFARE Classic (Bambu) ────────────────────────────
  last_tag_seen_ms = millis();
  const bool newly_placed = !tag_present;
  tag_present = true;
  // A successful read means zero consecutive misses, by definition.
  // This used to be reset only when the UID changed, so after the very
  // first read of a spool the counter never went back to zero. The
  // "4 consecutive misses" below then counted misses that were minutes
  // apart, and the fifth glitch of a session declared the spool removed
  // while it was still lying on the scale.
  nfc_absent_count = 0;
  // Putting a tag down wakes the screen, a tag lying there does not: see
  // handlePowerManagement(). One that merely dropped out and came back
  // under a spool that never moved is not news either.
  if (newly_placed && !weightSaysSpoolStayed()) resetActivityTimer();
  // Back after it demonstrably left the pad: whatever was answered
  // for it last time was about that trip, this is a new one.
  if (newly_placed && loc_left_pad) g_loc_popup_shown_for_id = -1;
  if (newly_placed && loc_left_pad) s_beeped_uid[0] = '\0';   // back after it left
  if (newly_placed) loc_left_pad = false;

  char uid_str[24];
  snprintf(uid_str, sizeof(uid_str), "%02X:%02X:%02X:%02X",
    uid[0], uid[1], uid[2], uid[3]);

  // Written since it was read: decoded again, like a new placement. The
  // decode puts the tag's own fields on screen until the backend answers,
  // so the spool is looked up again too; otherwise "Generic" stayed.
  const bool reread = mifareTakeReread(uid);
  if (reread) spoolman_queried_uid[0] = '\0';
  bool uid_changed = new_placement || reread ||
                     (strcmp(uid_str, g_tag.uid_str) != 0);
  new_placement = false;
  if (newly_placed || uid_changed) tagUnfinishedNotice(uid, 4, uid_str);
  int bambu_blocks_read = countBambuDataBlocksRead(g_tag);
  bool uuid_missing = (strlen(g_tag.tray_uuid) < 32);
  bool contents_incomplete = (bambu_blocks_read < 48);

  beepOnNewTag(uid_str);
  if (uid_changed) {
    Serial.printf("NFC: New 4-byte UID %s\n", uid_str);
    resetActivityTimer();   // a different tag is always news
    // The NTAG marker belongs to the NTAG that was read last, and a
    // different tag has been read since. Left standing, the same NTAG
    // put back without a removal in between counted as handled and was
    // never looked up: on 22.09.2026 an NTAG after two Bambu tags kept
    // the Bambu spool on screen, "Update weight" included.
    ntag_handled_uid[0] = '\0';
    nfc_retry_count = 0; nfc_absent_count = 0;
    last_bambu_retry_ms = 0;
    bambu_uid_probed = false;
    bambu_card_refused = false;
    snapmaker_decoded = false;
    creality_decoded = false;
    blank_mifare = false;
    cfs_checked_uid[0] = '\0';
    lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
    lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(UI_COL_GOOD), 0);
    lv_label_set_text(lbl_status, T(STR_READING_TAG));
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_GOOD), 0);
    // Which family to try first. A refused key leaves the card
    // unreachable for a while (12.10.2026: Creality tags tried after the
    // Bambu probe opened only now and then), so the first try has to be
    // the right one. Known tags go straight to their family; see
    // services/tag_family.h. An unknown tag gets Creality first when
    // that is enabled: the key is a single AES derivation from the UID
    // and a tag that opens with it is Creality's, so no Bambu scan and
    // no Snapmaker probe, and the branch below for a plain 4 byte card
    // looks the spool up by its UID. A tag that does not open is woken
    // again inside scanCrealityTag(), so the Bambu scan still finds it.
    TagFamily family = tagFamilyGet(uid);
    // The second tag of a Bambu spool is asked for: an unknown chip gets
    // the Bambu keys first, on the card the poll has just selected. The
    // Creality and factory keys ahead of it knocked a weak Bambu chip off
    // the reader and took the question's 30 s (07.11.2026, #77).
    const bool bambu_asked = secondTagExpectsBambu() &&
        (family == TAG_FAMILY_UNKNOWN || family == TAG_FAMILY_NOT_CREALITY);
    // A tag known to be blank is asked with the factory key first, on
    // the card the poll has just selected, so it never sees a refusal.
    // One that has been written since (FilaStation, CFTag) refuses it
    // and goes through the family choice as an unknown tag.
    int factory = MIFARE_FACTORY_REFUSED;
    // Refused the Creality key last time: the factory key goes first now,
    // on the freshly selected card, ahead of the Bambu probe. A blank
    // sticker that sits weakly on the reader may not come back from the
    // refused Creality key at all (13.10.2026, 6E:C6:DB:4F: no answer to
    // any wake), so asking it in second place found nothing. A Bambu tag
    // pays one refusal on its first placement; after that its family is
    // stored and it goes straight to the Bambu scan.
    if (g_creality_tags && family == TAG_FAMILY_NOT_CREALITY && !bambu_asked) {
      factory = mifareProbeFactory(uid, uid_str);
    }
    if (g_creality_tags && family == TAG_FAMILY_BLANK) {
      factory = mifareProbeFactory(uid, uid_str);
      // Only a tag that refused the factory key or showed data has
      // changed. One that opened and then did not read is the same
      // blank tag on a weak placement (26.10.2026, 15:C5:C5:11 of spool
      // 38: forgotten as blank here, so the write was never offered).
      if (factory != MIFARE_FACTORY_BLANK && factory != MIFARE_FACTORY_UNREAD) {
        tagFamilySet(uid, TAG_FAMILY_UNKNOWN);
        family = TAG_FAMILY_UNKNOWN;
      }
    }
    bool blank_now = (factory != MIFARE_FACTORY_REFUSED);
    const bool creality_first = g_creality_tags && !bambu_asked &&
        (family == TAG_FAMILY_UNKNOWN || family == TAG_FAMILY_CREALITY);
    // An unknown tag alternates between placements: Creality first, then
    // Bambu first, then Creality again, until one family reads it. On
    // hardware (12.10.2026) one side of a Creality spool refused key A on
    // the first try, was marked for Bambu, and never got Creality again:
    // the mark was only dropped once the Bambu retries ran out, and a tag
    // that keeps dropping out never runs them out. So the mark is used
    // once and dropped right here.
    if (family == TAG_FAMILY_NOT_CREALITY) tagFamilySet(uid, TAG_FAMILY_UNKNOWN);
    CrealityScanResult cfs_scan = CREALITY_SCAN_NO_AUTH;
    if (blank_now) {
      // Handled below, like a blank tag found after the Creality probe.
    } else if (creality_first &&
        (cfs_scan = scanCrealityTag(uid, uidLen, /*fresh=*/true)) == CREALITY_SCAN_OK) {
      creality_decoded = true;
      tagFamilySet(uid, TAG_FAMILY_CREALITY);
      nfc_retry_count = NFC_MAX_RETRIES;
      last_nfc_check_ms = 0;
    } else if (cfs_scan == CREALITY_SCAN_EMPTY) {
      // Opens with the Creality key and holds nothing: a CFS tag the
      // scale erased. Still Creality's key, so no factory key probe
      // that it can only refuse; otherwise like a blank sticker.
      tagFamilySet(uid, TAG_FAMILY_CREALITY);
      blank_now = true;
    } else if (g_creality_tags && family == TAG_FAMILY_CREALITY &&
               (factory = mifareProbeFactory(uid, uid_str)) != MIFARE_FACTORY_REFUSED) {
      // Remembered as Creality, but now on the factory key: erased
      // since (CFtag, FilaStation). On 14.10.2026 both tags of spool 9
      // were erased with CFtag and the scale kept trying the Creality
      // key only, so it never offered to write them again. Treated like
      // any blank sticker from here on. A weak Creality tag that did not
      // answer refuses this key too and goes on below as before.
      tagFamilySet(uid, TAG_FAMILY_UNKNOWN);
      blank_now = true;
    } else if (g_creality_tags && family == TAG_FAMILY_CREALITY) {
      // A known Creality tag that did not open this time - one side of a
      // spool lying badly on the pad (12.10.2026). The Bambu scan would
      // only refuse it again. Start a clean record for this UID instead,
      // so the retries below try Creality again on the next polls, and
      // when they run out the spool is still looked up by its UID.
      memset(&g_tag, 0, sizeof(g_tag));
      memcpy(g_tag.uid, uid, 4);
      snprintf(g_tag.uid_str, sizeof(g_tag.uid_str), "%s", uid_str);
    } else if (creality_first && family == TAG_FAMILY_UNKNOWN &&
               (factory = mifareProbeFactory(uid, uid_str)) != MIFARE_FACTORY_REFUSED) {
      // Refused the Creality key, opens with the factory key: a plain
      // sticker, blank ones most likely waiting to be linked and written
      // as a CFS tag. The Bambu probe would refuse it too and knock it
      // off the reader (13.10.2026), so it is not run at all.
      blank_now = true;
    } else if (g_snapmaker_tags && family == TAG_FAMILY_SNAPMAKER) {
      // Read as Snapmaker before: its own keys below, no Bambu probe
      // that can only be refused. A clean record for this UID, so the
      // Snapmaker scan below sees no blocks of the tag before it.
      memset(&g_tag, 0, sizeof(g_tag));
      memcpy(g_tag.uid, uid, 4);
      snprintf(g_tag.uid_str, sizeof(g_tag.uid_str), "%s", uid_str);
    } else {
      // Bambu first on the next placement (once, see above).
      if (creality_first && family == TAG_FAMILY_UNKNOWN) {
        tagFamilySet(uid, TAG_FAMILY_NOT_CREALITY);
      }
      scanTag(uid, uidLen);
      if (bambuScanCardRefused()) bambu_card_refused = true;
      // Remembered as soon as any sector read, not only once the scan
      // has settled on a later poll: on 13.10.2026 a Bambu spool read
      // 6/48 blocks and dropped out before that poll ever came.
      if (countBambuDataBlocksRead(g_tag) > 0) tagFamilySet(uid, TAG_FAMILY_BAMBU);
    }
    // Snapmaker: opt-in, off by default, and then none of this touches
    // the reader. Once per placement, right after the first Bambu probe
    // came back with nothing, or straight away for a tag read as
    // Snapmaker before; never for one read as Bambu before. A tag that
    // answers to Snapmaker's keys is no Bambu tag, so the Bambu retries
    // are skipped and the branch below for a plain 4 byte card looks the
    // spool up by its UID.
    if (blank_now) {
      // Opens with the factory key. Kept on the reader like a Creality
      // tag either way; only an empty one is remembered as blank and
      // offered the CFS write.
      blank_mifare = true;
      if (factory == MIFARE_FACTORY_BLANK) tagFamilySet(uid, TAG_FAMILY_BLANK);
      // A clean record for this UID: looked up by its UID like any
      // plain 4 byte card, once the retries count as spent.
      memset(&g_tag, 0, sizeof(g_tag));
      memcpy(g_tag.uid, uid, 4);
      snprintf(g_tag.uid_str, sizeof(g_tag.uid_str), "%s", uid_str);
      snprintf(g_tag.tray_uuid, sizeof(g_tag.tray_uuid), "%s", uid_str);
      nfc_retry_count = NFC_MAX_RETRIES;
      last_nfc_check_ms = 0;
    }
    if (creality_decoded || blank_now) {
      // Already settled above.
    } else if (g_snapmaker_tags && family != TAG_FAMILY_BAMBU &&
        countBambuDataBlocksRead(g_tag) == 0 &&
        scanSnapmakerTag(uid, uidLen) != SNAPMAKER_SCAN_NO_AUTH) {
      snapmaker_decoded = true;
      // Next time straight to its own keys: no Bambu probe, and no
      // Creality attempt when that switch is on too.
      tagFamilySet(uid, TAG_FAMILY_SNAPMAKER);
      nfc_retry_count = NFC_MAX_RETRIES;
      last_nfc_check_ms = 0;
    }
  } else if (bambu_blocks_read == 0 && !bambu_uid_probed &&
             nfc_retry_count >= NFC_UID_PROBE_AFTER_RETRIES &&
             nfc_retry_count < NFC_MAX_RETRIES &&
             wifi_ok && !isSpoolFlowIdInputOpen() && !isSecondTagPopupOpen()) {
    // Once per placement, see NFC_UID_PROBE_AFTER_RETRIES.
    bambu_uid_probed = true;
    crumbSet("uid probe");
    if (spoolmanTagResolves(uid_str)) {
      logSDf("NFC: %s refused %d probes, but the backend knows the UID - not a Bambu tag to wait for",
             uid_str, nfc_retry_count + 1);
      // The branch below for a tag that has used up its retries does the
      // real lookup and all the bookkeeping. Poll again at once rather
      // than half a second from now.
      nfc_retry_count = NFC_MAX_RETRIES;
      last_nfc_check_ms = 0;
    }
  } else if ((uuid_missing || contents_incomplete) && nfc_retry_count < NFC_MAX_RETRIES &&
             millis() - last_bambu_retry_ms >= NFC_BAMBU_RETRY_BACKOFF_MS) {
    last_bambu_retry_ms = millis();
    nfc_retry_count++;
    Serial.printf("NFC: Bambu contents incomplete (%d/48 blocks, tray_uuid %s), retry %d/%d\n",
      bambu_blocks_read,
      uuid_missing ? "missing" : "present",
      nfc_retry_count,
      NFC_MAX_RETRIES);
    lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
    lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(UI_COL_GOOD), 0);
    lv_label_set_text(lbl_status, T(STR_READING_TAG));
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_GOOD), 0);
    if (g_creality_tags && tagFamilyGet(uid) == TAG_FAMILY_CREALITY) {
      // A known Creality tag gets its own key again, on the card this
      // poll has just selected, rather than the Bambu scan.
      if (scanCrealityTag(uid, uidLen, /*fresh=*/true) == CREALITY_SCAN_OK) {
        creality_decoded = true;
        nfc_retry_count = NFC_MAX_RETRIES;
        last_nfc_check_ms = 0;
      }
    } else if (g_snapmaker_tags && tagFamilyGet(uid) == TAG_FAMILY_SNAPMAKER) {
      // The same for a known Snapmaker tag that did not read on its
      // first try: its own keys again, not the Bambu scan.
      if (scanSnapmakerTag(uid, uidLen) != SNAPMAKER_SCAN_NO_AUTH) {
        snapmaker_decoded = true;
        nfc_retry_count = NFC_MAX_RETRIES;
        last_nfc_check_ms = 0;
      }
    } else {
      scanTag(uid, uidLen);
      if (bambuScanCardRefused()) bambu_card_refused = true;
      if (countBambuDataBlocksRead(g_tag) > 0) tagFamilySet(uid, TAG_FAMILY_BAMBU);
    }
  } else {
    // The "Tag placed" line waits until the scan has settled, so it
    // says what the scale concluded: Bambu once any sector has read,
    // MIFARE once the retries are spent with nothing. In between,
    // while the retries run, nothing is logged yet.
    // Read as Bambu: remember it, so the next placement goes straight
    // to the Bambu scan. No write when it is already known.
    if (bambu_blocks_read > 0) tagFamilySet(uid, TAG_FAMILY_BAMBU);
    if (bambu_blocks_read > 0 || nfc_retry_count >= NFC_MAX_RETRIES) {
      TagSeen::note(uid_str, bambu_blocks_read > 0 ? "Bambu"
                             : creality_decoded    ? "Creality"
                             : snapmaker_decoded   ? "Snapmaker" : "MIFARE",
                    // A sector that opened is enough, also between two
                    // retries: the UID is all a link needs.
                    bambu_blocks_read > 0 ? TV_BAMBU
                    : (creality_decoded || snapmaker_decoded || blank_mifare) ? TV_OTHER
                    : bambu_card_refused ? TV_REFUSED : TV_NO_ANSWER);
    }
    // What the read attempts came to, once: read in full, or out of
    // retries. Logging only.
    if (!(uuid_missing || contents_incomplete) || nfc_retry_count >= NFC_MAX_RETRIES) {
      bambuScanReport();
    }
    if ((uuid_missing || contents_incomplete) && nfc_retry_count >= NFC_MAX_RETRIES &&
        bambu_blocks_read == 0) {
      // Not a Bambu tag at all. Every sector failed authentication, so
      // there is nothing here to decode and no amount of retrying will
      // change that. It is a plain 4 byte card, the kind sold as an RFID
      // button and stuck to spools by SpoolLink users.
      //
      // Those never reached the backend: the branch below insists on a
      // 32 character tray uuid, so they sat in "waiting" forever. Looking
      // them up by their UID is the whole point.
      //
      // Keyed off zero blocks rather than off the retry count alone. A
      // real Bambu tag that only read partially still has dozens of
      // blocks and belongs in the branch above, where "waiting" is the
      // honest answer rather than "not in Spoolman".
      if (wifi_ok && !isSpoolFlowIdInputOpen() && !isSecondTagPopupOpen() &&
          strcmp(uid_str, spoolman_queried_uid) != 0) {
        querySpoolman(uid_str, LOOKUP_FROM_UID);
        strncpy(spoolman_queried_uid, uid_str, sizeof(spoolman_queried_uid)-1);
        spoolman_queried_uid[sizeof(spoolman_queried_uid)-1] = '\0';
        if (!lookupPending()) lookupFollowUp(LOOKUP_FROM_UID, uid_str);
      }
      lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
      lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(UI_COL_GOOD), 0);
      paintTagStatus();
    } else if ((uuid_missing || contents_incomplete) && nfc_retry_count >= NFC_MAX_RETRIES) {
      lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
      lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(UI_COL_WARN), 0);
      lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
      lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_WARN), 0);
    } else {
      // tray_uuid present - query Spoolman if not done yet
      if (!isSpoolFlowIdInputOpen() && !isSecondTagPopupOpen() &&
          strcmp(g_tag.uid_str, spoolman_queried_uid) != 0 && strlen(g_tag.tray_uuid) == 32) {
        crumbSet("backend lookup");
        querySpoolman(g_tag.tray_uuid, LOOKUP_FROM_BAMBU);
        strncpy(spoolman_queried_uid, g_tag.uid_str, sizeof(spoolman_queried_uid)-1);
        spoolman_queried_uid[sizeof(spoolman_queried_uid)-1] = '\0';
        if (!lookupPending()) lookupFollowUp(LOOKUP_FROM_BAMBU, g_tag.tray_uuid);
      } else if (!sm_found && !link_popup_dismissed && !isSpoolFlowLinkEntryOpen() &&
                 wifi_ok && strlen(g_tag.tray_uuid) == 32) {
        // Auto-popup disabled - user uses the Link/Copy buttons in Zone 5
        (void)link_tag_first_seen_ms;
      }
      lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
      lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(UI_COL_GOOD), 0);
      paintTagStatus();
    }
  }

  // A blank tag that belongs to a spool already, and has not been asked
  // about: offer the CFS write. Covers a write that found no tag (the
  // card had dropped off the reader, 13.10.2026) once the spool is put
  // back, and a blank tag linked from Spoolman's web page. Only while
  // the tag answers right now and nothing else holds the screen.
  if (blank_mifare && g_creality_tags && sm_found && sm_id > 0 &&
      strcmp(g_tag.uid_str, uid_str) == 0 && lookupWasFor(uid_str) &&
      tagFamilyGet(uid) == TAG_FAMILY_BLANK && !tagCfsAskedFor(uid_str) &&
      !lookupPending() && !isTagWritePopupOpen() && !isConfirmPopupOpen() &&
      !isSpoolFlowLinkEntryOpen() && !isSpoolFlowIdInputOpen() &&
      !isSecondTagPopupOpen() && strcmp(tagWriteState(), "pending") != 0) {
    logSDf("Tag write: %s is blank and belongs to spool %d, offering Creality CFS",
           uid_str, sm_id);
    showTagWriteAskPopupFmt(sm_id, TAG_FMT_CREALITY);
  }
  // A Creality tag the scales wrote themselves (its UID in the spool's
  // nfc_uid) whose spool has changed since - another colour, material
  // or weight in Spoolman: offer to write it again. And an original tag
  // that describes the spool's filament but carries Creality's serial
  // instead of the spool id: offer to write the id, which is what
  // CFSync links the CFS slot by. Once per placement; an original tag
  // that describes another filament is only offered that after a link.
  // lookupWasFor(): sm_id must be this tag's spool. On 14.10.2026 the
  // tag of spool 13 was compared with spool 12, which had been lifted a
  // moment before - with two spools of one filament that would have
  // offered to write 12's id onto 13's tag.
  if (creality_decoded && g_creality_tags && sm_found && sm_id > 0 &&
      strcmp(cfs_checked_uid, uid_str) != 0 && strcmp(g_tag.uid_str, uid_str) == 0 &&
      lookupWasFor(uid_str) && !lookupPending() && !isTagWritePopupOpen() && !isConfirmPopupOpen() &&
      !isSpoolFlowLinkEntryOpen() && !isSpoolFlowIdInputOpen() &&
      !isSecondTagPopupOpen() && strcmp(tagWriteState(), "pending") != 0) {
    snprintf(cfs_checked_uid, sizeof(cfs_checked_uid), "%s", uid_str);
    bool own = false, differs = false, serial_only = false;
    if (tagCrealityCheck(sm_id, uid_str, &own, &differs, &serial_only) && differs) {
      if (own)              showTagWriteAskPopupFmt(sm_id, TAG_FMT_CREALITY, 1);
      else if (serial_only) showTagWriteAskPopupFmt(sm_id, TAG_FMT_CREALITY, 3);
    }
  }
}
