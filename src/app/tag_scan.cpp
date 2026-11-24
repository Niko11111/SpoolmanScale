#include "app/tag_scan.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cmath>
#include <cstring>

#include "app_config.h"
#include "app/app_loop.h"
#include "app/app_loop_shared.h"
#include "app/app_state.h"
#include "app/perf_monitor.h"
#include "app/tag_scan_internal.h"
#include "bambu/bambu_scan.h"
#include "creality/creality_scan.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "hardware/sound.h"
#include "openprinttag/opt_sim.h"
#include "openprinttag/opt_tag.h"
#include "services/breadcrumb.h"
#include "services/nfc_measure.h"
#include "services/nfc_reset.h"
#include "services/user_options.h"
#include "ui/header_status.h"
#include "ui/second_tag_popup.h"
#include "ui/spool_flow.h"
#include "ui/spoolman_lookup.h"
#include "ui/theme.h"
#include "ui/unknown_spool_popup.h"
#include "lang.h"

using namespace apploop;
using namespace tagscan;

// The tag the read beep last sounded for. Its own marker on purpose: the
// lookup markers (g_tag.uid_str, ntag_handled_uid) are cleared and rewritten
// by retries, rereads after a write and tagLookupForget(), and following them
// would beep on every poll of a Bambu tag still being read, or once more
// right after the write tone. Cleared when the spool demonstrably left the
// pad: on removal, or when a placement finds loc_left_pad set.
char tagscan::beeped_uid[24] = "";

void tagscan::beepOnNewTag(const char *uid_str) {
  if (strcmp(uid_str, beeped_uid) == 0) return;
  snprintf(beeped_uid, sizeof(beeped_uid), "%s", uid_str);
  soundPlay(SND_NFC_READ);
}

// The poll finds the same tag several times a second. This says so once,
// so the log reads as "a tag was put on" rather than as a scan trace.
static char logged_uid[26] = "";

// See tagSettledVerdict() in app_loop.h. Written by TagSeen below.
static char       s_settled_uid[26] = "";
static TagVerdict s_settled_verdict = TV_NONE;

TagVerdict tagSettledVerdict(const char* uid_str) {
  if (!uid_str || !uid_str[0] || strcmp(uid_str, s_settled_uid) != 0) return TV_NONE;
  return s_settled_verdict;
}

void tagscan::TagSeen::note(const char *uid, const char *kind, TagVerdict verdict) {
    if (!uid || !uid[0]) return;
    // The verdict is kept on every call, the line is written once.
    snprintf(s_settled_uid, sizeof(s_settled_uid), "%s", uid);
    s_settled_verdict = verdict;
    if (strcmp(logged_uid, uid) == 0) return;
    snprintf(logged_uid, sizeof(logged_uid), "%s", uid);
    logSDf("Tag placed: %s (%s)", uid, kind);
}

void tagscan::TagSeen::forget() {
    logged_uid[0] = '\0';
    s_settled_uid[0] = '\0';
    s_settled_verdict = TV_NONE;
}

unsigned long tagscan::last_nfc_check_ms = 0;
bool tagscan::bambu_uid_probed = false;   // see NFC_UID_PROBE_AFTER_RETRIES
bool tagscan::bambu_card_refused = false; // the card turned a Bambu key down, see TagVerdict
bool tagscan::creality_decoded = false;   // this placement read as a Creality CFS tag
bool tagscan::blank_mifare = false;       // this placement is a blank MIFARE tag
bool tagscan::new_placement = false;      // same tag back after a long absence
static unsigned long last_nfc_stats_ms = 0;
static uint8_t last_uid_len = 0;   // 4 = Bambu, 7 = NTAG, 8 = ISO 15693, for the removal delay

static unsigned long first_miss_ms = 0;       // start of the current detection gap
static unsigned long tag_absent_since_ms = 0; // when the last removal was declared

// What the pad carried at the last poll that read the tag. A tag that stops
// answering while the weight falls well below this was lifted, not lost.
static float weight_at_last_read = 0.0f;

// Something spool-sized lies on the pad, and it has not fallen to under half
// of what the pad carried when the tag was last read. Independent of the
// settled reference, which a spool put down a second ago does not have yet:
// on 13.10.2026 a Bambu tag read once and went silent 1.5 s after the spool
// was put down, before the weight had settled, so the spool was dropped and
// never weighed although it lay there.
static bool padCarriesSpool() {
  if (!g_scale_fitted || !scale_ready) return false;
  const float floor_g = fmaxf(LOC_WEIGHT_MIN_G, weight_at_last_read * LOC_WEIGHT_GONE_FRACTION);
  return scale_weight_g >= floor_g;
}

// The same way back for the reader, and the reason it did not exist before:
// the reader watchdog at the end of tagScanNoTag() runs only under
// `if (nfc_ok)` in tagScanTick(), so it only ever
// ran for a reader that had already worked once. A PN532 that failed at boot
// left nfc_ok false, skipped the whole scan block including its own
// watchdog, and stayed dead until someone power cycled the device - over a
// connector that may well have been pushed back in minutes earlier.
//
// That matters more now than it did: the diagnosis tells people to check a
// plug, and a suggestion whose result only shows after a restart is not much
// of a suggestion. Only attempted while the chip actually acknowledges its
// address, so a device built without a reader does not retry forever.
void tagReaderRecoverTick() {
  static unsigned long last_nfc_recover_ms = 0;
  static uint8_t nfc_recover_tries = 0;
  if (!nfc_ok && millis() - last_nfc_recover_ms >= 5000) {
    last_nfc_recover_ms = millis();
    if (!nfcChipOnBus(I2C_EXT)) {
      // Off the bus entirely. Nothing to re-initialise, and the counter is
      // cleared so a reader that is plugged back in gets a full set of
      // attempts rather than the remainder of an old one.
      nfc_recover_tries = 0;
    } else if (nfc_recover_tries < NFC_RECOVER_ATTEMPTS) {
      nfc_recover_tries++;
      uint32_t ver = 0;
      if (nfcHardwareReinit(&ver)) {
        nfc_ok = true;
        nfc_recover_tries = 0;
        nfc_stat_reinits++;
        nfcReaderNoteRecovery();
        Serial.printf("NFC: reader came back (fw 0x%08lX)\n", (unsigned long)ver);
        logSDf("NFC: reader recovered (fw 0x%08lX)", (unsigned long)ver);
        updateHeaderStatus();
      } else {
        Serial.printf("NFC: re-init failed (%u/%u)\n",
                      nfc_recover_tries, NFC_RECOVER_ATTEMPTS);
        logSDf("NFC: re-init failed (%u/%u)",
               nfc_recover_tries, NFC_RECOVER_ATTEMPTS);
      }
    }
  } else if (nfc_ok) {
    nfc_recover_tries = 0;
  }
}

// No tag answered the poll: the grace period, the wake of a silent Creality
// tag, the hold by the weight, the removal, and the reader watchdog.
static void tagScanNoTag() {
  // No tag found
  // A Creality tag that was read and then stops answering is most often
  // still lying there: on hardware (13.10.2026) it went quiet right after
  // the read and the spool was declared removed while it sat on the pad.
  // Wake it before counting the miss; at most every 400 ms, so a spool
  // that really left costs a few wake attempts and not more.
  static unsigned long last_presence_recover_ms = 0;
  static char recover_uid[24] = "";
  static int recover_count = 0;
  bool recovered = false;
  // Held by the weight: nothing to count while the pad still carries
  // what it carried when the tag was last read.
  bool held = false;
  if (tag_present && tag_kept_by_weight) {
    if (padCarriesSpool()) {
      held = true;
      last_tag_seen_ms = millis();
    } else {
      tag_kept_by_weight = false;
      logSDf("NFC: the pad lost the spool (%.0fg, %.0fg at the last read) - checking the tag again",
             scale_weight_g, weight_at_last_read);
    }
  }
  // Only for the first seconds after the tag last answered: a Creality
  // tag sits off-centre on the flange, and a spool turned so the tag is
  // out of the reader's reach (13.10.2026) does not come back from any
  // wake. Beyond that the usual grace period decides.
  // Lifted, not lost: the weight fell well below what the pad carried
  // at the last read. No wakes then, so the removal comes at once.
  const bool lifted = g_scale_fitted && weight_at_last_read >= LOC_WEIGHT_MIN_G &&
                      scale_weight_g < weight_at_last_read - LOC_WEIGHT_TOLERANCE_G;
  if (!held && !lifted && tag_present && (creality_decoded || blank_mifare) && last_uid_len == 4 &&
      millis() - last_tag_seen_ms < NFC_CFS_RECOVER_WINDOW_MS &&
      millis() - last_presence_recover_ms >= NFC_CFS_RECOVER_EVERY_MS) {
    last_presence_recover_ms = millis();
    const int w = crealityRecoverCard(g_tag.uid, g_tag.uid_str);
    if (strcmp(recover_uid, g_tag.uid_str) != 0) {
      snprintf(recover_uid, sizeof(recover_uid), "%s", g_tag.uid_str);
      recover_count = 0;
    }
    if (w) {
      recovered = true;
      if (++recover_count <= NFC_CFS_RECOVER_LOG_FIRST ||
          recover_count % NFC_CFS_RECOVER_LOG_EVERY == 0) {
        logSDf("NFC: %s stopped answering, woken again (woke=%d, %d so far)",
               g_tag.uid_str, w, recover_count);
      }
    }
  }
  if (held) {
    nfc_fast_polls = 0;
    nfc_miss_streak = 0;
  } else if (recovered) {
    last_tag_seen_ms = millis();
    nfc_fast_polls = 0;
    nfc_miss_streak = 0;
    nfc_absent_count = 0;
  } else if (tag_present) {
    // First close the gap with a few short-interval retries. Most NTAG
    // dropouts are a single missed read and come back on the next one.
    // Neither branch leaves the loop pass early any more: the two returns
    // that stood here skipped the link bar check and the 5 ms pause at
    // the end of the loop on every fast re-poll.
    const bool retrying = (nfc_fast_polls < NFC_FAST_POLL_MAX);
    if (retrying) {
      if (nfc_fast_polls == 0) first_miss_ms = millis();
      nfc_fast_polls++;   // next poll follows in NFC_POLL_FAST_MS
    }
    // Retries exhausted. NTAG gets the longer grace period because it is
    // the flakier of the two protocols.
    //
    // The grace period is measured from the first missed read, not from
    // the last successful one. A full Bambu scan blocks for about five
    // seconds, and last_tag_seen_ms does not advance while it runs, so
    // measuring from there declared every tag removed the moment the
    // scan returned - which restarted the retry counter and looped
    // forever on a tag that would not authenticate.
    const unsigned long absent_limit =
      (last_uid_len == 7 || last_uid_len == OPT_UID_BYTES) ? NFC_ABSENT_NTAG_MS : NFC_ABSENT_BAMBU_MS;
    // Unless the scale already says the spool is gone: then the grace
    // period only holds the old spool on the screen, the touch slowed by
    // the fast re-polls, and the location question back by 2.5 s.
    const bool weight_gone = weightSaysSpoolGone() &&
                             nfc_fast_polls >= NFC_GONE_MIN_MISSES;
    if (!weight_gone && !retrying && millis() - first_miss_ms >= absent_limit &&
        g_creality_tags && last_uid_len == 4 && padCarriesSpool()) {
      // Silent tag, unchanged weight: the spool is still lying there.
      // Creality tags only, and only for a 4 byte tag: the weak CFS tags
      // on a side-mounted reader are what this is for, and with the
      // switch off the removal works exactly as before.
      tag_kept_by_weight = true;
      nfc_fast_polls = 0;
      last_tag_seen_ms = millis();
      logSDf("NFC: tag silent, but the pad still carries %.0fg (%.0fg at the last read) - spool stays present",
             scale_weight_g, weight_at_last_read);
    } else if (weight_gone || (!retrying && millis() - first_miss_ms >= absent_limit)) {
      nfc_stat_removals++;
      bambuScanReport();   // a Bambu tag that left before its reads settled
      Serial.printf("NFC: tag removed (gap %u ms, %d fast re-polls, %s)\n",
        (unsigned)(millis() - first_miss_ms), nfc_fast_polls,
        weight_gone ? "weight gone" : "grace period over");
      logSDf("NFC: tag removed after %u ms (%s)",
             (unsigned)(millis() - first_miss_ms),
             weight_gone ? "weight gone" : "grace period over");
      nfc_fast_polls = 0;
      tag_present = false;
      tag_absent_since_ms = millis();
      nfc_absent_count = 0;
      last_tag_seen_ms = millis();
      spoolman_queried_uid[0] = '\0';  // allow re-query when same tag is placed again
      // Only a spool that demonstrably left counts as news when it comes
      // back. An NTAG whose reception drops out for longer than the grace
      // period, with the spool still sitting on the pad, would otherwise
      // clear the display and fetch the whole spool again on every
      // dropout - which is the loop the display gate was there to stop.
      //
      // A different tag is unaffected: its UID no longer matches the
      // marker, so swapping spools still reads.
      if (weightSaysSpoolStayed()) {
        logSDf("NFC: tag lost, but the pad still carries %.0fg of %.0fg - kept",
               scale_weight_g, loc_weight_ref);
      } else {
        ntag_handled_uid[0] = '\0';
        beeped_uid[0] = '\0';   // put back, it beeps again
        // The spool left before its verdict was in: nothing to paint it
        // on. The inventory still comes in for cache and index. Not in
        // the branch above, where the spool is still there and nothing
        // would look it up again.
        lookupAbandon();
        // The card for an unknown spool goes with it; put down again, it
        // may be asked about again.
        unknownSpoolForget();
      }
      TagSeen::forget();
      link_popup_dismissed = false;   // Reset flag → next spool can show popup
      link_tag_first_seen_ms = 0;
      lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
      lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(UI_COL_WARN), 0);
      lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
      lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_WARN), 0);
      onTagRemoved();
    }
    // Do NOT close list - user should be able to select spool
    // even if tag is temporarily removed
  }

  // ── Reader watchdog ───────────────────────────────────────────────
  // A long miss streak is normal with an empty scale, so it is not by
  // itself evidence of a problem. Probe the reader instead: a PN532 that
  // has locked up stops answering GetFirmwareVersion, and because it
  // shares I2C_EXT with the NAU7802 it would take the scale down too.
  if (nfc_miss_streak >= NFC_HEALTHCHECK_AFTER_MISSES) {
    nfc_miss_streak = 0;
    if (!nfcHardwarePing()) {
      uint32_t ver = 0;
      bool recovered = nfcHardwareReinit(&ver);
      nfc_stat_reinits++;
      nfcReaderNoteRecovery();
      Serial.printf("NFC: reader not responding, re-init %s (fw 0x%08lX)\n",
        recovered ? "ok" : "FAILED", (unsigned long)ver);
      logSDf("NFC: reader re-init %s (fw 0x%08lX)",
        recovered ? "ok" : "failed", (unsigned long)ver);
      nfc_ok = recovered;
      updateHeaderStatus();
    }
  }
}

void tagScanTick() {
  // ============================================================
  //  NFC SCAN: one poll, then the branch for what answered
  //  - 4 byte UID: MIFARE Classic (Bambu, Creality, Snapmaker, blank, other)
  //  - 7 byte UID: NTAG (a record of ours or a foreign one, or blank)
  //  - ISO 15693 (PN7160 only): OpenPrintTag
  //  - anything else, or nothing: the no-tag branch
  // ============================================================
  // A read-rate measurement (services/nfc_measure.h) has the reader to itself
  // while it runs; the scan path picks up again when it is over.
  const bool nfc_measuring = nfcMeasureTick();
  if (nfc_ok && !nfc_measuring) {
    // Fast re-poll only makes sense while a tag is believed to be on the
    // reader. With nothing on the scale the slow interval is the right one.
    const bool fast_mode = (tag_present && nfc_fast_polls > 0);
    const unsigned long poll_interval = fast_mode ? NFC_POLL_FAST_MS : NFC_POLL_SLOW_MS;
    const uint16_t poll_timeout = fast_mode ? NFC_TIMEOUT_FAST_MS : NFC_TIMEOUT_SLOW_MS;

    perfSection("nfc");
    if (millis() - last_nfc_check_ms >= poll_interval) {
      last_nfc_check_ms = millis();
      uint8_t uid[NFC_UID_MAX], uidLen = 0;
      crumbSet("nfc poll");
      const unsigned long poll_start_ms = millis();
      // ISO 14443A and, on a PN7160, ISO 15693 (OpenPrintTag). On a PN532 this
      // is the same call as before and tech stays NFC_TECH_A.
      uint8_t tech = NFC_TECH_A;
      bool found = nfcReadAnyTarget(uid, &uidLen, poll_timeout, &tech);
      // A simulated OpenPrintTag, only while one is armed over the web.
      if (!found && optSimPoll(uid, &uidLen, &tech)) found = true;
      perfNfcPoll(found, (uint32_t)(millis() - poll_start_ms));

      nfc_stat_scans++;
      if (found) {
        last_uid_len = uidLen;
        tag_kept_by_weight = false;
        weight_at_last_read = scale_weight_g;
        // Only a genuinely long absence earns a fresh set of retries. Without
        // this a tag that keeps failing to authenticate would be re-scanned
        // indefinitely, five seconds per attempt.
        if (tag_absent_since_ms != 0) {
          // While the second-tag question stands it asks for exactly that:
          // lift the spool and put it back for a fresh read. So there any
          // declared removal counts, not only a long one.
          if (millis() - tag_absent_since_ms > NFC_RETRY_RESET_ABSENT_MS ||
              isSecondTagPopupOpen()) {
            nfc_retry_count = 0;
            bambu_uid_probed = false;
            bambu_card_refused = false;
            // Back after a long absence: a new placement, even of the same
            // tag. It goes through the family choice below like a new UID;
            // until 12.10.2026 it only re-ran the Bambu scan, so a Creality
            // tag put back after ten seconds was never tried with its key.
            // Creality tags only: with them off, the same tag back gets its
            // retries again and nothing else, as before.
            new_placement = g_creality_tags;
          }
          tag_absent_since_ms = 0;
        }
        if (nfc_fast_polls > 0) {
          nfc_stat_recovered++;
          Serial.printf("NFC: recovered after %d fast re-poll(s) (%u ms gap)\n",
            nfc_fast_polls, (unsigned)(millis() - first_miss_ms));
          nfc_fast_polls = 0;
        }
        nfc_miss_streak = 0;
      } else {
        nfc_stat_misses++;
        nfc_miss_streak++;
      }

      // Aggregate statistics to SD, verbose only.
      if (sd_verbose && millis() - last_nfc_stats_ms >= NFC_STATS_LOG_INTERVAL_MS) {
        last_nfc_stats_ms = millis();
        logSDf("[verbose] NFC stats: scans=%lu misses=%lu recovered=%lu removals=%lu reinits=%lu",
          nfc_stat_scans, nfc_stat_misses, nfc_stat_recovered,
          nfc_stat_removals, nfc_stat_reinits);
      }

      if (found && uidLen == 4) {
        tagScanMifare(uid, uidLen);
      } else if (found && uidLen == 7) {
        tagScanNtag(uid);
      } else if (found && tech == NFC_TECH_V && uidLen == OPT_UID_BYTES) {
        tagScanIso15693(uid);
      } else {
        // Also a tag that answered but fits no branch (another UID length).
        tagScanNoTag();
      }
    }
  }
}
