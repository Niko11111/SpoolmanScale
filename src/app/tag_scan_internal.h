#pragma once

// State the three tag_scan files share: tag_scan.cpp (poll, no tag, reader
// watchdog), tag_scan_mifare.cpp and tag_scan_ntag.cpp. Included by those
// three only (check.sh). The NFC_* timings live here so they stay in one place.

#include <stdint.h>

#include "app/app_loop.h"

constexpr int NFC_MAX_RETRIES = 5;

// ── NFC polling (v0.6.1-beta) ──────────────────────────────────────────────
// A single missed read used to count as a miss straight away. NTAG couples
// more weakly than Bambu's MIFARE Classic, so those single dropouts are common
// even when the spool has not moved. Instead of retrying inside the same loop
// pass - which would block lv_timer_handler() for twice the timeout - a miss
// shortens the next poll interval. Every retry is therefore a separate loop
// pass and the UI keeps running between them.
//
// The slow timeout is what an empty reader costs: the poll waits it out on
// this task every time, and no touch is read meanwhile. At 150 ms that was 30 %
// of all time with nothing on the scale. Measured over 926 successful polls
// with NTAG, Bambu and a plain MIFARE Classic 1k: a tag that is there answers
// in 26 to 38 ms, never more. Only a tag arriving while the poll was already
// waiting took longer, and that one is found by the next poll instead. A tag
// needing longer than the timeout would never be found, since every poll
// starts the search again, so this stays at twice the slowest answer seen.
constexpr unsigned long NFC_POLL_SLOW_MS   = 500;
constexpr unsigned long NFC_POLL_FAST_MS   = 60;
constexpr uint16_t      NFC_TIMEOUT_SLOW_MS = 80;
constexpr uint16_t      NFC_TIMEOUT_FAST_MS = 100;
// Raised from 5 to 7 after hardware testing: three of four recovered dropouts
// needed all five attempts and ran 1.2 to 1.4 s, so the old limit was only
// just sufficient. Costs nothing when reads succeed.
constexpr int           NFC_FAST_POLL_MAX   = 7;

// Removal is decided on elapsed time, not on a miss count. With a variable
// poll interval a count no longer maps to a fixed duration.
constexpr unsigned long NFC_ABSENT_BAMBU_MS = 1500;
constexpr unsigned long NFC_ABSENT_NTAG_MS  = 2500;

// An idle reader misses continuously because there is simply no tag, so a
// blind re-init after N misses would fire every few seconds while the scale
// sits empty. Probe first, and only re-init when the probe fails.
constexpr int NFC_HEALTHCHECK_AFTER_MISSES = 60;

// Aggregate NFC statistics go to the SD log on this interval, and only when
// verbose logging is on. Per-event lines stay on Serial.
constexpr unsigned long NFC_STATS_LOG_INTERVAL_MS = 300000;

// A Bambu tag that will not authenticate used to be retried back to back, and
// a full failing scan takes several seconds. Five of those in a row froze the
// UI for roughly 17 seconds. Hammering a tag that is not responding does not
// help it, so the retries are spaced out.
constexpr unsigned long NFC_BAMBU_RETRY_BACKOFF_MS = 1500;

// A 4 byte tag that refuses every sector is either a Bambu tag lying badly or
// not a Bambu tag at all, and only the retries can tell: over four days one
// real Bambu spool in fifty needed all six attempts. A plain MIFARE card
// therefore sat through them all, ten seconds, before its UID was looked up.
// After this many refused retries the backend is asked, cheaply, whether it
// knows the UID. A yes ends the probing. A no changes nothing: the retries go
// on, so no Bambu tag is given up on any earlier than before.
constexpr int NFC_UID_PROBE_AFTER_RETRIES = 1;

// A tag that has used up its retries must stay given up on. Clearing the retry
// counter on every removal let a tag that never authenticates restart the
// count each time and re-scan forever. The counter is only cleared once the
// tag has really been gone for a while, or when a different tag shows up.
constexpr unsigned long NFC_RETRY_RESET_ABSENT_MS = 10000;

// A Creality tag that stops answering right after its read is woken, but only
// this long after it last answered: a spool turned so the tag is out of reach
// (13.10.2026) does not come back from any wake. Beyond it the usual grace
// period decides.
constexpr unsigned long NFC_CFS_RECOVER_WINDOW_MS = 3000;
// At most one wake per interval, so a spool that really left costs a few
// wake attempts and not more.
constexpr unsigned long NFC_CFS_RECOVER_EVERY_MS  = 400;
// Wakes logged per tag: the first few, then one in this many.
constexpr int NFC_CFS_RECOVER_LOG_FIRST = 3;
constexpr int NFC_CFS_RECOVER_LOG_EVERY = 50;

// Two missed reads in a row, 60 ms apart, plus a halved weight: the spool is
// off the pad. Without the weight the NFC grace period decides, as before.
constexpr int NFC_GONE_MIN_MISSES = 2;

// Written by the poll in tag_scan.cpp, read and set by the branches.
extern unsigned long last_nfc_check_ms;
extern bool bambu_uid_probed;
extern bool bambu_card_refused;
extern bool creality_decoded;
extern bool blank_mifare;
extern bool new_placement;
extern char s_beeped_uid[24];

void beepOnNewTag(const char *uid_str);

// The poll finds the same tag several times a second. note() says so once,
// and keeps the verdict tagSettledVerdict() reports.
struct TagSeen {
  static void note(const char *uid, const char *kind, TagVerdict verdict);
  static void forget();
};

// One branch each of the poll, for the tag it found.
void tagScanMifare(uint8_t *uid, uint8_t uidLen);
void tagScanNtag(uint8_t *uid);
void tagScanIso15693(uint8_t *uid);
