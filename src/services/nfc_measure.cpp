#include "nfc_measure.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "app/app_state.h"
#include "bambu/bambu_kdf.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "services/nfc_measure_stats.h"

namespace {

enum class MeasureState : uint8_t { Idle, Pending, Running, Done, Failed };

// One cycle per slot, whatever the chip. A PN7160 with discovery running
// answers "no tag" at once where a PN532 waits out its poll; counted per poll,
// the faster chip would rack up misses the slower one never gets to make.
constexpr uint32_t MEASURE_CYCLE_MS        = 200;
constexpr uint16_t MEASURE_POLL_TIMEOUT_MS = 100;   // the scan path's fast poll
constexpr uint8_t  BAMBU_SECTOR    = 0;
constexpr uint8_t  BAMBU_BLOCK     = 1;    // the first data block: material
constexpr uint8_t  BAMBU_SECTORS   = 16;
constexpr uint8_t  NTAG_PAGE       = 4;    // the first user page
constexpr uint8_t  VICINITY_BLOCK  = 0;
constexpr uint8_t  MIFARE_UID_LEN  = 4;
constexpr uint8_t  NTAG_UID_LEN    = 7;
constexpr uint8_t  KEY_BYTES       = 6;
constexpr uint8_t  BLOCK_BYTES     = 16;
// A tag the Bambu key never opened is left at its UID after this many refusals
// in a row: each one halts the card for a while, which would count as misses.
constexpr uint8_t  KEY_GIVE_UP     = 3;
constexpr size_t   UID_STR_LEN     = 32;
constexpr size_t   STATS_JSON_LEN  = 256;

}  // namespace

static MeasureState s_state = MeasureState::Idle;
static uint16_t s_seconds = 0;
static uint32_t s_started_ms = 0;
static uint32_t s_ended_ms = 0;
static uint32_t s_next_cycle_ms = 0;
static NfcMeasureStats s_stats = {};

// The tag of the last read, and what is known about it.
static uint8_t     s_uid[NFC_UID_MAX];
static uint8_t     s_uid_len = 0;
static char        s_uid_str[UID_STR_LEN] = "";
static const char* s_kind = "none";
static uint8_t     s_key[KEY_BYTES];
static bool        s_key_known = false;
static bool        s_key_opened = false;
static uint8_t     s_key_refusals = 0;

static const char* stateName() {
  switch (s_state) {
    case MeasureState::Pending: return "pending";
    case MeasureState::Running: return "running";
    case MeasureState::Done:    return "done";
    case MeasureState::Failed:  return "failed";
    default:                    return "idle";
  }
}

bool nfcMeasureRequest(uint16_t seconds) {
  if (seconds < 1 || seconds > NFC_MEASURE_SECONDS_MAX) return false;
  if (s_state == MeasureState::Pending || s_state == MeasureState::Running) return false;
  s_seconds = seconds;
  s_state = MeasureState::Pending;
  return true;
}

// An ISO 15693 UID arrives least significant byte first and is printed the
// other way round, as on the tag's label.
static void formatUid(const uint8_t* uid, uint8_t len, bool reversed) {
  size_t used = 0;
  s_uid_str[0] = '\0';
  for (uint8_t i = 0; i < len && used + 3 < sizeof(s_uid_str); i++) {
    const uint8_t b = reversed ? uid[len - 1 - i] : uid[i];
    used += snprintf(s_uid_str + used, sizeof(s_uid_str) - used, i ? ":%02X" : "%02X", b);
  }
}

// Returns whether this is a different tag than the read before.
static bool noteTag(const uint8_t* uid, uint8_t len, uint8_t tech) {
  if (len == s_uid_len && memcmp(uid, s_uid, len) == 0) return false;
  const bool first = s_uid_len == 0;
  memcpy(s_uid, uid, len);
  s_uid_len = len;
  formatUid(uid, len, tech == NFC_TECH_V);
  s_kind = tech == NFC_TECH_V       ? "iso15693"
         : len == NTAG_UID_LEN      ? "ntag"
         : len == MIFARE_UID_LEN    ? "mifare" : "other";
  s_key_known = false;
  s_key_opened = false;
  s_key_refusals = 0;
  return !first;
}

static bool readBambuBlock(const uint8_t uid[4], uint8_t data[16]) {
  if (!s_key_opened && s_key_refusals >= KEY_GIVE_UP) return false;
  if (!s_key_known) {
    uint8_t keys[BAMBU_SECTORS][KEY_BYTES];
    s_key_known = deriveKeys(uid, MIFARE_UID_LEN, keys);
    if (s_key_known) memcpy(s_key, keys[BAMBU_SECTOR], KEY_BYTES);
  }
  if (s_key_known && nfcAuthMifareSector(BAMBU_SECTOR, s_key, uid, NFC_KEY_B) &&
      nfcReadMifareBlock(BAMBU_BLOCK, data)) {
    s_key_opened = true;
    s_key_refusals = 0;
    return true;
  }
  if (!s_key_opened && ++s_key_refusals == KEY_GIVE_UP) {
    logSDf("NFC measure: %s did not open with its Bambu key %u times - counting its UID only",
           s_uid_str, KEY_GIVE_UP);
  }
  return false;
}

static bool readOneBlock(const uint8_t* uid, uint8_t len, uint8_t tech) {
  uint8_t data[BLOCK_BYTES];
  if (tech == NFC_TECH_V) return nfcReadVicinityBlock(VICINITY_BLOCK, data);
  if (len == NTAG_UID_LEN) return nfcReadNtagPage(NTAG_PAGE, data);
  if (len == MIFARE_UID_LEN) return readBambuBlock(uid, data);
  return false;
}

static void runCycle() {
  const uint32_t t0 = millis();
  uint8_t uid[NFC_UID_MAX] = {0};
  uint8_t len = 0;
  uint8_t tech = NFC_TECH_A;
  const bool found = nfcReadAnyTarget(uid, &len, MEASURE_POLL_TIMEOUT_MS, &tech);
  const bool changed = found && noteTag(uid, len, tech);
  const bool block = found && readOneBlock(uid, len, tech);
  nfcMeasureCount(s_stats, millis() - t0, found, block, changed);
}

static void begin() {
  if (!nfc_ok) {
    s_state = MeasureState::Failed;
    logSDf("NFC measure: not started, the %s is not ready", nfcChipName());
    return;
  }
  s_stats = {};
  s_uid_len = 0;
  s_uid_str[0] = '\0';
  s_kind = "none";
  s_started_ms = millis();
  s_next_cycle_ms = s_started_ms;
  s_state = MeasureState::Running;
  logSDf("NFC measure: %s, %u s, started", nfcChipName(), s_seconds);
}

static void finish() {
  s_state = MeasureState::Done;
  s_ended_ms = millis();
  const uint32_t uid_pm = nfcMeasurePerMille(s_stats.uid_reads, s_stats.cycles);
  const uint32_t blk_pm = nfcMeasurePerMille(s_stats.block_reads, s_stats.cycles);
  logSDf("NFC measure: %s, %u s, %lu cycles, UID %lu.%lu %%, block %lu.%lu %%, "
         "%lu ms avg, %lu ms max, %lu UID changes, tag %s (%s)",
         nfcChipName(), s_seconds, (unsigned long)s_stats.cycles,
         (unsigned long)(uid_pm / 10), (unsigned long)(uid_pm % 10),
         (unsigned long)(blk_pm / 10), (unsigned long)(blk_pm % 10),
         (unsigned long)nfcMeasureAvgMs(s_stats), (unsigned long)s_stats.cycle_ms_max,
         (unsigned long)s_stats.uid_changes, s_uid_str[0] ? s_uid_str : "-", s_kind);
}

bool nfcMeasureTick() {
  if (s_state == MeasureState::Pending) begin();
  if (s_state != MeasureState::Running) return false;
  const uint32_t now = millis();
  if (now - s_started_ms >= (uint32_t)s_seconds * 1000u) {
    finish();
    return false;
  }
  if ((int32_t)(now - s_next_cycle_ms) < 0) return true;
  s_next_cycle_ms += MEASURE_CYCLE_MS;
  // A cycle that ran long does not earn a burst of make-up cycles after it.
  if ((int32_t)(now - s_next_cycle_ms) > 0) s_next_cycle_ms = now + MEASURE_CYCLE_MS;
  runCycle();
  return true;
}

void nfcMeasureJson(char* out, size_t out_len) {
  char stats[STATS_JSON_LEN];
  nfcMeasureStatsJson(s_stats, stats, sizeof(stats));
  uint32_t elapsed = 0;
  if (s_state == MeasureState::Running) elapsed = millis() - s_started_ms;
  if (s_state == MeasureState::Done) elapsed = s_ended_ms - s_started_ms;
  snprintf(out, out_len,
           "{\"state\":\"%s\",\"chip\":\"%s\",\"seconds\":%u,\"elapsed_ms\":%lu,"
           "\"cycle_ms\":%lu,\"tag\":\"%s\",\"kind\":\"%s\",%s}",
           stateName(), nfcChipName(), s_seconds, (unsigned long)elapsed,
           (unsigned long)MEASURE_CYCLE_MS, s_uid_str, s_kind, stats);
}
