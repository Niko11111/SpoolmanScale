#include "openprinttag/opt_write.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <math.h>
#include <string.h>

#include "app/app_state.h"
#include "app/id_spool.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "openprinttag/opt_aux.h"
#include "openprinttag/opt_scan.h"
#include "openprinttag/opt_tag.h"
#include "services/user_options.h"
#include "lang.h"

namespace {

constexpr size_t   BLOCK_BYTES = 4;     // ICODE SLIX2
// The head read first, as the scan does: the CC and the TLVs' start.
constexpr uint8_t  HEAD_BLOCKS = 8;
// The scan's ceiling (opt_scan.cpp): every region is at most 512 bytes.
constexpr size_t   MEM_MAX = 512;
// A block is written this often at most; whether it took, the read-back
// decides, not the answer, which can be lost although the block was written.
constexpr uint8_t  BLOCK_TRIES = 3;
// Attempts in all, this far apart: a reselect the chip missed, a spool still
// settling. A spool lifted right after the send ends it at once.
constexpr uint8_t  ATTEMPTS = 4;
constexpr uint32_t ATTEMPT_GAP_MS = 750;
// attempt(): try again later; 0 is done, anything else a STR_ id.
constexpr int      ATTEMPT_RETRY = -1;

// One write while it runs, in PSRAM: kept for good, a kilobyte and a half
// would sit in the internal RAM the renderer and the workers live on. The
// target is planned once, by the first attempt that reads the tag: a region a
// broken-off attempt left half written no longer decodes, the region it was
// going to be still is that.
struct Job {
  uint8_t  was[MEM_MAX];      // the tag as read by this attempt
  uint8_t  now[MEM_MAX];      // and as it is to be
  uint8_t  target[MEM_MAX];   // the aux region as it is to be
  size_t   at, size;          // where that region lies, valid with planned
  bool     planned;
  uint32_t consumed;
  float    full;
};

}  // namespace

static Job*     s_job = nullptr;
static bool     s_pending = false;
static float    s_remaining_g = 0.0f;
static char     s_uid[OPT_UID_STR_LEN + 1] = "";
static uint8_t  s_uid_wire[OPT_UID_BYTES] = {0};
static uint8_t  s_attempts = 0;
static uint32_t s_next_ms = 0;

void optWeightWritePark(float remaining_g) {
  if (!g_opt_write_weight || nfcChip() != NFC_CHIP_PN7160 || !optTagOnReader()) return;
  // A spool picked by its number is not the one the tag belongs to.
  if (idSpoolActive() || !isfinite(remaining_g)) return;
  if (optLastReadSimulated()) {
    logSD("OPT: the simulated tag takes no weight");
    return;
  }
  if (!s_job) s_job = (Job*)heap_caps_malloc(sizeof(Job), MALLOC_CAP_SPIRAM);
  if (!s_job) {
    logSD("OPT: no memory for the tag's image, weight not written");
    return;
  }
  s_job->planned = false;
  s_pending = true;
  s_remaining_g = remaining_g;
  s_attempts = 0;
  s_next_ms = millis();
  snprintf(s_uid, sizeof(s_uid), "%s", g_tag.uid_str);
  optLastUidWire(s_uid_wire);
}

// The tag as it is now, not as the scan read it: a printer may have written
// its aux since. The CC and TLVs, then up to the end of the NDEF message.
static size_t readFresh(uint8_t* mem) {
  memset(mem, 0, MEM_MAX);
  if (!nfcReadVicinityBlocks(0, HEAD_BLOCKS, mem)) return 0;
  size_t want = optBytesNeeded(mem, HEAD_BLOCKS * BLOCK_BYTES);
  if (want == 0 || want > MEM_MAX) return 0;
  const uint16_t blocks = (uint16_t)((want + BLOCK_BYTES - 1) / BLOCK_BYTES);
  if (blocks > HEAD_BLOCKS &&
      !nfcReadVicinityBlocks(HEAD_BLOCKS, blocks - HEAD_BLOCKS, mem + HEAD_BLOCKS * BLOCK_BYTES))
    return 0;
  return want;
}

// The aux region as it is to be, from the tag as read. 0, ATTEMPT_RETRY for a
// read that does not decode, or why the tag cannot take the weight.
static int planTarget(Job& j, size_t len) {
  OptTag t;
  if (optDecodeMemory(j.was, len, &t) != OPT_OK) return ATTEMPT_RETRY;
  j.full = optFullWeightG(t);
  if (j.full <= 0.0f) return STR_OPTW_FAIL_FULL;
  j.consumed = optConsumedFor(j.full, s_remaining_g);
  if (!optAuxLocate(j.was, len, &j.at, &j.size) ||
      !optAuxWithConsumed(j.was + j.at, j.size, j.consumed, j.target)) return STR_OPTW_FAIL_AUX;
  j.planned = true;
  return 0;
}

static bool writeBlock(uint8_t b, const uint8_t* want) {
  for (uint8_t i = 0; i < BLOCK_TRIES; i++) {
    uint8_t back[BLOCK_BYTES];
    nfcWriteVicinityBlock(s_uid_wire, b, want);
    if (nfcReadVicinityBlock(b, back) && memcmp(back, want, BLOCK_BYTES) == 0) return true;
  }
  logSDf("OPT: block %u of %s did not take", (unsigned)b, s_uid);
  return false;
}

// The blocks of the aux region that differ between was and now. How many were
// written, -1 when one did not take.
static int writeChanged(const Job& j) {
  int written = 0;
  for (size_t b = j.at / BLOCK_BYTES; b * BLOCK_BYTES < j.at + j.size; b++) {
    const uint8_t* want = j.now + b * BLOCK_BYTES;
    if (memcmp(j.was + b * BLOCK_BYTES, want, BLOCK_BYTES) == 0) continue;
    if (!writeBlock((uint8_t)b, want)) return -1;
    written++;
  }
  return written;
}

// One attempt. 0 when the tag holds the target, ATTEMPT_RETRY, or why not.
static int attempt(Job& j) {
  if (!optTagOnReader() || strcmp(g_tag.uid_str, s_uid) != 0) return STR_OPTW_FAIL_GONE;
  const size_t len = readFresh(j.was);
  if (len == 0) return ATTEMPT_RETRY;
  if (!j.planned) {
    const int why = planTarget(j, len);
    if (why) return why;
  }
  if (j.at + j.size > len) return ATTEMPT_RETRY;
  memcpy(j.now, j.was, MEM_MAX);
  memcpy(j.now + j.at, j.target, j.size);
  const int blocks = writeChanged(j);
  if (blocks < 0) return ATTEMPT_RETRY;
  logSDf("OPT: %s consumed %u g (full %.0f g, left %.0f g), %d block(s) written", s_uid,
         (unsigned)j.consumed, j.full, s_remaining_g, blocks);
  return 0;
}

int optWeightWriteTick() {
  if (!s_pending || (int32_t)(millis() - s_next_ms) < 0) return 0;
  int why = attempt(*s_job);
  if (why == ATTEMPT_RETRY && ++s_attempts < ATTEMPTS) {
    s_next_ms = millis() + ATTEMPT_GAP_MS;
    return 0;
  }
  if (why == ATTEMPT_RETRY) why = STR_OPTW_FAIL_WRITE;
  if (why == 0) optNoteConsumed((float)s_job->consumed);
  else logSDf("OPT: weight not written to %s (%d), %u attempt(s)", s_uid, why, (unsigned)s_attempts + 1);
  s_pending = false;
  heap_caps_free(s_job);
  s_job = nullptr;
  return why;
}
