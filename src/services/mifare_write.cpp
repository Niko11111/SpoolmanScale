#include "mifare_write.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "services/tag_pending.h"

// The key every MIFARE Classic tag leaves the factory with.
static const uint8_t FACTORY_KEY[MIFARE_KEY_BYTES] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
// The transport configuration (FF 07 80, user byte 69): data blocks read and
// written with key A or B, key A rewrites the trailer. The only access bits
// this file ever writes; Creality's own tags carry the same.
static const uint8_t TRANSPORT_ACCESS[4] = {0xFF, 0x07, 0x80, 0x69};

static constexpr uint8_t BLOCKS_PER_SECTOR = 4;
static constexpr uint8_t LAST_SECTOR       = 15;   // MIFARE Classic 1K
static constexpr uint8_t PROBE_SECTOR      = 1;

// Timings from Jensilein's side-mounted reader, 12. and 13.10.2026.
static constexpr uint16_t      WAKE_POLL_MS       = 300;
static constexpr int           WAKE_FIELD_CYCLES  = 2;
static constexpr uint16_t      WAKE_SETTLE_MS     = 30;    // after a field cycle
static constexpr uint16_t      FIND_POLL_MS       = 600;   // the first look for the card
static constexpr unsigned long WAIT_TOTAL_MS      = 20000; // for the spool to be put back
static constexpr uint16_t      WAIT_POLL_MS       = 150;
static constexpr uint16_t      WAIT_STEP_MS       = 20;
// Seen while the spool is still being put down, at the edge of the field, a
// card answers a poll and then refuses its own key (13.10.2026).
static constexpr unsigned long PUT_DOWN_SETTLE_MS = 700;
// Any tag not known to be Bambu's that refuses both keys, or whose sector
// breaks off mid read, is asked to be put back this often (26.10.2026).
static constexpr int           PUT_BACK_ASKS      = 2;
// Reads of the probe sector at most: the first, and one more after a wake for
// each that failed or showed data.
static constexpr int           PROBE_READ_ATTEMPTS = 3;
// "Holds data" is believed once this many reads say so (17.10.2026).
static constexpr int           PROBE_DATA_READS   = 2;
// A write that has once seen data in the sector writes only after this many
// blank reads in a row (17.10.2026: one blank read after a misread was all
// that stood between a foreign tag and a write).
static constexpr int           BLANK_READS_AFTER_DATA = 2;
// One write, every wait and every put-back included. Each wait alone may take
// WAIT_TOTAL_MS, and with two put-backs they would add up to over two
// minutes of "put the spool back".
static constexpr unsigned long WRITE_DEADLINE_MS  = 60000;
// The check after a write gets at least this long to see the tag again, even
// when the write itself used up the deadline: the blocks are on the tag by then.
static constexpr unsigned long VERIFY_WAIT_MIN_MS = 5000;
// Before a put-back is waited for, the tag has to leave the reader: gone for
// PUT_BACK_GONE_POLLS polls in a row, within PUT_BACK_LIFT_MS (see waitForLift).
static constexpr unsigned long PUT_BACK_LIFT_MS    = 8000;
static constexpr int           PUT_BACK_GONE_POLLS = 2;

// The tag a write was last verified on, until the scan has read it again.
static uint8_t s_reread_uid[4];
static bool    s_reread_armed = false;

// What the last probe found in sector 1 of a card that opened with the factory
// key and was not blank, for the question before it is overwritten.
static uint8_t s_held_uid[4];
static uint8_t s_held[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES];
static bool    s_held_valid = false;

static uint8_t firstBlock(uint8_t sector)   { return sector * BLOCKS_PER_SECTOR; }
static uint8_t trailerBlock(uint8_t sector) { return sector * BLOCKS_PER_SECTOR + 3; }

bool mifareBlockIsBlank(const uint8_t b[MIFARE_BLOCK_BYTES]) {
  const uint8_t first = b[0];
  if (first != 0x00 && first != 0xFF && first != 0x20) return false;
  for (int i = 1; i < MIFARE_BLOCK_BYTES; i++) if (b[i] != first) return false;
  return true;
}

// The data blocks of a sector that is already open: 1 all blank, 0 data in
// them, -1 a read failed. A sticker on the edge of the field can hand back a
// block that is not what it holds (17.10.2026, 6D:7B:DB:4F: "holds data"
// once, blank half a minute later, never written in between), so callers
// only believe "data" once a second read after a fresh wake says the same.
static int readDataBlocks(uint8_t sector, uint8_t blk[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES]) {
  int r = 1;
  for (uint8_t b = 0; b < MIFARE_DATA_BLOCKS_MAX; b++) {
    if (!nfcReadMifareBlock(firstBlock(sector) + b, blk[b])) return -1;
    if (!mifareBlockIsBlank(blk[b])) r = 0;
  }
  return r;
}

static bool samePoll(const uint8_t uid[4], uint16_t timeout_ms) {
  uint8_t got[NFC_UID_MAX];
  uint8_t got_len = 0;
  return nfcReadPassiveTarget(got, &got_len, timeout_ms) &&
         got_len == 4 && memcmp(got, uid, 4) == 0;
}

int mifareWakeCard(const uint8_t uid[4], const char* uid_str, bool* reader_silent) {
  if (samePoll(uid, WAKE_POLL_MS)) return 1;
  // The reader may still hold the card as its target from the refused key and
  // not list it again; releasing costs one command and resets nothing else.
  const bool released = nfcInRelease();
  if (samePoll(uid, WAKE_POLL_MS)) return 2;
  for (int cycle = 1; cycle <= WAKE_FIELD_CYCLES; cycle++) {
    const uint8_t rf = nfcRfFieldCycle();
    if (!(rf & NFC_RF_CHIP_OK)) {   // do not pile more commands on it
      logSDf("NFC: %s field cycle %d left the reader SILENT (off=%s on=%s)",
             uid_str, cycle, (rf & NFC_RF_OFF_OK) ? "ok" : "fail",
             (rf & NFC_RF_ON_OK) ? "ok" : "fail");
      *reader_silent = true;
      return 0;
    }
    if (samePoll(uid, WAKE_POLL_MS)) return 2 + cycle;
    delay(WAKE_SETTLE_MS);
    if (samePoll(uid, WAKE_POLL_MS)) return 2 + cycle;
  }
  logSDf("NFC: %s no answer to a wake (release %s, %d field cycles)",
         uid_str, released ? "ok" : "failed", WAKE_FIELD_CYCLES);
  return 0;
}

// The whole seconds of a wait that are still to come, for the screen.
static int secondsLeft(unsigned long t0, unsigned long budget_ms) {
  const unsigned long used = millis() - t0;
  return used >= budget_ms ? 0 : (int)((budget_ms - used + 999) / 1000);
}

// Polls for the card the write is meant for. Plain polls only: a card that
// was just put down answers them, and nothing else touches it meanwhile.
static bool waitForCard(uint8_t uid[NFC_UID_MAX], uint8_t* uid_len,
                        const uint8_t* expect, MifareWaitFn wait, unsigned long budget_ms) {
  if (!wait || !budget_ms) return false;
  const unsigned long t0 = millis();
  wait(0, secondsLeft(t0, budget_ms));
  while (millis() - t0 < budget_ms) {
    *uid_len = 0;
    if (nfcReadPassiveTarget(uid, uid_len, WAIT_POLL_MS) && *uid_len == 4 &&
        (!expect || memcmp(uid, expect, 4) == 0)) {
      const unsigned long t1 = millis();
      while (millis() - t1 < PUT_DOWN_SETTLE_MS) {
        wait(1, secondsLeft(t0, budget_ms));
        delay(WAIT_STEP_MS);
      }
      *uid_len = 0;
      if (nfcReadPassiveTarget(uid, uid_len, WAKE_POLL_MS) && *uid_len == 4 &&
          (!expect || memcmp(uid, expect, 4) == 0)) {
        return true;
      }
    }
    wait(1, secondsLeft(t0, budget_ms));
    delay(WAIT_STEP_MS);
  }
  return false;
}

// One mifareWrite() as it runs: what the caller asked for, and once the card
// is found, the card and its key. The steps below share it instead of handing
// the same six values on from one to the next.
struct WriteRun {
  const MifareWriteJob& job;
  const uint8_t* expect;      // the UID the write is for, or nullptr for any
  MifareWaitFn wait;
  bool overwrite;
  unsigned long started;      // millis() when the write began, for WRITE_DEADLINE_MS
  uint8_t uid[4];
  char uid_str[24];
  uint8_t key[MIFARE_KEY_BYTES];
};

// What a wait may still take: one wait's worth at most, and never past the
// write's deadline. 0 once the deadline has passed.
static unsigned long waitBudget(const WriteRun& run) {
  const unsigned long used = millis() - run.started;
  if (used >= WRITE_DEADLINE_MS) {
    logSDf("%s write: %lu s for this write are up - not waiting any longer",
           run.job.label, WRITE_DEADLINE_MS / 1000UL);
    return 0;
  }
  const unsigned long left = WRITE_DEADLINE_MS - used;
  return left < WAIT_TOTAL_MS ? left : WAIT_TOTAL_MS;
}

// Waits for the card and reads the job's sector the moment it answers a poll -
// exactly what the main poll does, and the one moment a weakly placed tag
// reliably opens (13.10.2026: read 0.7 s after being put down, 6E:C6:DB:4F
// refused its key every time). A refused read leaves the card silent until it
// is put down again, so the loop just keeps polling for that.
static bool waitAndRead(const WriteRun& run, const uint8_t key_in[MIFARE_KEY_BYTES],
                        uint8_t blocks[4][MIFARE_BLOCK_BYTES], unsigned long budget_ms) {
  if (!run.wait || !budget_ms) return false;
  uint8_t uid[4], key[MIFARE_KEY_BYTES];
  memcpy(uid, run.uid, 4);
  memcpy(key, key_in, MIFARE_KEY_BYTES);
  const unsigned long t0 = millis();
  run.wait(0, secondsLeft(t0, budget_ms));
  while (millis() - t0 < budget_ms) {
    if (samePoll(uid, WAIT_POLL_MS) && nfcReadMifareSector(run.job.sector, key, uid, blocks, NFC_KEY_A)) {
      return true;
    }
    run.wait(1, secondsLeft(t0, budget_ms));
    delay(WAIT_STEP_MS);
  }
  return false;
}

// Finds the card to write to. A card that refused a key earlier may not
// answer a plain poll; release it, then reset the field once, then ask for
// the spool to be put back. An overwrite with a known UID skips the waiting
// here and reads the tag the moment it answers (*deferred).
static bool findCard(const WriteRun& run, uint8_t uid[NFC_UID_MAX], bool* deferred) {
  const MifareWriteJob& job = run.job;
  const uint8_t* expect = run.expect;
  MifareWaitFn wait = run.wait;
  uint8_t uid_len = 0;
  auto right_card = [&]() { return uid_len == 4 && (!expect || memcmp(uid, expect, 4) == 0); };
  bool found = nfcReadPassiveTarget(uid, &uid_len, FIND_POLL_MS) && right_card();
  if (!found) {
    nfcInRelease();
    found = nfcReadPassiveTarget(uid, &uid_len, WAKE_POLL_MS) && right_card();
  }
  if (!found && (nfcRfFieldCycle() & NFC_RF_CHIP_OK)) {
    delay(WAKE_SETTLE_MS);
    found = nfcReadPassiveTarget(uid, &uid_len, WAKE_POLL_MS) && right_card();
  }
  // Only a tag known to carry the format is read the moment it answers again
  // (overwriteFirst); any other tag - the tag view offers the write for a
  // blank tag and one on the factory key too - is waited for like a blank one.
  if (!found && run.overwrite && expect && wait && tagFamilyGet(expect) == job.family) {
    memcpy(uid, expect, 4);
    *deferred = true;
    return true;
  }
  if (!found) {
    logSDf("%s write: tag does not answer, waiting for the spool to be put back", job.label);
    found = waitForCard(uid, &uid_len, expect, wait, waitBudget(run));
  }
  if (!found) logSDf("%s write: no 4 byte tag on the reader", job.label);
  return found;
}

// The first block onto the card is where a write can be cut short, so the
// card's UID is marked unfinished right before it (services/tag_pending.h).
static bool writeDataBlocks(const WriteRun& run, int* refused_block) {
  const MifareWriteJob& job = run.job;
  tagPendingBegin(run.uid, 4);
  for (uint8_t b = 0; b < job.data_blocks; b++) {
    const uint8_t block = firstBlock(job.sector) + b;
    if (!nfcWriteMifareBlock(block, job.data[b])) {
      if (refused_block) *refused_block = block;
      return false;
    }
  }
  return true;
}

// What the tag is once the job is on it. Still on the factory key - an erase,
// or a job without a trailer - it is no tag of the format: blank when the
// blocks are empty, otherwise nothing the scale knows.
static TagFamily familyAfter(const MifareWriteJob& job, const uint8_t key[MIFARE_KEY_BYTES]) {
  if (memcmp(key, FACTORY_KEY, MIFARE_KEY_BYTES) != 0) return job.family;
  for (uint8_t b = 0; b < job.data_blocks; b++) {
    if (!mifareBlockIsBlank(job.data[b])) return TAG_FAMILY_UNKNOWN;
  }
  return TAG_FAMILY_BLANK;
}

// Reads the sector back with the final key and compares it with the job.
// A card that has gone quiet after the write is read once it has been put
// back.
static MifareWriteResult verifyWritten(const WriteRun& run, const uint8_t key[6], bool silent) {
  const MifareWriteJob& job = run.job;
  const char* uid_str = run.uid_str;
  MifareWaitFn wait = run.wait;
  uint8_t uid[4], k[MIFARE_KEY_BYTES];
  memcpy(uid, run.uid, 4);
  memcpy(k, key, MIFARE_KEY_BYTES);
  uint8_t back[4][MIFARE_BLOCK_BYTES];
  bool read = false;
  const int woke = silent ? 0 : mifareWakeCard(uid, uid_str, &silent);
  if (woke && !silent) read = nfcReadMifareSector(job.sector, k, uid, back, NFC_KEY_A);
  if (!read && wait) {
    silent = false;
    logSDf("%s write: %s written, waiting for it to answer for the check", job.label, uid_str);
    unsigned long budget = waitBudget(run);
    if (budget < VERIFY_WAIT_MIN_MS) budget = VERIFY_WAIT_MIN_MS;
    read = waitAndRead(run, k, back, budget);
  }
  bool verified = read;
  for (uint8_t b = 0; verified && b < job.data_blocks; b++) {
    verified = memcmp(back[b], job.data[b], MIFARE_BLOCK_BYTES) == 0;
  }
  if (!silent) mifareWakeCard(uid, uid_str, &silent);
  if (!verified) {
    logSDf("%s write: %s did not read back as written", job.label, uid_str);
    return MIFARE_WRITE_VERIFY_FAILED;
  }
  tagFamilySet(uid, familyAfter(job, k));
  memcpy(s_reread_uid, uid, 4);
  s_reread_armed = true;
  if (s_held_valid && memcmp(uid, s_held_uid, 4) == 0) s_held_valid = false;
  logSDf("%s write: %s written and verified", job.label, uid_str);
  return MIFARE_WRITE_OK;
}

bool mifareTakeReread(const uint8_t uid[4]) {
  if (!s_reread_armed || memcmp(uid, s_reread_uid, 4) != 0) return false;
  s_reread_armed = false;
  return true;
}

bool mifareFactoryHeld(const uint8_t uid[4],
                       uint8_t out[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES]) {
  if (!s_held_valid || memcmp(uid, s_held_uid, 4) != 0) return false;
  memcpy(out, s_held, sizeof(s_held));
  return true;
}

// New data blocks on a tag that already opens with the format's key and
// whose sector was just authenticated with key A (by the read). The keys stay
// as they are. Some writers lock the data blocks to key B, which is the same
// key on Creality's own tags, so that is tried once before giving up.
static MifareWriteResult overwriteData(const WriteRun& run, bool had_record) {
  const MifareWriteJob& job = run.job;
  const char* uid_str = run.uid_str;
  const uint8_t* key = run.key;
  uint8_t uid[4];
  memcpy(uid, run.uid, 4);
  bool silent = false;
  logSDf("%s write: %s opens with the format's key%s - overwriting as asked",
         job.label, uid_str, had_record ? " and holds a record" : "");
  bool wrote = writeDataBlocks(run, nullptr);
  if (!wrote) {
    logSDf("%s write: %s refused the write with key A, trying key B", job.label, uid_str);
    wrote = mifareWakeCard(uid, uid_str, &silent) && !silent &&
            nfcAuthMifareSector(job.sector, key, uid, NFC_KEY_B) &&
            writeDataBlocks(run, nullptr);
  }
  if (!wrote) {
    logSDf("%s write: %s refused the overwrite", job.label, uid_str);
    if (!silent) mifareWakeCard(uid, uid_str, &silent);
    return MIFARE_WRITE_FAILED;
  }
  return verifyWritten(run, key, silent);
}

// Step 0 of an overwrite: the format's own key first, on the card as freshly
// selected as it gets. Asked the factory key first, a weakly placed tag
// refused it and then its own key as well (13.10.2026), and the write gave up
// as 'not blank'. True when the outcome is decided, in *out.
static bool overwriteFirst(const WriteRun& run, bool deferred, bool* silent,
                           MifareWriteResult* out) {
  const MifareWriteJob& job = run.job;
  const char* uid_str = run.uid_str;
  MifareWaitFn wait = run.wait;
  uint8_t u[4], k[MIFARE_KEY_BYTES];
  memcpy(u, run.uid, 4);
  memcpy(k, run.key, MIFARE_KEY_BYTES);
  uint8_t blocks[4][MIFARE_BLOCK_BYTES];
  bool ok = !deferred && nfcReadMifareSector(job.sector, k, u, blocks, NFC_KEY_A);
  // Only a tag known to carry the format is waited for here: a blank one
  // never opens with this key, and 20 s of "put it back" would be for
  // nothing. A weak tag the scale never settled gets the key again later.
  const bool waited = !ok && wait && tagFamilyGet(u) == job.family;
  if (waited) {
    logSDf("%s write: %s does not answer with its key, waiting for the spool to be put back",
           job.label, uid_str);
    ok = waitAndRead(run, k, blocks, waitBudget(run));
  }
  if (ok) {
    *out = overwriteData(run, job.is_own_record(blocks));
    return true;
  }
  if (!mifareWakeCard(u, uid_str, silent) || *silent) {
    // A reader left silent by a field cycle gets no more commands piled on.
    // So does a spool that was just waited for in vain: a second wait of
    // 20 s would only ask the same again (14.11.2026, spool 23: two
    // countdowns, 42 s, before "no tag").
    if (*silent || waited) {
      if (waited) logSDf("%s write: %s was not put back - not written", job.label, uid_str);
      *out = MIFARE_WRITE_NO_TAG;
      return true;
    }
    // A tag that has gone quiet is asked to be put back rather than given
    // up on: from the tag view that is a weak tag more often than not.
    uint8_t got[NFC_UID_MAX];
    uint8_t got_len = 0;
    if (!waitForCard(got, &got_len, u, wait, waitBudget(run))) {
      *out = MIFARE_WRITE_NO_TAG;
      return true;
    }
  }
  return false;   // opens with neither (formatted elsewhere, say): factory key next
}

// The factory key refused: the tag may already carry the format. Left alone
// unless an overwrite was asked for. True when that decided the outcome, in
// *out; false when the tag refused the format's key as well.
static bool tryOwnKey(const WriteRun& run, bool* silent, MifareWriteResult* out) {
  const MifareWriteJob& job = run.job;
  const char* uid_str = run.uid_str;
  uint8_t uid[4], k[MIFARE_KEY_BYTES];
  memcpy(uid, run.uid, 4);
  memcpy(k, run.key, MIFARE_KEY_BYTES);
  uint8_t blocks[4][MIFARE_BLOCK_BYTES];
  const int woke = mifareWakeCard(uid, uid_str, silent);
  if (!woke || *silent || !nfcReadMifareSector(job.sector, k, uid, blocks, NFC_KEY_A)) {
    logSDf("%s write: %s refused the factory key and the format's key (woke=%d)",
           job.label, uid_str, woke);
    return false;
  }
  const bool rec = job.is_own_record(blocks);
  // Opens with the format's key but holds nothing it can read: a write cut
  // short half way, old and new blocks mixed, which neither the printer nor
  // the scale can use. A write asked for this very tag repairs it; a
  // readable record stays protected unless an overwrite was confirmed, or
  // this very write was started on the tag before and never read back.
  const bool asked_for_it = run.expect && memcmp(run.expect, uid, 4) == 0;
  const bool unfinished = tagPendingResumes(uid, 4);
  if (run.overwrite || unfinished || (!rec && asked_for_it)) {
    *out = overwriteData(run, rec);
    return true;
  }
  logSDf("%s write: %s already opens with the format's key%s - not written",
         job.label, uid_str, rec ? " and holds a record" : "");
  mifareWakeCard(uid, uid_str, silent);
  if (rec) tagFamilySet(uid, job.family);
  *out = MIFARE_WRITE_IS_FORMAT;
  return true;
}

// Before a put-back is waited for: the tag has to leave the reader first. A
// tag that still answers polls while it lies there would otherwise be "put
// back" at once, and both put-backs ran out in two seconds without the spool
// ever being lifted (10.11.2026, FC:69:DB:4F on spool 47: "not a blank tag"
// twice). Gone means PUT_BACK_GONE_POLLS polls in a row without it. A spool
// that is not lifted within PUT_BACK_LIFT_MS is asked again where it lies -
// as before, only later. A tag that a refused key has silenced is gone at the
// first poll and costs nothing here.
static void waitForLift(const WriteRun& run) {
  if (!run.wait) return;
  unsigned long budget = waitBudget(run);
  if (!budget) return;   // waitBudget() has said so; waitForCard() ends the write
  if (budget > PUT_BACK_LIFT_MS) budget = PUT_BACK_LIFT_MS;
  const unsigned long t0 = millis();
  run.wait(0, secondsLeft(t0, budget));
  int gone = 0;
  while (millis() - t0 < budget) {
    gone = samePoll(run.uid, WAIT_POLL_MS) ? 0 : gone + 1;
    if (gone >= PUT_BACK_GONE_POLLS) return;
    run.wait(1, secondsLeft(t0, budget));
    delay(WAIT_STEP_MS);
  }
  logSDf("%s write: %s was not lifted within %lu s - asking it again where it lies",
         run.job.label, run.uid_str, (budget + 999) / 1000UL);
}

// Asks for the spool to be put back and opens the job's sector with the
// factory key again. A spool that does not come back in time is gone: the
// write ends as "no tag", not as a foreign tag, so the caller offers it again.
enum PutBack { PUT_BACK_OPENED, PUT_BACK_REFUSED, PUT_BACK_GONE };
static PutBack putBackFactory(const WriteRun& run) {
  uint8_t got[NFC_UID_MAX];
  uint8_t got_len = 0;
  waitForLift(run);
  if (!waitForCard(got, &got_len, run.uid, run.wait, waitBudget(run))) {
    logSDf("%s write: %s was not put back - not written", run.job.label, run.uid_str);
    return PUT_BACK_GONE;
  }
  return nfcAuthMifareSector(run.job.sector, FACTORY_KEY, run.uid, NFC_KEY_A)
             ? PUT_BACK_OPENED : PUT_BACK_REFUSED;
}

// After a read with the factory key the card does not answer the next one:
// wake it and open the sector again.
static bool reopenFactory(const WriteRun& run, bool* silent) {
  return mifareWakeCard(run.uid, run.uid_str, silent) && !*silent &&
         nfcAuthMifareSector(run.job.sector, FACTORY_KEY, run.uid, NFC_KEY_A);
}

// Cosmetic second sector, see MifareWriteJob::pad_sector. Nothing depends on
// it, so a refusal is only logged.
static void padSector(const MifareWriteJob& job, const uint8_t uid_in[4], const char* uid_str) {
  uint8_t uid[4];
  memcpy(uid, uid_in, 4);
  if (!nfcAuthMifareSector(job.pad_sector, FACTORY_KEY, uid, NFC_KEY_A)) {
    logSDf("%s write: %s sector %u not on the factory key, left as it is",
           job.label, uid_str, (unsigned)job.pad_sector);
    return;
  }
  const uint8_t first = firstBlock(job.pad_sector);
  for (uint8_t b = 0; b < MIFARE_DATA_BLOCKS_MAX; b++) {
    uint8_t d[MIFARE_BLOCK_BYTES];
    if (!nfcReadMifareBlock(first + b, d) || !mifareBlockIsBlank(d)) return;
  }
  uint8_t pad[MIFARE_BLOCK_BYTES];
  memset(pad, job.pad_byte, sizeof(pad));
  for (uint8_t b = 0; b < MIFARE_DATA_BLOCKS_MAX; b++) {
    if (!nfcWriteMifareBlock(first + b, pad)) {
      logSDf("%s write: %s sector %u block %u refused (not needed)",
             job.label, uid_str, (unsigned)job.pad_sector, (unsigned)(first + b));
      return;
    }
  }
}

// What the job's sector of a tag just opened with the factory key says about
// writing: 1 it may be written, 0 it holds data the write must leave alone,
// -1 a read failed. May be written: every data block is empty, or already
// holds this job's own block - a write of the same job cut short before the
// trailer - or the tag holds this very write, started before and never
// finished, or the owner confirmed an overwrite after being shown what is
// there (tag_write_popup.cpp; the factory key protects nothing, so that
// answer is the only guard there is).
static int sectorWritable(const WriteRun& run, bool unfinished,
                          uint8_t old[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES]) {
  const MifareWriteJob& job = run.job;
  const int st = readDataBlocks(job.sector, old);
  if (st < 0) return -1;
  if (st == 1 || run.overwrite || unfinished) return 1;
  for (uint8_t b = 0; b < MIFARE_DATA_BLOCKS_MAX; b++) {
    if (!mifareBlockIsBlank(old[b]) && memcmp(old[b], job.data[b], MIFARE_BLOCK_BYTES) != 0) {
      logSDf("%s write: %s block %u holds data", job.label, run.uid_str,
             (unsigned)(firstBlock(job.sector) + b));
      return 0;
    }
  }
  return 1;
}

// sectorWritable() on a tag that may sit weakly: once data that may not be
// written has been seen in this write (*saw_data, kept across put-backs), it
// writes only when the next BLANK_READS_AFTER_DATA reads, each after a fresh
// wake, all say writable (see readDataBlocks).
static int readForWrite(const WriteRun& run, bool unfinished,
                        uint8_t old[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES], bool* silent,
                        bool* saw_data) {
  int st = sectorWritable(run, unfinished, old);
  if (st < 0) return -1;
  if (st == 1 && !*saw_data) return 1;
  *saw_data = true;
  for (int n = 0; n < BLANK_READS_AFTER_DATA; n++) {
    if (!reopenFactory(run, silent)) return -1;
    st = sectorWritable(run, unfinished, old);
    if (st != 1) return st;
  }
  logSDf("%s write: %s read as holding data before, writable on the next %d reads - writing",
         run.job.label, run.uid_str, BLANK_READS_AFTER_DATA);
  return 1;
}

// readForWrite until the sector says something: a read that broke off on a
// weakly placed tag asks for the spool to be put back, twice at most
// (26.10.2026). MIFARE_WRITE_OK when the sector may be written; otherwise
// the outcome.
static MifareWriteResult readSectorOrAsk(const WriteRun& run, bool* silent) {
  const MifareWriteJob& job = run.job;
  const bool unfinished = tagPendingResumes(run.uid, 4);
  uint8_t old[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES];
  bool saw_data = false;
  int st = readForWrite(run, unfinished, old, silent, &saw_data);
  const bool may_retry = run.wait && tagFamilyGet(run.uid) != TAG_FAMILY_BAMBU;
  for (int again = 0; st < 0 && may_retry && again < PUT_BACK_ASKS; again++) {
    logSDf("%s write: %s sector %u did not read - asking for it again (%d/%d)", job.label,
           run.uid_str, (unsigned)job.sector, again + 1, PUT_BACK_ASKS);
    *silent = false;
    const PutBack pb = putBackFactory(run);
    if (pb == PUT_BACK_GONE) return MIFARE_WRITE_NO_TAG;
    if (pb == PUT_BACK_OPENED) st = readForWrite(run, unfinished, old, silent, &saw_data);
  }
  if (st == 1) return MIFARE_WRITE_OK;
  logSDf("%s write: %s sector %u %s - not written", job.label, run.uid_str,
         (unsigned)job.sector, st == 0 ? "holds data" : "unreadable");
  mifareWakeCard(run.uid, run.uid_str, silent);
  return st == 0 ? MIFARE_WRITE_NOT_BLANK : MIFARE_WRITE_FAILED;
}

// The sector opened with the factory key and may be written (readSectorOrAsk).
// Then the data, then the trailer that locks it to the new key - last.
// Finally read back the way the printer will.
static MifareWriteResult writeBlank(const WriteRun& run) {
  const MifareWriteJob& job = run.job;
  const char* uid_str = run.uid_str;
  const uint8_t* key = run.key;
  uint8_t uid[4];
  memcpy(uid, run.uid, 4);
  bool silent = false;
  const MifareWriteResult r = readSectorOrAsk(run, &silent);
  if (r != MIFARE_WRITE_OK) return r;
  int refused = -1;
  if (!writeDataBlocks(run, &refused)) {
    logSDf("%s write: %s block %d refused", job.label, uid_str, refused);
    mifareWakeCard(uid, uid_str, &silent);
    return MIFARE_WRITE_FAILED;
  }
  if (job.set_trailer) {
    uint8_t trailer[MIFARE_BLOCK_BYTES];
    memcpy(trailer, key, MIFARE_KEY_BYTES);
    memcpy(trailer + MIFARE_KEY_BYTES, TRANSPORT_ACCESS, sizeof(TRANSPORT_ACCESS));
    memcpy(trailer + MIFARE_KEY_BYTES + sizeof(TRANSPORT_ACCESS), key, MIFARE_KEY_BYTES);
    if (!nfcWriteMifareBlock(trailerBlock(job.sector), trailer)) {
      logSDf("%s write: %s trailer refused", job.label, uid_str);
      mifareWakeCard(uid, uid_str, &silent);
      return MIFARE_WRITE_FAILED;
    }
  }
  if (job.pad_sector) padSector(job, uid, uid_str);
  return verifyWritten(run, job.set_trailer ? key : FACTORY_KEY, silent);
}

// Sector 0 holds the UID and the manufacturer block; a trailer outside the
// job's sector, or a pad sector on top of it, would be somebody else's data.
static bool jobUsable(const MifareWriteJob& job) {
  return job.label && job.own_key && job.is_own_record &&
         job.sector >= 1 && job.sector <= LAST_SECTOR &&
         job.data_blocks >= 1 && job.data_blocks <= MIFARE_DATA_BLOCKS_MAX &&
         (job.pad_sector == 0 || (job.pad_sector <= LAST_SECTOR && job.pad_sector != job.sector));
}

// Opens the job's sector with the factory key. A refused key halts the card,
// so every "no" is followed by a wake before the next question, and a card
// that refuses the factory key is asked the format's key as well (tryOwnKey,
// which may decide the outcome on its own, in *out).
//
// Refusing both says nothing for sure: a weakly placed sticker refuses even
// the right key now and then (13.10.2026), and on 26.10.2026 the erased
// original tag 15:C5:C5:11 of spool 38 was turned away as "not a blank
// tag" twice while it kept dropping out, although it opened with the
// factory key a minute before and took a CFtag write from a phone
// afterwards. Only the remembered family used to decide whether a refusal
// was worth a second try - and a tag that drops out is exactly one whose
// family the scale never settled. So any tag that is not known to be
// Bambu's is asked to be put back, twice at most, before it counts as
// somebody else's. Nothing is written until one of the two keys opens it,
// so a truly foreign tag only costs the user the two placements. A spool
// that is not put back ends the write as "no tag".
static bool openFactory(const WriteRun& run, bool* silent, MifareWriteResult* out) {
  const MifareWriteJob& job = run.job;
  if (nfcAuthMifareSector(job.sector, FACTORY_KEY, run.uid, NFC_KEY_A)) return true;
  const bool may_retry = run.wait && tagFamilyGet(run.uid) != TAG_FAMILY_BAMBU;
  for (int again = 0; ; again++) {
    if (tryOwnKey(run, silent, out)) return false;
    if (!may_retry || again >= PUT_BACK_ASKS) break;
    logSDf("%s write: %s a weak read? asking for it again (%d/%d)", job.label, run.uid_str,
           again + 1, PUT_BACK_ASKS);
    *silent = false;
    const PutBack pb = putBackFactory(run);
    if (pb == PUT_BACK_OPENED) return true;
    if (pb == PUT_BACK_GONE) { *out = MIFARE_WRITE_NO_TAG; return false; }
  }
  logSDf("%s write: %s refuses the factory key and the format's key - not a blank tag, not written",
         job.label, run.uid_str);
  if (!*silent) mifareWakeCard(run.uid, run.uid_str, silent);
  *out = MIFARE_WRITE_NOT_BLANK;
  return false;
}

MifareWriteResult mifareWrite(const MifareWriteJob& job, uint8_t uid_out[4],
                              const uint8_t* expect, MifareWaitFn wait, bool overwrite) {
  if (!jobUsable(job)) {
    logSD("MIFARE write: the job names a sector or blocks it may not touch - nothing written");
    return MIFARE_WRITE_FAILED;
  }
  WriteRun run{job, expect, wait, overwrite, millis(), {0}, "", {0}};
  uint8_t uid[NFC_UID_MAX] = {0};
  bool deferred = false;
  if (!findCard(run, uid, &deferred)) return MIFARE_WRITE_NO_TAG;
  memcpy(uid_out, uid, 4);
  memcpy(run.uid, uid, 4);
  const char* uid_str = run.uid_str;
  snprintf(run.uid_str, sizeof(run.uid_str), "%02X:%02X:%02X:%02X", uid[0], uid[1], uid[2], uid[3]);
  if (tagFamilyGet(uid) == TAG_FAMILY_BAMBU) {
    logSDf("%s write: %s is a Bambu tag - never written", job.label, uid_str);
    return MIFARE_WRITE_NOT_BLANK;
  }
  if (!job.own_key(uid, run.key)) {
    logSDf("%s write: %s no key for this UID", job.label, uid_str);
    return MIFARE_WRITE_FAILED;
  }
  bool silent = false;
  MifareWriteResult decided = MIFARE_WRITE_FAILED;
  // A card the probe has just opened with the factory key is asked that key
  // first. The format's key first would be refused, and a refusal knocks the
  // card off the reader until it is put down again (12.11.2026).
  uint8_t held[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES];
  const bool on_factory_key = mifareFactoryHeld(uid, held);
  if (overwrite && !on_factory_key && overwriteFirst(run, deferred, &silent, &decided)) {
    return decided;
  }
  // Nothing below writes a block unless the sector was opened in this very
  // write: with the factory key (openFactory, or putBackFactory after a
  // put-back) and read as writable (readSectorOrAsk), or with the format's
  // own key under the rules of tryOwnKey. Asking for a put-back never
  // counts as an answer: a tag that refuses both keys after the last one is
  // NOT_BLANK. A Bambu tag opens with neither key, and one already known as
  // Bambu's is turned away above before any key is tried.
  if (!openFactory(run, &silent, &decided)) return decided;
  return writeBlank(run);
}

MifareWriteResult mifareErase(const MifareWriteJob& format, uint8_t uid_out[4],
                              const uint8_t* expect, MifareWaitFn wait) {
  MifareWriteJob job = format;
  memset(job.data, 0, sizeof(job.data));
  job.set_trailer = false;
  job.pad_sector  = 0;
  logSDf("%s write: erasing sector %u, keys stay as they are", job.label, (unsigned)job.sector);
  return mifareWrite(job, uid_out, expect, wait, /*overwrite=*/true);
}

int mifareProbeFactory(const uint8_t uid[4], const char* uid_str) {
  bool silent = false;
  if (!nfcAuthMifareSector(PROBE_SECTOR, FACTORY_KEY, uid, NFC_KEY_A)) {
    const int w = mifareWakeCard(uid, uid_str, &silent);   // for whichever probe comes next
    logSDf("NFC: %s refuses the factory key (woke=%d)", uid_str, w);
    return MIFARE_FACTORY_REFUSED;
  }
  // Opening with the factory key is not yet "blank": the data blocks have to
  // be read too. A read that fails says nothing about them (13.10.2026: a
  // blank sticker, half off the reader after the refused Creality key,
  // opened and then read nothing, and went to the Bambu probe as "holds
  // data"). So a failed read gets another go after a wake, and data is only
  // believed on a second read (see readDataBlocks).
  int data = -1;   // -1 unread, 0 holds data, 1 blank
  int data_reads = 0;
  uint8_t got[MIFARE_DATA_BLOCKS_MAX][MIFARE_BLOCK_BYTES];
  for (int attempt = 0; attempt < PROBE_READ_ATTEMPTS; attempt++) {
    if (attempt > 0 && (!mifareWakeCard(uid, uid_str, &silent) || silent ||
                        !nfcAuthMifareSector(PROBE_SECTOR, FACTORY_KEY, uid, NFC_KEY_A))) break;
    data = readDataBlocks(PROBE_SECTOR, got);
    if (data == 1) {
      if (data_reads > 0) {
        logSDf("NFC: %s showed data on one read, blank on the next - weak read", uid_str);
      }
      break;
    }
    if (data == 0 && ++data_reads >= PROBE_DATA_READS) break;
  }
  // Data seen once and then no second read: not confirmed, so unread.
  if (data == 0 && data_reads < PROBE_DATA_READS) data = -1;
  // All three blocks of the read that confirmed the data: they are what the
  // question before an overwrite shows (mifareFactoryHeld()).
  if (memcmp(uid, s_held_uid, 4) == 0) s_held_valid = false;
  if (data == 0) {
    memcpy(s_held_uid, uid, 4);
    memcpy(s_held, got, sizeof(s_held));
    s_held_valid = true;
  }
  // After an authentication the card does not answer the next poll.
  const int back = silent ? 0 : mifareWakeCard(uid, uid_str, &silent);
  logSDf("NFC: %s opens with the factory key, %s (woke=%d)", uid_str,
         data == 1 ? "blank" : data == 0 ? "but sector 1 holds data"
                                         : "but sector 1 could not be read", back);
  // Unread is kept apart from "holds data" (26.10.2026): a blank sticker that
  // drops out mid read is still blank, and a caller that took it for data
  // forgot that the tag had been blank and never offered the write again.
  return data == 1 ? MIFARE_FACTORY_BLANK
         : data < 0 ? MIFARE_FACTORY_UNREAD : MIFARE_FACTORY_OPENS;
}
