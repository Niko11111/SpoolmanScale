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
// A tag found blank this session that refuses the factory key now and then.
static constexpr int           BLANK_ASK_AGAIN    = 2;
static constexpr int           PROBE_READ_TRIES   = 2;

static uint8_t firstBlock(uint8_t sector)   { return sector * BLOCKS_PER_SECTOR; }
static uint8_t trailerBlock(uint8_t sector) { return sector * BLOCKS_PER_SECTOR + 3; }

// A data block nobody has written: all zeros, all FF, or all spaces.
static bool blockIsBlank(const uint8_t b[MIFARE_BLOCK_BYTES]) {
  const uint8_t first = b[0];
  if (first != 0x00 && first != 0xFF && first != 0x20) return false;
  for (int i = 1; i < MIFARE_BLOCK_BYTES; i++) if (b[i] != first) return false;
  return true;
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

// Polls for the card the write is meant for. Plain polls only: a card that
// was just put down answers them, and nothing else touches it meanwhile.
static bool waitForCard(uint8_t uid[NFC_UID_MAX], uint8_t* uid_len,
                        const uint8_t* expect, MifareWaitFn wait) {
  if (!wait) return false;
  wait(0);
  const unsigned long t0 = millis();
  while (millis() - t0 < WAIT_TOTAL_MS) {
    *uid_len = 0;
    if (nfcReadPassiveTarget(uid, uid_len, WAIT_POLL_MS) && *uid_len == 4 &&
        (!expect || memcmp(uid, expect, 4) == 0)) {
      const unsigned long t1 = millis();
      while (millis() - t1 < PUT_DOWN_SETTLE_MS) { wait(1); delay(WAIT_STEP_MS); }
      *uid_len = 0;
      if (nfcReadPassiveTarget(uid, uid_len, WAKE_POLL_MS) && *uid_len == 4 &&
          (!expect || memcmp(uid, expect, 4) == 0)) {
        return true;
      }
    }
    wait(1);
    delay(WAIT_STEP_MS);
  }
  return false;
}

// Waits for the card and reads the sector the moment it answers a poll -
// exactly what the main poll does, and the one moment a weakly placed tag
// reliably opens (13.10.2026: read 0.7 s after being put down, 6E:C6:DB:4F
// refused its key every time). A refused read leaves the card silent until it
// is put down again, so the loop just keeps polling for that.
static bool waitAndRead(uint8_t sector, const uint8_t uid_in[4], const uint8_t key_in[6],
                        uint8_t blocks[4][MIFARE_BLOCK_BYTES], MifareWaitFn wait) {
  uint8_t uid[4], key[MIFARE_KEY_BYTES];
  memcpy(uid, uid_in, 4);
  memcpy(key, key_in, MIFARE_KEY_BYTES);
  wait(0);
  const unsigned long t0 = millis();
  while (millis() - t0 < WAIT_TOTAL_MS) {
    if (samePoll(uid, WAIT_POLL_MS) && nfcReadMifareSector(sector, key, uid, blocks, NFC_KEY_A)) {
      return true;
    }
    wait(1);
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
  uint8_t uid[4];
  char uid_str[24];
  uint8_t key[MIFARE_KEY_BYTES];
};

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
  if (!found && run.overwrite && expect && wait) {
    memcpy(uid, expect, 4);
    *deferred = true;
    return true;
  }
  if (!found) {
    logSDf("%s write: tag does not answer, waiting for the spool to be put back", job.label);
    found = waitForCard(uid, &uid_len, expect, wait);
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
    read = waitAndRead(job.sector, uid, k, back, wait);
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
  tagFamilySet(uid, job.family);
  logSDf("%s write: %s written and verified", job.label, uid_str);
  return MIFARE_WRITE_OK;
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
  if (!ok && wait) {
    logSDf("%s write: %s does not answer with its key, waiting for the spool to be put back",
           job.label, uid_str);
    ok = waitAndRead(job.sector, u, k, blocks, wait);
  }
  if (ok) {
    *out = overwriteData(run, job.is_own_record(blocks));
    return true;
  }
  if (!mifareWakeCard(u, uid_str, silent) || *silent) {
    *out = MIFARE_WRITE_NO_TAG;
    return true;
  }
  return false;   // opens with neither (formatted elsewhere, say): factory key next
}

// The factory key refused: the tag may already carry the format. Left alone
// unless an overwrite was asked for.
static MifareWriteResult ownKeyInstead(const WriteRun& run) {
  const MifareWriteJob& job = run.job;
  const char* uid_str = run.uid_str;
  uint8_t uid[4], k[MIFARE_KEY_BYTES];
  memcpy(uid, run.uid, 4);
  memcpy(k, run.key, MIFARE_KEY_BYTES);
  bool silent = false;
  uint8_t blocks[4][MIFARE_BLOCK_BYTES];
  const int woke = mifareWakeCard(uid, uid_str, &silent);
  if (woke && !silent && nfcReadMifareSector(job.sector, k, uid, blocks, NFC_KEY_A)) {
    const bool rec = job.is_own_record(blocks);
    // Opens with the format's key but holds nothing it can read: a write cut
    // short half way, old and new blocks mixed, which neither the printer nor
    // the scale can use. A write asked for this very tag repairs it; a
    // readable record stays protected unless an overwrite was confirmed, or
    // this very write was started on the tag before and never read back.
    const bool asked_for_it = run.expect && memcmp(run.expect, uid, 4) == 0;
    const bool unfinished = tagPendingResumes(uid, 4);
    if (run.overwrite || unfinished || (!rec && asked_for_it)) return overwriteData(run, rec);
    logSDf("%s write: %s already opens with the format's key%s - not written",
           job.label, uid_str, rec ? " and holds a record" : "");
    mifareWakeCard(uid, uid_str, &silent);
    if (rec) tagFamilySet(uid, job.family);
    return MIFARE_WRITE_IS_FORMAT;
  }
  logSDf("%s write: %s refuses the factory key - not a blank tag, not written",
         job.label, uid_str);
  if (!silent) mifareWakeCard(uid, uid_str, &silent);
  return MIFARE_WRITE_NOT_BLANK;
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
    if (!nfcReadMifareBlock(first + b, d) || !blockIsBlank(d)) return;
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

// The sector opened with the factory key: its data blocks must be empty, or
// already hold this job's own blocks - a write of the same job cut short
// before the trailer, which is why such a tag can simply be written again -
// or belong to this very write, started on the tag before and never finished.
// Then the data, then the trailer that locks it to the new key - last.
// Finally read back the way the printer will.
static MifareWriteResult writeBlank(const WriteRun& run) {
  const MifareWriteJob& job = run.job;
  const char* uid_str = run.uid_str;
  const uint8_t* key = run.key;
  uint8_t uid[4];
  memcpy(uid, run.uid, 4);
  bool silent = false;
  const uint8_t first = firstBlock(job.sector);
  const bool unfinished = tagPendingResumes(uid, 4);
  for (uint8_t b = 0; b < MIFARE_DATA_BLOCKS_MAX; b++) {
    uint8_t old[MIFARE_BLOCK_BYTES];
    const bool readable = nfcReadMifareBlock(first + b, old);
    const bool resumable = readable && (unfinished || blockIsBlank(old) ||
                                        memcmp(old, job.data[b], MIFARE_BLOCK_BYTES) == 0);
    if (!resumable) {
      logSDf("%s write: %s block %u %s - not written", job.label, uid_str,
             (unsigned)(first + b), readable ? "holds data" : "unreadable");
      mifareWakeCard(uid, uid_str, &silent);
      return readable ? MIFARE_WRITE_NOT_BLANK : MIFARE_WRITE_FAILED;
    }
  }
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

MifareWriteResult mifareWrite(const MifareWriteJob& job, uint8_t uid_out[4],
                              const uint8_t* expect, MifareWaitFn wait, bool overwrite) {
  if (!jobUsable(job)) {
    logSD("MIFARE write: the job names a sector or blocks it may not touch - nothing written");
    return MIFARE_WRITE_FAILED;
  }
  WriteRun run{job, expect, wait, overwrite, {0}, "", {0}};
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
  MifareWriteResult decided;
  if (overwrite && overwriteFirst(run, deferred, &silent, &decided)) {
    return decided;
  }
  bool opened = nfcAuthMifareSector(job.sector, FACTORY_KEY, uid, NFC_KEY_A);
  for (int again = 0; !opened && again < BLANK_ASK_AGAIN && wait &&
                      tagFamilyGet(uid) == TAG_FAMILY_BLANK; again++) {
    logSDf("%s write: %s refused the factory key, but was blank - asking for it again",
           job.label, uid_str);
    uint8_t got[NFC_UID_MAX];
    uint8_t got_len = 0;
    if (!waitForCard(got, &got_len, uid, wait)) break;
    opened = nfcAuthMifareSector(job.sector, FACTORY_KEY, uid, NFC_KEY_A);
  }
  if (!opened) return ownKeyInstead(run);
  return writeBlank(run);
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
  // data"). So a failed read gets one more go after a wake.
  int data = -1;   // -1 unread, 0 holds data, 1 blank
  for (int attempt = 0; attempt < PROBE_READ_TRIES && data < 0; attempt++) {
    if (attempt > 0 && (!mifareWakeCard(uid, uid_str, &silent) ||
                        !nfcAuthMifareSector(PROBE_SECTOR, FACTORY_KEY, uid, NFC_KEY_A))) break;
    int blank = 1;
    for (uint8_t b = 0; b < MIFARE_DATA_BLOCKS_MAX && blank == 1; b++) {
      uint8_t d[MIFARE_BLOCK_BYTES];
      if (!nfcReadMifareBlock(firstBlock(PROBE_SECTOR) + b, d)) blank = -1;
      else if (!blockIsBlank(d)) blank = 0;
    }
    data = blank;
  }
  // After an authentication the card does not answer the next poll.
  const int back = silent ? 0 : mifareWakeCard(uid, uid_str, &silent);
  logSDf("NFC: %s opens with the factory key, %s (woke=%d)", uid_str,
         data == 1 ? "blank" : data == 0 ? "but sector 1 holds data"
                                         : "but sector 1 could not be read", back);
  return data == 1 ? MIFARE_FACTORY_BLANK : MIFARE_FACTORY_OPENS;
}
