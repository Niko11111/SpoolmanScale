#include "creality_scan.h"
#include "creality_tag.h"
#include "app/app_state.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "bambu/bambu_tag.h"
#include "services/spool_color.h"
#include "services/tag_family.h"
#include <Arduino.h>
#include <cstring>
#include <stdio.h>

// The plain record of the Creality tag read (or written) last, for the
// comparison with Spoolman. One tag at a time is all the scale handles.
static uint8_t s_rec_uid[4];
static char    s_rec[41] = "";

void crealityRememberRecord(const uint8_t uid[4], const char rec40[40]) {
  memcpy(s_rec_uid, uid, 4);
  memcpy(s_rec, rec40, 40);
  s_rec[40] = '\0';
}

bool crealityLastRecord(const uint8_t uid[4], char out[41]) {
  if (!s_rec[0] || memcmp(uid, s_rec_uid, 4) != 0) return false;
  memcpy(out, s_rec, 41);
  return true;
}

// Gets a card back that a refused key has left unreachable. Returns how it
// answered: 1 = plain wake, 2 = after the reader released its target,
// 3..4 = after one or two RF field cycles, 0 = not at all.
static int wakeCard(const uint8_t uid[4], const char* uid_str, bool* reader_silent) {
  uint8_t got[NFC_UID_MAX];
  uint8_t got_len = 0;
  auto same_card = [&]() -> bool {
    got_len = 0;
    return nfcReadPassiveTarget(got, &got_len, 300) &&
           got_len == 4 && memcmp(got, uid, 4) == 0;
  };
  if (same_card()) return 1;
  // The reader may still hold the card as its target from the refused key and
  // not list it again; releasing costs one command and resets nothing else.
  bool released = nfcInRelease();
  if (same_card()) return 2;
  for (int cycle = 1; cycle <= 2; cycle++) {
    uint8_t rf = nfcRfFieldCycle();
    if (!(rf & NFC_RF_CHIP_OK)) {   // do not pile more commands on it
      logSDf("NFC: %s field cycle %d left the reader SILENT (off=%s on=%s)",
             uid_str, cycle, (rf & NFC_RF_OFF_OK) ? "ok" : "fail",
             (rf & NFC_RF_ON_OK) ? "ok" : "fail");
      *reader_silent = true;
      return 0;
    }
    if (same_card()) return 2 + cycle;
    delay(30);
    if (same_card()) return 2 + cycle;
  }
  logSDf("NFC: %s no answer to a wake (release %s, 2 field cycles)",
         uid_str, released ? "ok" : "failed");
  return 0;
}

CrealityScanResult scanCrealityTag(uint8_t *uid, uint8_t uid_len, bool fresh) {
  if (uid_len != 4) return CREALITY_SCAN_NO_AUTH;

  uint8_t key[6];
  if (!crealityDeriveSectorKey(uid, key)) return CREALITY_SCAN_NO_AUTH;

  char uid_str[24];
  snprintf(uid_str, sizeof(uid_str), "%02X:%02X:%02X:%02X", uid[0], uid[1], uid[2], uid[3]);

  // Called first now, on a card the poll has just selected and no key has
  // been tried on (12.10.2026): when the Bambu probe ran first, every refused
  // key left the card unreachable, and neither a wake, nor a field cycle of
  // 20 or 100 ms, brought it back reliably. On a fresh card, key A goes
  // straight through, the way the Bambu scan reads its sector 0.
  //
  // Creality's own spools and the current writers set key A and key B to the
  // same derived key. FilaStation up to v2.10 set only key B, so that is the
  // second try, after a wake. Whatever the outcome, a refused card is woken
  // once more before returning, so the Bambu probe that follows finds it.
  // As with Snapmaker, no key goes to the log.
  uint8_t blocks[4][16];
  bool reader_silent = false;

  int woke_a = fresh ? 1 : wakeCard(uid, uid_str, &reader_silent);
  bool ok_a = woke_a && nfcReadMifareSector(1, key, uid, blocks, NFC_KEY_A);
  int woke_b = 0;
  bool ok_b = false;
  if (!ok_a && !reader_silent) {
    woke_b = wakeCard(uid, uid_str, &reader_silent);
    ok_b = woke_b && nfcReadMifareSector(1, key, uid, blocks, NFC_KEY_B);
  }
  if (!ok_a && !ok_b) {
    // woke: 1 = plain wake (or fresh), 2 = after release, 3/4 = after field
    // cycles, 0 = never.
    logSDf("NFC: %s not opened with the Creality key (key A: woke=%d, key B: woke=%d)",
           uid_str, woke_a, woke_b);
    if (!reader_silent) wakeCard(uid, uid_str, &reader_silent);
    return CREALITY_SCAN_NO_AUTH;
  }
  logSDf("NFC: %s opened with the Creality key (%s, woke=%d%s)",
         uid_str, ok_a ? "key A" : "key B", ok_a ? woke_a : woke_b,
         (ok_a && fresh) ? ", first try" : "");

  CrealityTag t;
  if (!crealityDecode(blocks, &t)) {
    logSDf("NFC: %s opens with the Creality key but holds no Creality record", uid_str);
    return CREALITY_SCAN_GARBLED;
  }
  {
    uint8_t enc[48], plain[48];
    for (int b = 0; b < 3; b++) memcpy(enc + b * 16, blocks[b], 16);
    if (crealityDecrypt48(enc, plain)) crealityRememberRecord(uid, (const char*)plain);
  }

  memset(&g_tag, 0, sizeof(g_tag));
  memcpy(g_tag.uid, uid, 4);
  snprintf(g_tag.uid_str, sizeof(g_tag.uid_str), "%s", uid_str);
  snprintf(g_tag.decoder, sizeof(g_tag.decoder), "Creality");
  snprintf(g_tag.serial, sizeof(g_tag.serial), "%s", t.serial);

  // The base material ("PLA", "PETG-CF") is what the link list filters on by
  // its first three letters; the product name goes to detailed_filament.
  if (t.material[0]) {
    snprintf(g_tag.material, sizeof(g_tag.material), "%s", t.material);
  }
  if (t.name[0]) {
    snprintf(g_tag.detailed_filament, sizeof(g_tag.detailed_filament), "%s", t.name);
  } else {
    snprintf(g_tag.detailed_filament, sizeof(g_tag.detailed_filament), "Creality ID %s", t.filament_id);
  }
  snprintf(g_tag.vendor, sizeof(g_tag.vendor), "%s", t.brand[0] ? t.brand : "Creality");
  snprintf(g_tag.material_id, sizeof(g_tag.material_id), "%s", t.filament_id);

  if (t.has_color) {
    snprintf(g_tag.color_hex, sizeof(g_tag.color_hex), "#%02X%02X%02X", t.r, t.g, t.b);
    g_tag.color = spoolColorFromRgba(t.r, t.g, t.b, 0xFF);
  }
  // What v0.8.2 uses to create a spool from a tag. Creality's record has
  // no diameter, and CFS only takes 1.75 mm.
  if (t.material[0]) {
    snprintf(g_tag.filament_type, sizeof(g_tag.filament_type), "%s", t.material);
  }
  g_tag.length_m = t.length_m;
  g_tag.diameter_mm = 1.75f;
  g_tag.color_count = t.has_color ? 1 : 0;
  g_tag.temp_min = t.temp_min;
  g_tag.temp_max = t.temp_max;
  g_tag.spool_weight = t.weight_g;
  snprintf(g_tag.production_date, sizeof(g_tag.production_date), "%s", t.date);

  // Looked up by UID, like every non-Bambu MIFARE tag.
  snprintf(g_tag.tray_uuid, sizeof(g_tag.tray_uuid), "%s", uid_str);

  logSDf("NFC: Creality tag %s, %s %s, colour %s, %u g, serial %s", uid_str,
         g_tag.vendor, g_tag.detailed_filament,
         g_tag.color_hex[0] ? g_tag.color_hex : "-",
         (unsigned)t.weight_g, t.serial);

  // The card is still authenticated after the read and does not answer the
  // next poll, so the loop declared it removed 1.5 s after every read while
  // the spool lay on the pad (12.10.2026), and found it again moments later.
  // Bring it back to a freshly selected state, the one the polls see.
  bool silent = false;
  int back = wakeCard(uid, uid_str, &silent);
  if (back != 1) {
    logSDf("NFC: %s after the read: %s", uid_str,
           back ? "awake again after a reset" : "no answer to the next poll");
  }

  g_tag_ready = true;
  return CREALITY_SCAN_OK;
}

int crealityRecoverCard(const uint8_t uid[4], const char* uid_str) {
  bool silent = false;
  return wakeCard(uid, uid_str, &silent);
}

// ============================================================
//  WRITING A BLANK TAG
// ============================================================

static const uint8_t FACTORY_KEY[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// A data block nobody has written: all zeros, all FF, or all spaces.
static bool blockIsBlank(const uint8_t b[16]) {
  const uint8_t first = b[0];
  if (first != 0x00 && first != 0xFF && first != 0x20) return false;
  for (int i = 1; i < 16; i++) if (b[i] != first) return false;
  return true;
}

// Blocks 4-6 once sector 1 is open: 1 all blank, 0 data in them, -1 a read
// failed. A sticker on the edge of the field can hand back a block that is
// not what it holds (17.10.2026, 6D:7B:DB:4F: "holds data" once, blank half
// a minute later, never written in between), so "data" is only believed
// once a second read after a fresh wake says the same.
static int readSector1(uint8_t blk[3][16]) {
  int r = 1;
  for (int b = 0; b < 3; b++) {
    if (!nfcReadMifareBlock(4 + b, blk[b])) return -1;
    if (!blockIsBlank(blk[b])) r = 0;
  }
  return r;
}

// Polls for the card the write is meant for. Plain polls only: a card that
// was just put down answers them, and nothing else touches it meanwhile.
static bool waitForCard(uint8_t uid[NFC_UID_MAX], uint8_t* uid_len,
                        const uint8_t* expect, CrealityWaitFn wait) {
  if (!wait) return false;
  wait(0);
  const unsigned long t0 = millis();
  while (millis() - t0 < 20000) {
    *uid_len = 0;
    if (nfcReadPassiveTarget(uid, uid_len, 150) && *uid_len == 4 &&
        (!expect || memcmp(uid, expect, 4) == 0)) {
      // Seen while the spool is still being put down, at the edge of the
      // field, the card answers a poll and then refuses its own key
      // (13.10.2026). Let it settle and select it once more.
      const unsigned long t1 = millis();
      while (millis() - t1 < 700) { wait(1); delay(20); }
      *uid_len = 0;
      if (nfcReadPassiveTarget(uid, uid_len, 300) && *uid_len == 4 &&
          (!expect || memcmp(uid, expect, 4) == 0)) {
        return true;
      }
    }
    wait(1);
    delay(20);
  }
  return false;
}

// Waits up to 20 s for the card and reads sector 1 with the Creality key the
// moment it answers a poll - exactly what the main poll does, and the one
// moment a weakly placed tag reliably opens (13.10.2026: read 0.7 s after
// being put down, 6E:C6:DB:4F refused its key every time). A refused read
// leaves the card silent until it is put down again, so the loop just keeps
// polling for that.
static bool waitAndRead(const uint8_t* uid_in, uint8_t key[6], uint8_t blocks[4][16],
                        CrealityWaitFn wait) {
  uint8_t uid[4];
  memcpy(uid, uid_in, 4);
  wait(0);
  const unsigned long t0 = millis();
  while (millis() - t0 < 20000) {
    uint8_t got[NFC_UID_MAX];
    uint8_t got_len = 0;
    if (nfcReadPassiveTarget(got, &got_len, 150) && got_len == 4 && memcmp(got, uid, 4) == 0) {
      if (nfcReadMifareSector(1, key, uid, blocks, NFC_KEY_A)) return true;
    }
    wait(1);
    delay(20);
  }
  return false;
}

// Reads sector 1 back with the UID's key and compares it with what was
// written. A card that has gone quiet after the write is read once it has
// been put back.
static CrealityWriteResult verifyWritten(const uint8_t* uid, const char* uid_str,
                                         uint8_t key[6], const uint8_t cipher[48],
                                         const char rec40[40], CrealityWaitFn wait,
                                         bool silent) {
  uint8_t u[4];
  memcpy(u, uid, 4);
  uint8_t back[4][16];
  bool read = false;
  int woke = silent ? 0 : wakeCard(u, uid_str, &silent);
  if (woke && !silent) read = nfcReadMifareSector(1, key, u, back, NFC_KEY_A);
  if (!read && wait) {
    silent = false;
    logSDf("CFS write: %s written, waiting for it to answer for the check", uid_str);
    read = waitAndRead(u, key, back, wait);
  }
  const bool verified = read &&
                        memcmp(back[0], cipher, 16) == 0 &&
                        memcmp(back[1], cipher + 16, 16) == 0 &&
                        memcmp(back[2], cipher + 32, 16) == 0;
  if (!silent) wakeCard(u, uid_str, &silent);
  if (!verified) {
    logSDf("CFS write: %s did not read back as written", uid_str);
    return CREALITY_WRITE_VERIFY_FAILED;
  }
  tagFamilySet(u, TAG_FAMILY_CREALITY);
  // What the next comparison with Spoolman sees for this tag.
  crealityRememberRecord(u, rec40);
  logSDf("CFS write: %s written and verified (%.40s)", uid_str, rec40);
  return CREALITY_WRITE_OK;
}

// Writes blocks 4..6 of a tag that already opens with the Creality key and
// whose sector 1 was just authenticated with key A (by the read). The keys
// stay as they are. Some writers lock the data blocks to key B, which is the
// same key on Creality's own tags, so that is tried once before giving up.
static CrealityWriteResult overwriteRecord(const uint8_t* uid_in, const char* uid_str,
                                           uint8_t key[6], const uint8_t cipher[48],
                                           const char rec40[40], CrealityWaitFn wait,
                                           bool had_record) {
  uint8_t uid[4];
  memcpy(uid, uid_in, 4);
  bool silent = false;
  logSDf("CFS write: %s opens with the Creality key%s - overwriting as asked",
         uid_str, had_record ? " and holds a record" : "");
  bool wrote = true;
  for (int b = 0; b < 3 && wrote; b++) wrote = nfcWriteMifareBlock(4 + b, cipher + b * 16);
  if (!wrote) {
    logSDf("CFS write: %s refused the write with key A, trying key B", uid_str);
    wrote = wakeCard(uid, uid_str, &silent) && !silent &&
            nfcAuthMifareSector(1, key, uid, NFC_KEY_B);
    for (int b = 0; b < 3 && wrote; b++) wrote = nfcWriteMifareBlock(4 + b, cipher + b * 16);
  }
  if (!wrote) {
    logSDf("CFS write: %s refused the overwrite", uid_str);
    if (!silent) wakeCard(uid, uid_str, &silent);
    return CREALITY_WRITE_FAILED;
  }
  return verifyWritten(uid, uid_str, key, cipher, rec40, wait, silent);
}

CrealityWriteResult crealityWriteTag(const char rec40[40], uint8_t uid_out[4],
                                     const uint8_t* expect, CrealityWaitFn wait,
                                     bool overwrite) {
  uint8_t uid[NFC_UID_MAX] = {0};
  uint8_t uid_len = 0;
  auto right_card = [&]() {
    return uid_len == 4 && (!expect || memcmp(uid, expect, 4) == 0);
  };
  bool found = nfcReadPassiveTarget(uid, &uid_len, 600) && right_card();
  // A card that refused a key earlier may not answer a plain poll; release
  // it, then reset the field once, then ask for the spool to be put back.
  if (!found) { nfcInRelease(); found = nfcReadPassiveTarget(uid, &uid_len, 300) && right_card(); }
  if (!found && (nfcRfFieldCycle() & NFC_RF_CHIP_OK)) {
    delay(30);
    found = nfcReadPassiveTarget(uid, &uid_len, 300) && right_card();
  }
  // An overwrite reads the tag the moment it answers again (below), the way
  // the main poll reads it; nothing more is asked of it here.
  bool deferred = false;
  if (!found && overwrite && expect && wait) {
    memcpy(uid, expect, 4);
    uid_len = 4;
    found = deferred = true;
  }
  if (!found) {
    logSD("CFS write: tag does not answer, waiting for the spool to be put back");
    found = waitForCard(uid, &uid_len, expect, wait);
  }
  if (!found) {
    logSD("CFS write: no 4 byte tag on the reader");
    return CREALITY_WRITE_NO_TAG;
  }
  memcpy(uid_out, uid, 4);
  char uid_str[24];
  snprintf(uid_str, sizeof(uid_str), "%02X:%02X:%02X:%02X", uid[0], uid[1], uid[2], uid[3]);

  uint8_t key[6];
  uint8_t cipher[48];
  if (!crealityDeriveSectorKey(uid, key) || !crealityEncryptRecord(rec40, cipher)) {
    logSDf("CFS write: %s AES failed", uid_str);
    return CREALITY_WRITE_FAILED;
  }

  bool silent = false;

  // 0. Overwriting a Creality tag: its own key first, on the card as freshly
  //    selected as it gets. Asked the factory key first, a weakly placed tag
  //    refused it and then its Creality key as well (13.10.2026), and the
  //    write gave up as 'not blank'. A refusal here gets the spool put back,
  //    twice at most; a tag that opens with neither (formatted by CFtag, say)
  //    goes on to the factory key below.
  if (overwrite) {
    uint8_t blocks[4][16];
    bool ok = !deferred && nfcReadMifareSector(1, key, uid, blocks, NFC_KEY_A);
    if (!ok && wait) {
      logSDf("CFS write: %s does not answer with the Creality key, waiting for the spool to be put back",
             uid_str);
      ok = waitAndRead(uid, key, blocks, wait);
    }
    if (ok) {
      CrealityTag t;
      return overwriteRecord(uid, uid_str, key, cipher, rec40, wait, crealityDecode(blocks, &t));
    }
    if (!wakeCard(uid, uid_str, &silent) || silent) return CREALITY_WRITE_NO_TAG;
  }

  // 1. Is sector 1 still on the factory key? A refused key halts the card,
  //    so every "no" is followed by a wake before the next question.
  //    A tag this session already found blank is not given up on after one
  //    refusal: a weakly placed sticker refuses even the right key now and
  //    then (13.10.2026). It is asked to be put back, twice at most.
  bool opened = nfcAuthMifareSector(1, FACTORY_KEY, uid, NFC_KEY_A);
  for (int again = 0; !opened && again < 2 && wait &&
                      tagFamilyGet(uid) == TAG_FAMILY_BLANK; again++) {
    logSDf("CFS write: %s refused the factory key, but was blank - asking for it again", uid_str);
    uint8_t got[NFC_UID_MAX];
    uint8_t got_len = 0;
    if (!waitForCard(got, &got_len, uid, wait)) break;
    opened = nfcAuthMifareSector(1, FACTORY_KEY, uid, NFC_KEY_A);
  }
  if (!opened) {
    int woke = wakeCard(uid, uid_str, &silent);
    uint8_t blocks[4][16];
    if (woke && !silent && nfcReadMifareSector(1, key, uid, blocks, NFC_KEY_A)) {
      CrealityTag t;
      const bool rec = crealityDecode(blocks, &t);
      if (!overwrite) {
        logSDf("CFS write: %s already opens with the Creality key%s - not written",
               uid_str, rec ? " and holds a record" : "");
        wakeCard(uid, uid_str, &silent);
        if (rec) tagFamilySet(uid, TAG_FAMILY_CREALITY);
        return CREALITY_WRITE_IS_CREALITY;
      }
      return overwriteRecord(uid, uid_str, key, cipher, rec40, wait, rec);
    }
    logSDf("CFS write: %s refuses the factory key - not a blank tag, not written", uid_str);
    if (!silent) wakeCard(uid, uid_str, &silent);
    return CREALITY_WRITE_NOT_BLANK;
  }

  uint8_t old[3][16];
  int st = readSector1(old);
  CrealityTag t;
  if (st == 0 && !crealityDecode(old, &t)) {
    // Data that is no CFS record: read it once more after a fresh wake
    // before refusing (see readSector1).
    if (wakeCard(uid, uid_str, &silent) && !silent &&
        nfcAuthMifareSector(1, FACTORY_KEY, uid, NFC_KEY_A)) {
      st = readSector1(old);
      if (st == 1) logSDf("CFS write: %s read as holding data, blank on the second read - writing", uid_str);
    } else {
      st = -1;
    }
  }
  if (st < 0) {
    logSDf("CFS write: %s sector 1 unreadable - not written", uid_str);
    wakeCard(uid, uid_str, &silent);
    return CREALITY_WRITE_FAILED;
  }
  if (st == 0) {
    // Only a CFS record still on the factory key may be written over: an
    // earlier write of ours that stopped before the trailer (see
    // crealityProbeFactory). Anything else stays untouched.
    if (!crealityDecode(old, &t)) {
      logSDf("CFS write: %s sector 1 holds data - not written", uid_str);
      wakeCard(uid, uid_str, &silent);
      return CREALITY_WRITE_NOT_BLANK;
    }
    logSDf("CFS write: %s holds an unlocked CFS record (earlier write cut short) - writing it again",
           uid_str);
  }

  // 2. Sector 1: the record, then the trailer that locks it to the new key.
  //    The trailer goes last, so a failure before it leaves a tag that is
  //    still on the factory key and can simply be written again.
  for (int b = 0; b < 3; b++) {
    if (!nfcWriteMifareBlock(4 + b, cipher + b * 16)) {
      logSDf("CFS write: %s block %d refused", uid_str, 4 + b);
      wakeCard(uid, uid_str, &silent);
      return CREALITY_WRITE_FAILED;
    }
  }
  uint8_t trailer[16];
  memcpy(trailer, key, 6);
  trailer[6] = 0xFF; trailer[7] = 0x07; trailer[8] = 0x80; trailer[9] = 0x69;
  memcpy(trailer + 10, key, 6);
  if (!nfcWriteMifareBlock(7, trailer)) {
    logSDf("CFS write: %s trailer refused", uid_str);
    wakeCard(uid, uid_str, &silent);
    return CREALITY_WRITE_FAILED;
  }

  // 3. Sector 2 holds spaces on Creality's own tags. Only on a blank one, and
  //    nothing depends on it: the printer reads sector 1.
  if (nfcAuthMifareSector(2, FACTORY_KEY, uid, NFC_KEY_A)) {
    uint8_t spaces[16];
    memset(spaces, ' ', 16);
    bool blank2 = true;
    for (int b = 0; b < 3 && blank2; b++) {
      uint8_t d[16];
      blank2 = nfcReadMifareBlock(8 + b, d) && blockIsBlank(d);
    }
    if (blank2) {
      for (int b = 0; b < 3; b++) {
        if (!nfcWriteMifareBlock(8 + b, spaces)) {
          logSDf("CFS write: %s sector 2 block %d refused (not needed)", uid_str, 8 + b);
          break;
        }
      }
    }
  } else {
    logSDf("CFS write: %s sector 2 not on the factory key, left as it is", uid_str);
  }

  // 4. Read it back the way the scale and the printer will.
  return verifyWritten(uid, uid_str, key, cipher, rec40, wait, silent);
}

int crealityProbeFactory(const uint8_t uid[4], const char* uid_str) {
  bool silent = false;
  if (!nfcAuthMifareSector(1, FACTORY_KEY, uid, NFC_KEY_A)) {
    int w = wakeCard(uid, uid_str, &silent);   // for whichever probe comes next
    logSDf("NFC: %s refuses the factory key (woke=%d)", uid_str, w);
    return CREALITY_FACTORY_REFUSED;
  }
  // Opening with the factory key is not yet "blank": the data blocks have to
  // be read too. A read that fails says nothing about them (13.10.2026: a
  // blank sticker, half off the reader after the refused Creality key,
  // opened and then read nothing, and went to the Bambu probe as "holds
  // data"). So a failed read gets one more go after a wake.
  // A CFS record on the factory key is a write that stopped before the
  // trailer took (17.10.2026, 00:DF:A7:2E on spool 28: the sticker dropped
  // out mid write and was then "holds data" for good, so the scale never
  // offered it again). Ours to finish: treated as blank. Other data is
  // only believed on the second read (see readSector1).
  int data = -1;   // -1 unread, 0 holds data, 1 blank
  bool half = false;
  int data_reads = 0;
  uint8_t blk[3][16];
  for (int attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) {
      if (!wakeCard(uid, uid_str, &silent) || silent ||
          !nfcAuthMifareSector(1, FACTORY_KEY, uid, NFC_KEY_A)) break;
    }
    data = readSector1(blk);
    if (data == 1) {
      if (data_reads > 0) logSDf("NFC: %s showed data on one read, blank on the next - weak read", uid_str);
      break;
    }
    if (data == 0) {
      CrealityTag t;
      half = crealityDecode(blk, &t);
      if (half || ++data_reads >= 2) break;
    }
  }
  // After an authentication the card does not answer the next poll.
  int back = silent ? 0 : wakeCard(uid, uid_str, &silent);
  logSDf("NFC: %s opens with the factory key, %s (woke=%d)", uid_str,
         data == 1 ? "blank"
         : half    ? "holds a CFS record that was never locked - treated as blank"
         : data == 0 ? "but sector 1 holds data"
                     : "but sector 1 could not be read", back);
  return (data == 1 || half) ? CREALITY_FACTORY_BLANK : CREALITY_FACTORY_OPENS;
}
