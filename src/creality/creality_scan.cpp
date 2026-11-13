#include "creality_scan.h"
#include "creality_tag.h"
#include "app/app_state.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "bambu/bambu_tag.h"
#include "services/spool_color.h"
#include "services/mifare_write.h"
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

// See crealityTagEmpty().
static uint8_t s_empty_uid[4];
static bool    s_empty_valid = false;

bool crealityTagEmpty(const uint8_t uid[4]) {
  return s_empty_valid && memcmp(uid, s_empty_uid, 4) == 0;
}

static void noteEmpty(const uint8_t uid[4], bool empty) {
  if (empty) {
    memcpy(s_empty_uid, uid, 4);
    s_empty_valid = true;
  } else if (crealityTagEmpty(uid)) {
    s_empty_valid = false;
  }
}

static bool sectorEmpty(const uint8_t blocks[4][16]) {
  for (int b = 0; b < 3; b++) if (!mifareBlockIsBlank(blocks[b])) return false;
  return true;
}

bool crealityLastRecord(const uint8_t uid[4], char out[41]) {
  if (!s_rec[0] || memcmp(uid, s_rec_uid, 4) != 0) return false;
  memcpy(out, s_rec, 41);
  return true;
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

  int woke_a = fresh ? 1 : mifareWakeCard(uid, uid_str, &reader_silent);
  bool ok_a = woke_a && nfcReadMifareSector(1, key, uid, blocks, NFC_KEY_A);
  int woke_b = 0;
  bool ok_b = false;
  if (!ok_a && !reader_silent) {
    woke_b = mifareWakeCard(uid, uid_str, &reader_silent);
    ok_b = woke_b && nfcReadMifareSector(1, key, uid, blocks, NFC_KEY_B);
  }
  if (!ok_a && !ok_b) {
    // woke: 1 = plain wake (or fresh), 2 = after release, 3/4 = after field
    // cycles, 0 = never.
    logSDf("NFC: %s not opened with the Creality key (key A: woke=%d, key B: woke=%d)",
           uid_str, woke_a, woke_b);
    if (!reader_silent) mifareWakeCard(uid, uid_str, &reader_silent);
    return CREALITY_SCAN_NO_AUTH;
  }
  logSDf("NFC: %s opened with the Creality key (%s, woke=%d%s)",
         uid_str, ok_a ? "key A" : "key B", ok_a ? woke_a : woke_b,
         (ok_a && fresh) ? ", first try" : "");

  const bool empty = sectorEmpty(blocks);
  noteEmpty(uid, empty);
  CrealityTag t;
  if (!crealityDecode(blocks, &t)) {
    logSDf("NFC: %s opens with the Creality key but %s", uid_str,
           empty ? "sector 1 is empty" : "holds no Creality record");
    // Woken like after a good read: an empty tag stays on the reader as one.
    bool silent = false;
    if (empty) mifareWakeCard(uid, uid_str, &silent);
    return empty ? CREALITY_SCAN_EMPTY : CREALITY_SCAN_GARBLED;
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
  int back = mifareWakeCard(uid, uid_str, &silent);
  if (back != 1) {
    logSDf("NFC: %s after the read: %s", uid_str,
           back ? "awake again after a reset" : "no answer to the next poll");
  }

  g_tag_ready = true;
  return CREALITY_SCAN_OK;
}

int crealityRecoverCard(const uint8_t uid[4], const char* uid_str) {
  bool silent = false;
  return mifareWakeCard(uid, uid_str, &silent);
}
