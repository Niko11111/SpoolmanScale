#include "bambu_scan.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <cstring>
#include <lvgl.h>

#include "bambu_kdf.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "lang.h"


static bool readSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16]) {
  return nfcReadMifareSector(sector, key, uid, blocks);
}

// How many sectors have to refuse authentication, from sector 0 on, before a
// scan gives up on the rest. See the comment at the probe below.
static constexpr int BAMBU_PROBE_SECTORS = 2;

// NOTE: Per-sector status display was removed here on purpose. Forcing
// lv_timer_handler() + lv_refr_now() between sector reads slows the scan
// down and the parallel display bus activity disturbs the PN532 RF
// communication, causing sector read failures (regression vs v0.5.12-beta).

int countBambuDataBlocksRead(const BambuTagData& tag) {
  int count = 0;
  for (int sector = 0; sector < 16; sector++) {
    for (int b = 0; b < 3; b++) {
      if (tag.block_ok[sector * 4 + b]) count++;
    }
  }
  return count;
}

// Scratch buffer for one scan attempt. scanTag() used to memset g_tag before
// reading, so a retry that went worse than the attempt before it left the
// display with nothing at all - observed in the field as a tag that showed
// complete data on the first pass and blank fields after retry 2. The result
// is now assembled here and only adopted into g_tag when it is at least as
// complete as what is already there. Static rather than a local to keep 1.5 KB
// off the loop task stack.
static BambuTagData scan_buf;

BambuScanResult scanTag(uint8_t *uid, uint8_t uid_len) {
  char uid_str[24];
  sprintf(uid_str, "%02X:%02X:%02X:%02X", uid[0], uid[1], uid[2], uid[3]);

  // A different tag replaces the old data unconditionally. Only a retry on the
  // same tag has to prove it is an improvement.
  const bool uid_changed = (strcmp(uid_str, g_tag.uid_str) != 0);
  const int  prev_blocks = uid_changed ? -1 : countBambuDataBlocksRead(g_tag);

  memset(&scan_buf, 0, sizeof(scan_buf));
  memcpy(scan_buf.uid, uid, 4);
  strncpy(scan_buf.uid_str, uid_str, sizeof(scan_buf.uid_str) - 1);
  scan_buf.uid_str[sizeof(scan_buf.uid_str)-1] = '\0';

  Serial.printf("\n=== Tag gefunden: %s ===\n", scan_buf.uid_str);
  // Not "Bambu tag found": a 4 byte UID says MIFARE Classic, and whether it
  // is a Bambu tag is what the sectors below decide.
  logSDf("NFC: 4-byte MIFARE tag found UID=%s", scan_buf.uid_str);

  Serial.println("Deriving keys...");
  if (!deriveKeys(uid, uid_len, scan_buf.keys)) {
    Serial.println("Key derivation failed!");
    return BAMBU_SCAN_NO_AUTH;   // g_tag is left untouched
  }

  for (int i = 0; i < 16; i++) {
    Serial.printf("Key %2d: %02X%02X%02X%02X%02X%02X\n", i,
      scan_buf.keys[i][0], scan_buf.keys[i][1], scan_buf.keys[i][2],
      scan_buf.keys[i][3], scan_buf.keys[i][4], scan_buf.keys[i][5]);
  }
  if (sd_verbose) {
    for (int i = 0; i < 16; i++) {
      logSDf("[verbose] KDF key %2d: %02X%02X%02X%02X%02X%02X", i,
        scan_buf.keys[i][0], scan_buf.keys[i][1], scan_buf.keys[i][2],
        scan_buf.keys[i][3], scan_buf.keys[i][4], scan_buf.keys[i][5]);
    }
  }

  Serial.println("Reading sectors...");
  int success_count = 0;
  char sector_summary[160] = "";
  BambuScanResult result = BAMBU_SCAN_OK;

  for (int sector = 0; sector < 16; sector++) {
    uint8_t sec_blocks[4][16];
    bool ok = readSector(sector, scan_buf.keys[sector], uid, sec_blocks);
    if (!ok) result = BAMBU_SCAN_PARTIAL;

    for (int b = 0; b < 3; b++) {
      int block_num = sector * 4 + b;
      if (ok) {
        memcpy(scan_buf.blocks[block_num], sec_blocks[b], 16);
        scan_buf.block_ok[block_num] = true;
        success_count++;
      }
    }
    Serial.printf("Sector %2d: %s\n", sector, ok ? "OK" : "FAIL");
    if (sd_verbose) {
      char tmp[12];
      snprintf(tmp, sizeof(tmp), "%d:%s ", sector, ok ? "OK" : "FAIL");
      strncat(sector_summary, tmp, sizeof(sector_summary) - strlen(sector_summary) - 1);
    }

    // The probe. A tag that is not Bambu refuses every sector, because the
    // derived keys are simply not its keys, and reading on would cost the
    // remaining sectors three attempts each for nothing: about five seconds
    // per scan, six scans with the retries, half a minute before the loop
    // gives up and looks the UID up in the backend. So the scan stops once
    // the first sectors have all refused.
    //
    // Two sectors rather than one, and the caller's retries untouched. A
    // Bambu tag with poor coupling refuses as well, and it must not be taken
    // for a plain card on the strength of a single sector. With two probe
    // sectors of three attempts each and the same five retries as before, a
    // Bambu tag gets every attempt it had, only cheaper; a plain card is
    // through in about ten seconds instead of thirty-five.
    if (sector == BAMBU_PROBE_SECTORS - 1 && success_count == 0) {
      Serial.printf("First %d sectors refused auth, scan aborted\n", BAMBU_PROBE_SECTORS);
      logSDf("NFC: first %d sectors refused auth, scan aborted", BAMBU_PROBE_SECTORS);
      result = BAMBU_SCAN_NO_AUTH;
      break;
    }
  }
  if (sd_verbose) logSDf("[verbose] sectors: %s", sector_summary);

  Serial.printf("%d/48 blocks read\n", success_count);
  logSDf("NFC: %d/48 blocks read", success_count);

  uint8_t block0[16];
  if (nfcReadMifareBlock(0, block0)) {
    memcpy(scan_buf.blocks[0], block0, 16);
    scan_buf.block_ok[0] = true;
  }

  parseTagData(scan_buf);

  Serial.printf("tray_uuid: %s\n", scan_buf.tray_uuid);
  Serial.printf("MaterialVariantID:   %s\n", scan_buf.material_variant_id);
  Serial.printf("MaterialID: %s\n", scan_buf.material_id);
  Serial.printf("Material:  %s\n", scan_buf.material);
  // RGBA, because the alpha byte is what separates clear from black. Also on
  // the card: a swatch that looks wrong is otherwise not traceable to the tag.
  char rgba[SPOOL_COLOR_HEX_MAX];
  spoolColorFormat(scan_buf.color, rgba, sizeof(rgba));
  Serial.printf("Color:     %s\n", rgba[0] ? rgba : "-");
  logSDf("NFC: material '%s', colour %s", scan_buf.material, rgba[0] ? rgba : "-");
  Serial.printf("Temp:      %d - %d C\n", scan_buf.temp_min, scan_buf.temp_max);
  Serial.printf("Vendor:    %s\n", scan_buf.vendor);
  Serial.printf("Date:      %s\n", scan_buf.production_date);

  // Adopt only on a new tag or on an improvement. A retry that read fewer
  // blocks than the attempt before it is discarded, so the display keeps the
  // best data seen for this tag instead of falling back to blanks.
  const int new_blocks = countBambuDataBlocksRead(scan_buf);
  if (uid_changed || new_blocks >= prev_blocks) {
    memcpy(&g_tag, &scan_buf, sizeof(g_tag));
    g_tag_ready = true;
  } else {
    Serial.printf("NFC: retry read worse (%d < %d blocks), keeping previous data\n",
      new_blocks, prev_blocks);
    logSDf("NFC: retry read worse (%d < %d blocks), previous data kept",
      new_blocks, prev_blocks);
  }

  return result;
}
