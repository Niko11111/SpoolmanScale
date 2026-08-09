#include "bambu_scan.h"

#include <Arduino.h>
#include <cstring>
#include <lvgl.h>

#include "bambu_kdf.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "lang.h"

extern BambuTagData g_tag;
extern bool g_tag_ready;
extern lv_obj_t *lbl_status;

static bool readSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16]) {
  return nfcReadMifareSector(sector, key, uid, blocks);
}

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

void scanTag(uint8_t *uid, uint8_t uid_len) {
  memset(&g_tag, 0, sizeof(g_tag));
  memcpy(g_tag.uid, uid, 4);
  sprintf(g_tag.uid_str, "%02X:%02X:%02X:%02X",
    uid[0], uid[1], uid[2], uid[3]);

  Serial.printf("\n=== Tag gefunden: %s ===\n", g_tag.uid_str);
  logSDf("NFC: Bambu tag found UID=%s", g_tag.uid_str);

  Serial.println("Deriving keys...");
  if (!deriveKeys(uid, uid_len, g_tag.keys)) {
    Serial.println("Key derivation failed!");
    return;
  }

  for (int i = 0; i < 16; i++) {
    Serial.printf("Key %2d: %02X%02X%02X%02X%02X%02X\n", i,
      g_tag.keys[i][0], g_tag.keys[i][1], g_tag.keys[i][2],
      g_tag.keys[i][3], g_tag.keys[i][4], g_tag.keys[i][5]);
  }
  if (sd_verbose) {
    for (int i = 0; i < 16; i++) {
      logSDf("[verbose] KDF key %2d: %02X%02X%02X%02X%02X%02X", i,
        g_tag.keys[i][0], g_tag.keys[i][1], g_tag.keys[i][2],
        g_tag.keys[i][3], g_tag.keys[i][4], g_tag.keys[i][5]);
    }
  }

  Serial.println("Reading sectors...");
  int success_count = 0;
  char sector_summary[160] = "";
  for (int sector = 0; sector < 16; sector++) {
    uint8_t sec_blocks[4][16];
    bool ok = readSector(sector, g_tag.keys[sector], uid, sec_blocks);
    for (int b = 0; b < 3; b++) {
      int block_num = sector * 4 + b;
      if (ok) {
        memcpy(g_tag.blocks[block_num], sec_blocks[b], 16);
        g_tag.block_ok[block_num] = true;
        success_count++;
      }
    }
    Serial.printf("Sector %2d: %s\n", sector, ok ? "OK" : "FAIL");
    if (sd_verbose) {
      char tmp[12];
      snprintf(tmp, sizeof(tmp), "%d:%s ", sector, ok ? "OK" : "FAIL");
      strncat(sector_summary, tmp, sizeof(sector_summary) - strlen(sector_summary) - 1);
    }
  }
  if (sd_verbose) logSDf("[verbose] sectors: %s", sector_summary);

  Serial.printf("%d/48 blocks read\n", success_count);
  logSDf("NFC: %d/48 blocks read", success_count);

  uint8_t block0[16];
  if (nfcReadMifareBlock(0, block0)) {
    memcpy(g_tag.blocks[0], block0, 16);
    g_tag.block_ok[0] = true;
  }

  parseTagData(g_tag);

  Serial.printf("tray_uuid: %s\n", g_tag.tray_uuid);
  Serial.printf("MaterialVariantID:   %s\n", g_tag.material_variant_id);
  Serial.printf("MaterialID: %s\n", g_tag.material_id);
  Serial.printf("Material:  %s\n", g_tag.material);
  Serial.printf("Color:     %s\n", g_tag.color_hex);
  Serial.printf("Temp:      %d - %d C\n", g_tag.temp_min, g_tag.temp_max);
  Serial.printf("Vendor:    %s\n", g_tag.vendor);
  Serial.printf("Date:      %s\n", g_tag.production_date);

  g_tag_ready = true;
}
