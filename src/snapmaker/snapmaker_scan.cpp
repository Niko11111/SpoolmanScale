#include "snapmaker_scan.h"
#include "snapmaker_kdf.h"
#include "app/app_state.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "bambu/bambu_tag.h"
#include "services/spool_color.h"
#include <Arduino.h>
#include <cstring>
#include <stdio.h>

SnapmakerScanResult scanSnapmakerTag(uint8_t *uid, uint8_t uid_len) {
  if (uid_len != 4) return SNAPMAKER_SCAN_NO_AUTH;
  
  uint8_t keyA[16][6];
  if (!deriveSnapmakerKeys(uid, keyA)) {
    return SNAPMAKER_SCAN_NO_AUTH;
  }
  
  char uid_str[24];
  snprintf(uid_str, sizeof(uid_str), "%02X:%02X:%02X:%02X", uid[0], uid[1], uid[2], uid[3]);

  uint8_t sec0_blocks[4][16];
  
  uint8_t dummy_uid[NFC_UID_MAX];
  uint8_t dummy_uid_len = 0;
  nfcReadPassiveTarget(dummy_uid, &dummy_uid_len, 150); // Wake from HALT

  // No key in any log: logs get passed around, and a line to the card holds
  // the loop for some 26 ms. A tag that is not Snapmaker's says nothing at all
  // here, the caller already logged that it is no Bambu tag either.
  if (!nfcReadMifareSector(0, keyA[0], uid, sec0_blocks, NFC_KEY_A)) {
    return SNAPMAKER_SCAN_NO_AUTH; // Fast fail
  }

  uint8_t sec1_blocks[4][16];
  bool sec1_ok = nfcReadMifareSector(1, keyA[1], uid, sec1_blocks, NFC_KEY_A);

  uint8_t sec2_blocks[4][16];
  bool sec2_ok = nfcReadMifareSector(2, keyA[2], uid, sec2_blocks, NFC_KEY_A);
  
  SnapmakerScanResult result = (sec1_ok && sec2_ok) ? SNAPMAKER_SCAN_OK : SNAPMAKER_SCAN_PARTIAL;
  
  // Parse
  memset(&g_tag, 0, sizeof(g_tag));
  memcpy(g_tag.uid, uid, 4);
  strncpy(g_tag.uid_str, uid_str, sizeof(g_tag.uid_str) - 1);
  g_tag.uid_str[sizeof(g_tag.uid_str)-1] = '\0';
  
  // Sector 0
  // Block 1 (bytes 16..31): VENDOR (ASCII, NUL-padded)
  strncpy(g_tag.vendor, (char*)sec0_blocks[1], sizeof(g_tag.vendor) - 1);
  g_tag.vendor[sizeof(g_tag.vendor)-1] = '\0';
  
  // Sector 1
  if (sec1_ok) {
    // Block 0
    uint16_t main_type = sec1_blocks[0][2] | (sec1_blocks[0][3] << 8);
    uint16_t sub_type = sec1_blocks[0][4] | (sec1_blocks[0][5] << 8);
    
    const char* mt_str = "Unknown";
    switch(main_type) {
      case 1: mt_str = "PLA"; break;
      case 2: mt_str = "PETG"; break;
      case 3: mt_str = "ABS"; break;
      case 4: mt_str = "TPU"; break;
      case 5: mt_str = "PVA"; break;
      case 6: mt_str = "ASA"; break;
      case 9: mt_str = "PA"; break;
      case 10: mt_str = "PA-CF"; break;
      case 11: mt_str = "PA-GF"; break;
      case 12: mt_str = "PC"; break;
      case 20: mt_str = "PLA-CF"; break;
      case 22: mt_str = "PEBA"; break;
      case 23: mt_str = "TPE"; break;
    }
    
    const char* st_str = "";
    switch(sub_type) {
      case 1: st_str = "Basic"; break;
      case 2: st_str = "Matte"; break;
      case 3: st_str = "SnapSpeed"; break;
      case 4: st_str = "Silk"; break;
      case 5: st_str = "Support"; break;
      case 6: st_str = "HF"; break;
      case 7: st_str = "95A"; break;
      case 8: st_str = "95A HF"; break;
      case 9: st_str = "90A"; break;
      case 10: st_str = "85A"; break;
      case 11: st_str = "Wood"; break;
      case 12: st_str = "Translucent"; break;
      case 13: st_str = "Full Spectrum"; break;
    }
    
    if (strlen(st_str) > 0) {
      snprintf(g_tag.material, sizeof(g_tag.material), "%s %s", mt_str, st_str);
    } else {
      strncpy(g_tag.material, mt_str, sizeof(g_tag.material) - 1);
    }
    g_tag.material[sizeof(g_tag.material)-1] = '\0';
    
    // Block 1
    snprintf(g_tag.color_hex, sizeof(g_tag.color_hex), "#%02X%02X%02X",
             sec1_blocks[1][0], sec1_blocks[1][1], sec1_blocks[1][2]);
    // The swatch is drawn from g_tag.color, not from the hex string. Opaque:
    // what the fourth byte of this block means is not established.
    g_tag.color = spoolColorFromRgba(sec1_blocks[1][0], sec1_blocks[1][1],
                                     sec1_blocks[1][2], 0xFF);
  }
  
  if (sec2_ok) {
    // Block 0
    g_tag.spool_weight = sec2_blocks[0][2] | (sec2_blocks[0][3] << 8);
    
    // Block 1
    g_tag.temp_max = sec2_blocks[1][4] | (sec2_blocks[1][5] << 8);
    g_tag.temp_min = sec2_blocks[1][6] | (sec2_blocks[1][7] << 8);
    
    // Block 2
    memcpy(g_tag.production_date, sec2_blocks[2], 8);
    g_tag.production_date[8] = '\0';
  }
  
  strncpy(g_tag.tray_uuid, uid_str, sizeof(g_tag.tray_uuid) - 1);
  g_tag.tray_uuid[sizeof(g_tag.tray_uuid)-1] = '\0';

  // A sector that authenticates with a key derived from Snapmaker's salt is
  // Snapmaker's, whatever the vendor block says.
  if (!g_tag.vendor[0]) snprintf(g_tag.vendor, sizeof(g_tag.vendor), "Snapmaker");

  logSDf("NFC: Snapmaker tag %s, %s, colour %s%s", uid_str,
         g_tag.material[0] ? g_tag.material : "-",
         g_tag.color_hex[0] ? g_tag.color_hex : "-",
         result == SNAPMAKER_SCAN_OK ? "" : " (partial read)");

  g_tag_ready = true;
  return result;
}
