#include "bambu_tag.h"

#include <stdio.h>
#include <string.h>

static void copyPrintableField(char* dest, size_t dest_size, const uint8_t* src, size_t src_size) {
  if (!dest || dest_size == 0) return;
  memset(dest, 0, dest_size);
  size_t copy_len = src_size < dest_size - 1 ? src_size : dest_size - 1;
  memcpy(dest, src, copy_len);
  for (size_t i = 0; i < copy_len; i++) {
    if (dest[i] < 0x20 || dest[i] > 0x7E) {
      dest[i] = '\0';
      break;
    }
  }
}

void parseTagData(BambuTagData& tag) {
  // Block 1: bytes 0-7 = Material Variant ID, bytes 8-15 = Material ID.
  if (tag.block_ok[1]) {
    copyPrintableField(tag.material_variant_id, sizeof(tag.material_variant_id), tag.blocks[1], 8);
    copyPrintableField(tag.material_id, sizeof(tag.material_id), tag.blocks[1] + 8, 8);
  }

  // tray_uuid: block 9 (verified with Spoolman: 4E3C9740796645ACBC2732FDD6456A0D)
  if (tag.block_ok[9]) {
    char uuid[33] = "";
    for (int i = 0; i < 16; i++) {
      sprintf(uuid + i * 2, "%02X", tag.blocks[9][i]);
    }
    strncpy(tag.tray_uuid, uuid, 32);
    tag.tray_uuid[32] = '\0';
  }

  // Material: sector 2, block 8
  // Material: block 4 (long form, e.g. "PETG HF")
  if (tag.block_ok[4]) {
    copyPrintableField(tag.material, sizeof(tag.material), tag.blocks[4], 15);
  }

  // Color: block 5, bytes 0-2 = R,G,B (verified: FF D0 0B = #FFD00B)
  if (tag.block_ok[5]) {
    sprintf(tag.color_hex, "#%02X%02X%02X",
      tag.blocks[5][0], tag.blocks[5][1], tag.blocks[5][2]);
  }

  // Temperatures: block 6, bytes 8-9 = max, 10-11 = min (little endian, directly in C)
  if (tag.block_ok[6]) {
    int t1 = tag.blocks[6][8]  | (tag.blocks[6][9]  << 8);
    int t2 = tag.blocks[6][10] | (tag.blocks[6][11] << 8);
    if (t1 > 100 && t1 < 400) tag.temp_max = t1;
    if (t2 > 100 && t2 < 400) tag.temp_min = t2;
  }

  // Vendor: block 16 (ASCII, e.g. "Bambu Lab")
  if (tag.block_ok[16]) {
    memset(tag.vendor, 0, sizeof(tag.vendor));
    for (int i = 0; i < 16 && tag.blocks[16][i] != 0; i++) {
      char c = tag.blocks[16][i];
      if (c >= 0x20 && c <= 0x7E) {
        tag.vendor[i] = c;
      } else {
        tag.vendor[i] = 0;
        break;
      }
    }
  }

  // Production date: block 12 as ASCII "2025_03_07_04_18"
  if (tag.block_ok[12]) {
    char raw[17] = "";
    memcpy(raw, tag.blocks[12], 16);
    raw[16] = 0;
    // Format: YYYY_MM_DD_HH_MM -> DD.MM.YYYY
    if (raw[4] == '_' && raw[7] == '_') {
      snprintf(tag.production_date, sizeof(tag.production_date),
        "%.2s.%.2s.%.4s", raw + 8, raw + 5, raw);
    }
  }
}
