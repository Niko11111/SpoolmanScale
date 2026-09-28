#include "bambu_tag.h"

#include <stdio.h>
#include <string.h>

// What a real Bambu tag holds lies well inside these; outside them the block
// did not read what it should, and the field stays 0.
#define BAMBU_NET_WEIGHT_MIN_G     50
#define BAMBU_NET_WEIGHT_MAX_G   5000
#define BAMBU_DIAMETER_MIN_MM    1.0f
#define BAMBU_DIAMETER_MAX_MM    3.5f
#define BAMBU_DRY_TEMP_MIN_C       30
#define BAMBU_DRY_TEMP_MAX_C      120
#define BAMBU_DRY_HOURS_MAX        48
#define BAMBU_LENGTH_MIN_M         10
#define BAMBU_LENGTH_MAX_M       2000
#define BAMBU_BLOCK16_COLOR_INFO    2
#define BAMBU_COLOR_COUNT_MAX       8

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

  // Base type: block 2, what the printer groups by ("PLA" for PLA Matte)
  if (tag.block_ok[2]) {
    copyPrintableField(tag.filament_type, sizeof(tag.filament_type), tag.blocks[2], 16);
  }

  // Material: block 4, the long form ("PETG HF"), all 16 bytes of it
  if (tag.block_ok[4]) {
    copyPrintableField(tag.material, sizeof(tag.material), tag.blocks[4], 16);
  }

  // Colour: block 5, bytes 0-3 = R,G,B,A (verified: FF D0 0B FF = #FFD00B).
  // The alpha byte is what tells a clear filament (00000000) from a black
  // one (000000FF), see services/spool_color.h.
  tag.color = SpoolColor{};
  tag.color_hex[0] = '\0';
  if (tag.block_ok[5]) {
    const uint8_t* c = tag.blocks[5];
    tag.color = spoolColorFromRgba(c[0], c[1], c[2], c[3]);
    if (spoolColorNamesHue(tag.color)) {
      snprintf(tag.color_hex, sizeof(tag.color_hex), "#%06X", (unsigned)tag.color.rgb);
    }
    // Bytes 4-5: net weight in g (E8 03 = 1000), bytes 8-11: diameter as a
    // float. Seen on real tags: 1000, 500 (support, PVA) and 250 g, 1.75 mm.
    const int net = c[4] | (c[5] << 8);
    if (net >= BAMBU_NET_WEIGHT_MIN_G && net <= BAMBU_NET_WEIGHT_MAX_G) tag.spool_weight = net;
    float dia = 0.0f;
    memcpy(&dia, c + 8, sizeof(dia));   // little endian, as the ESP32 is
    if (dia >= BAMBU_DIAMETER_MIN_MM && dia <= BAMBU_DIAMETER_MAX_MM) tag.diameter_mm = dia;
  }

  // Temperatures: block 6, bytes 8-9 = max, 10-11 = min (little endian, directly in C)
  if (tag.block_ok[6]) {
    int t1 = tag.blocks[6][8]  | (tag.blocks[6][9]  << 8);
    int t2 = tag.blocks[6][10] | (tag.blocks[6][11] << 8);
    if (t1 > 100 && t1 < 400) tag.temp_max = t1;
    if (t2 > 100 && t2 < 400) tag.temp_min = t2;
    // Bytes 0-1: drying temperature in C, 2-3: drying time in hours. Real
    // tags: PLA 55/8, PETG 65/8, ABS and ASA 80/8, PA 80/12, TPU 70/8.
    // Bytes 4-7 would be the bed, but real tags mostly leave them at 0.
    const int dt = tag.blocks[6][0] | (tag.blocks[6][1] << 8);
    const int dh = tag.blocks[6][2] | (tag.blocks[6][3] << 8);
    if (dt >= BAMBU_DRY_TEMP_MIN_C && dt <= BAMBU_DRY_TEMP_MAX_C &&
        dh >= 1 && dh <= BAMBU_DRY_HOURS_MAX) {
      tag.dry_temp_c = dt;
      tag.dry_hours  = dh;
    }
  }

  // Filament length: block 14, bytes 4-5, metres (PLA Basic 330, PVA 164)
  if (tag.block_ok[14]) {
    const int m = tag.blocks[14][4] | (tag.blocks[14][5] << 8);
    if (m >= BAMBU_LENGTH_MIN_M && m <= BAMBU_LENGTH_MAX_M) tag.length_m = m;
  }

  // Extra colour: block 16. Bytes 0-1 name the format, 02 00 is colour
  // info; 2-3 count the colours, 4-7 hold the second one as A, B, G, R.
  // Block 5 stays the first colour either way.
  if (tag.block_ok[16]) {
    const uint8_t* x = tag.blocks[16];
    const int fmt   = x[0] | (x[1] << 8);
    const int count = x[2] | (x[3] << 8);
    if (fmt == BAMBU_BLOCK16_COLOR_INFO && count >= 1 && count <= BAMBU_COLOR_COUNT_MAX) {
      tag.color_count = (uint8_t)count;
      if (count >= 2) tag.color2 = spoolColorFromRgba(x[7], x[6], x[5], x[4]);
    }
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
