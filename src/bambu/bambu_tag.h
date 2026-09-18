#pragma once

#include <stdint.h>

#include "../services/spool_color.h"

struct BambuTagData {
  uint8_t  uid[4];
  char     uid_str[24];        // 4-byte UID: "XX:XX:XX:XX" = 11+1, 7-byte UID: "XX:XX:XX:XX:XX:XX:XX" = 23+1
  uint8_t  keys[16][6];        // 16 derived keys
  uint8_t  blocks[64][16];     // all 64 blocks (16 sectors x 4 blocks)
  bool     block_ok[64];       // which blocks were successfully read

  char     tray_uuid[36];
  char     material_variant_id[9];
  char     material_id[9];
  // Block 4 holds up to 16 characters with no terminator when they are all
  // used: "PETG Translucent" is exactly 16 and lost its last letter at [16].
  char     material[17];
  // What the tag says about the colour, alpha included. Invalid when block 5
  // did not read.
  SpoolColor color;
  // The same as "#RRGGBB" for everything that compares colours, and empty
  // when the tag names no hue: a clear filament is 00000000, and holding
  // that against a spool as black kept every clear spool out of the link
  // list. Use color for anything that is drawn.
  char     color_hex[8];
  char     vendor[32];
  char     detailed_filament[64];
  int      temp_min;
  int      temp_max;
  float    spool_weight;
  char     production_date[12];
  char     short_uid[20];

  bool     spoolman_found;
  int      spoolman_id;
  float    spoolman_remaining; // g
  float    spoolman_total;     // g
  char     spoolman_last_dried[32];
};

void parseTagData(BambuTagData& tag);
