#pragma once

#include <stdint.h>

struct BambuTagData {
  uint8_t  uid[4];
  char     uid_str[24];        // 4-byte UID: "XX:XX:XX:XX" = 11+1, 7-byte UID: "XX:XX:XX:XX:XX:XX:XX" = 23+1
  uint8_t  keys[16][6];        // 16 derived keys
  uint8_t  blocks[64][16];     // all 64 blocks (16 sectors x 4 blocks)
  bool     block_ok[64];       // which blocks were successfully read

  char     tray_uuid[36];
  char     material_variant_id[9];
  char     material_id[9];
  char     material[16];
  char     color_hex[8];       // #RRGGBB
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
