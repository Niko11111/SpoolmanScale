#include "spoolscale_tag.h"

#include <Arduino.h>
#include <cstring>
#include <esp_system.h>

#include "nfc.h"

bool ntagReadPage(uint8_t page, uint8_t *buf) {
  return nfcReadNtagPage(page, buf);
}

bool ntagWritePage(uint8_t page, uint8_t *data) {
  return nfcWriteNtagPage(page, data);
}

TagType detectNtagType(uint8_t *uid, uint8_t uidLen) {
  if (uidLen == 4) return TAG_BAMBU;
  if (uidLen != 7) return TAG_UNKNOWN;
  uint8_t page4[4] = {0};
  if (!nfcReadNtagPage(4, page4)) return TAG_UNKNOWN;
  if (memcmp(page4, "SPSC", 4) == 0) return TAG_SPOOLSCALE;
  if (page4[0] == 0x00 && page4[1] == 0x00 && page4[2] == 0x00 && page4[3] == 0x00) return TAG_BLANK;
  if (page4[0] == 0xFF && page4[1] == 0xFF && page4[2] == 0xFF && page4[3] == 0xFF) return TAG_BLANK;
  return TAG_UNKNOWN;
}

bool readSpoolScaleTag(int *out_spool_id, char *out_uuid, size_t uuid_len) {
  uint8_t p10[4], p11[4], p12[4], p13[4], p14[4];
  if (!ntagReadPage(10, p10)) return false;
  if (!ntagReadPage(11, p11)) return false;
  if (!ntagReadPage(12, p12)) return false;
  if (!ntagReadPage(13, p13)) return false;
  if (!ntagReadPage(14, p14)) return false;

  *out_spool_id = p10[0] | (p10[1] << 8) | (p10[2] << 16) | (p10[3] << 24);

  snprintf(out_uuid, uuid_len, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
    p11[0], p11[1], p11[2], p11[3],
    p12[0], p12[1], p12[2], p12[3],
    p13[0], p13[1], p13[2], p13[3],
    p14[0], p14[1], p14[2], p14[3]);
  return true;
}

bool writeSpoolScaleTag(int spool_id, const char *uuid_hex) {
  uint8_t magic[4] = {'S','P','S','C'};
  if (!ntagWritePage(9, magic)) return false;

  uint8_t id_bytes[4];
  id_bytes[0] = spool_id & 0xFF;
  id_bytes[1] = (spool_id >> 8) & 0xFF;
  id_bytes[2] = (spool_id >> 16) & 0xFF;
  id_bytes[3] = (spool_id >> 24) & 0xFF;
  if (!ntagWritePage(10, id_bytes)) return false;

  uint8_t uuid_bytes[16];
  for (int i = 0; i < 16; i++) {
    unsigned int b;
    sscanf(uuid_hex + i * 2, "%02x", &b);
    uuid_bytes[i] = (uint8_t)b;
  }
  for (int p = 0; p < 4; p++) {
    if (!ntagWritePage(11 + p, uuid_bytes + p * 4)) return false;
  }
  return true;
}

void generateUUID(char *out, size_t len) {
  uint32_t a = esp_random();
  uint32_t b = esp_random();
  uint32_t c = esp_random();
  uint32_t d = esp_random();
  snprintf(out, len, "%08x%08x%08x%08x", a, b, c, d);
}
