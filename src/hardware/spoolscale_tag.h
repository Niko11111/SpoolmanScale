#pragma once

#include <stddef.h>
#include <stdint.h>

enum TagType { TAG_BAMBU, TAG_SPOOLSCALE, TAG_BLANK, TAG_UNKNOWN };

bool ntagReadPage(uint8_t page, uint8_t *buf);
bool ntagWritePage(uint8_t page, uint8_t *data);
TagType detectNtagType(uint8_t *uid, uint8_t uidLen);
bool readSpoolScaleTag(int *out_spool_id, char *out_uuid, size_t uuid_len);
bool writeSpoolScaleTag(int spool_id, const char *uuid_hex);
void generateUUID(char *out, size_t len);
