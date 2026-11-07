#include "last_dried.h"

#include <string.h>

#include "services/tag_field.h"

void lastDriedNewest(JsonVariantConst extra, char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  char own[LAST_DRIED_ISO_MAX];
  char bambu[LAST_DRIED_ISO_MAX];
  lastDriedUtc(extra[LAST_DRIED_FIELD] | (const char*)nullptr, own, sizeof(own));
  lastDriedUtc(extra[BAMBU_LAST_DRIED_FIELD] | (const char*)nullptr, bambu, sizeof(bambu));

  const char* pick = (strcmp(bambu, own) > 0) ? bambu : own;
  strncpy(out, pick, out_size - 1);
  out[out_size - 1] = '\0';
}
