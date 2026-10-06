#include "last_dried.h"

#include <string.h>

#include "services/tag_field.h"

// Whether the time part after 'T' names a zone: a Z, or an offset such as
// "+02:00". A '-' before the T belongs to the date and does not count.
static bool namesZone(const char* t) {
  return strchr(t, 'Z') || strchr(t, '+') || strchr(t, '-');
}

void lastDriedUtc(const char* raw, char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  out[0] = '\0';
  if (!raw) return;

  size_t len = strlen(raw);
  if (len >= 2 && raw[0] == '"' && raw[len - 1] == '"') { raw++; len -= 2; }
  if (len == 0) return;
  if (len >= out_size) len = out_size - 1;
  memcpy(out, raw, len);
  out[len] = '\0';

  const char* t = strchr(out, 'T');
  if (!t || namesZone(t)) return;
  if (len + 1 < out_size) {
    out[len]     = 'Z';
    out[len + 1] = '\0';
  }
}

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
