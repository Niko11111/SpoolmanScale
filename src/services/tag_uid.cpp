#include "tag_uid.h"

#include <ctype.h>
#include <string.h>

// Longest identifier the scale ever compares is a Bambu tray uuid at 32
// characters. 48 leaves room without putting a large buffer on the stack of a
// function that runs once per spool during a full inventory scan.
#define TAG_UID_NORM_MAX  48

void tagUidNormalize(const char* in, char* out, size_t out_len) {
  if (!out || out_len == 0) return;
  size_t o = 0;
  for (const char* p = in; p && *p && o + 1 < out_len; p++) {
    if (isxdigit((unsigned char)*p)) out[o++] = (char)toupper((unsigned char)*p);
  }
  out[o] = '\0';
}

bool cardUidsContain(const char* card_uids_raw, const char* uid) {
  if (!card_uids_raw || !card_uids_raw[0] || !uid || !uid[0]) return false;

  char want[TAG_UID_NORM_MAX];
  tagUidNormalize(uid, want, sizeof(want));
  if (!want[0]) return false;

  const char* seg = card_uids_raw;
  while (*seg) {
    const char* end = strchr(seg, ',');
    if (!end) end = seg + strlen(seg);

    char have[TAG_UID_NORM_MAX];
    size_t o = 0;
    for (const char* p = seg; p < end && o + 1 < sizeof(have); p++) {
      if (isxdigit((unsigned char)*p)) have[o++] = (char)toupper((unsigned char)*p);
    }
    have[o] = '\0';

    if (have[0] && strcmp(have, want) == 0) return true;

    if (!*end) break;
    seg = end + 1;
  }
  return false;
}
