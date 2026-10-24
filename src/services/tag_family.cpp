#include "tag_family.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/prefs_store.h"

// NVS key, at most 15 characters. The value is "UUUUUUUUF" per entry: the
// UID as eight hex digits and the family letter, newest first.
#define KEY_TAG_FAMILY "tag_family"

static constexpr int MAX_ENTRIES = 48;

struct Entry {
  uint8_t uid[4];
  char    family;
};

static Entry entries[MAX_ENTRIES];
static int   count = 0;
static bool  loaded = false;

static int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static void load() {
  if (loaded) return;
  loaded = true;
  count = 0;
  String s = prefsGetString(KEY_TAG_FAMILY, "");
  const char* p = s.c_str();
  const size_t len = strlen(p);
  for (size_t off = 0; off + 9 <= len && count < MAX_ENTRIES; off += 9) {
    Entry e;
    bool ok = true;
    for (int i = 0; i < 4 && ok; i++) {
      int hi = hexNibble(p[off + i * 2]), lo = hexNibble(p[off + i * 2 + 1]);
      if (hi < 0 || lo < 0) ok = false;
      else e.uid[i] = (uint8_t)((hi << 4) | lo);
    }
    e.family = p[off + 8];
    if (!ok || (e.family != TAG_FAMILY_CREALITY && e.family != TAG_FAMILY_BAMBU)) continue;
    entries[count++] = e;
  }
}

// Only the families worth keeping across a restart go to flash.
static void save() {
  char buf[MAX_ENTRIES * 9 + 1];
  size_t n = 0;
  for (int i = 0; i < count; i++) {
    const Entry& e = entries[i];
    if (e.family != TAG_FAMILY_CREALITY && e.family != TAG_FAMILY_BAMBU) continue;
    n += snprintf(buf + n, sizeof(buf) - n, "%02X%02X%02X%02X%c",
                  e.uid[0], e.uid[1], e.uid[2], e.uid[3], e.family);
  }
  buf[n] = '\0';
  prefsPutString(KEY_TAG_FAMILY, buf);
}

static int find(const uint8_t uid[4]) {
  for (int i = 0; i < count; i++) {
    if (memcmp(entries[i].uid, uid, 4) == 0) return i;
  }
  return -1;
}

TagFamily tagFamilyGet(const uint8_t uid[4]) {
  load();
  int i = find(uid);
  return i < 0 ? TAG_FAMILY_UNKNOWN : (TagFamily)entries[i].family;
}

void tagFamilySet(const uint8_t uid[4], TagFamily family) {
  load();
  int i = find(uid);
  if (i >= 0 && entries[i].family == family) return;   // nothing changes
  if (i < 0 && family == TAG_FAMILY_UNKNOWN) return;

  const bool was_stored = i >= 0 && (entries[i].family == TAG_FAMILY_CREALITY ||
                                     entries[i].family == TAG_FAMILY_BAMBU);
  if (i >= 0) {   // take it out, it goes back in at the front
    memmove(&entries[i], &entries[i + 1], (count - i - 1) * sizeof(Entry));
    count--;
  }
  if (family != TAG_FAMILY_UNKNOWN) {
    if (count == MAX_ENTRIES) count--;   // the oldest falls off the end
    memmove(&entries[1], &entries[0], count * sizeof(Entry));
    memcpy(entries[0].uid, uid, 4);
    entries[0].family = family;
    count++;
  }

  const bool now_stored = family == TAG_FAMILY_CREALITY || family == TAG_FAMILY_BAMBU;
  logSDf("NFC: %02X:%02X:%02X:%02X remembered as %s", uid[0], uid[1], uid[2], uid[3],
         family == TAG_FAMILY_CREALITY ? "Creality" :
         family == TAG_FAMILY_BAMBU ? "Bambu" :
         family == TAG_FAMILY_NOT_CREALITY ? "not Creality (this session)" :
         family == TAG_FAMILY_BLANK ? "blank (this session)" : "unknown");
  if (was_stored || now_stored) save();
}
