#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ============================================================
//  UNFINISHED TAG WRITE - the marker as it is stored
//
//  Pure logic for services/tag_pending.cpp: how the one marker is
//  spelled in NVS and when a tag on the reader is the one it names.
//  No NVS, no NFC, so test/test_tag_pending.py compiles it on the
//  host.
//
//  Spelled as text, "04A1B2C3D4E5F6/123/1": the UID in hex, the
//  spool and the TagFormat. One short string is one NVS entry plus
//  its data, the cheapest thing the store can hold.
// ============================================================

#define TAG_PENDING_UID_MAX  7     // NTAG; a MIFARE Classic UID is 4
// Hex UID, two separators, a spool id and a format, with room to spare.
#define TAG_PENDING_TEXT_MAX 40

struct TagPendingMark {
  uint8_t uid[TAG_PENDING_UID_MAX];
  uint8_t uid_len;   // 0 = no marker
  int     spool_id;
  uint8_t fmt;
};

// Only the two UID lengths the scale ever writes to.
static inline bool tagPendingUidLenOk(uint8_t len) { return len == 4 || len == 7; }

static inline bool tagPendingEncode(const TagPendingMark& m, char* out, size_t out_len) {
  if (!out || out_len < TAG_PENDING_TEXT_MAX) return false;
  if (!tagPendingUidLenOk(m.uid_len) || m.spool_id <= 0) return false;
  size_t n = 0;
  for (uint8_t i = 0; i < m.uid_len; i++) n += (size_t)snprintf(out + n, out_len - n, "%02X", m.uid[i]);
  snprintf(out + n, out_len - n, "/%d/%u", m.spool_id, (unsigned)m.fmt);
  return true;
}

static inline int tagPendingHexDigit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

// Anything that is not exactly what tagPendingEncode() writes is no marker:
// a value read back from flash is not trusted to be whole.
static inline bool tagPendingDecode(const char* s, TagPendingMark* out) {
  if (!s || !out) return false;
  TagPendingMark m{};
  const char* slash = strchr(s, '/');
  if (!slash) return false;
  const size_t hex = (size_t)(slash - s);
  if (hex % 2 != 0 || !tagPendingUidLenOk((uint8_t)(hex / 2))) return false;
  m.uid_len = (uint8_t)(hex / 2);
  for (uint8_t i = 0; i < m.uid_len; i++) {
    const int hi = tagPendingHexDigit(s[2 * i]);
    const int lo = tagPendingHexDigit(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    m.uid[i] = (uint8_t)(hi * 16 + lo);
  }
  int spool = 0;
  unsigned fmt = 0;
  char tail = 0;
  if (sscanf(slash, "/%d/%u%c", &spool, &fmt, &tail) != 2) return false;
  if (spool <= 0 || fmt > 0xFF) return false;
  m.spool_id = spool;
  m.fmt = (uint8_t)fmt;
  *out = m;
  return true;
}

static inline bool tagPendingMatches(const TagPendingMark& m, const uint8_t* uid, uint8_t uid_len) {
  return uid && m.uid_len != 0 && m.uid_len == uid_len && memcmp(m.uid, uid, uid_len) == 0;
}
