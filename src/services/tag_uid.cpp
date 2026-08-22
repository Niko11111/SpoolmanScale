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

// Trims whitespace and Spoolman's outer JSON quotes off the whole value, so
// callers may hand in either the raw field or an already cleaned list.
static void unquotedSpan(const char* in, const char** begin, const char** end) {
  const char* b = in ? in : "";
  const char* e = b + strlen(b);
  while (b < e && (*b == ' ' || *b == '\t')) b++;
  while (e > b && (e[-1] == ' ' || e[-1] == '\t')) e--;
  if (e - b >= 2 && *b == '"' && e[-1] == '"') { b++; e--; }
  *begin = b;
  *end   = e;
}

// Rebuilds the list into `out`, entry by entry and verbatim apart from
// surrounding whitespace. Empty entries are dropped, which is what turns a
// hand edited "A,,B" or a trailing comma back into something well formed.
//
// When `skip` is given, entries whose normalised form equals it are left out
// and *skipped_any is set. Returns false when the result does not fit, in
// which case `out` must not be used.
static bool rebuildList(const char* current, const char* skip,
                        char* out, size_t out_len, size_t* out_used,
                        bool* skipped_any) {
  const char *b, *e;
  unquotedSpan(current, &b, &e);
  if (skipped_any) *skipped_any = false;

  size_t o = 0;
  const char* seg = b;
  while (seg < e) {
    const char* stop = (const char*)memchr(seg, ',', (size_t)(e - seg));
    if (!stop) stop = e;

    const char* s = seg;
    const char* t = stop;
    while (s < t && (*s == ' ' || *s == '\t')) s++;
    while (t > s && (t[-1] == ' ' || t[-1] == '\t')) t--;

    if (t > s) {
      bool drop = false;
      if (skip && skip[0]) {
        char raw[TAG_UID_NORM_MAX];
        size_t n = (size_t)(t - s);
        if (n >= sizeof(raw)) n = sizeof(raw) - 1;
        memcpy(raw, s, n);
        raw[n] = '\0';
        char norm[TAG_UID_NORM_MAX];
        tagUidNormalize(raw, norm, sizeof(norm));
        drop = (norm[0] && strcmp(norm, skip) == 0);
      }
      if (drop) {
        if (skipped_any) *skipped_any = true;
      } else {
        size_t len = (size_t)(t - s);
        if (o + len + (o ? 1 : 0) + 1 > out_len) return false;
        if (o) out[o++] = ',';
        memcpy(out + o, s, len);
        o += len;
      }
    }
    seg = (stop < e) ? stop + 1 : e;
  }

  out[o] = '\0';
  if (out_used) *out_used = o;
  return true;
}

int cardUidsCount(const char* card_uids_raw) {
  const char *b, *e;
  unquotedSpan(card_uids_raw, &b, &e);

  int n = 0;
  const char* seg = b;
  while (seg < e) {
    const char* stop = (const char*)memchr(seg, ',', (size_t)(e - seg));
    if (!stop) stop = e;
    const char* s = seg;
    const char* t = stop;
    while (s < t && (*s == ' ' || *s == '\t')) s++;
    while (t > s && (t[-1] == ' ' || t[-1] == '\t')) t--;
    if (t > s) n++;
    seg = (stop < e) ? stop + 1 : e;
  }
  return n;
}

CardUidsResult cardUidsAppend(const char* current, const char* uid,
                              char* out, size_t out_len) {
  if (!out || out_len == 0) return CARD_UIDS_FULL;
  out[0] = '\0';

  char want[TAG_UID_NORM_MAX];
  tagUidNormalize(uid, want, sizeof(want));
  if (!want[0]) return CARD_UIDS_FULL;

  size_t used = 0;
  if (!rebuildList(current, nullptr, out, out_len, &used, nullptr)) {
    out[0] = '\0';
    return CARD_UIDS_FULL;
  }

  // Idempotent: linking the same tag twice must not grow the list. The caller
  // still gets the list back so it can carry on as if it had just written it.
  if (cardUidsContain(current, want)) return CARD_UIDS_ALREADY_PRESENT;

  if (used + strlen(want) + (used ? 1 : 0) + 1 > out_len) return CARD_UIDS_FULL;

  if (used) out[used++] = ',';
  strcpy(out + used, want);
  return CARD_UIDS_ADDED;
}

bool cardUidsRemove(const char* current, const char* uid,
                    char* out, size_t out_len) {
  if (!out || out_len == 0) return false;
  out[0] = '\0';

  char want[TAG_UID_NORM_MAX];
  tagUidNormalize(uid, want, sizeof(want));
  if (!want[0]) return false;

  bool removed = false;
  if (!rebuildList(current, want, out, out_len, nullptr, &removed)) {
    // Cannot happen in practice, the result is never longer than the input,
    // but a silently half written list is not something to risk.
    out[0] = '\0';
    return false;
  }
  return removed;
}
