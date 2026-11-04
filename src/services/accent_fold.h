#pragma once

#include <stddef.h>
#include <string.h>

// ============================================================
//  ACCENTS FOLDED ONTO THEIR BASE LETTERS
//
//  The label fonts above 24 px have no French supplement behind
//  them, and a 300 dpi head prints the large lines in those
//  sizes. A line they cannot spell loses its accents instead of
//  showing boxes: é becomes e, œ becomes oe, ’ becomes '. The
//  letters the large fonts do have, ä ö ü Ä Ö Ü ß, stay as they
//  are, and so does anything this table does not know.
// ============================================================

// U+00C0 to U+00FF in order; NULL keeps the letter as it is.
static const char* const ACCENT_FOLD_LATIN1[64] = {
  "A", "A", "A", "A", NULL, "A", "AE", "C", "E", "E", "E", "E", "I", "I", "I", "I",
  "D", "N", "O", "O", "O", "O", NULL, NULL, "O", "U", "U", "U", NULL, "Y", "Th", NULL,
  "a", "a", "a", "a", NULL, "a", "ae", "c", "e", "e", "e", "e", "i", "i", "i", "i",
  "d", "n", "o", "o", "o", "o", NULL, NULL, "o", "u", "u", "u", NULL, "y", "th", "y",
};

// What the supplement spells beyond Latin-1. No replacement is longer than
// the sequence it stands for, so a folded line never outgrows its original.
struct AccentFoldPair { const char* seq; const char* plain; };
static const AccentFoldPair ACCENT_FOLD_OTHER[] = {
  { "\xC2\xA0", " " },        // no-break space
  { "\xC2\xAB", "\"" },       // left guillemet
  { "\xC2\xBB", "\"" },       // right guillemet
  { "\xC5\x92", "OE" },       // OE ligature
  { "\xC5\x93", "oe" },       // oe ligature
  { "\xC5\xB8", "Y" },        // Y with diaeresis
  { "\xE2\x80\x99", "'" },    // right single quotation mark
  { "\xE2\x80\xA6", "..." },  // ellipsis
};

// The byte length of the UTF-8 sequence at p: 1 for ASCII and for anything
// that is not a complete sequence, so a broken byte is copied as it is.
static inline size_t accentFoldSeqLen(const unsigned char* p) {
  size_t len = 1;
  if (p[0] >= 0xF0) len = 4;
  else if (p[0] >= 0xE0) len = 3;
  else if (p[0] >= 0xC0) len = 2;
  for (size_t i = 1; i < len; i++)
    if ((p[i] & 0xC0) != 0x80) return 1;
  return len;
}

// The replacement for the sequence at p of `len` bytes, NULL to keep it.
static inline const char* accentFoldFor(const unsigned char* p, size_t len) {
  if (len == 2 && p[0] == 0xC3) return ACCENT_FOLD_LATIN1[p[1] - 0x80];
  for (const AccentFoldPair& f : ACCENT_FOLD_OTHER)
    if (strlen(f.seq) == len && memcmp(f.seq, p, len) == 0) return f.plain;
  return NULL;
}

// Takes the trademark, registered and copyright signs out of `s`, in place.
// No label font has them and they say nothing on a spool: "Panchroma™ Marble"
// printed a box after the first word.
static inline void labelDropMarks(char* s) {
  if (!s) return;
  static const char* const MARKS[] = { "\xE2\x84\xA2", "\xC2\xAE", "\xC2\xA9" };
  char* out = s;
  for (const char* p = s; *p; ) {
    bool mark = false;
    for (const char* m : MARKS) {
      const size_t len = strlen(m);
      if (strncmp(p, m, len) == 0) { p += len; mark = true; break; }
    }
    if (!mark) *out++ = *p++;
  }
  *out = '\0';
}

// Copies `in` into `out` (n bytes, always NUL-terminated) with the accents
// folded onto their base letters. True when at least one letter changed.
// A sequence the room does not hold ends the copy on a character boundary.
static inline bool accentFold(const char* in, char* out, size_t n) {
  if (!out || n == 0) return false;
  out[0] = '\0';
  if (!in) return false;
  bool changed = false;
  size_t o = 0;
  for (const unsigned char* p = (const unsigned char*)in; *p; ) {
    const size_t len = accentFoldSeqLen(p);
    const char* rep = accentFoldFor(p, len);
    const char* src = rep ? rep : (const char*)p;
    const size_t take = rep ? strlen(rep) : len;
    if (o + take >= n) break;
    memcpy(out + o, src, take);
    o += take;
    p += len;
    if (rep) changed = true;
  }
  out[o] = '\0';
  return changed;
}
