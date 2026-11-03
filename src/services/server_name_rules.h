#pragma once

#include <stddef.h>

// What a server's own name is allowed to be before the scale shows it. The
// name comes from a stranger's /api/v1/info and ends up inside a format string
// (backendText() replaces a word in texts that are then given to snprintf), in
// a page and in a three letter badge. Pure logic: no Arduino, no state.

#define SERVER_NAME_MAX      31   // bytes, the integration spec's limit
#define SERVER_BADGE_LEN      3   // the header has room for three characters
#define SERVER_BADGE_DEFAULT "SRV"

// Letters, digits, blank and a few marks of plain ASCII. Everything else is
// refused rather than dropped: "%" and "<" must never arrive, and a non-ASCII
// letter may have no glyph in the panel's fonts, which draws a box.
inline bool serverNameCharOk(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
         c == ' ' || c == '.' || c == '-' || c == '_' || c == '+' || c == '(' || c == ')';
}

// Copies the name without blanks around it and cut to SERVER_NAME_MAX. False,
// with out empty, for an empty name or one with a character that is not
// allowed: the caller then keeps its generic wording.
inline bool serverNameClean(const char* in, char* out, size_t n) {
  if (!out || n == 0) return false;
  out[0] = '\0';
  if (!in) return false;
  while (*in == ' ') in++;
  size_t len = 0;
  for (const char* p = in; *p; p++) {
    if (!serverNameCharOk(*p)) return false;
    len++;
  }
  size_t room = n - 1 < SERVER_NAME_MAX ? n - 1 : SERVER_NAME_MAX;
  if (len > room) len = room;
  while (len > 0 && in[len - 1] == ' ') len--;
  if (len == 0) return false;
  for (size_t i = 0; i < len; i++) out[i] = in[i];
  out[len] = '\0';
  return true;
}

// The first three letters or digits in upper case, "FilaCloud" to "FIL". A
// name with fewer of them gets SERVER_BADGE_DEFAULT. out holds at least
// SERVER_BADGE_LEN + 1 bytes.
inline void serverNameBadge(const char* name, char* out) {
  size_t j = 0;
  for (const char* p = name; p && *p && j < SERVER_BADGE_LEN; p++) {
    const char c = *p;
    const bool letter_or_digit = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                 (c >= '0' && c <= '9');
    if (letter_or_digit) out[j++] = (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
  }
  if (j < SERVER_BADGE_LEN) {
    for (j = 0; j < SERVER_BADGE_LEN; j++) out[j] = SERVER_BADGE_DEFAULT[j];
  }
  out[SERVER_BADGE_LEN] = '\0';
}
