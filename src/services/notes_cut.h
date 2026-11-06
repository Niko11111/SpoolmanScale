#pragma once

#include <stddef.h>
#include <stdint.h>

// ============================================================
//  HOW MUCH OF A RELEASE'S NOTES THE FIRMWARE PAGE SHOWS
//
//  The notes come whole from GitHub (github_release.cpp reads the answer to
//  its end either way); this is the copy that goes on to the browser. The
//  notes of v0.8.3 have 28 460 bytes and the old 8000 showed less than a
//  third of them. Text this long lies in PSRAM (platformio.ini:
//  CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=4096), so the internal heap does not
//  pay for it.
//
//  A cut that falls inside a character of more than one byte leaves the
//  browser a broken sign at the end of the text; it goes back to where that
//  character begins.
// ============================================================

constexpr size_t GH_NOTES_MAX = 32000;

// How many of the len bytes of s to keep for at most max bytes, without ending
// inside a UTF-8 sequence. s[n] is the first byte left out; while it is a
// continuation byte (10xxxxxx) the character it belongs to began earlier and
// goes out whole.
inline size_t notesCutLength(const char* s, size_t len, size_t max) {
  if (len <= max) return len;
  size_t n = max;
  while (n > 0 && ((uint8_t)s[n] & 0xC0) == 0x80) n--;
  return n;
}
