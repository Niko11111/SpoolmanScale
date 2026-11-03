#pragma once

#include <stdint.h>

// ============================================================
//  WHOSE REQUESTS THESE ARE: ONE NUMBER
//
//  What goes out with a request decides whose spools the server answers
//  with. On a service with accounts every account has the same address, so a
//  new key is a different inventory behind an address that did not change.
//  This number tells the two apart without keeping a second copy of a secret:
//  it stays in a local variable for the length of one call and is never
//  logged. A collision would only skip a reset the user can force by
//  restarting, one chance in four billion.
//
//  0 when nothing goes out with a request. FNV-1a, 32 bits.
// ============================================================

inline uint32_t accessStampMix(uint32_t hash, uint8_t byte) {
  return (hash ^ byte) * 16777619UL;
}

inline uint32_t accessStampText(uint32_t hash, const char* text) {
  for (const char* p = text ? text : ""; *p; p++) hash = accessStampMix(hash, (uint8_t)*p);
  // The end of the text counts: "ab" + "c" is not "a" + "bc".
  return accessStampMix(hash, 0);
}

inline uint32_t accessStamp(bool sent, uint8_t mode, const char* user, const char* secret) {
  if (!sent) return 0;
  uint32_t hash = accessStampMix(2166136261UL, mode);
  hash = accessStampText(hash, user);
  return accessStampText(hash, secret);
}
