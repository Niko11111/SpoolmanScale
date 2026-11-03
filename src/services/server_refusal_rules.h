#pragma once

#include <stdint.h>

// ============================================================
//  WHAT A SERVER'S "NO" MEANS
//
//  The server is there and answered, but will not do this for us. None of it
//  is a broken server, and "API Error" sent people looking for one.
// ============================================================

enum ServerRefusal : uint8_t {
  REFUSAL_NONE,
  REFUSAL_ACCESS,    // 401, 403: the key or password is wrong, missing or revoked
  REFUSAL_ACCOUNT,   // 402: the account behind the key is not active
  REFUSAL_TOO_MANY   // 429: rate limited
};

inline ServerRefusal serverRefusalOf(int code) {
  switch (code) {
    case 401:
    case 403: return REFUSAL_ACCESS;
    case 402: return REFUSAL_ACCOUNT;
    case 429: return REFUSAL_TOO_MANY;
    default:  return REFUSAL_NONE;
  }
}

// A 429 that names no wait, or names it as a date, which the scale may not be
// able to compare: it has no clock without a time server.
constexpr uint32_t RETRY_AFTER_DEFAULT_S = 60;
// A daily limit legitimately names hours. Past a day it is a broken value, and
// background requests should not stand still for longer on the word of one.
constexpr uint32_t RETRY_AFTER_MAX_S = 24UL * 60UL * 60UL;

// The value of a Retry-After header in seconds: digits only, at least one
// second, at most a day.
inline uint32_t retryAfterSeconds(const char* value) {
  if (!value || !*value) return RETRY_AFTER_DEFAULT_S;
  uint32_t seconds = 0;
  for (const char* c = value; *c; c++) {
    if (*c < '0' || *c > '9') return RETRY_AFTER_DEFAULT_S;
    seconds = seconds * 10 + (uint32_t)(*c - '0');
    if (seconds >= RETRY_AFTER_MAX_S) return RETRY_AFTER_MAX_S;
  }
  return seconds ? seconds : 1;
}
