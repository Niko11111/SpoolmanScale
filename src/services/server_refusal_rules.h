#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

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

constexpr uint16_t HTTP_DEFAULT_PORT  = 80;
constexpr uint16_t HTTPS_DEFAULT_PORT = 443;

// Whether a request went to the backend itself: the host AND the port of its
// base address. A refusal from a second service on the same machine
// (OpenSpoolman on :8001 beside Spoolman on :7912) is that service's own and
// must not mark the backend's key as rejected or pause it for a day.
inline bool sameServerAddress(const char* base_url, const char* host, uint16_t port) {
  if (!base_url || !host || !*host) return false;
  uint16_t base_port = HTTP_DEFAULT_PORT;
  const char* p = base_url;
  if (strncasecmp(p, "https://", 8) == 0) { p += 8; base_port = HTTPS_DEFAULT_PORT; }
  else if (strncasecmp(p, "http://", 7) == 0) p += 7;
  else return false;
  // The authority runs to the path; a user and password before '@' are not the host.
  const char* end = p;
  while (*end && *end != '/' && *end != '?' && *end != '#') end++;
  for (const char* at = p; at < end; at++)
    if (*at == '@') p = at + 1;
  const char* colon = nullptr;
  if (*p != '[') colon = (const char*)memchr(p, ':', (size_t)(end - p));
  const char* host_end = colon ? colon : end;
  const size_t host_len = (size_t)(host_end - p);
  if (host_len == 0 || strlen(host) != host_len || strncasecmp(p, host, host_len) != 0) return false;
  if (colon) base_port = (uint16_t)atoi(colon + 1);
  return base_port == port;
}
