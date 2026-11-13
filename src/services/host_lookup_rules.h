#pragma once

#include <stdint.h>

// ============================================================
//  WHEN A NAME THAT FAILED IS LOOKED UP AGAIN
//
//  lwIP gives up on a name nobody answers for only after its retries: 7 s
//  for a ".local" server that is switched off or in another network. Asked
//  from the loop on every request, that stood the scale still for 21 s a
//  minute (13.11.2026, three requests of 7 s each, the touch dead between).
//  So a name that failed is answered "no" at once, and only a background
//  check looks it up again, at most once per HOST_RECHECK_MS.
// ============================================================

constexpr uint32_t HOST_RECHECK_MS = 15000;

enum HostLookupStep : uint8_t {
  HOST_ASK,              // look the name up here and now
  HOST_REFUSE,           // failed before, a check runs or ran a moment ago
  HOST_REFUSE_RECHECK    // failed before, start a check in the background
};

// failed: the name failed and no lookup has found it since.
// since_check_ms: how long ago it was last looked up.
// checking: a background check is running (for this name or another).
inline HostLookupStep hostLookupStep(bool failed, uint32_t since_check_ms, bool checking) {
  if (!failed) return HOST_ASK;
  if (checking || since_check_ms < HOST_RECHECK_MS) return HOST_REFUSE;
  return HOST_REFUSE_RECHECK;
}
