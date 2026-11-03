#pragma once

#include <stdint.h>

// ============================================================
//  HOW LONG THE SCALE KEEPS ASKING ABOUT AN UNKNOWN TAG
//
//  A tag the server does not know may be linked from outside at any moment,
//  so the scale asks again while it lies on the reader. Left alone that never
//  ended: one or two requests every 4 s is 21,600 to 43,200 a day for a spool
//  somebody forgot on the scale, against any server, and enough to use up an
//  online service's daily allowance within a working day.
//
//  The first minutes stay fast: long enough to walk to a computer and create
//  the spool there, which is what the asking is for. Putting the spool down
//  again or touching the display starts the count over.
// ============================================================

constexpr uint32_t RECHECK_FAST_FOR_MS   = 5UL * 60UL * 1000UL;
constexpr uint32_t RECHECK_SLOW_GAP_MS   = 60UL * 1000UL;
constexpr uint32_t RECHECK_STOP_AFTER_MS = 2UL * 60UL * 60UL * 1000UL;

// A gap of zero: no more asking until the count starts over.
constexpr uint32_t RECHECK_STOPPED = 0;

enum RecheckPhase : uint8_t { RECHECK_PHASE_FAST, RECHECK_PHASE_SLOW, RECHECK_PHASE_OVER };

inline RecheckPhase recheckPhase(uint32_t quiet_ms) {
  if (quiet_ms >= RECHECK_STOP_AFTER_MS) return RECHECK_PHASE_OVER;
  return quiet_ms >= RECHECK_FAST_FOR_MS ? RECHECK_PHASE_SLOW : RECHECK_PHASE_FAST;
}

// The wait before the next question. `quiet_ms` is the time since the spool was
// put down or the display touched, `gap_ms` the wait the answers so far ask for
// (it grows while the server does not answer). The longer of the two applies.
inline uint32_t recheckPacedGap(uint32_t quiet_ms, uint32_t gap_ms) {
  switch (recheckPhase(quiet_ms)) {
    case RECHECK_PHASE_OVER: return RECHECK_STOPPED;
    case RECHECK_PHASE_SLOW: return gap_ms > RECHECK_SLOW_GAP_MS ? gap_ms : RECHECK_SLOW_GAP_MS;
    default:                 return gap_ms;
  }
}
