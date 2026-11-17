#pragma once

// The counting behind the read-rate measurement (services/nfc_measure.h).
// Pure: no reader, no clock, so it is tested on the host
// (test/test_nfc_measure_stats.py).

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct NfcMeasureStats {
  uint32_t cycles;          // polls made
  uint32_t uid_reads;       // polls that found a tag
  uint32_t block_reads;     // ... and then read one block from it
  uint32_t uid_changes;     // found a different UID than the read before
  uint32_t cycle_ms_total;
  uint32_t cycle_ms_max;
};

// One cycle. A block read without a UID cannot happen and is not counted.
inline void nfcMeasureCount(NfcMeasureStats& s, uint32_t cycle_ms, bool uid_ok,
                            bool block_ok, bool uid_changed) {
  s.cycles++;
  if (uid_ok) s.uid_reads++;
  if (uid_ok && block_ok) s.block_reads++;
  if (uid_ok && uid_changed) s.uid_changes++;
  s.cycle_ms_total += cycle_ms;
  if (cycle_ms > s.cycle_ms_max) s.cycle_ms_max = cycle_ms;
}

// Rounded per mille, 0 without cycles. Keeps 99.5 % apart from 100 % in the
// JSON without a float.
inline uint32_t nfcMeasurePerMille(uint32_t part, uint32_t whole) {
  if (whole == 0) return 0;
  return (uint32_t)(((uint64_t)part * 1000u + whole / 2) / whole);
}

inline uint32_t nfcMeasureAvgMs(const NfcMeasureStats& s) {
  if (s.cycles == 0) return 0;
  return (s.cycle_ms_total + s.cycles / 2) / s.cycles;
}

// The counters as JSON members without the braces, for the route's answer.
inline int nfcMeasureStatsJson(const NfcMeasureStats& s, char* out, size_t out_len) {
  return snprintf(out, out_len,
                  "\"cycles\":%lu,\"uid_reads\":%lu,\"block_reads\":%lu,"
                  "\"uid_permille\":%lu,\"block_permille\":%lu,\"uid_changes\":%lu,"
                  "\"cycle_ms_avg\":%lu,\"cycle_ms_max\":%lu",
                  (unsigned long)s.cycles, (unsigned long)s.uid_reads,
                  (unsigned long)s.block_reads,
                  (unsigned long)nfcMeasurePerMille(s.uid_reads, s.cycles),
                  (unsigned long)nfcMeasurePerMille(s.block_reads, s.cycles),
                  (unsigned long)s.uid_changes, (unsigned long)nfcMeasureAvgMs(s),
                  (unsigned long)s.cycle_ms_max);
}
