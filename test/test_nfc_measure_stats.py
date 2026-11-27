"""Compile the counting of the reader measurement and check the rates it
reports: per mille, rounded, never a block read without a UID, and the JSON
members the maintenance route answers with (services/nfc_measure_stats.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/nfc_measure_stats.h"
#include <cassert>
#include <cstring>

int main() {
  // No cycles: nothing to divide by, every rate is zero.
  NfcMeasureStats s = {};
  assert(nfcMeasurePerMille(0, 0) == 0);
  assert(nfcMeasureAvgMs(s) == 0);

  // 50 cycles of 200 ms, the default 10 s window: 49 UIDs, 47 blocks.
  for (int i = 0; i < 50; i++) {
    const bool uid = i != 7;
    const bool block = uid && i != 11 && i != 12;
    nfcMeasureCount(s, 80 + (i % 3) * 10, uid, block, false);
  }
  assert(s.cycles == 50 && s.uid_reads == 49 && s.block_reads == 47);
  assert(nfcMeasurePerMille(s.uid_reads, s.cycles) == 980);
  assert(nfcMeasurePerMille(s.block_reads, s.cycles) == 940);
  assert(s.cycle_ms_max == 100);

  // A block without a UID does not count, nor does a change without a UID.
  NfcMeasureStats t = {};
  nfcMeasureCount(t, 10, false, true, true);
  assert(t.cycles == 1 && t.uid_reads == 0 && t.block_reads == 0 && t.uid_changes == 0);

  // Rounding: 2 of 3 is 666.7 per mille, reported as 667; 1 of 3 as 333.
  assert(nfcMeasurePerMille(2, 3) == 667);
  assert(nfcMeasurePerMille(1, 3) == 333);
  assert(nfcMeasurePerMille(3, 3) == 1000);
  // Large counts do not overflow on the way.
  assert(nfcMeasurePerMille(4000000000u, 4000000000u) == 1000);

  // Average rounded too: 10 + 11 ms is 10.5, reported as 11.
  NfcMeasureStats a = {};
  nfcMeasureCount(a, 10, true, true, false);
  nfcMeasureCount(a, 11, true, true, true);
  assert(nfcMeasureAvgMs(a) == 11 && a.uid_changes == 1);

  char json[256];
  nfcMeasureStatsJson(a, json, sizeof(json));
  assert(strcmp(json,
    "\"cycles\":2,\"uid_reads\":2,\"block_reads\":2,\"uid_permille\":1000,"
    "\"block_permille\":1000,\"uid_changes\":1,\"cycle_ms_avg\":11,\"cycle_ms_max\":11") == 0);
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "t.cpp"
    binary = Path(tmp) / "t"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", f"-I{root / 'src'}", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("nfc measure stats: ok")
