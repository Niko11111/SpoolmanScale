#pragma once

// Where a read of an OpenPrintTag starts (openprinttag/opt_scan.cpp): at block
// 0, or where a broken-off read of the same tag stopped, while what it got is
// still fresh. Pure logic, no hardware, host-tested in
// test/test_opt_resume.py.
//
// Why: a spool turned past the reader gives each attempt a short window, and
// every attempt started over from block 0. On 19.11.2026 one placement read
// 32, 160, 0, 32, 224 and 160 bytes in six attempts on a 312 byte tag - 608
// bytes in all, never 312 in one go, and the spool went unrecognised.

#include <stddef.h>
#include <stdint.h>

// kept_bytes: what the last broken-off read of this UID got, 0 when there is
// none. age_ms: how long ago that read ended. keep_ms: how long it stays
// usable. head_bytes: the head the length is read from (the CC and the first
// TLVs); without it whole there is nothing to go on. block_bytes: one block.
inline uint16_t optResumeBlock(size_t kept_bytes, uint32_t age_ms, uint32_t keep_ms,
                               size_t head_bytes, size_t block_bytes) {
  if (block_bytes == 0 || kept_bytes < head_bytes || age_ms > keep_ms) return 0;
  return (uint16_t)(kept_bytes / block_bytes);
}
