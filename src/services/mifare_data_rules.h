#pragma once

#include <stddef.h>
#include <stdint.h>

// ============================================================
//  WHAT A PERSON CAN RECOGNISE IN A CARD'S DATA
//
//  Before the scale overwrites a MIFARE card that opens with the factory
//  key but already holds data, it says what is on it. A card from an access
//  system or a hobby project often carries a name or a number in plain
//  ASCII; that is the one thing its owner would recognise. Pure logic, no
//  NFC: the host test compiles this header (test/test_mifare_data.py).
// ============================================================

#define MIFARE_DATA_TEXT_MIN  4   // shorter runs turn up in random bytes

// The longest run of printable ASCII in data, spaces trimmed at both ends and
// cut to fit out. True when at least MIFARE_DATA_TEXT_MIN characters remain;
// out is then terminated, otherwise empty.
inline bool mifareDataText(const uint8_t* data, size_t len, char* out, size_t out_len) {
  if (!out || out_len == 0) return false;
  out[0] = '\0';
  if (!data || out_len < 2) return false;
  size_t best_at = 0, best_n = 0, run_at = 0, run_n = 0;
  for (size_t i = 0; i < len; i++) {
    const bool printable = data[i] >= 0x20 && data[i] < 0x7F;
    if (!printable) { run_n = 0; continue; }
    if (run_n == 0) run_at = i;
    run_n++;
    if (run_n > best_n) { best_at = run_at; best_n = run_n; }
  }
  while (best_n > 0 && data[best_at] == ' ') { best_at++; best_n--; }
  while (best_n > 0 && data[best_at + best_n - 1] == ' ') best_n--;
  if (best_n < MIFARE_DATA_TEXT_MIN) return false;
  const size_t n = best_n < out_len - 1 ? best_n : out_len - 1;
  for (size_t i = 0; i < n; i++) out[i] = (char)data[best_at + i];
  out[n] = '\0';
  return true;
}
