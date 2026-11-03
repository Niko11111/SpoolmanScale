#pragma once

#include <stdint.h>

// The rules behind an empty spool weight, free of JSON and of the device, so a
// host test can run them (test/test_tare_chain.py).

// Which level supplied the empty-spool weight. An inherited value is a
// reasonable starting point, not a measurement, and the UI says so.
enum TareSource : uint8_t {
  TARE_NONE = 0,   // nothing known, the spool counts as 0 g
  TARE_SPOOL,      // stored for this spool
  TARE_FILAMENT,   // default for this filament
  TARE_VENDOR      // default for the brand
};

// The first level that holds a value answers: spool, filament, vendor. A null
// pointer is a level with nothing stored, and a stored 0 is a value - a refill
// wound on no spool weighs nothing, and Spoolman reads it the same way since
// v0.27.1 (Donkie/Spoolman#1253). A negative number counts as nothing stored.
// `source`, when given, receives which level answered.
float tareFromChain(const float* spool_g, const float* filament_g, const float* vendor_g,
                    uint8_t* source);

// Whether Spoolman's /measure subtracts the same tare this firmware did, so
// the gross reading can be handed over. Two cases where it may not:
// - a tare known only on the vendor: older servers stop at the filament and
//   fall back to zero (Donkie/Spoolman#1117);
// - a stored 0: servers before v0.27.1 take it for unset and subtract the
//   filament's tare, 250 g too much on a refill.
// In both the caller writes the remaining weight it worked out itself, which
// is right on every server version.
bool tareMeasureAgrees(uint8_t source, float tare_g);
