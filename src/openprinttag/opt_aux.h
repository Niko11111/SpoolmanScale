#pragma once

// An OpenPrintTag's aux region (opt_tag.h) with a new consumed_weight: what
// printers write as they use the filament, and with its switch on the scale,
// after a weight was sent to the backend (opt_write.cpp).
//
// Written the way Prusa's firmware writes it (Prusa-Firmware-Buddy,
// opt_reader.cpp, looked at 26.11.2026): the whole region encoded again as a
// map of indefinite length, consumed_weight first as whole grams, every other
// entry copied byte for byte in its order (workgroup and keys the scale does
// not know included), zeros behind the map. Where the break no longer fits,
// a map of given length, as the format's own encoder writes an empty one.
// Which bytes changed, and so which blocks go onto the tag, is the writer's
// business. Pure: no Arduino, tested on the host with the format's own
// vectors (test/test_openprinttag.py).

#include <stddef.h>
#include <stdint.h>

// aux: the region as read (optAuxLocate()), size bytes. out: the region as
// it is to be written, the same size; never the same buffer as aux. A region
// of nothing but zeros counts as empty. False when the old content is no map,
// or the new map does not fit the region.
bool optAuxWithConsumed(const uint8_t* aux, size_t size, uint32_t consumed_g, uint8_t* out);

// Grams consumed from a spool that held full_g when new and holds remaining_g
// now, rounded; 0 when more than full is left.
uint32_t optConsumedFor(float full_g, float remaining_g);
