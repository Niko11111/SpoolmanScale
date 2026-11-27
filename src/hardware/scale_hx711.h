#pragma once

// The HX711 load cell ADC on connector pins 5 (SCK) and 6 (DOUT), bit-banged.
// Only hardware/scale.cpp calls this, when no NAU7802 answers on I2C_EXT.
// Driver after PR #53 (nikpcenicni): channel A, gain 128, 24 bit samples.

#include <stdint.h>

// Sets the pins, power-cycles the chip and waits for two conversions; the
// first one after a reset is thrown away. calibration_wait_cb runs while
// waiting, as for the NAU7802. False when no HX711 answers within a second.
bool hx711Begin(void (*calibration_wait_cb)());

// A conversion was ready within the last 1.5 s, or is ready now. The HX711
// has no address to probe: DOUT going low is the only sign of life, and a
// pulled-up DOUT with nothing behind it stays high.
bool hx711Present();

// DOUT is low: a new conversion waits to be read.
bool hx711Available();

// Clocks out the waiting conversion. Every read takes the conversion away, so
// without a new one this answers the last sample again, as the NAU7802's
// result register would: tare and calibration read outside the loop's rhythm.
int32_t hx711ReadRaw();
