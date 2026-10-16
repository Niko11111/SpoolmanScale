#pragma once

#include <Arduino.h>
#include <Wire.h>
#include <stdint.h>

bool scaleHardwareBegin(TwoWire* wire, void (*calibration_wait_cb)() = nullptr);

// Is the selected ADC present/ready? NAU7802 uses an I2C address probe; HX711
// reports conversion readiness on DOUT, so its liveness is tied to a fresh
// conversion rather than a bus acknowledgment.
bool scaleHardwarePresent();
// Slow bounded probe for recovery paths. On HX711 this waits up to one
// conversion period for DOUT to go low; do not call from the fast loop.
bool scaleHardwareProbe();

bool scaleHardwareAvailable();
// Reads only a fresh conversion. Returns false if the ADC is not ready or the
// output pointer is null; callers must not use a failed sample.
bool scaleHardwareReadRaw(int32_t* raw);
// The last sample scaleHardwareReadRaw() returned, without touching the ADC.
// For reports: on the HX711 every read consumes a conversion, and a second
// reader would take samples away from the weight filter.
bool scaleHardwareLastRaw(int32_t* raw);
