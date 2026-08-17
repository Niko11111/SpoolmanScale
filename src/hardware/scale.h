#pragma once

#include <Arduino.h>
#include <Wire.h>
#include <stdint.h>

bool scaleHardwareBegin(TwoWire* wire, void (*calibration_wait_cb)() = nullptr);
bool scaleHardwareAvailable();
int32_t scaleHardwareReadRaw();
