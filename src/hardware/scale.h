#pragma once

#include <Arduino.h>
#include <Wire.h>
#include <stdint.h>

bool scaleHardwareBegin(TwoWire* wire, void (*calibration_wait_cb)() = nullptr);
int32_t scaleHardwareReadRaw();
