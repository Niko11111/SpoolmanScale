#pragma once

#include <Arduino.h>

bool displayHardwareBegin(void (*touch_activity_cb)() = nullptr);
void displaySetBrightness(uint8_t brightness);
void displayPrepareDeepSleep();
