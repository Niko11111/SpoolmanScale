#pragma once

#include <Arduino.h>

bool displayHardwareBegin(void (*touch_activity_cb)() = nullptr);
void displaySetBrightness(uint8_t brightness);
void displayPrepareDeepSleep();

// Backlight fully off, and back again. Not the same as brightness 0.
void displayBacklightOff();
void displayBacklightOn(uint8_t brightness);
