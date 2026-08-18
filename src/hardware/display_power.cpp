#include "display_power.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <esp_sleep.h>

#include "app_config.h"
#include "display.h"
#include "sd_logger.h"


static unsigned long last_activity_ms = 0;
static bool is_dimmed = false;

void displayPowerInit() {
  last_activity_ms = millis();
  is_dimmed = false;
  // loadPrefs() has already restored bright_normal from NVS by this point;
  // nothing else pushed it to the hardware, so the saved level only took
  // effect after the first dim/wake cycle.
  displaySetBrightness((uint8_t)bright_normal);
}

void resetActivityTimer() {
  last_activity_ms = millis();
  if (is_dimmed) {
    displaySetBrightness((uint8_t)bright_normal);
    is_dimmed = false;
  }
}

void handlePowerManagement() {
  unsigned long elapsed = millis() - last_activity_ms;

  // A sleep timeout of zero means never. Without the first test the
  // comparison would be true on the very first pass and the scale would drop
  // into deep sleep right after booting.
  if (sleep_timeout_ms > 0 && elapsed >= (unsigned long)sleep_timeout_ms) {
    Serial.println("Deep sleep...");
    logSD("Deep sleep: entering");
    displayPrepareDeepSleep();
    delay(100);
    esp_deep_sleep_start();
  }

  if (!is_dimmed && elapsed >= (unsigned long)dim_timeout_ms) {
    displaySetBrightness(BRIGHT_DIM_DEFAULT);
    is_dimmed = true;
  }
}
