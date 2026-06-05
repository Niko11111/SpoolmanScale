#include "display_power.h"

#include <Arduino.h>
#include <esp_sleep.h>

#include "app_config.h"
#include "display.h"
#include "sd_logger.h"

extern int bright_normal;
extern int dim_timeout_ms;
extern int sleep_timeout_ms;

static unsigned long last_activity_ms = 0;
static bool is_dimmed = false;

void resetActivityTimer() {
  last_activity_ms = millis();
  if (is_dimmed) {
    displaySetBrightness((uint8_t)bright_normal);
    is_dimmed = false;
  }
}

void handlePowerManagement() {
  unsigned long elapsed = millis() - last_activity_ms;

  if (elapsed >= (unsigned long)sleep_timeout_ms) {
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
