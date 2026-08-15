#include "setup_flow.h"

#include <Arduino.h>
#include <cstring>

#include "app_config.h"
#include "app/app_state.h"
#include "hardware/sd_logger.h"

void setSetupActive(bool active, const char *reason) {
  if (setup_active == active) return;
  setup_active = active;
  logSDf("SETUP: %s (%s)", active ? "active" : "ended", reason ? reason : "?");
  Serial.printf("SETUP: %s (%s)\n", active ? "active" : "ended", reason ? reason : "?");
}

void logSetupBootState(const char *branch) {
  // Everything needed to tell a real first boot from menu navigation, in one
  // line: which firmware is actually running, which branch the boot logic
  // took, and the three values that branch depends on.
  logSDf("BOOT: %s branch=%s lang_set=%d first_boot=%d ssid=%s setup=%d",
         FW_VERSION, branch,
         cfg_lang_set ? 1 : 0,
         cfg_first_boot ? 1 : 0,
         strlen(cfg_wifi_ssid) > 0 ? "set" : "empty",
         setup_active ? 1 : 0);
  Serial.printf("BOOT: %s branch=%s lang_set=%d first_boot=%d ssid=%s setup=%d\n",
         FW_VERSION, branch,
         cfg_lang_set ? 1 : 0,
         cfg_first_boot ? 1 : 0,
         strlen(cfg_wifi_ssid) > 0 ? "set" : "empty",
         setup_active ? 1 : 0);
}
