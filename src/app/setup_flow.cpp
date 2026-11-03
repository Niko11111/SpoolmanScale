#include "setup_flow.h"

#include <Arduino.h>
#include <cstring>

#include "app_config.h"
#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/prefs_store.h"
#include "services/user_options.h"

void setSetupActive(bool active, const char *reason) {
  if (setup_active == active) return;
  setup_active = active;
  logSDf("SETUP: %s (%s)", active ? "active" : "ended", reason ? reason : "?");
  Serial.printf("SETUP: %s (%s)\n", active ? "active" : "ended", reason ? reason : "?");
  // Finished, skipped or closed, the setup no longer has anything to resume.
  if (!active && cfg_setup_resume) {
    cfg_setup_resume = false;
    prefsPutBool("setup_resume", false);
  }
}

void logSetupBootState(const char *branch) {
  // Everything needed to tell a real first boot from menu navigation, in one
  // line: which firmware is actually running, which branch the boot logic
  // took, and the values that branch depends on.
  logSDf("BOOT: %s branch=%s lang_set=%d first_boot=%d ssid=%s setup_resume=%d setup=%d",
         FW_VERSION, branch,
         cfg_lang_set ? 1 : 0,
         cfg_first_boot ? 1 : 0,
         strlen(cfg_wifi_ssid) > 0 ? "set" : "empty",
         cfg_setup_resume ? 1 : 0,
         setup_active ? 1 : 0);
  Serial.printf("BOOT: %s branch=%s lang_set=%d first_boot=%d ssid=%s setup_resume=%d setup=%d\n",
         FW_VERSION, branch,
         cfg_lang_set ? 1 : 0,
         cfg_first_boot ? 1 : 0,
         strlen(cfg_wifi_ssid) > 0 ? "set" : "empty",
         cfg_setup_resume ? 1 : 0,
         setup_active ? 1 : 0);
}

// A backend whose credentials are entered in the browser has that step on
// top of WiFi, backend, server and scale.
static bool setupHasCredentialStep() {
  return backendAuthInBrowser();
}

#define SETUP_FIXED_STEPS 3   // WiFi, backend, server

// Without a load cell the scale step is never shown, so it is not counted.
int setupStepCount() {
  return SETUP_FIXED_STEPS + (setupHasCredentialStep() ? 1 : 0) + (g_scale_fitted ? 1 : 0);
}

int setupStepTotal(SetupStep step) {
  if (step != SETUP_STEP_ONLINE) return setupStepCount();
  return SETUP_FIXED_STEPS + 1 + (g_scale_fitted ? 1 : 0);
}

int setupStepNumber(SetupStep step) {
  switch (step) {
    case SETUP_STEP_WIFI:        return 1;
    case SETUP_STEP_BACKEND:     return 2;
    case SETUP_STEP_SERVER:      return 3;
    case SETUP_STEP_ONLINE:      return 3;
    case SETUP_STEP_CREDENTIALS: return setupHasCredentialStep() ? 4 : 0;
    case SETUP_STEP_SCALE:       return setupStepCount();
    default:                     return 0;
  }
}

static bool s_server_later = false;
static bool s_key_required = false;

void setupNoteServerLater(bool later)    { s_server_later = later; }
bool setupServerLater()                   { return s_server_later; }
void setupNoteKeyRequired(bool required) { s_key_required = required; }
bool setupKeyRequired()                   { return s_key_required; }
