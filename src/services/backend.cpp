#include "backend.h"

#include <Arduino.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/prefs_store.h"

// NVS keys. Kept short, NVS limits key length to 15 characters.
#define NVS_BACKEND_MODE    "backend_mode"
#define NVS_FILAMAN_KEY     "filaman_key"
#define NVS_FILAMAN_DEVICE  "filaman_dev"

static BackendMode s_mode = BACKEND_SPOOLMAN;
static char s_api_key[80]      = "";
static char s_device_token[80] = "";

void backendLoadSettings() {
  uint8_t raw = prefsGetUChar(NVS_BACKEND_MODE, BACKEND_SPOOLMAN);
  s_mode = (raw == BACKEND_FILAMAN) ? BACKEND_FILAMAN : BACKEND_SPOOLMAN;

  String key = prefsGetString(NVS_FILAMAN_KEY, "");
  strncpy(s_api_key, key.c_str(), sizeof(s_api_key) - 1);
  s_api_key[sizeof(s_api_key) - 1] = '\0';

  String dev = prefsGetString(NVS_FILAMAN_DEVICE, "");
  strncpy(s_device_token, dev.c_str(), sizeof(s_device_token) - 1);
  s_device_token[sizeof(s_device_token) - 1] = '\0';

  // Never log the tokens themselves, only whether they are present.
  logSDf("Backend: mode=%s key=%s device=%s",
    s_mode == BACKEND_FILAMAN ? "FilaMan" : "Spoolman",
    s_api_key[0] ? "set" : "empty",
    s_device_token[0] ? "set" : "empty");
}

BackendMode backendMode() { return s_mode; }
bool backendIsFilaMan()   { return s_mode == BACKEND_FILAMAN; }

void backendSetMode(BackendMode mode) {
  s_mode = (mode == BACKEND_FILAMAN) ? BACKEND_FILAMAN : BACKEND_SPOOLMAN;
  prefsPutUChar(NVS_BACKEND_MODE, (uint8_t)s_mode);
  logSDf("Backend: mode -> %s", backendIsFilaMan() ? "FilaMan" : "Spoolman");
}

const char* backendBaseUrl() {
  // Both backends currently share cfg_spoolman_base. For FilaMan the user
  // enters the host including port, e.g. 192.168.4.100:8002, so the stored
  // "http://<value>" is already the correct API root.
  return cfg_spoolman_base;
}

const char* filamanApiKey()      { return s_api_key; }
const char* filamanDeviceToken() { return s_device_token; }

void filamanSetApiKey(const char* key) {
  if (!key) return;
  strncpy(s_api_key, key, sizeof(s_api_key) - 1);
  s_api_key[sizeof(s_api_key) - 1] = '\0';
  prefsPutString(NVS_FILAMAN_KEY, s_api_key);
  logSDf("Backend: FilaMan API key %s", s_api_key[0] ? "stored" : "cleared");
}

void filamanSetDeviceToken(const char* token) {
  if (!token) return;
  strncpy(s_device_token, token, sizeof(s_device_token) - 1);
  s_device_token[sizeof(s_device_token) - 1] = '\0';
  prefsPutString(NVS_FILAMAN_DEVICE, s_device_token);
  logSDf("Backend: FilaMan device token %s", s_device_token[0] ? "stored" : "cleared");
}

bool backendIsConfigured() {
  if (strlen(cfg_spoolman_base) <= 7) return false;   // longer than "http://"
  if (!backendIsFilaMan()) return true;
  return s_api_key[0] != '\0' && s_device_token[0] != '\0';
}
