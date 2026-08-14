#include "backend.h"

#include <Arduino.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/app_settings.h"
#include "services/prefs_store.h"

// NVS keys. Kept short, NVS limits key length to 15 characters.
#define NVS_BACKEND_MODE    "backend_mode"
#define NVS_FILAMAN_KEY     "filaman_key"
#define NVS_FILAMAN_DEVICE  "filaman_dev"
#define NVS_FILAMAN_HOST    "filaman_host"

static BackendMode s_mode = BACKEND_SPOOLMAN;
static char s_api_key[80]      = "";
static char s_device_token[80] = "";
static char s_filaman_host[64] = "";
static char s_filaman_base[80] = "";

static void rebuildFilamanBase() {
  if (s_filaman_host[0]) {
    snprintf(s_filaman_base, sizeof(s_filaman_base), "http://%s", s_filaman_host);
  } else {
    s_filaman_base[0] = '\0';
  }
}

void backendLoadSettings() {
  uint8_t raw = prefsGetUChar(NVS_BACKEND_MODE, BACKEND_SPOOLMAN);
  s_mode = (raw == BACKEND_FILAMAN) ? BACKEND_FILAMAN : BACKEND_SPOOLMAN;

  String key = prefsGetString(NVS_FILAMAN_KEY, "");
  strncpy(s_api_key, key.c_str(), sizeof(s_api_key) - 1);
  s_api_key[sizeof(s_api_key) - 1] = '\0';

  String dev = prefsGetString(NVS_FILAMAN_DEVICE, "");
  strncpy(s_device_token, dev.c_str(), sizeof(s_device_token) - 1);
  s_device_token[sizeof(s_device_token) - 1] = '\0';

  String host = prefsGetString(NVS_FILAMAN_HOST, "");
  strncpy(s_filaman_host, host.c_str(), sizeof(s_filaman_host) - 1);
  s_filaman_host[sizeof(s_filaman_host) - 1] = '\0';
  rebuildFilamanBase();

  // Never log the tokens themselves, only whether they are present.
  logSDf("Backend: mode=%s host=%s key=%s device=%s",
    s_mode == BACKEND_FILAMAN ? "FilaMan" : "Spoolman",
    s_filaman_host[0] ? s_filaman_host : "-",
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
  return backendIsFilaMan() ? s_filaman_base : cfg_spoolman_base;
}

const char* backendHost() {
  return backendIsFilaMan() ? s_filaman_host : cfg_spoolman_ip;
}

void backendSetHost(const char* host) {
  if (!host) return;
  if (!backendIsFilaMan()) {
    saveSpoolmanIP(host);   // unchanged path, same NVS key as before
    return;
  }
  strncpy(s_filaman_host, host, sizeof(s_filaman_host) - 1);
  s_filaman_host[sizeof(s_filaman_host) - 1] = '\0';
  rebuildFilamanBase();
  prefsPutString(NVS_FILAMAN_HOST, s_filaman_host);
  logSDf("Backend: FilaMan host -> %s", s_filaman_host);
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

const char* backendName() {
  return backendIsFilaMan() ? "FilaMan" : "Spoolman";
}

void backendText(const char* src, char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  out[0] = '\0';
  if (!src) return;

  // In Spoolman mode nothing changes, so take the cheap path.
  if (!backendIsFilaMan()) {
    strncpy(out, src, out_size - 1);
    out[out_size - 1] = '\0';
    return;
  }

  static const char  kNeedle[] = "Spoolman";
  static const size_t kNeedleLen = sizeof(kNeedle) - 1;
  const char* name = backendName();
  const size_t name_len = strlen(name);

  size_t o = 0;
  for (const char* p = src; *p && o < out_size - 1; ) {
    if (strncmp(p, kNeedle, kNeedleLen) == 0 &&
        strncmp(p + kNeedleLen, "Scale", 5) != 0) {   // never touch SpoolmanScale
      size_t room = out_size - 1 - o;
      size_t n = (name_len < room) ? name_len : room;
      memcpy(out + o, name, n);
      o += n;
      p += kNeedleLen;
      continue;
    }
    out[o++] = *p++;
  }
  out[o] = '\0';
}

bool backendIsConfigured() {
  if (strlen(backendBaseUrl()) <= 7) return false;   // longer than "http://"
  if (!backendIsFilaMan()) return true;
  return s_api_key[0] != '\0' && s_device_token[0] != '\0';
}
