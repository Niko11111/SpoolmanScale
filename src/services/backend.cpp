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
#define NVS_BAMBUDDY_KEY    "bb_key"
#define NVS_BAMBUDDY_HOST   "bb_host"

static BackendMode s_mode = BACKEND_SPOOLMAN;
static char s_api_key[80]      = "";
static char s_device_token[80] = "";
static char s_filaman_host[64] = "";
static char s_filaman_base[80] = "";
// BamBuddy keys look like "bb_" plus 43 base64url characters, 46 in total.
static char s_bambuddy_key[80]  = "";
static char s_bambuddy_host[64] = "";
static char s_bambuddy_base[80] = "";

static void rebuildFilamanBase() {
  if (s_filaman_host[0]) {
    snprintf(s_filaman_base, sizeof(s_filaman_base), "http://%s", s_filaman_host);
  } else {
    s_filaman_base[0] = '\0';
  }
}

static void rebuildBamBuddyBase() {
  if (s_bambuddy_host[0]) {
    snprintf(s_bambuddy_base, sizeof(s_bambuddy_base), "http://%s", s_bambuddy_host);
  } else {
    s_bambuddy_base[0] = '\0';
  }
}

void backendLoadSettings() {
  uint8_t raw = prefsGetUChar(NVS_BACKEND_MODE, BACKEND_SPOOLMAN);
  // Anything unknown falls back to Spoolman, so a value written by a newer
  // firmware cannot leave the device in a mode this build has no code for.
  s_mode = (raw == BACKEND_FILAMAN)  ? BACKEND_FILAMAN
         : (raw == BACKEND_BAMBUDDY) ? BACKEND_BAMBUDDY
                                     : BACKEND_SPOOLMAN;

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

  String bb_key = prefsGetString(NVS_BAMBUDDY_KEY, "");
  strncpy(s_bambuddy_key, bb_key.c_str(), sizeof(s_bambuddy_key) - 1);
  s_bambuddy_key[sizeof(s_bambuddy_key) - 1] = '\0';

  String bb_host = prefsGetString(NVS_BAMBUDDY_HOST, "");
  strncpy(s_bambuddy_host, bb_host.c_str(), sizeof(s_bambuddy_host) - 1);
  s_bambuddy_host[sizeof(s_bambuddy_host) - 1] = '\0';
  rebuildBamBuddyBase();

  // Both channels, so the active backend is visible in a serial monitor as
  // well and not only on the card. writeBootBlock() repeats the same line
  // inside the daily log file, which is the one a user actually sends in.
  char line[160];
  backendStatusLine(line, sizeof(line));
  logSDf("Backend: %s", line);
  Serial.printf("Backend: %s\n", line);
}

BackendMode backendMode() { return s_mode; }
bool backendIsFilaMan()   { return s_mode == BACKEND_FILAMAN; }
bool backendIsBamBuddy()  { return s_mode == BACKEND_BAMBUDDY; }

void backendSetMode(BackendMode mode) {
  s_mode = (mode == BACKEND_FILAMAN)  ? BACKEND_FILAMAN
         : (mode == BACKEND_BAMBUDDY) ? BACKEND_BAMBUDDY
                                      : BACKEND_SPOOLMAN;
  prefsPutUChar(NVS_BACKEND_MODE, (uint8_t)s_mode);
  logSDf("Backend: mode -> %s", backendName());
}

const char* backendBaseUrl() {
  switch (s_mode) {
    case BACKEND_FILAMAN:  return s_filaman_base;
    case BACKEND_BAMBUDDY: return s_bambuddy_base;
    default:               return cfg_spoolman_base;
  }
}

const char* backendHost() {
  switch (s_mode) {
    case BACKEND_FILAMAN:  return s_filaman_host;
    case BACKEND_BAMBUDDY: return s_bambuddy_host;
    default:               return cfg_spoolman_ip;
  }
}

void backendSetHost(const char* host) {
  if (!host) return;
  switch (s_mode) {
    case BACKEND_FILAMAN:
      strncpy(s_filaman_host, host, sizeof(s_filaman_host) - 1);
      s_filaman_host[sizeof(s_filaman_host) - 1] = '\0';
      rebuildFilamanBase();
      prefsPutString(NVS_FILAMAN_HOST, s_filaman_host);
      logSDf("Backend: FilaMan host -> %s", s_filaman_host);
      return;
    case BACKEND_BAMBUDDY:
      strncpy(s_bambuddy_host, host, sizeof(s_bambuddy_host) - 1);
      s_bambuddy_host[sizeof(s_bambuddy_host) - 1] = '\0';
      rebuildBamBuddyBase();
      prefsPutString(NVS_BAMBUDDY_HOST, s_bambuddy_host);
      logSDf("Backend: BamBuddy host -> %s", s_bambuddy_host);
      return;
    default:
      saveSpoolmanIP(host);   // unchanged path, same NVS key as before
      return;
  }
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

const char* bambuddyApiKey() { return s_bambuddy_key; }

void bambuddySetApiKey(const char* key) {
  if (!key) return;
  strncpy(s_bambuddy_key, key, sizeof(s_bambuddy_key) - 1);
  s_bambuddy_key[sizeof(s_bambuddy_key) - 1] = '\0';
  prefsPutString(NVS_BAMBUDDY_KEY, s_bambuddy_key);
  logSDf("Backend: BamBuddy API key %s", s_bambuddy_key[0] ? "stored" : "cleared");
}

const char* backendModeName(BackendMode mode) {
  switch (mode) {
    case BACKEND_FILAMAN:  return "FilaMan";
    case BACKEND_BAMBUDDY: return "BamBuddy";
    default:               return "Spoolman";
  }
}

const char* backendName() { return backendModeName(s_mode); }

const char* backendBadge() {
  switch (s_mode) {
    case BACKEND_FILAMAN:  return "FLM";
    case BACKEND_BAMBUDDY: return "BBY";
    default:               return "SPM";
  }
}

void backendCaption(char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  snprintf(out, out_size, "%s:", backendName());
}

void backendStatusLine(char* out, size_t out_size) {
  if (!out || out_size == 0) return;

  // backendHost() picks the host of the active mode, so a leftover FilaMan
  // address never shows up while Spoolman is selected, and the other way round.
  const char* host = backendHost();

  if (backendIsFilaMan()) {
    snprintf(out, out_size, "%s | host=%s | key=%s | device=%s | configured=%s",
      backendName(),
      host[0] ? host : "-",
      s_api_key[0] ? "set" : "empty",
      s_device_token[0] ? "set" : "empty",
      backendIsConfigured() ? "yes" : "no");
  } else if (backendIsBamBuddy()) {
    // The key is reported but never gates "configured" - an instance with
    // authentication disabled works without one.
    snprintf(out, out_size, "%s | host=%s | key=%s | configured=%s",
      backendName(),
      host[0] ? host : "-",
      s_bambuddy_key[0] ? "set" : "empty",
      backendIsConfigured() ? "yes" : "no");
  } else {
    snprintf(out, out_size, "%s | host=%s | configured=%s",
      backendName(),
      host[0] ? host : "-",
      backendIsConfigured() ? "yes" : "no");
  }
}

void backendText(const char* src, char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  out[0] = '\0';
  if (!src) return;

  // In Spoolman mode nothing changes, so take the cheap path.
  if (s_mode == BACKEND_SPOOLMAN) {
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
  if (!backendIsFilaMan()) return true;              // Spoolman and BamBuddy need no credentials
  return s_api_key[0] != '\0' && s_device_token[0] != '\0';
}
