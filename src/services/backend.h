#pragma once

#include <stdint.h>

// ============================================================
//  BACKEND SELECTION
//
//  SpoolmanScale can talk to more than one filament management
//  backend. Which one is active is decided at runtime from NVS,
//  never at compile time.
//
//  Spoolman is reached with a plain base URL and no credentials.
//  FilaMan needs two separate tokens:
//    - a device token, obtained by registering a 6 character code,
//      used for heartbeat, weight reporting and reading
//    - an API key created by the user in the FilaMan UI, used for
//      everything that writes
//  FilaMan has no per device permissions, which is why both are
//  needed. See SpoolmanScale_FilaMan_Integration_v2_0.md.
// ============================================================

enum BackendMode : uint8_t {
  BACKEND_SPOOLMAN = 0,
  BACKEND_FILAMAN  = 1
};

// Return value used by backend_api when a call has no equivalent in
// the active backend. Deliberately distinct from the HTTP client's
// error codes so it can be told apart in logs.
#define BACKEND_NOT_SUPPORTED  (-90)

// Loads mode and FilaMan credentials from NVS. Call once during boot,
// after prefs_store is available and before the first backend call.
void backendLoadSettings();

BackendMode backendMode();
void        backendSetMode(BackendMode mode);   // persists to NVS
bool        backendIsFilaMan();

// Base URL of the active backend, always without a trailing slash.
// In Spoolman mode this is cfg_spoolman_base, so existing behaviour
// is unchanged.
const char* backendBaseUrl();

// FilaMan credentials. Empty strings when unset.
const char* filamanApiKey();
const char* filamanDeviceToken();
void        filamanSetApiKey(const char* key);          // persists
void        filamanSetDeviceToken(const char* token);   // persists

// True when the active backend has everything it needs to talk to
// its server. Spoolman only needs a base URL.
bool backendIsConfigured();
