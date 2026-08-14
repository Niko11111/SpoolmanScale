#pragma once

#include <stddef.h>
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
// is unchanged. In FilaMan mode it is built from the separate FilaMan
// host, which lets the user switch back and forth without retyping
// an address every time.
const char* backendBaseUrl();

// Host of the active backend as the user typed it, "ip" or "ip:port",
// without the http:// prefix. Empty when unset.
const char* backendHost();

// Stores the host for the currently active backend and rebuilds its
// base URL. In Spoolman mode this delegates to saveSpoolmanIP() so the
// existing behaviour and NVS key stay exactly as they were.
void backendSetHost(const char* host);

// FilaMan credentials. Empty strings when unset.
const char* filamanApiKey();
const char* filamanDeviceToken();
void        filamanSetApiKey(const char* key);          // persists
void        filamanSetDeviceToken(const char* token);   // persists

// True when the active backend has everything it needs to talk to
// its server. Spoolman only needs a base URL.
bool backendIsConfigured();

// Product name of the active backend, "Spoolman" or "FilaMan".
const char* backendName();

// Copies a UI string into a RAM buffer and replaces the word "Spoolman"
// with the active backend's name on the way. Two jobs in one call:
//
//   1. T() returns a pointer into Flash which LVGL cannot read, so every
//      string has to be copied into a local buffer anyway.
//   2. Roughly two dozen strings name Spoolman explicitly. Rather than
//      litter lang.cpp with %s placeholders, which would break the
//      argument order of the strings that already take format arguments,
//      the substitution happens here.
//
// "SpoolmanScale" is left alone, that is the product name of this device.
// In Spoolman mode the function is a plain copy.
//
// Usage:  char buf[64]; backendText(T(STR_X), buf, sizeof(buf));
void backendText(const char* src, char* out, size_t out_size);
