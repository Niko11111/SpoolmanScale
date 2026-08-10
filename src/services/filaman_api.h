#pragma once

#include <stddef.h>
#include <stdint.h>

// ============================================================
//  FILAMAN HTTP LAYER
//
//  FilaMan uses two credentials, because it has no per device
//  permissions:
//    Authorization: Device <dev.N....>   heartbeat, weight, reading
//    Authorization: ApiKey <uak.N....>   everything that writes
//
//  Only the pieces needed for setup exist so far. The read and
//  write paths follow in later stages.
// ============================================================

// Exchanges the 6 character code from the FilaMan admin for a device
// token. Returns the HTTP status code, 200 on success, and copies the
// token into out_token. The token is never logged.
//
// Device codes are single use. A consumed code answers 404 "Invalid device
// code", a code belonging to an already registered device answers 403. On
// failure the server's own message is copied into out_error when given, so
// the user sees why instead of a bare status number.
int filamanRegisterDevice(const char* base_url, const char* device_code,
                          char* out_token, size_t out_size,
                          char* out_error = nullptr, size_t err_size = 0,
                          uint32_t timeout_ms = 8000);

// Presence ping. FilaMan marks a device offline after 180 seconds
// without one, so this is meant to run about once a minute.
int filamanHeartbeat(const char* base_url, const char* device_token,
                     const char* ip_address, uint32_t timeout_ms = 5000);

// GET /health, which sits outside /api/v1 unlike Spoolman's.
int filamanGetHealthCode(const char* base_url, uint32_t timeout_ms = 3000);
