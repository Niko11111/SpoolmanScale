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
int filamanRegisterDevice(const char* base_url, const char* device_code,
                          char* out_token, size_t out_size,
                          uint32_t timeout_ms = 8000);

// Presence ping. FilaMan marks a device offline after 180 seconds
// without one, so this is meant to run about once a minute.
int filamanHeartbeat(const char* base_url, const char* device_token,
                     const char* ip_address, uint32_t timeout_ms = 5000);

// GET /health, which sits outside /api/v1 unlike Spoolman's.
int filamanGetHealthCode(const char* base_url, uint32_t timeout_ms = 3000);
