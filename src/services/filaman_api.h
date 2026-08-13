#pragma once

#include <ArduinoJson.h>
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

// ---------- reading, translated to the Spoolman shape ----------
//
// FilaMan uses different field names than Spoolman. Rather than teach the
// UI about both, these functions rewrite the answer into the shape the
// existing code already parses. That keeps spool_flow.cpp and
// spoolman_lookup.cpp completely untouched. See the integration doc,
// decision A.
//
// out_doc receives Spoolman-shaped data, so callers cannot tell which
// backend answered.

// Single spool by id. Result is an object like Spoolman's /api/v1/spool/{id}.
int filamanGetSpoolJson(const char* base_url, const char* api_key, int spool_id,
                        JsonDocument& out_doc, uint32_t timeout_ms = 8000,
                        DeserializationError* out_err = nullptr);

// Spool list. Result is a plain array like Spoolman's /api/v1/spool, with
// FilaMan's {items,page,page_size,total} envelope already unwrapped.
// When search_term is given, the server filters and usually returns a single
// entry, which avoids pulling the whole inventory for a tag lookup.
int filamanGetSpoolListJson(const char* base_url, const char* api_key,
                            bool include_archived, JsonDocument& out_doc,
                            const char* search_term = nullptr,
                            int page_size = 100, uint32_t timeout_ms = 15000,
                            DeserializationError* out_err = nullptr);
