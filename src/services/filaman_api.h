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

// Server version. FilaMan has no version endpoint that works without admin
// rights, but /openapi.json carries it in info.version and needs no
// credentials. That document is 240 kB, so only its first bytes are read and
// the connection is dropped: the version sits within the first 60.
bool filamanGetVersion(const char* base_url, char* out_version, size_t out_size,
                       uint32_t timeout_ms = 5000);

// Number of spools not archived. Taken from the "total" of a one item page
// rather than counting, which keeps the answer small.
int filamanCountActiveSpools(const char* base_url, const char* api_key,
                             uint32_t timeout_ms = 6000);

// Timestamp of the most recent weighing, read from the spool event log.
// FilaMan records every measurement itself, including the ones this scale
// reports, so nothing has to be written to get a "last weighed" date.
//
// last_used_at on the spool only fills from real print consumption and stays
// empty without a printer integration, which is why the event log is the
// better source for "when did I last handle this spool".
//
// A few events are fetched rather than one, because a status change or a
// manual correction in between would otherwise hide the last measurement.
// Writes an ISO timestamp to out_iso. Returns false if there is none.
bool filamanGetLastMeasuredAt(const char* base_url, const char* api_key, int spool_id,
                              char* out_iso, size_t out_size, uint32_t timeout_ms = 6000);

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

// Returned when FilaMan is selected but no device token has been registered.
// Distinct from -1 so a caller can tell "not set up yet" from "call failed".
#define FILAMAN_NO_DEVICE_TOKEN  (-91)

// ---------- writing ----------
//
// Only custom_fields needs the read-modify-write dance: a PATCH replaces the
// whole object, verified against a live instance. Every other field can be
// patched on its own.

// Sets rfid_uid. Used for link, and with an empty uuid for unlink.
int filamanPatchRfidUid(const char* base_url, const char* api_key, int spool_id,
                        const char* uuid, uint32_t timeout_ms = 5000);

// Writes one key inside custom_fields while preserving the others.
// Costs a GET before the PATCH, which is why nothing else uses this path.
int filamanPatchCustomField(const char* base_url, const char* api_key, int spool_id,
                            const char* key, const char* value,
                            uint32_t timeout_ms = 8000);

// Reports a measured weight through the device API. FilaMan works out the
// remaining filament itself, so the empty spool weight must NOT be
// subtracted beforehand. Identifies the spool by id, or by tag when id is 0.
int filamanReportWeight(const char* base_url, const char* device_token,
                        int spool_id, const char* tag_uuid, float measured_g,
                        uint32_t timeout_ms = 8000);

// Result of a remotely triggered tag operation, answering a trigger that
// arrived on /api/v1/rfid/write. Authenticated with the device token, not the
// API key, exactly like the heartbeat.
//
// This is the write path of the remote link, and it is used instead of
// filamanPatchRfidUid on purpose. The server clears the UID from every other
// spool first, archived ones included, which a plain PATCH would not do: the
// column is UNIQUE, so a UID still sitting on an old spool would make the
// PATCH fail. It also resolves the "pending" state the web UI polls, which is
// why a failure has to be reported just as reliably as a success.
//
// error_message may be null when success is true. spool_id is echoed back so
// the server knows which spool the UID belongs to.
int filamanRfidResult(const char* base_url, const char* device_token,
                      bool success, const char* tag_uuid, int spool_id,
                      const char* error_message, uint32_t timeout_ms = 6000);

// Status change, for example archiving. Uses its own endpoint rather than a
// PATCH, see /api/v1/spools/{id}/status.
int filamanSetStatus(const char* base_url, const char* api_key, int spool_id,
                     const char* status_key, uint32_t timeout_ms = 5000);

// Single numeric fields on the spool.
int filamanPatchSpoolFloat(const char* base_url, const char* api_key, int spool_id,
                           const char* field, float value, uint32_t timeout_ms = 5000);

// Two numeric fields in one PATCH. Needed wherever a value only makes sense
// together with a second one - a fresh initial weight leaves a stale remaining
// behind, an archived spool leaves a stale remaining behind. Spoolman writes
// both in a single request and FilaMan has to as well, or the two disagree for
// as long as it takes the next scan to overwrite the display.
int filamanPatchSpoolFloat2(const char* base_url, const char* api_key, int spool_id,
                            const char* field_a, float value_a,
                            const char* field_b, float value_b,
                            uint32_t timeout_ms = 5000);

// Single numeric field on a filament, for the default empty spool weight.
int filamanPatchFilamentFloat(const char* base_url, const char* api_key, int filament_id,
                              const char* field, float value, uint32_t timeout_ms = 5000);

// Single numeric field on a manufacturer. FilaMan calls them manufacturers,
// Spoolman calls them vendors, and both keep an empty spool weight there.
int filamanPatchManufacturerFloat(const char* base_url, const char* api_key, int manufacturer_id,
                                  const char* field, float value, uint32_t timeout_ms = 5000);

// Creates a spool. Only filament_id is mandatory. The new id is written to
// out_spool_id, which the copy flow needs in order to link the tag right
// afterwards. rfid_uid may be passed to create and link in one request.
int filamanCreateSpool(const char* base_url, const char* api_key, int filament_id,
                       float initial_weight, float spool_weight, float remaining_weight,
                       const char* rfid_uid = nullptr, int* out_spool_id = nullptr,
                       uint32_t timeout_ms = 8000);

// Locations. Spoolman has them as plain strings on the spool, FilaMan as
// objects with an id. These translate in both directions using a small cache
// that is refreshed as a side effect of reading spools.

// Result is an array of name strings, matching Spoolman's /api/v1/location.
int filamanGetLocationsJson(const char* base_url, const char* api_key,
                            JsonDocument& out_doc, uint32_t timeout_ms = 8000,
                            DeserializationError* out_err = nullptr);

// Takes a location name and resolves it to an id. An empty or null name
// clears the location.
int filamanPatchSpoolLocation(const char* base_url, const char* api_key, int spool_id,
                              const char* location_name, uint32_t timeout_ms = 8000);

// Spool list. Result is a plain array like Spoolman's /api/v1/spool, with
// FilaMan's {items,page,page_size,total} envelope already unwrapped.
// When search_term is given, the server filters and usually returns a single
// entry, which avoids pulling the whole inventory for a tag lookup.
int filamanGetSpoolListJson(const char* base_url, const char* api_key,
                            bool include_archived, JsonDocument& out_doc,
                            const char* search_term = nullptr,
                            int page_size = 100, uint32_t timeout_ms = 15000,
                            DeserializationError* out_err = nullptr);

// ---------- the device's own auto-assign settings ----------
//
// FilaMan can mark a spool as "pending" on every running printer driver for
// a number of seconds right after it was weighed, so that the next tray to
// be loaded gets it. Whether that happens is a property of the device, not
// of the request: the server reads auto_assign_enabled inside
// POST /devices/scale/weight and hands the spool to the drivers there.
//
// Both fields live behind the admin API and need admin:devices_manage,
// which the ApiKey carries only if the account behind it has the permission.
// The device token can be used instead when the device was given that scope.

// The device's own id, taken from the token: it is "dev.<id>.<secret>".
// 0 when no token is registered.
int filamanDeviceId();

// Reads auto_assign_enabled and auto_assign_timeout for one device out of
// the admin device list. Returns the HTTP status, 200 on success, 404 when
// the id is not in the list, -2 on a parse error.
int filamanGetDeviceAutoAssign(const char* base_url, const char* api_key,
                               int device_id, bool* out_enabled,
                               int* out_timeout_s, uint32_t timeout_ms = 8000);

// Writes one or both fields. A null pointer means "leave alone": the server
// parses DeviceUpdate with exclude_unset, so an omitted field keeps its
// stored value. The device name is deliberately never sent.
int filamanSetDeviceAutoAssign(const char* base_url, const char* api_key,
                               int device_id, const bool* enabled,
                               const int* timeout_s, uint32_t timeout_ms = 5000);
