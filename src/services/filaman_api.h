#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

#include "services/ams_slots.h"

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

// That count and the id of the first spool on the same one item page. Returns
// the HTTP code as it came, -2 for a body that did not parse. 200 with
// *out_count at -1 is an answer without a total.
int filamanInventoryStamp(const char* base_url, const char* api_key,
                          int* out_count, int* out_witness_id, uint32_t timeout_ms);

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

// When the spool was last used, from the same log. "Used" is any entry that
// moved the weight: a print the consumption tracking booked off, or a
// weighing. A move_location is not one - being reassigned to a bay is not
// using the filament, and the driver writes those often enough to bury
// everything else.
//
// Asked by the weight fields rather than by event_type, so a type FilaMan
// adds later counts the moment it carries a delta.
//
// This is what last_used_at should hold and does not: FilaMan books the
// consumption into the event log and leaves the spool field null, so a spool
// that has been printed from for weeks still reads as never used.
bool filamanGetLastUsedAt(const char* base_url, const char* api_key, int spool_id,
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

// Sets rfid_uid_2, the second slot FilaMan grew in 1.3.1. Same shape as the
// call above, and deliberately not a copy of filamanLinkRfidUid() below: the
// dance that one does - find the holder, take the tag off it, keep the old
// value - exists only because a PATCH used to fail at the unique index.
// set_rfid_uids() does all of it server side now, and having the same rule in
// two places is how the two start to disagree.
//
// Fails with a validation error on a server that has no such column, which is
// why callers ask filamanHasRfidSlot2() first.
int filamanPatchRfidUid2(const char* base_url, const char* api_key, int spool_id,
                         const char* uuid, uint32_t timeout_ms = 5000);

// Whether this server has the second slot at all.
//
// The test is the presence of the key rfid_uid_2 in a spool response, not a
// version number. FastAPI serialises the field even when it is null, so its
// mere presence separates 1.3.1 from everything before it - while a version
// number is a wager the moment somebody builds their own image, which is
// exactly what the instance on the homeserver does.
//
// Cached per base URL. An inconclusive answer is not cached, so one bad
// moment cannot switch the feature off for the whole session.
// Whether the probe above has a cached answer for this server at all. Its
// "false" covers both "the column is not there" and "could not tell", and an
// unlink has to treat those two differently.
bool filamanRfidSlot2Known(const char* base_url);

// True when the last spool list stopped short of the whole inventory (the
// timeout, or the page cap). A tag not found in such a list is unknown, not
// absent - the difference between "link it" and "create a duplicate".
bool filamanLastListPartial();

bool filamanHasRfidSlot2(const char* base_url, const char* api_key,
                         uint32_t timeout_ms = 5000);

// Frees a spool of every chip it holds, both slots in one request, and drops
// the legacy value in custom_fields with it.
//
// One request on purpose: set_rfid_uids() back-fills the primary slot from the
// secondary, so clearing them one after the other would move the second chip
// into the first slot in between and the first PATCH would look like a no-op.
// rfid_uid_2 is only named when the server has it.
int filamanClearRfidUids(const char* base_url, const char* api_key, int spool_id,
                         uint32_t timeout_ms = 8000);

// Forgets the cached answer above. Called when the backend or its address
// changes, because the capability belongs to the server, not to the scale.
void filamanForgetRfidSlot2();

// Link that clears the way first. rfid_uid is UNIQUE, so claiming a UID that
// another spool still holds fails with HTTP 500. Takes it off that spool,
// keeps whatever the target had in custom_fields.previous_tag, then patches.
int filamanLinkRfidUid(const char* base_url, const char* api_key, int spool_id,
                       const char* uuid, char* out_note, size_t note_size,
                       uint32_t timeout_ms = 8000);

// Writes one key inside custom_fields while preserving the others.
// Costs a GET before the PATCH, which is why nothing else uses this path.
int filamanPatchCustomField(const char* base_url, const char* api_key, int spool_id,
                            const char* key, const char* value,
                            uint32_t timeout_ms = 8000);

// A Bambu chip uid is four bytes, eight characters normalised. The plugin
// pads the field to sixteen with what the AMS reported, so only the front is
// ever compared.
#define FILAMAN_BAMBU_CHIP_LEN  8

// Undoes, on unlink, what this scale would have written into the Bambu
// plugin's fields - external_id and a chip slot - and nothing else. Without
// it the plugin's own entries keep naming the tag, the next scan finds the
// spool through them, and rfid_uid is written straight back.
int filamanUnlinkBambuFields(const char* base_url, const char* api_key, int spool_id,
       const char* chip_uid_hex, uint32_t timeout_ms = 8000);

// Sets external_id. Used to write "bambulab:<tray uuid>" onto a spool this
// scale linked, which is the only field the Bambu Lab plugin's duplicate
// check consults - without it the plugin creates the spool a second time.
//
// Only ever called with the field empty. It is the plugin's namespace, and a
// spoolman:<id> left by the importer says where the record came from.
int filamanPatchExternalId(const char* base_url, const char* api_key, int spool_id,
                           const char* external_id, uint32_t timeout_ms = 5000);

// Reports a measured weight through the device API. FilaMan works out the
// remaining filament itself, so the empty spool weight must NOT be
// subtracted beforehand. Identifies the spool by id, or by tag when id is 0.
int filamanReportWeight(const char* base_url, const char* device_token,
                        int spool_id, const char* tag_uuid, float measured_g,
                        uint32_t timeout_ms = 8000);

// Announces a tag the scale has just read, so a browser watching this reader
// can follow it to the spool. FilaMan records the scan in its reader table -
// the database is the hand-off, because its event bus is per Gunicorn worker
// and an event would reach only the browsers on one of them.
//
// The answer carries matched_spool_id, so this doubles as a lookup, but unlike
// Spoolman's /tag/scan it does not embed the spool: the caller still runs its
// normal lookup. Device token, like the weight report.
//
// alt_uid is the other spelling of the same tag, when there is one. A Bambu
// spool is on file under its tray uuid when the driver imported it and under
// the chip uid when this scale linked it, and which one a server keeps is not
// something the scale can know - so it offers both and lets the server match.
// reader_id and reader_name are the same pair Spoolman's /tag/scan takes: a
// stable id a browser can bind to, and the name its picker shows.
int filamanTagScan(const char* base_url, const char* device_token, const char* uid,
                   const char* alt_uid, const char* reader_id, const char* reader_name,
                   const char* format, JsonDocument& doc, uint32_t timeout_ms = 5000,
                   DeserializationError* out_err = nullptr);

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

// Answers a scan trigger that arrived on /api/v1/rfid/scan-request with the
// contents of the tag. Device token again, like the heartbeat. tag_json is
// what the web UI then offers to import.
int filamanSendTagData(const char* base_url, const char* device_token,
                       const char* tag_json, uint32_t timeout_ms = 6000);

// FilaMan's status table is part of the API contract: six rows with fixed ids
// and no CRUD endpoint to change them. GET /api/v1/spools/statuses would cost
// a round trip to learn something that cannot move, so the ids live here and
// their labels live in lang.cpp.
#define FILAMAN_STATUS_NEW       1
#define FILAMAN_STATUS_OPENED    2
#define FILAMAN_STATUS_DRYING    3
#define FILAMAN_STATUS_ACTIVE    4
#define FILAMAN_STATUS_EMPTY     5
#define FILAMAN_STATUS_ARCHIVED  6
#define FILAMAN_STATUS_COUNT     6

// The key POST /api/v1/spools/{id}/status expects, or nullptr for an id the
// server invented after this firmware was built.
const char* filamanStatusKey(int status_id);

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

// Throws the cached location table away. It is keyed by nothing but time - a
// five minute TTL - so after a switch to a different FilaMan instance it would
// keep resolving ids that belong to the server just left, and writing them.
// There was no way to reach it from outside at all.
void filamanForgetLocations();

// --- ams slots -----------------------------------------------

// FilaMan has an endpoint built for exactly this job: /api/v1/display, "all
// active printers with their AMS slots". It arrives already grouped by unit,
// with kind telling an AMS, an AMS HT and the external holder apart, so no
// regrouping is needed on this side.
//
// Verified against FilaMan 1.3.1 on 11.09.2026, schema_version 3:
//   {"schema_version":3,"printers":[{"id":1,"name":"X1C","connected":null,
//     "ams":[{"ams_id":0,"kind":"ams","label":"AMS A","temperature":null,
//       "humidity":null,"slots":[{"slot":0,"label":"A1","empty":true,
//         "active":false,"color":"#202020","material":"","spool_id":null,
//         "remaining_percent":null,"remaining_grams":null}]}]}]}
// The external holder comes as one entry of kind "external" with ams_id 255
// and bays 254 and 255, an AMS HT as kind "ams_ht" with ams_id 128 and one
// bay. An empty bay carries a placeholder grey, so empty is the only thing
// that says a bay is free - never the colour.
//
// fields=full is asked for rather than fields=slots: the short form leaves
// out temperature, humidity and the gram figure, which is most of what the
// unit row shows.
//
// Needs a user API key whose principal has the display:read permission. A
// device token carrying that scope would do as well: the route is meant for
// panels and says so.
int  filamanGetAmsState(const char* base_url, const char* api_key,
       int printer_id, AmsSlotState& out, uint32_t timeout_ms = 8000);

// The printers, from the same endpoint in its short form. No second route
// and no pagination to walk: /api/v1/display already answers for every
// active printer, which is exactly the set worth offering.
int  filamanListPrinters(const char* base_url, const char* api_key,
       AmsPrinterList& out, uint32_t timeout_ms = 8000);
