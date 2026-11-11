#pragma once

#include <stddef.h>
#include <stdint.h>

#include "services/ams_slots.h"

// ============================================================
//  AMS SOURCE
//
//  Spoolman keeps filament, not printers, so on that backend the AMS view
//  needs a second server that listens to the printer: today an OpenSpoolman
//  build that carries the AMS source routes, later any service that answers
//  the same contract. Configured on the backend web page; without an address
//  the Spoolman backend simply has no AMS view, as before.
//
//  The contract, version 1, under <base>/api/v1/ams-source:
//
//    GET  (the prefix itself)       {version, server{name, version},
//                                    capabilities[]}: what the source can do
//    GET  /printers                 [{id, name, connected}], ids from 1
//    GET  /printers/{id}/status     the printer's own shape (see
//                                   bambu_status.h) plus spool_id and
//                                   remain_g per bay
//    POST /printers/{id}/assign     {spool_id, ams_id, tray_id}
//    POST /printers/{id}/unassign   {ams_id, tray_id}
//
//  The spool ids are Spoolman's: the source books against the same database
//  the scale talks to. An optional key goes out as X-API-Key.
// ============================================================

// Long enough for "https://" plus a host name, a port and a path prefix.
#define AMS_SOURCE_HOST_MAX  96
#define AMS_SOURCE_KEY_MAX   80
// "OpenSpoolMan", "SpoolmanSync", and its version.
#define AMS_SOURCE_NAME_MAX  32
#define AMS_SOURCE_VER_MAX   16

// Reads address and key from NVS. Once at boot, beside the backend's own.
void amsSourceLoadSettings();

// The address as entered ("192.168.4.100:8001" or "https://..."), empty when
// none is set.
const char* amsSourceHost();
bool        amsSourceHasKey();

// An address is set. Says nothing about whether it answers.
bool amsSourceConfigured();

// Stores a new address, and a new key unless key is nullptr. An empty address
// switches the source off. False when a value does not fit. The key belongs to
// the address it was entered for: a changed address with key nullptr drops it,
// so it is never sent to a host nobody entered it for.
bool amsSourceSet(const char* host, const char* key);

// Whether storing `host` without a new key would drop a stored key: a key is
// stored and `host` is another, non-empty address. For a page to ask for the
// key instead of saving.
bool amsSourceHostNeedsKey(const char* host);

// What the source said about itself, asked once per address on the first
// printer list. Until it has answered, nothing is offered that needs a
// capability: a source that cannot assign must not get a bay picker.
bool        amsSourceKnown();
bool        amsSourceCanAssign();
bool        amsSourceCanUnassign();
const char* amsSourceServerName();      // empty until known
const char* amsSourceServerVersion();   // empty until known

int amsSourceListPrinters(AmsPrinterList& out, uint32_t timeout_ms);
int amsSourceGetState(int printer_id, AmsSlotState& out, uint32_t timeout_ms);
int amsSourceAssign(int spool_id, int printer_id, int ams_id, int tray_id,
                    uint32_t timeout_ms);
int amsSourceUnassign(int printer_id, int ams_id, int tray_id, uint32_t timeout_ms);
