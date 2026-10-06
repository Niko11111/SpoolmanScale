#pragma once
// ============================================================
//  last_dried.h - one drying date out of the shapes servers store it in
//
//  The scale keeps the date in Spoolman's extra.last_dried as a UTC instant
//  with a Z. BamBuddy (#2863, from v1.2.6b1-daily.20261006) keeps its own:
//  last_dried_at on the spool, and in Spoolman mode the extra field
//  bambu_last_dried_at - both UTC, but written without the Z. isoDayLocal()
//  only converts a value that carries the Z, so without it a drying at 22:30
//  UTC would show on the wrong local day.
// ============================================================

#include <ArduinoJson.h>
#include <stddef.h>

// Big enough for "2026-10-06T22:07:00.000000Z".
#define LAST_DRIED_ISO_MAX  32

// raw as a server stored it, in the form isoDayLocal() reads: surrounding
// quotes removed (Spoolman JSON-encodes extra values), and a Z added to a
// date-time that names no zone. A bare date is passed through. Empty out
// when raw is null or empty.
void lastDriedUtc(const char* raw, char* out, size_t out_size);

// The later of extra.last_dried and extra.bambu_last_dried_at, each through
// lastDriedUtc(). Both are UTC once normalised, so the later one is the one
// that sorts higher. Empty out when neither is set.
void lastDriedNewest(JsonVariantConst extra, char* out, size_t out_size);
