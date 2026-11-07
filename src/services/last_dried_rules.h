#pragma once

#include <stddef.h>
#include <string.h>

// One drying date as a server stored it, brought into the form isoDayLocal()
// reads. Pure logic: no Arduino, no JSON, so a host test can run it
// (test/test_last_dried.py).

// Big enough for "2026-10-06T22:07:00.000000Z".
#define LAST_DRIED_ISO_MAX  32

// Whether the time part after 'T' names a zone: a Z, or an offset such as
// "+02:00". A '-' before the T belongs to the date and does not count.
inline bool lastDriedNamesZone(const char* t) {
  return strchr(t, 'Z') || strchr(t, '+') || strchr(t, '-');
}

// raw as a server stored it, in the form isoDayLocal() reads: surrounding
// quotes removed (Spoolman JSON-encodes extra values), and a Z added to a
// date-time that names no zone. A bare date is passed through. Empty out
// when raw is null, empty, or the JSON text null - Spooly sends that for a
// spool never dried, and shown as a date it would read "null".
inline void lastDriedUtc(const char* raw, char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  out[0] = '\0';
  if (!raw) return;

  size_t len = strlen(raw);
  if (len >= 2 && raw[0] == '"' && raw[len - 1] == '"') { raw++; len -= 2; }
  if (len == 0) return;
  if (len == 4 && strncmp(raw, "null", 4) == 0) return;
  if (len >= out_size) len = out_size - 1;
  memcpy(out, raw, len);
  out[len] = '\0';

  const char* t = strchr(out, 'T');
  if (!t || lastDriedNamesZone(t)) return;
  if (len + 1 < out_size) {
    out[len]     = 'Z';
    out[len + 1] = '\0';
  }
}
