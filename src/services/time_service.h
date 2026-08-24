#pragma once

#include <Arduino.h>

void syncNTP();

// POSIX TZ string, for example "CET-1CEST,M3.5.0,M10.5.0/3". Empty means UTC.
// Stored in preferences, applied at boot and whenever it is set.
String timeZoneGet();
void   timeZoneSet(const char *tz);

// Formats a UTC timestamp in the display zone. Borrows the C library's zone
// for the length of the call and hands it straight back, so nothing else -
// the SD log above all - sees a different clock.
void   timeZoneFormat(time_t when, char *out, size_t out_len);
String getTodayISO();
