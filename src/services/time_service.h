#pragma once

#include <Arduino.h>

// One POSIX TZ string per zone, plus what to show for it.
//
// The POSIX form carries the switching rules, not just the offset, which is
// the whole reason this table exists: configTime() takes numbers, and numbers
// cannot say when summer time starts. See syncNTP() in the .cpp.
//
// The names are proper names and stay untranslated. "offset" is only a hint
// for the picker, never used for arithmetic.
struct TimeZoneEntry {
  const char *name;
  const char *tz;
  const char *offset;
};

extern const TimeZoneEntry TZ_LIST[];
extern const size_t        TZ_COUNT;

void syncNTP();

// The stored zone, or the one derived from the language on a device that has
// never been asked. German means central Europe, everything else means UTC:
// a language says something about the zone, but not enough to be binding.
String timeZoneGet();

// Stores the zone and applies it at once. No restart: tzset() takes effect on
// the next localtime_r(), so the next log line is already in the new zone.
void   timeZoneSet(const char *tz);

// Hands the stored zone to the C library. Called at boot, before anything
// formats a time, and again by timeZoneSet().
void   timeZoneApply();

// Display name of the stored zone, for the button that opens the picker.
// Falls back to the raw POSIX string for a zone that is not in the table.
const char* timeZoneName();

// Index into TZ_LIST, or -1 when the stored zone is not one of them.
int    timeZoneIndex();
