#pragma once
// ============================================================
//  dried_marker.h - the drying date the scale kept in a BamBuddy note
//
//  Before BamBuddy had a field for it (#2863), the scale wrote the drying
//  date into the spool's note as "[last_dried:YYYY-MM-DD]", the first builds
//  as "[dried:YYYY-MM-DD]". BamBuddy never writes either, so the exact shape
//  with a ten-character date is how a marker is known to be the scale's.
//  Pure text work, no network.
// ============================================================

#include <stddef.h>

// "YYYY-MM-DD" plus the terminator.
#define DRIED_MARKER_DAY_MAX  11

// The marker's day, a local calendar day without a zone. False when the note
// holds no marker of either spelling with a ten-character date.
bool driedMarkerParse(const char* note, char* day_out, size_t out_size);

// The note without the marker: the marker goes, with one of the spaces
// around it, and the ends are trimmed. The rest of the note stays as it was,
// a "[drying:...]" marker included. A note without a marker is copied as it
// is. out_size of strlen(note) + 1 is always enough.
void driedMarkerStrip(const char* note, char* out, size_t out_size);

// Whether the marker still says something the server's own field does not:
// true when native_day is empty or an earlier day. Both are local
// "YYYY-MM-DD" days, so the later one sorts higher.
bool driedMarkerNewer(const char* marker_day, const char* native_day);
