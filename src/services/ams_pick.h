#pragma once

#include <stdint.h>

// ============================================================
//  AMS BAY PICK FLOW
//
//  What happens between weighing a spool and it being recorded
//  in a bay: the scale remembers what it saw, waits for the
//  spool to be lifted, and then offers the picker.
//
//  No HTTPClient here. Every request goes out through
//  backend_api, the same way ams_assign.cpp does it for
//  FilaMan's own, differently shaped AMS assignment.
//
//  The note is deliberately not shared with ams_assign.cpp.
//  There, already_reported carries a meaning that only exists
//  in FilaMan's model - the weight is already in and a yes
//  books it a second time, because that is the only thing that
//  opens a window. Here nothing opens a window and the request
//  carries no weight at all, so the note is simply smaller.
// ============================================================

// After this the offer is stale and the note is dropped. Nothing is lost:
// the weight was written when it was measured.
#define AMS_PICK_MAX_MS  120000

// True when the flow may run: a backend that can pin a spool to a bay, and
// the user has asked for it.
bool amsPickActive();

// Remembers the spool that was just weighed, so lifting it can offer the
// picker. The name is copied for the header line, not looked up again: the
// spool globals survive a removal by a minute and would still be readable,
// but a second spool landing in that minute would rename the first one's
// question.
void amsPickNote(int spool_id, const char* spool_name);

bool          amsPickHasPending();
int           amsPickPendingSpoolId();
unsigned long amsPickPendingAgeMs();
void          amsPickDropPending();

// Opens the picker for the remembered spool. Raises a flag only, so it is
// safe from anywhere.
void amsPickShow();

// Drops a note nobody acted on. Called from appLoop().
void amsPickTick();
