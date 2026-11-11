#pragma once

#include <stdint.h>

#include "services/tag_pending_rules.h"

// ============================================================
//  UNFINISHED TAG WRITE
//
//  The UID a write was started on and has not read back as written
//  yet. A spool lifted mid-write, a crash or a power cut leaves a
//  tag half written; its UID does not change, so the scale knows it
//  again when it is put back, says so and offers to finish it.
//
//    tagPendingArm()    a write job starts: what it is for (RAM)
//    tagPendingBegin()  the first block or page is about to go onto
//                       that tag: the marker goes to NVS
//    tagPendingDone()   the tag read back as written: marker gone
//    tagPendingDisarm() the job is over, whatever came of it; a
//                       marker already stored stays
//
//  One marker, not one per spool: the scale writes one tag at a
//  time, and a write begun on another tag replaces it. In NVS so it
//  outlives a restart in the middle of a write; a copy in RAM
//  answers every question after the first, so the scan pays one
//  compare for it and the flash is touched only by a write.
//
//  Loop task only, like every NFC write.
// ============================================================

void tagPendingArm(int spool_id, uint8_t fmt);
void tagPendingDisarm();

// Called by the page and block writers before every write; only the first one
// of an armed job stores anything.
void tagPendingBegin(const uint8_t* uid, uint8_t uid_len);

// The write onto this tag read back as written.
void tagPendingDone(const uint8_t* uid, uint8_t uid_len);

// The marker for this tag, if it is the one left unfinished.
bool tagPendingFor(const uint8_t* uid, uint8_t uid_len, TagPendingMark* out);

// True when the armed job is the very write that was cut short on this tag:
// same tag, same spool, same format. Only then may the MIFARE writer finish
// over what the cut left on it; another spool's write keeps the usual guards.
bool tagPendingResumes(const uint8_t* uid, uint8_t uid_len);

// The owner declined to finish the write on this tag.
void tagPendingDrop(const uint8_t* uid, uint8_t uid_len);

// Backend or host switched: the spool id in the marker names a spool on a
// server no longer in use, and finishing would write that spool's data.
void tagPendingForget();
