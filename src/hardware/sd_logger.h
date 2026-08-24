#pragma once

#include <Arduino.h>

extern bool sd_available;
extern bool sd_verbose;

String getCurrentLogFilename();
void logSD(const char* msg);
void logSDf(const char* fmt, ...);
void initSD();

// ---- session log --------------------------------------------------
//
// Every line also lands in a ring buffer in PSRAM, whether or not a card is
// fitted. Without one that ring is the only log the device has, which is
// exactly the case where somebody is trying to find out why something did
// not work. The card is for keeping logs, not for having them.
//
// Allocated once at boot and lost on restart. The mutex costs nothing and is
// kept because the web handler is the reader: it runs from appLoop() today,
// but that is a scheduling detail this file should not depend on.
void   logRingInit();
size_t logRingCount();

// Lines written since boot, counting the ones already overwritten. A reader
// that remembers this number can ask for what it has not seen instead of
// fetching the whole ring, which is what makes following the log cheap.
uint32_t logRingSeq();

// One line by its absolute sequence number. False when that line has already
// been overwritten, which tells a reader its cursor is stale.
//
// The line comes back without a timestamp: when is the UTC moment it was
// written, or 0 if the clock was not set yet, in which case up_s holds
// seconds since boot instead. Rendering is the caller's business.
bool   logRingGetSeq(uint32_t seq, char *out, size_t out_len,
                     time_t *when, uint32_t *up_s);
void cleanOldLogs();

// Makes the writer forget how big it believes today's log to be, so the next
// line asks the card again. Whoever deletes a log file calls this: the cap is
// a megabyte per file, and without it the old count keeps standing over a
// file that is no longer there - card free, log mute all the same.
void sdLogResetSize();
void writeBootBlock(const char* boot_or_reboot);
