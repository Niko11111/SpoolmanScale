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
// Allocated once at boot and lost on restart. Reads may come from the web
// task while the loop writes, so both sides take a mutex.
void   logRingInit();
size_t logRingCount();
// idx 0 is the oldest line still held. False when the ring is empty, the
// index is past the end, or the buffer could not be allocated.
//
// The line comes back without a timestamp; when is the UTC moment it was
// written, or 0 when the clock was not set yet and up_s holds seconds since
// boot instead. Rendering is the caller's business, which is what keeps the
// display zone out of this file.
bool   logRingGet(size_t idx, char *out, size_t out_len,
                  time_t *when, uint32_t *up_s);
void cleanOldLogs();

// Makes the writer forget how big it believes today's log to be, so the next
// line asks the card again. Whoever deletes a log file calls this: the cap is
// a megabyte per file, and without it the old count keeps standing over a
// file that is no longer there - card free, log mute all the same.
void sdLogResetSize();
void writeBootBlock(const char* boot_or_reboot);
