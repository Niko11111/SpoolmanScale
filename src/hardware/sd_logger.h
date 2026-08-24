#pragma once

#include <Arduino.h>

extern bool sd_available;
extern bool sd_verbose;

String getCurrentLogFilename();
void logSD(const char* msg);
void logSDf(const char* fmt, ...);
void initSD();
void cleanOldLogs();

// Makes the writer forget how big it believes today's log to be, so the next
// line asks the card again. Whoever deletes a log file calls this: the cap is
// a megabyte per file, and without it the old count keeps standing over a
// file that is no longer there - card free, log mute all the same.
void sdLogResetSize();
void writeBootBlock(const char* boot_or_reboot);
