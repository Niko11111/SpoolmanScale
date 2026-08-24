#pragma once

#include <Arduino.h>

extern bool sd_available;
extern bool sd_verbose;

String getCurrentLogFilename();
void logSD(const char* msg);
void logSDf(const char* fmt, ...);
void initSD();
void cleanOldLogs();

// Lifts the write cap. sd_log_size counts the bytes written since boot, not
// the bytes on the card, so deleting the files does not lower it by itself -
// and past a megabyte logSD() stops writing without a word. Freeing the card
// and leaving the writer muted until the next reboot would make deleting the
// logs a half measure, so whoever clears them calls this.
void sdLogResetSize();
void writeBootBlock(const char* boot_or_reboot);
