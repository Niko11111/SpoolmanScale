#pragma once

#include <Arduino.h>

extern bool sd_available;
extern bool sd_verbose;

String getCurrentLogFilename();
void logSD(const char* msg);
void logSDf(const char* fmt, ...);
void initSD();
void cleanOldLogs();
void writeBootBlock(const char* boot_or_reboot);
