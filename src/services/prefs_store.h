#pragma once

#include <Arduino.h>
#include <stdint.h>

// One namespace, one open per call. Every write reports whether it took:
// NVS is flash, and a full or worn partition turns a write into a silent
// no-op - the screen says "saved", the next boot has forgotten it. The
// failure is logged once a minute at most, so a broken partition does not
// bury the log under its own symptom.
String prefsGetString(const char* key, const char* default_value = "");
float prefsGetFloat(const char* key, float default_value);
int prefsGetInt(const char* key, int default_value);
uint32_t prefsGetUInt(const char* key, uint32_t default_value);
uint8_t prefsGetUChar(const char* key, uint8_t default_value);
bool prefsGetBool(const char* key, bool default_value);

bool prefsPutString(const char* key, const char* value);
bool prefsPutFloat(const char* key, float value);
bool prefsPutInt(const char* key, int value);
bool prefsPutUInt(const char* key, uint32_t value);
bool prefsPutUChar(const char* key, uint8_t value);
bool prefsPutBool(const char* key, bool value);
