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

// ------------------------------------------------------------------
//  Writes parked while LVGL dispatches events
//
//  A flash write takes 10 to 100 ms and used to run inside the button
//  callback that changed the setting. While deferral is on, put*() parks
//  the value instead and returns true; the loop turns deferral off again as
//  soon as lv_timer_handler() returns and flushes, so nothing waits longer
//  than the rest of that pass. get*() answers from the parked value first,
//  so a callback that writes and reads back sees what it wrote. A parked
//  write that then fails is reported the same way a direct one is.
//
//  A restart from inside a callback has to flush by hand - that is the one
//  way a parked value could be lost. A factory reset discards instead, so
//  no setting is written back after the erase.
// ------------------------------------------------------------------
void prefsDeferWrites(bool on);
void prefsFlush();
void prefsDiscardWrites();
