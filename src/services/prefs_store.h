#pragma once

#include <Arduino.h>
#include <stdint.h>

String prefsGetString(const char* key, const char* default_value = "");
float prefsGetFloat(const char* key, float default_value);
int prefsGetInt(const char* key, int default_value);
uint32_t prefsGetUInt(const char* key, uint32_t default_value);
uint8_t prefsGetUChar(const char* key, uint8_t default_value);
bool prefsGetBool(const char* key, bool default_value);

void prefsPutString(const char* key, const char* value);
void prefsPutFloat(const char* key, float value);
void prefsPutInt(const char* key, int value);
void prefsPutUInt(const char* key, uint32_t value);
void prefsPutUChar(const char* key, uint8_t value);
void prefsPutBool(const char* key, bool value);
void prefsPutBoolInNamespace(const char* ns, const char* key, bool value);
