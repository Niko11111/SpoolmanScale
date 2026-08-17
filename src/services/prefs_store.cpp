#include "prefs_store.h"

#include <Preferences.h>

static const char* PREFS_NAMESPACE = "spoolscale";

String prefsGetString(const char* key, const char* default_value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  String value = prefs.getString(key, default_value);
  prefs.end();
  return value;
}

float prefsGetFloat(const char* key, float default_value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  float value = prefs.isKey(key) ? prefs.getFloat(key, default_value) : default_value;
  prefs.end();
  return value;
}

int prefsGetInt(const char* key, int default_value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  int value = prefs.getInt(key, default_value);
  prefs.end();
  return value;
}

uint32_t prefsGetUInt(const char* key, uint32_t default_value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  uint32_t value = prefs.getUInt(key, default_value);
  prefs.end();
  return value;
}

uint8_t prefsGetUChar(const char* key, uint8_t default_value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  uint8_t value = prefs.getUChar(key, default_value);
  prefs.end();
  return value;
}

bool prefsGetBool(const char* key, bool default_value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  bool value = prefs.getBool(key, default_value);
  prefs.end();
  return value;
}

void prefsPutString(const char* key, const char* value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  prefs.putString(key, value);
  prefs.end();
}

void prefsPutFloat(const char* key, float value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  prefs.putFloat(key, value);
  prefs.end();
}

void prefsPutInt(const char* key, int value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  prefs.putInt(key, value);
  prefs.end();
}

void prefsPutUInt(const char* key, uint32_t value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  prefs.putUInt(key, value);
  prefs.end();
}

void prefsPutUChar(const char* key, uint8_t value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  prefs.putUChar(key, value);
  prefs.end();
}

void prefsPutBool(const char* key, bool value) {
  Preferences prefs;
  prefs.begin(PREFS_NAMESPACE, false);
  prefs.putBool(key, value);
  prefs.end();
}
