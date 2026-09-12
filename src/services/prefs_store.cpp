#include "prefs_store.h"

#include <Preferences.h>

#include "hardware/sd_logger.h"

static const char* PREFS_NAMESPACE = "spoolscale";

// How long the same failure stays quiet after it was logged once.
#define PREFS_FAIL_LOG_MS  60000UL

// A write or an open that did not take. Logged, not thrown: the caller has
// nothing better to do than carry on, but the log has to say why a setting
// came back on the next boot.
static void prefsReportFail(const char* what, const char* key) {
  static unsigned long last_ms = 0;
  if (last_ms && millis() - last_ms < PREFS_FAIL_LOG_MS) return;
  last_ms = millis();
  Serial.printf("NVS: %s of '%s' failed\n", what, key);
  logSDf("NVS: %s of '%s' failed - the setting will not survive a restart", what, key);
}

static bool prefsOpen(Preferences& prefs, const char* key) {
  if (prefs.begin(PREFS_NAMESPACE, false)) return true;
  prefsReportFail("open", key);
  return false;
}

// Guarded with isKey() the same way prefsGetFloat() is: getString() logs an
// ESP_LOGE on a key that is not there yet, and a setting whose default is
// "unset" would put a red NOT_FOUND line in every boot log for the life of
// the device. The value returned is the same either way.
String prefsGetString(const char* key, const char* default_value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return String(default_value);
  String value = prefs.isKey(key) ? prefs.getString(key, default_value)
                                  : String(default_value);
  prefs.end();
  return value;
}

float prefsGetFloat(const char* key, float default_value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return default_value;
  float value = prefs.isKey(key) ? prefs.getFloat(key, default_value) : default_value;
  prefs.end();
  return value;
}

int prefsGetInt(const char* key, int default_value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return default_value;
  int value = prefs.getInt(key, default_value);
  prefs.end();
  return value;
}

uint32_t prefsGetUInt(const char* key, uint32_t default_value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return default_value;
  uint32_t value = prefs.getUInt(key, default_value);
  prefs.end();
  return value;
}

uint8_t prefsGetUChar(const char* key, uint8_t default_value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return default_value;
  uint8_t value = prefs.getUChar(key, default_value);
  prefs.end();
  return value;
}

bool prefsGetBool(const char* key, bool default_value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return default_value;
  bool value = prefs.getBool(key, default_value);
  prefs.end();
  return value;
}

// put*() returns the number of bytes written, 0 on failure.
bool prefsPutString(const char* key, const char* value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putString(key, value) > 0 || (value && !value[0]);
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}

bool prefsPutFloat(const char* key, float value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putFloat(key, value) > 0;
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}

bool prefsPutInt(const char* key, int value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putInt(key, value) > 0;
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}

bool prefsPutUInt(const char* key, uint32_t value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putUInt(key, value) > 0;
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}

bool prefsPutUChar(const char* key, uint8_t value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putUChar(key, value) > 0;
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}

bool prefsPutBool(const char* key, bool value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putBool(key, value) > 0;
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}
