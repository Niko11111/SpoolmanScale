#include "prefs_store.h"

#include <Preferences.h>
#include <string.h>

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

// ------------------------------------------------------------------
//  The parking queue
// ------------------------------------------------------------------
// NVS keys are 15 characters at most; the queue holds a handful of entries,
// which is more than one event pass ever produces. A key written twice in one
// pass keeps one slot with the later value. When the queue is full or a
// string will not fit, the write goes straight to flash as it always did.
#define PREFS_Q_LEN      8
#define PREFS_Q_KEY_MAX  16
#define PREFS_Q_STR_MAX  96

enum PrefsType : uint8_t { PT_STRING, PT_FLOAT, PT_INT, PT_UINT, PT_UCHAR, PT_BOOL };

struct PrefsQueued {
  char      key[PREFS_Q_KEY_MAX];
  PrefsType type;
  union {
    float    f;
    int      i;
    uint32_t u;
    uint8_t  c;
    bool     b;
  } v;
  char      s[PREFS_Q_STR_MAX];
};

static PrefsQueued s_q[PREFS_Q_LEN];
static uint8_t     s_q_len   = 0;
static bool        s_defer   = false;

static PrefsQueued* prefsQueued(const char* key) {
  for (uint8_t i = 0; i < s_q_len; i++)
    if (strcmp(s_q[i].key, key) == 0) return &s_q[i];
  return nullptr;
}

// The slot for `key`: the existing one if the key is already parked, else a
// fresh one. Null when the queue is full or the key does not fit - the
// caller then writes directly.
static PrefsQueued* prefsPark(const char* key, PrefsType type) {
  if (!s_defer || strlen(key) >= PREFS_Q_KEY_MAX) return nullptr;
  PrefsQueued* q = prefsQueued(key);
  if (!q) {
    if (s_q_len >= PREFS_Q_LEN) return nullptr;
    q = &s_q[s_q_len++];
    strncpy(q->key, key, PREFS_Q_KEY_MAX - 1);
    q->key[PREFS_Q_KEY_MAX - 1] = '\0';
  }
  q->type = type;
  return q;
}

static bool prefsWriteString(const char* key, const char* value);
static bool prefsWriteFloat(const char* key, float value);
static bool prefsWriteInt(const char* key, int value);
static bool prefsWriteUInt(const char* key, uint32_t value);
static bool prefsWriteUChar(const char* key, uint8_t value);
static bool prefsWriteBool(const char* key, bool value);

void prefsDeferWrites(bool on) { s_defer = on; }

void prefsDiscardWrites() { s_q_len = 0; }

void prefsFlush() {
  // Taken off the queue before it is written, so a failure report cannot
  // find the entry still parked and a re-entrant put*() starts clean.
  PrefsQueued batch[PREFS_Q_LEN];
  const uint8_t n = s_q_len;
  memcpy(batch, s_q, sizeof(PrefsQueued) * n);
  s_q_len = 0;
  const bool was_deferring = s_defer;
  s_defer = false;
  for (uint8_t i = 0; i < n; i++) {
    const PrefsQueued& q = batch[i];
    switch (q.type) {
      case PT_STRING: prefsWriteString(q.key, q.s);   break;
      case PT_FLOAT:  prefsWriteFloat(q.key, q.v.f);  break;
      case PT_INT:    prefsWriteInt(q.key, q.v.i);    break;
      case PT_UINT:   prefsWriteUInt(q.key, q.v.u);   break;
      case PT_UCHAR:  prefsWriteUChar(q.key, q.v.c);  break;
      case PT_BOOL:   prefsWriteBool(q.key, q.v.b);   break;
    }
  }
  s_defer = was_deferring;
}

// Guarded with isKey() the same way prefsGetFloat() is: getString() logs an
// ESP_LOGE on a key that is not there yet, and a setting whose default is
// "unset" would put a red NOT_FOUND line in every boot log for the life of
// the device. The value returned is the same either way.
String prefsGetString(const char* key, const char* default_value) {
  if (const PrefsQueued* q = prefsQueued(key)) if (q->type == PT_STRING) return String(q->s);
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return String(default_value);
  String value = prefs.isKey(key) ? prefs.getString(key, default_value)
                                  : String(default_value);
  prefs.end();
  return value;
}

bool prefsHasKey(const char* key) {
  if (prefsQueued(key)) return true;
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool there = prefs.isKey(key);
  prefs.end();
  return there;
}

float prefsGetFloat(const char* key, float default_value) {
  if (const PrefsQueued* q = prefsQueued(key)) if (q->type == PT_FLOAT) return q->v.f;
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return default_value;
  float value = prefs.isKey(key) ? prefs.getFloat(key, default_value) : default_value;
  prefs.end();
  return value;
}

int prefsGetInt(const char* key, int default_value) {
  if (const PrefsQueued* q = prefsQueued(key)) if (q->type == PT_INT) return q->v.i;
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return default_value;
  int value = prefs.getInt(key, default_value);
  prefs.end();
  return value;
}

uint32_t prefsGetUInt(const char* key, uint32_t default_value) {
  if (const PrefsQueued* q = prefsQueued(key)) if (q->type == PT_UINT) return q->v.u;
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return default_value;
  uint32_t value = prefs.getUInt(key, default_value);
  prefs.end();
  return value;
}

uint8_t prefsGetUChar(const char* key, uint8_t default_value) {
  if (const PrefsQueued* q = prefsQueued(key)) if (q->type == PT_UCHAR) return q->v.c;
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return default_value;
  uint8_t value = prefs.getUChar(key, default_value);
  prefs.end();
  return value;
}

bool prefsGetBool(const char* key, bool default_value) {
  if (const PrefsQueued* q = prefsQueued(key)) if (q->type == PT_BOOL) return q->v.b;
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return default_value;
  bool value = prefs.getBool(key, default_value);
  prefs.end();
  return value;
}

// ------------------------------------------------------------------
//  Writes
// ------------------------------------------------------------------
bool prefsPutString(const char* key, const char* value) {
  if (!value) value = "";
  if (strlen(value) < PREFS_Q_STR_MAX) {
    if (PrefsQueued* q = prefsPark(key, PT_STRING)) {
      strncpy(q->s, value, PREFS_Q_STR_MAX - 1);
      q->s[PREFS_Q_STR_MAX - 1] = '\0';
      return true;
    }
  }
  return prefsWriteString(key, value);
}
bool prefsPutFloat(const char* key, float value) {
  if (PrefsQueued* q = prefsPark(key, PT_FLOAT)) { q->v.f = value; return true; }
  return prefsWriteFloat(key, value);
}
bool prefsPutInt(const char* key, int value) {
  if (PrefsQueued* q = prefsPark(key, PT_INT)) { q->v.i = value; return true; }
  return prefsWriteInt(key, value);
}
bool prefsPutUInt(const char* key, uint32_t value) {
  if (PrefsQueued* q = prefsPark(key, PT_UINT)) { q->v.u = value; return true; }
  return prefsWriteUInt(key, value);
}
bool prefsPutUChar(const char* key, uint8_t value) {
  if (PrefsQueued* q = prefsPark(key, PT_UCHAR)) { q->v.c = value; return true; }
  return prefsWriteUChar(key, value);
}
bool prefsPutBool(const char* key, bool value) {
  if (PrefsQueued* q = prefsPark(key, PT_BOOL)) { q->v.b = value; return true; }
  return prefsWriteBool(key, value);
}

// Preferences::put*() returns the number of bytes written, 0 on failure.
static bool prefsWriteString(const char* key, const char* value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putString(key, value) > 0 || (value && !value[0]);
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}

static bool prefsWriteFloat(const char* key, float value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putFloat(key, value) > 0;
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}

static bool prefsWriteInt(const char* key, int value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putInt(key, value) > 0;
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}

static bool prefsWriteUInt(const char* key, uint32_t value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putUInt(key, value) > 0;
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}

static bool prefsWriteUChar(const char* key, uint8_t value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putUChar(key, value) > 0;
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}

static bool prefsWriteBool(const char* key, bool value) {
  Preferences prefs;
  if (!prefsOpen(prefs, key)) return false;
  const bool ok = prefs.putBool(key, value) > 0;
  prefs.end();
  if (!ok) prefsReportFail("write", key);
  return ok;
}
