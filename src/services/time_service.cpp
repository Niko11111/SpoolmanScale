#include "time_service.h"

#include <time.h>

#include "services/prefs_store.h"

// The offsets used to be baked in as +1/+1, which is central Europe. Every
// timestamp the device produced was in that zone whatever the owner's own
// happened to be, log lines and last_used dates alike.
#define TZ_DEFAULT "CET-1CEST,M3.5.0,M10.5.0/3"

String timeZoneGet() { return prefsGetString("tz", TZ_DEFAULT); }

// Runs the body with the display zone in force and puts the old one back.
// Only the session log uses this. The system clock, and therefore everything
// written to the card, stays on whatever configTime() set - that side belongs
// to upstream and this must not move it.
void timeZoneFormat(time_t when, char *out, size_t out_len) {
  char saved[64] = "";
  const char *env = getenv("TZ");
  if (env) snprintf(saved, sizeof(saved), "%s", env);

  const String tz = timeZoneGet();
  setenv("TZ", tz.c_str(), 1);
  tzset();

  struct tm t;
  localtime_r(&when, &t);
  snprintf(out, out_len, "%02d:%02d:%02d", t.tm_hour, t.tm_min, t.tm_sec);

  if (saved[0]) setenv("TZ", saved, 1); else unsetenv("TZ");
  tzset();
}

void timeZoneSet(const char *tz) {
  prefsPutString("tz", tz ? tz : "");
}

void syncNTP() {
  configTime(3600, 3600, "pool.ntp.org", "time.nist.gov");
  Serial.print("NTP sync...");
  struct tm ti;
  for (int i = 0; i < 20; i++) {
    delay(500);
    if (getLocalTime(&ti)) {
      Serial.printf("OK! %02d.%02d.%04d\n", ti.tm_mday, ti.tm_mon + 1, ti.tm_year + 1900);
      return;
    }
    Serial.print(".");
  }
  Serial.println("NTP ERROR");
}

String getTodayISO() {
  struct tm ti;
  if (!getLocalTime(&ti)) return "2026-01-01";
  char buf[16];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02d", ti.tm_year + 1900, ti.tm_mon + 1, ti.tm_mday);
  return String(buf);
}
