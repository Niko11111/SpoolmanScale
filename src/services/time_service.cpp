#include "time_service.h"

#include <time.h>

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
