#include "breadcrumb.h"

#include <Arduino.h>
#include <esp_attr.h>
#include <cstring>

// RTC_NOINIT_ATTR is the point of the whole file: the startup code does not
// zero this memory, so it survives a panic, a watchdog and ESP.restart(). Only
// a power cycle clears it, which is why the magic exists - after one, these
// bytes are whatever the RAM happened to hold.
#define CRUMB_MAGIC   0x5350C817u
#define CRUMB_LEN     32

RTC_NOINIT_ATTR static uint32_t s_magic;
RTC_NOINIT_ATTR static char     s_crumb[CRUMB_LEN];
RTC_NOINIT_ATTR static uint32_t s_uptime_ms;

// What the previous boot left, copied out of RTC memory before this boot
// starts overwriting it.
static char     s_prev[CRUMB_LEN] = "";
static uint32_t s_prev_uptime     = 0;

void crumbSet(const char* where) {
  if (!where) return;
  s_magic = CRUMB_MAGIC;
  strncpy(s_crumb, where, CRUMB_LEN - 1);
  s_crumb[CRUMB_LEN - 1] = '\0';
  s_uptime_ms = millis();
}

void crumbBegin() {
  if (s_magic == CRUMB_MAGIC) {
    // A truncated write cannot terminate the string, and a corrupted cell
    // cannot either. Terminated here so nothing downstream reads past the end.
    s_crumb[CRUMB_LEN - 1] = '\0';
    strncpy(s_prev, s_crumb, CRUMB_LEN - 1);
    s_prev[CRUMB_LEN - 1] = '\0';
    s_prev_uptime = s_uptime_ms;
  } else {
    s_prev[0]     = '\0';
    s_prev_uptime = 0;
  }
  crumbSet("boot");
}

const char* crumbPrevious()          { return s_prev; }
uint32_t    crumbPreviousUptimeMs()  { return s_prev_uptime; }
