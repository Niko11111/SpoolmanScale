#include "breadcrumb.h"

#include <Arduino.h>
#include <esp_attr.h>
#include <esp_idf_version.h>
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
  crumbWatchdogBegin();
}

// The task watchdog, as configured, watches the idle task of CPU 0 only
// (CONFIG_ESP_TASK_WDT_CHECK_IDLE_TASK_CPU0; the loop task is not subscribed).
// A TASK_WDT reset therefore means something on CPU 0 kept it busy for 5 s,
// and the crumb above, which is the loop's on CPU 1, cannot say what. The
// core calls this weak hook from the watchdog interrupt just before it aborts;
// the names of the two running tasks are copied by hand, nothing here may
// reach flash.
#define WDT_MAGIC     0x57445431u
#define WDT_NAME_LEN  16

RTC_NOINIT_ATTR static uint32_t s_wdt_magic;
RTC_NOINIT_ATTR static char     s_wdt_task[2][WDT_NAME_LEN];
static char s_wdt_prev[2 * WDT_NAME_LEN + 16] = "";

#ifndef SPOOLMANSCALE_SIM
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

extern "C" void IRAM_ATTR esp_task_wdt_isr_user_handler(void) {
  for (int cpu = 0; cpu < 2; cpu++) {
#if ESP_IDF_VERSION_MAJOR >= 5
    TaskHandle_t t = xTaskGetCurrentTaskHandleForCore(cpu);
#else
    TaskHandle_t t = xTaskGetCurrentTaskHandleForCPU(cpu);
#endif
    const char* n = t ? pcTaskGetName(t) : nullptr;
    int i = 0;
    for (; n && n[i] && i < WDT_NAME_LEN - 1; i++) s_wdt_task[cpu][i] = n[i];
    s_wdt_task[cpu][i] = '\0';
  }
  s_wdt_magic = WDT_MAGIC;
}
#endif

void crumbWatchdogBegin() {
  if (s_wdt_magic == WDT_MAGIC) {
    s_wdt_task[0][WDT_NAME_LEN - 1] = '\0';
    s_wdt_task[1][WDT_NAME_LEN - 1] = '\0';
    snprintf(s_wdt_prev, sizeof(s_wdt_prev), "cpu0=%s cpu1=%s",
             s_wdt_task[0], s_wdt_task[1]);
  }
  s_wdt_magic = 0;
}

const char* crumbWatchdogTasks()     { return s_wdt_prev; }

const char* crumbPrevious()          { return s_prev; }
uint32_t    crumbPreviousUptimeMs()  { return s_prev_uptime; }
