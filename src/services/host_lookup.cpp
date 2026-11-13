#include "services/host_lookup.h"

#include <Arduino.h>
#include <Network.h>
#include <string.h>
#include <freertos/FreeRTOS.h>

#include "hardware/sd_logger.h"
#include "services/host_lookup_rules.h"
#include "services/worker_heap.h"

// The names that failed: the backend's own, perhaps the filament database's
// and GitHub's, so four is room to spare. A name too long for a slot is not
// remembered and is looked up every time, as it always was.
#define HOST_SLOTS         4
#define HOST_NAME_BYTES    96
// lwIP's getaddrinfo and a log line, no TLS in this task.
#define CHECK_STACK_BYTES  4096
#define CHECK_PRIORITY     1
#define CHECK_CORE         0

struct FailedHost {
  char     name[HOST_NAME_BYTES];   // empty: a free slot
  uint32_t checked_ms;              // when it was last looked up
};

// Read and written by the loop, the request workers and the check task.
static FailedHost   s_failed[HOST_SLOTS];
static bool         s_checking = false;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
// The check task's name, written only while s_checking is being set.
static char         s_check_name[HOST_NAME_BYTES];

// Holding s_lock.
static int findSlot(const char* host) {
  for (int i = 0; i < HOST_SLOTS; i++) {
    if (s_failed[i].name[0] && strcmp(s_failed[i].name, host) == 0) return i;
  }
  return -1;
}

// Holding s_lock: a free slot, or else the one looked up longest ago.
static int slotToFill(uint32_t now) {
  int oldest = 0;
  for (int i = 0; i < HOST_SLOTS; i++) {
    if (!s_failed[i].name[0]) return i;
    if (now - s_failed[i].checked_ms > now - s_failed[oldest].checked_ms) oldest = i;
  }
  return oldest;
}

// Marks the name as failed and restarts its pace. True when it was not
// marked before, which is when the log says so.
static bool markFailed(const char* host) {
  const size_t len = strlen(host);
  if (len >= HOST_NAME_BYTES) return true;
  const uint32_t now = millis();
  bool fresh = false;
  portENTER_CRITICAL(&s_lock);
  int i = findSlot(host);
  if (i < 0) {
    i = slotToFill(now);
    memcpy(s_failed[i].name, host, len + 1);
    fresh = true;
  }
  s_failed[i].checked_ms = now;
  portEXIT_CRITICAL(&s_lock);
  return fresh;
}

// True when the name had been marked.
static bool clearFailed(const char* host) {
  portENTER_CRITICAL(&s_lock);
  const int i = findSlot(host);
  if (i >= 0) s_failed[i].name[0] = '\0';
  portEXIT_CRITICAL(&s_lock);
  return i >= 0;
}

static void setChecking(bool on) {
  portENTER_CRITICAL(&s_lock);
  s_checking = on;
  portEXIT_CRITICAL(&s_lock);
}

static int lookUp(const char* host) {
  IPAddress ip;
  return Network.hostByName(host, ip);   // 1 on success, an lwIP error otherwise
}

// Kept out of the task function: the task deletes itself and never returns
// from it, see test/test_task_self_delete.py.
static void runCheck() {
  if (lookUp(s_check_name) != 1) {
    markFailed(s_check_name);
    return;
  }
  if (clearFailed(s_check_name)) logSDf("Backend: %s resolves again, requests go through", s_check_name);
}

static void checkTask(void*) {
  runCheck();
  setChecking(false);
  vTaskDelete(NULL);
}

static void startCheck(const char* host) {
  portENTER_CRITICAL(&s_lock);
  const bool busy = s_checking;
  s_checking = true;
  portEXIT_CRITICAL(&s_lock);
  if (busy) return;
  // The pace counts from this attempt, whether the task can start or not.
  markFailed(host);
  memcpy(s_check_name, host, strlen(host) + 1);   // marked, so it fits
  if (workerHeapReady(nullptr, workerFloorBackend(), CHECK_STACK_BYTES, nullptr) &&
      xTaskCreatePinnedToCore(checkTask, "dnscheck", CHECK_STACK_BYTES, nullptr,
                              CHECK_PRIORITY, nullptr, CHECK_CORE) == pdPASS) {
    return;
  }
  setChecking(false);
}

bool hostLookupOk(const char* host) {
  if (!host || !host[0] || host[0] == '[') return true;
  IPAddress literal;
  if (literal.fromString(host)) return true;

  const uint32_t now = millis();
  portENTER_CRITICAL(&s_lock);
  const int i = findSlot(host);
  const uint32_t since = i >= 0 ? now - s_failed[i].checked_ms : 0;
  const bool checking = s_checking;
  portEXIT_CRITICAL(&s_lock);

  switch (hostLookupStep(i >= 0, since, checking)) {
    case HOST_REFUSE:         return false;
    case HOST_REFUSE_RECHECK: startCheck(host); return false;
    case HOST_ASK:            break;
  }
  const int r = lookUp(host);
  if (r == 1) return true;
  if (markFailed(host)) {
    logSDf("Backend: %s does not resolve (DNS error %d), requests fail at once until it does", host, r);
  }
  return false;
}
