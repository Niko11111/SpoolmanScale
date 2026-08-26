#include "ota_state.h"

#include <stdio.h>
#include <time.h>

#include <Arduino.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "services/prefs_store.h"

bool update_available = false;
bool gh_prerelease = false;

char gh_latest_version[40] = "";

volatile bool gh_flash_active = false;

bool g_upd_autocheck = true;
uint32_t g_upd_last_epoch = 0;

static uint32_t fw_since  = 0;
static bool     fw_stamped = false;

uint32_t firmwareInstalledAt() { return fw_since; }

void firmwareStampTick() {
  if (fw_stamped) return;
  const time_t now = time(nullptr);
  struct tm t;
  gmtime_r(&now, &t);
  // Before NTP the clock reads 1970, and a date from then is worse than none.
  if (t.tm_year + 1900 < 2024) return;
  fw_stamped = true;

  if (prefsGetString("fw_ver", "") == FW_VERSION) {
    fw_since = prefsGetUInt("fw_since", 0);
    return;
  }
  fw_since = (uint32_t)now;
  prefsPutString("fw_ver", FW_VERSION);
  prefsPutUInt("fw_since", fw_since);
  logSDf("Firmware %s recorded as installed", FW_VERSION);
}

static void fmtBytes(char* buf, size_t len, uint32_t bytes) {
  if (bytes >= 1048576UL) snprintf(buf, len, "%.2f MB", bytes / 1048576.0f);
  else                    snprintf(buf, len, "%lu KB", (unsigned long)(bytes / 1024UL));
}

void otaProgressLine(char* buf, size_t len, uint32_t done, uint32_t total) {
  char d[16];
  fmtBytes(d, sizeof(d), done);
  if (!total) { snprintf(buf, len, "%s", d); return; }
  char t[16];
  fmtBytes(t, sizeof(t), total);
  // The browser path measures the whole multipart body, so done can edge past
  // total by the envelope. Clamped, because 101 % reads as a fault.
  uint32_t pct = (uint32_t)((uint64_t)done * 100 / total);
  if (pct > 100) pct = 100;
  snprintf(buf, len, "%s / %s - %lu %%", d, t, (unsigned long)pct);
}
