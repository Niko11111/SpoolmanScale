#include "ota_state.h"

#include <stdio.h>

bool update_available = false;
bool gh_prerelease = false;

char gh_latest_version[32] = "";

volatile bool gh_flash_active = false;

bool g_upd_autocheck = true;
uint32_t g_upd_last_epoch = 0;

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
