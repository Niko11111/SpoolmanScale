#include "sd_logger.h"
#include "app/app_state.h"
#include "services/backend.h"

#include "pins.h"

#include <SD.h>
#include <SPI.h>
#include <WiFi.h>
#include <esp_system.h>
#include <stdarg.h>
#include <time.h>

#include "../app_config.h"

// WiFi state is still owned by main.cpp during this phase.

static SPIClass spiSD(HSPI);
bool sd_available = false;
bool sd_verbose = false;
// How many bytes the file named below already holds. A counter rather than a
// question to the card on every line, because this check sits in front of
// every single log call.
static unsigned long sd_log_size = 0;
// Which file that count belongs to. It used to belong to nothing in
// particular: it started at zero on every boot, so the cap was a megabyte per
// boot session rather than per day, which is what the plan asked for. Several
// restarts in a day pushed the file well past the limit, and a long uptime
// silenced the log while the file was still small.
static char sd_log_file[24] = "";

#define SD_LOG_MAX_SIZE  (1024UL * 1024UL)

// 240 lines is a few minutes of ordinary running and the whole of a boot,
// which is what this exists for. 38 kB, and it goes in PSRAM: the internal
// heap is the one that runs out.
#define LOG_RING_LINES 240
#define LOG_RING_WIDTH 160

static char             *ring      = nullptr;
static uint32_t         *ring_when = nullptr;   // UTC epoch, 0 before the clock is set
static uint32_t         *ring_up   = nullptr;   // seconds since boot
static uint16_t          ring_head = 0;   // next slot to write
static uint16_t          ring_used = 0;
static uint32_t          ring_seq  = 0;   // total ever written
static SemaphoreHandle_t ring_lock = nullptr;

void logRingInit() {
  if (ring) return;
  ring_lock = xSemaphoreCreateMutex();
  if (!ring_lock) return;
  // No fallback to the internal heap on purpose. 38 kB there would cost more
  // than the feature is worth, and a board without PSRAM simply logs to the
  // card as it always did.
  ring = (char *)heap_caps_malloc((size_t)LOG_RING_LINES * LOG_RING_WIDTH,
                                  MALLOC_CAP_SPIRAM);
  ring_when = (uint32_t *)heap_caps_malloc(LOG_RING_LINES * sizeof(uint32_t),
                                           MALLOC_CAP_SPIRAM);
  ring_up   = (uint32_t *)heap_caps_malloc(LOG_RING_LINES * sizeof(uint32_t),
                                           MALLOC_CAP_SPIRAM);
  if (!ring || !ring_when || !ring_up) {
    free(ring); free(ring_when); free(ring_up);
    ring = nullptr; ring_when = nullptr; ring_up = nullptr;
    return;
  }
  memset(ring, 0, (size_t)LOG_RING_LINES * LOG_RING_WIDTH);
  memset(ring_when, 0, LOG_RING_LINES * sizeof(uint32_t));
  memset(ring_up, 0, LOG_RING_LINES * sizeof(uint32_t));
}

static void ringPut(time_t when, const char *msg) {
  if (!ring || !ring_lock) return;
  // A log line is never worth blocking the loop for. Dropping one beats
  // holding up a weight reading.
  if (xSemaphoreTake(ring_lock, pdMS_TO_TICKS(20)) != pdTRUE) return;
  snprintf(ring + (size_t)ring_head * LOG_RING_WIDTH, LOG_RING_WIDTH, "%s", msg);
  ring_when[ring_head] = (uint32_t)when;
  ring_up[ring_head]   = (uint32_t)(millis() / 1000);
  ring_head = (uint16_t)((ring_head + 1) % LOG_RING_LINES);
  if (ring_used < LOG_RING_LINES) ring_used++;
  ring_seq++;
  xSemaphoreGive(ring_lock);
}

size_t logRingCount() { return ring_used; }
uint32_t logRingSeq()  { return ring_seq; }

bool logRingGetSeq(uint32_t seq, char *out, size_t out_len,
                   time_t *when, uint32_t *up_s) {
  if (!ring || !ring_lock || !out || out_len == 0) return false;
  if (xSemaphoreTake(ring_lock, pdMS_TO_TICKS(20)) != pdTRUE) return false;
  // Everything before this has been overwritten by newer lines.
  const uint32_t oldest = ring_seq - ring_used;
  bool ok = (seq >= oldest && seq < ring_seq);
  if (ok) {
    const size_t slot = seq % LOG_RING_LINES;
    snprintf(out, out_len, "%s", ring + slot * LOG_RING_WIDTH);
    if (when) *when = (time_t)ring_when[slot];
    if (up_s) *up_s = ring_up[slot];
  }
  xSemaphoreGive(ring_lock);
  return ok;
}

bool logRingGet(size_t idx, char *out, size_t out_len,
                time_t *when, uint32_t *up_s) {
  if (!ring || !ring_lock || !out || out_len == 0) return false;
  if (xSemaphoreTake(ring_lock, pdMS_TO_TICKS(20)) != pdTRUE) return false;
  bool ok = idx < ring_used;
  if (ok) {
    const size_t oldest = (ring_head + LOG_RING_LINES - ring_used) % LOG_RING_LINES;
    const size_t slot = (oldest + idx) % LOG_RING_LINES;
    snprintf(out, out_len, "%s", ring + slot * LOG_RING_WIDTH);
    if (when) *when = (time_t)ring_when[slot];
    if (up_s) *up_s = ring_up[slot];
  }
  xSemaphoreGive(ring_lock);
  return ok;
}

String getCurrentLogFilename() {
  struct tm t;
  if (!getLocalTime(&t)) {
    return String("/log_pre_ntp.txt");
  }
  char buf[32];
  snprintf(buf, sizeof(buf), "/log_%04d-%02d-%02d.txt",
    t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
  return String(buf);
}

void sdLogResetSize() {
  // Forgetting which file the count belonged to is the part that matters: the
  // next line then asks the card again. Deleting today's log on its own would
  // otherwise leave the old count standing over a file that is empty.
  sd_log_size = 0;
  sd_log_file[0] = '\0';
}

void logSD(const char* msg) {
  // Before the card is considered: this is what a device without one keeps.
  // With no clock yet, uptime says more than a row of question marks.
  struct tm now;
  const bool have_clock = getLocalTime(&now);
  char stamp[10];
  if (have_clock) {
    snprintf(stamp, sizeof(stamp), "%02d:%02d:%02d",
             now.tm_hour, now.tm_min, now.tm_sec);
  } else {
    strncpy(stamp, "??:??:??", sizeof(stamp) - 1);
    stamp[sizeof(stamp) - 1] = '\0';
  }
  // getLocalTime() answers yes as soon as the clock is set at all, and before
  // NTP that clock is wrong rather than absent. A year that cannot be right is
  // the tell; those lines carry uptime instead.
  const bool synced = have_clock && (now.tm_year + 1900) >= 2024;
  ringPut(synced ? time(nullptr) : (time_t)0, msg);

  if (!sd_available) return;

  String fname = getCurrentLogFilename();

  // A file the count does not belong to - a new day, the first line after a
  // restart, or the switch away from log_pre_ntp once the clock is set - means
  // asking the card how big it already is. One extra open per boot and per day
  // change; every line after that takes the cheap check below.
  if (strcmp(sd_log_file, fname.c_str()) != 0) {
    File probe = SD.open(fname.c_str(), FILE_READ);
    sd_log_size = probe ? (unsigned long)probe.size() : 0;
    if (probe) probe.close();
    strncpy(sd_log_file, fname.c_str(), sizeof(sd_log_file) - 1);
    sd_log_file[sizeof(sd_log_file) - 1] = '\0';
  }

  if (sd_log_size > SD_LOG_MAX_SIZE) return;

  File f = SD.open(fname.c_str(), FILE_APPEND);
  if (!f) return;
  size_t written = f.printf("[%s] %s\n", stamp, msg);
  f.close();
  sd_log_size += written;
}

void logSDf(const char* fmt, ...) {
  char buf[256];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  logSD(buf);
}

const char* resetReasonStr() {
  esp_reset_reason_t r = esp_reset_reason();
  switch (r) {
    case ESP_RST_UNKNOWN:    return "UNKNOWN";
    case ESP_RST_POWERON:    return "POWERON (cold boot)";
    case ESP_RST_EXT:        return "EXT (external pin)";
    case ESP_RST_SW:         return "SW (ESP.restart)";
    case ESP_RST_PANIC:      return "PANIC (exception/abort)";
    case ESP_RST_INT_WDT:    return "INT_WDT (interrupt watchdog)";
    case ESP_RST_TASK_WDT:   return "TASK_WDT (task watchdog)";
    case ESP_RST_WDT:        return "WDT (other watchdog)";
    case ESP_RST_DEEPSLEEP:  return "DEEPSLEEP (wake from sleep)";
    case ESP_RST_BROWNOUT:   return "BROWNOUT (voltage drop)";
    case ESP_RST_SDIO:       return "SDIO";
    default:                 return "OTHER";
  }
}

void writeBootBlock(const char* boot_or_reboot) {
  // One line in the session log, so a ring without a card still says which
  // firmware and which backend produced everything below it.
  char backend_ring[160];
  backendStatusLine(backend_ring, sizeof(backend_ring));
  logSDf("%s: SpoolmanScale %s | %s | %s", boot_or_reboot, FW_VERSION,
         resetReasonStr(), backend_ring);

  if (!sd_available) return;

  String fname = getCurrentLogFilename();
  File f = SD.open(fname.c_str(), FILE_APPEND);
  if (!f) return;

  char dt_buf[32];
  struct tm t;
  if (getLocalTime(&t)) {
    snprintf(dt_buf, sizeof(dt_buf), "%02d.%02d.%04d %02d:%02d:%02d",
      t.tm_mday, t.tm_mon + 1, t.tm_year + 1900,
      t.tm_hour, t.tm_min, t.tm_sec);
  } else {
    strncpy(dt_buf, "(time not synced)", sizeof(dt_buf)-1);
  }

  f.println("=====================================");
  f.printf("SpoolmanScale %s\n", FW_VERSION);
  f.printf("%s: %s\n", boot_or_reboot, dt_buf);
  f.printf("Reset reason: %s\n", resetReasonStr());
  if (wifi_ok) {
    f.printf("WiFi: %s | IP: %s\n",
      cfg_wifi_ssid, WiFi.localIP().toString().c_str());
  } else {
    f.println("WiFi: (not connected)");
  }
  // Which backend the device talks to. Without this a log tells nobody
  // whether Spoolman or FilaMan is in play, which is the first thing needed
  // to read the rest of the file.
  char backend_line[160];
  backendStatusLine(backend_line, sizeof(backend_line));
  f.printf("Backend: %s\n", backend_line);
  f.printf("Free heap: %d | PSRAM: %d\n",
    ESP.getFreeHeap(), ESP.getFreePsram());
  if (sd_verbose) f.println("Verbose logging: ON");
  f.println("=====================================");
  f.close();

  // Written past the cap and never counted. Dropping the count here makes the
  // next log line re-read the file, so the block's own bytes are included
  // instead of quietly buying the session a few hundred bytes of headroom.
  sdLogResetSize();
}

void cleanOldLogs() {
  if (!sd_available) return;

  struct tm now;
  if (!getLocalTime(&now)) {
    Serial.println("cleanOldLogs: no time -> skip");
    return;
  }

  time_t now_t = mktime(&now);
  time_t cutoff = now_t - (7 * 24 * 3600);

  File root = SD.open("/");
  if (!root || !root.isDirectory()) {
    Serial.println("cleanOldLogs: cannot open root");
    return;
  }

  int deleted = 0;
  File entry = root.openNextFile();
  while (entry) {
    String name = entry.name();
    if (entry.isDirectory()) {
      entry = root.openNextFile();
      continue;
    }

    String fname = name;
    if (!fname.startsWith("/")) fname = "/" + fname;

    if (fname.startsWith("/log_") && fname.endsWith(".txt") && fname.length() == 19) {
      int yyyy = fname.substring(5, 9).toInt();
      int mm   = fname.substring(10, 12).toInt();
      int dd   = fname.substring(13, 15).toInt();
      if (yyyy >= 2024 && mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31) {
        struct tm filedate = {};
        filedate.tm_year = yyyy - 1900;
        filedate.tm_mon  = mm - 1;
        filedate.tm_mday = dd;
        filedate.tm_hour = 12;
        time_t file_t = mktime(&filedate);
        if (file_t < cutoff) {
          entry.close();
          if (SD.remove(fname.c_str())) {
            deleted++;
            Serial.printf("cleanOldLogs: removed %s\n", fname.c_str());
          }
          entry = root.openNextFile();
          continue;
        }
      }
    }
    entry = root.openNextFile();
  }
  root.close();
  if (deleted > 0) Serial.printf("cleanOldLogs: %d file(s) deleted\n", deleted);
}

void initSD() {
  spiSD.begin(hw_pins::SD_SCK, hw_pins::SD_MISO, hw_pins::SD_MOSI, hw_pins::SD_CS);
  if (SD.begin(hw_pins::SD_CS, spiSD)) {
    sd_available = true;
    sd_verbose = SD.exists("/verbose.txt");
    uint8_t cardType = SD.cardType();
    const char* typeStr = "UNKNOWN";
    switch (cardType) {
      case CARD_MMC:  typeStr = "MMC";  break;
      case CARD_SD:   typeStr = "SDSC"; break;
      case CARD_SDHC: typeStr = "SDHC"; break;
      case CARD_NONE: typeStr = "NONE"; break;
    }
    uint64_t cardSize = SD.cardSize() / (1024 * 1024);
    Serial.printf("SD OK: type=%s size=%lluMB verbose=%s\n",
      typeStr, cardSize, sd_verbose ? "yes" : "no");
  } else {
    Serial.println("SD: not available (card missing or init failed)");
    sd_available = false;
  }
}
