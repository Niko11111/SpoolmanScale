#include "sd_logger.h"
#include "app/app_state.h"

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
static unsigned long sd_log_size = 0;

#define SD_LOG_MAX_SIZE  (1024UL * 1024UL)

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

void logSD(const char* msg) {
  if (!sd_available) return;
  if (sd_log_size > SD_LOG_MAX_SIZE) return;

  char timestamp[10];
  struct tm t;
  if (getLocalTime(&t)) {
    snprintf(timestamp, sizeof(timestamp), "%02d:%02d:%02d",
      t.tm_hour, t.tm_min, t.tm_sec);
  } else {
    strncpy(timestamp, "??:??:??", sizeof(timestamp)-1);
  }

  String fname = getCurrentLogFilename();
  File f = SD.open(fname.c_str(), FILE_APPEND);
  if (!f) return;
  size_t written = f.printf("[%s] %s\n", timestamp, msg);
  f.close();
  sd_log_size += written;
}

void logSDf(const char* fmt, ...) {
  if (!sd_available) return;
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
  f.printf("Free heap: %d | PSRAM: %d\n",
    ESP.getFreeHeap(), ESP.getFreePsram());
  if (sd_verbose) f.println("Verbose logging: ON");
  f.println("=====================================");
  f.close();
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
