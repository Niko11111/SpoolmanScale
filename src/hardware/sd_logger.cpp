#include "sd_logger.h"

#include "services/loop_task.h"
#include "app/app_state.h"
#include "services/backend.h"
#include "services/breadcrumb.h"
#include "services/prefs_store.h"

#include "pins.h"
#include "flash_log.h"

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

// The old switch, kept for one reason only: it is still written alongside the
// new key so a device that is put back on an older firmware finds what it
// expects instead of logging again after somebody switched it off.
#define SD_LOG_PREF_KEY "sd_log"
#define LOG_DEST_PREF_KEY "log_dest"
#define LOG_LVL_PREF_KEY  "log_lvl"

static LogDest  s_dest = LOG_DEST_SD;
static LogLevel s_lvl  = LOG_LVL_NORMAL;
// What this boot can really do. Set once initSD() knows whether a card came
// up and whether the ring in flash opened.
static LogDest  s_dest_eff = LOG_DEST_OFF;

static const char* destName(LogDest d) {
  switch (d) {
    case LOG_DEST_SD:       return "SD card";
    case LOG_DEST_INTERNAL: return "internal storage";
    default:                return "off";
  }
}

static const char* levelName(LogLevel l) {
  switch (l) {
    case LOG_LVL_VERBOSE: return "verbose";
    case LOG_LVL_NORMAL:  return "normal";
    default:              return "minimal";
  }
}


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

// Per file, not per day: a full file is rotated to .1 and a fresh one starts,
// so a busy day costs at most twice this. cleanOldLogs() drops everything
// older than a week, which caps the whole store at 14 files - a rounding
// error on any card this firmware will ever see. The old value was 1 MB and
// came from v0.5.9-beta with no reason recorded; a single day of verbose
// logging hit it and the log then went silent for the rest of the day.
#define SD_LOG_MAX_SIZE  (8UL * 1024UL * 1024UL)

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

// getLocalTime() waits up to five seconds for a clock that is not set, with a
// delay(10) between attempts, and this is asked once per log line. Before NTP
// that turns every line into a five second stall: twenty seconds of boot, and
// in AP setup mode, where the clock is never set at all, it never stops.
//
// The question is only whether the year is plausible, and that needs no
// waiting. A year before 2024 means the clock is running from the epoch
// rather than from the network.
static bool clockReady(struct tm *out) {
  const time_t now = time(nullptr);
  struct tm t;
  localtime_r(&now, &t);
  if (t.tm_year + 1900 < 2024) return false;
  if (out) *out = t;
  return true;
}

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

// The moment, not a rendered stamp. The device runs in the owner's zone, so
// formatting belongs where the line is read - and a stored string could not be
// re-rendered after the zone changes.
static void ringPut(time_t when, const char *msg) {
  if (!ring || !ring_lock) return;
  // Verbose lines are two per screen visit and would evict everything worth
  // keeping from 240 slots. They still go to the card, which is where anyone
  // who switched them on is looking.
  if (strncmp(msg, "[verbose]", 9) == 0) return;
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

String getCurrentLogFilename() {
  struct tm t;
  // clockReady() rather than getLocalTime(): the answer is the same and it
  // does not stall five seconds per line while the clock is unset. This is
  // most of what made a fitted card add twenty seconds to a boot.
  if (!clockReady(&t)) {
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

// Lines written from a task other than the loop's. The card is the loop's:
// two tasks appending to the same file through the SD library corrupt the
// file and sometimes the driver. So a line from the web worker is parked here
// with its stamp and written by sdLoggerTick() on the next loop pass.
#define SD_QUEUE_LEN      8
#define SD_QUEUE_LINE_MAX 160
struct QueuedLine { char stamp[10]; char msg[SD_QUEUE_LINE_MAX]; time_t when; uint32_t up_s; };
static QueuedLine     s_queue[SD_QUEUE_LEN];
static uint8_t        s_queue_len = 0;
static portMUX_TYPE   s_queue_mux = portMUX_INITIALIZER_UNLOCKED;

static void sdWriteLine(const char* stamp, const char* msg);

// The longest a single line held up the loop since the last
// sdWriteMaxTakeMs(). Every line is an open, an append and a close on the
// card, and all of them run on the loop task.
static uint32_t s_write_max_ms = 0;

// The only place a line is judged. It sits behind the session ring on
// purpose: what "smallest scope" leaves out is still worth seeing live in the
// browser, it is just not worth a flash write and a place in the history.
//
// What MIN drops is the screen trace, 115 of the roughly 763 call sites. On a
// real day that is small: of 13,179 lines on 19.09.2026, 10,682 were verbose
// and only 190 were this trace. The scope that saves the space is VERBOSE
// being off; MIN saves the last 1.4 percent on top.
//
// BTN: stays, because what somebody pressed is the most useful thing there is
// for working out what happened before a fault, and it is cheap: 33 lines in
// that whole day.
static bool logLineWanted(const char* msg) {
  if (!msg) return false;
  if (strncmp(msg, "[verbose]", 9) == 0) return s_lvl >= LOG_LVL_VERBOSE;
  if (s_lvl > LOG_LVL_MIN) return true;
  static const char* const SCREEN_TRACE[] = { "SHOW:", "UI:", "BUILD:" };
  for (size_t i = 0; i < sizeof(SCREEN_TRACE) / sizeof(SCREEN_TRACE[0]); i++) {
    const size_t n = strlen(SCREEN_TRACE[i]);
    if (strncmp(msg, SCREEN_TRACE[i], n) == 0) return false;
  }
  return true;
}

// One figure for both destinations, because only one of them is ever active.
// That keeps the number in the perf line comparable with the 26 to 28 ms the
// card was measured at.
static void writeLineTimed(const char* stamp, const char* msg,
                           time_t when, uint32_t up_s) {
  const unsigned long write_start_ms = millis();
  if (s_dest_eff == LOG_DEST_INTERNAL) {
    flashLogWrite(when, up_s, msg);
  } else if (s_dest_eff == LOG_DEST_SD) {
    sdWriteLine(stamp, msg);
  }
  const uint32_t write_ms = (uint32_t)(millis() - write_start_ms);
  if (write_ms > s_write_max_ms) s_write_max_ms = write_ms;
}

uint32_t sdWriteMaxTakeMs() {
  const uint32_t taken = s_write_max_ms;
  s_write_max_ms = 0;
  return taken;
}

static void queueLine(const char* stamp, const char* msg, time_t when) {
  portENTER_CRITICAL(&s_queue_mux);
  if (s_queue_len < SD_QUEUE_LEN) {
    QueuedLine& q = s_queue[s_queue_len++];
    strncpy(q.stamp, stamp, sizeof(q.stamp) - 1); q.stamp[sizeof(q.stamp) - 1] = '\0';
    strncpy(q.msg, msg, sizeof(q.msg) - 1);       q.msg[sizeof(q.msg) - 1] = '\0';
    q.when = when;
    q.up_s = (uint32_t)(millis() / 1000);
  }
  portEXIT_CRITICAL(&s_queue_mux);
}

void sdLoggerTick() {
  if (!s_queue_len) return;
  QueuedLine batch[SD_QUEUE_LEN];
  uint8_t n;
  portENTER_CRITICAL(&s_queue_mux);
  n = s_queue_len;
  memcpy(batch, s_queue, sizeof(QueuedLine) * n);
  s_queue_len = 0;
  portEXIT_CRITICAL(&s_queue_mux);
  for (uint8_t i = 0; i < n; i++)
    writeLineTimed(batch[i].stamp, batch[i].msg, batch[i].when, batch[i].up_s);
}

void logSD(const char* msg) {
  // Before the card is considered: this is what a device without one keeps.
  // The ring has its own lock, so this part is safe from any task.
  struct tm now;
  const bool synced = clockReady(&now);
  ringPut(synced ? time(nullptr) : (time_t)0, msg);

  char stamp[10];
  if (synced) {
    snprintf(stamp, sizeof(stamp), "%02d:%02d:%02d",
             now.tm_hour, now.tm_min, now.tm_sec);
  } else {
    strncpy(stamp, "??:??:??", sizeof(stamp) - 1);
    stamp[sizeof(stamp) - 1] = '\0';
  }

  if (!logLineWanted(msg)) return;
  if (s_dest_eff == LOG_DEST_OFF) return;
  if (s_dest_eff == LOG_DEST_SD && !sd_available) return;
  const time_t when = synced ? time(nullptr) : (time_t)0;
  if (!onLoopTask()) { queueLine(stamp, msg, when); return; }
  writeLineTimed(stamp, msg, when, (uint32_t)(millis() / 1000));
}

static void sdWriteLine(const char* stamp, const char* msg) {

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

  // Full means start a new one, never stop. Stopping is how a panic three
  // hours after the cap was reached came to leave no trace at all, in a file
  // that looked complete because the boot block after it is written past
  // this check.
  if (sd_log_size > SD_LOG_MAX_SIZE) {
    String rotated = fname;
    rotated.replace(".txt", ".1.txt");
    SD.remove(rotated.c_str());            // only one generation is kept
    if (SD.rename(fname.c_str(), rotated.c_str())) {
      sd_log_size = 0;
      File f = SD.open(fname.c_str(), FILE_APPEND);
      if (f) {
        size_t w = f.printf("[%s] --- continued, previous part is %s ---\n",
                            stamp, rotated.c_str());
        f.close();
        sd_log_size += w;
      }
    } else {
      // Rotation failed - carry on writing rather than going quiet. A file
      // growing past the cap is a far smaller problem than a blind spot.
      Serial.printf("logSD: rotate to %s failed, continuing in place\n",
                    rotated.c_str());
      sd_log_size = 0;
    }
  }

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

  // What the previous boot was doing when it stopped. Only worth a line when
  // it did not stop on purpose: after a clean restart the crumb names the
  // restart, which says nothing anyone needs.
  const esp_reset_reason_t rr = esp_reset_reason();
  const bool crashed = (rr == ESP_RST_PANIC || rr == ESP_RST_INT_WDT ||
                        rr == ESP_RST_TASK_WDT || rr == ESP_RST_WDT ||
                        rr == ESP_RST_BROWNOUT);
  if (crashed && crumbPrevious()[0]) {
    logSDf("Last seen before the reset: %s (after %lus)",
           crumbPrevious(), (unsigned long)(crumbPreviousUptimeMs() / 1000));
  }
  if (rr == ESP_RST_TASK_WDT && crumbWatchdogTasks()[0]) {
    logSDf("Task watchdog: running then %s", crumbWatchdogTasks());
  }

  if (s_dest_eff == LOG_DEST_OFF) return;

  // Built once and handed to whichever destination is active, so the card and
  // the flash ring carry the same block rather than two versions of it.
  char dt_buf[32];
  struct tm t;
  if (getLocalTime(&t)) {
    snprintf(dt_buf, sizeof(dt_buf), "%02d.%02d.%04d %02d:%02d:%02d",
      t.tm_mday, t.tm_mon + 1, t.tm_year + 1900,
      t.tm_hour, t.tm_min, t.tm_sec);
  } else {
    strncpy(dt_buf, "(time not synced)", sizeof(dt_buf)-1);
    dt_buf[sizeof(dt_buf)-1] = '\0';
  }

  char backend_line[160];
  backendStatusLine(backend_line, sizeof(backend_line));

  String block;
  block.reserve(512);
  block += F("=====================================\n");
  block += "SpoolmanScale " FW_VERSION "\n";
  block += String(boot_or_reboot) + ": " + dt_buf + "\n";
  block += String("Reset reason: ") + resetReasonStr() + "\n";
  if (crashed && crumbPrevious()[0]) {
    block += "Last seen before the reset: " + String(crumbPrevious()) +
             " (after " + String((unsigned long)(crumbPreviousUptimeMs() / 1000)) + "s)\n";
  }
  if (wifi_ok) {
    block += "WiFi: " + String(cfg_wifi_ssid) + " | IP: " +
             WiFi.localIP().toString() + "\n";
  } else {
    block += F("WiFi: (not connected)\n");
  }
  // Which backend the device talks to. Without this a log tells nobody
  // whether Spoolman or FilaMan is in play, which is the first thing needed
  // to read the rest of the file.
  block += String("Backend: ") + backend_line + "\n";
  block += "Free heap: " + String(ESP.getFreeHeap()) +
           " | PSRAM: " + String(ESP.getFreePsram()) + "\n";
  block += String("Log: ") + destName(s_dest_eff) + ", scope " + levelName(s_lvl) + "\n";
  block += F("=====================================\n");

  if (s_dest_eff == LOG_DEST_INTERNAL) {
    // A record per line, so the ring renders the block the way it renders
    // everything else and the reader needs no special case.
    int from = 0;
    while (from < (int)block.length()) {
      const int nl = block.indexOf('\n', from);
      const int to = (nl < 0) ? block.length() : nl;
      if (to > from) {
        const String one = block.substring(from, to);
        flashLogWrite(getLocalTime(&t) ? time(nullptr) : (time_t)0,
                      (uint32_t)(millis() / 1000), one.c_str());
      }
      from = to + 1;
    }
    return;
  }

  if (!sd_available) return;
  String fname = getCurrentLogFilename();
  File f = SD.open(fname.c_str(), FILE_APPEND);
  if (!f) return;
  f.print(block);
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

    // 19 is "/log_YYYY-MM-DD.txt"; a rotated part is longer ("...-24.1.txt")
    // and must be matched too, or it would never be cleaned up and the week's
    // worth of logs would grow without limit.
    if (fname.startsWith("/log_") && fname.endsWith(".txt") && fname.length() >= 19) {
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

// What the owner wants, read once. A getter cannot tell "never stored" from
// "stored as the default", which is why prefsHasKey() exists: an upgraded
// device has to keep doing what it did, a fresh one starts on the flash.
static void loadLogSettings() {
  if (prefsHasKey(LOG_DEST_PREF_KEY)) {
    const uint8_t v = prefsGetUChar(LOG_DEST_PREF_KEY, (uint8_t)LOG_DEST_INTERNAL);
    s_dest = (v > LOG_DEST_INTERNAL) ? LOG_DEST_INTERNAL : (LogDest)v;
  } else if (prefsHasKey(SD_LOG_PREF_KEY)) {
    // Whether a card happens to be in the slot today says nothing about what
    // the owner wants, so it plays no part in this. The card question is
    // asked again on every boot, in applyEffectiveDest().
    s_dest = prefsGetBool(SD_LOG_PREF_KEY, true) ? LOG_DEST_SD : LOG_DEST_OFF;
    prefsPutUChar(LOG_DEST_PREF_KEY, (uint8_t)s_dest);
  } else {
    s_dest = LOG_DEST_INTERNAL;          // a device out of the box
  }

  if (prefsHasKey(LOG_LVL_PREF_KEY)) {
    const uint8_t v = prefsGetUChar(LOG_LVL_PREF_KEY, (uint8_t)LOG_LVL_MIN);
    s_lvl = (v > LOG_LVL_VERBOSE) ? LOG_LVL_VERBOSE : (LogLevel)v;
  } else {
    // A device that was already writing to a card keeps the scope it had;
    // nothing about its log should change because of this update.
    s_lvl = (s_dest == LOG_DEST_SD) ? LOG_LVL_NORMAL : LOG_LVL_MIN;
    prefsPutUChar(LOG_LVL_PREF_KEY, (uint8_t)s_lvl);
  }
  sd_verbose = (s_lvl >= LOG_LVL_VERBOSE);
}

// A destination that is not there falls back rather than going quiet, and the
// stored wish stays untouched so the card coming back restores it by itself.
static void applyEffectiveDest() {
  LogDest want = s_dest;
  if (want == LOG_DEST_SD && !sd_available) {
    want = flashLogAvailable() ? LOG_DEST_INTERNAL : LOG_DEST_OFF;
  } else if (want == LOG_DEST_INTERNAL && !flashLogAvailable()) {
    want = sd_available ? LOG_DEST_SD : LOG_DEST_OFF;
  }
  s_dest_eff = want;
}

void initSD() {
  // setup() runs on the same task loop() does, so this is the loop task.
  loopTaskRemember();
  // Before the card is looked at, so the boot block already knows whether it
  // is allowed to write.
  loadLogSettings();
  spiSD.begin(hw_pins::SD_SCK, hw_pins::SD_MISO, hw_pins::SD_MOSI, hw_pins::SD_CS);
  if (SD.begin(hw_pins::SD_CS, spiSD)) {
    sd_available = true;
    uint8_t cardType = SD.cardType();
    const char* typeStr = "UNKNOWN";
    switch (cardType) {
      case CARD_MMC:  typeStr = "MMC";  break;
      case CARD_SD:   typeStr = "SDSC"; break;
      case CARD_SDHC: typeStr = "SDHC"; break;
      case CARD_NONE: typeStr = "NONE"; break;
    }
    uint64_t cardSize = SD.cardSize() / (1024 * 1024);
    Serial.printf("SD OK: type=%s size=%lluMB\n", typeStr, cardSize);
  } else {
    Serial.println("SD: not available (card missing or init failed)");
    sd_available = false;
  }

  // The ring in flash is opened whether or not it is the chosen destination:
  // the status page reports what is stored either way, and switching over in
  // the browser must not need a restart.
  flashLogBegin();
  applyEffectiveDest();
  Serial.printf("Log: %s, scope %s%s\n", destName(s_dest_eff), levelName(s_lvl),
                (s_dest_eff != s_dest) ? " (fell back, the chosen one is not there)" : "");
}

LogDest  logDestStored()    { return s_dest; }
LogDest  logDestEffective() { return s_dest_eff; }
LogLevel logLevel()         { return s_lvl; }

bool logDestSet(LogDest d) {
  if (d == s_dest) return true;
  if (!prefsPutUChar(LOG_DEST_PREF_KEY, (uint8_t)d)) return false;
  // Kept in step so a device put back on an older firmware still knows that
  // somebody had switched the card log off.
  prefsPutBool(SD_LOG_PREF_KEY, d != LOG_DEST_OFF);
  // The last line before a destination goes quiet says why it did, so a log
  // that simply stops is not read as a crash. Both lines reach the ring.
  logSDf("Log: destination -> %s", destName(d));
  s_dest = d;
  applyEffectiveDest();
  logSDf("Log: destination is %s", destName(s_dest_eff));
  return true;
}

bool logLevelSet(LogLevel l) {
  if (l == s_lvl) return true;
  if (!prefsPutUChar(LOG_LVL_PREF_KEY, (uint8_t)l)) return false;
  // Raised before the line is written, lowered after it, so the line that
  // records the change is never the one the change throws away.
  if (l > s_lvl) { s_lvl = l; sd_verbose = (l >= LOG_LVL_VERBOSE); }
  logSDf("Log: scope -> %s", levelName(l));
  s_lvl = l;
  sd_verbose = (l >= LOG_LVL_VERBOSE);
  return true;
}
