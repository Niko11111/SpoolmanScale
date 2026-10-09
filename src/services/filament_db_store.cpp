#include "filament_db_store.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <esp_partition.h>
#include <esp_rom_crc.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../bambu/bambu_catalog.h"
#include "../hardware/flash_log.h"
#include "../hardware/sd_logger.h"
#include "filament_db.h"

// Behind the log ring and the Bambu catalog. 20 kB at the most today
// (160 makers, 640 pairs), in 32 kB so the database can grow.
#define STORE_OFFSET        (FLASH_LOG_BYTES + BAMBU_CATALOG_BYTES)
#define STORE_BYTES         (32UL * 1024UL)
#define STORE_SECTOR        4096UL
#define STORE_MAGIC         0x49424446UL   // "FDBI"
// The records are stored as they lie in memory: a change to FdbMaker or
// FdbPair needs a new version, and a copy of an older one counts as none.
#define STORE_VERSION       1
#define STORE_MAX_AGE_S     (7UL * 24UL * 60UL * 60UL)
// A stamp before this is a clock that was never set, not a date.
#define STORE_STAMP_MIN     1700000000UL
#define STORE_URL_MAX       96

static_assert(sizeof(FdbMaker) == 36, "a stored maker is 36 bytes; a change needs STORE_VERSION");
static_assert(sizeof(FdbPair) == 22, "a stored pair is 22 bytes; a change needs STORE_VERSION");

struct StoreHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t maker_n;
  uint16_t pair_n;
  uint16_t reserved0;
  uint32_t crc;          // over the makers and the pairs
  uint32_t stamp;        // when the index was read, Unix time
  char     base_url[STORE_URL_MAX];
  uint8_t  reserved[12];
};
static_assert(sizeof(StoreHeader) == 128, "the header is 128 bytes on the device and the host");
static_assert(sizeof(StoreHeader) + FDB_MAKERS_MAX * sizeof(FdbMaker) +
              FDB_PAIRS_MAX * sizeof(FdbPair) <= STORE_BYTES, "a full index fits the region");

static const esp_partition_t* dataPartition() {
  const esp_partition_t* p = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                      ESP_PARTITION_SUBTYPE_DATA_SPIFFS, NULL);
  if (!p || p->size < STORE_OFFSET + STORE_BYTES) return nullptr;
  return p;
}

static size_t bodyBytes(int maker_n, int pair_n) {
  return (size_t)maker_n * sizeof(FdbMaker) + (size_t)pair_n * sizeof(FdbPair);
}

static uint32_t clockNow() {
  const time_t now = time(nullptr);
  return now >= (time_t)STORE_STAMP_MIN ? (uint32_t)now : 0;
}

// Why a stored header is not used, or nullptr when it is.
static const char* headerProblem(const StoreHeader& h, const char* base_url, uint32_t now) {
  if (h.magic != STORE_MAGIC || h.version != STORE_VERSION) return "none";
  if (h.maker_n == 0 || h.maker_n > FDB_MAKERS_MAX || h.pair_n > FDB_PAIRS_MAX) return "damaged";
  if (strncmp(h.base_url, base_url, sizeof(h.base_url)) != 0) return "another server";
  if (!now) return "clock not set";
  if (h.stamp < STORE_STAMP_MIN || now < h.stamp || now - h.stamp > STORE_MAX_AGE_S) return "too old";
  return nullptr;
}

bool fdbStoreLoad(const char* base_url) {
  const esp_partition_t* part = dataPartition();
  if (!part || !base_url) return false;
  StoreHeader h;
  if (esp_partition_read(part, STORE_OFFSET, &h, sizeof(h)) != ESP_OK) return false;
  const char* problem = headerProblem(h, base_url, clockNow());
  if (problem) { logSDf("Filament DB: stored index not used (%s)", problem); return false; }

  const size_t body = bodyBytes(h.maker_n, h.pair_n);
  uint8_t* buf = (uint8_t*)heap_caps_malloc(body, MALLOC_CAP_SPIRAM);
  if (!buf) buf = (uint8_t*)malloc(body);
  if (!buf) return false;
  bool ok = esp_partition_read(part, STORE_OFFSET + sizeof(h), buf, body) == ESP_OK &&
            esp_rom_crc32_le(0, buf, body) == h.crc;
  if (ok) {
    const FdbMaker* makers = (const FdbMaker*)buf;
    const FdbPair* pairs = (const FdbPair*)(buf + (size_t)h.maker_n * sizeof(FdbMaker));
    ok = fdbIndexRestore(makers, h.maker_n, pairs, h.pair_n);
  }
  heap_caps_free(buf);
  if (!ok) { logSD("Filament DB: stored index damaged, reading the database"); return false; }
  logSDf("Filament DB: index from flash, %lu h old, %u makers, %u pairs",
         (unsigned long)((clockNow() - h.stamp) / 3600UL), (unsigned)h.maker_n, (unsigned)h.pair_n);
  return true;
}

// Body first, header last: a store cut short leaves no magic and reads as
// none rather than as a broken one.
static bool writeStore(const esp_partition_t* part, const StoreHeader& h, const uint8_t* body,
                       size_t body_len) {
  const size_t total = sizeof(h) + body_len;
  const size_t erase = (total + STORE_SECTOR - 1) / STORE_SECTOR * STORE_SECTOR;
  return esp_partition_erase_range(part, STORE_OFFSET, erase) == ESP_OK &&
         esp_partition_write(part, STORE_OFFSET + sizeof(h), body, body_len) == ESP_OK &&
         esp_partition_write(part, STORE_OFFSET, &h, sizeof(h)) == ESP_OK;
}

void fdbStoreSave(const char* base_url) {
  const esp_partition_t* part = dataPartition();
  const uint32_t now = clockNow();
  // Without a date the age could never be told: better none than one that
  // never runs out.
  if (!part || !base_url || !now) return;
  const FdbMaker* makers = nullptr;
  const FdbPair* pairs = nullptr;
  int pair_n = 0;
  const int maker_n = fdbIndexSnapshot(&makers, &pairs, &pair_n);
  if (maker_n <= 0) return;

  const size_t maker_bytes = (size_t)maker_n * sizeof(FdbMaker);
  const size_t body = bodyBytes(maker_n, pair_n);
  uint8_t* buf = (uint8_t*)heap_caps_malloc(body, MALLOC_CAP_SPIRAM);
  if (!buf) buf = (uint8_t*)malloc(body);
  if (!buf) { logSD("Filament DB: no memory to keep the index"); return; }
  memcpy(buf, makers, maker_bytes);
  memcpy(buf + maker_bytes, pairs, (size_t)pair_n * sizeof(FdbPair));

  StoreHeader h;
  memset(&h, 0, sizeof(h));
  h.magic   = STORE_MAGIC;
  h.version = STORE_VERSION;
  h.maker_n = (uint16_t)maker_n;
  h.pair_n  = (uint16_t)pair_n;
  h.crc     = esp_rom_crc32_le(0, buf, body);
  h.stamp   = now;
  snprintf(h.base_url, sizeof(h.base_url), "%s", base_url);
  const bool ok = writeStore(part, h, buf, body);
  heap_caps_free(buf);
  logSDf("Filament DB: index kept in flash: %s, %u bytes", ok ? "ok" : "write failed",
         (unsigned)(sizeof(h) + body));
}
