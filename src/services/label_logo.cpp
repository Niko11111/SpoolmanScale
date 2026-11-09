#include "label_logo.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <esp_partition.h>
#include <esp_rom_crc.h>
#include <stdio.h>
#include <string.h>

#include "../bambu/bambu_catalog.h"
#include "../hardware/flash_log.h"
#include "../hardware/sd_logger.h"
#include "filament_db_store.h"
#include "tag_family.h"

// Behind the log ring, the Bambu catalog, the tag family memory and the
// filament index: 624 kB into the data partition, 512 kB for the logos.
// 624 kB is a sector boundary, so the header starts on a sector of its own.
#define LOGO_OFFSET      (FLASH_LOG_BYTES + BAMBU_CATALOG_BYTES + TAG_FAMILY_BYTES + \
                          FILAMENT_DB_STORE_BYTES)
#define LOGO_SECTOR      4096UL
#define LOGO_DATA_OFFSET (LOGO_OFFSET + LOGO_SECTOR)
// What the bits may take: everything behind the header's sector.
#define LOGO_DATA_BYTES  (LABEL_LOGO_BYTES - LOGO_SECTOR)
#define LOGO_MAGIC       0x4F4C474CUL   // "LGLO", little endian
// A change to LogoEntry needs a new version; an older store then reads as
// none rather than as a broken one.
#define LOGO_VERSION     1

static_assert(LOGO_OFFSET % LOGO_SECTOR == 0, "the header starts on a sector");
static_assert(LOGO_DATA_OFFSET + LOGO_DATA_BYTES == LOGO_OFFSET + LABEL_LOGO_BYTES,
              "the data runs to the end of the region");

// The header sits in the first sector, the entries right behind it, the bits
// from the second sector on. The header is written last: a write cut short
// leaves no magic, and the store reads as empty.
struct LogoHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t count;
  uint32_t used;              // bytes of bits
  uint8_t  reserved[116];
};
static_assert(sizeof(LogoHeader) == 128, "the header is 128 bytes");

struct LogoEntry {
  char     key[LABEL_LOGO_KEY_BYTES];
  uint16_t w, h;
  uint32_t off;               // into the bits, from the second sector on
  uint32_t len;
  uint32_t crc;               // over the bits
};
static_assert(sizeof(LogoEntry) == 40, "an entry is 40 bytes; a change needs LOGO_VERSION");
static_assert(sizeof(LogoHeader) + LABEL_LOGO_MAX_COUNT * sizeof(LogoEntry) <= LOGO_SECTOR,
              "a full index fits the header's sector");

static LogoHeader s_head{};
static LogoEntry s_entries[LABEL_LOGO_MAX_COUNT];
static int s_count = 0;
static bool s_loaded = false;
// Where a change is built before the flash is touched.
static LogoEntry s_next[LABEL_LOGO_MAX_COUNT];

// The one logo a label draws: the bits are read out of flash on the lookup and
// reused, because the header is measured up to four times before it is drawn.
static char s_cache_key[LABEL_LOGO_KEY_BYTES];
static uint8_t* s_cache_bits = nullptr;
static size_t s_cache_cap = 0;
static LabelLogo s_cache{};
static bool s_cache_valid = false;

// The room a logo of this size takes, rows padded to whole bytes.
static size_t logoBytes(uint16_t w, uint16_t h) {
  return (size_t)((w + 7) / 8) * h;
}

static uint8_t* allocBits(size_t bytes) {
  uint8_t* p = (uint8_t*)heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM);
  return p ? p : (uint8_t*)malloc(bytes);
}

static const esp_partition_t* dataPartition() {
  const esp_partition_t* p = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                      ESP_PARTITION_SUBTYPE_DATA_SPIFFS, NULL);
  if (!p || p->size < LOGO_OFFSET + LABEL_LOGO_BYTES) return nullptr;
  return p;
}

// Whether a stored entry points where the header says it may.
static bool validEntry(const LogoEntry& e, uint32_t used) {
  if (!memchr(e.key, '\0', sizeof(e.key)) || !e.key[0]) return false;
  if (e.w == 0 || e.h == 0 || e.w > LABEL_LOGO_MAX_W || e.h > LABEL_LOGO_MAX_H) return false;
  if (e.len != logoBytes(e.w, e.h) || e.len > LABEL_LOGO_MAX_BITS) return false;
  return (uint64_t)e.off + e.len <= used;
}

static bool readHeader(const esp_partition_t* part, LogoHeader* h) {
  if (esp_partition_read(part, LOGO_OFFSET, h, sizeof(*h)) != ESP_OK) return false;
  if (h->magic != LOGO_MAGIC || h->version != LOGO_VERSION) return false;
  return h->count <= LABEL_LOGO_MAX_COUNT && h->used <= LOGO_DATA_BYTES;
}

bool labelLogoBegin(void) {
  s_loaded = true;
  s_count = 0;
  s_head = LogoHeader{};
  s_cache_valid = false;
  const esp_partition_t* part = dataPartition();
  if (!part || !readHeader(part, &s_head)) {
    s_head = LogoHeader{};
    return false;
  }
  if (!s_head.count) return false;
  if (esp_partition_read(part, LOGO_OFFSET + sizeof(LogoHeader), s_entries,
                         (size_t)s_head.count * sizeof(LogoEntry)) != ESP_OK) {
    s_head = LogoHeader{};
    return false;
  }
  for (int i = 0; i < s_head.count; i++) {
    if (validEntry(s_entries[i], s_head.used)) continue;
    logSD("Label logo: the store is damaged, no logo is used");
    s_head = LogoHeader{};
    return false;
  }
  s_count = s_head.count;
  return true;
}

static void ensureLoaded() {
  if (!s_loaded) labelLogoBegin();
}

int labelLogoCount(void) {
  ensureLoaded();
  return s_count;
}

bool labelLogoAt(int i, LabelLogoInfo* out) {
  ensureLoaded();
  if (!out || i < 0 || i >= s_count) return false;
  snprintf(out->key, sizeof(out->key), "%s", s_entries[i].key);
  out->w = s_entries[i].w;
  out->h = s_entries[i].h;
  out->bytes = s_entries[i].len;
  return true;
}

static int findEntry(const char* key) {
  for (int i = 0; i < s_count; i++)
    if (strncmp(s_entries[i].key, key, LABEL_LOGO_KEY_BYTES) == 0) return i;
  return -1;
}

// Reads one entry's bits into the cache's buffer and checks them.
static bool loadBits(const LogoEntry& e, size_t len) {
  if (len > s_cache_cap) {
    uint8_t* buf = (uint8_t*)heap_caps_realloc(s_cache_bits, len, MALLOC_CAP_SPIRAM);
    if (!buf) buf = (uint8_t*)realloc(s_cache_bits, len);
    if (!buf) { logSD("Label logo: no room to read one"); return false; }
    s_cache_bits = buf;
    s_cache_cap = len;
  }
  const esp_partition_t* part = dataPartition();
  if (!part || esp_partition_read(part, LOGO_DATA_OFFSET + e.off, s_cache_bits, len) != ESP_OK)
    return false;
  return esp_rom_crc32_le(0, s_cache_bits, len) == e.crc;
}

const LabelLogo* labelLogoFor(const char* vendor) {
  ensureLoaded();
  char key[LABEL_LOGO_KEY_BYTES];
  labelLogoKey(vendor, key, sizeof(key));
  if (!key[0]) return nullptr;
  if (s_cache_valid && strncmp(s_cache_key, key, sizeof(key)) == 0)
    return s_cache.bits ? &s_cache : nullptr;
  s_cache = LabelLogo{};
  s_cache_valid = true;
  snprintf(s_cache_key, sizeof(s_cache_key), "%s", key);
  const int i = findEntry(key);
  if (i < 0) return nullptr;
  const LogoEntry& e = s_entries[i];
  if (!loadBits(e, logoBytes(e.w, e.h))) {
    logSDf("Label logo: %s fails its check", key);
    return nullptr;
  }
  s_cache = LabelLogo{ s_cache_bits, e.w, e.h };
  return &s_cache;
}

uint32_t labelLogoUsedBytes(void) {
  ensureLoaded();
  return s_head.used;
}

uint32_t labelLogoCapacityBytes(void) {
  return LOGO_DATA_BYTES;
}

// Body first, header last: a store cut short reads as none, not as broken.
static bool storeRewrite(const LogoEntry* entries, int count, const uint8_t* bits, size_t used) {
  const esp_partition_t* part = dataPartition();
  if (!part || count < 0 || count > LABEL_LOGO_MAX_COUNT || used > LOGO_DATA_BYTES) return false;
  const size_t body = count ? used : 0;
  const size_t erase = LOGO_SECTOR +
                       (body ? (body + LOGO_SECTOR - 1) / LOGO_SECTOR * LOGO_SECTOR : 0);
  LogoHeader h{};
  h.magic = LOGO_MAGIC;
  h.version = LOGO_VERSION;
  h.count = (uint16_t)count;
  h.used = (uint32_t)used;
  bool ok = esp_partition_erase_range(part, LOGO_OFFSET, erase) == ESP_OK;
  if (ok && body)
    ok = esp_partition_write(part, LOGO_DATA_OFFSET, bits, body) == ESP_OK;
  if (ok && count)
    ok = esp_partition_write(part, LOGO_OFFSET + sizeof(LogoHeader), entries,
                             (size_t)count * sizeof(LogoEntry)) == ESP_OK;
  if (ok) ok = esp_partition_write(part, LOGO_OFFSET, &h, sizeof(h)) == ESP_OK;
  if (!ok) {
    // The flash may hold no store now, or the one from before: read it again
    // instead of trusting the index in RAM.
    s_loaded = false;
    s_count = 0;
    s_cache_valid = false;
    return false;
  }
  s_head = h;
  memcpy(s_entries, entries, (size_t)count * sizeof(LogoEntry));
  s_count = count;
  s_cache_valid = false;
  s_cache = LabelLogo{};
  return true;
}

// A change to the store: the entries to keep are copied with their bits, plus
// the one to add. `key` is the entry left out, whether it is replaced or
// dropped.
struct LogoJob {
  const char* key;
  const LabelLogo* add;
  uint8_t* old;
  uint8_t* fresh;
  int count;
  size_t used;
};

static bool buildStore(LogoJob& job) {
  int n = 0;
  size_t pos = 0;
  for (int i = 0; i < s_count; i++) {
    if (strncmp(s_entries[i].key, job.key, LABEL_LOGO_KEY_BYTES) == 0) continue;
    LogoEntry e = s_entries[i];
    memcpy(job.fresh + pos, job.old + e.off, e.len);
    e.off = (uint32_t)pos;
    pos += e.len;
    s_next[n++] = e;
  }
  if (job.add) {
    const size_t len = logoBytes(job.add->w, job.add->h);
    LogoEntry e{};
    snprintf(e.key, sizeof(e.key), "%s", job.key);
    e.w = job.add->w;
    e.h = job.add->h;
    e.off = (uint32_t)pos;
    e.len = (uint32_t)len;
    e.crc = esp_rom_crc32_le(0, job.add->bits, len);
    memcpy(job.fresh + pos, job.add->bits, len);
    pos += len;
    s_next[n++] = e;
  }
  job.count = n;
  job.used = pos;
  return true;
}

// Reads the kept bits, builds the new store in `fresh` and writes it.
static bool runJob(LogoJob& job, size_t total) {
  const esp_partition_t* part = dataPartition();
  if (!part) return false;
  job.old = s_head.used ? allocBits(s_head.used) : nullptr;
  job.fresh = total ? allocBits(total) : nullptr;
  bool ok = (!s_head.used || (job.old && esp_partition_read(part, LOGO_DATA_OFFSET,
                                                            job.old, s_head.used) == ESP_OK)) &&
            (!total || job.fresh);
  if (ok) ok = buildStore(job) && storeRewrite(s_next, job.count, job.fresh, job.used);
  heap_caps_free(job.old);
  heap_caps_free(job.fresh);
  job.old = nullptr;
  job.fresh = nullptr;
  return ok;
}

static size_t keptBytes(int except) {
  size_t kept = 0;
  for (int i = 0; i < s_count; i++)
    if (i != except) kept += s_entries[i].len;
  return kept;
}

bool labelLogoPut(const char* vendor, const LabelLogo& logo) {
  ensureLoaded();
  char key[LABEL_LOGO_KEY_BYTES];
  labelLogoKey(vendor, key, sizeof(key));
  const size_t len = logoBytes(logo.w, logo.h);
  if (!key[0] || !logo.bits || !len || len > LABEL_LOGO_MAX_BITS) return false;
  if (logo.w > LABEL_LOGO_MAX_W || logo.h > LABEL_LOGO_MAX_H) return false;
  const int at = findEntry(key);
  if (at < 0 && s_count >= LABEL_LOGO_MAX_COUNT) return false;
  const size_t needed = keptBytes(at) + len;
  if (needed > LOGO_DATA_BYTES) { logSD("Label logo: the store is full"); return false; }
  LogoJob job{ key, &logo, nullptr, nullptr, 0, 0 };
  if (!runJob(job, needed)) return false;
  logSDf("Label logo: %s stored, %ux%u, %u bytes", key, logo.w, logo.h, (unsigned)len);
  return true;
}

bool labelLogoDrop(const char* vendor) {
  ensureLoaded();
  char key[LABEL_LOGO_KEY_BYTES];
  labelLogoKey(vendor, key, sizeof(key));
  const int at = key[0] ? findEntry(key) : -1;
  if (at < 0) return false;
  LogoJob job{ key, nullptr, nullptr, nullptr, 0, 0 };
  if (!runJob(job, keptBytes(at))) return false;
  logSDf("Label logo: %s dropped", key);
  return true;
}
