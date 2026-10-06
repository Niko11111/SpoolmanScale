#include "bambu_catalog.h"

#include <Arduino.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <esp_partition.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hardware/flash_log.h"
#include "hardware/sd_logger.h"
#include "services/backend_http.h"
#include "services/github_release.h"

// Last: T() is a macro, and ArduinoJson uses T as a template parameter.
#include "lang.h"

// The table as BambuStudio ships it, from its default branch: Bambu adds
// colours there when they go on sale.
#define BAMBU_CATALOG_URL \
  "https://raw.githubusercontent.com/bambulab/BambuStudio/master/" \
  "resources/profiles/BBL/filament/filaments_color_codes.json"
#define BAMBU_CATALOG_TIMEOUT_MS  15000
// 230 kB today; room for Bambu to keep adding colours for a while.
#define BAMBU_CATALOG_DOWNLOAD_MAX  (1024UL * 1024UL)
// No byte for this long on an open socket: stuck, not slow.
#define BAMBU_CATALOG_STALL_MS    20000UL
#define BAMBU_CATALOG_POLL_MS     10

#define CAT_OFFSET        FLASH_LOG_BYTES
#define CAT_SECTOR        4096UL
#define CAT_MAGIC         0x54414342UL   // "BCAT"
#define CAT_VERSION       2      // 2: the ETag the copy was downloaded under
#define CAT_COLOURS       4      // gradients and multi colour spools carry up to four
#define CAT_MAX_ENTRIES   1200
// A stamp before this is a clock that was never set, not a date.
#define CAT_STAMP_MIN     1700000000UL

// ---- the stored form ------------------------------------------
// A header, fixed records, then every string once in a pool the records
// point into. Written header last, so a store cut short leaves no magic and
// reads as no catalog rather than as a broken one.
struct CatHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t count;
  uint32_t pool_bytes;
  uint32_t crc;         // over records and pool
  uint32_t stamp;
  // What GitHub called this version of the file. Sent back as If-None-Match,
  // it turns the daily check into a 304 without a body while nothing changed.
  char     etag[96];
  uint8_t  reserved[12];
};
static_assert(sizeof(CatHeader) == 128, "the header is 128 bytes on the device and the host");

struct CatRec {
  char     id[6];       // "GFA10"
  char     code[4];     // "B0", as the table spells it
  uint8_t  ncol;
  uint8_t  pad;
  char     article[8];  // "12601"
  uint32_t rgba[CAT_COLOURS];   // 0xRRGGBBAA, the first colour first
  uint16_t product, en, de, fr;         // offsets into the pool
};
static_assert(sizeof(CatRec) == 44, "a record is 44 bytes on the device and the host");

// The PSRAM copy the lookups read. Loaded on the first lookup and again after
// a store; only the loop task touches it.
static uint8_t*          s_blob    = nullptr;
static const CatHeader*  s_hdr     = nullptr;
static bool              s_tried   = false;
// Set by the store on the worker task, read by the loop task.
static volatile bool     s_storing = false;
static volatile bool     s_dirty   = false;
// When the last download or check reached GitHub, for the loop to keep.
static volatile uint32_t s_checked = 0;

struct SpiRamAllocator : ArduinoJson::Allocator {
  void* allocate(size_t n) override {
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM);
    if (!p) p = malloc(n);
    return p;
  }
  void  deallocate(void* p) override { heap_caps_free(p); }
  void* reallocate(void* p, size_t n) override {
    void* q = heap_caps_realloc(p, n, MALLOC_CAP_SPIRAM);
    if (!q) q = realloc(p, n);
    return q;
  }
};

static uint32_t crc32(const uint8_t* p, size_t n) {
  uint32_t c = 0xFFFFFFFFUL;
  for (size_t i = 0; i < n; i++) {
    c ^= p[i];
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320UL & (0UL - (c & 1)));
  }
  return ~c;
}

static const esp_partition_t* dataPartition() {
  const esp_partition_t* p = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                      ESP_PARTITION_SUBTYPE_DATA_SPIFFS, NULL);
  if (!p || p->size < CAT_OFFSET + BAMBU_CATALOG_BYTES) return nullptr;
  return p;
}

// ---- loading, loop task ---------------------------------------

static void unload() {
  if (s_blob) heap_caps_free(s_blob);
  s_blob = nullptr;
  s_hdr  = nullptr;
}

static void ensureLoaded() {
  if (s_storing) return;
  if (s_dirty) { s_dirty = false; unload(); s_tried = false; }
  if (s_tried) return;
  s_tried = true;

  const esp_partition_t* part = dataPartition();
  if (!part) return;
  CatHeader h;
  if (esp_partition_read(part, CAT_OFFSET, &h, sizeof(h)) != ESP_OK) return;
  if (h.magic != CAT_MAGIC || h.version != CAT_VERSION) return;
  const size_t body = (size_t)h.count * sizeof(CatRec) + h.pool_bytes;
  if (h.count == 0 || h.count > CAT_MAX_ENTRIES ||
      sizeof(h) + body > BAMBU_CATALOG_BYTES) {
    logSDf("Bambu catalog: header out of range (%u colours, %lu pool bytes)",
           (unsigned)h.count, (unsigned long)h.pool_bytes);
    return;
  }
  uint8_t* blob = (uint8_t*)heap_caps_malloc(sizeof(h) + body, MALLOC_CAP_SPIRAM);
  if (!blob) blob = (uint8_t*)malloc(sizeof(h) + body);
  if (!blob) return;
  if (esp_partition_read(part, CAT_OFFSET, blob, sizeof(h) + body) != ESP_OK ||
      crc32(blob + sizeof(h), body) != h.crc) {
    logSD("Bambu catalog: stored copy fails its checksum, ignored");
    heap_caps_free(blob);
    return;
  }
  s_blob = blob;
  s_hdr  = (const CatHeader*)blob;
  logSDf("Bambu catalog: %u colours loaded", (unsigned)h.count);
}

static const CatRec* recs() { return (const CatRec*)(s_blob + sizeof(CatHeader)); }

static const char* poolStr(uint16_t off) {
  const char* pool = (const char*)(s_blob + sizeof(CatHeader) + s_hdr->count * sizeof(CatRec));
  return off < s_hdr->pool_bytes ? pool + off : "";
}

// "B0", "B00", "G6", "G06": the tag and the table do not agree on the zeros
// (PLA Basic Bambu Green is A00-G06 on the spool, G6 in the table), so a
// colour code is compared as its letter and its number.
static bool codeKey(const char* s, char* letter, int* num) {
  if (!s || !s[0] || s[0] < 'A' || s[0] > 'Z') return false;
  *letter = s[0];
  char* end = nullptr;
  const long n = strtol(s + 1, &end, 10);
  if (end == s + 1 || *end) return false;
  *num = (int)n;
  return true;
}

static bool sameColour(uint32_t rgba, const SpoolColor& c) {
  return c.valid && (rgba >> 8) == c.rgb && (uint8_t)(rgba & 0xFF) == c.alpha;
}

bool bambuCatalogFind(const char* material_id, const char* variant_id,
                      const SpoolColor& color, BambuCatalogHit* out) {
  ensureLoaded();
  if (!s_hdr || !material_id || !material_id[0] || !out) return false;

  char want_l = 0;
  int  want_n = -1;
  const char* dash = variant_id ? strchr(variant_id, '-') : nullptr;
  const bool have_code = dash && codeKey(dash + 1, &want_l, &want_n);

  // The code decides where it matches and the colour agrees. Where the two
  // disagree the colour wins if another entry of the product has exactly
  // it: a batch whose code the table spells differently still has its own
  // colour. The code alone is the last resort.
  const CatRec* by_code = nullptr;
  const CatRec* by_colour = nullptr;
  for (int i = 0; i < s_hdr->count; i++) {
    const CatRec& r = recs()[i];
    if (strncmp(r.id, material_id, sizeof(r.id)) != 0) continue;
    char l; int n;
    if (have_code && codeKey(r.code, &l, &n) && l == want_l && n == want_n) {
      if (sameColour(r.rgba[0], color)) { by_code = &r; by_colour = &r; break; }
      if (!by_code) by_code = &r;
    }
    if (!by_colour && sameColour(r.rgba[0], color)) by_colour = &r;
  }
  const CatRec* hit = by_colour ? by_colour : by_code;
  if (!hit) return false;

  snprintf(out->article, sizeof(out->article), "%s", hit->article);
  snprintf(out->product, sizeof(out->product), "%s", poolStr(hit->product));
  const uint16_t local = g_lang == LANG_DE ? hit->de : g_lang == LANG_FR ? hit->fr : hit->en;
  const char* name = poolStr(local);
  snprintf(out->color_name, sizeof(out->color_name), "%s", name[0] ? name : poolStr(hit->en));
  snprintf(out->color_name_en, sizeof(out->color_name_en), "%s", poolStr(hit->en));
  return true;
}

int bambuCatalogCount() {
  ensureLoaded();
  return s_hdr ? s_hdr->count : 0;
}

uint32_t bambuCatalogStamp() {
  ensureLoaded();
  return s_hdr ? s_hdr->stamp : 0;
}

// ---- converting and storing, worker task ----------------------

// Appends s to the pool, or finds it there already: a product name stands
// behind dozens of colours and is stored once.
static bool poolAdd(uint8_t* pool, size_t cap, size_t* used, const char* s, uint16_t* off) {
  if (!s) s = "";
  const size_t len = strlen(s) + 1;
  for (size_t i = 0; i + len <= *used; ) {
    const size_t l = strlen((const char*)pool + i) + 1;
    if (l == len && memcmp(pool + i, s, len) == 0) { *off = (uint16_t)i; return true; }
    i += l;
  }
  if (*used + len > cap || *used + len > 0xFFFF) return false;
  memcpy(pool + *used, s, len);
  *off = (uint16_t)*used;
  *used += len;
  return true;
}

static uint32_t parseRgba(const char* hex) {
  if (!hex || hex[0] != '#') return 0;
  const size_t n = strlen(hex + 1);
  uint32_t v = strtoul(hex + 1, nullptr, 16);
  if (n == 6) v = (v << 8) | 0xFF;
  else if (n != 8) return 0;
  return v;
}

bool bambuCatalogStore(JsonArrayConst entries, uint32_t stamp, const char* etag,
                       char* err, size_t err_len, int* count) {
  if (count) *count = 0;
  const esp_partition_t* part = dataPartition();
  if (!part) { snprintf(err, err_len, "no data partition"); return false; }
  const size_t n_in = entries.size();
  if (n_in == 0) { snprintf(err, err_len, "the table is empty"); return false; }

  uint8_t* buf = (uint8_t*)heap_caps_malloc(BAMBU_CATALOG_BYTES, MALLOC_CAP_SPIRAM);
  if (!buf) { snprintf(err, err_len, "no memory"); return false; }
  memset(buf, 0, BAMBU_CATALOG_BYTES);

  // Records first, then the pool where the room ends: its size is only known
  // once every string is in.
  CatRec* out = (CatRec*)(buf + sizeof(CatHeader));
  const size_t max_recs = (BAMBU_CATALOG_BYTES - sizeof(CatHeader)) / (sizeof(CatRec) + 16);
  uint8_t* pool = (uint8_t*)heap_caps_malloc(BAMBU_CATALOG_BYTES, MALLOC_CAP_SPIRAM);
  if (!pool) { heap_caps_free(buf); snprintf(err, err_len, "no memory"); return false; }
  size_t used = 0;
  uint16_t empty_off = 0;
  poolAdd(pool, BAMBU_CATALOG_BYTES, &used, "", &empty_off);

  size_t n = 0;
  bool full = false;
  for (JsonObjectConst e : entries) {
    const char* id   = e["fila_id"] | "";
    const char* code = e["color_code"] | "";
    if (strlen(id) != 5 || !code[0] || strlen(code) > 3) continue;   // not a tag's pair
    if (n >= max_recs) { full = true; break; }
    CatRec& r = out[n];
    memset(&r, 0, sizeof(r));
    memcpy(r.id, id, 5);
    memcpy(r.code, code, strlen(code));
    snprintf(r.article, sizeof(r.article), "%s", e["fila_color_code"] | "");
    for (JsonVariantConst c : e["fila_color"].as<JsonArrayConst>()) {
      if (r.ncol >= CAT_COLOURS) break;
      r.rgba[r.ncol++] = parseRgba(c | "");
    }
    JsonObjectConst names = e["fila_color_name"];
    if (!poolAdd(pool, BAMBU_CATALOG_BYTES, &used, e["fila_type"] | "", &r.product) ||
        !poolAdd(pool, BAMBU_CATALOG_BYTES, &used, names["en"] | "", &r.en) ||
        !poolAdd(pool, BAMBU_CATALOG_BYTES, &used, names["de"] | "", &r.de) ||
        !poolAdd(pool, BAMBU_CATALOG_BYTES, &used, names["fr"] | "", &r.fr)) {
      full = true;
      break;
    }
    n++;
  }
  const size_t body = n * sizeof(CatRec) + used;
  if (n == 0 || full || sizeof(CatHeader) + body > BAMBU_CATALOG_BYTES) {
    heap_caps_free(pool);
    heap_caps_free(buf);
    snprintf(err, err_len, n ? "the table no longer fits in %lu kB" : "no usable entries",
             (unsigned long)(BAMBU_CATALOG_BYTES / 1024));
    return false;
  }
  memcpy(buf + sizeof(CatHeader) + n * sizeof(CatRec), pool, used);
  heap_caps_free(pool);

  CatHeader* h = (CatHeader*)buf;
  h->magic      = CAT_MAGIC;
  h->version    = CAT_VERSION;
  h->count      = (uint16_t)n;
  h->pool_bytes = (uint32_t)used;
  h->crc        = crc32(buf + sizeof(CatHeader), body);
  h->stamp      = stamp >= CAT_STAMP_MIN ? stamp : 0;
  snprintf(h->etag, sizeof(h->etag), "%s", etag ? etag : "");

  // Only the sectors the new copy needs. Erasing the whole 64 kB would stall
  // both cores for close to a second, for nothing.
  const size_t total  = sizeof(CatHeader) + body;
  const size_t erase  = (total + CAT_SECTOR - 1) / CAT_SECTOR * CAT_SECTOR;
  s_storing = true;
  bool ok = esp_partition_erase_range(part, CAT_OFFSET, erase) == ESP_OK &&
            esp_partition_write(part, CAT_OFFSET + sizeof(CatHeader),
                                buf + sizeof(CatHeader), body) == ESP_OK &&
            esp_partition_write(part, CAT_OFFSET, buf, sizeof(CatHeader)) == ESP_OK;
  if (ok) {
    // Read back and checked, as the loader will: a store that cannot be
    // loaded is reported now, not found out at the next scan.
    ok = esp_partition_read(part, CAT_OFFSET, buf, total) == ESP_OK &&
         crc32(buf + sizeof(CatHeader), body) == h->crc;
  }
  heap_caps_free(buf);
  s_dirty   = true;
  s_storing = false;
  if (!ok) { snprintf(err, err_len, "writing to flash failed"); return false; }
  if (count) *count = (int)n;
  logSDf("Bambu catalog: %u colours stored, %lu bytes", (unsigned)n, (unsigned long)total);
  return true;
}

// The ETag of the stored copy, straight from flash: this runs on the worker,
// which must not touch the loop's PSRAM copy.
static bool storedEtag(char* out, size_t n) {
  out[0] = '\0';
  const esp_partition_t* part = dataPartition();
  CatHeader h;
  if (!part || esp_partition_read(part, CAT_OFFSET, &h, sizeof(h)) != ESP_OK) return false;
  if (h.magic != CAT_MAGIC || h.version != CAT_VERSION) return false;
  h.etag[sizeof(h.etag) - 1] = '\0';
  snprintf(out, n, "%s", h.etag);
  return out[0] != '\0';
}

static void noteChecked() {
  const time_t now = time(nullptr);
  s_checked = (uint32_t)now >= CAT_STAMP_MIN ? (uint32_t)now : 1;
}

uint32_t bambuCatalogTakeChecked() {
  const uint32_t c = s_checked;
  s_checked = 0;
  return c;
}

BambuCatalogOutcome bambuCatalogDownload(bool conditional, char* err, size_t err_len,
                                         int* count) {
  if (count) *count = 0;
  WiFiClientSecure client;
  githubTrust(client);
  HTTPClient http;
  http.setTimeout(BAMBU_CATALOG_TIMEOUT_MS);
  if (!http.begin(client, BAMBU_CATALOG_URL)) {
    snprintf(err, err_len, "connection failed");
    return BCO_FAILED;
  }
  const char* keep[] = { "ETag", "Transfer-Encoding" };
  http.collectHeaders(keep, 2);
  char etag[96];
  if (conditional && storedEtag(etag, sizeof(etag))) http.addHeader("If-None-Match", etag);
  const int code = http.GET();
  if (code == 304) {
    http.end();
    noteChecked();
    logSD("Bambu catalog: unchanged at BambuStudio (304)");
    return BCO_UNCHANGED;
  }
  if (code != 200) {
    snprintf(err, err_len, "HTTP %d", code);
    http.end();
    return BCO_FAILED;
  }
  snprintf(etag, sizeof(etag), "%s", http.header("ETag").c_str());

  // The whole file first, then the parse. Parsing straight off the TLS
  // stream gave up the moment the data paused ("IncompleteInput" after 2 s
  // on the device, 28.09.2026): the parser takes a quiet socket for the end.
  const int size = http.getSize();
  if (size > (int)BAMBU_CATALOG_DOWNLOAD_MAX) {
    snprintf(err, err_len, "the table is %d bytes, more than expected", size);
    http.end();
    return BCO_FAILED;
  }
  const size_t cap = size > 0 ? (size_t)size : BAMBU_CATALOG_DOWNLOAD_MAX;
  char* raw = (char*)heap_caps_malloc(cap + 1, MALLOC_CAP_SPIRAM);
  if (!raw) { snprintf(err, err_len, "no memory"); http.end(); return BCO_FAILED; }
  Stream* in = http.getStreamPtr();
  // GitHub sends the file with a Content-Length. Sent chunked instead, the
  // raw socket carries a size line before every piece, and the parser would
  // take those for JSON; ChunkedStream takes them out. Its timeout is 0
  // because it waits on the socket itself, and the end is its last chunk,
  // not a closed socket.
  const bool chunked = http.header("Transfer-Encoding").equalsIgnoreCase("chunked");
  ChunkedStream dechunk;
  if (chunked) {
    dechunk.reset(in);
    dechunk.setTimeout(0);
    in = &dechunk;
    logSD("Bambu catalog: the answer is chunked, size lines taken out");
  }
  size_t got = 0;
  unsigned long last = millis();
  while (got < cap) {
    const int avail = in->available();
    if (avail > 0) {
      const size_t want = (size_t)avail < cap - got ? (size_t)avail : cap - got;
      const int n = in->readBytes(raw + got, want);
      if (n > 0) { got += (size_t)n; last = millis(); }
      continue;
    }
    if (chunked && dechunk.done()) break;
    if (!http.connected()) break;
    if (millis() - last > BAMBU_CATALOG_STALL_MS) break;
    delay(BAMBU_CATALOG_POLL_MS);
  }
  http.end();
  if (size > 0 && got != (size_t)size) {
    heap_caps_free(raw);
    snprintf(err, err_len, "download stopped at %u of %d bytes", (unsigned)got, size);
    return BCO_FAILED;
  }
  raw[got] = '\0';

  // Seven fields per colour of a 230 kB file. The rest - the Chinese colour
  // type, nine more languages - is dropped while it is parsed.
  JsonDocument filter;
  JsonObject f = filter["data"].to<JsonArray>().add<JsonObject>();
  f["fila_id"] = true;
  f["color_code"] = true;
  f["fila_color_code"] = true;
  f["fila_type"] = true;
  f["fila_color"] = true;
  f["fila_color_name"]["en"] = true;
  f["fila_color_name"]["de"] = true;
  f["fila_color_name"]["fr"] = true;

  SpiRamAllocator psram;
  JsonDocument doc(&psram);
  const DeserializationError e =
      deserializeJson(doc, (const char*)raw, got, DeserializationOption::Filter(filter));
  heap_caps_free(raw);
  if (e) {
    snprintf(err, err_len, "the table did not parse: %s", e.c_str());
    return BCO_FAILED;
  }
  if (!bambuCatalogStore(doc["data"].as<JsonArrayConst>(), (uint32_t)time(nullptr), etag,
                         err, err_len, count)) {
    return BCO_FAILED;
  }
  noteChecked();
  return BCO_UPDATED;
}
