#include "spoolman_filament_db.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>
#include <math.h>
#include <string.h>
#include <strings.h>

#include "../hardware/sd_logger.h"
#include "fdb_block_stream.h"
#include "filament_db.h"
#include "filament_db_store.h"
#include "spoolman_api.h"
#include "tag_create.h"

// The whole database is 3 MB; on a slow link that takes a while, and the
// read timeout is per read, not for the whole answer.
#define SM_FDB_TIMEOUT_MS      15000
// The search answers at most 100 per request (422 above, Spoolman 0.27.0).
#define SM_FDB_PAGE            100
// Polymaker PLA, the longest list, is 768 entries over every diameter.
#define SM_FDB_PAGES_MAX       20
// The index counts each filament once, not once per weight it comes in:
// hashes of maker, material and name in an open table, a power of two well
// above the 4705 names of 1.75 mm.
#define SM_FDB_SEEN_SLOTS      16384
#define SM_FDB_DIRECTION_ACROSS "coaxial"

// ------------------------------------------------------------
//  Reading the body
// ------------------------------------------------------------

static int skipBlanks(Stream& s) {
  int c;
  do { c = s.read(); } while (c == ' ' || c == '\n' || c == '\r' || c == '\t');
  return c;
}

typedef void (*FdbElementFn)(JsonObjectConst e, void* ctx);

// Each object of a JSON array, one at a time, through the filter: the
// array is never held whole. False when the body is not such an array or
// broke off.
static bool eachElement(Stream& raw, JsonDocument& filter, FdbElementFn fn, void* ctx) {
  FdbBlockStream s(raw);
  s.setTimeout(SM_FDB_TIMEOUT_MS);
  if (skipBlanks(s) != '[') return false;
  JsonDocument doc;
  for (;;) {
    while (s.peek() == ' ' || s.peek() == '\n' || s.peek() == '\r' || s.peek() == '\t') s.read();
    if (s.peek() == ']') return true;
    const DeserializationError err = deserializeJson(doc, s, DeserializationOption::Filter(filter));
    if (err) { logSDf("Filament DB: element did not parse: %s", err.c_str()); return false; }
    fn(doc.as<JsonObjectConst>(), ctx);
    const int c = skipBlanks(s);
    if (c == ']') return true;
    if (c != ',') return false;
  }
}

static bool diameterFits(JsonObjectConst e) {
  return fabsf((e["diameter"] | 0.0f) - FDB_DIAMETER_MM) <= FDB_DIAMETER_TOL_MM;
}

// ------------------------------------------------------------
//  The index
// ------------------------------------------------------------

struct IndexCtx {
  uint32_t* seen;
};

static uint32_t nameHash(const char* maker, const char* material, const char* name) {
  uint32_t h = 2166136261u;   // FNV-1a
  for (const char* part : { maker, material, name }) {
    for (const char* p = part; *p; p++) { h ^= (uint8_t)*p; h *= 16777619u; }
    h ^= 0x1F; h *= 16777619u;   // a separator: "AB"+"C" is not "A"+"BC"
  }
  return h ? h : 1;   // 0 marks an empty slot
}

// True the first time a hash is offered. A full table counts everything.
static bool firstTime(uint32_t* seen, uint32_t h) {
  for (uint32_t i = 0, slot = h; i < SM_FDB_SEEN_SLOTS; i++, slot++) {
    uint32_t& v = seen[slot & (SM_FDB_SEEN_SLOTS - 1)];
    if (v == h) return false;
    if (v == 0) { v = h; return true; }
  }
  return true;
}

static void indexElement(JsonObjectConst e, void* p) {
  IndexCtx* ctx = (IndexCtx*)p;
  if (!diameterFits(e)) return;
  const char* maker = e["manufacturer"] | "";
  const char* material = e["material"] | "";
  if (!firstTime(ctx->seen, nameHash(maker, material, e["name"] | ""))) return;
  fdbIndexAdd(maker, material);
}

static bool readIndex(Stream& body, void* ctx) {
  JsonDocument filter;
  filter["manufacturer"] = true;
  filter["material"]     = true;
  filter["name"]         = true;
  filter["diameter"]     = true;
  return eachElement(body, filter, indexElement, ctx);
}

// The makers the inventory has spools by, marked in the index. A failure
// here costs only the order of the list.
static void markOwnedMakers(const char* base_url) {
  JsonDocument filter;
  filter.to<JsonArray>().add<JsonObject>()["name"] = true;
  JsonDocument doc;
  const int code = spoolmanGetJson(base_url, "/api/v1/vendor", doc, SM_FDB_TIMEOUT_MS, &filter);
  if (code != 200) { logSDf("Filament DB: vendor list -> HTTP %d", code); return; }
  for (JsonObjectConst v : doc.as<JsonArrayConst>()) fdbMarkOwned(v["name"] | "");
}

// The search came with Spoolman 0.27. An older one has the whole database,
// but no way to read one maker's list from it, and the picker needs both:
// asked first, before 3 MB are read for nothing.
static int searchAvailable(const char* base_url) {
  JsonDocument doc;
  return spoolmanGetJson(base_url, "/api/v1/external/filament/search?limit=1&query=PLA", doc,
                         SM_FDB_TIMEOUT_MS);
}

int spoolmanFdbLoadIndex(const char* base_url) {
  // After a restart the index of the last week is still in flash, and the
  // 3 MB need not be read again. Whose spools the inventory has may have
  // changed since, so that is asked either way.
  if (fdbStoreLoad(base_url)) {
    markOwnedMakers(base_url);
    return 200;
  }
  const int probe = searchAvailable(base_url);
  if (probe != 200) {
    logSDf("Filament DB: search -> HTTP %d", probe);
    return probe;
  }
  IndexCtx ctx;
  ctx.seen = (uint32_t*)heap_caps_calloc(SM_FDB_SEEN_SLOTS, sizeof(uint32_t), MALLOC_CAP_SPIRAM);
  if (!ctx.seen) ctx.seen = (uint32_t*)calloc(SM_FDB_SEEN_SLOTS, sizeof(uint32_t));
  if (!ctx.seen) { logSD("Filament DB: no memory to count the index"); return -1; }
  const int code = spoolmanGetStreamed(base_url, "/api/v1/external/filament", SM_FDB_TIMEOUT_MS,
                                       readIndex, &ctx);
  heap_caps_free(ctx.seen);
  if (code != 200) {
    logSDf("Filament DB: index -> HTTP %d", code);
    return code;
  }
  fdbStoreSave(base_url);   // before the marks: those are asked fresh each time
  markOwnedMakers(base_url);
  return 200;
}

// ------------------------------------------------------------
//  One maker's list
// ------------------------------------------------------------

struct EntriesCtx {
  const char* maker;
  const char* material;
  int         seen_on_page;   // elements of the page, matching or not
  bool        full;
};

// SpoolmanDB writes a see-through colour with its alpha in front, AARRGGBB.
static void readColor(const char* db_hex, FdbEntry* e) {
  snprintf(e->db_hex, sizeof(e->db_hex), "%s", db_hex);
  const size_t len = strlen(db_hex);
  char rgba[9] = "";
  if (len == 8) snprintf(rgba, sizeof(rgba), "%.6s%.2s", db_hex + 2, db_hex);
  else          snprintf(rgba, sizeof(rgba), "%.6s", db_hex);
  snprintf(e->hex[0], sizeof(e->hex[0]), "%.6s", rgba);
  e->ncolors = len >= 6 ? 1 : 0;
  e->family  = colorFamilyOf(rgba, e->ncolors);
}

static void readColors(JsonArrayConst list, const char* direction, FdbEntry* e) {
  e->ncolors = 0;
  for (JsonVariantConst c : list) {
    if (e->ncolors >= TAG_CREATE_COLOURS) break;
    snprintf(e->hex[e->ncolors++], sizeof(e->hex[0]), "%.6s", c | "");
  }
  e->kind   = strcmp(direction, SM_FDB_DIRECTION_ACROSS) == 0 ? TCK_DUAL : TCK_GRADIENT;
  e->family = colorFamilyOf(e->hex[0], e->ncolors);
}

static void entryElement(JsonObjectConst j, void* p) {
  EntriesCtx* ctx = (EntriesCtx*)p;
  ctx->seen_on_page++;
  if (!diameterFits(j)) return;
  if (strcasecmp(j["manufacturer"] | "", ctx->maker) != 0) return;
  if (strcasecmp(j["material"] | "", ctx->material) != 0) return;
  FdbEntry e = {};
  snprintf(e.id, sizeof(e.id), "%s", j["id"] | "");
  snprintf(e.name, sizeof(e.name), "%s", j["name"] | "");
  e.weight_g       = (uint16_t)lroundf(j["weight"] | 0.0f);
  e.spool_weight_g = (uint16_t)lroundf(j["spool_weight"] | 0.0f);
  e.density        = j["density"] | 0.0f;
  e.extruder_temp  = (int16_t)(j["extruder_temp"] | 0);
  e.bed_temp       = (int16_t)(j["bed_temp"] | 0);
  JsonArrayConst multi = j["color_hexes"].as<JsonArrayConst>();
  if (multi.size() >= 2) readColors(multi, j["multi_color_direction"] | "", &e);
  else                   readColor(j["color_hex"] | "", &e);
  if (!e.id[0] || !e.name[0] || fdbEntryListed(e)) return;
  if (!fdbEntryAdd(e)) ctx->full = true;
}

static bool readEntries(Stream& body, void* ctx) {
  static const char* const FIELDS[] = {
    "id", "manufacturer", "name", "material", "diameter", "weight", "spool_weight",
    "density", "extruder_temp", "bed_temp", "color_hex", "color_hexes", "multi_color_direction"
  };
  JsonDocument filter;
  for (const char* f : FIELDS) filter[f] = true;
  return eachElement(body, filter, entryElement, ctx);
}

int spoolmanFdbLoadEntries(const char* base_url, const char* maker, const char* material) {
  // The search takes every word, in any field: maker and material narrow it
  // to the maker's filaments of that material and a few more ("PLA" is in
  // "PLA-CF"), which entryElement() then leaves out.
  const String words = String(maker) + " " + material;
  const String query = String("/api/v1/external/filament/search?limit=") + SM_FDB_PAGE +
                       "&query=" + spoolmanUrlEncode(words.c_str()) + "&offset=";
  EntriesCtx ctx = { maker, material, 0, false };
  for (int page = 0; page < SM_FDB_PAGES_MAX && !ctx.full; page++) {
    ctx.seen_on_page = 0;
    const String path = query + (page * SM_FDB_PAGE);
    const int code = spoolmanGetStreamed(base_url, path.c_str(), SM_FDB_TIMEOUT_MS, readEntries, &ctx);
    if (code != 200) {
      logSDf("Filament DB: %s page %d -> HTTP %d", words.c_str(), page, code);
      return code;
    }
    if (ctx.seen_on_page < SM_FDB_PAGE) break;   // the last page
  }
  if (ctx.full) logSDf("Filament DB: %s cut at %d entries", words.c_str(), FDB_ENTRIES_MAX);
  return 200;
}
