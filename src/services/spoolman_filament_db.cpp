#include "spoolman_filament_db.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>
#include <math.h>
#include <string.h>
#include <strings.h>

#include "../app/backend_switch.h"
#include "../hardware/sd_logger.h"
#include "fdb_block_stream.h"
#include "filament_db.h"
#include "filament_db_store.h"
#include "spoolman_api.h"
#include "tag_create.h"

// The whole database is 3 MB; on a slow link that takes a while, and the
// read timeout is per read, not for the whole answer.
#define SM_FDB_TIMEOUT_MS      15000
// A probe reads no body: the status is the answer.
#define SM_FDB_PROBE_TIMEOUT_MS 8000
// The search answers at most 100 per request (422 above, Spoolman 0.27.0).
#define SM_FDB_PAGE            100
// Polymaker PLA, the longest list, is 768 entries over every diameter.
#define SM_FDB_PAGES_MAX       20
// The index counts each filament once, not once per weight it comes in:
// hashes of maker, material and name in an open table, a power of two well
// above the 4705 names of 1.75 mm.
#define SM_FDB_SEEN_SLOTS      16384
#define SM_FDB_DIRECTION_ACROSS "coaxial"
// The routes of the inventory contract, section 6.4.
#define SM_FDB_INDEX_PATH      "/api/v1/external/manufacturer"
#define SM_FDB_LIST_PATH       "/api/v1/external/filament"
#define SM_FDB_SEARCH_PATH     "/api/v1/external/filament/search"
// FDB_DIAMETER_MM as the query spells it.
#define SM_FDB_DIAMETER_QUERY  "diameter=1.75"
// What a name may put between the product line and the colour.
#define SM_FDB_LINE_SEP        " - "

namespace {

// ArduinoJson has to be told to use PSRAM, and the allocator must be defined
// in every translation unit that needs it. The light index is tens of kB.
struct SpiRamAllocator : ArduinoJson::Allocator {
  void* allocate(size_t size) override {
    void* ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
    if (!ptr) ptr = malloc(size);
    return ptr;
  }
  void deallocate(void* pointer) override { heap_caps_free(pointer); }
  void* reallocate(void* ptr, size_t new_size) override {
    void* p = heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM);
    if (!p) p = realloc(ptr, new_size);
    return p;
  }
};

SpiRamAllocator s_psram;

}  // namespace

// ------------------------------------------------------------
//  Which form
// ------------------------------------------------------------

// Per backend generation. Two tasks may probe at once the first time (the
// picker's index on its task, a tag's plan elsewhere): both write the same
// answer, so the race costs one request at most.
static SmFdbForm s_form       = SM_FDB_UNKNOWN;
static uint32_t  s_form_gen   = 0;
static int       s_probe_code = 0;

static bool readNothing(Stream&, void*) { return true; }

static int probe(const char* base_url, const char* path) {
  return spoolmanGetStreamed(base_url, path, SM_FDB_PROBE_TIMEOUT_MS, readNothing, nullptr);
}

static bool saysNo(int code) { return code == 404 || code == 405; }

SmFdbForm spoolmanFdbForm(const char* base_url) {
  const uint32_t gen = backendGeneration();
  if (s_form != SM_FDB_UNKNOWN && s_form_gen == gen) return s_form;
  int code = probe(base_url, SM_FDB_INDEX_PATH);
  SmFdbForm form = SM_FDB_UNKNOWN;
  if (code == 200) {
    form = SM_FDB_LIGHT;
  } else if (saysNo(code)) {
    code = probe(base_url, SM_FDB_SEARCH_PATH "?limit=1&query=PLA");
    if (code == 200)    form = SM_FDB_SPOOLMAN;
    else if (saysNo(code)) form = SM_FDB_NONE;
  }
  static const char* const NAMES[] = { "not answered", "light form", "Spoolman form", "none" };
  logSDf("Filament DB: %s (HTTP %d)", NAMES[form], code);
  s_probe_code = code;
  s_form       = form;
  s_form_gen   = gen;
  return form;
}

int spoolmanFdbProbeCode() { return s_probe_code; }

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

// An entry without a diameter reads as 1.75 mm (contract 6.4).
static bool diameterFits(JsonObjectConst e) {
  JsonVariantConst d = e["diameter"];
  if (d.isNull()) return true;
  return fabsf((d | 0.0f) - FDB_DIAMETER_MM) <= FDB_DIAMETER_TOL_MM;
}

// The fields of an entry the scale reads (contract 6.4).
static void entryFilter(JsonDocument& filter) {
  static const char* const FIELDS[] = {
    "id", "manufacturer", "name", "material", "line", "diameter", "weight", "spool_weight",
    "density", "extruder_temp", "bed_temp", "color_hex", "color_hexes", "multi_color_direction"
  };
  for (const char* f : FIELDS) filter[f] = true;
}

// The maker's filtered list of the light form.
static String lightListPath(const char* maker, const char* material) {
  return String(SM_FDB_LIST_PATH "?manufacturer=") + spoolmanUrlEncode(maker) +
         "&material=" + spoolmanUrlEncode(material) + "&" SM_FDB_DIAMETER_QUERY;
}

// ------------------------------------------------------------
//  The index, Spoolman form: the whole database boiled down
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

static int loadWholeIndex(const char* base_url) {
  // After a restart the index of the last week is still in flash, and the
  // 3 MB need not be read again. Whose spools the inventory has may have
  // changed since, so that is asked either way.
  if (fdbStoreLoad(base_url)) {
    markOwnedMakers(base_url);
    return 200;
  }
  IndexCtx ctx;
  ctx.seen = (uint32_t*)heap_caps_calloc(SM_FDB_SEEN_SLOTS, sizeof(uint32_t), MALLOC_CAP_SPIRAM);
  if (!ctx.seen) ctx.seen = (uint32_t*)calloc(SM_FDB_SEEN_SLOTS, sizeof(uint32_t));
  if (!ctx.seen) { logSD("Filament DB: no memory to count the index"); return -1; }
  const int code = spoolmanGetStreamed(base_url, SM_FDB_LIST_PATH, SM_FDB_TIMEOUT_MS, readIndex, &ctx);
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
//  The index, light form: makers with materials and counts
// ------------------------------------------------------------

static uint16_t countOf(JsonVariantConst v) {
  const long n = v | 0L;
  if (n <= 0) return 0;
  return n > UINT16_MAX ? UINT16_MAX : (uint16_t)n;
}

static int loadLightIndex(const char* base_url) {
  JsonDocument filter;
  JsonObject f = filter.to<JsonArray>().add<JsonObject>();
  f["name"] = true;
  JsonObject m = f["materials"].to<JsonArray>().add<JsonObject>();
  m["name"]  = true;
  m["count"] = true;
  JsonDocument doc(&s_psram);
  const int code = spoolmanGetJson(base_url, SM_FDB_INDEX_PATH "?" SM_FDB_DIAMETER_QUERY, doc,
                                   SM_FDB_TIMEOUT_MS, &filter);
  if (code != 200) {
    logSDf("Filament DB: index -> HTTP %d", code);
    return code;
  }
  int makers = 0, pairs = 0;
  for (JsonObjectConst mk : doc.as<JsonArrayConst>()) {
    const char* maker = mk["name"] | "";
    if (!maker[0]) continue;
    makers++;
    for (JsonObjectConst mat : mk["materials"].as<JsonArrayConst>()) {
      const char* material = mat["name"] | "";
      if (!material[0]) continue;
      fdbPairAdd(maker, material, countOf(mat["count"]));
      pairs++;
    }
  }
  logSDf("Filament DB: index, %d makers, %d pairs", makers, pairs);
  return 200;
}

int spoolmanFdbLoadIndex(const char* base_url) {
  const SmFdbForm form = spoolmanFdbForm(base_url);
  if (form == SM_FDB_LIGHT) {
    const int code = loadLightIndex(base_url);
    if (code == 200) markOwnedMakers(base_url);
    return code;
  }
  // None (404), or not answered: its code, asked again later.
  if (form != SM_FDB_SPOOLMAN) return s_probe_code;
  return loadWholeIndex(base_url);
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

// Where the colour begins in a name that starts with the entry's product
// line: "Matte Black" with line "Matte" is 6, "Matte - Black" is 8; 0 when
// the name does not start with it, or has nothing after it.
static uint8_t lineOffset(const char* name, const char* line) {
  const size_t n = strlen(line);
  if (!n || strncasecmp(name, line, n) != 0) return 0;
  size_t at = n;
  if (strncmp(name + at, SM_FDB_LINE_SEP, strlen(SM_FDB_LINE_SEP)) == 0) at += strlen(SM_FDB_LINE_SEP);
  else if (name[at] == ' ') at += 1;
  else return 0;
  return at < FDB_NAME_MAX && name[at] ? (uint8_t)at : 0;
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
  snprintf(e.line, sizeof(e.line), "%s", j["line"] | "");
  e.color_at       = lineOffset(e.name, e.line);
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
  JsonDocument filter;
  entryFilter(filter);
  return eachElement(body, filter, entryElement, ctx);
}

// The light form answers the whole list of one maker and material at once.
static int loadLightEntries(const char* base_url, EntriesCtx* ctx) {
  const String path = lightListPath(ctx->maker, ctx->material);
  const int code = spoolmanGetStreamed(base_url, path.c_str(), SM_FDB_TIMEOUT_MS, readEntries, ctx);
  if (code != 200) logSDf("Filament DB: %s %s -> HTTP %d", ctx->maker, ctx->material, code);
  if (ctx->full) logSDf("Filament DB: %s %s cut at %d entries", ctx->maker, ctx->material, FDB_ENTRIES_MAX);
  return code;
}

int spoolmanFdbLoadEntries(const char* base_url, const char* maker, const char* material) {
  EntriesCtx ctx = { maker, material, 0, false };
  if (spoolmanFdbForm(base_url) == SM_FDB_LIGHT) return loadLightEntries(base_url, &ctx);
  // The search takes every word, in any field: maker and material narrow it
  // to the maker's filaments of that material and a few more ("PLA" is in
  // "PLA-CF"), which entryElement() then leaves out.
  const String words = String(maker) + " " + material;
  const String query = String(SM_FDB_SEARCH_PATH "?limit=") + SM_FDB_PAGE +
                       "&query=" + spoolmanUrlEncode(words.c_str()) + "&offset=";
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

// ------------------------------------------------------------
//  The light list for the plan
// ------------------------------------------------------------

struct EachCtx {
  SpoolmanFdbEntryFn fn;
  void*              ctx;
};

static void eachOfElement(JsonObjectConst e, void* p) {
  EachCtx* c = (EachCtx*)p;
  c->fn(e, c->ctx);
}

static bool readEach(Stream& body, void* ctx) {
  JsonDocument filter;
  entryFilter(filter);
  return eachElement(body, filter, eachOfElement, ctx);
}

int spoolmanFdbEachOf(const char* base_url, const char* maker, const char* material,
                      SpoolmanFdbEntryFn fn, void* ctx) {
  EachCtx c = { fn, ctx };
  const String path = lightListPath(maker, material);
  return spoolmanGetStreamed(base_url, path.c_str(), SM_FDB_TIMEOUT_MS, readEach, &c);
}
