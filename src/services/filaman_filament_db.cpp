#include "filaman_filament_db.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "../hardware/sd_logger.h"
#include "color_family.h"
#include "fdb_block_stream.h"
#include "filaman_api.h"
#include "filament_db.h"
#include "tag_create.h"

// The proxy asks db.filaman.app on every request and gives it 15 s itself.
#define FM_FDB_TIMEOUT_MS   20000
// The proxy's page ceiling (422 above).
#define FM_FDB_PAGE         100
// SUNLU, the most filaments of one maker, is 10 pages (09.10.2026).
#define FM_FDB_PAGES_MAX    20
// FilaMan's own lists answer up to 200 a page.
#define FM_OWN_PAGE         200
#define FM_OWN_PAGES_MAX    10
// Different material names over every maker looked at; a maker has up to 40.
#define FM_MATERIALS_MAX    128
#define FM_STYLE_STRIPED    "striped"
#define FM_MODE_MULTI       "multi"

namespace {

// ArduinoJson has to be told to use PSRAM, and the allocator must be defined
// in every translation unit that needs it. A filtered page is tens of kB.
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

// A maker as the FilamentDB knows it.
struct FmMaker {
  char name[32];
  int  id;
  char slug[32];
  bool web_logo;
  bool label_logo;
};

struct FmMaterial {
  char name[17];   // as FdbPair holds it
  char key[24];
};

struct EntriesCtx {
  int  no_color;
  bool full;
};

typedef void (*FmItemFn)(JsonObjectConst item, void* ctx);
typedef bool (*FmFullFn)(void* ctx);

// One paged list to walk: path ends in "page=", the page number goes after
// it. full() may end the walk early.
struct FmList {
  const char*   base_url;
  const char*   api_key;
  String        path;
  int           page_size;
  JsonDocument* filter;
  FmItemFn      fn;
  FmFullFn      full;
  void*         ctx;
};

}  // namespace

// Filled on the task, read by the loop once a load is collected.
static FmMaker*    s_makers    = nullptr;
static int         s_maker_n   = 0;
static FmMaterial* s_materials = nullptr;
static int         s_material_n = 0;

template <typename T>
static T* psramTable(T* p, size_t n) {
  if (p) return p;
  void* m = heap_caps_calloc(n, sizeof(T), MALLOC_CAP_SPIRAM);
  if (!m) m = calloc(n, sizeof(T));
  return (T*)m;
}

// ------------------------------------------------------------
//  Pages
// ------------------------------------------------------------

struct PageRead {
  JsonDocument* doc;
  JsonDocument* filter;
};

static bool readPage(Stream& raw, void* ctx) {
  PageRead* p = (PageRead*)ctx;
  FdbBlockStream s(raw);
  s.setTimeout(FM_FDB_TIMEOUT_MS);
  const DeserializationError err = deserializeJson(*p->doc, s, DeserializationOption::Filter(*p->filter));
  if (err) logSDf("Filament DB: FilaMan page did not parse: %s", err.c_str());
  return !err;
}

static int getPage(const char* base_url, const char* api_key, const String& path,
                   JsonDocument& doc, JsonDocument& filter) {
  PageRead r = { &doc, &filter };
  return filamanGetStreamed(base_url, api_key, path.c_str(), FM_FDB_TIMEOUT_MS, readPage, &r);
}

// Every item of a paged list. The HTTP code.
static int eachItem(const FmList& list, int pages_max) {
  for (int page = 1; page <= pages_max; page++) {
    JsonDocument doc(&s_psram);
    const int code = getPage(list.base_url, list.api_key, list.path + page, doc, *list.filter);
    if (code != 200) {
      logSDf("Filament DB: %s%d -> HTTP %d", list.path.c_str(), page, code);
      return code;
    }
    JsonArrayConst items = doc["items"].as<JsonArrayConst>();
    for (JsonObjectConst item : items) list.fn(item, list.ctx);
    if ((int)items.size() < list.page_size || (list.full && list.full(list.ctx))) break;
  }
  return 200;
}

static JsonObject itemFilter(JsonDocument& filter) {
  return filter["items"].to<JsonArray>().add<JsonObject>();
}

static bool diameterFits(JsonObjectConst f) {
  return fabsf((f["diameter_mm"] | 0.0f) - FDB_DIAMETER_MM) <= FDB_DIAMETER_TOL_MM;
}

static const FmMaker* findMaker(const char* name) {
  for (int i = 0; s_makers && i < s_maker_n; i++)
    if (strcasecmp(s_makers[i].name, name) == 0) return &s_makers[i];
  return nullptr;
}

// ------------------------------------------------------------
//  The index
// ------------------------------------------------------------

// 200 when the plugin is active, 404 when it is not, else the code.
static int pluginActive(const char* base_url, const char* api_key) {
  JsonDocument filter;
  filter["active"] = true;
  JsonDocument doc;
  const int code = getPage(base_url, api_key, "/api/v1/filamentdb/status", doc, filter);
  if (code != 200) { logSDf("Filament DB: FilaMan status -> HTTP %d", code); return code; }
  if (doc["active"] | false) return 200;
  logSD("Filament DB: FilamentDB plugin not active in FilaMan");
  return 404;
}

static void makerItem(JsonObjectConst m, void*) {
  const char* name = m["name"] | "";
  const int count = m["filament_count"] | 0;
  if (!name[0] || count <= 0 || s_maker_n >= FDB_MAKERS_MAX) return;
  FmMaker& out = s_makers[s_maker_n++];
  snprintf(out.name, sizeof(out.name), "%s", name);
  snprintf(out.slug, sizeof(out.slug), "%s", m["slug"] | "");
  out.id         = m["id"] | 0;
  out.web_logo   = m["has_web_logo"] | false;
  out.label_logo = m["has_label_logo"] | false;
  fdbMakerAdd(name, (uint16_t)(count > UINT16_MAX ? UINT16_MAX : count));
}

static void ownedItem(JsonObjectConst m, void*) { fdbMarkOwned(m["name"] | ""); }

// The makers FilaMan has filaments by, marked in the index. A failure here
// costs only the order of the list.
static void markOwnedMakers(const char* base_url, const char* api_key) {
  JsonDocument filter;
  itemFilter(filter)["name"] = true;
  const FmList list = { base_url, api_key, String("/api/v1/manufacturers?page_size=") + FM_OWN_PAGE + "&page=",
                        FM_OWN_PAGE, &filter, ownedItem, nullptr, nullptr };
  eachItem(list, FM_OWN_PAGES_MAX);
}

int filamanFdbLoadIndex(const char* base_url, const char* api_key) {
  const int active = pluginActive(base_url, api_key);
  if (active != 200) return active;
  s_makers    = psramTable(s_makers, FDB_MAKERS_MAX);
  s_materials = psramTable(s_materials, FM_MATERIALS_MAX);
  if (!s_makers || !s_materials) { logSD("Filament DB: no memory for the FilaMan makers"); return -1; }
  s_maker_n = 0;
  s_material_n = 0;
  JsonDocument filter;
  JsonObject f = itemFilter(filter);
  for (const char* key : { "id", "name", "slug", "has_web_logo", "has_label_logo", "filament_count" })
    f[key] = true;
  const FmList list = { base_url, api_key,
                        String("/api/v1/filamentdb/manufacturers?page_size=") + FM_FDB_PAGE + "&page=",
                        FM_FDB_PAGE, &filter, makerItem, nullptr, nullptr };
  const int code = eachItem(list, FM_FDB_PAGES_MAX);
  if (code != 200) return code;
  markOwnedMakers(base_url, api_key);
  return 200;
}

// ------------------------------------------------------------
//  A maker's materials
// ------------------------------------------------------------

static void rememberMaterial(const char* name, const char* key) {
  char held[sizeof(FmMaterial::name)];
  snprintf(held, sizeof(held), "%s", name);
  for (int i = 0; i < s_material_n; i++)
    if (strcasecmp(s_materials[i].name, held) == 0) return;
  if (s_material_n >= FM_MATERIALS_MAX) return;
  FmMaterial& m = s_materials[s_material_n++];
  snprintf(m.name, sizeof(m.name), "%s", held);
  snprintf(m.key, sizeof(m.key), "%s", key);
}

static void pairItem(JsonObjectConst f, void* ctx) {
  if (!diameterFits(f)) return;
  const char* name = f["material"]["name"] | "";
  const char* key  = f["material"]["key"] | "";
  if (!name[0] || !key[0]) return;
  rememberMaterial(name, key);
  fdbIndexAdd((const char*)ctx, name);
}

int filamanFdbLoadPairs(const char* base_url, const char* api_key, const char* maker) {
  const FmMaker* m = findMaker(maker);
  if (!m || !s_materials) { logSDf("Filament DB: %s is not in the FilaMan index", maker); return -1; }
  JsonDocument filter;
  JsonObject f = itemFilter(filter);
  f["diameter_mm"] = true;
  f["material"]["key"]  = true;
  f["material"]["name"] = true;
  const FmList list = { base_url, api_key,
                        String("/api/v1/filamentdb/filaments?manufacturer_id=") + m->id +
                          "&page_size=" + FM_FDB_PAGE + "&page=",
                        FM_FDB_PAGE, &filter, pairItem, nullptr, (void*)maker };
  return eachItem(list, FM_FDB_PAGES_MAX);
}

// ------------------------------------------------------------
//  One maker's list
// ------------------------------------------------------------

// "#1E63BF" as "1E63BF"; false when there is no colour.
static bool plainHex(const char* code, char* out, size_t out_size) {
  if (code[0] == '#') code++;
  if (strlen(code) < 6) return false;
  snprintf(out, out_size, "%.6s", code);
  return true;
}

// The colours of an entry. A multi colour one lists them; FilaMan stripes
// them across the filament or runs them along it.
static bool readColors(JsonObjectConst f, FdbEntry* e) {
  JsonArrayConst list = f["colors"].as<JsonArrayConst>();
  e->ncolors = 0;
  e->kind = TCK_SINGLE;
  if (strcmp(f["color_mode"] | "", FM_MODE_MULTI) == 0 && list.size() >= 2) {
    for (JsonObjectConst c : list) {
      if (e->ncolors >= TAG_CREATE_COLOURS) break;
      if (plainHex(c["hex_code"] | "", e->hex[e->ncolors], sizeof(e->hex[0]))) e->ncolors++;
    }
    e->kind = strcmp(f["multi_color_style"] | "", FM_STYLE_STRIPED) == 0 ? TCK_DUAL : TCK_GRADIENT;
  }
  if (e->ncolors < 2) {
    e->kind = TCK_SINGLE;
    e->ncolors = plainHex(f["hex_color"] | "", e->hex[0], sizeof(e->hex[0])) ? 1 : 0;
  }
  if (e->ncolors == 0) return false;
  snprintf(e->db_hex, sizeof(e->db_hex), "%s", e->hex[0]);
  e->family = colorFamilyOf(e->hex[0], e->ncolors);
  return true;
}

// The colour's name ends the designation, "Aero - Black (14103)": where it
// begins, 0 when the designation is the colour alone or does not end in it.
static uint8_t colorOffset(const char* designation, const char* color_name) {
  const size_t d = strlen(designation), c = strlen(color_name);
  if (c == 0 || c >= d || strcmp(designation + d - c, color_name) != 0) return 0;
  return d - c < FDB_NAME_MAX ? (uint8_t)(d - c) : 0;
}

static void entryItem(JsonObjectConst f, void* p) {
  EntriesCtx* ctx = (EntriesCtx*)p;
  if (ctx->full || !diameterFits(f)) return;
  FdbEntry e = {};
  // Without a colour the filament cannot be created, nor drawn.
  if (!readColors(f, &e)) { ctx->no_color++; return; }
  const char* designation = f["designation"] | "";
  snprintf(e.id, sizeof(e.id), "%d", f["id"] | 0);
  snprintf(e.name, sizeof(e.name), "%s", designation);
  snprintf(e.line, sizeof(e.line), "%s", f["material_subtype"] | "");
  e.color_at       = colorOffset(designation, f["color_name"] | "");
  e.weight_g       = (uint16_t)(f["nominal_weight_g"] | 0);
  e.spool_weight_g = (uint16_t)lroundf(f["spool_profile"]["empty_weight_g"] | 0.0f);
  e.density        = f["density_g_cm3"] | 0.0f;
  e.extruder_temp  = (int16_t)(f["temp_nozzle_max"] | 0);
  e.bed_temp       = (int16_t)(f["temp_bed"] | 0);
  if (!e.name[0] || fdbEntryListed(e)) return;
  if (!fdbEntryAdd(e)) ctx->full = true;
}

static bool entriesFull(void* p) { return ((EntriesCtx*)p)->full; }

static void entryFilter(JsonDocument& filter) {
  JsonObject f = itemFilter(filter);
  for (const char* key : { "id", "designation", "color_name", "material_subtype", "hex_color",
                           "color_mode", "multi_color_style", "diameter_mm", "density_g_cm3",
                           "temp_nozzle_max", "temp_bed", "nominal_weight_g" })
    f[key] = true;
  f["colors"].to<JsonArray>().add<JsonObject>()["hex_code"] = true;
  f["spool_profile"]["empty_weight_g"] = true;
}

int filamanFdbLoadEntries(const char* base_url, const char* api_key,
                          const char* maker, const char* material) {
  const FmMaker* m = findMaker(maker);
  char key[sizeof(FmMaterial::key)];
  if (!m || !filamanFdbMaterialKey(material, key, sizeof(key))) {
    logSDf("Filament DB: %s %s is not in the FilaMan index", maker, material);
    return -1;
  }
  JsonDocument filter;
  entryFilter(filter);
  EntriesCtx ctx = { 0, false };
  const FmList list = { base_url, api_key,
                        String("/api/v1/filamentdb/filaments?manufacturer_id=") + m->id + "&material_key=" +
                          filamanUrlEncode(key) + "&page_size=" + FM_FDB_PAGE + "&page=",
                        FM_FDB_PAGE, &filter, entryItem, entriesFull, &ctx };
  const int code = eachItem(list, FM_FDB_PAGES_MAX);
  if (ctx.no_color) logSDf("Filament DB: %s %s, %d without a colour left out", maker, material, ctx.no_color);
  if (ctx.full) logSDf("Filament DB: %s %s cut at %d entries", maker, material, FDB_ENTRIES_MAX);
  return code;
}

// ------------------------------------------------------------
//  For the create path
// ------------------------------------------------------------

bool filamanFdbMakerInfo(const char* maker, FmFdbMakerInfo* out) {
  const FmMaker* m = maker ? findMaker(maker) : nullptr;
  if (!m || !out) return false;
  snprintf(out->slug, sizeof(out->slug), "%s", m->slug);
  out->web_logo   = m->web_logo;
  out->label_logo = m->label_logo;
  return true;
}

bool filamanFdbMaterialKey(const char* material, char* out, size_t out_size) {
  for (int i = 0; material && s_materials && i < s_material_n; i++) {
    if (strcasecmp(s_materials[i].name, material) != 0) continue;
    snprintf(out, out_size, "%s", s_materials[i].key);
    return true;
  }
  return false;
}

// ------------------------------------------------------------
//  A tag's entry
// ------------------------------------------------------------

// For one article the proxy answers with a handful at the most.
#define FM_FDB_TAG_PAGE  20

struct TagFind {
  const TagCreateInput* in;
  JsonObjectConst       best;
  bool                  best_material;   // best is of the tag's material
};

static bool namesArticle(JsonObjectConst f, const char* article) {
  return tagCreateArticleInText(f["designation"] | "", article) ||
         tagCreateArticleInText(f["color_name"] | "", article);
}

static void judgeTagEntry(JsonObjectConst f, TagFind* find) {
  if (!diameterFits(f) || !namesArticle(f, find->in->article)) return;
  const bool material = strcasecmp(f["material"]["key"] | "", find->in->material) == 0;
  if (!find->best.isNull() && (find->best_material || !material)) return;
  find->best = f;
  find->best_material = material;
}

static void takeTagEntry(JsonObjectConst f, TagDbEntry* out) {
  memset(out, 0, sizeof(*out));
  snprintf(out->id, sizeof(out->id), "%d", f["id"] | 0);
  snprintf(out->name, sizeof(out->name), "%s", f["designation"] | "");
  snprintf(out->color_name, sizeof(out->color_name), "%s", f["color_name"] | "");
  snprintf(out->line, sizeof(out->line), "%s", f["material_subtype"] | "");
  snprintf(out->material_key, sizeof(out->material_key), "%s", f["material"]["key"] | "");
  const char* hex = f["hex_color"] | "";
  if (plainHex(hex, out->color_hex, sizeof(out->color_hex)))
    snprintf(out->color_raw, sizeof(out->color_raw), "%s", out->color_hex);
  out->net_weight_g = f["nominal_weight_g"] | 0;
  out->density      = f["density_g_cm3"] | 0.0f;
  out->nozzle_min   = f["temp_nozzle_min"] | 0;
  out->nozzle_max   = f["temp_nozzle_max"] | 0;
  out->bed_temp     = f["temp_bed"] | 0;
}

bool filamanFdbFindForTag(const char* base_url, const char* api_key, const TagCreateInput& in,
                          TagDbEntry* out) {
  if (!in.article[0] || !in.vendor[0]) return false;
  JsonDocument filter;
  JsonObject f = itemFilter(filter);
  for (const char* key : { "id", "designation", "color_name", "material_subtype", "hex_color",
                           "diameter_mm", "density_g_cm3", "temp_nozzle_min", "temp_nozzle_max",
                           "temp_bed", "nominal_weight_g" })
    f[key] = true;
  f["material"]["key"] = true;
  const String path = String("/api/v1/filamentdb/filaments?manufacturer_name=") + filamanUrlEncode(in.vendor) +
                      "&search=" + filamanUrlEncode(in.article) + "&page_size=" + FM_FDB_TAG_PAGE;
  JsonDocument doc(&s_psram);
  const int code = getPage(base_url, api_key, path, doc, filter);
  if (code != 200) {
    logSDf("Filament DB: tag %s %s -> HTTP %d", in.vendor, in.article, code);
    return false;
  }
  TagFind find = { &in, JsonObjectConst(), false };
  for (JsonObjectConst item : doc["items"].as<JsonArrayConst>()) judgeTagEntry(item, &find);
  if (find.best.isNull()) {
    logSDf("Filament DB: tag %s %s not in the FilamentDB", in.vendor, in.article);
    return false;
  }
  takeTagEntry(find.best, out);
  logSDf("Filament DB: tag %s %s is #%s \"%s\"%s", in.vendor, in.article, out->id, out->name,
         find.best_material ? "" : " (other material)");
  return true;
}
