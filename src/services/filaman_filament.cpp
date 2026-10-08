#include "filaman_filament.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>
#include <string.h>
#include <strings.h>

#include "../hardware/sd_logger.h"
#include "filaman_api.h"

#define FM_FIL_TIMEOUT_MS   8000
// FilaMan's page ceiling. Bambu's PLA alone came to 234 filaments on a test
// instance, so a lookup reads more than one page.
#define FM_FIL_PAGE_SIZE     200
// A safety net against a server that keeps answering full pages.
#define FM_FIL_MAX_PAGES      10

namespace {

// ArduinoJson has to be told to use PSRAM, and the allocator must be defined
// in every translation unit that needs it. A page of filaments is tens of
// kilobytes.
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

// What the walk through the vendor's filaments has found so far.
struct FilamentSearch {
  const TagCreateInput* in;
  int  by_article;        // lowest id carrying the article number
  int  by_look;           // lowest id with the colour and the product line
  char name_article[64];
  char name_look[64];
};

}  // namespace

// ------------------------------------------------------------
//  Paged lists
// ------------------------------------------------------------

// The request a lookup failed on, for the card: an HTTP status, or a
// transport code below zero.
static int s_failed_code = 0;

// Reads one page of a list into doc. The number of items on it, or -1 with
// the server's answer in s_failed_code.
static int readPage(const char* base_url, const char* api_key, const String& path,
                    JsonDocument& doc, JsonDocument& filter) {
  const int code = filamanGetJson(base_url, api_key, path.c_str(), doc, filter, FM_FIL_TIMEOUT_MS);
  if (code != 200) { s_failed_code = code; return -1; }
  return (int)doc["items"].size();
}

// The vendor's id, 0 when FilaMan has none yet, -1 on failure.
static int findManufacturer(const char* base_url, const char* api_key, const char* vendor) {
  JsonDocument filter;
  JsonObject f = filter["items"].to<JsonArray>().add<JsonObject>();
  f["id"]   = true;
  f["name"] = true;
  for (int page = 1; page <= FM_FIL_MAX_PAGES; page++) {
    JsonDocument doc(&s_psram);
    const String path = String("/api/v1/manufacturers?page_size=") + FM_FIL_PAGE_SIZE + "&page=" + page;
    const int n = readPage(base_url, api_key, path, doc, filter);
    if (n < 0) return n;
    for (JsonObjectConst m : doc["items"].as<JsonArrayConst>())
      if (strcasecmp(m["name"] | "", vendor) == 0) return m["id"] | 0;
    if (n < FM_FIL_PAGE_SIZE) break;
  }
  return 0;
}

// The colours a new filament needs, as FilaMan spells them without "#":
// the tag's colours, or 00000000 for a clear filament, which is how FilaMan
// already holds Bambu's clear spools.
struct ColorSet {
  char hex[TAG_CREATE_COLOURS][9];
  int  id[TAG_CREATE_COLOURS];
  int  count;
};

static void colorSetFor(const TagCreateInput& in, ColorSet* set) {
  memset(set, 0, sizeof(*set));
  if (in.clear) { snprintf(set->hex[0], sizeof(set->hex[0]), "%s", in.rgba); set->count = 1; return; }
  for (uint8_t i = 0; i < in.color_count; i++)
    snprintf(set->hex[set->count++], sizeof(set->hex[0]), "%s", in.colors_hex[i]);
}

// Whether FilaMan's "#009bd8" is this colour. A six digit colour matches only
// a seven character code: an eight digit one carries an alpha the hue lacks.
static bool sameCode(const char* code, const char* hex) {
  if (strlen(code) != strlen(hex) + 1) return false;
  return strcasecmp(code + 1, hex) == 0;
}

static void noteColor(JsonObjectConst c, ColorSet* set) {
  for (int i = 0; i < set->count; i++)
    if (!set->id[i] && sameCode(c["hex_code"] | "", set->hex[i])) set->id[i] = c["id"] | 0;
}

// Fills in the ids of the colours FilaMan already has, in one walk through
// its list; the rest stay 0. -1 on failure.
static int findColors(const char* base_url, const char* api_key, ColorSet* set) {
  JsonDocument filter;
  JsonObject f = filter["items"].to<JsonArray>().add<JsonObject>();
  f["id"]       = true;
  f["hex_code"] = true;
  for (int page = 1; page <= FM_FIL_MAX_PAGES; page++) {
    JsonDocument doc(&s_psram);
    const String path = String("/api/v1/colors?page_size=") + FM_FIL_PAGE_SIZE + "&page=" + page;
    const int n = readPage(base_url, api_key, path, doc, filter);
    if (n < 0) return n;
    for (JsonObjectConst c : doc["items"].as<JsonArrayConst>()) noteColor(c, set);
    if (n < FM_FIL_PAGE_SIZE) break;
  }
  return 0;
}

// ------------------------------------------------------------
//  The vendor's filaments
// ------------------------------------------------------------

static bool hasColor(JsonObjectConst fil, const char* hex) {
  for (JsonObjectConst c : fil["colors"].as<JsonArrayConst>())
    if (tagCreateSameHex(c["color"]["hex_code"] | "", hex)) return true;
  return false;
}

// The tag's colour is on the filament. A gradient, dual colour or clear spool
// is told by its colour's name ("Arctic Whisper", "Clear (32101)"): FilaMan's
// import keeps such a colour as one averaged value, A4BFDA for Arctic Whisper.
static bool colorsFit(JsonObjectConst fil, const TagCreateInput& in) {
  if (in.clear || in.color_count >= 2)
    return tagCreateNameMatches(fil["manufacturer_color_name"] | "", in);
  return in.color_count == 1 && hasColor(fil, in.color_hex);
}

static void keepLowest(int id, const char* name, int* best, char* best_name) {
  if (*best != 0 && id >= *best) return;
  *best = id;
  snprintf(best_name, 64, "%s", name);
}

static void judgeFilament(JsonObjectConst fil, FilamentSearch* s) {
  const TagCreateInput& in = *s->in;
  const int id = fil["id"] | 0;
  const char* designation = fil["designation"] | "";
  if (id <= 0) return;
  if (in.article[0] && (strcmp(filamanFilamentArticle(fil), in.article) == 0 ||
                        tagCreateArticleInText(fil["manufacturer_color_name"] | "", in.article) ||
                        tagCreateArticleInText(designation, in.article))) {
    keepLowest(id, designation, &s->by_article, s->name_article);
    return;
  }
  if (colorsFit(fil, in) &&
      tagCreateSubgroupMatches(fil["material_subgroup"] | "", designation, in))
    keepLowest(id, designation, &s->by_look, s->name_look);
}

static void filamentFilter(JsonDocument& filter) {
  JsonObject f = filter["items"].to<JsonArray>().add<JsonObject>();
  f["id"]                      = true;
  f["designation"]             = true;
  f["material_subgroup"]       = true;
  f["manufacturer_color_name"] = true;
  f["shop_url"]                = true;
  f["custom_fields"]["article_number"]     = true;
  f["custom_fields"]["bambu_product_code"] = true;
  f["colors"].to<JsonArray>().add<JsonObject>()["color"]["hex_code"] = true;
}

// Walks the vendor's filaments of the tag's material. 0 when done, -1 when a
// page could not be read.
static int searchFilaments(const char* base_url, const char* api_key, int vendor_id,
                           FilamentSearch* s) {
  JsonDocument filter;
  filamentFilter(filter);
  const String base = String("/api/v1/filaments?manufacturer_id=") + vendor_id + "&type=" +
                      filamanUrlEncode(s->in->material) + "&page_size=" + FM_FIL_PAGE_SIZE + "&page=";
  for (int page = 1; page <= FM_FIL_MAX_PAGES; page++) {
    JsonDocument doc(&s_psram);
    const int n = readPage(base_url, api_key, base + page, doc, filter);
    if (n < 0) return n;
    for (JsonObjectConst fil : doc["items"].as<JsonArrayConst>()) judgeFilament(fil, s);
    if (n < FM_FIL_PAGE_SIZE) break;
  }
  return 0;
}

// ------------------------------------------------------------
//  The plan
// ------------------------------------------------------------

static void planFound(const FilamentSearch& s, TagFilamentPlan* plan) {
  const bool article = s.by_article > 0;
  plan->state = TFS_FOUND;
  plan->filament_id = article ? s.by_article : s.by_look;
  snprintf(plan->name, sizeof(plan->name), "%s", article ? s.name_article : s.name_look);
}

void filamanPlanTagFilament(const char* base_url, const char* api_key,
                            const TagCreateInput& in, TagFilamentPlan* plan) {
  tagFilamentPlanClear(plan);
  s_failed_code = 0;
  plan->vendor_id = findManufacturer(base_url, api_key, in.vendor);
  if (plan->vendor_id < 0) { plan->state = TFS_FAILED; plan->http_code = s_failed_code; return; }

  if (plan->vendor_id > 0) {
    FilamentSearch s = {};
    s.in = &in;
    if (searchFilaments(base_url, api_key, plan->vendor_id, &s) < 0) {
      plan->state = TFS_FAILED;
      plan->http_code = s_failed_code;
      return;
    }
    if (s.by_article > 0 || s.by_look > 0) { planFound(s, plan); return; }
  }
  if (!in.names_known || (!in.color_count && !in.clear)) { plan->state = TFS_NEEDS_CATALOG; return; }
  tagCreateFilamanDesignation(in, plan->name, sizeof(plan->name));
  plan->state = TFS_CREATE_TAG;
}

// ------------------------------------------------------------
//  Creating
// ------------------------------------------------------------

static int postForId(const char* base_url, const char* api_key, const char* path,
                     JsonDocument& body, int* out_id) {
  String payload;
  serializeJson(body, payload);
  JsonDocument answer;
  const int code = filamanPostJson(base_url, api_key, path, payload, answer, FM_FIL_TIMEOUT_MS);
  *out_id = code == 200 ? (answer["id"] | 0) : 0;
  logSDf("FilaMan: POST %s -> HTTP %d, id %d", path, code, *out_id);
  return code;
}

static int ensureVendor(const char* base_url, const char* api_key, const TagCreateInput& in,
                        int known_id, int* out_id) {
  *out_id = known_id;
  if (known_id > 0) return 200;
  JsonDocument body;
  body["name"] = in.vendor;
  if (in.spool_weight_g > 0) body["empty_spool_weight_g"] = in.spool_weight_g;
  return postForId(base_url, api_key, "/api/v1/manufacturers", body, out_id);
}

// The ids of every colour the filament needs, creating the ones FilaMan has
// not got. 200, or the failing request's code.
static int ensureColors(const char* base_url, const char* api_key, ColorSet* set) {
  if (findColors(base_url, api_key, set) < 0) return s_failed_code;
  for (int i = 0; i < set->count; i++) {
    if (set->id[i] > 0) continue;
    // Named by its value, like the colours FilaMan's import creates.
    char hex[10];
    snprintf(hex, sizeof(hex), "#%s", set->hex[i]);
    JsonDocument body;
    body["name"]     = hex;
    body["hex_code"] = hex;
    const int code = postForId(base_url, api_key, "/api/v1/colors", body, &set->id[i]);
    if (set->id[i] <= 0) return code;
  }
  return 200;
}

static void filamentBody(const TagCreateInput& in, int vendor_id, const ColorSet& set,
                         JsonDocument& body) {
  char text[64];
  tagCreateFilamanDesignation(in, text, sizeof(text));
  body["designation"]     = text;
  body["manufacturer_id"] = vendor_id;
  body["material_type"]   = in.material;
  tagCreateFilamanSubgroup(in, text, sizeof(text));
  if (text[0]) body["material_subgroup"] = text;
  tagCreateFilamanColorName(in, text, sizeof(text));
  body["manufacturer_color_name"] = text;
  body["diameter_mm"] = in.diameter_mm > 0 ? in.diameter_mm : TAG_CREATE_DIAMETER_MM;
  if (in.net_weight_g > 0) body["raw_material_weight_g"] = in.net_weight_g;
  // Several colours: along the filament a gradient, across it stripes.
  body["color_mode"] = set.count >= 2 ? "multi" : "single";
  if (set.count >= 2) body["multi_color_style"] = in.color_kind == TCK_DUAL ? "striped" : "gradient";
  JsonArray colors = body["colors"].to<JsonArray>();
  for (int i = 0; i < set.count; i++) {
    JsonObject color = colors.add<JsonObject>();
    color["color_id"] = set.id[i];
    color["position"] = i + 1;
  }
  // The keys FilaMan's FilamentDB import uses, so its forms show them.
  if (in.article[0])   body["custom_fields"]["article_number"]  = in.article;
  if (in.temp_min > 0) body["custom_fields"]["temp_nozzle_min"] = in.temp_min;
  if (in.temp_max > 0) body["custom_fields"]["temp_nozzle_max"] = in.temp_max;
}

int filamanCreateTagFilament(const char* base_url, const char* api_key,
                             const TagCreateInput& in, const TagFilamentPlan& plan,
                             int* out_filament_id) {
  *out_filament_id = 0;
  int vendor_id = 0;
  int code = ensureVendor(base_url, api_key, in, plan.vendor_id, &vendor_id);
  if (vendor_id <= 0) return code;
  ColorSet set;
  colorSetFor(in, &set);
  code = ensureColors(base_url, api_key, &set);
  if (code != 200) return code;

  JsonDocument body;
  filamentBody(in, vendor_id, set, body);
  return postForId(base_url, api_key, "/api/v1/filaments", body, out_filament_id);
}
