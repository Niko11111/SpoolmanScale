#include "bambuddy_filament_db.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>
#include <initializer_list>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "../app_config.h"
#include "../hardware/sd_logger.h"
#include "bambuddy_api.h"
#include "color_family.h"
#include "fdb_block_stream.h"
#include "filament_db.h"
#include "tag_create_bambu.h"

// One local server, answers in a tenth of a second (09.10.2026).
#define BB_FDB_TIMEOUT_MS   15000
#define BB_PATH_COLORS      "/api/v1/inventory/colors"
#define BB_PATH_CORES       "/api/v1/inventory/catalog"
#define BB_PATH_SPOOLS      "/api/v1/inventory/spools"
// Between product line and colour in an entry's name, so that the same
// colour of two lines ("Black" in PLA Basic and PLA Matte) stays two
// entries, and fdbLineName() reads the line back from the front.
#define BB_LINE_SEP         " - "

namespace {

// ArduinoJson has to be told to use PSRAM, and the allocator must be defined
// in every translation unit that needs it. The colours are about 60 kB
// once filtered.
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

struct ListRead {
  JsonDocument* doc;
  JsonDocument* filter;
};

}  // namespace

// ------------------------------------------------------------
//  Material and product line
// ------------------------------------------------------------

// The material words of the catalog's 57 products (09.10.2026). A word
// that is one of these, or one of these with a suffix after a dash
// ("PLA-CF", "PETG-HS", "PAHT-CF"), is the material; the other words are
// the product line.
static const char* const MATERIAL_WORDS[] = {
  "PLA", "PLA+", "PETG", "ABS", "ABS+", "ASA", "TPU", "PVA", "PAHT", "PA", "PC", "CPE",
  "rPETG", "rPLA",
};

static bool isMaterialWord(const char* word, size_t len) {
  for (const char* m : MATERIAL_WORDS) {
    const size_t n = strlen(m);
    if (len < n || strncasecmp(word, m, n) != 0) continue;
    if (len == n || word[n] == '-') return true;
  }
  return false;
}

static void appendWord(char* out, size_t out_size, const char* word, size_t len) {
  const size_t used = strlen(out);
  if (used + (used ? 1 : 0) + len + 1 > out_size) return;
  snprintf(out + used, out_size - used, "%s%.*s", used ? " " : "", (int)len, word);
}

void bambuddySplitProduct(const char* product, char* material, size_t material_size,
                          char* line, size_t line_size) {
  material[0] = line[0] = '\0';
  if (!product) return;
  const char* found = nullptr;
  size_t found_len = 0;
  for (const char* w = product; *w; ) {
    while (*w == ' ') w++;
    size_t len = 0;
    while (w[len] && w[len] != ' ') len++;
    if (!found && len && isMaterialWord(w, len)) { found = w; found_len = len; }
    else if (len) appendWord(line, line_size, w, len);
    w += len;
  }
  if (found) {
    snprintf(material, material_size, "%.*s", (int)found_len, found);
    return;
  }
  snprintf(material, material_size, "%s", product);
  line[0] = '\0';
}

// The split, the material as the index holds it (FdbPair cuts at 16).
static void splitAsIndexed(const char* product, char* material, char* line, size_t line_size) {
  bambuddySplitProduct(product, material, sizeof(FdbPair::material), line, line_size);
}

// ------------------------------------------------------------
//  Requests
// ------------------------------------------------------------

static bool readList(Stream& raw, void* ctx) {
  ListRead* r = (ListRead*)ctx;
  FdbBlockStream s(raw);
  s.setTimeout(BB_FDB_TIMEOUT_MS);
  const DeserializationError err = deserializeJson(*r->doc, s, DeserializationOption::Filter(*r->filter));
  if (err) logSDf("Filament DB: BamBuddy list did not parse: %s", err.c_str());
  return !err;
}

// One whole list, filtered to the keys given. The HTTP code.
static int getList(const char* base_url, const char* api_key, const char* path,
                   JsonDocument& doc, std::initializer_list<const char*> keys) {
  JsonDocument filter;
  JsonObject f = filter.to<JsonArray>().add<JsonObject>();
  for (const char* key : keys) f[key] = true;
  ListRead r = { &doc, &filter };
  const int code = bbGetStreamed(base_url, api_key, path, BB_FDB_TIMEOUT_MS, readList, &r);
  if (code != 200) logSDf("Filament DB: BamBuddy %s -> HTTP %d", path, code);
  return code;
}

// ------------------------------------------------------------
//  The index
// ------------------------------------------------------------

static void loadCores(const char* base_url, const char* api_key) {
  JsonDocument doc(&s_psram);
  if (getList(base_url, api_key, BB_PATH_CORES, doc, { "id", "name", "weight" }) != 200) return;
  int n = 0;
  for (JsonObjectConst c : doc.as<JsonArrayConst>()) {
    const int weight = c["weight"] | 0;
    if (weight <= 0 || weight > UINT16_MAX) continue;
    if (!fdbCoreAdd(c["name"] | "", (uint16_t)weight, c["id"] | 0)) break;
    n++;
  }
  logSDf("Filament DB: BamBuddy spool catalog, %d empty spools", n);
}

// The makers the inventory has, and the empty spool each one used last.
static void noteInventory(const char* base_url, const char* api_key) {
  JsonDocument doc(&s_psram);
  if (getList(base_url, api_key, BB_PATH_SPOOLS, doc,
              { "id", "brand", "core_weight", "core_weight_catalog_id" }) != 200) return;
  for (JsonObjectConst s : doc.as<JsonArrayConst>()) {
    const char* brand = s["brand"] | "";
    if (!brand[0]) continue;
    fdbMarkOwned(brand);
    fdbCoreNoteOwned(brand, s["core_weight_catalog_id"] | 0, s["core_weight"] | 0, s["id"] | 0);
  }
}

int bambuddyFdbLoadIndex(const char* base_url, const char* api_key) {
  JsonDocument doc(&s_psram);
  const int code = getList(base_url, api_key, BB_PATH_COLORS, doc, { "manufacturer", "material" });
  if (code != 200) return code;
  char material[sizeof(FdbPair::material)], line[FDB_LINE_MAX];
  for (JsonObjectConst c : doc.as<JsonArrayConst>()) {
    splitAsIndexed(c["material"] | "", material, line, sizeof(line));
    fdbIndexAdd(c["manufacturer"] | "", material);
  }
  doc.clear();
  loadCores(base_url, api_key);
  noteInventory(base_url, api_key);
  return 200;
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

// One colour as an entry; false when it has no colour to draw.
static bool toEntry(JsonObjectConst c, const char* line, FdbEntry* e) {
  if (!plainHex(c["hex_color"] | "", e->hex[0], sizeof(e->hex[0]))) return false;
  const char* color = c["color_name"] | "";
  if (!color[0]) return false;
  snprintf(e->id, sizeof(e->id), "%d", c["id"] | 0);
  snprintf(e->line, sizeof(e->line), "%s", line);
  if (line[0]) snprintf(e->name, sizeof(e->name), "%s" BB_LINE_SEP "%s", line, color);
  else         snprintf(e->name, sizeof(e->name), "%s", color);
  const size_t at = line[0] ? strlen(line) + strlen(BB_LINE_SEP) : 0;
  e->color_at = at < FDB_NAME_MAX ? (uint8_t)at : 0;
  snprintf(e->db_hex, sizeof(e->db_hex), "%s", e->hex[0]);
  e->ncolors = 1;
  e->kind    = TCK_SINGLE;
  e->family  = colorFamilyOf(e->hex[0], e->ncolors);
  return true;
}

int bambuddyFdbLoadEntries(const char* base_url, const char* api_key,
                           const char* maker, const char* material) {
  JsonDocument doc(&s_psram);
  const int code = getList(base_url, api_key, BB_PATH_COLORS, doc,
                           { "id", "manufacturer", "material", "color_name", "hex_color" });
  if (code != 200) return code;
  char base[sizeof(FdbPair::material)], line[FDB_LINE_MAX];
  int no_color = 0;
  for (JsonObjectConst c : doc.as<JsonArrayConst>()) {
    if (strcasecmp(c["manufacturer"] | "", maker) != 0) continue;
    splitAsIndexed(c["material"] | "", base, line, sizeof(line));
    if (strcasecmp(base, material) != 0) continue;
    FdbEntry e = {};
    if (!toEntry(c, line, &e)) { no_color++; continue; }
    if (fdbEntryListed(e)) continue;
    if (!fdbEntryAdd(e)) { logSDf("Filament DB: %s %s cut at %d entries", maker, material, FDB_ENTRIES_MAX); break; }
  }
  if (no_color) logSDf("Filament DB: %s %s, %d without a colour left out", maker, material, no_color);
  return 200;
}

// ------------------------------------------------------------
//  The picked entry
// ------------------------------------------------------------

void bambuddyFdbCompleteInput(TagCreateInput* in) {
  if (!in) return;
  // "PLA Matte" on the card, as BamBuddy shows material and subtype.
  if (in->subtype[0]) snprintf(in->product, sizeof(in->product), "%s %s", in->material, in->subtype);
  // BamBuddy keeps the colour's English name; without it the plan would ask
  // BamBuddy for a name by hex and might get another colour's.
  snprintf(in->color_name_en, sizeof(in->color_name_en), "%s", in->db_color_name);
  if (strcasecmp(in->vendor, BAMBU_VENDOR_NAME) != 0) return;
  const bool hit = tagCreateBambuFromCatalog(in);
  logSDf("Filament DB: %s \"%s\" %s in the Bambu catalog%s%s", in->product, in->db_color_name,
         hit ? "found" : "not found", hit ? ", article " : "", hit ? in->article : "");
}
