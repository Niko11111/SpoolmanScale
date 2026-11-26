#include "spoolman_filament.h"
#include "text_util.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <math.h>
#include <new>
#include <string.h>
#include <strings.h>

#include "../hardware/sd_logger.h"
#include "density_rules.h"
#include "spoolman_api.h"
#include "spoolman_filament_db.h"
#include "tag_color_match.h"
#include "tag_create_record.h"

#define SM_FIL_TIMEOUT_MS        8000
// The database search answers from a file of some 8000 entries.
#define SM_FIL_DB_TIMEOUT_MS    12000
// One product of one maker rarely has more colours than this.
#define SM_FIL_DB_LIMIT           100
// Spoolman's multi_color_direction: colours side by side across the
// filament (dual colour silk), or one after the other along it (gradient).
#define SM_DIRECTION_ACROSS      "coaxial"
#define SM_DIRECTION_ALONG       "longitudinal"
// Diameters on tag and in the database agree to the hundredth.
#define SM_FIL_DIAMETER_TOL_MM   0.02f

// ------------------------------------------------------------
//  Finding a filament the inventory already has
// ------------------------------------------------------------

typedef bool (*FilamentAccept)(JsonObjectConst fil, const TagCreateInput& in);

static bool vendorIs(JsonObjectConst fil, const TagCreateInput& in) {
  const char* v = fil["vendor"]["name"] | "";
  return strcasecmp(v, in.vendor) == 0;
}

// An article number belongs to its maker; the colour is part of it.
static bool acceptByArticle(JsonObjectConst fil, const TagCreateInput& in) {
  return vendorIs(fil, in);
}

static bool acceptByExternalId(JsonObjectConst, const TagCreateInput&) {
  return true;
}

// A list of colours as text, from Spoolman's "AAAAAA,BBBBBB" or from the
// database's array.
static String hexList(JsonVariantConst v) {
  if (!v.is<JsonArrayConst>()) return String(v | "");
  String out;
  for (JsonVariantConst c : v.as<JsonArrayConst>()) {
    if (out.length()) out += ",";
    out += c | "";
  }
  return out;
}

// Whether a filament or a database entry has the tag's colour. A gradient,
// dual colour or clear spool is told by its name instead (the caller checks
// it): the databases spell those colours differently - FilaMan keeps Arctic
// Whisper as one averaged A4BFDA, SpoolmanDB as 9CDBD9,FFFFFF - while the
// name is the same everywhere.
static bool colorsFit(JsonVariantConst single, const TagCreateInput& in) {
  if (in.clear || in.color_count >= 2) return true;
  return tagCreateSameHex(single | "", in.color_hex);
}

// A filament someone created by hand: same maker, material and colour, and
// a name that starts with the product line.
static bool acceptByLook(JsonObjectConst fil, const TagCreateInput& in) {
  if (!vendorIs(fil, in)) return false;
  if (strcasecmp(fil["material"] | "", in.material) != 0) return false;
  if (!colorsFit(fil["color_hex"], in)) return false;
  // A database pick has the database's own name: PolyLite and PolyTerra
  // Black share maker, material and nearly the colour, never the name.
  if (in.db_name[0]) return strcasecmp(fil["name"] | "", in.db_name) == 0;
  return tagCreateNameMatches(fil["name"] | "", in);
}

// The lowest id among the filaments the query returns and accept() takes.
// 0 when none; -1 when the server could not be asked, its code in the plan.
static int findFilament(const char* base_url, const String& query, FilamentAccept accept,
                        const TagCreateInput& in, TagFilamentPlan* plan) {
  JsonDocument filter;
  JsonObject f = filter.to<JsonArray>().add<JsonObject>();
  f["id"]             = true;
  f["name"]           = true;
  f["material"]       = true;
  f["color_hex"]      = true;
  f["vendor"]["name"] = true;
  // What a spool created under it is weighed against (tagCreateTare()).
  f["spool_weight"]                 = true;
  f["vendor"]["empty_spool_weight"] = true;

  JsonDocument doc;
  const int code = spoolmanGetJson(base_url, (String("/api/v1/filament?") + query).c_str(),
                                   doc, SM_FIL_TIMEOUT_MS, &filter);
  if (code != 200) { plan->http_code = code; return -1; }

  int best = 0, hits = 0;
  for (JsonObjectConst fil : doc.as<JsonArrayConst>()) {
    const int id = fil["id"] | 0;
    if (id <= 0 || !accept(fil, in)) continue;
    hits++;
    if (best == 0 || id < best) {
      best = id;
      snprintf(plan->name, sizeof(plan->name), "%s", fil["name"] | "");
      plan->found_spool_weight_g  = (int)lroundf(fil["spool_weight"] | 0.0f);
      plan->vendor_spool_weight_g = (int)lroundf(fil["vendor"]["empty_spool_weight"] | 0.0f);
    }
  }
  if (hits > 1) logSDf("Spoolman: %d filaments fit %s, taking #%d", hits, query.c_str(), best);
  return best;
}

// "key=\"value\"": Spoolman reads a quoted term as exact, not as a part.
static String exactTerm(const char* key, const char* value) {
  return String(key) + "=" + spoolmanUrlEncode((String("\"") + value + "\"").c_str());
}

// A name searched without regard to case: Spoolman's exact term (in quotes)
// tells "Anycubic" from the "ANYCUBIC" a SpoolmanDB import made, and the
// scale filed a second maker beside it. Unquoted the term is a part of the
// name in any case, so the caller compares the rows itself (strcasecmp). A
// comma would split the term in two, a quote end it: those stay exact.
static String caselessTerm(const char* key, const char* value) {
  if (strpbrk(value, ",\"")) return exactTerm(key, value);
  return String(key) + "=" + spoolmanUrlEncode(value);
}

// ------------------------------------------------------------
//  SpoolmanDB and the material list
// ------------------------------------------------------------

// Maker, material, diameter, weight and product line: everything but the colour.
static bool dbEntryFitsBesidesColor(JsonObjectConst e, const TagCreateInput& in) {
  if (strcasecmp(e["manufacturer"] | "", in.vendor) != 0) return false;
  if (strcasecmp(e["material"] | "", in.material) != 0) return false;
  if (in.diameter_mm > 0 && fabsf((e["diameter"] | 0.0f) - in.diameter_mm) > SM_FIL_DIAMETER_TOL_MM)
    return false;
  if (in.net_weight_g > 0 && (int)lroundf(e["weight"] | 0.0f) != in.net_weight_g) return false;
  return tagCreateNameMatches(e["name"] | "", in);
}

static bool dbEntryFits(JsonObjectConst e, const TagCreateInput& in) {
  return colorsFit(e["color_hex"], in) && dbEntryFitsBesidesColor(e, in);
}

static void matcherBegin(ColorMatcher* mt, const TagCreateInput& in) {
  const ColorQuery q = { in.color_hex, in.subtype, (uint16_t)in.net_weight_g };
  tagColorMatchBegin(mt, q);
}

// Offers one entry to the match; true when it is the nearest so far.
static bool matcherAdd(ColorMatcher* mt, JsonObjectConst e, const TagCreateInput& in, int index) {
  if (e["color_hexes"].is<JsonArrayConst>()) return false;   // multi colour
  if (!dbEntryFitsBesidesColor(e, in)) return false;
  // Maker, material and line fit already; SpoolmanDB keeps the line in the name.
  const ColorCandidate c = { e["color_hex"] | "", 1, e["name"] | "", "",
                             (uint16_t)lroundf(e["weight"] | 0.0f) };
  return tagColorMatchAdd(mt, c, index);
}

// Whether the nearest colour counts, said in the log either way.
static bool matcherSure(const ColorMatcher& mt) {
  const ColorMatch m = tagColorMatchEnd(mt);
  char text[TCM_TEXT_MAX];
  tagColorMatchText(mt, m, text, sizeof(text));
  if (text[0]) logSDf("Spoolman: %s", text);
  return m.verdict == CMV_SURE;
}

// The entry as the card compares it with the tag and fills in from it
// (tag_db_match.h). SpoolmanDB names one print temperature, compared with the
// top of the tag's range, and writes a see-through colour as AARRGGBB.
static void noteDbEntry(JsonObjectConst e, TagDbEntry* db) {
  memset(db, 0, sizeof(*db));
  snprintf(db->id, sizeof(db->id), "%s", e["id"] | "");
  snprintf(db->name, sizeof(db->name), "%s", e["name"] | "");
  snprintf(db->color_name, sizeof(db->color_name), "%s", e["name"] | "");
  const char* raw = e["color_hex"] | "";
  snprintf(db->color_raw, sizeof(db->color_raw), "%s", raw);
  snprintf(db->color_hex, sizeof(db->color_hex), "%.6s", strlen(raw) == 8 ? raw + 2 : raw);
  db->net_weight_g = (int)lroundf(e["weight"] | 0.0f);
  db->density      = e["density"] | 0.0f;
  db->nozzle_max   = e["extruder_temp"] | 0;
  db->bed_temp     = e["bed_temp"] | 0;
}

static void takeDbEntry(JsonObjectConst e, TagFilamentPlan* plan) {
  noteDbEntry(e, &plan->db);
  plan->db_found = true;
  snprintf(plan->external_id, sizeof(plan->external_id), "%s", e["id"] | "");
  snprintf(plan->name, sizeof(plan->name), "%s", e["name"] | "");
  plan->density        = e["density"] | 0.0f;
  plan->spool_weight_g = (int)lroundf(e["spool_weight"] | 0.0f);
  plan->extruder_temp  = e["extruder_temp"] | 0;
  plan->bed_temp       = e["bed_temp"] | 0;
  snprintf(plan->db_color_hex, sizeof(plan->db_color_hex), "%s", e["color_hex"] | "");
  snprintf(plan->db_multi_hexes, sizeof(plan->db_multi_hexes), "%s", hexList(e["color_hexes"]).c_str());
  snprintf(plan->db_multi_direction, sizeof(plan->db_multi_direction), "%s",
           e["multi_color_direction"] | "");
}

struct DbLookup {
  const TagCreateInput* in;
  TagFilamentPlan*      plan;
  bool                  found;
  // The nearest colour, for a tag that names none: the list streams past,
  // so the best entry so far is kept as a plan of its own.
  bool                  near;
  ColorMatcher          mt;
  TagFilamentPlan       near_plan;
  int                   index;
};

static void lookupElement(JsonObjectConst e, void* p) {
  DbLookup* l = (DbLookup*)p;
  if (l->found) return;
  if (dbEntryFits(e, *l->in)) {
    takeDbEntry(e, l->plan);
    l->found = true;
    return;
  }
  if (l->near && matcherAdd(&l->mt, e, *l->in, l->index)) {
    tagFilamentPlanClear(&l->near_plan);
    takeDbEntry(e, &l->near_plan);
  }
  l->index++;
}

// The light form has no word search: the maker's entries of the material,
// compared one by one as they come. Its list is the maker's whole one, so
// the nearest colour in it is the nearest there is.
static bool findInLightList(const char* base_url, const TagCreateInput& in, TagFilamentPlan* plan) {
  // On the heap: the kept plan and the match are larger than a stack frame
  // of the loop task should carry.
  DbLookup* l = new (std::nothrow) DbLookup();
  if (!l) return false;
  l->in = &in;
  l->plan = plan;
  l->near = tagCreateNearestColorAllowed(in);
  if (l->near) matcherBegin(&l->mt, in);
  const int code = spoolmanFdbEachOf(base_url, in.vendor, in.material, lookupElement, l);
  if (code != 200) logSDf("Spoolman: filament database list -> HTTP %d", code);
  bool found = l->found;
  if (!found && code == 200 && l->near && matcherSure(l->mt)) {
    *plan = l->near_plan;
    found = true;
  }
  delete l;
  return found;
}

// The nearest colour among the search's answers. Only from a complete
// answer: the nearest of a list cut at the limit may not be the nearest.
static bool findNearestInSearch(JsonArrayConst list, const TagCreateInput& in,
                                TagFilamentPlan* plan) {
  if (!tagCreateNearestColorAllowed(in)) return false;
  if (list.size() >= SM_FIL_DB_LIMIT) {
    logSDf("Spoolman: %u database entries, the limit - no nearest colour", (unsigned)list.size());
    return false;
  }
  ColorMatcher mt;
  matcherBegin(&mt, in);
  int i = 0;
  for (JsonObjectConst e : list) matcherAdd(&mt, e, in, i++);
  if (!matcherSure(mt)) return false;
  takeDbEntry(list[tagColorMatchEnd(mt).best].as<JsonObjectConst>(), plan);
  return true;
}

// Looks the product up in the server's filament database. True with plan
// filled from the entry. A server without one simply has no entry.
static bool findInDatabase(const char* base_url, const TagCreateInput& in, TagFilamentPlan* plan) {
  if (!in.color_count && !in.clear) return false;
  const SmFdbForm form = spoolmanFdbForm(base_url);
  if (form == SM_FDB_NONE) return false;
  if (form == SM_FDB_LIGHT) return findInLightList(base_url, in, plan);
  // The search matches word by word. A filament the database names by its
  // colour alone (the plain line, a gradient, a clear one) has no product
  // word there, so the colour's name narrows it instead: "Bambu Lab PLA"
  // alone runs into the limit.
  String words = String(in.vendor) + " " + in.material + " ";
  if (!tagCreateNamedByColor(in)) words += in.subtype;
  else if (in.color_name_en[0]) words += in.color_name_en;
  else return false;
  const String path = String("/api/v1/external/filament/search?limit=") + SM_FIL_DB_LIMIT +
                      "&query=" + spoolmanUrlEncode(words.c_str());
  JsonDocument doc;
  const int code = spoolmanGetJson(base_url, path.c_str(), doc, SM_FIL_DB_TIMEOUT_MS);
  if (code != 200) {
    logSDf("Spoolman: filament database search -> HTTP %d", code);
    return false;
  }
  for (JsonObjectConst e : doc.as<JsonArrayConst>()) {
    if (!dbEntryFits(e, in)) continue;
    takeDbEntry(e, plan);
    return true;
  }
  return findNearestInSearch(doc.as<JsonArrayConst>(), in, plan);
}

// A filament picked from SpoolmanDB on the scale: the entry is known already,
// and filament_db.h brought everything the plan takes from it.
static void takePickedEntry(const TagCreateInput& in, TagFilamentPlan* plan) {
  snprintf(plan->external_id, sizeof(plan->external_id), "%s", in.db_id);
  snprintf(plan->name, sizeof(plan->name), "%s", in.db_name);
  plan->density        = in.db_density;
  plan->spool_weight_g = in.spool_weight_g;
  plan->extruder_temp  = in.temp_max;
  plan->bed_temp       = in.db_bed_temp;
  if (in.color_count >= 2) {
    tagCreateColorList(in, plan->db_multi_hexes, sizeof(plan->db_multi_hexes));
    snprintf(plan->db_multi_direction, sizeof(plan->db_multi_direction), "%s",
             in.color_kind == TCK_DUAL ? SM_DIRECTION_ACROSS : SM_DIRECTION_ALONG);
  } else {
    snprintf(plan->db_color_hex, sizeof(plan->db_color_hex), "%s", in.db_color_hex);
  }
}

// The densities seen, counted in hundredths, the precision the database
// writes, and which one most entries share.
struct DensityCount {
  const char* material;
  int value[SM_FIL_DB_LIMIT];
  int count[SM_FIL_DB_LIMIT];
  int n;
  int best;
};

static void countDensity(JsonObjectConst e, void* p) {
  DensityCount* dc = (DensityCount*)p;
  if (strcasecmp(e["material"] | "", dc->material) != 0) return;
  const int d = (int)lroundf((e["density"] | 0.0f) * 100.0f);
  if (d <= 0) return;
  int i = 0;
  while (i < dc->n && dc->value[i] != d) i++;
  if (i == dc->n) {
    if (dc->n == SM_FIL_DB_LIMIT) return;
    dc->value[dc->n] = d;
    dc->count[dc->n++] = 0;
  }
  dc->count[i]++;
  if (dc->best < 0 || dc->count[i] > dc->count[dc->best]) dc->best = i;
}

// The density most of the database's filaments of exactly this material
// have: in the Spoolman form whoever makes them (a search for the material),
// in the light form the maker's own list of it; 0 when there is none.
// Spoolman's material list below is a short list of suggestions that spells
// TPU "Flexible (TPU)" and has no PA at all, while the database holds 216
// TPU (74 of them at 1.20 g/cm3).
static float databaseDensity(const char* base_url, const char* vendor, const char* material) {
  DensityCount dc = {};
  dc.material = material;
  dc.best = -1;
  if (spoolmanFdbForm(base_url) == SM_FDB_LIGHT) {
    if (spoolmanFdbEachOf(base_url, vendor, material, countDensity, &dc) != 200) return 0.0f;
  } else {
    JsonDocument filter;
    JsonObject f = filter.to<JsonArray>().add<JsonObject>();
    f["material"] = true;
    f["density"]  = true;
    const String path = String("/api/v1/external/filament/search?limit=") + SM_FIL_DB_LIMIT +
                        "&query=" + spoolmanUrlEncode(material);
    JsonDocument doc;
    if (spoolmanGetJson(base_url, path.c_str(), doc, SM_FIL_DB_TIMEOUT_MS, &filter) != 200) return 0.0f;
    for (JsonObjectConst e : doc.as<JsonArrayConst>()) countDensity(e, &dc);
  }
  return dc.best < 0 ? 0.0f : dc.value[dc.best] / 100.0f;
}

// The density Spoolman's material list gives the tag's material, 0 if none.
static float materialDensity(const char* base_url, const char* material) {
  JsonDocument filter;
  JsonObject f = filter.to<JsonArray>().add<JsonObject>();
  f["material"] = true;
  f["density"]  = true;
  JsonDocument doc;
  if (spoolmanGetJson(base_url, "/api/v1/external/material", doc, SM_FIL_TIMEOUT_MS, &filter) != 200)
    return 0.0f;
  for (JsonObjectConst m : doc.as<JsonArrayConst>())
    if (strcasecmp(m["material"] | "", material) == 0) return m["density"] | 0.0f;
  return 0.0f;
}

// The density of one database entry when it is the tag's product, else 0.
static float entryProductDensity(JsonObjectConst e, const DensityProduct& want) {
  const float d = e["density"] | 0.0f;
  if (!densityPlausible(d)) return 0.0f;
  const int weight_g = (int)lroundf(e["weight"] | 0.0f);
  return densityEntryIsProduct(e["manufacturer"] | "", e["name"] | "", weight_g, want) ? d : 0.0f;
}

struct ProductDensityScan {
  DensityProduct want;
  float          density;
  char           name[48];  // the entry it came from, for the log; copied,
                            // the document it was read from is gone by then
};

static void scanProductDensity(JsonObjectConst e, void* p) {
  ProductDensityScan* scan = (ProductDensityScan*)p;
  if (scan->density > 0.0f) return;
  scan->density = entryProductDensity(e, scan->want);
  if (scan->density > 0.0f) snprintf(scan->name, sizeof(scan->name), "%s", e["name"] | "");
}

// The density of the database entry that carries the tag's product name, 0
// if there is none. A Bambu support tag names its material ABS-S, which
// neither the database nor Spoolman's material list knows; the database has
// the product as "Support for ABS", material ABS. Only the density is taken:
// the filament is still made from the tag, with the tag's material.
static float productDensity(const char* base_url, const TagCreateInput& in) {
  if (!in.product[0]) return 0.0f;
  ProductDensityScan scan = { { in.vendor, in.product, in.net_weight_g }, 0.0f, "" };
  const SmFdbForm form = spoolmanFdbForm(base_url);
  if (form == SM_FDB_LIGHT) {
    // No word search there: the maker's list of the material the product is
    // filed under, known for the support codes only.
    const char* base = densitySupportBase(in.material);
    if (!base) return 0.0f;
    const int code = spoolmanFdbEachOf(base_url, in.vendor, base, scanProductDensity, &scan);
    if (code != 200) logSDf("Spoolman: filament database list by product -> HTTP %d", code);
  } else if (form == SM_FDB_SPOOLMAN) {
    JsonDocument filter;
    JsonObject f = filter.to<JsonArray>().add<JsonObject>();
    f["manufacturer"] = true;
    f["name"]         = true;
    f["weight"]       = true;
    f["density"]      = true;
    const String words = String(in.vendor) + " " + in.product;
    const String path = String("/api/v1/external/filament/search?limit=") + SM_FIL_DB_LIMIT +
                        "&query=" + spoolmanUrlEncode(words.c_str());
    JsonDocument doc;
    const int code = spoolmanGetJson(base_url, path.c_str(), doc, SM_FIL_DB_TIMEOUT_MS, &filter);
    if (code != 200) logSDf("Spoolman: filament database search by product -> HTTP %d", code);
    else for (JsonObjectConst e : doc.as<JsonArrayConst>()) scanProductDensity(e, &scan);
  }
  if (scan.density > 0.0f)
    logSDf("Spoolman: density %.2f for %s from the database entry \"%s\"",
           scan.density, in.material, scan.name);
  return scan.density;
}

// The vendor's id, 0 when the inventory has none yet; -1 when the server
// could not be asked, its code in the plan.
static int findVendor(const char* base_url, const char* vendor, TagFilamentPlan* plan) {
  JsonDocument doc;
  const String path = String("/api/v1/vendor?") + caselessTerm("name", vendor);
  const int code = spoolmanGetJson(base_url, path.c_str(), doc, SM_FIL_TIMEOUT_MS);
  if (code != 200) { plan->http_code = code; return -1; }
  for (JsonObjectConst v : doc.as<JsonArrayConst>()) {
    if (!tagCreateVendorIs(v["name"] | "", vendor)) continue;
    // The brand's empty spool, for what the new spool is weighed against.
    plan->vendor_spool_weight_g = (int)lroundf(v["empty_spool_weight"] | 0.0f);
    return v["id"] | 0;
  }
  return 0;
}

// ------------------------------------------------------------
//  The plan
// ------------------------------------------------------------

// Steps through the ways a filament can already be there. True when one
// decided: found, or the server failed.
static bool planExisting(const char* base_url, const TagCreateInput& in, TagFilamentPlan* plan) {
  int id = 0;
  if (in.article[0])
    id = findFilament(base_url, exactTerm("article_number", in.article), acceptByArticle, in, plan);
  if (id == 0 && plan->external_id[0])
    id = findFilament(base_url, exactTerm("external_id", plan->external_id), acceptByExternalId, in, plan);
  if (id == 0 && (in.color_count || in.clear)) {
    // Spoolman's colour filter knows one colour; a multi colour or clear
    // spool is compared here, among the vendor's filaments of the material.
    String q = caselessTerm("vendor.name", in.vendor) + "&" + caselessTerm("material", in.material);
    if (in.color_count == 1) q += String("&color_similarity_threshold=0&color_hex=") + in.color_hex;
    id = findFilament(base_url, q, acceptByLook, in, plan);
  }
  if (id > 0) { plan->state = TFS_FOUND; plan->filament_id = id; return true; }
  if (id < 0) { plan->state = TFS_FAILED; return true; }
  return false;
}

// The last word on a density nothing else had: the one typed in on the card,
// or a plan that asks for it. Spoolman refuses a filament without one, and
// the scale used to stop here with "failed (HTTP 0)", as if the server were
// gone. False when the plan stops.
static bool densityOrAsk(const TagCreateInput& in, TagFilamentPlan* plan) {
  if (plan->density > 0.0f) return true;
  if (in.user_density > 0.0f) { plan->density = in.user_density; return true; }
  logSDf("Spoolman: no density known for %s, asking for one", in.material);
  plan->state = TFS_NEEDS_DENSITY;
  return false;
}

// A filament from the tag alone: only with names for it (article number and
// colour, or material and hex where the format has no names), and only with
// a density, which Spoolman requires.
static void planFromTag(const char* base_url, const TagCreateInput& in, TagFilamentPlan* plan) {
  if (!tagCreateNamesEnough(in) || (!in.color_count && !in.clear)) { plan->state = TFS_NEEDS_CATALOG; return; }
  plan->density = databaseDensity(base_url, in.vendor, in.material);
  if (plan->density <= 0.0f) plan->density = materialDensity(base_url, in.material);
  if (plan->density <= 0.0f) plan->density = productDensity(base_url, in);
  if (!densityOrAsk(in, plan)) return;
  tagCreateSpoolmanName(in, plan->name, sizeof(plan->name));
  plan->spool_weight_g = in.spool_weight_g;
  plan->state = TFS_CREATE_TAG;
}

void spoolmanPlanTagFilament(const char* base_url, const TagCreateInput& in,
                             TagFilamentPlan* plan) {
  tagFilamentPlanClear(plan);
  // The database first: its id also finds a filament imported from it.
  const bool picked = in.db_id[0] != '\0';
  if (picked) takePickedEntry(in, plan);
  const bool in_db = picked || findInDatabase(base_url, in, plan);
  if (planExisting(base_url, in, plan)) return;

  plan->vendor_id = findVendor(base_url, in.vendor, plan);
  if (plan->vendor_id < 0) { plan->state = TFS_FAILED; return; }
  // Spoolman requires a density; a picked entry without one borrows it the
  // way a filament from a tag does.
  if (picked && plan->density <= 0.0f) plan->density = databaseDensity(base_url, in.vendor, in.material);
  if (picked && plan->density <= 0.0f) plan->density = materialDensity(base_url, in.material);
  if (picked && !densityOrAsk(in, plan)) return;
  if (in_db) { plan->state = TFS_CREATE_DB; return; }
  planFromTag(base_url, in, plan);
}

// ------------------------------------------------------------
//  Creating
// ------------------------------------------------------------

static int createVendor(const char* base_url, const TagCreateInput& in, int* out_id) {
  JsonDocument body;
  body["name"] = in.vendor;
  if (in.spool_weight_g > 0) body["empty_spool_weight"] = in.spool_weight_g;
  String payload;
  serializeJson(body, payload);
  JsonDocument answer;
  const int code = spoolmanPostJson(base_url, "/api/v1/vendor", payload, answer, SM_FIL_TIMEOUT_MS);
  *out_id = answer["id"] | 0;
  logSDf("Spoolman: vendor %s created -> HTTP %d, id %d", in.vendor, code, *out_id);
  return code;
}

// Spoolman takes one colour in color_hex, or several in multi_color_hexes
// with the way they lie on the spool, never both.
static void colorFields(const TagCreateInput& in, const TagFilamentPlan& plan, JsonDocument& body) {
  if (plan.external_id[0]) {
    if (plan.db_multi_hexes[0] && plan.db_multi_direction[0]) {
      body["multi_color_hexes"]     = plan.db_multi_hexes;
      body["multi_color_direction"] = plan.db_multi_direction;
    } else if (plan.db_color_hex[0]) {
      body["color_hex"] = plan.db_color_hex;
    }
    return;
  }
  if (in.color_count >= 2) {
    char list[TAG_CREATE_COLOURS * 7 + 1];
    tagCreateColorList(in, list, sizeof(list));
    body["multi_color_hexes"]     = list;
    body["multi_color_direction"] = in.color_kind == TCK_DUAL ? SM_DIRECTION_ACROSS : SM_DIRECTION_ALONG;
    return;
  }
  // See-through keeps its alpha, a clear filament is 00000000.
  const bool opaque = strlen(in.rgba) == 8 && strcmp(in.rgba + 6, "FF") == 0;
  body["color_hex"] = (in.clear || !opaque) ? in.rgba : in.color_hex;
}

static void filamentBody(const TagCreateInput& in, const TagFilamentPlan& plan,
                         int vendor_id, JsonDocument& body) {
  body["name"]      = plan.name;
  body["vendor_id"] = vendor_id;
  body["material"]  = in.material;
  body["density"]   = plan.density;
  body["diameter"]  = in.diameter_mm > 0 ? in.diameter_mm : TAG_CREATE_DIAMETER_MM;
  colorFields(in, plan, body);
  if (in.net_weight_g > 0)   body["weight"] = in.net_weight_g;
  if (plan.spool_weight_g > 0) body["spool_weight"] = plan.spool_weight_g;
  if (in.article[0])         body["article_number"] = in.article;
  if (plan.external_id[0])   body["external_id"] = plan.external_id;
  // The database's own values where there is an entry, the tag's otherwise.
  const int nozzle = plan.extruder_temp > 0 ? plan.extruder_temp : in.temp_max;
  if (nozzle > 0)        body["settings_extruder_temp"] = nozzle;
  if (plan.bed_temp > 0) body["settings_bed_temp"] = plan.bed_temp;
}

int spoolmanCreateTagFilament(const char* base_url, const TagCreateInput& in,
                              const TagFilamentPlan& plan, int* out_filament_id) {
  *out_filament_id = 0;
  int vendor_id = plan.vendor_id;
  if (vendor_id <= 0) {
    const int code = createVendor(base_url, in, &vendor_id);
    if (vendor_id <= 0) return code;
  }
  JsonDocument body;
  filamentBody(in, plan, vendor_id, body);
  String payload;
  serializeJson(body, payload);
  JsonDocument answer;
  const int code = spoolmanPostJson(base_url, "/api/v1/filament", payload, answer, SM_FIL_TIMEOUT_MS);
  *out_filament_id = answer["id"] | 0;
  logSDf("Spoolman: filament \"%s\" created -> HTTP %d, id %d", plan.name, code, *out_filament_id);
  return code;
}

int spoolmanVendorSpools(const char* base_url, SpoolChoice* out, int max, int* n) {
  *n = 0;
  JsonDocument filter;
  JsonObject f = filter.to<JsonArray>().add<JsonObject>();
  f["name"] = true;
  f["empty_spool_weight"] = true;
  JsonDocument doc;
  const int code = spoolmanGetJson(base_url, "/api/v1/vendor", doc, SM_FIL_TIMEOUT_MS, &filter);
  if (code != 200) { logSDf("Spoolman: vendor spools -> HTTP %d", code); return code; }
  for (JsonObjectConst v : doc.as<JsonArrayConst>()) {
    if (*n >= max) break;
    const int weight = (int)lroundf(v["empty_spool_weight"] | 0.0f);
    if (weight <= 0 || weight > UINT16_MAX) continue;
    spoolChoiceClear(&out[*n]);
    out[*n].weight_g = (uint16_t)weight;
    out[*n].source   = SCS_SERVER;
    // Cut on a whole character: a tile and the NVS recents show it.
    utf8Cut(v["name"] | "", sizeof(out[*n].name) - 1, out[*n].name, sizeof(out[*n].name));
    (*n)++;
  }
  return code;
}
