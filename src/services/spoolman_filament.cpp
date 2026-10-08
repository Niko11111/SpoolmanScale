#include "spoolman_filament.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <math.h>
#include <string.h>
#include <strings.h>

#include "../hardware/sd_logger.h"
#include "spoolman_api.h"

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
    }
  }
  if (hits > 1) logSDf("Spoolman: %d filaments fit %s, taking #%d", hits, query.c_str(), best);
  return best;
}

// "key=\"value\"": Spoolman reads a quoted term as exact, not as a part.
static String exactTerm(const char* key, const char* value) {
  return String(key) + "=" + spoolmanUrlEncode((String("\"") + value + "\"").c_str());
}

// ------------------------------------------------------------
//  SpoolmanDB and the material list
// ------------------------------------------------------------

static bool dbEntryFits(JsonObjectConst e, const TagCreateInput& in) {
  if (strcasecmp(e["manufacturer"] | "", in.vendor) != 0) return false;
  if (strcasecmp(e["material"] | "", in.material) != 0) return false;
  if (!colorsFit(e["color_hex"], in)) return false;
  if (in.diameter_mm > 0 && fabsf((e["diameter"] | 0.0f) - in.diameter_mm) > SM_FIL_DIAMETER_TOL_MM)
    return false;
  if (in.net_weight_g > 0 && (int)lroundf(e["weight"] | 0.0f) != in.net_weight_g) return false;
  return tagCreateNameMatches(e["name"] | "", in);
}

static void takeDbEntry(JsonObjectConst e, TagFilamentPlan* plan) {
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

// Looks the product up in SpoolmanDB. True with plan filled from the entry.
// An older Spoolman without the search (404) simply has no entry.
static bool findInDatabase(const char* base_url, const TagCreateInput& in, TagFilamentPlan* plan) {
  if (!in.color_count && !in.clear) return false;
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
  return false;
}

// The density most of SpoolmanDB's filaments of exactly this material have,
// whoever makes them; 0 when it has none. Spoolman's material list below is
// a short list of suggestions that spells TPU "Flexible (TPU)" and has no PA
// at all, while the database holds 216 TPU (74 of them at 1.20 g/cm3).
static float databaseDensity(const char* base_url, const char* material) {
  JsonDocument filter;
  JsonObject f = filter.to<JsonArray>().add<JsonObject>();
  f["material"] = true;
  f["density"]  = true;
  const String path = String("/api/v1/external/filament/search?limit=") + SM_FIL_DB_LIMIT +
                      "&query=" + spoolmanUrlEncode(material);
  JsonDocument doc;
  if (spoolmanGetJson(base_url, path.c_str(), doc, SM_FIL_DB_TIMEOUT_MS, &filter) != 200) return 0.0f;

  // Counted in hundredths, the precision the database writes.
  int value[SM_FIL_DB_LIMIT], count[SM_FIL_DB_LIMIT], n = 0, best = -1;
  for (JsonObjectConst e : doc.as<JsonArrayConst>()) {
    if (strcasecmp(e["material"] | "", material) != 0) continue;
    const int d = (int)lroundf((e["density"] | 0.0f) * 100.0f);
    if (d <= 0) continue;
    int i = 0;
    while (i < n && value[i] != d) i++;
    if (i == n) { if (n == SM_FIL_DB_LIMIT) continue; value[n] = d; count[n++] = 0; }
    count[i]++;
    if (best < 0 || count[i] > count[best]) best = i;
  }
  return best < 0 ? 0.0f : value[best] / 100.0f;
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

// The vendor's id, 0 when the inventory has none yet; -1 when the server
// could not be asked, its code in the plan.
static int findVendor(const char* base_url, const char* vendor, TagFilamentPlan* plan) {
  JsonDocument doc;
  const String path = String("/api/v1/vendor?") + exactTerm("name", vendor);
  const int code = spoolmanGetJson(base_url, path.c_str(), doc, SM_FIL_TIMEOUT_MS);
  if (code != 200) { plan->http_code = code; return -1; }
  for (JsonObjectConst v : doc.as<JsonArrayConst>())
    if (strcasecmp(v["name"] | "", vendor) == 0) return v["id"] | 0;
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
    String q = exactTerm("vendor.name", in.vendor) + "&" + exactTerm("material", in.material);
    if (in.color_count == 1) q += String("&color_similarity_threshold=0&color_hex=") + in.color_hex;
    id = findFilament(base_url, q, acceptByLook, in, plan);
  }
  if (id > 0) { plan->state = TFS_FOUND; plan->filament_id = id; return true; }
  if (id < 0) { plan->state = TFS_FAILED; return true; }
  return false;
}

// A filament from the tag alone: only with names for it (article number and
// colour), and only with a density, which Spoolman requires.
static void planFromTag(const char* base_url, const TagCreateInput& in, TagFilamentPlan* plan) {
  if (!in.names_known || (!in.color_count && !in.clear)) { plan->state = TFS_NEEDS_CATALOG; return; }
  plan->density = databaseDensity(base_url, in.material);
  if (plan->density <= 0.0f) plan->density = materialDensity(base_url, in.material);
  if (plan->density <= 0.0f) {
    logSDf("Spoolman: no density known for %s, filament not created", in.material);
    plan->state = TFS_FAILED;
    return;
  }
  tagCreateSpoolmanName(in, plan->name, sizeof(plan->name));
  plan->spool_weight_g = in.spool_weight_g;
  plan->state = TFS_CREATE_TAG;
}

void spoolmanPlanTagFilament(const char* base_url, const TagCreateInput& in,
                             TagFilamentPlan* plan) {
  tagFilamentPlanClear(plan);
  // The database first: its id also finds a filament imported from it.
  const bool in_db = findInDatabase(base_url, in, plan);
  if (planExisting(base_url, in, plan)) return;

  plan->vendor_id = findVendor(base_url, in.vendor, plan);
  if (plan->vendor_id < 0) { plan->state = TFS_FAILED; return; }
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
