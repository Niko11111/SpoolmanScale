#include "bambuddy_api.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <ctype.h>
#include <math.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/user_options.h"

namespace {

// ArduinoJson has to be told to use PSRAM, and the allocator must be defined
// in every translation unit that needs it.
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

}  // namespace

// Path of the device protocol. Same on both inventory modes, the server
// routes the write to whichever database it is configured for.
#define BB_DEVICE_BASE  "/api/v1/spoolbuddy"

static BbInventoryMode s_mode = BB_INV_LOCAL;
static char s_spoolman_url[96] = "";

static bool hasBaseUrl(const char* base_url) {
  return base_url && strlen(base_url) > 7;   // longer than "http://"
}

// BamBuddy stores label_weight and core_weight as integers and rejects
// nothing, but a fractional gram would be silently truncated. A load cell
// has no meaningful accuracy below a gram, so round on the way out.
static int roundGrams(float g) {
  return (int)lroundf(g);
}

static void addKey(HTTPClient& http, const char* api_key) {
  if (api_key && api_key[0]) http.addHeader("X-API-Key", api_key);
}

// ------------------------------------------------------------
//  REQUEST HELPERS
// ------------------------------------------------------------

// GET returning parsed JSON. An optional filter keeps the document small on
// the big answers. Deserialises straight off the socket, never via
// getString(): the inventory answer can be far larger than the free heap.
static int getJson(const char* url, const char* api_key, JsonDocument& doc,
                   uint32_t timeout_ms, DeserializationError* out_err,
                   JsonDocument* filter) {
  HTTPClient http;
  if (!http.begin(url)) return -1;
  http.setTimeout(timeout_ms);
  addKey(http, api_key);

  int code = http.GET();
  if (code != 200) {
    http.end();
    return code;
  }

  DeserializationError err = filter
    ? deserializeJson(doc, http.getStream(), DeserializationOption::Filter(*filter))
    : deserializeJson(doc, http.getStream());
  http.end();

  if (out_err) *out_err = err;
  if (err) {
    logSDf("BamBuddy: JSON parse failed (%s) on %s", err.c_str(), url);
    return -2;
  }
  return 200;
}

// POST or PATCH with a JSON body. Answers are small here, so the body is
// read as a String and handed back when the caller wants to look at it.
// Any 2xx is normalised to 200 so call sites can compare against one value.
static int sendJson(const char* method, const char* url, const char* api_key,
                    const String& body, uint32_t timeout_ms, String* out_body) {
  HTTPClient http;
  if (!http.begin(url)) return -1;
  http.setTimeout(timeout_ms);
  http.addHeader("Content-Type", "application/json");
  addKey(http, api_key);

  int code = http.sendRequest(method, (uint8_t*)body.c_str(), body.length());
  if (code >= 200 && code < 300) {
    if (out_body) *out_body = http.getString();
    http.end();
    return 200;
  }

  // Truncated so a validation error is readable in the log without filling
  // the card. 422 in particular carries the field that was rejected.
  if (code > 0) {
    String err = http.getString();
    if (err.length() > 120) err = err.substring(0, 120);
    logSDf("BamBuddy: %s %s -> %d %s", method, url, code, err.c_str());
  } else {
    logSDf("BamBuddy: %s %s -> transport error %d", method, url, code);
  }
  http.end();
  return code;
}

// ------------------------------------------------------------
//  SETUP
// ------------------------------------------------------------

int bbDetectInventoryMode(const char* base_url, const char* api_key,
                          uint32_t timeout_ms) {
  s_mode = BB_INV_LOCAL;
  s_spoolman_url[0] = '\0';
  if (!hasBaseUrl(base_url)) return -1;

  char url[160];
  snprintf(url, sizeof(url), "%s/api/v1/settings/spoolman", base_url);

  JsonDocument doc;
  int code = getJson(url, api_key, doc, timeout_ms, nullptr, nullptr);
  if (code != 200) {
    // 403 means the key was created without "Read Status". Local mode is the
    // right guess then: it is what a fresh install runs, and a wrong guess
    // surfaces as a 404 on the first spool read rather than silently.
    logSDf("BamBuddy: inventory mode unknown (HTTP %d), assuming local", code);
    return code;
  }

  // Both values arrive as strings, not as JSON booleans.
  const char* enabled = doc["spoolman_enabled"] | "false";
  if (strcasecmp(enabled, "true") == 0) {
    s_mode = BB_INV_SPOOLMAN;
    const char* url_s = doc["spoolman_url"] | "";
    strncpy(s_spoolman_url, url_s, sizeof(s_spoolman_url) - 1);
    s_spoolman_url[sizeof(s_spoolman_url) - 1] = '\0';
    // Reported with a trailing slash, which would double up when paths are
    // appended.
    size_t n = strlen(s_spoolman_url);
    while (n > 0 && s_spoolman_url[n - 1] == '/') s_spoolman_url[--n] = '\0';
  }

  // Logged on the first look and on every change, not on every check - this
  // runs with the health check now and a line every 30 s would bury the log.
  // A change is worth a line though: it means the scale is writing somewhere
  // else from here on.
  static bool  seen = false;
  static BbInventoryMode last = BB_INV_LOCAL;
  if (!seen || last != s_mode) {
    logSDf("BamBuddy: inventory mode %s%s%s",
           s_mode == BB_INV_SPOOLMAN ? "Spoolman" : "local",
           s_spoolman_url[0] ? " via " : "",
           s_spoolman_url[0] ? s_spoolman_url : "");
    seen = true;
    last = s_mode;
  }
  return 200;
}

BbInventoryMode bbInventoryMode() { return s_mode; }

const char* bbInventoryBase() {
  return (s_mode == BB_INV_SPOOLMAN) ? "/api/v1/spoolman/inventory"
                                     : "/api/v1/inventory";
}

const char* bbSpoolmanUrl() { return s_spoolman_url; }

const char* bbDeviceId() {
  static char id[20] = "";
  if (!id[0]) {
    // Mirrors the "sb-<mac>" of BamBuddy's own daemon so the two are
    // recognisable side by side in the device list.
    uint64_t mac = ESP.getEfuseMac();
    uint8_t b[6];
    for (int i = 0; i < 6; i++) b[i] = (uint8_t)(mac >> (8 * i));
    snprintf(id, sizeof(id), "ssc-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
  }
  return id;
}

// ============================================================
//  TRANSLATION: BamBuddy spool  ->  Spoolman spool
//
//  Field names verified against BamBuddy 1.2.5.3, in both
//  inventory modes: the Spoolman proxy normalises to the same
//  names as the built in database, so one mapper serves both.
// ============================================================

// Pulls a "[last_dried:YYYY-MM-DD]" marker out of the note field. BamBuddy
// has no column for a drying date, so the marker is where the scale keeps it.
// Read unconditionally: a marker that is there is worth showing no matter
// which write route the user picked.
//
// "[dried:...]" is the spelling the first builds wrote and is still accepted.
// Nothing migrates it on its own; the next drying entry rewrites it, which is
// enough for a marker that only matters while it is current.
static bool driedFromNote(const char* note, char* out, size_t out_size) {
  if (!note || !out || out_size < 11) return false;
  const char* p = strstr(note, "[last_dried:");
  if (p) {
    p += 12;
  } else {
    p = strstr(note, "[dried:");
    if (!p) return false;
    p += 7;
  }
  const char* end = strchr(p, ']');
  if (!end || (size_t)(end - p) != 10) return false;   // YYYY-MM-DD
  memcpy(out, p, 10);
  out[10] = '\0';
  return true;
}

static void mapSpool(JsonObjectConst src, JsonObject dst) {
  const int   label = src["label_weight"] | 1000;
  const int   core  = src["core_weight"]  | 250;
  const float used  = src["weight_used"]  | 0.0f;

  dst["id"] = src["id"] | 0;

  // BamBuddy stores what was consumed and derives the rest. Spoolman is the
  // other way round, so remaining is computed here.
  float remaining = (float)label - used;
  if (remaining < 0.0f) remaining = 0.0f;
  dst["remaining_weight"] = remaining;
  dst["used_weight"]      = used;
  dst["spool_weight"]     = (float)core;
  dst["initial_weight"]   = (float)label;

  dst["archived"] = !src["archived_at"].isNull();

  const char* last_used = src["last_used"] | (const char*)nullptr;
  if (last_used) dst["last_used"] = last_used;

  const char* loc = src["storage_location"] | (const char*)nullptr;
  if (loc && loc[0]) dst["location"] = loc;

  const char* note = src["note"] | (const char*)nullptr;
  if (note && note[0]) dst["comment"] = note;

  // Spoolman keeps the tag in extra.tag. BamBuddy has two columns: tray_uuid
  // for Bambu Lab spools, tag_uid for everything else. tray_uuid wins,
  // matching the order BamBuddy itself searches in.
  JsonObject extra = dst["extra"].to<JsonObject>();
  const char* tray = src["tray_uuid"] | "";
  const char* uid  = src["tag_uid"]   | "";
  if (tray[0])     extra["tag"] = tray;
  else if (uid[0]) extra["tag"] = uid;

  char dried[12];
  if (driedFromNote(note, dried, sizeof(dried))) extra["last_dried"] = dried;

  // Only the built-in inventory keeps this; behind the Spoolman proxy it is
  // always null. Carried along in the document so the display needs no second
  // request - unlike FilaMan, where the date has to be dug out of an event log.
  const char* weighed = src["last_weighed_at"] | (const char*)nullptr;
  if (weighed) extra["last_weighed"] = weighed;

  // BamBuddy has no filament type as an object: brand, material and colour
  // sit on the spool itself. The shape is rebuilt here because the UI reads
  // it, but ids stay 0 - there is nothing on the server to patch, and the
  // filament and vendor tare scopes report "not supported" for that reason.
  JsonObject f = dst["filament"].to<JsonObject>();
  f["id"]           = 0;
  f["material"]     = src["material"] | "";
  f["weight"]       = (float)label;
  f["spool_weight"] = (float)core;

  // Spoolman shows one name. Brand plus subtype is the most useful pairing,
  // with the colour name filling in when there is no subtype.
  const char* brand   = src["brand"]      | "";
  const char* subtype = src["subtype"]    | "";
  const char* colname = src["color_name"] | "";
  char name[64];
  if (subtype[0])      snprintf(name, sizeof(name), "%s %s", brand, subtype);
  else if (colname[0]) snprintf(name, sizeof(name), "%s %s", brand, colname);
  else                 snprintf(name, sizeof(name), "%s", brand);
  // Trims the leading space a missing brand would leave behind.
  const char* np = name;
  while (*np == ' ') np++;
  f["name"] = np;

  // rgba is RRGGBBAA, Spoolman wants RRGGBB.
  const char* rgba = src["rgba"] | "";
  char hex[7] = "";
  if (strlen(rgba) >= 6) { memcpy(hex, rgba, 6); hex[6] = '\0'; }
  f["color_hex"] = hex;

  JsonObject vendor = f["vendor"].to<JsonObject>();
  vendor["id"]   = 0;
  vendor["name"] = brand;
}

// ------------------------------------------------------------
//  READING
// ------------------------------------------------------------

int bbGetHealthCode(const char* base_url, const char* api_key,
                    uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  // Step one, no credentials. /api/v1/health does not exist in BamBuddy;
  // asking for it returns 404 with a key and 401 without, because the auth
  // layer runs before routing. updates/version is public in both cases.
  char url[160];
  snprintf(url, sizeof(url), "%s/api/v1/updates/version", base_url);
  {
    HTTPClient http;
    if (!http.begin(url)) return -1;
    http.setTimeout(timeout_ms);
    int code = http.GET();
    http.end();
    if (code != 200) return code;   // server not there, or not BamBuddy
  }

  // Step two: does the key get us in? Answers 401 or 403 when it does not,
  // which the connection test can report as a credential problem rather than
  // an unreachable server.
  snprintf(url, sizeof(url), "%s/api/v1/system/info", base_url);
  HTTPClient http;
  if (!http.begin(url)) return -1;
  http.setTimeout(timeout_ms);
  addKey(http, api_key);
  int code = http.GET();
  http.end();
  return code;
}

bool bbGetVersion(const char* base_url, const char* api_key,
                  char* out_version, size_t out_size, uint32_t timeout_ms) {
  if (!out_version || out_size == 0) return false;
  out_version[0] = '\0';
  if (!hasBaseUrl(base_url)) return false;

  char url[160];
  snprintf(url, sizeof(url), "%s/api/v1/updates/version", base_url);

  JsonDocument doc;
  if (getJson(url, api_key, doc, timeout_ms, nullptr, nullptr) != 200) return false;

  const char* v = doc["version"] | "";
  if (!v[0]) return false;
  strncpy(out_version, v, out_size - 1);
  out_version[out_size - 1] = '\0';
  return true;
}

int bbGetSpoolJson(const char* base_url, const char* api_key, int spool_id,
                   JsonDocument& doc, uint32_t timeout_ms,
                   DeserializationError* out_err) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;

  char url[192];
  snprintf(url, sizeof(url), "%s%s/spools/%d", base_url, bbInventoryBase(), spool_id);

  SpiRamAllocator alloc;
  JsonDocument raw(&alloc);
  int code = getJson(url, api_key, raw, timeout_ms, out_err, nullptr);
  if (code != 200) return code;

  JsonObject out = doc.to<JsonObject>();
  mapSpool(raw.as<JsonObjectConst>(), out);

  // With the drying date kept on the Spoolman side, one small extra request
  // fetches it - BamBuddy's proxy hides the extra dict it lives in. Only in
  // that mode and only when the user picked it, so the normal scan stays at
  // two requests.
  if (g_bb_dried_target == BB_DRIED_SPOOLMAN && s_mode == BB_INV_SPOOLMAN) {
    char dried[32];
    if (bbGetDriedFromSpoolman(spool_id, dried, sizeof(dried), timeout_ms)) {
      out["extra"]["last_dried"] = dried;
    }
  }
  return 200;
}

int bbGetSpoolListJson(const char* base_url, const char* api_key,
                       bool allow_archived, JsonDocument& doc,
                       uint32_t timeout_ms, DeserializationError* out_err) {
  if (!hasBaseUrl(base_url)) return -1;

  char url[224];
  snprintf(url, sizeof(url), "%s%s/spools%s", base_url, bbInventoryBase(),
           allow_archived ? "?include_archived=true" : "");

  SpiRamAllocator alloc;
  JsonDocument raw(&alloc);
  int code = getJson(url, api_key, raw, timeout_ms, out_err, nullptr);
  if (code != 200) return code;

  JsonArray out = doc.to<JsonArray>();
  for (JsonVariantConst v : raw.as<JsonArrayConst>()) {
    mapSpool(v.as<JsonObjectConst>(), out.add<JsonObject>());
  }
  return 200;
}

int bbGetLocationsJson(const char* base_url, const char* api_key,
                       JsonDocument& doc, uint32_t timeout_ms,
                       DeserializationError* out_err) {
  if (!hasBaseUrl(base_url)) return -1;

  // Locations live in BamBuddy's own tables even when the inventory is
  // proxied to Spoolman, so this path never takes the spoolman prefix.
  char url[160];
  snprintf(url, sizeof(url), "%s/api/v1/inventory/locations", base_url);

  JsonDocument raw;
  int code = getJson(url, api_key, raw, timeout_ms, out_err, nullptr);
  if (code != 200) return code;

  // Spoolman answers with a plain array of name strings.
  JsonArray out = doc.to<JsonArray>();
  for (JsonVariantConst v : raw.as<JsonArrayConst>()) {
    const char* name = v["name"] | "";
    if (name[0]) out.add(name);
  }
  return 200;
}

int bbCountActiveSpools(const char* base_url, const char* api_key,
                        uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  char url[192];
  snprintf(url, sizeof(url), "%s%s/spools", base_url, bbInventoryBase());

  // There is no count header and no page size, so the list has to be
  // fetched. The filter keeps only the id, which is the difference between
  // a few hundred bytes and the whole inventory in PSRAM.
  JsonDocument filter;
  filter.to<JsonArray>().add<JsonObject>()["id"] = true;

  SpiRamAllocator alloc;
  JsonDocument raw(&alloc);
  int code = getJson(url, api_key, raw, timeout_ms, nullptr, &filter);
  if (code != 200) return code;

  return (int)raw.as<JsonArrayConst>().size();
}

// Strips everything that is not a hex digit and upper cases the rest, which
// is the form BamBuddy stores and the only one its link endpoint accepts.
static void toPlainHex(const char* src, char* out, size_t out_size) {
  size_t o = 0;
  for (const char* p = src; p && *p && o + 1 < out_size; p++) {
    if (isxdigit((unsigned char)*p)) out[o++] = toupper((unsigned char)*p);
  }
  out[o] = '\0';
}

int bbFindSpoolByTag(const char* base_url, const char* api_key, const char* tag,
                     JsonDocument& doc, uint32_t timeout_ms,
                     DeserializationError* out_err) {
  doc.to<JsonArray>();
  if (!hasBaseUrl(base_url) || !tag || !tag[0]) return -1;

  char hex[40];
  toPlainHex(tag, hex, sizeof(hex));
  if (!hex[0]) return -1;

  // A 32 character identifier is a Bambu tray uuid, anything shorter an NFC
  // tag uid. BamBuddy matches the tray uuid first, which is what makes a
  // Bambu spool the AMS already knows resolve without any linking.
  const bool is_tray = (strlen(hex) == 32);

  int spool_id = 0;
  int code = bbTagScanned(base_url, api_key, is_tray ? nullptr : hex,
                          is_tray ? hex : nullptr, &spool_id, timeout_ms);
  if (code != 200) return code;

  // Second attempt with the caller's spelling. Only worth it when the two
  // differ, which means the identifier carried separators - the shape older
  // firmware wrote into Spoolman's extra.tag, where BamBuddy compares
  // character for character.
  if (spool_id == 0 && strcmp(hex, tag) != 0) {
    code = bbTagScanned(base_url, api_key, tag, nullptr, &spool_id, timeout_ms);
    if (code != 200) return code;
    if (spool_id > 0) {
      logSDf("BamBuddy: tag %s matched only in the legacy spelling", tag);
    }
  }

  if (spool_id == 0) return 200;   // known good answer, just no match

  JsonDocument spool;
  code = bbGetSpoolJson(base_url, api_key, spool_id, spool, timeout_ms, out_err);
  if (code != 200) return code;

  // The caller re-checks extra.tag against what it asked for, because the
  // other two backends search by substring and can answer with a spool that
  // merely contains the string. BamBuddy does not: the server compared the
  // identifier itself and named this spool. Reporting the queried spelling
  // therefore states what actually happened, and it keeps a tag stored as
  // plain hex from failing a check against a scan that carried separators.
  spool["extra"]["tag"] = tag;

  doc.to<JsonArray>().add(spool);
  return 200;
}

// ------------------------------------------------------------
//  WRITING
// ------------------------------------------------------------

int bbUpdateSpoolWeight(const char* base_url, const char* api_key,
                        int spool_id, float gross_grams, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;
  if (gross_grams < 0.0f) gross_grams = 0.0f;

  char url[160];
  snprintf(url, sizeof(url), "%s" BB_DEVICE_BASE "/scale/update-spool-weight", base_url);

  JsonDocument body;
  body["spool_id"]     = spool_id;
  body["weight_grams"] = roundGrams(gross_grams);

  String out;
  serializeJson(body, out);
  return sendJson("POST", url, api_key, out, timeout_ms, nullptr);
}

int bbLinkTag(const char* base_url, const char* api_key, int spool_id,
              const char* tag_uid, const char* tray_uuid, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;
  const bool has_tray = tray_uuid && tray_uuid[0];
  const bool has_uid  = tag_uid   && tag_uid[0];
  if (!has_tray && !has_uid) return -1;

  char url[224];
  JsonDocument body;

  if (s_mode == BB_INV_SPOOLMAN) {
    // The proxy has its own endpoint and refuses tag fields on the generic
    // PATCH. It validates ^[0-9A-Fa-f]+$, so anything with separators is
    // rejected with 422 - callers hand in plain hex.
    snprintf(url, sizeof(url), "%s/api/v1/spoolman/inventory/spools/%d/tag",
             base_url, spool_id);
    if (has_tray) body["tray_uuid"] = tray_uuid;
    else          body["tag_uid"]   = tag_uid;
  } else {
    snprintf(url, sizeof(url), "%s/api/v1/inventory/spools/%d/link-tag",
             base_url, spool_id);
    if (has_tray) body["tray_uuid"] = tray_uuid;
    if (has_uid)  body["tag_uid"]   = tag_uid;
    body["tag_type"]    = has_tray ? "bambulab" : "generic";
    body["data_origin"] = "nfc_link";
  }

  String out;
  serializeJson(body, out);
  return sendJson("PATCH", url, api_key, out, timeout_ms, nullptr);
}

int bbUnlinkTag(const char* base_url, const char* api_key, int spool_id,
                uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;

  char url[192];
  snprintf(url, sizeof(url), "%s%s/spools/%d", base_url, bbInventoryBase(), spool_id);

  // Written out rather than built, because what matters here is that both
  // keys are present and null. In Spoolman mode the proxy checks exactly
  // that - both named and both empty - before it clears extra.tag, and it
  // refuses the request outright if a tag field carries a value.
  return sendJson("PATCH", url, api_key,
                  "{\"tag_uid\":null,\"tray_uuid\":null}", timeout_ms, nullptr);
}

int bbArchiveSpool(const char* base_url, const char* api_key, int spool_id,
                   uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;

  char url[192];
  snprintf(url, sizeof(url), "%s%s/spools/%d/archive", base_url,
           bbInventoryBase(), spool_id);
  return sendJson("POST", url, api_key, "{}", timeout_ms, nullptr);
}

int bbPatchSpoolFields(const char* base_url, const char* api_key, int spool_id,
                       const int* label_weight, const int* core_weight,
                       const float* weight_used, const char* storage_location,
                       const char* note, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;

  JsonDocument body;
  if (label_weight)     body["label_weight"] = *label_weight;
  if (weight_used)      body["weight_used"]  = *weight_used;
  if (storage_location) body["storage_location"] = storage_location;
  if (note)             body["note"] = note;
  if (core_weight) {
    // Only reaches the database in BamBuddy's own inventory. The Spoolman
    // proxy accepts core_weight and drops it on the floor: "Accepted for
    // schema parity but not persisted to Spoolman". Sending it there would
    // return 200 and change nothing, so the caller is told instead.
    if (s_mode == BB_INV_SPOOLMAN) return -1;
    body["core_weight"] = *core_weight;
  }
  if (body.size() == 0) return -1;

  char url[192];
  snprintf(url, sizeof(url), "%s%s/spools/%d", base_url, bbInventoryBase(), spool_id);

  String out;
  serializeJson(body, out);
  return sendJson("PATCH", url, api_key, out, timeout_ms, nullptr);
}

int bbPatchDriedNote(const char* base_url, const char* api_key, int spool_id,
                     const char* iso, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0 || !iso || strlen(iso) < 10) return -1;

  char day[11];
  memcpy(day, iso, 10);
  day[10] = '\0';

  // Read first. The note belongs to the user and may hold anything; only the
  // marker may change. A failed read is not a reason to overwrite it, so this
  // gives up rather than guessing - the same rule filamanPatchCustomField
  // follows for FilaMan's custom fields.
  char url[192];
  snprintf(url, sizeof(url), "%s%s/spools/%d", base_url, bbInventoryBase(), spool_id);

  JsonDocument cur;
  int code = getJson(url, api_key, cur, timeout_ms, nullptr, nullptr);
  if (code != 200) {
    logSDf("BamBuddy: note not read (HTTP %d), drying date not written", code);
    return (code < 0) ? code : -2;
  }

  const char* old_note = cur["note"] | "";
  String note(old_note);

  char marker[28];
  snprintf(marker, sizeof(marker), "[last_dried:%s]", day);

  // Either spelling is replaced, so a note written by an older build is
  // brought up to date the first time a drying entry is made.
  int at = note.indexOf("[last_dried:");
  if (at < 0) at = note.indexOf("[dried:");
  if (at >= 0) {
    int end = note.indexOf(']', at);
    if (end < 0) end = note.length() - 1;      // truncated marker, replace to the end
    note = note.substring(0, at) + marker + note.substring(end + 1);
  } else {
    if (note.length()) note += " ";
    note += marker;
  }
  note.trim();

  // BamBuddy caps the note at 500 characters and would answer 422. Dropping
  // the write is better than losing the tail of someone's note.
  if (note.length() > 500) {
    logSD("BamBuddy: note would exceed 500 characters, drying date not written");
    return -2;
  }

  JsonDocument body;
  body["note"] = note;
  String out;
  serializeJson(body, out);
  return sendJson("PATCH", url, api_key, out, timeout_ms, nullptr);
}

bool bbGetDriedFromSpoolman(int spool_id, char* out_iso, size_t out_size,
                            uint32_t timeout_ms) {
  if (out_iso && out_size) out_iso[0] = '\0';
  if (!out_iso || out_size < 11 || spool_id <= 0) return false;
  if (!s_spoolman_url[0]) return false;

  // Straight to Spoolman, past BamBuddy: the proxy drops the extra dict, and
  // the id is the same on both sides because it passes Spoolman's own through.
  char url[192];
  snprintf(url, sizeof(url), "%s/api/v1/spool/%d", s_spoolman_url, spool_id);

  // Only the one field is wanted; the rest of a Spoolman spool is ballast.
  JsonDocument filter;
  filter["extra"]["last_dried"] = true;

  JsonDocument doc;
  if (getJson(url, nullptr, doc, timeout_ms, nullptr, &filter) != 200) return false;

  // Spoolman stores extra values JSON encoded, so the value arrives quoted.
  String v = doc["extra"]["last_dried"].as<String>();
  v.replace("\"", "");
  v.trim();
  if (v.length() < 10) return false;

  strncpy(out_iso, v.c_str(), out_size - 1);
  out_iso[out_size - 1] = '\0';
  return true;
}

int bbCreateSpool(const char* base_url, const char* api_key,
                  const char* material, const char* brand, const char* color_name,
                  const char* rgba, int label_weight, int core_weight,
                  const char* tag_uid, const char* tray_uuid,
                  int* out_spool_id, uint32_t timeout_ms) {
  if (out_spool_id) *out_spool_id = 0;
  if (!hasBaseUrl(base_url) || !material || !material[0]) return -1;

  JsonDocument body;
  body["material"] = material;
  if (brand      && brand[0])      body["brand"]      = brand;
  if (color_name && color_name[0]) body["color_name"] = color_name;
  if (rgba       && rgba[0])       body["rgba"]       = rgba;
  if (label_weight > 0) body["label_weight"] = label_weight;
  if (core_weight  > 0) body["core_weight"]  = core_weight;
  // Both are part of the create schema, so creating and linking is one
  // request rather than two.
  if (tag_uid   && tag_uid[0])   body["tag_uid"]   = tag_uid;
  if (tray_uuid && tray_uuid[0]) body["tray_uuid"] = tray_uuid;

  char url[192];
  snprintf(url, sizeof(url), "%s%s/spools", base_url, bbInventoryBase());

  String out, resp;
  serializeJson(body, out);
  int code = sendJson("POST", url, api_key, out, timeout_ms, &resp);
  if (code != 200) return code;

  JsonDocument doc;
  if (deserializeJson(doc, resp)) return -2;
  if (out_spool_id) *out_spool_id = doc["id"] | 0;
  return 200;
}

// ------------------------------------------------------------
//  DEVICE PROTOCOL
// ------------------------------------------------------------

int bbRegisterDevice(const char* base_url, const char* api_key, const char* ip,
                     const char* firmware, int32_t tare_offset,
                     float calibration_factor, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  JsonDocument body;
  body["device_id"]          = bbDeviceId();
  body["hostname"]           = "SpoolmanScale";
  body["ip_address"]         = (ip && ip[0]) ? ip : "0.0.0.0";
  body["firmware_version"]   = firmware ? firmware : "";
  body["has_nfc"]            = true;
  body["has_scale"]          = true;
  body["tare_offset"]        = tare_offset;
  body["calibration_factor"] = calibration_factor;
  body["nfc_reader_type"]    = "PN532";
  body["nfc_connection"]     = "i2c";
  body["has_backlight"]      = true;

  char url[160];
  snprintf(url, sizeof(url), "%s" BB_DEVICE_BASE "/devices/register", base_url);

  String out;
  serializeJson(body, out);
  int code = sendJson("POST", url, api_key, out, timeout_ms, nullptr);
  if (code == 200) logSDf("BamBuddy: registered as %s", bbDeviceId());
  return code;
}

int bbHeartbeat(const char* base_url, const char* api_key, bool nfc_ok,
                bool scale_ok, uint32_t uptime_s, const char* ip,
                const char* firmware, char* out_command, size_t out_command_size,
                int* out_write_spool_id, uint32_t timeout_ms) {
  if (out_command && out_command_size > 0) out_command[0] = '\0';
  if (out_write_spool_id) *out_write_spool_id = 0;
  if (!hasBaseUrl(base_url)) return -1;

  JsonDocument body;
  body["nfc_ok"]           = nfc_ok;
  body["scale_ok"]         = scale_ok;
  body["uptime_s"]         = uptime_s;
  body["ip_address"]       = (ip && ip[0]) ? ip : "0.0.0.0";
  body["firmware_version"] = firmware ? firmware : "";
  body["nfc_reader_type"]  = "PN532";
  body["nfc_connection"]   = "i2c";

  char url[192];
  snprintf(url, sizeof(url), "%s" BB_DEVICE_BASE "/devices/%s/heartbeat",
           base_url, bbDeviceId());

  String out, resp;
  serializeJson(body, out);
  // A 404 here means the device was deleted in the web interface. The caller
  // registers again rather than staying silently invisible.
  int code = sendJson("POST", url, api_key, out, timeout_ms, &resp);
  if (code != 200) return code;

  JsonDocument doc;
  if (deserializeJson(doc, resp)) return -2;

  // tare_offset and calibration_factor come back too and are deliberately
  // ignored: ours are measured on the factor screen, and letting a server
  // value win would silently decalibrate the scale.
  const char* cmd = doc["pending_command"] | "";
  if (out_command && out_command_size > 0 && cmd[0]) {
    strncpy(out_command, cmd, out_command_size - 1);
    out_command[out_command_size - 1] = '\0';
  }
  if (out_write_spool_id) {
    *out_write_spool_id = doc["pending_write_payload"]["spool_id"] | 0;
  }
  return 200;
}

int bbTagScanned(const char* base_url, const char* api_key, const char* tag_uid,
                 const char* tray_uuid, int* out_spool_id, uint32_t timeout_ms) {
  if (out_spool_id) *out_spool_id = 0;
  if (!hasBaseUrl(base_url)) return -1;
  const bool has_tray = tray_uuid && tray_uuid[0];
  const bool has_uid  = tag_uid   && tag_uid[0];
  if (!has_tray && !has_uid) return -1;

  JsonDocument body;
  body["device_id"] = bbDeviceId();
  // tag_uid is required by the schema. For a Bambu spool the 4 byte UID goes
  // here and the tray uuid alongside it, which is what BamBuddy matches on
  // first.
  body["tag_uid"] = has_uid ? tag_uid : tray_uuid;
  if (has_tray) body["tray_uuid"] = tray_uuid;

  char url[160];
  snprintf(url, sizeof(url), "%s" BB_DEVICE_BASE "/nfc/tag-scanned", base_url);

  String out, resp;
  serializeJson(body, out);
  int code = sendJson("POST", url, api_key, out, timeout_ms, &resp);
  if (code != 200) return code;

  JsonDocument doc;
  if (deserializeJson(doc, resp)) return -2;
  if (out_spool_id) *out_spool_id = doc["spool_id"] | 0;
  return 200;
}

int bbTagRemoved(const char* base_url, const char* api_key, const char* tag_uid,
                 uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || !tag_uid || !tag_uid[0]) return -1;

  JsonDocument body;
  body["device_id"] = bbDeviceId();
  body["tag_uid"]   = tag_uid;

  char url[160];
  snprintf(url, sizeof(url), "%s" BB_DEVICE_BASE "/nfc/tag-removed", base_url);

  String out;
  serializeJson(body, out);
  return sendJson("POST", url, api_key, out, timeout_ms, nullptr);
}

int bbScaleReading(const char* base_url, const char* api_key, float grams,
                   bool stable, int32_t raw_adc, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  JsonDocument body;
  body["device_id"]    = bbDeviceId();
  body["weight_grams"] = grams;
  body["stable"]       = stable;
  body["raw_adc"]      = raw_adc;

  char url[160];
  snprintf(url, sizeof(url), "%s" BB_DEVICE_BASE "/scale/reading", base_url);

  String out;
  serializeJson(body, out);
  return sendJson("POST", url, api_key, out, timeout_ms, nullptr);
}

int bbSetTare(const char* base_url, const char* api_key, int32_t tare_offset,
              uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  JsonDocument body;
  body["tare_offset"] = tare_offset;

  char url[192];
  snprintf(url, sizeof(url), "%s" BB_DEVICE_BASE "/devices/%s/calibration/set-tare",
           base_url, bbDeviceId());

  String out;
  serializeJson(body, out);
  return sendJson("POST", url, api_key, out, timeout_ms, nullptr);
}

int bbCommandResult(const char* base_url, const char* api_key,
                    const char* command, bool success, const char* message,
                    uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || !command || !command[0]) return -1;

  JsonDocument body;
  body["command"] = command;
  body["success"] = success;
  if (message && message[0]) body["message"] = message;

  char url[192];
  snprintf(url, sizeof(url), "%s" BB_DEVICE_BASE "/devices/%s/system/command-result",
           base_url, bbDeviceId());

  String out;
  serializeJson(body, out);
  return sendJson("POST", url, api_key, out, timeout_ms, nullptr);
}

int bbDiagnosticResult(const char* base_url, const char* api_key,
                       const char* diagnostic, bool success, const char* output,
                       int exit_code, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || !diagnostic || !diagnostic[0]) return -1;

  JsonDocument body;
  body["diagnostic"] = diagnostic;
  body["success"]    = success;
  body["output"]     = output ? output : "";
  body["exit_code"]  = exit_code;

  char url[192];
  snprintf(url, sizeof(url), "%s" BB_DEVICE_BASE "/diagnostics/%s/result",
           base_url, bbDeviceId());

  String out;
  serializeJson(body, out);
  return sendJson("POST", url, api_key, out, timeout_ms, nullptr);
}

int bbWriteTagResult(const char* base_url, const char* api_key, int spool_id,
                     const char* tag_uid, bool success, const char* message,
                     uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;

  JsonDocument body;
  body["device_id"] = bbDeviceId();
  body["spool_id"]  = spool_id;
  // The schema wants 8 to 30 hex characters even on a failure report, so a
  // missing uid is padded rather than left empty.
  body["tag_uid"]   = (tag_uid && strlen(tag_uid) >= 8) ? tag_uid : "00000000";
  body["success"]   = success;
  if (message && message[0]) body["message"] = message;

  char url[160];
  snprintf(url, sizeof(url), "%s" BB_DEVICE_BASE "/nfc/write-result", base_url);

  String out;
  serializeJson(body, out);
  return sendJson("POST", url, api_key, out, timeout_ms, nullptr);
}
