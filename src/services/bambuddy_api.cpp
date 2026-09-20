#include "bambuddy_api.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <ctype.h>
#include <math.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/device_name.h"
#include "services/http_progress.h"
#include "services/spool_cache.h"
#include "services/spool_color.h"
#include "services/tag_uid.h"
#include "services/wifi_manager.h"
#include "services/time_service.h"
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

  // Wrapped only while somebody is listening, so every other request in the
  // firmware reads exactly the stream it always did. One request, no paging,
  // so nothing has to be carried over.
  DeserializationError err = DeserializationError::Ok;
  if (httpProgressActive()) {
    HttpProgressStream ps(http.getStream());
    err = filter ? deserializeJson(doc, ps, DeserializationOption::Filter(*filter))
                 : deserializeJson(doc, ps);
  } else {
    err = filter
      ? deserializeJson(doc, http.getStream(), DeserializationOption::Filter(*filter))
      : deserializeJson(doc, http.getStream());
  }
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
  // Decided in locals and published once at the end. Clearing the globals
  // first left them saying "local" for the whole request, and a write from
  // the drying worker on the other core could land in that window and go to
  // the wrong inventory.
  BbInventoryMode mode = BB_INV_LOCAL;
  char spoolman_url[sizeof(s_spoolman_url)] = "";
  if (!hasBaseUrl(base_url)) {
    s_mode = mode;
    s_spoolman_url[0] = '\0';
    return -1;
  }

  char url[160];
  snprintf(url, sizeof(url), "%s/api/v1/settings/spoolman", base_url);

  JsonDocument doc;
  int code = getJson(url, api_key, doc, timeout_ms, nullptr, nullptr);
  if (code != 200) {
    // 403 means the key was created without "Read Status". Local mode is the
    // right guess then: it is what a fresh install runs, and a wrong guess
    // surfaces as a 404 on the first spool read rather than silently.
    logSDf("BamBuddy: inventory mode unknown (HTTP %d), assuming local", code);
    s_mode = mode;
    s_spoolman_url[0] = '\0';
    return code;
  }

  // Both values arrive as strings, not as JSON booleans.
  const char* enabled = doc["spoolman_enabled"] | "false";
  if (strcasecmp(enabled, "true") == 0) {
    mode = BB_INV_SPOOLMAN;
    snprintf(spoolman_url, sizeof(spoolman_url), "%s", doc["spoolman_url"] | "");
    // Reported with a trailing slash, which would double up when paths are
    // appended.
    size_t n = strlen(spoolman_url);
    while (n > 0 && spoolman_url[n - 1] == '/') spoolman_url[--n] = '\0';
  }
  // The url first: a reader that sees the new mode then also sees its url.
  memcpy(s_spoolman_url, spoolman_url, sizeof(s_spoolman_url));
  s_mode = mode;

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
    // Same server, same address, another inventory behind it: spool 12 of
    // BamBuddy's own database is not spool 12 of the Spoolman it proxies. The
    // kept list is keyed by address and backend and would not notice. Only a
    // flag, so it does not matter which task the health check runs on.
    spoolCacheForget("BamBuddy inventory moved");
  }
  return 200;
}

BbInventoryMode bbInventoryMode() { return s_mode; }

const char* bbInventoryBase() {
  return (s_mode == BB_INV_SPOOLMAN) ? "/api/v1/spoolman/inventory"
                                     : "/api/v1/inventory";
}

const char* bbSpoolmanUrl() { return s_spoolman_url; }

// Moved to wifi_manager so mDNS can advertise the same identity. Kept as a
// pass-through rather than replaced at the call sites, because "device id"
// means something specific to BamBuddy and the name carries that here.
const char* bbDeviceId() { return wifiManagerDeviceId(); }

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

  // Spoolman shows one name. BamBuddy keeps the three parts apart, so they are
  // joined in the order they are printed on the spool itself: "PETG HF
  // Orange". The brand stays out of it - the display gives the vendor its own
  // line, and an earlier version that led with the brand dropped the colour
  // name entirely, because the subtype won and nothing else was appended.
  const char* brand   = src["brand"]      | "";
  const char* mat_s   = src["material"]   | "";
  const char* subtype = src["subtype"]    | "";
  const char* colname = src["color_name"] | "";
  const char* parts[3] = { mat_s, subtype, colname };
  char name[64] = "";
  size_t nl = 0;
  for (int i = 0; i < 3; i++) {
    if (!parts[i][0]) continue;
    int w = snprintf(name + nl, sizeof(name) - nl, "%s%s", nl ? " " : "", parts[i]);
    if (w < 0) break;
    nl += (size_t)w;
    if (nl >= sizeof(name) - 1) break;   // snprintf already truncated
  }
  // A spool with none of the three is unusual but not impossible; the brand
  // keeps the row from rendering blank.
  if (!name[0]) {
    strncpy(name, brand, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
  }
  f["name"] = name;

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

int bbGetSpoolRawJson(const char* base_url, const char* api_key, int spool_id,
                      JsonDocument& doc, uint32_t timeout_ms,
                      DeserializationError* out_err) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;

  char url[192];
  snprintf(url, sizeof(url), "%s%s/spools/%d", base_url, bbInventoryBase(), spool_id);
  return getJson(url, api_key, doc, timeout_ms, out_err, nullptr);
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
  // -1 like the other two backends: the caller shows a count, and a 403 from
  // a key without the inventory scope used to read as "403 spools".
  if (code != 200) return -1;

  return (int)raw.as<JsonArrayConst>().size();
}

int bbFindSpoolByTag(const char* base_url, const char* api_key, const char* tag,
                     JsonDocument& doc, uint32_t timeout_ms,
                     DeserializationError* out_err) {
  doc.to<JsonArray>();
  if (!hasBaseUrl(base_url) || !tag || !tag[0]) return -1;

  char hex[40];
  // Plain uppercase hex is what BamBuddy stores and the only form its link
  // endpoint accepts. tagUidNormalize() is the one place that knows this.
  tagUidNormalize(tag, hex, sizeof(hex));
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

int bbRestoreSpool(const char* base_url, const char* api_key, int spool_id,
                   uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;

  // The counterpart to /archive, and it sits right next to it in both
  // inventory modes, so bbInventoryBase() picks the right one.
  char url[192];
  snprintf(url, sizeof(url), "%s%s/spools/%d/restore", base_url,
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

  // The note holds a bare date with no zone, so it has to be the local day.
  // Slicing the incoming UTC instant would put a drying just after midnight
  // on the day before.
  char day[11];
  isoDayLocal(iso, day, sizeof(day));

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

// A Bambu tag stores the colour as a value, never as a name. BamBuddy keeps a
// catalogue that can turn one into the other, and does it better than a plain
// hex table would: the material decides between entries that share a hex, so
// "PLA Matte Charcoal" does not come back as "PLA Basic Black".
//
// Always the local path - the catalogue is BamBuddy's own, like locations, and
// exists in both inventory modes. An unknown colour answers with null, which
// is not an error: the spool is simply created without a colour name.
int bbLookupColorName(const char* base_url, const char* api_key, const char* hex6,
                      const char* material, char* out_name, size_t out_size,
                      uint32_t timeout_ms) {
  if (out_name && out_size) out_name[0] = '\0';
  if (!hasBaseUrl(base_url) || !hex6 || strlen(hex6) < 6) return -1;

  char esc[48] = "";
  if (material && material[0]) {
    // Only spaces need escaping here: material names are ASCII letters,
    // digits, spaces and hyphens.
    size_t o = 0;
    for (size_t i = 0; material[i] && o + 4 < sizeof(esc); i++) {
      if (material[i] == ' ') { memcpy(esc + o, "%20", 3); o += 3; }
      else esc[o++] = material[i];
    }
    esc[o] = '\0';
  }

  char url[256];
  snprintf(url, sizeof(url), "%s/api/v1/inventory/colors/by-material?hex=%.6s%s%s",
           base_url, hex6, esc[0] ? "&material=" : "", esc);

  JsonDocument doc;
  int code = getJson(url, api_key, doc, timeout_ms, nullptr, nullptr);
  if (code != 200) return code;

  const char* name = doc["color_name"] | "";
  if (name[0] && out_name && out_size) {
    strncpy(out_name, name, out_size - 1);
    out_name[out_size - 1] = '\0';
  }
  Serial.printf("BamBuddy colour: %.6s + '%s' -> '%s'\n",
                hex6, material ? material : "", name);
  return 200;
}

int bbCreateSpool(const char* base_url, const char* api_key,
                  const BbNewSpool& spool, int* out_spool_id,
                  uint32_t timeout_ms) {
  if (out_spool_id) *out_spool_id = 0;
  if (!hasBaseUrl(base_url) || !spool.material || !spool.material[0]) return -1;

  JsonDocument body;
  body["material"] = spool.material;
  if (spool.subtype    && spool.subtype[0])    body["subtype"]    = spool.subtype;
  if (spool.brand      && spool.brand[0])      body["brand"]      = spool.brand;
  if (spool.color_name && spool.color_name[0]) body["color_name"] = spool.color_name;
  if (spool.rgba       && spool.rgba[0])       body["rgba"]       = spool.rgba;
  if (spool.label_weight > 0) body["label_weight"] = spool.label_weight;
  if (spool.core_weight  > 0) body["core_weight"]  = spool.core_weight;
  // Always written, zero included: BamBuddy stores what was consumed and
  // derives the rest, so leaving it out would make every new spool full.
  body["weight_used"] = roundGrams(spool.weight_used < 0.0f ? 0.0f : spool.weight_used);
  // Only the built-in inventory has these. Behind the Spoolman proxy they are
  // not part of the schema and are dropped server side without complaint.
  if (spool.nozzle_temp_min > 0) body["nozzle_temp_min"] = spool.nozzle_temp_min;
  if (spool.nozzle_temp_max > 0) body["nozzle_temp_max"] = spool.nozzle_temp_max;

  char url[192];
  snprintf(url, sizeof(url), "%s%s/spools", base_url, bbInventoryBase());

  String out, resp;
  serializeJson(body, out);
  // Worth a line of its own: behind the Spoolman proxy an empty brand makes
  // the server build a filament with no vendor and a name cut to the bare
  // material, which looks like data loss on the display but starts here.
  // Serial as well as SD: without a card logSDf() is a no-op, and this is the
  // line that tells an empty vendor or colour apart from a server that
  // dropped them.
  Serial.printf("BamBuddy create: mat='%s' sub='%s' brand='%s' col='%s' label=%d core=%d used=%.0f\n",
                spool.material,
                spool.subtype    ? spool.subtype    : "",
                spool.brand      ? spool.brand      : "",
                spool.color_name ? spool.color_name : "",
                spool.label_weight, spool.core_weight, spool.weight_used);
  logSDf("BamBuddy create: mat=%s sub=%s brand=%s col=%s label=%d core=%d used=%.0f",
         spool.material,
         spool.subtype    ? spool.subtype    : "",
         spool.brand      ? spool.brand      : "",
         spool.color_name ? spool.color_name : "",
         spool.label_weight, spool.core_weight, spool.weight_used);
  int code = sendJson("POST", url, api_key, out, timeout_ms, &resp);
  if (code != 200) return code;

  JsonDocument doc;
  if (deserializeJson(doc, resp)) return -2;
  if (out_spool_id) *out_spool_id = doc["id"] | 0;
  return 200;
}

// ------------------------------------------------------------
//  AMS SLOTS
// ------------------------------------------------------------

// Bambu sends a tray colour as six hex digits, or eight with an alpha byte
// on the end. 00000000 means two different things: an empty or unconfigured
// bay reports it, and so does a clear filament - PETG Translucent Clear, PC
// Transparent. The bay's material tells them apart. With one, the zeros are
// a clear spool and drawn as glass; without, they say nothing, and painting
// them as black or as glass would claim a colour the bay does not have.
static void parseTrayColor(const char* hex, const char* tray_type, SpoolColor* out) {
  spoolColorParse(hex, out);
  if (!spoolColorNamesHue(*out) && !(tray_type && tray_type[0])) *out = SpoolColor{};
}

// One AMSTray object into one bay. Shared by the AMS units and the external
// holder, because BamBuddy describes both with the same schema.
static void fillTray(JsonObjectConst t, AmsSlotTray& out, uint8_t tray_id) {
  out = AmsSlotTray{};
  out.tray_id  = tray_id;
  // BamBuddy reports no gram figure per bay, only the percentage Bambu sends.
  out.remain_g = AMS_REMAIN_NA;
  // Nor a nozzle range: it takes one when a spool is created and never hands
  // it back. Said here rather than left at the zero of the initializer, which
  // a reader would take for a real 0 °C.
  out.nozzle_min = AMS_REMAIN_NA;
  out.nozzle_max = AMS_REMAIN_NA;

  // The sub brand is the name a user recognises ("PLA Matte"); the bare
  // material is the fallback when the spool carries no brand information.
  const char* sub  = t["tray_sub_brands"] | "";
  const char* type = t["tray_type"] | "";
  const char* name = (sub && sub[0]) ? sub : type;
  strncpy(out.name, name ? name : "", sizeof(out.name) - 1);
  // The bare type as well, on its own: it is the printer's word for what is
  // in the bay, and the detail card holds it against the spool the assignment
  // list names. The name above cannot do that - "Support for PLA" is a sub
  // brand too.
  strncpy(out.type, type ? type : "", sizeof(out.type) - 1);

  parseTrayColor(t["tray_color"] | "", out.type, &out.color);

  // Bambu itself sends -1 for "no idea", and anything outside 0..100 is a
  // value we would only misdraw.
  int remain = t["remain"] | AMS_REMAIN_NA;
  if (remain < 0 || remain > 100) remain = AMS_REMAIN_NA;
  out.remain = (int8_t)remain;

  // exists is the authority when the field is there. When it is missing,
  // a bay that names a material is holding one - that is how BamBuddy's own
  // interface reads it too.
  JsonVariantConst ex = t["exists"];
  out.exists = ex.isNull() ? (out.name[0] != '\0') : (ex.as<bool>());
}

int bbGetAmsState(const char* base_url, const char* api_key, int printer_id,
                  AmsSlotState& out, uint32_t timeout_ms) {
  out = AmsSlotState{};
  if (!hasBaseUrl(base_url) || printer_id <= 0) return -1;

  char url[192];
  snprintf(url, sizeof(url), "%s/api/v1/printers/%d/status", base_url, printer_id);

  JsonDocument filter;
  filter["name"]       = true;
  filter["connected"]  = true;
  filter["ams_exists"] = true;

  JsonObject fu = filter["ams"].to<JsonArray>().add<JsonObject>();
  fu["id"]        = true;
  fu["humidity"]  = true;
  fu["temp"]      = true;
  fu["is_ams_ht"] = true;
  // "n3f", "ams", "n3s": which hardware the unit is. Only an AMS 2 Pro gets
  // the card's "all spools in this unit" drying answer.
  fu["module_type"] = true;
  // The running cycle. Without these the view never showed a drying unit on
  // this backend at all, although BamBuddy reports all three.
  fu["dry_status"]      = true;
  fu["dry_time"]        = true;
  fu["dry_target_temp"] = true;
  JsonObject ft = fu["tray"].to<JsonArray>().add<JsonObject>();
  ft["id"]              = true;
  ft["tray_color"]      = true;
  ft["tray_type"]       = true;
  ft["tray_sub_brands"] = true;
  ft["remain"]          = true;
  ft["exists"]          = true;

  // Which bay the printer feeds from. Bambu numbers it globally as
  // ams_id * 4 + slot, so it is resolved back to a pair below.
  filter["tray_now"] = true;

  // vt_tray is an AMSTray array of its own at the top level, not a child of
  // ams, so the same field set has to be named a second time.
  JsonObject fv = filter["vt_tray"].to<JsonArray>().add<JsonObject>();
  fv["id"]              = true;
  fv["tray_color"]      = true;
  fv["tray_type"]       = true;
  fv["tray_sub_brands"] = true;
  fv["remain"]          = true;
  fv["exists"]          = true;

  // No PSRAM allocator: what survives the filter is a couple of kilobytes
  // and is copied into the fixed struct right away.
  JsonDocument doc;
  int code = getJson(url, api_key, doc, timeout_ms, nullptr, &filter);
  if (code != 200) return code;

  out.printer_id = printer_id;
  strncpy(out.printer, doc["name"] | "", sizeof(out.printer) - 1);
  // Same distinction as on the FilaMan side, so both branches mean the same
  // thing by an absent flag.
  JsonVariantConst conn = doc["connected"];
  out.conn_known = !conn.isNull();
  out.connected  = conn | false;
  out.ams_exists = doc["ams_exists"] | false;
  // The status payload carries no job progress. Left at the zero the struct
  // starts with, the view reads it as "printing 0 %" on every idle printer.
  out.job_percent = AMS_JOB_NA;

  // 255 is Bambu's "nothing loaded", and so is a missing field.
  const int tray_now = doc["tray_now"] | 255;

  for (JsonVariantConst uv : doc["ams"].as<JsonArrayConst>()) {
    JsonObjectConst u = uv.as<JsonObjectConst>();
    if (out.unit_count >= AMS_MAX_UNITS) {
      logSDf("BamBuddy: printer %d reports more than %d AMS units, rest ignored",
             printer_id, AMS_MAX_UNITS);
      break;
    }
    AmsSlotUnit& dst = out.unit[out.unit_count];
    dst = AmsSlotUnit{};
    dst.ams_id = (uint8_t)(u["id"] | 0);
    const char* module_type = u["module_type"] | "";
    dst.model  = amsModelFromModuleType(module_type);
    dst.is_ht  = (u["is_ams_ht"] | false) || dst.ams_id >= 128 ||
                 dst.model == AMS_MODEL_AMS_HT;
    // A cycle counts as running on either signal, the same rule FilaMan
    // applies: a status of 1 to 4 (checking, drying, cooling, stopping), or
    // minutes still to go. An idle AMS 2 Pro reports status 0, and an AMS HT
    // reports the minutes while leaving the status at 0 and sending no target
    // temperature at all.
    const int dry_status = u["dry_status"] | 0;
    const int dry_time   = u["dry_time"] | 0;
    dst.drying      = (dry_status >= 1 && dry_status <= 4) || dry_time > 0;
    dst.dry_minutes = (dry_time > 0) ? (int16_t)dry_time : (int16_t)AMS_REMAIN_NA;
    JsonVariantConst dry_temp = u["dry_target_temp"];
    dst.dry_target_c = dry_temp.isNull() ? (int8_t)AMS_REMAIN_NA
                                         : (int8_t)lroundf(dry_temp.as<float>());

    if (sd_verbose) {
      logSDf("[verbose] BamBuddy: unit %d module_type=%s model=%d drying=%d %d min %d C",
             (int)dst.ams_id, module_type[0] ? module_type : "-", (int)dst.model,
             (int)dst.drying, (int)dst.dry_minutes, (int)dst.dry_target_c);
    }

    JsonVariantConst hum = u["humidity"];
    if (hum.isNull()) {
      dst.humidity = AMS_HUMIDITY_NA;
    } else {
      int h = hum.as<int>();
      // Bambu reports either a raw percentage or its own 1 to 5 step, and
      // never says which. Anything at or below the top step is read as a
      // step: an AMS at 5 percent humidity does not occur, a step 5 does.
      dst.humidity_is_level = (h > 0 && h <= 5);
      if (h < 0 || h > 100) h = AMS_HUMIDITY_NA;
      dst.humidity = (int8_t)h;
    }

    JsonVariantConst tmp = u["temp"];
    dst.temp_c10 = tmp.isNull() ? AMS_TEMP_NA : (int16_t)lroundf(tmp.as<float>() * 10.0f);

    for (JsonVariantConst tv : u["tray"].as<JsonArrayConst>()) {
      if (dst.tray_count >= AMS_MAX_TRAYS) break;
      JsonObjectConst t = tv.as<JsonObjectConst>();
      const uint8_t tid = (uint8_t)(t["id"] | dst.tray_count);
      fillTray(t, dst.tray[dst.tray_count], tid);
      // A regular AMS is addressed as ams_id * 4 + slot. An AMS HT numbers
      // itself from 128 and has one bay, so that product cannot fit the
      // field; the id itself is what the printer reports for it.
      const int global = dst.ams_id * 4 + tid;
      dst.tray[dst.tray_count].active =
        (tray_now == global) || (dst.is_ht && tray_now == dst.ams_id);
      dst.tray_count++;
    }
    out.unit_count++;
  }

  // The external holder is one unit carrying its bays, not one unit per bay:
  // a dual nozzle H2D has two of them side by side, and they belong together
  // on the screen the way the bays of an AMS do.
  JsonArrayConst vt = doc["vt_tray"].as<JsonArrayConst>();
  if (!vt.isNull() && vt.size() > 0 && out.unit_count < AMS_UNITS_TOTAL) {
    AmsSlotUnit& dst = out.unit[out.unit_count];
    dst = AmsSlotUnit{};
    dst.ams_id   = AMS_EXT_AMS_ID;
    dst.is_ext   = true;
    dst.humidity = AMS_HUMIDITY_NA;
    dst.temp_c10 = AMS_TEMP_NA;

    for (JsonVariantConst tv : vt) {
      if (dst.tray_count >= AMS_MAX_EXT) break;
      JsonObjectConst t = tv.as<JsonObjectConst>();
      const uint8_t tid = (uint8_t)(t["id"] | (AMS_EXT_TRAY_ID + dst.tray_count));
      fillTray(t, dst.tray[dst.tray_count], tid);
      dst.tray[dst.tray_count].active = (tray_now == tid);
      dst.tray_count++;
    }
    out.unit_count++;
  }

  out.valid = true;
  logSDf("BamBuddy: AMS of printer %d, %d unit(s), connected=%d ams_exists=%d",
         printer_id, (int)out.unit_count, (int)out.connected, (int)out.ams_exists);
  return 200;
}

int bbListPrinters(const char* base_url, const char* api_key,
                   AmsPrinterList& out, uint32_t timeout_ms) {
  out = AmsPrinterList{};
  if (!hasBaseUrl(base_url)) return -1;

  char url[160];
  snprintf(url, sizeof(url), "%s/api/v1/printers/", base_url);

  JsonDocument filter;
  filter.to<JsonArray>();   // accepts the bare array form

  SpiRamAllocator alloc;
  JsonDocument doc(&alloc);
  // Unfiltered: the endpoint declares no response schema at all, so a filter
  // written for a guessed shape would quietly empty the list instead of
  // failing. The answer is a handful of printers.
  int code = getJson(url, api_key, doc, timeout_ms, nullptr, nullptr);
  if (code != 200) return code;

  // Three shapes are accepted because the contract does not say which one
  // this is, and the one that arrived is logged so the guess never has to be
  // made twice.
  JsonArrayConst arr;
  const char* shape = "array";
  if (doc.is<JsonArrayConst>()) {
    arr = doc.as<JsonArrayConst>();
  } else if (doc["printers"].is<JsonArrayConst>()) {
    arr = doc["printers"].as<JsonArrayConst>();
    shape = "printers";
  } else if (doc["items"].is<JsonArrayConst>()) {
    arr = doc["items"].as<JsonArrayConst>();
    shape = "items";
  } else {
    logSD("BamBuddy: printer list has none of the three known shapes");
    return -2;
  }

  for (JsonVariantConst pv : arr) {
    if (out.count >= AMS_MAX_PRINTERS) {
      logSDf("BamBuddy: more than %d printers, rest ignored", AMS_MAX_PRINTERS);
      break;
    }
    JsonObjectConst po = pv.as<JsonObjectConst>();
    int id = po["id"] | 0;
    if (id <= 0) continue;
    AmsPrinter& dst = out.p[out.count];
    dst = AmsPrinter{};
    dst.id = id;
    strncpy(dst.name, po["name"] | "", sizeof(dst.name) - 1);
    // Neither key is guaranteed; absent means "do not grey it out".
    dst.active = po["is_active"] | true;
    dst.online = po["connected"] | po["online"] | false;
    out.count++;
  }

  logSDf("BamBuddy: %d printer(s) from a \"%s\" response", (int)out.count, shape);
  return 200;
}

// Both assignment routes, told apart in one place. They differ in more than
// the prefix bbInventoryBase() hands out, so that helper is deliberately not
// used here.
static const char* assignPath() {
  return (bbInventoryMode() == BB_INV_SPOOLMAN)
           ? "/api/v1/spoolman/inventory/slot-assignments"
           : "/api/v1/inventory/assignments";
}

int bbAssignSlot(const char* base_url, const char* api_key, int spool_id,
                 int printer_id, int ams_id, int tray_id, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0 || printer_id <= 0) return -1;

  // Checked here rather than left to the server: a 422 arrives as a wall of
  // validation JSON, and the one thing worth knowing is that this bay cannot
  // be addressed at all.
  if (ams_id < 0 || ams_id > 255 || tray_id < 0 || tray_id > 3) {
    logSDf("BamBuddy: bay %d/%d is outside what an assignment accepts",
           ams_id, tray_id);
    return -1;
  }

  const bool proxy = (bbInventoryMode() == BB_INV_SPOOLMAN);
  JsonDocument body;
  body[proxy ? "spoolman_spool_id" : "spool_id"] = spool_id;
  body["printer_id"] = printer_id;
  body["ams_id"]     = ams_id;
  body["tray_id"]    = tray_id;

  String payload;
  serializeJson(body, payload);

  char url[192];
  snprintf(url, sizeof(url), "%s%s", base_url, assignPath());

  int code = sendJson("POST", url, api_key, payload, timeout_ms, nullptr);
  logSDf("BamBuddy: spool %d -> printer %d bay %d/%d, HTTP %d",
         spool_id, printer_id, ams_id, tray_id, code);
  return code;
}

int bbUnassignSlot(const char* base_url, const char* api_key, int spool_id,
                   int printer_id, int ams_id, int tray_id, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  char url[208];
  if (bbInventoryMode() == BB_INV_SPOOLMAN) {
    if (spool_id <= 0) return -1;
    snprintf(url, sizeof(url), "%s%s/%d", base_url, assignPath(), spool_id);
  } else {
    if (printer_id <= 0 || ams_id < 0 || tray_id < 0) return -1;
    snprintf(url, sizeof(url), "%s%s/%d/%d/%d", base_url, assignPath(),
             printer_id, ams_id, tray_id);
  }

  int code = sendJson("DELETE", url, api_key, String("{}"), timeout_ms, nullptr);
  // 404 means it was not assigned, which is the state the caller wanted.
  if (code == 404) code = 200;
  logSDf("BamBuddy: release spool %d / bay %d/%d, HTTP %d",
         spool_id, ams_id, tray_id, code);
  return code;
}

// The slot assignments of one printer, cut down to the three numbers that
// make up an assignment. Both directions of the lookup - spool to bay and bay
// to spool - read the same list, so the route and the filter are built once:
// two copies would be two places for the proxy mode to be got wrong.
//
// Returns 200 and fills doc, or the transport's code. id_key is set to
// whichever key this inventory mode names the spool with.
static int bbGetAssignments(const char* base_url, const char* api_key,
                            int printer_id, JsonDocument& doc,
                            const char** id_key, uint32_t timeout_ms) {
  const bool proxy = (bbInventoryMode() == BB_INV_SPOOLMAN);
  *id_key = proxy ? "spoolman_spool_id" : "spool_id";

  char url[224];
  if (proxy) {
    snprintf(url, sizeof(url),
             "%s/api/v1/spoolman/inventory/slot-assignments/all?printer_id=%d",
             base_url, printer_id);
  } else {
    snprintf(url, sizeof(url), "%s/api/v1/inventory/assignments?printer_id=%d",
             base_url, printer_id);
  }

  // The local answer embeds the whole spool in every entry, so the filter is
  // what keeps this from pulling the inventory across for one number.
  JsonDocument filter;
  JsonObject f = filter.to<JsonArray>().add<JsonObject>();
  f["ams_id"]  = true;
  f["tray_id"] = true;
  f[*id_key]   = true;
  // The local answer carries the whole spool per assignment, so the weight
  // comes with the list rather than costing a request of its own. The proxy
  // mode names the id alone and this key is simply absent there.
  f["spool"]["remaining_weight"] = true;

  return getJson(url, api_key, doc, timeout_ms, nullptr, &filter);
}

int bbFindSpoolSlot(const char* base_url, const char* api_key, int spool_id,
                    int printer_id, int* out_ams, int* out_tray,
                    uint32_t timeout_ms) {
  if (out_ams)  *out_ams  = -1;
  if (out_tray) *out_tray = -1;
  if (!hasBaseUrl(base_url) || spool_id <= 0 || printer_id <= 0) return -1;

  JsonDocument doc;
  const char* id_key = nullptr;
  int code = bbGetAssignments(base_url, api_key, printer_id, doc, &id_key, timeout_ms);
  if (code != 200) return code;

  for (JsonVariantConst av : doc.as<JsonArrayConst>()) {
    JsonObjectConst a = av.as<JsonObjectConst>();
    if ((a[id_key] | 0) != spool_id) continue;
    if (out_ams)  *out_ams  = a["ams_id"]  | -1;
    if (out_tray) *out_tray = a["tray_id"] | -1;
    break;
  }
  return 200;
}

int bbFindBaySpool(const char* base_url, const char* api_key, int printer_id,
                   int ams_id, int tray_id, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || printer_id <= 0 || ams_id < 0 || tray_id < 0) return -1;

  JsonDocument doc;
  const char* id_key = nullptr;
  int code = bbGetAssignments(base_url, api_key, printer_id, doc, &id_key, timeout_ms);
  // Negated: the answer is a spool id when positive, and a 404 handed back
  // as it came was shown on the card as spool 404.
  if (code != 200) return code > 0 ? -code : code;

  for (JsonVariantConst av : doc.as<JsonArrayConst>()) {
    JsonObjectConst a = av.as<JsonObjectConst>();
    if ((a["ams_id"] | -1) != ams_id || (a["tray_id"] | -1) != tray_id) continue;
    int id = a[id_key] | 0;
    logSDf("BamBuddy: bay %d/%d of printer %d holds spool %d",
           ams_id, tray_id, printer_id, id);
    return id > 0 ? id : 0;
  }
  // The printer has no assignment for this bay. Not an error: a bay can hold
  // filament the inventory never heard of.
  return 0;
}

int bbFindPrinterSpools(const char* base_url, const char* api_key, int printer_id,
                        AmsSlotSpool* out, uint8_t max, uint8_t* out_count,
                        uint32_t timeout_ms) {
  if (out_count) *out_count = 0;
  if (!out || max == 0) return -1;
  if (!hasBaseUrl(base_url) || printer_id <= 0) return -1;

  JsonDocument doc;
  const char* id_key = nullptr;
  int code = bbGetAssignments(base_url, api_key, printer_id, doc, &id_key, timeout_ms);
  if (code != 200) return code > 0 ? -code : code;

  uint8_t n = 0;
  for (JsonVariantConst av : doc.as<JsonArrayConst>()) {
    if (n >= max) break;
    JsonObjectConst a = av.as<JsonObjectConst>();
    const int ams  = a["ams_id"]  | -1;
    const int tray = a["tray_id"] | -1;
    const int id   = a[id_key] | 0;
    if (ams < 0 || tray < 0 || id <= 0) continue;
    out[n].ams_id   = (uint8_t)ams;
    out[n].tray_id  = (uint8_t)tray;
    out[n].spool_id = id;
    out[n].grams    = AMS_REMAIN_NA;
    JsonVariantConst left = a["spool"]["remaining_weight"];
    if (!left.isNull()) {
      const long g = lroundf(left.as<float>());
      if (g >= 0 && g <= INT16_MAX) out[n].grams = (int16_t)g;
    }
    n++;
  }
  if (out_count) *out_count = n;
  logSDf("BamBuddy: printer %d has %u assigned bay(s)", printer_id, (unsigned)n);
  return 200;
}

int bbFindUnitSpools(const char* base_url, const char* api_key, int printer_id,
                     int ams_id, int* out_by_tray, uint8_t n, uint32_t timeout_ms) {
  if (!out_by_tray) return -1;
  for (uint8_t i = 0; i < n; i++) out_by_tray[i] = 0;
  if (!hasBaseUrl(base_url) || printer_id <= 0 || ams_id < 0) return -1;

  JsonDocument doc;
  const char* id_key = nullptr;
  int code = bbGetAssignments(base_url, api_key, printer_id, doc, &id_key, timeout_ms);
  if (code != 200) return code > 0 ? -code : code;

  for (JsonVariantConst av : doc.as<JsonArrayConst>()) {
    JsonObjectConst a = av.as<JsonObjectConst>();
    if ((a["ams_id"] | -1) != ams_id) continue;
    const int tray_id = a["tray_id"] | -1;
    const int id = a[id_key] | 0;
    if (tray_id < 0 || tray_id >= n || id <= 0) continue;
    out_by_tray[tray_id] = id;
  }
  logSDf("BamBuddy: unit %d of printer %d holds spools %d/%d/%d/%d", ams_id,
         printer_id, n > 0 ? out_by_tray[0] : 0, n > 1 ? out_by_tray[1] : 0,
         n > 2 ? out_by_tray[2] : 0, n > 3 ? out_by_tray[3] : 0);
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
  // The label the user chose, not the product name. The registration itself
  // hangs on device_id (bbDeviceId()), so this is the display field and
  // nothing keys off it - two scales on one BamBuddy can finally be told
  // apart in its device list.
  body["hostname"]           = deviceLabel();
  body["ip_address"]         = (ip && ip[0]) ? ip : "0.0.0.0";
  body["firmware_version"]   = firmware ? firmware : "";
  body["has_nfc"]            = true;
  // A device built from display and reader alone has no load cell, and saying
  // otherwise puts it in BamBuddy's device list as a scale. tare_offset and
  // calibration_factor stay in the body regardless: leaving fields out could
  // upset the parser on the other side, and has_scale is the field it is
  // meant to tell them apart by.
  body["has_scale"]          = g_scale_fitted;
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
