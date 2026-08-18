#include "filaman_api.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <math.h>
#include <string.h>

#include "hardware/sd_logger.h"

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

// FilaMan caps page_size at 200 and answers larger values with a validation
// error. The page ceiling is a safety net so a misbehaving server cannot
// spin the loop forever; 20 pages is 4000 spools.
#define FILAMAN_PAGE_MAX    200
#define FILAMAN_MAX_PAGES    20

static bool hasBaseUrl(const char* base_url) {
  return base_url && strlen(base_url) > 7;   // longer than "http://"
}

// FilaMan's API accepts fractional grams, its edit forms do not: they reject
// a value with decimals. A load cell has no meaningful accuracy below a gram
// anyway, so everything sent in grams is rounded. Spoolman keeps receiving
// the unrounded value, its behaviour is unchanged.
static float roundGrams(float g) {
  return roundf(g);
}

// Defined further down, next to the other request helpers.
static void addApiKey(HTTPClient& http, const char* api_key);

// ------------------------------------------------------------
//  LOCATION CACHE
//
//  Spools carry a location_id, the UI works with names. Rather than fetch
//  the list on every spool read, it is kept here and refreshed lazily. The
//  list is short and changes rarely.
// ------------------------------------------------------------
// Matches the ceiling the web interface allows for location_list_limit, so
// the cache can never be the narrower of the two. 100 x 40 bytes is 4 kB of
// static RAM, deliberately not heap: this sits in the scan path.
#define FILAMAN_LOC_MAX      100
#define FILAMAN_LOC_NAME_LEN 40
#define FILAMAN_LOC_TTL_MS   300000UL   // 5 minutes

static int           s_loc_id[FILAMAN_LOC_MAX];
static char          s_loc_name[FILAMAN_LOC_MAX][FILAMAN_LOC_NAME_LEN];
static int           s_loc_count = 0;
static unsigned long s_loc_fetched_ms = 0;

static const char* locationNameById(int id) {
  if (id <= 0) return nullptr;
  for (int i = 0; i < s_loc_count; i++) {
    if (s_loc_id[i] == id) return s_loc_name[i];
  }
  return nullptr;
}

static int locationIdByName(const char* name) {
  if (!name || !name[0]) return 0;
  for (int i = 0; i < s_loc_count; i++) {
    if (strcasecmp(s_loc_name[i], name) == 0) return s_loc_id[i];
  }
  return 0;
}

// Fetches the location list into the cache. force skips the age check, which
// matters when a name could not be resolved and the cache may be stale.
static bool fetchLocations(const char* base_url, const char* api_key, bool force) {
  if (!hasBaseUrl(base_url)) return false;
  if (!force && s_loc_count > 0 &&
      (millis() - s_loc_fetched_ms) < FILAMAN_LOC_TTL_MS) return true;

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/locations?page_size=" + FILAMAN_LOC_MAX);
  http.setTimeout(6000);
  addApiKey(http, api_key);
  if (http.GET() != 200) { http.end(); return false; }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, http.getStream());
  http.end();
  if (err) {
    logSDf("FilaMan: location list parse error: %s", err.c_str());
    return false;
  }

  JsonArrayConst items = doc["items"].isNull() ? doc.as<JsonArrayConst>()
                                               : doc["items"].as<JsonArrayConst>();
  int total = doc["total"] | (int)items.size();
  s_loc_count = 0;
  for (JsonObjectConst l : items) {
    if (s_loc_count >= FILAMAN_LOC_MAX) break;
    s_loc_id[s_loc_count] = l["id"] | 0;
    strncpy(s_loc_name[s_loc_count], l["name"] | "", FILAMAN_LOC_NAME_LEN - 1);
    s_loc_name[s_loc_count][FILAMAN_LOC_NAME_LEN - 1] = '\0';
    if (s_loc_id[s_loc_count] > 0 && s_loc_name[s_loc_count][0]) s_loc_count++;
  }
  s_loc_fetched_ms = millis();
  if (total > s_loc_count) {
    // Truncation must not be silent: a location past the cut cannot be
    // resolved and would be refused on write.
    logSDf("FilaMan: %d of %d locations cached, the rest cannot be assigned",
           s_loc_count, total);
  } else {
    logSDf("FilaMan: %d locations cached", s_loc_count);
  }
  return true;
}

// ============================================================
//  TRANSLATION: FilaMan spool  ->  Spoolman spool
//
//  Field names verified against a live FilaMan 1.2.36 instance.
//  Anything the UI does not read is left out on purpose, a smaller
//  document means less PSRAM and less parsing.
// ============================================================
static void mapSpool(JsonObjectConst src, JsonObject dst) {
  dst["id"]             = src["id"] | 0;
  dst["remaining_weight"] = src["remaining_weight_g"]      | 0.0f;
  dst["spool_weight"]     = src["empty_spool_weight_g"]    | 0.0f;
  dst["initial_weight"]   = src["initial_total_weight_g"]  | 0.0f;

  // FilaMan has no boolean, archived is status id 6.
  dst["archived"] = ((src["status_id"] | 0) == 6);

  // FilaMan maintains last_used_at itself and does not accept it in a PATCH.
  // It reflects real consumption, tracked through its printer integration.
  const char* last_used = src["last_used_at"] | (const char*)nullptr;
  if (last_used) dst["last_used"] = last_used;

  // Spoolman carries the location as a plain string, FilaMan as an id.
  // Resolved from the cache; if it is cold the field stays unset and the UI
  // guards against that already.
  const char* loc = locationNameById(src["location_id"] | 0);
  if (loc) dst["location"] = loc;

  // Spoolman keeps the tag in extra.tag, FilaMan in the native rfid_uid.
  // Spoolman stores extra values JSON encoded, so the reader strips quotes
  // with replace("\"",""). Writing the bare value is therefore safe and
  // keeps the document smaller.
  JsonObject extra = dst["extra"].to<JsonObject>();
  const char* uid = src["rfid_uid"] | "";
  if (uid[0]) {
    extra["tag"] = uid;
  } else {
    // Spools imported from Spoolman still carry the old value. Read it so
    // they are recognised before the migration writes rfid_uid.
    JsonVariantConst cf = src["custom_fields"];
    const char* legacy = cf["spoolmanscale_tag"] | (const char*)nullptr;
    if (!legacy) legacy = cf["spoolman_extra"]["tag"] | (const char*)nullptr;
    if (legacy && legacy[0]) {
      extra["tag"] = legacy;
      // Marks where the tag came from. Only these spools need migrating, and
      // without the flag a failed tag search would look the same and trigger
      // a pointless PATCH on every single scan.
      extra["tag_legacy"] = true;
    }
  }

  const char* dried = src["custom_fields"]["last_dried"] | (const char*)nullptr;
  if (dried) extra["last_dried"] = dried;

  JsonObjectConst fil = src["filament"];
  if (!fil.isNull()) {
    JsonObject f = dst["filament"].to<JsonObject>();
    f["id"]           = fil["id"] | 0;
    f["name"]         = fil["designation"]              | "";
    f["material"]     = fil["material_type"]            | "";
    f["weight"]       = fil["raw_material_weight_g"]    | 0.0f;
    f["spool_weight"] = fil["default_spool_weight_g"]   | 0.0f;
    // shop_url carries the article number in FilaMan.
    f["article_number"] = fil["shop_url"] | "";

    // FilaMan supports multi colour filaments, so colours are an array and
    // the hex code arrives with a leading '#'. Spoolman has neither.
    const char* hex = fil["colors"][0]["color"]["hex_code"] | "";
    if (hex[0] == '#') hex++;
    f["color_hex"] = hex;

    JsonObject vendor = f["vendor"].to<JsonObject>();
    vendor["id"]   = fil["manufacturer_id"] | 0;
    vendor["name"] = fil["manufacturer"]["name"] | "";
    vendor["empty_spool_weight"] = fil["manufacturer"]["empty_spool_weight_g"] | 0.0f;
  }
}

// Adds the Authorization header for the API key, which FilaMan requires for
// everything under /api/v1 apart from device endpoints.
static void addApiKey(HTTPClient& http, const char* api_key) {
  if (api_key && api_key[0]) {
    http.addHeader("Authorization", String("ApiKey ") + api_key);
  }
}

int filamanRegisterDevice(const char* base_url, const char* device_code,
                          char* out_token, size_t out_size,
                          char* out_error, size_t err_size,
                          uint32_t timeout_ms) {
  if (out_token && out_size > 0) out_token[0] = '\0';
  if (out_error && err_size > 0) out_error[0] = '\0';
  if (!hasBaseUrl(base_url) || !device_code || !device_code[0]) return -1;
  if (!out_token || out_size == 0) return -1;

  String url = String(base_url) + "/api/v1/devices/register";
  logSDf("FilaMan: registering device at %s", url.c_str());

  HTTPClient http;
  http.begin(url);
  http.setTimeout(timeout_ms);
  http.addHeader("X-Device-Code", device_code);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST("");

  if (code != 200) {
    // FilaMan answers with {"detail":{"code":"...","message":"..."}}.
    // Pass that message on, a bare status number helps nobody.
    String body = http.getString();
    http.end();
    if (out_error && err_size > 0) {
      JsonDocument edoc;
      const char* msg = nullptr;
      if (!deserializeJson(edoc, body)) msg = edoc["detail"]["message"] | (const char*)nullptr;
      strncpy(out_error, msg ? msg : body.c_str(), err_size - 1);
      out_error[err_size - 1] = '\0';
    }
    logSDf("FilaMan: device register failed, HTTP %d: %s", code, body.c_str());
    return code;
  }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, http.getString());
  http.end();
  if (err) {
    logSDf("FilaMan: device register parse error: %s", err.c_str());
    return -2;
  }

  const char* tok = doc["token"] | "";
  if (!tok[0]) {
    logSD("FilaMan: device register response had no token");
    return -2;
  }
  strncpy(out_token, tok, out_size - 1);
  out_token[out_size - 1] = '\0';
  // Length only, never the token itself.
  logSDf("FilaMan: device registered, token length %d", (int)strlen(out_token));
  return 200;
}

int filamanHeartbeat(const char* base_url, const char* device_token,
                     const char* ip_address, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || !device_token || !device_token[0]) return -1;

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/devices/heartbeat");
  http.setTimeout(timeout_ms);
  http.addHeader("Authorization", String("Device ") + device_token);
  http.addHeader("Content-Type", "application/json");

  JsonDocument body;
  body["ip_address"] = ip_address ? ip_address : "";
  String payload;
  serializeJson(body, payload);

  int code = http.POST(payload);
  http.end();
  return code;
}

int filamanRfidResult(const char* base_url, const char* device_token,
                      bool success, const char* tag_uuid, int spool_id,
                      const char* error_message, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || !device_token || !device_token[0]) return -1;

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/devices/rfid-result");
  http.setTimeout(timeout_ms);
  http.addHeader("Authorization", String("Device ") + device_token);
  http.addHeader("Content-Type", "application/json");

  JsonDocument body;
  body["success"] = success;
  if (tag_uuid && tag_uuid[0]) body["tag_uuid"] = tag_uuid;
  if (spool_id > 0)            body["spool_id"] = spool_id;
  if (error_message && error_message[0]) body["error_message"] = error_message;

  String payload;
  serializeJson(body, payload);

  int code = http.POST(payload);
  http.end();

  // Worth a line either way: this is the only signal the web UI gets, so a
  // link that looks done on the display but never reached the server has to
  // be visible in the log.
  logSDf("FilaMan: rfid-result success=%d spool=%d (HTTP %d)",
         success ? 1 : 0, spool_id, code);
  return code;
}

int filamanGetHealthCode(const char* base_url, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  HTTPClient http;
  http.begin(String(base_url) + "/health");   // no /api/v1 prefix
  http.setTimeout(timeout_ms);
  int code = http.GET();
  http.end();
  return code;
}

bool filamanGetVersion(const char* base_url, char* out_version, size_t out_size,
                       uint32_t timeout_ms) {
  if (out_version && out_size > 0) out_version[0] = '\0';
  if (!hasBaseUrl(base_url) || !out_version || out_size == 0) return false;

  HTTPClient http;
  http.begin(String(base_url) + "/openapi.json");
  http.setTimeout(timeout_ms);
  int code = http.GET();
  if (code != 200) { http.end(); return false; }

  // The document starts with
  //   {"openapi":"3.1.0","info":{"title":"FilaMan","version":"1.2.36"},...
  // A Range header is ignored by the server, so instead only the head of the
  // stream is read and the connection is then closed, which stops the rest
  // from being transferred.
  char head[256];
  size_t got = 0;
  WiFiClient* stream = http.getStreamPtr();
  uint32_t started = millis();
  while (got < sizeof(head) - 1 && (millis() - started) < timeout_ms) {
    if (!stream->available()) {
      if (!http.connected()) break;
      delay(5);
      continue;
    }
    int r = stream->read((uint8_t*)head + got, sizeof(head) - 1 - got);
    if (r <= 0) break;
    got += r;
  }
  head[got] = '\0';
  http.end();

  // First "version" key in the document belongs to info; the one before it is
  // "openapi", a different key.
  const char* p = strstr(head, "\"version\"");
  if (!p) return false;
  p = strchr(p + 9, '"');
  if (!p) return false;
  p++;
  const char* end = strchr(p, '"');
  if (!end || end <= p) return false;

  size_t n = (size_t)(end - p);
  if (n > out_size - 1) n = out_size - 1;
  memcpy(out_version, p, n);
  out_version[n] = '\0';
  return true;
}

int filamanCountActiveSpools(const char* base_url, const char* api_key,
                             uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/spools?page_size=1");
  http.setTimeout(timeout_ms);
  addApiKey(http, api_key);
  if (http.GET() != 200) { http.end(); return -1; }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, http.getStream());
  http.end();
  if (err) return -1;
  return doc["total"] | -1;
}

// How many events to look at when searching for the last measurement. The log
// is newest first, and status changes, drying and manual corrections sit
// between measurements, so a single entry is not enough.
#define FILAMAN_EVENT_SCAN  5

bool filamanGetLastMeasuredAt(const char* base_url, const char* api_key, int spool_id,
                              char* out_iso, size_t out_size, uint32_t timeout_ms) {
  if (out_iso && out_size > 0) out_iso[0] = '\0';
  if (!hasBaseUrl(base_url) || spool_id <= 0 || !out_iso || out_size == 0) return false;

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/spools/" + spool_id +
             "/events?page_size=" + FILAMAN_EVENT_SCAN);
  http.setTimeout(timeout_ms);
  addApiKey(http, api_key);
  if (http.GET() != 200) { http.end(); return false; }

  // Only the two keys that matter are parsed. Each event otherwise carries
  // colours, manufacturer and material, none of which are needed here.
  JsonDocument filter;
  JsonObject fi = filter["items"].to<JsonArray>().add<JsonObject>();
  fi["event_type"] = true;
  fi["event_at"]   = true;

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, http.getStream(),
                                             DeserializationOption::Filter(filter));
  http.end();
  if (err) {
    logSDf("FilaMan: event log parse error: %s", err.c_str());
    return false;
  }

  for (JsonObjectConst e : doc["items"].as<JsonArrayConst>()) {
    const char* type = e["event_type"] | "";
    if (strcmp(type, "measurement") != 0) continue;
    const char* at = e["event_at"] | (const char*)nullptr;
    if (!at || !at[0]) continue;
    strncpy(out_iso, at, out_size - 1);
    out_iso[out_size - 1] = '\0';
    return true;
  }
  return false;
}

// ============================================================
//  WRITING
// ============================================================

// Shared PATCH helper. Returns the HTTP status, or -1 when the request
// could not be built at all.
static int patchSpool(const char* base_url, const char* api_key, const char* path,
                      const String& body, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  HTTPClient http;
  http.begin(String(base_url) + path);
  http.setTimeout(timeout_ms);
  addApiKey(http, api_key);
  http.addHeader("Content-Type", "application/json");
  int code = http.PATCH(body);
  // Any 2xx counts. Treating only 200 as success would turn a 201 or 204 into
  // a failure for every caller.
  if (code < 200 || code >= 300) {
    String resp = http.getString();
    logSDf("FilaMan: PATCH %s -> HTTP %d: %s", path, code, resp.substring(0, 120).c_str());
  }
  http.end();
  return (code >= 200 && code < 300) ? 200 : code;
}

// Removes the tag from the places an imported spool can still carry it.
//
// Unlink used to clear rfid_uid only. The reader falls back to
// custom_fields.spoolmanscale_tag and custom_fields.spoolman_extra.tag for
// spools imported from Spoolman, so the very next scan found the spool again
// through the old value and the migration wrote it straight back into
// rfid_uid. From the outside the unlink simply did not stick.
//
// Costs a GET before the PATCH, like every custom_fields write, but unlink is
// a rare and deliberate action. Returns 200 when there was nothing to clear.
static int filamanClearLegacyTag(const char* base_url, const char* api_key, int spool_id,
                                 uint32_t timeout_ms) {
  HTTPClient get;
  get.begin(String(base_url) + "/api/v1/spools/" + spool_id);
  get.setTimeout(timeout_ms);
  addApiKey(get, api_key);
  if (get.GET() != 200) { get.end(); return 200; }   // nothing readable, nothing to clear

  SpiRamAllocator alloc;
  JsonDocument raw(&alloc);
  DeserializationError err = deserializeJson(raw, get.getStream());
  get.end();
  if (err) return 200;

  JsonObjectConst existing = raw["custom_fields"];
  if (existing.isNull()) return 200;

  const char* direct = existing["spoolmanscale_tag"] | (const char*)nullptr;
  const char* nested = existing["spoolman_extra"]["tag"] | (const char*)nullptr;
  if ((!direct || !direct[0]) && (!nested || !nested[0])) return 200;

  // A PATCH replaces the whole object, so everything is copied over and only
  // the two tag values are blanked.
  JsonDocument body(&alloc);
  JsonObject cf = body["custom_fields"].to<JsonObject>();
  for (JsonPairConst kv : existing) {
    if (strcmp(kv.key().c_str(), "spoolmanscale_tag") == 0) { cf["spoolmanscale_tag"] = ""; continue; }
    cf[kv.key()] = kv.value();
  }
  if (nested && nested[0] && cf["spoolman_extra"].is<JsonObject>()) {
    cf["spoolman_extra"]["tag"] = "";
  }

  if (body.overflowed()) {
    logSD("FilaMan: legacy tag copy overflowed, PATCH aborted to avoid data loss");
    return -2;
  }

  String payload;
  serializeJson(body, payload);
  int code = patchSpool(base_url, api_key,
                        (String("/api/v1/spools/") + spool_id).c_str(), payload, timeout_ms);
  logSDf("FilaMan: cleared legacy tag of spool %d, HTTP %d", spool_id, code);
  return code;
}

int filamanPatchRfidUid(const char* base_url, const char* api_key, int spool_id,
                        const char* uuid, uint32_t timeout_ms) {
  if (spool_id <= 0) return -1;
  JsonDocument body;
  if (uuid && uuid[0]) {
    body["rfid_uid"] = uuid;
  } else {
    // Unlink. An empty string is not the same as no value here: FilaMan
    // answers {"rfid_uid": ""} with HTTP 500 and keeps the old tag, while
    // null clears it. Verified against a live 1.2.36 instance.
    body["rfid_uid"] = nullptr;
  }
  String payload;
  serializeJson(body, payload);
  int code = patchSpool(base_url, api_key, (String("/api/v1/spools/") + spool_id).c_str(),
                        payload, timeout_ms);

  // On unlink the old value in custom_fields has to go as well, otherwise the
  // next scan finds the spool through it and the migration links it again.
  if (code == 200 && !(uuid && uuid[0])) {
    filamanClearLegacyTag(base_url, api_key, spool_id, timeout_ms);
  }
  return code;
}

int filamanPatchCustomField(const char* base_url, const char* api_key, int spool_id,
                            const char* key, const char* value, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0 || !key || !key[0]) return -1;

  // A PATCH on custom_fields replaces the whole object instead of merging,
  // so everything already there has to be read and sent back along with the
  // new value. Verified on a live instance: without this, last_dried and the
  // Spoolman import data would be wiped on the first write.
  HTTPClient get;
  get.begin(String(base_url) + "/api/v1/spools/" + spool_id);
  get.setTimeout(timeout_ms);
  addApiKey(get, api_key);
  int gcode = get.GET();
  if (gcode != 200) {
    get.end();
    logSDf("FilaMan: custom field GET failed, HTTP %d", gcode);
    return gcode;
  }

  SpiRamAllocator alloc;
  JsonDocument raw(&alloc);
  DeserializationError err = deserializeJson(raw, get.getStream());
  get.end();
  if (err) {
    logSDf("FilaMan: custom field GET parse error: %s", err.c_str());
    return -2;
  }

  // Same PSRAM allocator as the source document. With the default allocator
  // a large custom_fields object could fail to fit in internal RAM, and
  // ArduinoJson would then drop members silently, which is precisely the data
  // loss this read-modify-write exists to prevent.
  JsonDocument body(&alloc);
  JsonObject cf = body["custom_fields"].to<JsonObject>();
  JsonObjectConst existing = raw["custom_fields"];
  if (!existing.isNull()) {
    for (JsonPairConst kv : existing) {
      if (strcmp(kv.key().c_str(), key) == 0) continue;   // replaced below
      cf[kv.key()] = kv.value();
    }
  } else if (!raw["custom_fields"].isNull()) {
    logSD("FilaMan: custom_fields is not an object, existing values may be lost");
  }
  cf[key] = value ? value : "";

  if (body.overflowed()) {
    logSD("FilaMan: custom_fields copy overflowed, PATCH aborted to avoid data loss");
    return -2;
  }

  String payload;
  serializeJson(body, payload);
  return patchSpool(base_url, api_key, (String("/api/v1/spools/") + spool_id).c_str(),
                    payload, timeout_ms);
}

int filamanReportWeight(const char* base_url, const char* device_token,
                        int spool_id, const char* tag_uuid, float measured_g,
                        uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;
  if (!device_token || !device_token[0]) {
    // Distinct from -1 so the caller can tell "not set up" from "call failed".
    logSD("FilaMan: no device token, weight not reported");
    return FILAMAN_NO_DEVICE_TOKEN;
  }
  if (spool_id <= 0 && (!tag_uuid || !tag_uuid[0])) return -1;

  JsonDocument body;
  if (spool_id > 0)                 body["spool_id"] = spool_id;
  else                              body["tag_uuid"] = tag_uuid;
  body["measured_weight_g"] = roundGrams(measured_g);
  String payload;
  serializeJson(body, payload);

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/devices/scale/weight");
  http.setTimeout(timeout_ms);
  http.addHeader("Authorization", String("Device ") + device_token);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(payload);
  if (code < 200 || code >= 300) {
    String resp = http.getString();
    logSDf("FilaMan: weight report -> HTTP %d: %s", code, resp.substring(0, 120).c_str());
  }
  http.end();
  return (code >= 200 && code < 300) ? 200 : code;
}

int filamanSetStatus(const char* base_url, const char* api_key, int spool_id,
                     const char* status_key, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0 || !status_key) return -1;

  JsonDocument body;
  body["status"] = status_key;
  String payload;
  serializeJson(body, payload);

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/spools/" + spool_id + "/status");
  http.setTimeout(timeout_ms);
  addApiKey(http, api_key);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(payload);
  if (code < 200 || code >= 300) {
    String resp = http.getString();
    logSDf("FilaMan: status change -> HTTP %d: %s", code, resp.substring(0, 120).c_str());
  }
  http.end();
  return (code >= 200 && code < 300) ? 200 : code;
}

int filamanPatchSpoolFloat(const char* base_url, const char* api_key, int spool_id,
                           const char* field, float value, uint32_t timeout_ms) {
  if (spool_id <= 0 || !field) return -1;
  JsonDocument body;
  body[field] = roundGrams(value);
  String payload;
  serializeJson(body, payload);
  return patchSpool(base_url, api_key, (String("/api/v1/spools/") + spool_id).c_str(),
                    payload, timeout_ms);
}

int filamanPatchFilamentFloat(const char* base_url, const char* api_key, int filament_id,
                              const char* field, float value, uint32_t timeout_ms) {
  if (filament_id <= 0 || !field) return -1;
  JsonDocument body;
  body[field] = roundGrams(value);
  String payload;
  serializeJson(body, payload);
  return patchSpool(base_url, api_key, (String("/api/v1/filaments/") + filament_id).c_str(),
                    payload, timeout_ms);
}

int filamanPatchManufacturerFloat(const char* base_url, const char* api_key, int manufacturer_id,
                                  const char* field, float value, uint32_t timeout_ms) {
  if (manufacturer_id <= 0 || !field) return -1;
  JsonDocument body;
  body[field] = roundGrams(value);
  String payload;
  serializeJson(body, payload);
  return patchSpool(base_url, api_key,
                    (String("/api/v1/manufacturers/") + manufacturer_id).c_str(),
                    payload, timeout_ms);
}

int filamanCreateSpool(const char* base_url, const char* api_key, int filament_id,
                       float initial_weight, float spool_weight, float remaining_weight,
                       const char* rfid_uid, int* out_spool_id, uint32_t timeout_ms) {
  if (out_spool_id) *out_spool_id = 0;
  if (!hasBaseUrl(base_url) || filament_id <= 0) return -1;

  JsonDocument body;
  body["filament_id"]            = filament_id;
  body["initial_total_weight_g"] = roundGrams(initial_weight);
  body["empty_spool_weight_g"]   = roundGrams(spool_weight);
  body["remaining_weight_g"]     = roundGrams(remaining_weight);
  // 2 = opened. A spool that lands on the scale has been unwrapped, and
  // FilaMan would otherwise leave it at its own default.
  body["status_id"] = 2;
  // Creating and linking in one request saves a round trip and avoids a spool
  // existing untagged if the follow-up PATCH were to fail.
  if (rfid_uid && rfid_uid[0]) body["rfid_uid"] = rfid_uid;

  String payload;
  serializeJson(body, payload);

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/spools");
  http.setTimeout(timeout_ms);
  addApiKey(http, api_key);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(payload);

  if (code >= 200 && code < 300) {
    JsonDocument doc;
    if (!deserializeJson(doc, http.getString()) && out_spool_id) {
      *out_spool_id = doc["id"] | 0;
    }
    http.end();
    logSDf("FilaMan: spool created, id=%d", out_spool_id ? *out_spool_id : 0);
    return 200;
  }

  String resp = http.getString();
  http.end();
  logSDf("FilaMan: create spool -> HTTP %d: %s", code, resp.substring(0, 120).c_str());
  return code;
}

int filamanGetLocationsJson(const char* base_url, const char* api_key,
                            JsonDocument& out_doc, uint32_t timeout_ms,
                            DeserializationError* out_err) {
  (void)timeout_ms;
  if (out_err) *out_err = DeserializationError::Ok;
  if (!hasBaseUrl(base_url)) return -1;

  // Always fresh here: the picker is exactly where a location just added in
  // the browser should show up.
  if (!fetchLocations(base_url, api_key, true)) return -2;

  // Spoolman answers with a plain array of names, so that is what the picker
  // gets. The ids stay in the cache for the write direction.
  out_doc.clear();
  JsonArray arr = out_doc.to<JsonArray>();
  for (int i = 0; i < s_loc_count; i++) arr.add(s_loc_name[i]);
  return 200;
}

int filamanPatchSpoolLocation(const char* base_url, const char* api_key, int spool_id,
                              const char* location_name, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;

  JsonDocument body;
  if (!location_name || !location_name[0]) {
    body["location_id"] = nullptr;      // clear, same reasoning as rfid_uid
  } else {
    int id = locationIdByName(location_name);
    if (id <= 0) {
      // Cache cold or the location was created after the last fetch.
      fetchLocations(base_url, api_key, true);
      id = locationIdByName(location_name);
    }
    if (id <= 0) {
      logSDf("FilaMan: unknown location '%s', not written", location_name);
      return -1;
    }
    body["location_id"] = id;
  }

  String payload;
  serializeJson(body, payload);
  return patchSpool(base_url, api_key, (String("/api/v1/spools/") + spool_id).c_str(),
                    payload, timeout_ms);
}

// ============================================================
//  READING
// ============================================================

int filamanGetSpoolJson(const char* base_url, const char* api_key, int spool_id,
                        JsonDocument& out_doc, uint32_t timeout_ms,
                        DeserializationError* out_err) {
  if (out_err) *out_err = DeserializationError::Ok;
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/spools/" + spool_id);
  http.setTimeout(timeout_ms);
  addApiKey(http, api_key);
  int code = http.GET();
  if (code != 200) { http.end(); return code; }

  SpiRamAllocator alloc;
  JsonDocument raw(&alloc);
  DeserializationError err = deserializeJson(raw, http.getStream());
  http.end();
  if (err) {
    if (out_err) *out_err = err;
    logSDf("FilaMan: spool %d parse error: %s", spool_id, err.c_str());
    return -2;
  }

  // Warms the location cache so mapSpool can turn location_id into a name.
  // Cheap: at most one extra request every five minutes.
  fetchLocations(base_url, api_key, false);

  out_doc.clear();
  mapSpool(raw.as<JsonObjectConst>(), out_doc.to<JsonObject>());
  return 200;
}

int filamanGetSpoolListJson(const char* base_url, const char* api_key,
                            bool include_archived, JsonDocument& out_doc,
                            const char* search_term, int page_size,
                            uint32_t timeout_ms, DeserializationError* out_err) {
  if (out_err) *out_err = DeserializationError::Ok;
  if (!hasBaseUrl(base_url)) return -1;

  // FilaMan rejects page_size above 200 with a validation error, so an
  // inventory larger than that has to be fetched page by page. Spoolman
  // returns everything in one go, which is why nothing upstream expects
  // paging.
  if (page_size <= 0 || page_size > FILAMAN_PAGE_MAX) page_size = FILAMAN_PAGE_MAX;

  out_doc.clear();
  JsonArray dst = out_doc.to<JsonArray>();

  // Warms the location cache so mapSpool can turn location_id into a name.
  fetchLocations(base_url, api_key, false);

  int page = 1;
  int fetched = 0;
  int total = -1;

  // timeout_ms applies to the whole call, not to each page. Without this a
  // 20 second timeout over 20 pages could block the loop for minutes with
  // LVGL never being serviced.
  const uint32_t started_ms = millis();

  while (true) {
    String url = String(base_url) + "/api/v1/spools?page=" + page
               + "&page_size=" + page_size;
    if (include_archived) url += "&include_archived=true";
    if (search_term && search_term[0]) {
      url += "&search=";
      url += search_term;
    }

    uint32_t elapsed = millis() - started_ms;
    if (elapsed >= timeout_ms) {
      logSDf("FilaMan: spool list timed out after %d of %d spools", fetched, total);
      break;   // keep what was fetched, the caller sees a shorter list
    }

    HTTPClient http;
    http.begin(url);
    http.setTimeout(timeout_ms - elapsed);
    addApiKey(http, api_key);
    int code = http.GET();
    if (code != 200) { http.end(); out_doc.clear(); return code; }

    SpiRamAllocator alloc;
    JsonDocument raw(&alloc);
    DeserializationError err = deserializeJson(raw, http.getStream());
    http.end();
    if (err) {
      if (out_err) *out_err = err;
      logSDf("FilaMan: spool list page %d parse error: %s", page, err.c_str());
      out_doc.clear();
      return -2;
    }

    // FilaMan wraps lists in {items, page, page_size, total}, Spoolman
    // returns a bare array. Unwrap so callers see what they expect.
    JsonArrayConst items = raw["items"].isNull() ? raw.as<JsonArrayConst>()
                                                 : raw["items"].as<JsonArrayConst>();
    if (total < 0) total = raw["total"] | (int)items.size();

    for (JsonVariantConst v : items) {
      mapSpool(v.as<JsonObjectConst>(), dst.add<JsonObject>());
    }
    fetched += (int)items.size();

    // A search is expected to be small, one page is enough.
    if (search_term && search_term[0]) break;
    if (items.size() == 0) break;
    if (total >= 0 && fetched >= total) break;
    if (page >= FILAMAN_MAX_PAGES) {
      logSDf("FilaMan: stopped after %d pages, %d of %d spools fetched",
             page, fetched, total);
      break;
    }
    page++;
  }

  if (page > 1) logSDf("FilaMan: fetched %d spools over %d pages", fetched, page);
  return 200;
}
