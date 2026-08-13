#include "filaman_api.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
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

static bool hasBaseUrl(const char* base_url) {
  return base_url && strlen(base_url) > 7;   // longer than "http://"
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

  const char* last_used = src["last_used_at"] | (const char*)nullptr;
  if (last_used) dst["last_used"] = last_used;

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
    if (legacy && legacy[0]) extra["tag"] = legacy;
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

int filamanGetHealthCode(const char* base_url, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  HTTPClient http;
  http.begin(String(base_url) + "/health");   // no /api/v1 prefix
  http.setTimeout(timeout_ms);
  int code = http.GET();
  http.end();
  return code;
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

  String url = String(base_url) + "/api/v1/spools?page_size=" + page_size;
  if (include_archived) url += "&include_archived=true";
  if (search_term && search_term[0]) {
    url += "&search=";
    url += search_term;
  }

  HTTPClient http;
  http.begin(url);
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
    logSDf("FilaMan: spool list parse error: %s", err.c_str());
    return -2;
  }

  // FilaMan wraps lists in {items, page, page_size, total}, Spoolman returns
  // a bare array. Unwrap here so callers see what they expect.
  JsonArrayConst items = raw["items"].isNull() ? raw.as<JsonArrayConst>()
                                               : raw["items"].as<JsonArrayConst>();
  int total = raw["total"] | (int)items.size();
  if (total > page_size) {
    logSDf("FilaMan: %d spools total, only %d fetched - raise the page size",
           total, page_size);
  }

  out_doc.clear();
  JsonArray dst = out_doc.to<JsonArray>();
  for (JsonVariantConst v : items) {
    mapSpool(v.as<JsonObjectConst>(), dst.add<JsonObject>());
  }
  return 200;
}
