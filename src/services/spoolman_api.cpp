#include "spoolman_api.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <WiFiClient.h>
#include <string.h>

static bool hasBaseUrl(const char* base_url) {
  return base_url && strlen(base_url) > 4;
}

static int patchJson(const String& url, const String& body, uint32_t timeout_ms) {
  HTTPClient http;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(timeout_ms);
  int code = http.PATCH(body);
  http.end();
  return code;
}

static int postJson(const String& url, const String& body, uint32_t timeout_ms) {
  HTTPClient http;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(timeout_ms);
  int code = http.POST(body);
  http.end();
  return code;
}

static int getJson(const String& url, JsonDocument& doc, uint32_t timeout_ms,
                   JsonDocument* filter, DeserializationError* out_err) {
  if (out_err) *out_err = DeserializationError::Ok;

  HTTPClient http;
  http.begin(url);
  http.setTimeout(timeout_ms);
  int code = http.GET();
  if (code != 200) {
    http.end();
    return code;
  }

  DeserializationError err = filter
    ? deserializeJson(doc, *http.getStreamPtr(), DeserializationOption::Filter(*filter))
    : deserializeJson(doc, *http.getStreamPtr());
  http.end();
  if (out_err) *out_err = err;
  return err ? -2 : 200;
}

int spoolmanGetJson(const char* base_url, const char* path, JsonDocument& doc,
                    uint32_t timeout_ms, JsonDocument* filter, DeserializationError* out_err) {
  if (!hasBaseUrl(base_url) || !path) {
    if (out_err) *out_err = DeserializationError::InvalidInput;
    return -1;
  }
  return getJson(String(base_url) + path, doc, timeout_ms, filter, out_err);
}

int spoolmanGetSpoolJson(const char* base_url, int spool_id, JsonDocument& doc,
                         uint32_t timeout_ms, DeserializationError* out_err) {
  if (spool_id <= 0) {
    if (out_err) *out_err = DeserializationError::InvalidInput;
    return -1;
  }
  return getJson(String(base_url) + "/api/v1/spool/" + spool_id, doc, timeout_ms, nullptr, out_err);
}

int spoolmanGetSpoolListJson(const char* base_url, bool allow_archived, JsonDocument& doc,
                             uint32_t timeout_ms, JsonDocument* filter, DeserializationError* out_err) {
  return spoolmanGetJson(base_url,
    allow_archived ? "/api/v1/spool?allow_archived=true" : "/api/v1/spool?allow_archived=false",
    doc, timeout_ms, filter, out_err);
}

int spoolmanGetLocationsJson(const char* base_url, JsonDocument& doc,
                             uint32_t timeout_ms, DeserializationError* out_err) {
  return spoolmanGetJson(base_url, "/api/v1/location", doc, timeout_ms, nullptr, out_err);
}

int spoolmanGetSpoolFieldsJson(const char* base_url, JsonDocument& doc,
                               uint32_t timeout_ms, DeserializationError* out_err) {
  return spoolmanGetJson(base_url, "/api/v1/field/spool", doc, timeout_ms, nullptr, out_err);
}

int spoolmanGetHealthCode(const char* base_url, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/health");
  http.setTimeout(timeout_ms);
  int code = http.GET();
  http.end();
  return code;
}

bool spoolmanIsReachable(const char* base_url, uint32_t timeout_ms) {
  return spoolmanGetHealthCode(base_url, timeout_ms) == 200;
}

bool spoolmanGetVersion(const char* base_url, char* out_version, size_t out_size, uint32_t timeout_ms) {
  if (out_version && out_size > 0) out_version[0] = '\0';
  if (!hasBaseUrl(base_url) || !out_version || out_size == 0) return false;

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/info");
  http.setTimeout(timeout_ms);
  int code = http.GET();
  if (code != 200) {
    http.end();
    return false;
  }

  StaticJsonDocument<256> doc;
  DeserializationError err = deserializeJson(doc, http.getString());
  http.end();
  if (err) return false;

  strncpy(out_version, doc["version"] | "?", out_size - 1);
  out_version[out_size - 1] = '\0';
  return true;
}

int spoolmanCountActiveSpools(const char* base_url, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;

  // Spoolman reports the total in a header, so asking for a single spool is
  // enough: about 1 kB instead of the whole inventory, which is 176 kB with
  // 268 spools.
  //
  // This used to count occurrences of "filament" while streaming the full
  // list, and the read loop ended as soon as available() returned 0 for a
  // moment. That happens at every TCP packet boundary, so it counted the
  // first packet and stopped, which is why a large library reported a
  // handful of spools.
  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/spool?allow_archived=false&limit=1");
  http.setTimeout(timeout_ms);
  const char* collect[] = { "x-total-count" };
  http.collectHeaders(collect, 1);
  if (http.GET() != 200) {
    http.end();
    return -1;
  }

  String total = http.header("x-total-count");
  http.end();
  if (total.length() == 0) return -1;   // older Spoolman without the header
  return total.toInt();
}

int spoolmanCreateSpool(const char* base_url, int filament_id, float initial_weight,
                        float spool_weight, float remaining_weight, int* out_spool_id, uint32_t timeout_ms) {
  if (out_spool_id) *out_spool_id = 0;
  if (!hasBaseUrl(base_url) || filament_id <= 0) return -1;

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/spool");
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(timeout_ms);

  char body[256];
  snprintf(body, sizeof(body),
    "{\"filament_id\":%d,\"initial_weight\":%.1f,\"spool_weight\":%.1f,\"remaining_weight\":%.1f}",
    filament_id, initial_weight, spool_weight, remaining_weight);
  int code = http.POST(body);
  if ((code == 200 || code == 201) && out_spool_id) {
    StaticJsonDocument<256> doc;
    if (!deserializeJson(doc, http.getString())) {
      *out_spool_id = doc["id"] | 0;
    }
  }
  http.end();
  return code;
}

int spoolmanCreateSpoolField(const char* base_url, const char* field_name, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || !field_name || !field_name[0]) return -1;
  String body = "{\"name\":\"";
  body += field_name;
  body += "\",\"field_type\":\"text\",\"default_value\":\"\\\"\\\"\"}";
  return postJson(String(base_url) + "/api/v1/field/spool/" + field_name, body, timeout_ms);
}

int spoolmanPatchSpoolTag(const char* base_url, int spool_id, const char* uuid, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0 || !uuid) return -1;
  String body = "{\"extra\": {\"tag\": \"\\\"" + String(uuid) + "\\\"\"}}";
  return patchJson(String(base_url) + "/api/v1/spool/" + spool_id, body, timeout_ms);
}

int spoolmanPatchSpoolRemaining(const char* base_url, int spool_id, float remaining, const char* last_used_iso, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;
  char body[128];
  if (last_used_iso && last_used_iso[0]) {
    snprintf(body, sizeof(body), "{\"remaining_weight\": %.1f, \"last_used\": \"%s\"}", remaining, last_used_iso);
  } else {
    snprintf(body, sizeof(body), "{\"remaining_weight\": %.1f}", remaining);
  }
  return patchJson(String(base_url) + "/api/v1/spool/" + spool_id, String(body), timeout_ms);
}

int spoolmanPatchInitialWeight(const char* base_url, int spool_id, float initial_weight, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;
  char body[80];
  snprintf(body, sizeof(body), "{\"initial_weight\": %.1f, \"remaining_weight\": %.1f}",
    initial_weight, initial_weight);
  return patchJson(String(base_url) + "/api/v1/spool/" + spool_id, String(body), timeout_ms);
}

int spoolmanPatchArchiveSpool(const char* base_url, int spool_id, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;
  return patchJson(String(base_url) + "/api/v1/spool/" + spool_id,
    "{\"remaining_weight\": 0.0, \"archived\": true}", timeout_ms);
}

int spoolmanPatchSpoolWeight(const char* base_url, int spool_id, float spool_weight, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;
  char body[64];
  snprintf(body, sizeof(body), "{\"spool_weight\": %.1f}", spool_weight);
  return patchJson(String(base_url) + "/api/v1/spool/" + spool_id, String(body), timeout_ms);
}

int spoolmanPatchFilamentSpoolWeight(const char* base_url, int filament_id, float spool_weight, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || filament_id <= 0) return -1;
  char body[64];
  snprintf(body, sizeof(body), "{\"spool_weight\": %.1f}", spool_weight);
  return patchJson(String(base_url) + "/api/v1/filament/" + filament_id, String(body), timeout_ms);
}

int spoolmanPatchVendorEmptySpoolWeight(const char* base_url, int vendor_id, float spool_weight, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || vendor_id <= 0) return -1;
  char body[64];
  snprintf(body, sizeof(body), "{\"empty_spool_weight\": %.1f}", spool_weight);
  return patchJson(String(base_url) + "/api/v1/vendor/" + vendor_id, String(body), timeout_ms);
}

int spoolmanPatchSpoolLocation(const char* base_url, int spool_id, const char* location_name, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;
  if (!location_name || !location_name[0]) {
    return patchJson(String(base_url) + "/api/v1/spool/" + spool_id, "{\"location\":null}", timeout_ms);
  }
  String body = "{\"location\":\"";
  body += location_name;
  body += "\"}";
  return patchJson(String(base_url) + "/api/v1/spool/" + spool_id, body, timeout_ms);
}

int spoolmanPatchSpoolLastDried(const char* base_url, int spool_id, const char* iso_datetime, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0 || !iso_datetime || !iso_datetime[0]) return -1;
  String body = "{\"extra\": {\"last_dried\": \"\\\"";
  body += iso_datetime;
  body += "\\\"\"}}";
  return patchJson(String(base_url) + "/api/v1/spool/" + spool_id, body, timeout_ms);
}
