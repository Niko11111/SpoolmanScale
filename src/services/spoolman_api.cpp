#include "spoolman_api.h"
#include "http_progress.h"
#include "tag_uid.h"

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

static int putJson(const String& url, const String& body, uint32_t timeout_ms) {
  HTTPClient http;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(timeout_ms);
  int code = http.PUT(body);
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

// POST that keeps the answer. The tag endpoints reply with something worth
// reading on both the success and the failure path - the scan carries the
// whole matched spool, and a link conflict carries the id of the spool that
// already holds the tag - so throwing the body away the way postJson() does
// would mean a second request to learn what the first one already said.
static int postJsonDoc(const String& url, const String& body, JsonDocument& doc,
                       uint32_t timeout_ms, DeserializationError* out_err) {
  if (out_err) *out_err = DeserializationError::Ok;

  HTTPClient http;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(timeout_ms);
  int code = http.POST(body);
  if (code <= 0) { http.end(); return code; }

  DeserializationError err = deserializeJson(doc, *http.getStreamPtr());
  http.end();
  if (out_err) *out_err = err;
  // The status is what the caller acts on. A body that will not parse is worth
  // knowing about through out_err, but it does not turn a 201 into a failure.
  return code;
}

static int deleteReq(const String& url, uint32_t timeout_ms) {
  HTTPClient http;
  http.begin(url);
  http.setTimeout(timeout_ms);
  int code = http.sendRequest("DELETE");
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

  // Wrapped only while somebody is listening, so every other request in the
  // firmware reads exactly the stream it always did.
  DeserializationError err = DeserializationError::Ok;
  if (httpProgressActive()) {
    HttpProgressStream ps(*http.getStreamPtr());
    err = filter ? deserializeJson(doc, ps, DeserializationOption::Filter(*filter))
                 : deserializeJson(doc, ps);
  } else {
    err = filter
      ? deserializeJson(doc, *http.getStreamPtr(), DeserializationOption::Filter(*filter))
      : deserializeJson(doc, *http.getStreamPtr());
  }
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

// Percent-encodes everything outside [A-Za-z0-9]. Tag UIDs are hex in
// practice, but the value ends up in a URL and a stray character there would
// break the query rather than just miss.
static String urlEncode(const char* s) {
  String out;
  for (const char* p = s; *p; p++) {
    unsigned char c = (unsigned char)*p;
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
      out += (char)c;
    } else {
      char buf[4];
      snprintf(buf, sizeof(buf), "%%%02X", c);
      out += buf;
    }
  }
  return out;
}

int spoolmanFindSpoolByExtraField(const char* base_url, const char* key, const char* value,
                                  JsonDocument& doc, uint32_t timeout_ms,
                                  JsonDocument* filter, DeserializationError* out_err) {
  if (!key || !key[0] || !value || !value[0]) return -1;

  // Spoolman filters on extra fields server side, in SQL. The parameter is
  // not listed in openapi.json because extra fields are user defined and
  // cannot appear in a generated schema, but spool.find() takes
  // extra_field_filters and has since at least v0.26.1.
  //
  // Three properties of this filter matter here, all verified against a live
  // instance:
  //   - it is a partial, case insensitive match, so the caller must still
  //     compare the returned tag exactly. Never trust the first hit.
  //   - an empty value means "spools with no tag" and would return most of
  //     the inventory, hence the guard above.
  //   - an unknown parameter is ignored, so an older Spoolman simply answers
  //     with the full list and the caller's scan finds the spool anyway.
  //     That is the whole fallback: no version check, no second code path.
  //     The same happens for a field the server does not have, which is why
  //     callers ask backendHasExtraField() before spending a request here -
  //     otherwise the fast path silently becomes the slow one.
  //
  // The key is a parameter because Spoolman parses extra.<name> generically
  // (_parse_extra_field_filters), so every existing extra field is filterable
  // the same way. `value` arrives already formatted for its field: plain hex
  // where the field stores plain hex, verbatim where it does not. Formatting
  // it here would need the spec, and this layer deliberately knows nothing
  // about which field means what.
  String path = String("/api/v1/spool?allow_archived=false&extra.") + key
              + "=" + urlEncode(value);
  return spoolmanGetJson(base_url, path.c_str(), doc, timeout_ms, filter, out_err);
}

// ============================================================
//  NATIVE TAGS
//
//  Spoolman grew a tag relation of its own on master, after
//  every project around it had already settled on a different
//  extra field. Not in v0.26.1, so everything here is reached
//  only once spoolmanHasTagApi() has said the server knows it.
// ============================================================

int spoolmanHasTagApi(const char* base_url, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url)) return -1;
  // The reader registry is the cheapest thing to ask for: it takes no
  // parameters, changes nothing, and answers an empty list on a server that
  // has the feature and 404 on one that does not. Asking /api/v1/info instead
  // would only give a version number, and comparing against a release that has
  // not been cut yet is guesswork.
  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/tag/reader");
  http.setTimeout(timeout_ms);
  int code = http.GET();
  http.end();
  return code;
}

int spoolmanTagScan(const char* base_url, const char* uid, const char* reader_id,
                    const char* reader_name, const char* format, JsonDocument& doc,
                    uint32_t timeout_ms, DeserializationError* out_err) {
  if (!hasBaseUrl(base_url) || !uid || !uid[0]) return -1;

  // The UID goes out as the scale holds it. Spoolman normalises it on the way
  // in and echoes the canonical form back, and its own examples show both the
  // colon form and plain hex, so there is nothing to convert here.
  String body = String("{\"uid\":\"") + uid + "\"";
  if (reader_id   && reader_id[0])   body += String(",\"reader_id\":\"")  + reader_id + "\"";
  if (reader_name && reader_name[0]) body += String(",\"name\":\"")       + reader_name + "\"";
  if (format      && format[0])      body += String(",\"format\":\"")     + format + "\"";
  body += "}";

  return postJsonDoc(String(base_url) + "/api/v1/tag/scan", body, doc, timeout_ms, out_err);
}

int spoolmanLinkTag(const char* base_url, int spool_id, const char* uid,
                    const char* format, int* out_conflict_spool_id,
                    uint32_t timeout_ms) {
  if (out_conflict_spool_id) *out_conflict_spool_id = 0;
  if (!hasBaseUrl(base_url) || spool_id <= 0 || !uid || !uid[0]) return -1;

  String body = String("{\"uid\":\"") + uid + "\"";
  if (format && format[0]) body += String(",\"format\":\"") + format + "\"";
  body += "}";

  // 409 is not a failure to report as one: the body names the spool that holds
  // the tag, which is the one thing a caller needs in order to offer moving it
  // rather than sending the user off to find it.
  JsonDocument doc;
  int code = postJsonDoc(String(base_url) + "/api/v1/spool/" + spool_id + "/tag",
                         body, doc, timeout_ms, nullptr);
  if (code == 409 && out_conflict_spool_id)
    *out_conflict_spool_id = doc["spool_id"] | 0;
  return code;
}

int spoolmanUnlinkTag(const char* base_url, int spool_id, const char* uid,
                      uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0 || !uid || !uid[0]) return -1;
  // Matched the same way it is stored, so the colon form goes through as is.
  return deleteReq(String(base_url) + "/api/v1/spool/" + spool_id + "/tag/" + urlEncode(uid),
                   timeout_ms);
}

int spoolmanFindSpoolByNativeTag(const char* base_url, const char* uid,
                                 JsonDocument& doc, uint32_t timeout_ms,
                                 JsonDocument* filter, DeserializationError* out_err) {
  if (!hasBaseUrl(base_url) || !uid || !uid[0]) return -1;
  // Normalised server side, so the colon notation goes through unchanged.
  String path = String("/api/v1/spool?allow_archived=false&tag=") + urlEncode(uid);
  return spoolmanGetJson(base_url, path.c_str(), doc, timeout_ms, filter, out_err);
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

int spoolmanPatchExtraField(const char* base_url, int spool_id, const char* key,
                            const char* value, uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0 || !key || !key[0] || !value) return -1;
  // The JSON-inside-JSON encoding every text extra field uses: Spoolman stores
  // them as JSON text, so the value carries its own pair of quotes inside the
  // string. Spoolman merges per key, which is what lets the tag field and
  // last_dried survive each other.
  //
  // Built with String concatenation rather than by pasting the key in at
  // compile time. The old pair of functions did the latter, which only works
  // while the key is a macro - and the whole point here is that it is not.
  String body = String("{\"extra\": {\"") + key + "\": \"\\\"" + value + "\\\"\"}}";
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

int spoolmanReactivateSpool(const char* base_url, int spool_id, float remaining,
                            uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;
  // Both fields in one PATCH. Archiving set remaining_weight to 0, so bringing
  // the spool back without a weight would leave it looking empty, and a second
  // request could fail on its own and leave exactly that state behind.
  char body[80];
  snprintf(body, sizeof(body), "{\"archived\": false, \"remaining_weight\": %.1f}", remaining);
  return patchJson(String(base_url) + "/api/v1/spool/" + spool_id, String(body), timeout_ms);
}

int spoolmanMeasureSpool(const char* base_url, int spool_id, float gross_weight,
                         uint32_t timeout_ms) {
  if (!hasBaseUrl(base_url) || spool_id <= 0) return -1;
  if (gross_weight < 0.0f) return -1;
  char body[48];
  snprintf(body, sizeof(body), "{\"weight\": %.1f}", gross_weight);
  return putJson(String(base_url) + "/api/v1/spool/" + spool_id + "/measure",
                 String(body), timeout_ms);
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
