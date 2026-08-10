#include "filaman_api.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <string.h>

#include "hardware/sd_logger.h"

static bool hasBaseUrl(const char* base_url) {
  return base_url && strlen(base_url) > 7;   // longer than "http://"
}

int filamanRegisterDevice(const char* base_url, const char* device_code,
                          char* out_token, size_t out_size,
                          uint32_t timeout_ms) {
  if (out_token && out_size > 0) out_token[0] = '\0';
  if (!hasBaseUrl(base_url) || !device_code || !device_code[0]) return -1;
  if (!out_token || out_size == 0) return -1;

  HTTPClient http;
  http.begin(String(base_url) + "/api/v1/devices/register");
  http.setTimeout(timeout_ms);
  http.addHeader("X-Device-Code", device_code);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST("");

  if (code != 200) {
    http.end();
    logSDf("FilaMan: device register failed, HTTP %d", code);
    return code;
  }

  StaticJsonDocument<256> doc;
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

  StaticJsonDocument<128> body;
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
