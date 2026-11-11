#include "services/ams_source.h"
#include "services/backend_http.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <string.h>
#include <strings.h>

#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/bambu_status.h"
#include "services/prefs_store.h"

// NVS keys, at most 15 characters.
#define NVS_AMS_SRC_HOST  "ams_src_host"
#define NVS_AMS_SRC_KEY   "ams_src_key"

#define AMS_SOURCE_PREFIX  "/api/v1/ams-source"

static char s_host[AMS_SOURCE_HOST_MAX] = "";
static char s_base[AMS_SOURCE_HOST_MAX + 8] = "";   // room for "http://"
static char s_key[AMS_SOURCE_KEY_MAX] = "";

// The source's answer about itself. Reset with the address, filled by the
// first printer list that reaches it.
struct AmsSourceInfo {
  char name[AMS_SOURCE_NAME_MAX];
  char version[AMS_SOURCE_VER_MAX];
  int  contract;          // the contract version it speaks
  bool known;
  bool can_assign;
  bool can_unassign;
};
static AmsSourceInfo s_info = {};

// A key goes into a header as it is, so a CR or LF would start a header line
// of its own. Same rule the backend keys follow.
static bool copyClean(char* dst, size_t n, const char* src) {
  size_t j = 0;
  for (size_t i = 0; src && src[i]; i++) {
    const unsigned char c = (unsigned char)src[i];
    if (c <= 0x20 || c == 0x7f) continue;
    if (j + 1 >= n) { dst[0] = '\0'; return false; }
    dst[j++] = (char)c;
  }
  dst[j] = '\0';
  return true;
}

static void rebuildBase() {
  backendComposeBase(s_base, sizeof(s_base), s_host);
  // A trailing slash would double the one every path starts with.
  size_t len = strlen(s_base);
  while (len > 0 && s_base[len - 1] == '/') s_base[--len] = '\0';
}

void amsSourceLoadSettings() {
  String host = prefsGetString(NVS_AMS_SRC_HOST, "");
  String key  = prefsGetString(NVS_AMS_SRC_KEY, "");
  if (!copyClean(s_host, sizeof(s_host), host.c_str())) s_host[0] = '\0';
  if (!copyClean(s_key, sizeof(s_key), key.c_str()))    s_key[0] = '\0';
  rebuildBase();
}

const char* amsSourceHost()   { return s_host; }
bool        amsSourceHasKey() { return s_key[0] != '\0'; }

bool amsSourceConfigured() {
  return strlen(s_base) > 7;   // longer than "http://"
}

bool amsSourceSet(const char* host, const char* key) {
  char new_host[sizeof(s_host)];
  char new_key[sizeof(s_key)];
  if (!copyClean(new_host, sizeof(new_host), host)) return false;
  if (key && !copyClean(new_key, sizeof(new_key), key)) return false;

  if (!key && strcasecmp(new_host, s_host) != 0 && s_key[0]) {
    // The key was entered for the old address. Sent along to the new one it
    // would reach a host nobody gave it to, as the Spoolman key never does.
    new_key[0] = '\0';
    key = new_key;
    logSD("AMS source: new address, the key entered for the old one is dropped");
  }
  memcpy(s_host, new_host, sizeof(s_host));
  rebuildBase();
  s_info = AmsSourceInfo{};   // belongs to the address just replaced
  prefsPutString(NVS_AMS_SRC_HOST, s_host);
  if (key) {
    memcpy(s_key, new_key, sizeof(s_key));
    prefsPutString(NVS_AMS_SRC_KEY, s_key);
  }
  logSDf("AMS source: %s, key %s", s_host[0] ? s_host : "off",
         s_key[0] ? "set" : "empty");
  return true;
}

bool amsSourceHostNeedsKey(const char* host) {
  char clean[sizeof(s_host)];
  if (!s_key[0] || !copyClean(clean, sizeof(clean), host) || !clean[0]) return false;
  return strcasecmp(clean, s_host) != 0;
}

static void addKey(HTTPClient& http) {
  if (s_key[0]) http.addHeader("X-API-Key", s_key);
}

static int getJson(const char* url, JsonDocument& doc, JsonDocument* filter,
                   uint32_t timeout_ms) {
  BackendHttp http;
  if (!http.begin(url)) return -1;
  http.setTimeout(timeout_ms);
  addKey(http);

  const int code = http.GET();
  if (code != 200) {
    http.end();
    logSDf("AMS source: GET %s -> %d", url, code);
    return code;
  }
  DeserializationError err = filter
    ? deserializeJson(doc, http.getStream(), DeserializationOption::Filter(*filter))
    : deserializeJson(doc, http.getStream());
  http.end();
  if (err) {
    logSDf("AMS source: JSON parse failed (%s) on %s", err.c_str(), url);
    return -2;
  }
  return 200;
}

static int postJson(const char* url, const JsonDocument& body, uint32_t timeout_ms) {
  String out;
  serializeJson(body, out);

  BackendHttp http;
  if (!http.begin(url)) return -1;
  http.setTimeout(timeout_ms);
  http.addHeader("Content-Type", "application/json");
  addKey(http);

  const int code = http.POST(out);
  if (code >= 200 && code < 300) {
    http.end();
    return 200;
  }
  if (code > 0) {
    String err = http.getString();
    if (err.length() > 120) err = err.substring(0, 120);
    logSDf("AMS source: POST %s -> %d %s", url, code, err.c_str());
  } else {
    logSDf("AMS source: POST %s -> transport error %d", url, code);
  }
  http.end();
  return code;
}

bool        amsSourceKnown()         { return s_info.known; }
bool        amsSourceCanAssign()     { return s_info.known && s_info.can_assign; }
bool        amsSourceCanUnassign()   { return s_info.known && s_info.can_unassign; }
const char* amsSourceServerName()    { return s_info.name; }
const char* amsSourceServerVersion() { return s_info.version; }

// GET on the prefix itself. A source that does not answer it is still read -
// the status route is all the view needs - but offered nothing to write.
static void askWhatItCan(uint32_t timeout_ms) {
  char url[sizeof(s_base) + 32];
  snprintf(url, sizeof(url), "%s" AMS_SOURCE_PREFIX, s_base);

  JsonDocument doc;
  const int code = getJson(url, doc, nullptr, timeout_ms);
  if (code != 200) {
    logSDf("AMS source: no self description (%d), shown read-only", code);
    return;
  }
  AmsSourceInfo info = {};
  info.contract = doc["version"] | 0;
  strncpy(info.name, doc["server"]["name"] | "", sizeof(info.name) - 1);
  strncpy(info.version, doc["server"]["version"] | "", sizeof(info.version) - 1);
  for (JsonVariantConst c : doc["capabilities"].as<JsonArrayConst>()) {
    const char* cap = c | "";
    if (strcmp(cap, "assign") == 0)   info.can_assign = true;
    if (strcmp(cap, "unassign") == 0) info.can_unassign = true;
  }
  info.known = true;
  s_info = info;
  logSDf("AMS source: %s %s, contract %d, assign=%d unassign=%d",
         info.name[0] ? info.name : "?", info.version, info.contract,
         (int)info.can_assign, (int)info.can_unassign);
}

int amsSourceListPrinters(AmsPrinterList& out, uint32_t timeout_ms) {
  out = AmsPrinterList{};
  if (!amsSourceConfigured()) return -1;
  if (!s_info.known) askWhatItCan(timeout_ms);

  char url[sizeof(s_base) + 48];
  snprintf(url, sizeof(url), "%s" AMS_SOURCE_PREFIX "/printers", s_base);

  // A handful of printers: small enough without a filter.
  JsonDocument doc;
  const int code = getJson(url, doc, nullptr, timeout_ms);
  if (code != 200) return code;
  if (!doc.is<JsonArrayConst>()) {
    logSD("AMS source: printer list is not an array");
    return -2;
  }

  for (JsonVariantConst pv : doc.as<JsonArrayConst>()) {
    if (out.count >= AMS_MAX_PRINTERS) {
      logSDf("AMS source: more than %d printers, rest ignored", AMS_MAX_PRINTERS);
      break;
    }
    JsonObjectConst po = pv.as<JsonObjectConst>();
    const int id = po["id"] | 0;
    if (id <= 0) continue;
    AmsPrinter& dst = out.p[out.count];
    dst = AmsPrinter{};
    dst.id = id;
    strncpy(dst.name, po["name"] | "", sizeof(dst.name) - 1);
    dst.active = true;
    dst.online = po["connected"] | false;
    out.count++;
  }
  logSDf("AMS source: %d printer(s)", (int)out.count);
  return 200;
}

int amsSourceGetState(int printer_id, AmsSlotState& out, uint32_t timeout_ms) {
  out = AmsSlotState{};
  if (!amsSourceConfigured() || printer_id <= 0) return -1;

  char url[sizeof(s_base) + 64];
  snprintf(url, sizeof(url), "%s" AMS_SOURCE_PREFIX "/printers/%d/status",
           s_base, printer_id);

  JsonDocument filter;
  bambuStatusFilter(filter);
  JsonDocument doc;
  const int code = getJson(url, doc, &filter, timeout_ms);
  if (code != 200) return code;

  bambuStatusToAmsState(doc.as<JsonObjectConst>(), printer_id, out, "AMS source");
  logSDf("AMS source: printer %d, %d unit(s), connected=%d ams_exists=%d",
         printer_id, (int)out.unit_count, (int)out.connected, (int)out.ams_exists);
  return 200;
}

// One bay of one printer, as assign and unassign both address it.
struct AmsBay {
  int printer_id;
  int ams_id;
  int tray_id;
};

static int postTray(const char* verb, int spool_id, const AmsBay& bay, uint32_t timeout_ms) {
  if (!amsSourceConfigured() || bay.printer_id <= 0 || bay.ams_id < 0 || bay.tray_id < 0) return -1;

  char url[sizeof(s_base) + 64];
  snprintf(url, sizeof(url), "%s" AMS_SOURCE_PREFIX "/printers/%d/%s",
           s_base, bay.printer_id, verb);

  JsonDocument body;
  if (spool_id > 0) body["spool_id"] = spool_id;
  body["ams_id"]  = bay.ams_id;
  body["tray_id"] = bay.tray_id;
  const int code = postJson(url, body, timeout_ms);
  logSDf("AMS source: %s spool %d, printer %d bay %d/%d -> %d",
         verb, spool_id, bay.printer_id, bay.ams_id, bay.tray_id, code);
  return code;
}

int amsSourceAssign(int spool_id, int printer_id, int ams_id, int tray_id,
                    uint32_t timeout_ms) {
  if (spool_id <= 0) return -1;
  return postTray("assign", spool_id, AmsBay{printer_id, ams_id, tray_id}, timeout_ms);
}

int amsSourceUnassign(int printer_id, int ams_id, int tray_id, uint32_t timeout_ms) {
  return postTray("unassign", 0, AmsBay{printer_id, ams_id, tray_id}, timeout_ms);
}
