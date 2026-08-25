#include "github_release.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "services/ota_state.h"

#define GH_REPO "Niko11111/SpoolmanScale"

bool githubLatestTag(bool prerelease, char *tag, size_t tag_len,
                     char *published, size_t pub_len,
                     char *err, size_t err_len) {
  if (!tag || tag_len == 0) return false;
  tag[0] = '\0';
  if (published && pub_len) published[0] = '\0';
  if (err && err_len) err[0] = '\0';

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  // per_page caps the list. Unbounded it answers with every release ever cut -
  // 109 KB at the time of writing, against roughly 145 KB of free heap.
  String url = prerelease
    ? "https://api.github.com/repos/" GH_REPO "/releases?per_page=3"
    : "https://api.github.com/repos/" GH_REPO "/releases/latest";
  http.begin(client, url);
  http.addHeader("User-Agent", "SpoolmanScale-ESP32");
  http.setTimeout(8000);
  const uint32_t heap_before = ESP.getFreeHeap();
  int code = http.GET();
  Serial.printf("GitHub API: %d\n", code);

  if (code != 200) {
    if (err && err_len) snprintf(err, err_len, "HTTP %d", code);
    http.end();
    return false;
  }

  // Read as a String rather than straight off the socket. http.getStream()
  // hands back the raw client, which skips HTTPClient's chunked decoding - and
  // this endpoint answers chunked as soon as the list is not capped. The
  // memory win never came from the stream anyway: it comes from per_page and
  // from the filter, which is what keeps the parsed document small. With
  // per_page=3 the body is around 27 kB and bounded.
  String payload = http.getString();
  const int    payload_len = payload.length();
  const uint32_t heap_parse = ESP.getFreeHeap();
  http.end();

  DeserializationError jerr;
  int entries = 0;

  if (prerelease) {
    // add<JsonObject>() rather than the createNestedObject() the older filters
    // in this repo use - same result, and it is the form ArduinoJson 7 keeps.
    JsonDocument filter;
    JsonObject f = filter.to<JsonArray>().add<JsonObject>();
    f["tag_name"] = true;
    f["published_at"] = true;
    f["draft"] = true;

    JsonDocument doc;
    jerr = deserializeJson(doc, payload, DeserializationOption::Filter(filter));
    if (!jerr) {
      for (JsonVariant v : doc.as<JsonArray>()) {
        entries++;
        JsonObject rel = v.as<JsonObject>();
        if (rel["draft"] | false) continue;
        const char* t = rel["tag_name"] | "";
        if (t[0] != '\0') {
          // Copied while the document is still alive. The pointer dies with it.
          strncpy(tag, t, tag_len - 1);
          tag[tag_len - 1] = '\0';
          if (published && pub_len) {
            strncpy(published, rel["published_at"] | "", pub_len - 1);
            published[pub_len - 1] = '\0';
          }
          break;
        }
      }
    }
  } else {
    JsonDocument filter;
    filter["tag_name"] = true;
    filter["published_at"] = true;

    JsonDocument doc;
    jerr = deserializeJson(doc, payload, DeserializationOption::Filter(filter));
    if (!jerr) {
      entries = 1;
      const char* t = doc["tag_name"] | "";
      strncpy(tag, t, tag_len - 1);
      tag[tag_len - 1] = '\0';
      if (published && pub_len) {
        strncpy(published, doc["published_at"] | "", pub_len - 1);
        published[pub_len - 1] = '\0';
      }
    }
  }

  // Enough to diagnose the next failure without guessing. "No release found"
  // and "JSON error" looked identical from the outside before this, and both
  // have several possible causes.
  logSDf("OTA check: HTTP %d len=%d heap %u->%u pre=%d err=%s entries=%d tag='%s'",
         code, payload_len, (unsigned)heap_before, (unsigned)heap_parse,
         prerelease ? 1 : 0, jerr.c_str(), entries, tag);
  Serial.printf("OTA check: len=%d heap %u->%u err=%s entries=%d tag='%s'\n",
                payload_len, (unsigned)heap_before, (unsigned)heap_parse,
                jerr.c_str(), entries, tag);

  if (jerr) {
    // The first 60 characters say more than any error name: a chunk length, an
    // HTML error page or a truncated body are all obvious at a glance.
    logSDf("OTA check: body starts '%s'", payload.substring(0, 60).c_str());
    if (err && err_len) snprintf(err, err_len, "JSON: %s", jerr.c_str());
    return false;
  }

  if (tag[0] == '\0') {
    if (entries == 0) logSD("OTA check: list was empty");
    else              logSD("OTA check: entries had no usable tag_name");
    if (err && err_len) snprintf(err, err_len, "%s",
                                 entries == 0 ? "Empty release list"
                                              : "No usable release");
    return false;
  }
  return true;
}

// A tag goes straight into a URL, so nothing but the shape GitHub uses gets
// that far.
static bool tagLooksSafe(const char *tag) {
  if (!tag || !tag[0]) return false;
  size_t n = 0;
  for (const char *p = tag; *p; p++, n++) {
    const char c = *p;
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
    if (!ok) return false;
  }
  return n < 40;
}

// Long enough for the release notes this project writes - they run about 5 kB -
// with room to spare, and short enough that a pasted build log cannot matter.
#define GH_NOTES_MAX 8000

bool githubReleaseByTag(const char *tag, GithubRelease &out,
                        char *err, size_t err_len) {
  out.tag[0] = out.name[0] = out.published[0] = '\0';
  out.prerelease = false;
  out.notes = "";
  if (err && err_len) err[0] = '\0';

  if (!tagLooksSafe(tag)) {
    if (err && err_len) snprintf(err, err_len, "%s", "Bad tag");
    return false;
  }

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  String url = "https://api.github.com/repos/" GH_REPO "/releases/tags/";
  url += tag;
  http.begin(client, url);
  http.addHeader("User-Agent", "SpoolmanScale-ESP32");
  http.setTimeout(8000);
  int code = http.GET();

  // 404 is the ordinary answer for a build that was never published - a local
  // one, or an image pushed through the browser. Told apart from a real
  // failure so the page can say which it was.
  if (code != 200) {
    if (err && err_len) snprintf(err, err_len, code == 404 ? "notfound" : "HTTP %d", code);
    http.end();
    return false;
  }

  String payload = http.getString();
  http.end();

  JsonDocument filter;
  filter["tag_name"]     = true;
  filter["name"]         = true;
  filter["prerelease"]   = true;
  filter["published_at"] = true;
  filter["body"]         = true;

  JsonDocument doc;
  DeserializationError jerr =
    deserializeJson(doc, payload, DeserializationOption::Filter(filter));
  if (jerr) {
    if (err && err_len) snprintf(err, err_len, "JSON: %s", jerr.c_str());
    return false;
  }

  strncpy(out.tag, doc["tag_name"] | tag, sizeof(out.tag) - 1);
  out.tag[sizeof(out.tag) - 1] = '\0';
  strncpy(out.name, doc["name"] | "", sizeof(out.name) - 1);
  out.name[sizeof(out.name) - 1] = '\0';
  strncpy(out.published, doc["published_at"] | "", sizeof(out.published) - 1);
  out.published[sizeof(out.published) - 1] = '\0';
  out.prerelease = doc["prerelease"] | false;

  const char *b = doc["body"] | "";
  if (strlen(b) > GH_NOTES_MAX) {
    out.notes = String(b).substring(0, GH_NOTES_MAX);
    out.notes += "\n...";
  } else {
    out.notes = b;
  }

  logSDf("OTA notes: %s pre=%d published=%s body=%u",
         out.tag, out.prerelease ? 1 : 0, out.published, (unsigned)out.notes.length());
  return true;
}

bool githubFlashTag(const char *tag, OtaProgressFn progress,
                    char *err, size_t err_len) {
  if (err && err_len) err[0] = '\0';
  if (!tag || tag[0] == '\0') {
    if (err && err_len) snprintf(err, err_len, "%s", "No release selected");
    return false;
  }

  // Keeps the background check from opening a second TLS connection while the
  // image is being written. Cleared on every failing path below; a success
  // leaves it set, because the caller is about to restart.
  gh_flash_active = true;

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;

  // releases/latest skips pre-releases. Downloading from there while the check
  // above found a pre-release handed the device the previous public build: it
  // installed the downgrade, rebooted, found the same "update" again and
  // offered it once more. Addressing the release by its tag is the only form
  // that works for both kinds.
  String url = "https://github.com/" GH_REPO "/releases/download/";
  url += tag;
  url += "/SpoolmanScale.bin";
  Serial.printf("GitHub OTA URL: %s\n", url.c_str());
  http.begin(client, url);
  http.addHeader("User-Agent", "SpoolmanScale-ESP32");
  http.setTimeout(60000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

  int code = http.GET();
  Serial.printf("GitHub OTA download: %d\n", code);

  if (code != 200) {
    if (err && err_len) snprintf(err, err_len, "HTTP %d", code);
    http.end();
    gh_flash_active = false;
    return false;
  }

  int len = http.getSize();
  WiFiClient* stream = http.getStreamPtr();

  if (!Update.begin(len > 0 ? len : UPDATE_SIZE_UNKNOWN)) {
    if (err && err_len) snprintf(err, err_len, "%s", "No room for the image");
    http.end();
    gh_flash_active = false;
    return false;
  }

  // len is what is left to fetch; total is what there was. A server that sends
  // no Content-Length leaves total at 0, and then the caller gets a count
  // without a percentage rather than a bar that lies about the end.
  const uint32_t total = (len > 0) ? (uint32_t)len : 0;
  uint32_t done = 0;
  unsigned long last_paint = 0;

  uint8_t buf8[512];
  while (http.connected() && (len > 0 || len == -1)) {
    size_t available = stream->available();
    if (available) {
      size_t toRead = min(available, sizeof(buf8));
      size_t rd = stream->readBytes(buf8, toRead);
      if (Update.write(buf8, rd) != rd) break;
      done += rd;
      if (len > 0) len -= rd;
    }
    if (progress && millis() - last_paint >= OTA_PROGRESS_MS) {
      last_paint = millis();
      progress(done, total);
    }
    lv_timer_handler();
    delay(1);
  }
  http.end();

  if (Update.end(true) && !Update.hasError()) return true;

  if (err && err_len) snprintf(err, err_len, "Update error %u",
                               (unsigned)Update.getError());
  gh_flash_active = false;
  return false;
}
