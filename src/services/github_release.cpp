#include "github_release.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <lvgl.h>
#include <string.h>
#include "mbedtls/sha256.h"

#include "hardware/sd_logger.h"
#include "services/ota_state.h"

#define GH_REPO "Niko11111/SpoolmanScale"
// The release asset the device flashes, see githubFlashTag().
#define GH_IMAGE_ASSET "SpoolmanScale.bin"

// The image's size out of a release's asset list.
static uint32_t imageSizeOf(JsonVariantConst rel) {
  for (JsonObjectConst a : rel["assets"].as<JsonArrayConst>())
    if (strcmp(a["name"] | "", GH_IMAGE_ASSET) == 0) return a["size"] | 0u;
  return 0;
}

// No bytes for this long while the socket is still open: the download is
// stuck, not slow. GitHub's CDN streams a 2 MB image in a few seconds.
#define GH_DOWNLOAD_STALL_MS  20000

// The root store built into the SDK (CONFIG_MBEDTLS_CERTIFICATE_BUNDLE), as
// the linker names it. github.com and api.github.com chain to Sectigo today,
// the release assets and GitHub Pages to Let's Encrypt; the bundle carries
// both and whatever they move to next.
extern const uint8_t x509_crt_bundle_start[] asm("_binary_x509_crt_bundle_start");
extern const uint8_t x509_crt_bundle_end[] asm("_binary_x509_crt_bundle_end");

void githubTrust(WiFiClientSecure &client) {
  client.setCACertBundle(x509_crt_bundle_start, x509_crt_bundle_end - x509_crt_bundle_start);
}

bool githubLatestTag(bool prerelease, char *tag, size_t tag_len,
                     char *published, size_t pub_len,
                     char *err, size_t err_len, uint32_t *image_size) {
  if (!tag || tag_len == 0) return false;
  tag[0] = '\0';
  uint32_t found_size = 0;
  if (image_size) *image_size = 0;
  if (published && pub_len) published[0] = '\0';
  if (err && err_len) err[0] = '\0';

  WiFiClientSecure client;
  githubTrust(client);
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
    f["assets"][0]["name"] = true;
    f["assets"][0]["size"] = true;

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
          found_size = imageSizeOf(rel);
          if (image_size) *image_size = found_size;
          break;
        }
      }
    }
  } else {
    JsonDocument filter;
    filter["tag_name"] = true;
    filter["published_at"] = true;
    filter["assets"][0]["name"] = true;
    filter["assets"][0]["size"] = true;

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
      found_size = imageSizeOf(doc);
      if (image_size) *image_size = found_size;
    }
  }

  // Enough to diagnose the next failure without guessing. "No release found"
  // and "JSON error" looked identical from the outside before this, and both
  // have several possible causes.
  logSDf("OTA check: HTTP %d len=%d heap %u->%u pre=%d err=%s entries=%d tag='%s' image=%u",
         code, payload_len, (unsigned)heap_before, (unsigned)heap_parse,
         prerelease ? 1 : 0, jerr.c_str(), entries, tag, (unsigned)found_size);
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
  githubTrust(client);
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

// Lower-case hex of a digest, for the log line and the comparison.
static void hexDigest(const unsigned char *d, size_t n, char *out, size_t out_len) {
  static const char hexd[] = "0123456789abcdef";
  size_t o = 0;
  for (size_t i = 0; i < n && o + 2 < out_len; i++) {
    out[o++] = hexd[d[i] >> 4];
    out[o++] = hexd[d[i] & 0x0F];
  }
  out[o] = '\0';
}

bool githubFlashTag(const char *tag, const char *sha256_hex,
                    OtaProgressFn progress, char *err, size_t err_len) {
  if (err && err_len) err[0] = '\0';
  if (!tag || tag[0] == '\0') {
    if (err && err_len) snprintf(err, err_len, "%s", "No release selected");
    return false;
  }
  const bool check_sha = (sha256_hex && strlen(sha256_hex) == 64);

  // Keeps the background check from opening a second TLS connection while the
  // image is being written. Cleared on every failing path below; a success
  // leaves it set, because the caller is about to restart.
  gh_flash_active = true;

  WiFiClientSecure client;
  githubTrust(client);
  HTTPClient http;

  // releases/latest skips pre-releases. Downloading from there while the check
  // above found a pre-release handed the device the previous public build: it
  // installed the downgrade, rebooted, found the same "update" again and
  // offered it once more. Addressing the release by its tag is the only form
  // that works for both kinds.
  String url = "https://github.com/" GH_REPO "/releases/download/";
  url += tag;
  url += "/" GH_IMAGE_ASSET;
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
  unsigned long last_data  = millis();
  bool write_failed = false;
  bool stalled      = false;

  // Summed as the bytes go into flash, so the check at the end is over what
  // was written rather than over what was received.
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);

  uint8_t buf8[512];
  while (http.connected() && (len > 0 || len == -1)) {
    size_t available = stream->available();
    if (available) {
      size_t toRead = min(available, sizeof(buf8));
      size_t rd = stream->readBytes(buf8, toRead);
      if (Update.write(buf8, rd) != rd) { write_failed = true; break; }
      mbedtls_sha256_update(&sha, buf8, rd);
      done += rd;
      last_data = millis();
      if (len > 0) len -= rd;
    } else if (millis() - last_data >= GH_DOWNLOAD_STALL_MS) {
      stalled = true;
      break;
    }
    if (progress && millis() - last_paint >= OTA_PROGRESS_MS) {
      last_paint = millis();
      progress(done, total);
    }
    lv_timer_handler();
    delay(1);
  }
  http.end();

  unsigned char digest[32];
  mbedtls_sha256_finish(&sha, digest);
  mbedtls_sha256_free(&sha);
  char got[65];
  hexDigest(digest, sizeof(digest), got, sizeof(got));

  // Every way the bytes can be wrong is refused before the image is
  // committed. Update.end(true) used to run here whatever had happened, and
  // it means "finalise even if bytes are missing": a WiFi drop mid-download
  // produced a success message, a reboot, and the bootloader quietly falling
  // back to the old image.
  const char *fail = nullptr;
  char detail[80] = "";
  if (write_failed) {
    snprintf(detail, sizeof(detail), "Update error %u", (unsigned)Update.getError());
    fail = detail;
  } else if (stalled) {
    snprintf(detail, sizeof(detail), "Stalled after %u bytes", (unsigned)done);
    fail = detail;
  } else if (total > 0 && done != total) {
    snprintf(detail, sizeof(detail), "Incomplete: %u of %u bytes", (unsigned)done, (unsigned)total);
    fail = detail;
  } else if (done == 0) {
    fail = "Empty download";
  } else if (check_sha && strcasecmp(got, sha256_hex) != 0) {
    fail = "Checksum mismatch";
    logSDf("OTA: sha256 expected %s, got %s", sha256_hex, got);
  }

  if (fail) {
    Update.abort();
    logSDf("OTA: %s refused - %s", tag, fail);
    if (err && err_len) snprintf(err, err_len, "%s", fail);
    gh_flash_active = false;
    return false;
  }

  logSDf("OTA: %s complete, %u bytes, sha256 %s%s", tag, (unsigned)done, got,
         check_sha ? " (verified)" : " (no checksum published)");

  // With a known size the strict form: the library checks that every byte
  // it was promised has arrived. Only a server that sent no Content-Length
  // leaves it no way to know, and that case was already bounded above.
  const bool ended = (total > 0) ? Update.end(false) : Update.end(true);
  if (ended && !Update.hasError()) return true;

  if (err && err_len) snprintf(err, err_len, "Update error %u",
                               (unsigned)Update.getError());
  gh_flash_active = false;
  return false;
}
