#include "services/label_fetch.h"

#include <Arduino.h>
#include <HTTPClient.h>
#include <WiFiClient.h>
#include <esp_heap_caps.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "services/prefs_store.h"
#include "services/wifi_manager.h"

// NVS key: 15 characters at most, and never renamed (see label_printer.cpp).
#define PREF_LABEL_SVC  "label_svc"

// The print card is up while this runs; the service answers from its cache in
// well under a second, a cold render takes one or two.
#define LABEL_FETCH_TIMEOUT_MS  8000

static char s_url[128];
static bool s_loaded = false;

static void load() {
  if (s_loaded) return;
  s_loaded = true;
  snprintf(s_url, sizeof(s_url), "%s", prefsGetString(PREF_LABEL_SVC, "").c_str());
}

const char* labelServiceUrl() {
  load();
  return s_url;
}

bool labelServiceConfigured() {
  load();
  return s_url[0] != '\0';
}

bool labelServiceSetUrl(const char* url) {
  char v[sizeof(s_url)];
  const char* p = url ? url : "";
  while (*p == ' ' || *p == '\t') p++;
  snprintf(v, sizeof(v), "%s", p);
  size_t n = strlen(v);
  while (n && (v[n - 1] == ' ' || v[n - 1] == '\t' || v[n - 1] == '\r' ||
               v[n - 1] == '\n' || v[n - 1] == '/')) v[--n] = '\0';
  // Plain http only: the service runs on the LAN, and HTTPClient over TLS
  // would want a certificate the service does not have.
  if (n && strncmp(v, "http://", 7) != 0) return false;
  if (!prefsPutString(PREF_LABEL_SVC, v)) return false;
  snprintf(s_url, sizeof(s_url), "%s", v);
  s_loaded = true;
  logSDf("Label service -> '%s'", s_url);
  return true;
}

static bool fail(char* why, size_t why_len, const char* fmt, long a = 0, long b = 0) {
  if (why && why_len) snprintf(why, why_len, fmt, a, b);
  return false;
}

bool labelFetchRaster(const LabelPrinterConfig& c, int spool_id, bool filament,
                      LabelRaster* out, char* why, size_t why_len) {
  *out = LabelRaster{};
  if (!labelServiceConfigured()) return fail(why, why_len, "no label service set");
  if (!wifiManagerIsConnected()) return fail(why, why_len, "no WiFi");
  if (spool_id <= 0) return fail(why, why_len, "no spool");

  char url[256];
  snprintf(url, sizeof(url), "%s/label?spoolman_id=%d&w=%u&h=%u&format=raster%s",
           s_url, spool_id, (unsigned)c.media_width_mm, (unsigned)c.media_length_mm,
           filament ? "&what=filament" : "");

  // Its own client and connection: the backend's kept-alive one is not ours to
  // disturb, and this address is another host or port anyway.
  WiFiClient net;
  HTTPClient http;
  http.setTimeout(LABEL_FETCH_TIMEOUT_MS);
  http.setConnectTimeout(LABEL_FETCH_TIMEOUT_MS);
  if (!http.begin(net, url)) return fail(why, why_len, "bad label service address");
  const char* keys[] = {"X-Label-Width", "X-Label-Height", "X-Label-Row-Bytes"};
  http.collectHeaders(keys, 3);
  const int code = http.GET();
  if (code != 200) {
    http.end();
    return fail(why, why_len, "label service answered HTTP %ld", code);
  }
  const long w = http.header("X-Label-Width").toInt();
  const long h = http.header("X-Label-Height").toInt();
  const long rb = http.header("X-Label-Row-Bytes").toInt();
  const long len = http.getSize();

  // The label must be the loaded stock, within the dot of slack the printer
  // check allows (labelPrinterRasterFits), and shaped as the headers say.
  const long want_w = labelPrinterDotsForMm(c.media_width_mm);
  const long want_h = labelPrinterDotsForMm(c.media_length_mm);
  if (w < want_w - 1 || w > want_w + 1 || h < want_h - 1 || h > want_h + 1) {
    http.end();
    return fail(why, why_len, "label is %ld dots wide, the stock wants %ld", w, want_w);
  }
  if (rb != (w + 7) / 8 || len != rb * h) {
    http.end();
    return fail(why, why_len, "label shape does not add up (%ld bytes, %ld per row)", len, rb);
  }

  // The body, then the print row: the label at the content offset, bit by
  // bit, as packCanvas() places the canvas.
  uint8_t* body = (uint8_t*)heap_caps_malloc((size_t)len, MALLOC_CAP_SPIRAM);
  if (!body) {
    http.end();
    return fail(why, why_len, "no PSRAM for %ld bytes", len);
  }
  WiFiClient* stream = http.getStreamPtr();
  long got = 0;
  const uint32_t deadline = millis() + LABEL_FETCH_TIMEOUT_MS;
  while (got < len && millis() < deadline) {
    const int avail = stream->available();
    if (avail <= 0) {
      if (!http.connected()) break;
      delay(2);
      continue;
    }
    got += stream->readBytes(body + got, min((long)avail, len - got));
  }
  http.end();
  if (got != len) {
    free(body);
    return fail(why, why_len, "label cut short: %ld of %ld bytes", got, len);
  }

  const uint16_t row_w = labelPrinterRasterWidth(c.model, c.media_width_mm);
  const uint16_t row_bytes = (row_w + 7) / 8;
  const uint16_t x0 = labelPrinterContentX(c);
  if (row_w < LABEL_RASTER_MIN_W || x0 + w > row_w) {
    free(body);
    return fail(why, why_len, "label does not fit the print row (%ld + %ld dots)", x0, w);
  }
  const size_t length = (size_t)row_bytes * h;
  uint8_t* px = (uint8_t*)heap_caps_calloc(length, 1, MALLOC_CAP_SPIRAM);
  if (!px) {
    free(body);
    return fail(why, why_len, "no PSRAM for the print row");
  }
  for (long y = 0; y < h; y++) {
    const uint8_t* src = body + y * rb;
    uint8_t* row = px + (size_t)y * row_bytes;
    for (long x = 0; x < w; x++) {
      if (src[x >> 3] & (0x80 >> (x & 7))) {
        const uint16_t rx = x0 + x;
        row[rx >> 3] |= 0x80 >> (rx & 7);
      }
    }
  }
  free(body);
  out->width = row_w;
  out->height = (uint16_t)h;
  out->row_bytes = row_bytes;
  out->pixels = px;
  out->length = length;
  out->content_width = (uint16_t)w;
  if (!labelRasterValid(*out)) {
    free(px);
    *out = LabelRaster{};
    return fail(why, why_len, "label raster invalid");
  }
  logSDf("Label: fetched %s label for spool #%d, %ldx%ld dots at x %u",
         filament ? "filament" : "spool", spool_id, w, h, (unsigned)x0);
  return true;
}
