#include "web_net_probe.h"

#include <esp_heap_caps.h>

#include "services/backend_http.h"
#include "web/web_access.h"
#include "web/web_jobs.h"
#include "web/web_shell.h"

// Last: T() is a macro, and ArduinoJson uses T as a template parameter.
#include "lang.h"

#define PROBE_COLD_RUNS     3      // a new connection each: what one request costs today
#define PROBE_BODY_MAX      16384  // read and dropped; a probe is about time, not content
#define PROBE_TIMEOUT_MS    8000

// Reads the answer to the end, so the time includes the body, and returns
// how many bytes it was.
static size_t drain(HTTPClient& http) {
  Stream* in = http.getStreamPtr();
  size_t got = 0;
  uint8_t buf[256];
  const unsigned long t0 = millis();
  const int size = http.getSize();
  while (got < PROBE_BODY_MAX && millis() - t0 < PROBE_TIMEOUT_MS) {
    const int n = in->available();
    if (n > 0) {
      got += in->readBytes(buf, n < (int)sizeof(buf) ? n : sizeof(buf));
      continue;
    }
    if (size > 0 && got >= (size_t)size) break;
    if (!http.connected()) break;
    delay(2);
  }
  return got;
}

void netProbeRun(const char* url, String& body) {
  const uint32_t heap0  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
  uint32_t heap_low     = heap0;
  const uint32_t psram0 = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

  body = "{\"url\":\"" + jsonEsc(url) + "\",\"tls\":" +
         (backendUrlIsHttps(url) ? "true" : "false") + ",\"cold\":[";
  for (int i = 0; i < PROBE_COLD_RUNS; i++) {
    BackendHttp http;
    http.setTimeout(PROBE_TIMEOUT_MS);
    const unsigned long t0 = millis();
    int code = -1;
    size_t bytes = 0;
    if (http.begin(url)) {
      code = http.GET();
      if (code > 0) bytes = drain(http);
    }
    const unsigned long ms = millis() - t0;
    const uint32_t h = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    if (h < heap_low) heap_low = h;
    http.end();
    body += String(i ? "," : "") + "{\"code\":" + code + ",\"ms\":" + ms +
            ",\"bytes\":" + bytes + "}";
  }

  // Two requests on one connection: what keep-alive would save.
  body += "],\"reuse\":[";
  {
    BackendHttp http;
    http.setTimeout(PROBE_TIMEOUT_MS);
    http.setReuse(true);
    for (int i = 0; i < 2; i++) {
      const unsigned long t0 = millis();
      int code = -1;
      size_t bytes = 0;
      if (http.begin(url)) {
        code = http.GET();
        if (code > 0) bytes = drain(http);
      }
      const unsigned long ms = millis() - t0;
      const uint32_t h = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
      if (h < heap_low) heap_low = h;
      body += String(i ? "," : "") + "{\"code\":" + code + ",\"ms\":" + ms +
              ",\"bytes\":" + bytes + "}";
    }
    http.end();
  }
  body += "],\"heap_before\":" + String(heap0) + ",\"heap_low\":" + String(heap_low) +
          ",\"heap_after\":" + String(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)) +
          ",\"psram_before\":" + String(psram0) +
          ",\"psram_after\":" + String(heap_caps_get_free_size(MALLOC_CAP_SPIRAM)) +
          ",\"insecure\":" + (backendTlsInsecure() ? "true" : "false") + "}";
}

void netProbeRoutes(WebServer& srv) {
  // Asked again with the same url until the answer is in, like the other
  // worker jobs.
  srv.on("/api/net/probe", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    if (webJobKind() == WJ_NET_PROBE) {
      if (webJobState() == WJS_RUNNING) {
        srv.send(202, "application/json", "{\"pending\":true}");
        return;
      }
      if (webJobState() == WJS_DONE) {
        const String reply = webJobResult().body;
        webJobTake();
        srv.send(200, "application/json", reply);
        return;
      }
    }
    const String url = srv.arg("url");
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      srv.send(400, "application/json", "{\"error\":\"url must start with http:// or https://\"}");
      return;
    }
    if (webJobState() == WJS_DONE) webJobTake();   // somebody else's leftover
    if (!webJobStart(WJ_NET_PROBE, url.c_str(), false)) {
      srv.send(200, "application/json", "{\"error\":\"busy\"}");
      return;
    }
    srv.send(202, "application/json", "{\"pending\":true}");
  });
}
