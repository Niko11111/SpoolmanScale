#include "web/web_assets.h"

#include <Arduino.h>
#include <mbedtls/base64.h>
#include <string.h>

#include "web/web_shell.h"

// Decoded on demand rather than kept in RAM: a browser asks for this once and
// then caches it for a week, so holding 5 kB permanently to save a rare decode
// is a bad trade on a device with 320 kB.
static void sendLogo(WebServer &srv) {
  const char *b64 = webShellLogoBase64();
  const size_t b64len = strlen(b64);
  size_t need = 0;
  mbedtls_base64_decode(nullptr, 0, &need, (const unsigned char *)b64, b64len);
  uint8_t *buf = (uint8_t *)malloc(need);
  if (!buf) { srv.send(500, "text/plain", "out of memory"); return; }
  size_t out = 0;
  if (mbedtls_base64_decode(buf, need, &out, (const unsigned char *)b64, b64len) != 0) {
    free(buf);
    srv.send(500, "text/plain", "logo decode failed");
    return;
  }
  srv.sendHeader("Cache-Control", "public, max-age=604800");
  srv.setContentLength(out);
  srv.send(200, "image/jpeg", "");
  srv.sendContent((const char *)buf, out);
  free(buf);
}

void registerAssetRoutes(WebServer &srv) {
  srv.on("/logo.jpg",    HTTP_GET, [&srv]() { sendLogo(srv); });
  // Browsers ask for this path on their own, without being told to. Answering
  // it also stops the 404 that every page view used to produce.
  srv.on("/favicon.jpg", HTTP_GET, [&srv]() { sendLogo(srv); });
}
