#include "web_nfc_test.h"

#include "services/nfc_measure.h"
#include "web/web_access.h"

// Last: T() is a macro, and ArduinoJson uses T as a template parameter.
#include "lang.h"

#define NFC_TEST_JSON_LEN 512

void nfcTestRoutes(WebServer& srv) {
  // Only parks the request: the reader belongs to the loop task, and a
  // measurement takes seconds.
  srv.on("/api/nfc/measure", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    const long seconds = srv.hasArg("s") ? srv.arg("s").toInt() : NFC_MEASURE_SECONDS_DEFAULT;
    if (seconds < 1 || seconds > NFC_MEASURE_SECONDS_MAX || !nfcMeasureRequest((uint16_t)seconds)) {
      srv.send(409, "application/json",
               "{\"error\":\"a measurement is running, or s is outside 1-60\"}");
      return;
    }
    srv.send(202, "application/json", "{\"pending\":true}");
  });
  srv.on("/api/nfc/measure", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    char out[NFC_TEST_JSON_LEN];
    nfcMeasureJson(out, sizeof(out));
    srv.send(200, "application/json", out);
  });
}
