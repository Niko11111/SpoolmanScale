#include "web_nfc_test.h"

#include "hardware/display_power.h"
#include "hardware/nfc.h"
#include "services/nfc_measure.h"
#include "services/nfc_wake_test.h"
#include "openprinttag/opt_scan.h"
#include "openprinttag/opt_sim.h"
#include "web/web_access.h"

// Last: T() is a macro, and ArduinoJson uses T as a template parameter.
#include "lang.h"

#define NFC_TEST_JSON_LEN 1024
// UID, report and fields take some 700 bytes, the memory as hex up to 1024.
#define NFC_OPT_JSON_LEN  2048
#define OPT_SIM_SECONDS_DEFAULT 60
#define OPT_SIM_SECONDS_MAX     600

static void openPrintTagRoutes(WebServer& srv) {
  srv.on("/api/nfc/opt", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    static char out[NFC_OPT_JSON_LEN];   // not on the loop task's stack
    optScanJson(out, sizeof(out));
    srv.send(200, "application/json", out);
  });
  srv.on("/api/nfc/opt/sim", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    const String v = srv.arg("v");
    if (v == "off") {
      optSimOff();
      srv.send(200, "application/json", "{\"sim\":false}");
      return;
    }
    const long seconds = srv.hasArg("s") ? srv.arg("s").toInt() : OPT_SIM_SECONDS_DEFAULT;
    if (seconds < 1 || seconds > OPT_SIM_SECONDS_MAX || !optSimArm(v.c_str(), (uint16_t)seconds)) {
      char err[96];
      snprintf(err, sizeof(err), "{\"error\":\"v is one of %s or off, s 1-600\"}", optSimKeys());
      srv.send(400, "application/json", err);
      return;
    }
    srv.send(200, "application/json", "{\"sim\":true}");
  });
}

static void wakeTestRoutes(WebServer& srv) {
  srv.on("/api/nfc/waketest", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LOGS))) return;
    char out[NFC_TEST_JSON_LEN];
    snprintf(out, sizeof(out), "{\"on\":%s,\"chip\":\"%s\",\"last_wake\":\"%s\"}",
             nfcWakeTestEnabled() ? "true" : "false", nfcChipName(), nfcWakeTestLastWake());
    srv.send(200, "application/json", out);
  });
  srv.on("/api/nfc/waketest", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LOGS))) return;
    if (!srv.hasArg("on")) {
      srv.send(400, "application/json", "{\"error\":\"on=1 or on=0\"}");
      return;
    }
    const bool on = srv.arg("on") == "1";
    if (on && !nfcWakeAvailable()) {   // as /api/nfcwake on the settings page
      srv.send(409, "application/json", "{\"error\":\"reset wire not verified\"}");
      return;
    }
    nfcWakeTestSet(on);
    srv.send(200, "application/json", on ? "{\"on\":true}" : "{\"on\":false}");
  });
  // Only sets a flag: the loop task goes to sleep on its next pass, after
  // this answer has left.
  srv.on("/api/nfc/sleep", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_LOGS))) return;
    displayPowerSleepNow();
    srv.send(202, "application/json", "{\"sleeping\":true}");
  });
}

void nfcTestRoutes(WebServer& srv) {
  wakeTestRoutes(srv);
  openPrintTagRoutes(srv);
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
