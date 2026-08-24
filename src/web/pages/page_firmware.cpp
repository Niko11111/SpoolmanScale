// Firmware upload. Used to live at "/", which meant browsing the device
// address dropped the visitor straight into a file picker.
#include "web/web_pages.h"

#include <Arduino.h>
#include <Update.h>
#include <WebServer.h>
#include <lvgl.h>

#include "app/app_state.h"
#include "app_config.h"
#include "hardware/sd_logger.h"
#include "services/ota_state.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

// Set while an image is being received. The background update check reads
// this to stay out of the way: a second TLS connection during a flash is
// exactly the situation that must not happen.
static bool ota_upload_active = false;

// What the device screen needs to draw a bar while the browser pushes an
// image. Until now it said "Uploading..." once and then nothing for two
// minutes, so anyone standing at the scale could not tell a slow upload from
// a dead one.
static uint32_t ota_upload_total = 0;
static uint32_t ota_upload_done  = 0;
static unsigned long ota_last_paint = 0;

bool otaWebUploadActive() { return ota_upload_active; }

static const char* label() { return T(STR_W_NAV_FIRMWARE); }

static String body() {
  String h;
  h.reserve(2200);
  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_FIRMWARE);
  h += F("</h2><div class='rows' style='margin-bottom:16px'>");
  h += F("<div class='row'><span class='k'>");
  h += T(STR_W_FW_INSTALLED);
  h += F("</span><span class='v mono'>");
  h += FW_VERSION;
  h += F("</span></div></div>"
         "<form method='POST' action='/update' enctype='multipart/form-data'>"
         "<div class='field'><label>");
  h += T(STR_W_FW_FILE);
  h += F("</label><div class='inrow'>"
         "<input type='file' name='firmware' accept='.bin' required>"
         "<button type='submit'>");
  h += T(STR_W_FW_FLASH);
  h += F("</button></div><span class='hint'>");
  h += T(STR_W_FW_HINT);
  h += F("</span></div></form></div></div>");
  return h;
}

static void routes(WebServer &srv) {
  srv.on("/update", HTTP_POST,
    // Completion handler. Runs after the bytes are already written, which is
    // why the gate is checked in both callbacks: guarding only this one
    // refuses the reply and flashes the device anyway.
    [&srv]() {
      if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_FIRMWARE))) return;
      bool ok = !Update.hasError();
      String msg = ok
        ? "<!DOCTYPE html><html><head><meta charset='utf-8'>"
          "<meta http-equiv='refresh' content='5;url=/'>"
          "<style>body{background:#06080f;color:#28d49a;font-family:-apple-system,sans-serif;"
          "display:flex;flex-direction:column;align-items:center;justify-content:center;"
          "min-height:100vh;gap:12px}"
          "h1{font-size:28px}p{color:#4a6fa0;font-size:14px}</style></head>"
          "<body><h1>&#10003; " + String(T(STR_W_FW_OK)) + "</h1>"
          "<p>" + String(T(STR_W_FW_RESTARTING)) + "</p></body></html>"
        : "<!DOCTYPE html><html><head><meta charset='utf-8'>"
          "<style>body{background:#06080f;color:#ff8080;font-family:-apple-system,sans-serif;"
          "display:flex;flex-direction:column;align-items:center;justify-content:center;"
          "min-height:100vh;gap:12px}"
          "h1{font-size:28px}p{color:#4a6fa0;font-size:14px}"
          "a{color:#28d49a}</style></head>"
          "<body><h1>&#10007; " + String(T(STR_W_FW_FAIL)) + "</h1>"
          "<p>" + String(T(STR_W_FW_RETRY)) + "</p><a href='/'>&#8592; " + String(T(STR_W_BACK_STATUS)) + "</a></body></html>";
      srv.send(200, "text/html", msg);
      if (ok) {
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_SUCCESS));
        lv_timer_handler();
        delay(1500);
        logSD("Reboot: OTA browser update success");
        ESP.restart();
      } else {
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_FAIL));
      }
    },
    // Chunk handler.
    [&srv]() {
      if (!webGateOpen(GATE_MAINT)) return;
      HTTPUpload& upload = srv.upload();
      if (upload.status == UPLOAD_FILE_START) {
        Serial.printf("OTA start: %s\n", upload.filename.c_str());
        ota_upload_active = true;
        if (Update.isRunning()) Update.abort();  // clean up any previous failed upload
        if (!Update.begin(UPDATE_SIZE_UNKNOWN)) {
          Serial.println("OTA begin() error");
          ota_upload_active = false;
        }
        // The multipart envelope adds a few hundred bytes on top of the
        // image. On a 1.9 MB upload that is under 0.05 %, so it serves as the
        // denominator; otaProgressLine() clamps the last stretch at 100.
        ota_upload_total = (srv.clientContentLength() > 0)
                           ? (uint32_t)srv.clientContentLength() : 0;
        ota_upload_done  = 0;
        ota_last_paint   = 0;
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_UPLOADING));
        lv_timer_handler();
      } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
          Serial.println("OTA write() error");
        }
        ota_upload_done += upload.currentSize;
        // Same cadence as the GitHub path. Painting per chunk would cost more
        // than the write does.
        if (lbl_ota_status && millis() - ota_last_paint >= OTA_PROGRESS_MS) {
          ota_last_paint = millis();
          char line[48];
          otaProgressLine(line, sizeof(line), ota_upload_done, ota_upload_total);
          lv_label_set_text(lbl_ota_status, line);
          lv_refr_now(NULL);
        }
      } else if (upload.status == UPLOAD_FILE_END) {
        ota_upload_active = false;
        if (Update.end(true)) {
          Serial.printf("OTA end: %u bytes\n", upload.totalSize);
        } else {
          Serial.println("OTA end() error");
        }
      }
    }
  );
}

extern const WebPage PAGE_FIRMWARE;
const WebPage PAGE_FIRMWARE = {
  "/ota", label, GATE_MAINT, nullptr,
  body, routes
};
