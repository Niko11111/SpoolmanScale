#include "app_boot.h"

#include <Arduino.h>
#include <Wire.h>
#include <lvgl.h>
#include <cstring>

#include "app_config.h"
#include "app/app_state.h"
#include "app/setup_flow.h"
#include "hardware/display.h"
#include "hardware/display_power.h"
#include "hardware/nfc.h"
#include "hardware/pins.h"
#include "hardware/scale.h"
#include "hardware/sd_logger.h"
#include "services/app_settings.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/time_service.h"
#include "services/update_check.h"
#include "services/wifi_manager.h"
#include "ui/header_status.h"
#include "ui/main_screen.h"
#include "ui/setup_welcome_screen.h"
#include "ui/wifi_setup_screen.h"
#include "lang.h"

// ============================================================
//  CONNECT WIFI
// ============================================================
void wifiConnect() {
  Serial.printf("WiFi: %s\n", cfg_wifi_ssid);
  // Update status bar; may already be set from setup(), but ensure it's shown.
  if (lbl_status) {
    char wifi_buf[32];
    strncpy(wifi_buf, T(STR_WIFI_CONNECTING_BOOT), sizeof(wifi_buf)-1);
    lv_label_set_text(lbl_status, wifi_buf);
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x5090e0), 0);
    lv_timer_handler();
  }
  if (wifiManagerConnect(cfg_wifi_ssid, cfg_wifi_password, 20, 500)) {
      wifi_ok = true;
      Serial.printf("WiFi OK! IP: %s\n", wifiManagerLocalIP().toString().c_str());
      updateHeaderStatus();
      syncNTP();
      // SD logging: write boot block once time is available
      if (sd_available) {
        cleanOldLogs();   // requires synced time
        writeBootBlock("Boot");
        logSDf("WiFi connected: %s | RSSI: %d dBm",
          cfg_wifi_ssid, wifiManagerRSSI());
      }
      // Fix 2: immediate health check after WiFi connect, against whichever
      // backend is active. The URL comes from backendBaseUrl() and the label
      // from backendName(), so a log never claims the wrong product. The gate
      // is deliberately not backendIsConfigured(): FilaMan serves /health
      // without credentials, and a device missing its tokens is exactly the
      // one where this line is worth having.
      const char* backend_name = backendName();
      if (strlen(backendBaseUrl()) > 7) {   // longer than "http://"
        int code = backendGetHealthCode(backendBaseUrl(), 3000);
        sm_reachable = (code == 200);
        logSDf("%s health check: HTTP %d -> %s",
          backend_name, code, sm_reachable ? "OK" : "FAIL");
        Serial.printf("%s health: HTTP %d -> %s\n",
          backend_name, code, sm_reachable ? "OK" : "FAIL");
        // Server version, from /api/v1/info on Spoolman and /openapi.json on FilaMan
        if (sm_reachable) {
          char ver[32] = "?";
          if (backendGetVersion(backendBaseUrl(), ver, sizeof(ver), 3000)) {
            logSDf("%s version: %s", backend_name, ver);
            Serial.printf("%s version: %s\n", backend_name, ver);
          }
        }
      } else {
        sm_reachable = false;
        logSDf("%s health check skipped: no host configured", backend_name);
        Serial.printf("%s health check skipped: no host configured\n", backend_name);
      }
      updateHeaderStatus();
      lv_label_set_text(lbl_spoolman_weight, T(STR_WAIT_SCAN_SM));
      lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
      lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
      lv_timer_handler();
      return;
  }
  Serial.println("WiFi FAILED - continuing without Spoolman");
  logSD("WiFi connection FAILED");
  updateHeaderStatus();
  lv_label_set_text(lbl_spoolman_weight, T(STR_NO_WIFI));
  lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
  lv_timer_handler();
}

// Spoolman lookup/display logic lives in ui/spoolman_lookup.cpp.

// ============================================================
//  SETUP
// ============================================================
void appSetup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("=== SpoolmanScale " FW_VERSION " ===");
  Serial.println("KDF Master: 9a759cf2c4f7caff222cb9769b41bc96");
  Serial.println("Context:    RFID-B");

  loadPrefs();

  // SD card init (early so logs can capture boot sequence)
  // Note: cleanOldLogs() is deferred until after NTP sync (in wifiConnect)
  initSD();

  // Which backend is active, plus FilaMan credentials. Runs after initSD()
  // so the line lands in the log, and well before the first backend_api call
  // in wifiConnect(). Logs only whether tokens are present, never their values.
  backendLoadSettings();

  displayHardwareBegin(resetActivityTimer);
  // Apply the stored brightness and arm the idle timer from a real
  // millis() reading, not from 0.
  displayPowerInit();

  I2C_EXT.begin(hw_pins::I2C_EXT_SDA, hw_pins::I2C_EXT_SCL, 100000);

  // Build UI immediately after display init so the user sees a screen right away.
  // lbl_status shows STR_BOOTING until wifiConnect() completes
  buildUI();
  lv_timer_handler();
  updateHeaderStatus();

  delay(500);

  Serial.print("Looking for PN532... ");
  uint32_t ver = 0;
  if (nfcHardwareBegin(&I2C_EXT, hw_pins::PN532_RESET, &ver)) {
    nfc_ok = true;
    Serial.printf("OK (FW %d.%d)\n", (ver >> 16) & 0xFF, (ver >> 8) & 0xFF);
    logSDf("NFC ready (PN532 FW %d.%d)", (ver >> 16) & 0xFF, (ver >> 8) & 0xFF);
  } else {
    Serial.println("ERROR!");
    logSD("NFC init FAILED");
  }

  Serial.print("Looking for NAU7802... ");
  if (scaleHardwareBegin(&I2C_EXT, [](){
    Serial.print(".");
    delay(100);
    lv_timer_handler();  // tick runs off millis(), see LV_TICK_CUSTOM in lv_conf.h
  })) {
    scl_ok = true;
    scale_ready = true;
    Serial.printf("OK! cal_factor=%.4f  zero_offset=%d\n", cal_factor, zero_offset);
    logSDf("Scale ready (cal=%.4f zero=%d)", cal_factor, zero_offset);
  } else {
    // Two ways to land here: the chip did not answer on 0x2A at all, or it
    // answered but never finished calibrating. scaleHardwareBegin() prints
    // which one, so this must not claim a cause of its own.
    Serial.println("ERROR! Scale unavailable (NAU7802 on 0x2A)");
    logSD("Scale init FAILED");
  }

  updateHeaderStatus();
  Serial.println("Ready. Hold spool near reader...");

  // Boot logic:
  // 1. lang_set=false: language selection (always first)
  // 2. lang_set=true, first_boot=true, SSID empty: first boot welcome screen
  // 3. lang_set=true, first_boot=false, SSID empty: WiFi setup
  // 4. lang_set=true, SSID set: normal start
  if (!cfg_lang_set) {
    // The language screen is the first step of the setup, not something
    // outside it. Choosing German restarts the device and lands in branch 2,
    // choosing English continues without a restart, and that path used to
    // leave the flag unset for the whole rest of the chain.
    setSetupActive(true, "boot: no language yet");
    logSetupBootState("language");
    showWelcomeScreen();
  } else if (cfg_first_boot && strlen(cfg_wifi_ssid) == 0) {
    setSetupActive(true, "boot: first boot, no SSID");
    logSetupBootState("firstboot");
    showFirstBootScreen();
  } else if (strlen(cfg_wifi_ssid) == 0) {
    setSetupActive(true, "boot: no SSID");
    logSetupBootState("wifisetup");
    showWifiSetupScreen();
  } else {
    logSetupBootState("normal");
    wifiConnect();
  }

  // Arm the background update check. Scheduled for every boot path, including
  // the setup screens: the check itself waits for wifi_ok, so a device that
  // only gets on the network later still picks it up without a restart.
  updateCheckScheduleFirstRun();
}
