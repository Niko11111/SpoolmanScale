#include "ota_github.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <lvgl.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "ui_common.h"

extern bool wifi_ok;
extern bool show_ota_pending;
extern bool update_available;
extern bool gh_prerelease;
extern lv_obj_t *scr_ota_github;

void hideAllOverlays();
void showUpdateBadges(bool show);

static lv_obj_t *lbl_gh_status      = nullptr;
static lv_obj_t *lbl_gh_installed   = nullptr;
static lv_obj_t *lbl_gh_latest      = nullptr;
static lv_obj_t *btn_gh_update      = nullptr;
static lv_obj_t *lbl_gh_update_btn  = nullptr;
static char gh_latest_version[32]   = "";

static int parseVersion(const char* v) {
  const char *p = v;
  while (*p && !isdigit((unsigned char)*p)) p++;
  int major = 0, minor = 0, patch = 0;
  sscanf(p, "%d.%d.%d", &major, &minor, &patch);
  return major * 100000 + minor * 1000 + patch;
}

void doGithubOtaCheckSilent() {
  if (!wifi_ok) return;
  Serial.println("Silent OTA check...");

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  String url = gh_prerelease
    ? "https://api.github.com/repos/Niko11111/SpoolmanScale/releases"
    : "https://api.github.com/repos/Niko11111/SpoolmanScale/releases/latest";
  http.begin(client, url);
  http.addHeader("User-Agent", "SpoolmanScale-ESP32");
  http.setTimeout(8000);
  int code = http.GET();
  if (code != 200) { http.end(); Serial.printf("Silent OTA: HTTP %d\n", code); return; }

  String payload = http.getString();
  http.end();

  const char* tag = "";
  if (gh_prerelease) {
    DynamicJsonDocument doc(8192);
    doc.clear();
    if (deserializeJson(doc, payload)) return;
    JsonArray arr = doc.as<JsonArray>();
    for (JsonObject rel : arr) {
      if (rel["draft"] | false) continue;
      tag = rel["tag_name"] | "";
      if (tag[0] != '\0') break;
    }
  } else {
    DynamicJsonDocument doc(2048);
    doc.clear();
    if (deserializeJson(doc, payload)) return;
    tag = doc["tag_name"] | "";
  }

  if (tag[0] == '\0') return;

  strncpy(gh_latest_version, tag, sizeof(gh_latest_version)-1);
  gh_latest_version[sizeof(gh_latest_version)-1] = 0;

  int cur    = parseVersion(FW_VERSION);
  int remote = parseVersion(gh_latest_version);
  Serial.printf("Silent OTA: installed=%s latest=%s\n", FW_VERSION, gh_latest_version);

  if (remote > cur) {
    update_available = true;
    showUpdateBadges(true);
    Serial.println("Update available - badge shown");
  }
}

void doGithubOtaCheck() {
  if (!lbl_gh_status) return;

  if (!wifi_ok) {
    char buf[64]; strncpy(buf, T(STR_GH_OTA_NO_WIFI), sizeof(buf)-1); buf[sizeof(buf)-1]=0;
    lv_label_set_text(lbl_gh_status, buf);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    return;
  }

  char buf[64]; strncpy(buf, T(STR_GH_OTA_CHECKING), sizeof(buf)-1); buf[sizeof(buf)-1]=0;
  lv_label_set_text(lbl_gh_status, buf);
  lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x4a6fa0), 0);
  lv_timer_handler();

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  String url = gh_prerelease
    ? "https://api.github.com/repos/Niko11111/SpoolmanScale/releases"
    : "https://api.github.com/repos/Niko11111/SpoolmanScale/releases/latest";
  http.begin(client, url);
  http.addHeader("User-Agent", "SpoolmanScale-ESP32");
  http.setTimeout(8000);
  int code = http.GET();
  Serial.printf("GitHub API: %d\n", code);

  if (code != 200) {
    snprintf(buf, sizeof(buf), "HTTP %d", code);
    lv_label_set_text(lbl_gh_status, buf);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    http.end();
    return;
  }

  String payload = http.getString();
  http.end();

  const char* tag = "";
  if (gh_prerelease) {
    DynamicJsonDocument doc(8192);
    doc.clear();
    if (deserializeJson(doc, payload)) {
      lv_label_set_text(lbl_gh_status, "JSON error");
      lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
      return;
    }
    JsonArray arr = doc.as<JsonArray>();
    for (JsonObject rel : arr) {
      if (rel["draft"] | false) continue;
      tag = rel["tag_name"] | "";
      if (tag[0] != '\0') break;
    }
  } else {
    DynamicJsonDocument doc(2048);
    doc.clear();
    if (deserializeJson(doc, payload)) {
      lv_label_set_text(lbl_gh_status, "JSON error");
      lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
      return;
    }
    tag = doc["tag_name"] | "";
  }

  if (tag[0] == '\0') {
    lv_label_set_text(lbl_gh_status, "No release found");
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    return;
  }

  strncpy(gh_latest_version, tag, sizeof(gh_latest_version)-1);
  gh_latest_version[sizeof(gh_latest_version)-1] = 0;

  if (lbl_gh_installed) {
    char inst[48]; snprintf(inst, sizeof(inst), T(STR_GH_OTA_INSTALLED), FW_VERSION);
    lv_label_set_text(lbl_gh_installed, inst);
    lv_obj_clear_flag(lbl_gh_installed, LV_OBJ_FLAG_HIDDEN);
  }
  if (lbl_gh_latest) {
    char lat[48]; snprintf(lat, sizeof(lat), T(STR_GH_OTA_LATEST), gh_latest_version);
    lv_label_set_text(lbl_gh_latest, lat);
    lv_obj_clear_flag(lbl_gh_latest, LV_OBJ_FLAG_HIDDEN);
  }

  int cur = parseVersion(FW_VERSION);
  int remote = parseVersion(gh_latest_version);

  if (remote <= cur) {
    char upd[48]; strncpy(upd, T(STR_GH_OTA_UP_TO_DATE), sizeof(upd)-1); upd[sizeof(upd)-1]=0;
    lv_label_set_text(lbl_gh_status, upd);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x40c080), 0);
  } else {
    char avail[64]; snprintf(avail, sizeof(avail), T(STR_GH_OTA_UPDATE_AVAIL), gh_latest_version);
    lv_label_set_text(lbl_gh_status, avail);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xf0b838), 0);
    if (btn_gh_update) {
      lv_obj_clear_state(btn_gh_update, LV_STATE_DISABLED);
      lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x1a3020), 0);
      lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(btn_gh_update, lv_color_hex(0x28d49a), 0);
      if (lbl_gh_update_btn) {
        char ubtn[48]; strncpy(ubtn, T(STR_GH_OTA_UPDATE_BTN), sizeof(ubtn)-1); ubtn[sizeof(ubtn)-1]=0;
        lv_label_set_text(lbl_gh_update_btn, ubtn);
        lv_obj_set_style_text_color(lbl_gh_update_btn, lv_color_hex(0x40c080), 0);
      }
    }
    update_available = true;
    showUpdateBadges(true);
  }
}

void doGithubOtaFlash(const char* version) {
  (void)version;
  if (!lbl_gh_status) return;

  lv_obj_t *overlay = lv_obj_create(lv_layer_top());
  lv_obj_set_size(overlay, 480, 320);
  lv_obj_set_pos(overlay, 0, 0);
  lv_obj_set_style_bg_color(overlay, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_bg_opa(overlay, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(overlay, 0, 0);
  lv_obj_set_style_pad_all(overlay, 0, 0);
  lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(overlay, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *ico = lv_label_create(overlay);
  lv_label_set_text(ico, LV_SYMBOL_DOWNLOAD);
  lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(ico, LV_ALIGN_CENTER, 0, -40);

  lv_obj_t *lbl_ov = lv_label_create(overlay);
  char buf_ov[64]; strncpy(buf_ov, T(STR_GH_OTA_FLASHING), sizeof(buf_ov)-1); buf_ov[sizeof(buf_ov)-1]=0;
  lv_label_set_text(lbl_ov, buf_ov);
  lv_obj_set_style_text_color(lbl_ov, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_ov, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(lbl_ov, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_ov, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *lbl_hint = lv_label_create(overlay);
  lv_label_set_text(lbl_hint, "~30-60 sec");
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_hint, LV_ALIGN_CENTER, 0, 30);

  lv_refr_now(NULL);
  lv_timer_handler();

  char buf[64]; strncpy(buf, T(STR_GH_OTA_FLASHING), sizeof(buf)-1); buf[sizeof(buf)-1]=0;
  lv_label_set_text(lbl_gh_status, buf);
  lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xf0b838), 0);
  if (btn_gh_update) lv_obj_add_flag(btn_gh_update, LV_OBJ_FLAG_HIDDEN);
  lv_timer_handler();

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;

  String url = "https://github.com/Niko11111/SpoolmanScale/releases/latest/download/SpoolmanScale.bin";
  http.begin(client, url);
  http.addHeader("User-Agent", "SpoolmanScale-ESP32");
  http.setTimeout(60000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

  int code = http.GET();
  Serial.printf("GitHub OTA download: %d\n", code);

  if (code != 200) {
    snprintf(buf, sizeof(buf), "%s (HTTP %d)", T(STR_GH_OTA_FLASH_FAIL), code);
    lv_label_set_text(lbl_gh_status, buf);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    http.end();
    return;
  }

  int len = http.getSize();
  WiFiClient* stream = http.getStreamPtr();

  if (!Update.begin(len > 0 ? len : UPDATE_SIZE_UNKNOWN)) {
    lv_label_set_text(lbl_gh_status, T(STR_GH_OTA_FLASH_FAIL));
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    http.end();
    return;
  }

  uint8_t buf8[512];
  while (http.connected() && (len > 0 || len == -1)) {
    size_t available = stream->available();
    if (available) {
      size_t toRead = min(available, sizeof(buf8));
      size_t rd = stream->readBytes(buf8, toRead);
      if (Update.write(buf8, rd) != rd) break;
      if (len > 0) len -= rd;
    }
    lv_timer_handler();
    delay(1);
  }
  http.end();

  if (Update.end(true) && !Update.hasError()) {
    char ok[64]; strncpy(ok, T(STR_GH_OTA_FLASH_OK), sizeof(ok)-1); ok[sizeof(ok)-1]=0;
    lv_label_set_text(lbl_gh_status, ok);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x40c080), 0);
    lv_timer_handler();
    delay(2000);
    ESP.restart();
  } else {
    char fail[64]; strncpy(fail, T(STR_GH_OTA_FLASH_FAIL), sizeof(fail)-1); fail[sizeof(fail)-1]=0;
    lv_label_set_text(lbl_gh_status, fail);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
  }
}

void showOtaGithubScreen() {
  logSD("SHOW: OtaGithubScreen");
  logSD("UI: Screen -> OTA GitHub");
  lbl_gh_status     = nullptr;
  lbl_gh_installed  = nullptr;
  lbl_gh_latest     = nullptr;
  btn_gh_update     = nullptr;
  lbl_gh_update_btn = nullptr;
  if (!update_available) gh_latest_version[0] = '\0';

  if (scr_ota_github) { lv_obj_del(scr_ota_github); scr_ota_github = nullptr; }
  buildOtaGithubScreen();
  hideAllOverlays();
  lv_obj_clear_flag(scr_ota_github, LV_OBJ_FLAG_HIDDEN);
}

void buildOtaGithubScreen() {
  logSD("BUILD: OtaGithubScreen");
  scr_ota_github = buildOverlayScreen();

  char buf_title[32];
  strncpy(buf_title, T(STR_GH_OTA_TITLE), sizeof(buf_title)-1); buf_title[sizeof(buf_title)-1]=0;
  buildSubHeader(scr_ota_github, buf_title,
    [](lv_event_t *e){ logSD("BTN: OtaGithub -> Back"); show_ota_pending = true; });

  lv_obj_t *btn_check = lv_btn_create(scr_ota_github);
  lv_obj_set_size(btn_check, 280, 44);
  lv_obj_align(btn_check, LV_ALIGN_TOP_MID, 0, 56);
  lv_obj_set_style_bg_color(btn_check, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_check, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_check, 8, 0);
  lv_obj_set_style_shadow_width(btn_check, 0, 0);
  lv_obj_set_style_border_width(btn_check, 1, 0);
  lv_obj_set_style_border_color(btn_check, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_check, [](lv_event_t *e){ doGithubOtaCheck(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_check = lv_label_create(btn_check);
  char buf_check[48]; strncpy(buf_check, T(STR_GH_OTA_CHECK_BTN), sizeof(buf_check)-1); buf_check[sizeof(buf_check)-1]=0;
  lv_label_set_text(lbl_check, buf_check);
  lv_obj_set_style_text_color(lbl_check, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_check, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_check, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_check, LV_ALIGN_CENTER, 0, 0);

  lbl_gh_status = lv_label_create(scr_ota_github);
  lv_label_set_text(lbl_gh_status, "");
  lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_gh_status, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_gh_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_gh_status, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_gh_status, 440);
  lv_obj_align(lbl_gh_status, LV_ALIGN_TOP_MID, 0, 112);

  lbl_gh_installed = lv_label_create(scr_ota_github);
  lv_label_set_text(lbl_gh_installed, "");
  lv_obj_set_style_text_color(lbl_gh_installed, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_gh_installed, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_gh_installed, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_gh_installed, LV_ALIGN_TOP_MID, 0, 148);
  lv_obj_add_flag(lbl_gh_installed, LV_OBJ_FLAG_HIDDEN);

  lbl_gh_latest = lv_label_create(scr_ota_github);
  lv_label_set_text(lbl_gh_latest, "");
  lv_obj_set_style_text_color(lbl_gh_latest, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_gh_latest, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_gh_latest, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_gh_latest, LV_ALIGN_TOP_MID, 0, 170);
  lv_obj_add_flag(lbl_gh_latest, LV_OBJ_FLAG_HIDDEN);

  lv_obj_t *btn_pre = lv_btn_create(scr_ota_github);
  lv_obj_set_size(btn_pre, 140, 48);
  lv_obj_align(btn_pre, LV_ALIGN_BOTTOM_LEFT, 12, -24);
  lv_obj_set_style_bg_color(btn_pre, gh_prerelease ? lv_color_hex(0x0a2040) : lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_bg_color(btn_pre, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_pre, 8, 0);
  lv_obj_set_style_shadow_width(btn_pre, 0, 0);
  lv_obj_set_style_border_width(btn_pre, 1, 0);
  lv_obj_set_style_border_color(btn_pre, gh_prerelease ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a2030), 0);
  lv_obj_add_event_cb(btn_pre, [](lv_event_t *e) {
    gh_prerelease = !gh_prerelease;
    prefsPutBoolInNamespace("spool", "gh_prerelease", gh_prerelease);
    if (scr_ota_github) { lv_obj_del(scr_ota_github); scr_ota_github = nullptr; }
    buildOtaGithubScreen();
    if (scr_ota_github) lv_obj_clear_flag(scr_ota_github, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_pre = lv_label_create(btn_pre);
  char pre_buf[32];
  snprintf(pre_buf, sizeof(pre_buf), "%s\n%s", T(STR_GH_OTA_PRERELEASE), gh_prerelease ? "[ ON ]" : "[ OFF ]");
  lv_label_set_text(lbl_pre, pre_buf);
  lv_obj_set_style_text_color(lbl_pre, gh_prerelease ? lv_color_hex(0x28d49a) : lv_color_hex(0x2a3848), 0);
  lv_obj_set_style_text_font(lbl_pre, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_pre, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_pre, LV_ALIGN_CENTER, 0, 0);

  btn_gh_update = lv_btn_create(scr_ota_github);
  lv_obj_set_size(btn_gh_update, 310, 48);
  lv_obj_align(btn_gh_update, LV_ALIGN_BOTTOM_RIGHT, -12, -24);
  lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x111820), 0);
  lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x111820), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_gh_update, 8, 0);
  lv_obj_set_style_shadow_width(btn_gh_update, 0, 0);
  lv_obj_set_style_border_width(btn_gh_update, 1, 0);
  lv_obj_set_style_border_color(btn_gh_update, lv_color_hex(0x1a2030), 0);
  lv_obj_add_state(btn_gh_update, LV_STATE_DISABLED);
  lv_obj_add_event_cb(btn_gh_update, [](lv_event_t *e){
    doGithubOtaFlash(gh_latest_version);
  }, LV_EVENT_CLICKED, NULL);

  lbl_gh_update_btn = lv_label_create(btn_gh_update);
  char buf_ubtn[48]; strncpy(buf_ubtn, T(STR_GH_OTA_UPDATE_BTN), sizeof(buf_ubtn)-1); buf_ubtn[sizeof(buf_ubtn)-1]=0;
  lv_label_set_text(lbl_gh_update_btn, buf_ubtn);
  lv_obj_set_style_text_color(lbl_gh_update_btn, lv_color_hex(0x2a3848), 0);
  lv_obj_set_style_text_font(lbl_gh_update_btn, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_gh_update_btn, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_gh_update_btn, LV_ALIGN_CENTER, 0, 0);

  if (update_available && gh_latest_version[0] != '\0') {
    lv_obj_clear_state(btn_gh_update, LV_STATE_DISABLED);
    lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x1a3020), 0);
    lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(btn_gh_update, lv_color_hex(0x28d49a), 0);
    char ubtn2[48]; strncpy(ubtn2, T(STR_GH_OTA_UPDATE_BTN), sizeof(ubtn2)-1); ubtn2[sizeof(ubtn2)-1]=0;
    lv_label_set_text(lbl_gh_update_btn, ubtn2);
    lv_obj_set_style_text_color(lbl_gh_update_btn, lv_color_hex(0x40c080), 0);
    char avail[64]; snprintf(avail, sizeof(avail), T(STR_GH_OTA_UPDATE_AVAIL), gh_latest_version);
    lv_label_set_text(lbl_gh_status, avail);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xf0b838), 0);
    char inst[48]; snprintf(inst, sizeof(inst), T(STR_GH_OTA_INSTALLED), FW_VERSION);
    lv_label_set_text(lbl_gh_installed, inst);
    lv_obj_clear_flag(lbl_gh_installed, LV_OBJ_FLAG_HIDDEN);
    char lat[48]; snprintf(lat, sizeof(lat), T(STR_GH_OTA_LATEST), gh_latest_version);
    lv_label_set_text(lbl_gh_latest, lat);
    lv_obj_clear_flag(lbl_gh_latest, LV_OBJ_FLAG_HIDDEN);
  }
}
