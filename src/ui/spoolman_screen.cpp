#include "spoolman_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "connection_screen.h"
#include "extra_fields_screen.h"
#include "ota_browser.h"
#include "hardware/sd_logger.h"
#include "services/app_settings.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/bambuddy_api.h"
#include "header_status.h"
#include "services/mdns_service.h"
#include "services/wifi_manager.h"
#include "web/web_access.h"
#include "confirm_popup.h"
#include "lang.h"
#include "ui_common.h"



// Input buffer for Spoolman IP
static char sp_ip_input[64] = "";
// What the field held when the screen opened. The back button used to write
// unconditionally, so merely opening the screen and leaving it rewrote NVS -
// and on a host name a single stray tap appended a digit to it.
static char sp_ip_original[64] = "";
// True when the stored address cannot be typed on this screen.
static bool sp_locked = false;

// Every character the twelve key pad can produce. An empty host counts as
// numeric: there is nothing to protect yet, and the pad is the right tool.
//
// The address field is a plain string shared with the browser, and the browser
// has a real keyboard - it even advertises host names, because a reverse proxy
// tells its backends apart by the Host header. A name that arrives that way
// cannot be edited here, only damaged.
static bool hostIsNumeric(const char* h) {
  if (!h) return true;
  for (; *h; h++)
    if (!((*h >= '0' && *h <= '9') || *h == '.' || *h == ':')) return false;
  return true;
}

// Where to go to change it. Same cascade as the web screen (web_screen.cpp),
// because pointing at an address that does not answer is worse than saying
// which switch is off.
static void browserAddress(char* out, size_t len) {
  if (!webMasterEnabled())  { strncpy(out, T(STR_SP_WEB_OFF), len - 1); }
  else if (!wifi_ok)        { strncpy(out, T(STR_WIFI_STATUS_DISCONNECTED), len - 1); }
  else if (mdnsRunning())   { snprintf(out, len, "http://%s.local", mdnsHostname()); return; }
  else                      { snprintf(out, len, "http://%s",
                                       wifiManagerLocalIP().toString().c_str()); return; }
  out[len - 1] = '\0';
}

void spoolmanClearHost() {
  logSDf("Backend: address cleared on the device (was %s)", backendHost());
  backendSetHost("");
  sp_ip_input[0] = '\0';
  show_spoolman_pending = true;   // rebuilt one loop pass later, never here
}
static lv_obj_t *lbl_sp_ip_display = nullptr;
static lv_obj_t *lbl_sp_test_result = nullptr;  // test result label on IP screen
static lv_obj_t *btn_sp_extra_fields = nullptr;  // Extra Fields button on IP screen

void buildSpoolmanScreen() {
  logSD("BUILD: SpoolmanScreen");
  // This is the most object-heavy screen in the project (numpad + header,
  // ~40 LVGL objects). Log the LVGL pool state before allocating so an
  // exhausted pool is visible in the log instead of an unexplained halt.
  if (sd_verbose) {
    lv_mem_monitor_t lv_mem;
    lv_mem_monitor(&lv_mem);
    logSDf("[verbose] buildSpoolmanScreen: lv_free=%u lv_biggest=%u lv_used=%u%%",
      (unsigned)lv_mem.free_size, (unsigned)lv_mem.free_biggest_size,
      (unsigned)lv_mem.used_pct);
  }
  releaseScreen(&scr_spoolman);
  scr_spoolman = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_spoolman, 480, 320);
  lv_obj_set_pos(scr_spoolman, 0, 0);
  lv_obj_add_flag(scr_spoolman, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_spoolman, 0, 0);
  lv_obj_set_style_border_width(scr_spoolman, 0, 0);
  lv_obj_set_style_pad_all(scr_spoolman, 0, 0);
  lv_obj_clear_flag(scr_spoolman, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_spoolman, lv_color_hex(0x0a1020), 0);

  sp_locked = !hostIsNumeric(backendHost());

  // Header. The product name is not translated, so it is composed here
  // instead of living in lang.cpp twice.
  char buf_title[32];
  snprintf(buf_title, sizeof(buf_title), "%s Server", backendName());
  buildSubHeader(scr_spoolman, buf_title,
    [](lv_event_t *e){
      logSD("BTN: Spoolman -> Back");
      // Only on a real change. Writing whatever the field happens to hold
      // turned a look into an edit, which is how one tap could append a
      // digit to a host name and make it unresolvable.
      if (sp_ip_input[0] && strcmp(sp_ip_input, sp_ip_original) != 0)
        backendSetHost(sp_ip_input);
      // Return to wherever we came from. The Backend screen exists only
      // when the user navigated through it, the setup flow does not.
      if (scr_backend) show_backend_pending = true;
      else             show_connection_from_spoolman_pending = true;
    });

  // Hint: default port of the active backend, font14, y=52. Only a hint,
  // nothing is appended - an address typed without a port goes to 80.
  const char* def_port = (backendMode() == BACKEND_FILAMAN)  ? "8002"
                       : (backendMode() == BACKEND_BAMBUDDY) ? "8000"
                                                             : "7912";
  char buf_hint[48];
  if (sp_locked) {
    strncpy(buf_hint, T(STR_SP_LOCKED_TITLE), sizeof(buf_hint) - 1);
    buf_hint[sizeof(buf_hint) - 1] = '\0';
  } else {
    snprintf(buf_hint, sizeof(buf_hint), "192.168.x.x:%s", def_port);
  }
  lv_obj_t *lbl_hint = lv_label_create(scr_spoolman);
  lv_label_set_text(lbl_hint, buf_hint);
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(sp_locked ? 0xf0b838 : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 52);

  // Pre-fill with "192.168." if empty — user only needs to add last two octets + port
  const char* cur_host = backendHost();
  if (!cur_host || cur_host[0] == '\0') {
    strncpy(sp_ip_input, "192.168.", sizeof(sp_ip_input)-1);
  } else {
    strncpy(sp_ip_input, cur_host, sizeof(sp_ip_input)-1);
  }
  sp_ip_input[sizeof(sp_ip_input)-1] = '\0';
  strncpy(sp_ip_original, sp_ip_input, sizeof(sp_ip_original) - 1);
  sp_ip_original[sizeof(sp_ip_original)-1] = '\0';

  lv_obj_t *input_box = lv_obj_create(scr_spoolman);
  lv_obj_set_size(input_box, 420, 34);
  lv_obj_align(input_box, LV_ALIGN_TOP_MID, 0, 68);
  lv_obj_set_style_bg_color(input_box, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_border_color(input_box, lv_color_hex(sp_locked ? 0xf0b838 : 0x28d49a), 0);
  lv_obj_set_style_border_width(input_box, 1, 0);
  lv_obj_set_style_radius(input_box, 6, 0);
  lv_obj_set_style_pad_all(input_box, 0, 0);
  lv_obj_clear_flag(input_box, LV_OBJ_FLAG_SCROLLABLE);

  lbl_sp_ip_display = lv_label_create(input_box);
  lv_label_set_text(lbl_sp_ip_display, sp_ip_input[0] ? sp_ip_input : "_");
  lv_obj_set_style_text_color(lbl_sp_ip_display, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_sp_ip_display, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(lbl_sp_ip_display, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(lbl_sp_ip_display);

  // Numpad: NP_H=32, NP_GAP=3, start y=104 — larger than before
  const int NP_W = 130, NP_H = 32, NP_GAP = 3;
  const int NP_PAD_X = (480 - 3*NP_W - 2*NP_GAP) / 2;
  const int NP_START_Y = 104;

  if (sp_locked) {
    // No pad at all rather than a disabled one. A pad that is visible but does
    // nothing reads as a broken screen; this says what the address is, why it
    // cannot be edited here, and where it can be.
    lv_obj_t *lbl_why = lv_label_create(scr_spoolman);
    lv_obj_set_width(lbl_why, 440);
    lv_label_set_long_mode(lbl_why, LV_LABEL_LONG_WRAP);
    char buf_why[128];
    strncpy(buf_why, T(STR_SP_LOCKED_INFO), sizeof(buf_why) - 1);
    buf_why[sizeof(buf_why) - 1] = '\0';
    lv_label_set_text(lbl_why, buf_why);
    lv_obj_set_style_text_color(lbl_why, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(lbl_why, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl_why, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_why, LV_ALIGN_TOP_MID, 0, 118);

    char buf_addr[64];
    browserAddress(buf_addr, sizeof(buf_addr));
    lv_obj_t *lbl_addr = lv_label_create(scr_spoolman);
    lv_obj_set_width(lbl_addr, 440);
    lv_label_set_long_mode(lbl_addr, LV_LABEL_LONG_WRAP);
    lv_label_set_text(lbl_addr, buf_addr);
    lv_obj_set_style_text_color(lbl_addr, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_addr, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_addr, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_addr, LV_ALIGN_TOP_MID, 0, 172);

    // The escape hatch. Without it a typo made in the browser cannot be
    // undone from the device at all, because the pad has no letters.
    lv_obj_t *btn_clear = lv_btn_create(scr_spoolman);
    lv_obj_set_size(btn_clear, 200, 44);
    lv_obj_align(btn_clear, LV_ALIGN_TOP_MID, 0, 222);
    lv_obj_set_style_bg_color(btn_clear, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_clear, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_clear, 8, 0);
    lv_obj_set_style_shadow_width(btn_clear, 0, 0);
    lv_obj_set_style_border_width(btn_clear, 1, 0);
    lv_obj_set_style_border_color(btn_clear, lv_color_hex(0x602020), 0);
    lv_obj_add_event_cb(btn_clear, [](lv_event_t *e) {
      // Asks, then acts one loop pass later. Nothing is deleted from inside
      // this callback.
      showConfirmPopup(T(STR_SP_CLEAR_ASK), 4);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_clear = lv_label_create(btn_clear);
    char buf_clear[32];
    strncpy(buf_clear, T(STR_SP_CLEAR), sizeof(buf_clear) - 1);
    buf_clear[sizeof(buf_clear) - 1] = '\0';
    lv_label_set_text(lbl_clear, buf_clear);
    lv_obj_set_style_text_color(lbl_clear, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_clear, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_clear);
  } else {

  const char* np_labels[] = {
    "1","2","3",
    "4","5","6",
    "7","8","9",
    ".","0",":"
  };

  for (int i = 0; i < 12; i++) {
    int col = i % 3;
    int row = i / 3;
    int bx = NP_PAD_X + col * (NP_W + NP_GAP);
    int by = NP_START_Y + row * (NP_H + NP_GAP);

    lv_obj_t *btn = lv_btn_create(scr_spoolman);
    lv_obj_set_size(btn, NP_W, NP_H);
    lv_obj_set_pos(btn, bx, by);
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn, 6, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_set_style_border_width(btn, 1, 0);
    lv_obj_set_style_border_color(btn, lv_color_hex(0x1a2840), 0);

    lv_obj_t *lbl = lv_label_create(btn);
    lv_label_set_text(lbl, np_labels[i]);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl);

    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      const char* ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
      int len = strlen(sp_ip_input);
      if (len < (int)sizeof(sp_ip_input)-1) {
        sp_ip_input[len] = ch[0];
        sp_ip_input[len+1] = '\0';
      }
      if (lbl_sp_ip_display) lv_label_set_text(lbl_sp_ip_display, sp_ip_input);
    }, LV_EVENT_CLICKED, NULL);
  }

  // Row 5 left: delete
  int by5 = NP_START_Y + 4 * (NP_H + NP_GAP);
  int bw5 = (3*NP_W + 2*NP_GAP - NP_GAP) / 2;

  lv_obj_t *btn_del = lv_btn_create(scr_spoolman);
  lv_obj_set_size(btn_del, bw5, NP_H);
  lv_obj_set_pos(btn_del, NP_PAD_X, by5);
  lv_obj_set_style_bg_color(btn_del, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_del, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_del, 6, 0);
  lv_obj_set_style_shadow_width(btn_del, 0, 0);
  lv_obj_set_style_border_width(btn_del, 1, 0);
  lv_obj_set_style_border_color(btn_del, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_del, [](lv_event_t *e) {
    int len = strlen(sp_ip_input);
    if (len > 0) sp_ip_input[len-1] = '\0';
    if (lbl_sp_ip_display) lv_label_set_text(lbl_sp_ip_display, sp_ip_input[0] ? sp_ip_input : "_");
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_del = lv_label_create(btn_del);
  lv_label_set_text(lbl_del, LV_SYMBOL_BACKSPACE);
  lv_obj_set_style_text_color(lbl_del, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_del, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_del);

  // Row 5 right: save
  lv_obj_t *btn_ok = lv_btn_create(scr_spoolman);
  lv_obj_set_size(btn_ok, bw5, NP_H);
  lv_obj_set_pos(btn_ok, NP_PAD_X + bw5 + NP_GAP, by5);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok, 6, 0);
  lv_obj_set_style_shadow_width(btn_ok, 0, 0);
  lv_obj_set_style_border_width(btn_ok, 1, 0);
  lv_obj_set_style_border_color(btn_ok, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_ok, [](lv_event_t *e) {
    if (!sp_ip_input[0]) return;
    backendSetHost(sp_ip_input);

    // Show testing status
    if (lbl_sp_test_result) {
      lv_label_set_text(lbl_sp_test_result, "Connecting...");
      lv_obj_set_style_text_color(lbl_sp_test_result, lv_color_hex(0x4a6fa0), 0);
    }
    if (btn_sp_extra_fields) lv_obj_add_flag(btn_sp_extra_fields, LV_OBJ_FLAG_HIDDEN);
    lv_timer_handler();

    // Health check
    int hcode = backendGetHealthCode(cfg_spoolman_base, 4000);
    sm_reachable = (hcode == 200);

    if (!sm_reachable) {
      if (lbl_sp_test_result) {
        char buf[48];
        snprintf(buf, sizeof(buf), "Error: HTTP %d", hcode);
        lv_label_set_text(lbl_sp_test_result, buf);
        lv_obj_set_style_text_color(lbl_sp_test_result, lv_color_hex(0xff8080), 0);
      }
      logSDf("Spoolman IP test FAIL: HTTP %d ip=%s", hcode, sp_ip_input);
      Serial.printf("Spoolman IP test FAIL: HTTP %d ip=%s\n", hcode, sp_ip_input);
      return;
    }

    // BamBuddy needs to be asked where its inventory lives before anything
    // else is read. Placed after the health check so a wrong address fails
    // on the check rather than here.
    backendAfterConnect();

    // Fetch version from /api/v1/info
    char sm_ver[32] = "?";
    backendGetVersion(cfg_spoolman_base, sm_ver, sizeof(sm_ver), 3000);

    int spool_count = backendCountActiveSpools(cfg_spoolman_base, 6000);

    // A negative count means the question could not be answered, not that
    // there are no spools. In FilaMan that is the normal case during setup,
    // because counting needs the API key and it is entered a step later.
    // Printing "0 spools" there would look like an empty database.
    // Which database BamBuddy is on decides which half of the client runs,
    // so it belongs on screen and not only in the log. The two names are the
    // ones BamBuddy uses itself under Settings > Filament Tracking. Empty for
    // the other backends, where there is nothing to choose between.
    char inv_buf[32] = "";
    if (backendIsBamBuddy()) {
      char inv_name[24];
      strncpy(inv_name, T(bbInventoryMode() == BB_INV_SPOOLMAN ? STR_BB_INV_SPOOLMAN
                                                               : STR_BB_INV_OWN),
              sizeof(inv_name) - 1);
      inv_name[sizeof(inv_name) - 1] = '\0';
      snprintf(inv_buf, sizeof(inv_buf), "%s | ", inv_name);
    }

    char result_buf[96];
    if (spool_count < 0) {
      char conn_buf[24];
      strncpy(conn_buf, T(STR_CONNECTED), sizeof(conn_buf) - 1);
      conn_buf[sizeof(conn_buf) - 1] = '\0';
      snprintf(result_buf, sizeof(result_buf), "v%s | %s%s", sm_ver, inv_buf, conn_buf);
    } else {
      snprintf(result_buf, sizeof(result_buf), "v%s | %s%d spools",
               sm_ver, inv_buf, spool_count);
    }
    if (lbl_sp_test_result) {
      lv_label_set_text(lbl_sp_test_result, result_buf);
      lv_obj_set_style_text_color(lbl_sp_test_result, lv_color_hex(0x40c080), 0);
    }
    // Reveal the button again. In FilaMan and BamBuddy it only leads
    // somewhere during the setup, where it is the step to the credentials.
    if (btn_sp_extra_fields && (setup_active || backendMode() == BACKEND_SPOOLMAN)) {
      lv_obj_clear_flag(btn_sp_extra_fields, LV_OBJ_FLAG_HIDDEN);
    }

    logSDf("Spoolman IP test OK: %s | %d spools", sm_ver, spool_count);
    Serial.printf("Spoolman IP test OK: %s | %d spools\n", sm_ver, spool_count);
    updateHeaderStatus();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok = lv_label_create(btn_ok);
  lv_label_set_text(lbl_ok, T(STR_BTN_SAVE));
  lv_obj_set_style_text_color(lbl_ok, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_ok, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_ok);

  }   // end of the numeric pad

  // Bottom area: test result info (left) + Extra Fields button (right)
  // numpad bottom = NP_START_Y + 4*(NP_H+NP_GAP) + NP_H = 104+4*35+32 = 276
  // bottom row y=281, h=32, bottom=313 (7px margin)
  const int BOT_Y = 281, BOT_H = 32;

  // Test result label — left side, y=281
  lbl_sp_test_result = lv_label_create(scr_spoolman);
  lv_label_set_text(lbl_sp_test_result, "");
  lv_obj_set_style_text_color(lbl_sp_test_result, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sp_test_result, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_sp_test_result, LV_TEXT_ALIGN_LEFT, 0);
  lv_obj_set_size(lbl_sp_test_result, 260, BOT_H);
  lv_obj_set_pos(lbl_sp_test_result, NP_PAD_X, BOT_Y);

  // Extra Fields button — right side, 170px wide
  btn_sp_extra_fields = lv_btn_create(scr_spoolman);
  lv_obj_set_size(btn_sp_extra_fields, 170, BOT_H);
  lv_obj_set_pos(btn_sp_extra_fields, 480 - NP_PAD_X - 170, BOT_Y);
  lv_obj_set_style_bg_color(btn_sp_extra_fields, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_sp_extra_fields, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_sp_extra_fields, 8, 0);
  lv_obj_set_style_shadow_width(btn_sp_extra_fields, 0, 0);
  lv_obj_set_style_border_width(btn_sp_extra_fields, 1, 0);
  lv_obj_set_style_border_color(btn_sp_extra_fields, lv_color_hex(0x1a3060), 0);
  // This button doubles as the step onward during setup, which is why it
  // starts hidden there and only appears once the connection test passed.
  // FilaMan needs no extra fields at all, it accepts custom_fields keys
  // without a prior definition, and BamBuddy has a fixed schema, so outside
  // the setup neither has anything to do here.
  if (setup_active || backendMode() != BACKEND_SPOOLMAN) {
    lv_obj_add_flag(btn_sp_extra_fields, LV_OBJ_FLAG_HIDDEN);
  }
  lv_obj_add_event_cb(btn_sp_extra_fields, [](lv_event_t *e) {
    if (backendMode() != BACKEND_SPOOLMAN) {
      // Next comes the credential step, and those are entered in a browser.
      showOtaBrowserScreen(WEB_CTX_SETUP);
    } else {
      showExtraFieldsScreen(setup_active);
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ef = lv_label_create(btn_sp_extra_fields);
  { char ef_buf[32];
    if (backendMode() != BACKEND_SPOOLMAN) snprintf(ef_buf, sizeof(ef_buf), "%s  " LV_SYMBOL_RIGHT, T(STR_BTN_NEXT));
    else                                   snprintf(ef_buf, sizeof(ef_buf), "Extra Fields  " LV_SYMBOL_RIGHT);
    lv_label_set_text(lbl_ef, ef_buf); }
  lv_obj_set_style_text_color(lbl_ef, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_ef, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(lbl_ef, LV_ALIGN_CENTER, 0, 0);
}

// ============================================================
//  SPOOLMAN CONNECTION FAILED SCREEN
// ============================================================
void showSpoolmanFailScreen(bool is_setup_flow) {
  logSD("SHOW: SpoolmanFailScreen");
  logSDf("UI: Screen -> SpoolmanFail (setup=%d)", is_setup_flow ? 1 : 0);
  spoolman_fail_is_setup = is_setup_flow;
  hideAllOverlays();
  if (scr_spoolman_fail) { lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }

  // Copy all strings to RAM buffers — T() returns Flash pointers which LVGL can't read directly
  char buf_title[32], buf_msg[96], buf_retry[48], buf_skip[48];
  backendText(T(STR_SPOOLMAN_TITLE), buf_title, sizeof(buf_title));
  backendText(T(STR_SPOOLMAN_FAIL), buf_msg, sizeof(buf_msg));
  strncpy(buf_retry, T(STR_SPOOLMAN_RETRY), sizeof(buf_retry)-1); buf_retry[sizeof(buf_retry)-1]=0;
  strncpy(buf_skip,  T(STR_SPOOLMAN_SKIP),  sizeof(buf_skip)-1);  buf_skip[sizeof(buf_skip)-1]=0;

  scr_spoolman_fail = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_spoolman_fail, 480, 320);
  lv_obj_set_pos(scr_spoolman_fail, 0, 0);
  lv_obj_set_style_radius(scr_spoolman_fail, 0, 0);
  lv_obj_set_style_border_width(scr_spoolman_fail, 0, 0);
  lv_obj_set_style_pad_all(scr_spoolman_fail, 0, 0);
  lv_obj_clear_flag(scr_spoolman_fail, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_spoolman_fail, lv_color_hex(0x0a1020), 0);

  // Title
  lv_obj_t *lbl_title = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_title, buf_title);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 20);

  // Back → Spoolman IP
  addBackButton(scr_spoolman_fail, [](lv_event_t *e){
    logSD("BTN: SpoolmanFail -> Back");
    show_spoolman_pending = true;
    // pending handler will delete scr_spoolman_fail via hideAllOverlays + recreate spoolman
  });
  addCloseButton(scr_spoolman_fail);

  // Warning icon
  lv_obj_t *lbl_icon = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_icon, LV_SYMBOL_WARNING);
  lv_obj_set_style_text_color(lbl_icon, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_icon, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_icon, LV_ALIGN_TOP_MID, 0, 60);

  // IP entered
  char ip_buf[80];
  snprintf(ip_buf, sizeof(ip_buf), "http://%s", cfg_spoolman_ip);
  lv_obj_t *lbl_ip = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_ip, ip_buf);
  lv_obj_set_style_text_color(lbl_ip, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_ip, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_ip, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_ip, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_ip, 440);
  lv_obj_align(lbl_ip, LV_ALIGN_TOP_MID, 0, 96);

  // Error message (from RAM buffer)
  lv_obj_t *lbl_msg = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_msg, buf_msg);
  lv_obj_set_style_text_color(lbl_msg, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_msg, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_msg, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_msg, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_msg, 440);
  lv_obj_align(lbl_msg, LV_ALIGN_TOP_MID, 0, 128);

  // Change IP button (left)
  lv_obj_t *btn_retry = lv_btn_create(scr_spoolman_fail);
  lv_obj_set_size(btn_retry, 210, 50);
  lv_obj_set_pos(btn_retry, 16, 248);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_retry, 8, 0);
  lv_obj_set_style_shadow_width(btn_retry, 0, 0);
  lv_obj_set_style_border_width(btn_retry, 0, 0);
  lv_obj_add_event_cb(btn_retry, [](lv_event_t *e){
    logSD("BTN: SpoolmanFail -> Retry");
    show_spoolman_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_r = lv_label_create(btn_retry);
  lv_label_set_text(lbl_r, buf_retry);
  lv_obj_set_style_text_color(lbl_r, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_r, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_r);

  // Continue anyway button (right)
  lv_obj_t *btn_cont = lv_btn_create(scr_spoolman_fail);
  lv_obj_set_size(btn_cont, 210, 50);
  lv_obj_set_pos(btn_cont, 254, 248);
  lv_obj_set_style_bg_color(btn_cont, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_cont, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cont, 8, 0);
  lv_obj_set_style_shadow_width(btn_cont, 0, 0);
  lv_obj_set_style_border_width(btn_cont, 0, 0);
  lv_obj_add_event_cb(btn_cont, [](lv_event_t *e){
    // Delete this screen first to avoid it being accessed during navigation
    if (scr_spoolman_fail) { lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
    if (spoolman_fail_is_setup) {
      showExtraFieldsScreen(true);
    } else {
      if (scr_connection) { lv_obj_del(scr_connection); scr_connection = nullptr; }
      buildConnectionScreen();
      if (!scr_connection) buildConnectionScreen(); hideAllOverlays(); lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_c = lv_label_create(btn_cont);
  lv_label_set_text(lbl_c, buf_skip);
  lv_obj_set_style_text_color(lbl_c, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_c, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_c);
}
