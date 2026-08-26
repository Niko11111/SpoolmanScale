#include "extra_fields_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "services/backend_api.h"
#include "lang.h"
#include "ui_common.h"
#include "services/backend.h"
#include "theme.h"



static lv_obj_t *lbl_extra_fields_status = nullptr;
static lv_obj_t *btn_extra_fields_create = nullptr;
static lv_obj_t *btn_extra_fields_next   = nullptr;
static bool extra_fields_setup_flow = false;
static bool extra_fields_check_pending = false;
static bool extra_fields_create_pending = false;

void resetExtraFieldsScreenState() {
  lbl_extra_fields_status = nullptr;
  btn_extra_fields_create = nullptr;
  btn_extra_fields_next = nullptr;
  extra_fields_setup_flow = false;
  extra_fields_check_pending = false;
  extra_fields_create_pending = false;
}

void handleExtraFieldsDeferredActions() {
  if (extra_fields_check_pending) {
    extra_fields_check_pending = false;
    checkAndCreateExtraFields(false);
  }
  if (extra_fields_create_pending) {
    extra_fields_create_pending = false;
    checkAndCreateExtraFields(true);
  }
}

// ============================================================
//  EXTRA FIELDS SCREEN
//  Check/create Spoolman extra fields 'tag' and 'last_dried'
// ============================================================

// Required extra fields — extend this array for future fields
static const char* REQUIRED_EXTRA_FIELDS_BASE[] = { "tag", "last_dried" };
static const int   REQUIRED_EXTRA_FIELDS_BASE_COUNT = 2;

void showExtraFieldsScreen(bool is_setup_flow) {
  logSD("SHOW: ExtraFieldsScreen");
  logSDf("UI: Screen -> ExtraFields (setup=%d)", is_setup_flow ? 1 : 0);
  hideAllOverlays();
  extra_fields_setup_flow = is_setup_flow;
  if (scr_extra_fields) { lv_obj_del(scr_extra_fields); scr_extra_fields = nullptr; }
  lbl_extra_fields_status = nullptr;
  btn_extra_fields_create = nullptr;
  btn_extra_fields_next   = nullptr;
  buildExtraFieldsScreen(is_setup_flow);
  lv_obj_clear_flag(scr_extra_fields, LV_OBJ_FLAG_HIDDEN);
}

void buildExtraFieldsScreen(bool is_setup_flow) {
  logSD("BUILD: ExtraFieldsScreen");
  releaseScreen(&scr_extra_fields);
  scr_extra_fields = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_extra_fields, 480, 320);
  lv_obj_set_pos(scr_extra_fields, 0, 0);
  lv_obj_add_flag(scr_extra_fields, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_extra_fields, 0, 0);
  lv_obj_set_style_border_width(scr_extra_fields, 0, 0);
  lv_obj_set_style_pad_all(scr_extra_fields, 0, 0);
  lv_obj_clear_flag(scr_extra_fields, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_extra_fields, tc(TH_BG), 0);

  // Header: back returns to the filament manager screen, which is where this
  // screen is now reached from. Setup flow gets a title and an X instead.
  if (!is_setup_flow) {
    char hdr_b[40]; backendText(T(STR_EXTRA_FIELDS_TITLE), hdr_b, sizeof(hdr_b));
    buildSubHeader(scr_extra_fields, hdr_b,
      [](lv_event_t *e) {
        // Deferred: the backend screen is built from appLoop(), never from
        // inside the callback of the screen it is about to replace.
        show_backend_pending = true;
      });
  } else {
    // Setup flow: title only + X (→ main screen), no back button
    lv_obj_t *lbl_title = lv_label_create(scr_extra_fields);
    { char tb[40]; backendText(T(STR_EXTRA_FIELDS_TITLE), tb, sizeof(tb)); lv_label_set_text(lbl_title, tb); }
    lv_obj_set_style_text_color(lbl_title, tc(TH_ACCENT), 0);
    lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

    // X → main screen (exit setup)
    lv_obj_t *btn_x = lv_btn_create(scr_extra_fields);
    lv_obj_set_size(btn_x, 44, 44);
    lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
    lv_obj_set_style_bg_color(btn_x, tc(TH_DANGER_BG), 0);
    lv_obj_set_style_bg_color(btn_x, tc(TH_DANGER_PRESSED), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_x, 8, 0);
    lv_obj_set_style_shadow_width(btn_x, 0, 0);
    lv_obj_set_style_border_width(btn_x, 0, 0);
    lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_x = lv_label_create(btn_x);
    lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(lbl_x, tc(TH_DANGER_TEXT), 0);
    lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl_x);
  }

  // Hint text
  lv_obj_t *lbl_hint = lv_label_create(scr_extra_fields);
  lv_label_set_text(lbl_hint, T(STR_EXTRA_FIELDS_HINT));
  lv_obj_set_style_text_color(lbl_hint, tc(TH_TEXT_MUTED), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, 440);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 54);

  // Check button
  lv_obj_t *btn_check = lv_btn_create(scr_extra_fields);
  lv_obj_set_size(btn_check, 280, 44);
  lv_obj_align(btn_check, LV_ALIGN_TOP_MID, 0, 138);
  lv_obj_set_style_bg_color(btn_check, tc(TH_TILE_BG), 0);
  lv_obj_set_style_bg_color(btn_check, tc(TH_BORDER), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_check, 8, 0);
  lv_obj_set_style_shadow_width(btn_check, 0, 0);
  lv_obj_set_style_border_width(btn_check, 1, 0);
  lv_obj_set_style_border_color(btn_check, tc(TH_SURFACE_2), 0);
  lv_obj_add_event_cb(btn_check, [](lv_event_t *e) {
    extra_fields_check_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_check = lv_label_create(btn_check);
  lv_label_set_text(lbl_check, T(STR_EXTRA_FIELDS_CHECK_BTN));
  lv_obj_set_style_text_color(lbl_check, tc(TH_TEXT), 0);
  lv_obj_set_style_text_font(lbl_check, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_check);

  // Status label — below check button
  lbl_extra_fields_status = lv_label_create(scr_extra_fields);
  lv_label_set_text(lbl_extra_fields_status, "");
  lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_TEXT), 0);
  lv_obj_set_style_text_font(lbl_extra_fields_status, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_extra_fields_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_extra_fields_status, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_extra_fields_status, 440);
  lv_obj_align(lbl_extra_fields_status, LV_ALIGN_TOP_MID, 0, 192);

  // Create missing fields button — full width, above bottom row, initially hidden
  btn_extra_fields_create = lv_btn_create(scr_extra_fields);
  lv_obj_set_size(btn_extra_fields_create, 440, 42);
  lv_obj_align(btn_extra_fields_create, LV_ALIGN_TOP_MID, 0, 228);
  lv_obj_set_style_bg_color(btn_extra_fields_create, tc(TH_OK_BG), 0);
  lv_obj_set_style_bg_color(btn_extra_fields_create, tc(TH_SUCCESS_BG), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_extra_fields_create, 8, 0);
  lv_obj_set_style_shadow_width(btn_extra_fields_create, 0, 0);
  lv_obj_set_style_border_width(btn_extra_fields_create, 1, 0);
  lv_obj_set_style_border_color(btn_extra_fields_create, tc(TH_SUCCESS_BG), 0);
  lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
  lv_obj_add_event_cb(btn_extra_fields_create, [](lv_event_t *e) {
    // Confirmation popup
    lv_obj_t *pop = lv_obj_create(lv_scr_act());
    lv_obj_set_size(pop, 480, 320);
    lv_obj_set_pos(pop, 0, 0);
    lv_obj_set_style_bg_color(pop, lv_color_hex(0x00000080), 0);  // semi-transparent
    lv_obj_set_style_bg_opa(pop, LV_OPA_70, 0);
    lv_obj_set_style_border_width(pop, 0, 0);
    lv_obj_set_style_radius(pop, 0, 0);
    lv_obj_set_style_pad_all(pop, 0, 0);
    lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *box = lv_obj_create(pop);
    lv_obj_set_size(box, 420, 220);
    lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_bg_color(box, lv_color_hex(0x0d1a2a), 0);
    lv_obj_set_style_border_color(box, tc(TH_SURFACE_2), 0);
    lv_obj_set_style_border_width(box, 1, 0);
    lv_obj_set_style_radius(box, 10, 0);
    lv_obj_set_style_pad_all(box, 0, 0);
    lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *lbl_ct = lv_label_create(box);
    lv_label_set_text(lbl_ct, T(STR_EXTRA_FIELDS_CONFIRM_TITLE));
    lv_obj_set_style_text_color(lbl_ct, tc(TH_ACCENT), 0);
    lv_obj_set_style_text_font(lbl_ct, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_ct, LV_ALIGN_TOP_MID, 0, 18);

    lv_obj_t *lbl_cm = lv_label_create(box);
    lv_label_set_text(lbl_cm, T(STR_EXTRA_FIELDS_CONFIRM_MSG));
    lv_obj_set_style_text_color(lbl_cm, tc(TH_TEXT), 0);
    lv_obj_set_style_text_font(lbl_cm, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl_cm, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(lbl_cm, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(lbl_cm, 380);
    lv_obj_align(lbl_cm, LV_ALIGN_TOP_MID, 0, 52);

    // Confirm button
    lv_obj_t *btn_conf = lv_btn_create(box);
    lv_obj_set_size(btn_conf, 180, 44);
    lv_obj_align(btn_conf, LV_ALIGN_BOTTOM_RIGHT, -12, -12);
    lv_obj_set_style_bg_color(btn_conf, tc(TH_OK_BG), 0);
    lv_obj_set_style_bg_color(btn_conf, tc(TH_SUCCESS_BG), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_conf, 8, 0);
    lv_obj_set_style_shadow_width(btn_conf, 0, 0);
    lv_obj_set_style_border_width(btn_conf, 0, 0);
    lv_obj_add_event_cb(btn_conf, [](lv_event_t *e) {
      // Close popup (2 levels up: btn -> box -> pop)
      lv_obj_t *box_obj = lv_obj_get_parent(lv_event_get_target(e));
      lv_obj_t *pop_obj = lv_obj_get_parent(box_obj);
      lv_obj_del(pop_obj);
      // Defer HTTP call to loop — never call HTTP directly from LVGL event callback
      extra_fields_create_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_conf = lv_label_create(btn_conf);
    lv_label_set_text(lbl_conf, T(STR_CONFIRM));
    lv_obj_set_style_text_color(lbl_conf, tc(TH_SUCCESS_TEXT), 0);
    lv_obj_set_style_text_font(lbl_conf, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_conf);

    // Cancel button
    lv_obj_t *btn_can = lv_btn_create(box);
    lv_obj_set_size(btn_can, 140, 44);
    lv_obj_align(btn_can, LV_ALIGN_BOTTOM_LEFT, 12, -12);
    lv_obj_set_style_bg_color(btn_can, tc(TH_SURFACE_DARK), 0);
    lv_obj_set_style_bg_color(btn_can, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_can, 8, 0);
    lv_obj_set_style_shadow_width(btn_can, 0, 0);
    lv_obj_set_style_border_width(btn_can, 0, 0);
    lv_obj_add_event_cb(btn_can, [](lv_event_t *e) {
      lv_obj_t *box_obj = lv_obj_get_parent(lv_event_get_target(e));
      lv_obj_t *pop_obj = lv_obj_get_parent(box_obj);
      lv_obj_del(pop_obj);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_can = lv_label_create(btn_can);
    lv_label_set_text(lbl_can, T(STR_CANCEL));
    lv_obj_set_style_text_color(lbl_can, tc(TH_TEXT_MUTED), 0);
    lv_obj_set_style_text_font(lbl_can, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_can);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_create = lv_label_create(btn_extra_fields_create);
  lv_label_set_text(lbl_create, T(STR_EXTRA_FIELDS_CREATE_BTN));
  lv_obj_set_style_text_color(lbl_create, tc(TH_SUCCESS_TEXT), 0);
  lv_obj_set_style_text_font(lbl_create, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_create);

  // Bottom row (y=276): Test field (left, 210px) | Skip/Next (right, 210px)
  // Skip and its confirm variant only belong to the setup chain, where they are
  // the way onwards. Reached from the filament manager screen there is nothing
  // to skip to - the back button already leads out - so it is not built at all.
  if (is_setup_flow) {
  btn_extra_fields_next = lv_btn_create(scr_extra_fields);
  lv_obj_t *btn_skip_bottom = btn_extra_fields_next;
  lv_obj_set_size(btn_skip_bottom, 210, 40);
  lv_obj_set_pos(btn_skip_bottom, 246, 276);
  lv_obj_set_style_bg_color(btn_skip_bottom, tc(TH_SURFACE), 0);
  lv_obj_set_style_bg_color(btn_skip_bottom, tc(TH_SURFACE_2), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_skip_bottom, 8, 0);
  lv_obj_set_style_shadow_width(btn_skip_bottom, 0, 0);
  lv_obj_set_style_border_width(btn_skip_bottom, 1, 0);
  lv_obj_set_style_border_color(btn_skip_bottom, tc(TH_SURFACE_3), 0);
  lv_obj_add_event_cb(btn_skip_bottom, [](lv_event_t *e) {
    // Only reachable in the setup chain now, so there is one way onwards.
    // Deferred: never call showCalReminderScreen from an LVGL callback.
    cal_reminder_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_skip_b = lv_label_create(btn_skip_bottom);
  char skip_buf[32];
  snprintf(skip_buf, sizeof(skip_buf), "%s  " LV_SYMBOL_RIGHT, T(STR_EXTRA_FIELDS_SKIP));
  lv_label_set_text(lbl_skip_b, skip_buf);
  lv_obj_set_style_text_color(lbl_skip_b, tc(TH_TEXT_MUTED), 0);
  lv_obj_set_style_text_font(lbl_skip_b, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_skip_b);
  }

  // Generate test field button (left, fixed y)
  lv_obj_t *btn_test = lv_btn_create(scr_extra_fields);
  lv_obj_set_size(btn_test, 210, 40);
  lv_obj_set_pos(btn_test, 18, 276);
  lv_obj_set_style_bg_color(btn_test, lv_color_hex(0x1a1a0a), 0);
  lv_obj_set_style_bg_color(btn_test, lv_color_hex(0x2a2a1a), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_test, 8, 0);
  lv_obj_set_style_shadow_width(btn_test, 0, 0);
  lv_obj_set_style_border_width(btn_test, 1, 0);
  lv_obj_set_style_border_color(btn_test, lv_color_hex(0x2a2a1a), 0);
  lv_obj_add_event_cb(btn_test, [](lv_event_t *e) {
    if (!wifi_ok || cfg_spoolman_base[0] == '\0') {
      if (lbl_extra_fields_status) {
        lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_NO_WIFI));
        lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_DANGER_TEXT), 0);
      }
      return;
    }
    int code = backendCreateSpoolField(cfg_spoolman_base, "spoolscale_test", 1500);
    Serial.printf("Test field create: %d\n", code);
    if (lbl_extra_fields_status) {
      if (code == 200 || code == 201) {
        { char sb[96]; backendText(T(STR_EF_TEST_CREATED), sb, sizeof(sb)); lv_label_set_text(lbl_extra_fields_status, sb); }
        lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_WARNING), 0);
      } else if (code == 409) {
        { char sb[96]; backendText(T(STR_EF_TEST_EXISTS), sb, sizeof(sb)); lv_label_set_text(lbl_extra_fields_status, sb); }
        lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_WARNING), 0);
      } else {
        lv_label_set_text(lbl_extra_fields_status, T(STR_EF_TEST_FAIL));
        lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_DANGER_TEXT), 0);
      }
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_test = lv_label_create(btn_test);
  lv_label_set_text(lbl_test, T(STR_EF_TEST_BTN));
  lv_obj_set_style_text_color(lbl_test, tc(TH_WARNING), 0);
  lv_obj_set_style_text_font(lbl_test, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_test);
}

// Check existing fields, optionally create missing ones
void checkAndCreateExtraFields(bool create_missing) {
  if (!lbl_extra_fields_status) return;

  if (!wifi_ok) {
    lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_NO_WIFI));
    lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_DANGER_TEXT), 0);
    return;
  }
  if (cfg_spoolman_base[0] == '\0' || strcmp(cfg_spoolman_base, "http://") == 0) {
    { char sb[64]; backendText(T(STR_EXTRA_FIELDS_NO_SPOOLMAN), sb, sizeof(sb)); lv_label_set_text(lbl_extra_fields_status, sb); }
    lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_DANGER_TEXT), 0);
    return;
  }

  lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_CHECKING));
  lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_TEXT_MUTED), 0);
  if (btn_extra_fields_create) lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
  lv_timer_handler();
  yield();

  // GET /api/v1/field/spool — list all existing extra fields
  DynamicJsonDocument doc(8192);
  DeserializationError err = DeserializationError::Ok;
  int code = backendGetSpoolFieldsJson(cfg_spoolman_base, doc, 4000, &err);
  yield();
  lv_timer_handler();
  yield();
  lv_timer_handler();

  Serial.printf("Extra fields GET: %d\n", code);

  // Spoolman not reachable
  if (code < 0 || (code != 200 && code != 0)) {
    char buf[96];
    backendText(T(STR_SPOOLMAN_FAIL), buf, sizeof(buf));
    lv_label_set_text(lbl_extra_fields_status, buf);
    lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_DANGER_TEXT), 0);
    return;
  }

  // Parse existing field names
  int ef_count = REQUIRED_EXTRA_FIELDS_BASE_COUNT;
  bool field_exists[8] = {false};
  if (code == 200 && !err) {
    JsonArray arr = doc.as<JsonArray>();
    for (JsonObject f : arr) {
      const char* fname = f["key"] | "";
      for (int i = 0; i < ef_count; i++) {
        if (strcmp(fname, REQUIRED_EXTRA_FIELDS_BASE[i]) == 0) {
          field_exists[i] = true;
        }
      }
    }
  }

  // Build missing list
  char missing_buf[64] = "";
  int missing_count = 0;
  for (int i = 0; i < ef_count; i++) {
    if (!field_exists[i]) {
      if (missing_count > 0) strncat(missing_buf, ", ", sizeof(missing_buf)-1);
      strncat(missing_buf, REQUIRED_EXTRA_FIELDS_BASE[i], sizeof(missing_buf)-1);
      missing_count++;
    }
  }

  if (missing_count == 0) {
    // All OK
    lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_ALL_OK));
    lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_SUCCESS_TEXT), 0);
    if (btn_extra_fields_create) lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
    // Turn skip/next button green with "Next →" label
    if (btn_extra_fields_next) {
      lv_obj_set_style_bg_color(btn_extra_fields_next, tc(TH_OK_BG), 0);
      lv_obj_set_style_bg_color(btn_extra_fields_next, tc(TH_SUCCESS_BG), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(btn_extra_fields_next, tc(TH_SUCCESS_BG), 0);
      lv_obj_t *lbl = lv_obj_get_child(btn_extra_fields_next, 0);
      if (lbl) {
        char next_lbl[32];
        snprintf(next_lbl, sizeof(next_lbl), "%s  " LV_SYMBOL_RIGHT, T(STR_CONFIRM));
        lv_label_set_text(lbl, next_lbl);
        lv_obj_set_style_text_color(lbl, tc(TH_SUCCESS_TEXT), 0);
      }
    }
    Serial.println("Extra fields: all present");
    return;
  }

  if (!create_missing) {
    char status_buf[128];
    snprintf(status_buf, sizeof(status_buf), T(STR_EXTRA_FIELDS_MISSING), missing_buf);
    lv_label_set_text(lbl_extra_fields_status, status_buf);
    lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_WARNING), 0);
    if (btn_extra_fields_create) lv_obj_clear_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
    return;
  }

  // Create missing fields
  lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_CREATING));
  lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_TEXT_MUTED), 0);
  lv_timer_handler();
  yield();

  char fail_fields[64] = "";
  int fail_count = 0;
  for (int i = 0; i < ef_count; i++) {
    if (field_exists[i]) continue;
    lv_timer_handler();  // keep LVGL alive between HTTP calls
    yield();             // feed watchdog
    int c2 = backendCreateSpoolField(cfg_spoolman_base, REQUIRED_EXTRA_FIELDS_BASE[i], 3000);
    lv_timer_handler();  // update display after each POST
    yield();
    Serial.printf("Create field '%s': %d\n", REQUIRED_EXTRA_FIELDS_BASE[i], c2);
    if (c2 != 200 && c2 != 201) {
      if (fail_count > 0) strncat(fail_fields, ", ", sizeof(fail_fields)-1);
      strncat(fail_fields, REQUIRED_EXTRA_FIELDS_BASE[i], sizeof(fail_fields)-1);
      fail_count++;
    }
  }

  if (fail_count > 0) {
    char fail_buf[128];
    snprintf(fail_buf, sizeof(fail_buf), T(STR_EXTRA_FIELDS_CREATE_FAIL), fail_fields);
    lv_label_set_text(lbl_extra_fields_status, fail_buf);
    lv_obj_set_style_text_color(lbl_extra_fields_status, tc(TH_DANGER_TEXT), 0);
  } else {
    if (btn_extra_fields_create) lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
    yield();
    lv_timer_handler();
    checkAndCreateExtraFields(false);  // verify fields were created
  }
}


// ============================================================
//  OTA — BROWSER UPLOAD
// ============================================================

