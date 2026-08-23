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
#include "services/tag_field.h"
#include "services/user_options.h"
#include "lang.h"
#include "info_popup.h"
#include "tag_field_screen.h"
#include "ui_common.h"
#include "services/backend.h"



static lv_obj_t *lbl_extra_fields_status = nullptr;
static lv_obj_t *btn_extra_fields_create = nullptr;
static lv_obj_t *btn_extra_fields_next   = nullptr;
static bool extra_fields_setup_flow = false;
// Which screen opened this one, so the back button can return there.
static bool extra_fields_from_options = false;
static bool extra_fields_check_pending = false;

// The arrow label of each menu row, which carries whether the server has that
// field. Filled in by checkAndCreateExtraFields(), which already has the
// answer and does not need a second request for it.
enum FieldRow { FIELD_ROW_DRIED = 0, FIELD_ROW_TAG = 1, FIELD_ROW_COUNT = 2 };
static lv_obj_t *lbl_field_state[FIELD_ROW_COUNT] = { nullptr, nullptr };

// Whether this screen is part of first setup, so the tag field screen behind
// it can build the matching header.
static bool extra_fields_in_setup = false;
static bool extra_fields_create_pending = false;

void resetExtraFieldsScreenState() {
  for (int i = 0; i < FIELD_ROW_COUNT; i++) lbl_field_state[i] = nullptr;
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

// Upper bound for the list below, and the size of the parallel "does it exist"
// array in checkAndCreateExtraFields().
#define REQUIRED_EXTRA_FIELDS_MAX  8

// The extra fields the scale needs, written into `out`. Returns how many.
//
// last_dried always, and whichever field the user chose to keep tag UIDs in.
// Not all three tag fields: they are alternatives, and creating the two the
// user did not pick would hand them columns they never asked for. Not a fixed
// "tag" either, for the same reason - somebody who selected nfc_id has no use
// for an empty extra.tag.
//
// Without its field the choice cannot do anything at all: Spoolman answers a
// PATCH on an extra field it does not know with HTTP 400, and ignores a filter
// on one, which turns the fast search into a full inventory download.
static int requiredExtraFields(const char* out[], int max) {
  int n = 0;
  if (n < max) out[n++] = LAST_DRIED_FIELD;
  if (n < max) out[n++] = tagFieldKey();
  return n;
}

void showExtraFieldsScreen(bool is_setup_flow, bool from_options) {
  extra_fields_from_options = from_options;
  logSD("SHOW: ExtraFieldsScreen");
  logSDf("UI: Screen -> ExtraFields (setup=%d)", is_setup_flow ? 1 : 0);
  hideAllOverlays();
  extra_fields_setup_flow = is_setup_flow;
  if (scr_extra_fields) { lv_obj_del(scr_extra_fields); scr_extra_fields = nullptr; }
  lbl_extra_fields_status = nullptr;
  btn_extra_fields_create = nullptr;
  btn_extra_fields_next   = nullptr;
  for (int i = 0; i < FIELD_ROW_COUNT; i++) lbl_field_state[i] = nullptr;
  buildExtraFieldsScreen(is_setup_flow);
  lv_obj_clear_flag(scr_extra_fields, LV_OBJ_FLAG_HIDDEN);
  // Check straight away instead of waiting to be asked: the rows have nothing
  // to say until it has run, and "which fields are missing" is the only reason
  // to be on this screen. Deferred, so the HTTP work happens in appLoop().
  extra_fields_check_pending = true;
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
  lv_obj_set_style_bg_color(scr_extra_fields, lv_color_hex(0x0a1020), 0);

  // Header: back returns to whichever screen opened this one, the Spoolman
  // options or the address screen. Setup flow gets a title and an X instead.
  if (!is_setup_flow) {
    char hdr_b[40]; backendText(T(STR_EXTRA_FIELDS_TITLE), hdr_b, sizeof(hdr_b));
    buildSubHeader(scr_extra_fields, hdr_b,
      [](lv_event_t *e) {
        // Deferred either way: the target screen is built from appLoop(),
        // never from inside the callback of the screen it is about to replace.
        if (extra_fields_from_options) show_spoolman_options_pending = true;
        else                           show_backend_pending = true;
      });
  } else {
    // Setup flow: title only + X (→ main screen), no back button
    lv_obj_t *lbl_title = lv_label_create(scr_extra_fields);
    { char tb[40]; backendText(T(STR_EXTRA_FIELDS_TITLE), tb, sizeof(tb)); lv_label_set_text(lbl_title, tb); }
    lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

    // X → main screen (exit setup)
    lv_obj_t *btn_x = lv_btn_create(scr_extra_fields);
    lv_obj_set_size(btn_x, 44, 44);
    lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
    lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_x, 8, 0);
    lv_obj_set_style_shadow_width(btn_x, 0, 0);
    lv_obj_set_style_border_width(btn_x, 0, 0);
    lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_x = lv_label_create(btn_x);
    lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl_x);
  }

  // The two fields as a menu, in the same list idiom as every other option
  // screen. The row for the tag field opens the choice of which one it is; the
  // row for last_dried has nothing to choose, so it re-runs the check.
  //
  // Each row's arrow carries whether the server has that field. It is filled
  // in by checkAndCreateExtraFields() rather than probed here: this builder
  // runs straight from a button callback on two of its three call paths, and
  // asking the server from there would put an HTTP request inside an LVGL
  // event.
  lv_obj_t *list = lv_obj_create(scr_extra_fields);
  lv_obj_set_size(list, 480, 140);
  lv_obj_set_pos(list, 0, 50);
  lv_obj_set_style_bg_opa(list, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_left(list, 12, 0);
  lv_obj_set_style_pad_right(list, 12, 0);
  lv_obj_set_style_pad_top(list, 4, 0);
  lv_obj_set_style_pad_bottom(list, 4, 0);
  lv_obj_set_style_pad_row(list, 6, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(list, LV_OBJ_FLAG_SCROLL_ELASTIC);

  extra_fields_in_setup = is_setup_flow;

  // Row 1: which field holds the tag UID. The subtitle names the current
  // choice, so the setting can be read without opening it.
  { char buf_t[40]; strncpy(buf_t, T(STR_TAG_FIELD), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[48];
    snprintf(buf_s, sizeof(buf_s), "%s", tagFieldKey());
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_GPS, buf_t, buf_s, false, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_TAG_FIELD, STR_TAG_FIELD_INFO));
    lbl_field_state[FIELD_ROW_TAG] = lv_obj_get_child(btn, -1);
    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      logSD("BTN: Extra fields -> tag field");
      setTagFieldSetupFlow(extra_fields_in_setup);
      show_tag_field_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // Row 2: the drying date field. Nothing to choose, so tapping it re-runs
  // the check that offers to create whatever is missing.
  { char buf_t[40]; strncpy(buf_t, T(STR_EF_LAST_DRIED), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_CHARGE, buf_t, LAST_DRIED_FIELD,
                                false, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_EF_LAST_DRIED, STR_EF_LAST_DRIED_INFO));
    lbl_field_state[FIELD_ROW_DRIED] = lv_obj_get_child(btn, -1);
    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      extra_fields_check_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // Both rows start out saying nothing is known yet, which is the truth until
  // the check below has run.
  for (int i = 0; i < FIELD_ROW_COUNT; i++) {
    if (!lbl_field_state[i]) continue;
    lv_label_set_text(lbl_field_state[i], "");
    lv_obj_set_style_text_font(lbl_field_state[i], &lv_font_montserrat_ext_16, 0);
  }

  // Status label — below check button
  lbl_extra_fields_status = lv_label_create(scr_extra_fields);
  lv_label_set_text(lbl_extra_fields_status, "");
  lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_extra_fields_status, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_extra_fields_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_extra_fields_status, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_extra_fields_status, 440);
  lv_obj_align(lbl_extra_fields_status, LV_ALIGN_TOP_MID, 0, 192);

  // Create missing fields button — full width, above bottom row, initially hidden
  btn_extra_fields_create = lv_btn_create(scr_extra_fields);
  lv_obj_set_size(btn_extra_fields_create, 440, 42);
  lv_obj_align(btn_extra_fields_create, LV_ALIGN_TOP_MID, 0, 228);
  lv_obj_set_style_bg_color(btn_extra_fields_create, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_extra_fields_create, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_extra_fields_create, 8, 0);
  lv_obj_set_style_shadow_width(btn_extra_fields_create, 0, 0);
  lv_obj_set_style_border_width(btn_extra_fields_create, 1, 0);
  lv_obj_set_style_border_color(btn_extra_fields_create, lv_color_hex(0x2a5030), 0);
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
    lv_obj_set_style_border_color(box, lv_color_hex(0x1a3060), 0);
    lv_obj_set_style_border_width(box, 1, 0);
    lv_obj_set_style_radius(box, 10, 0);
    lv_obj_set_style_pad_all(box, 0, 0);
    lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *lbl_ct = lv_label_create(box);
    lv_label_set_text(lbl_ct, T(STR_EXTRA_FIELDS_CONFIRM_TITLE));
    lv_obj_set_style_text_color(lbl_ct, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_ct, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_ct, LV_ALIGN_TOP_MID, 0, 18);

    lv_obj_t *lbl_cm = lv_label_create(box);
    lv_label_set_text(lbl_cm, T(STR_EXTRA_FIELDS_CONFIRM_MSG));
    lv_obj_set_style_text_color(lbl_cm, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(lbl_cm, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl_cm, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(lbl_cm, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(lbl_cm, 380);
    lv_obj_align(lbl_cm, LV_ALIGN_TOP_MID, 0, 52);

    // Confirm button
    lv_obj_t *btn_conf = lv_btn_create(box);
    lv_obj_set_size(btn_conf, 180, 44);
    lv_obj_align(btn_conf, LV_ALIGN_BOTTOM_RIGHT, -12, -12);
    lv_obj_set_style_bg_color(btn_conf, lv_color_hex(0x1a3020), 0);
    lv_obj_set_style_bg_color(btn_conf, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
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
    lv_obj_set_style_text_color(lbl_conf, lv_color_hex(0x40c080), 0);
    lv_obj_set_style_text_font(lbl_conf, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_conf);

    // Cancel button
    lv_obj_t *btn_can = lv_btn_create(box);
    lv_obj_set_size(btn_can, 140, 44);
    lv_obj_align(btn_can, LV_ALIGN_BOTTOM_LEFT, 12, -12);
    lv_obj_set_style_bg_color(btn_can, lv_color_hex(0x1a2030), 0);
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
    lv_obj_set_style_text_color(lbl_can, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_can, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_can);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_create = lv_label_create(btn_extra_fields_create);
  lv_label_set_text(lbl_create, T(STR_EXTRA_FIELDS_CREATE_BTN));
  lv_obj_set_style_text_color(lbl_create, lv_color_hex(0x40c080), 0);
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
  lv_obj_set_style_bg_color(btn_skip_bottom, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_skip_bottom, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_skip_bottom, 8, 0);
  lv_obj_set_style_shadow_width(btn_skip_bottom, 0, 0);
  lv_obj_set_style_border_width(btn_skip_bottom, 1, 0);
  lv_obj_set_style_border_color(btn_skip_bottom, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_skip_bottom, [](lv_event_t *e) {
    // Only reachable in the setup chain now, so there is one way onwards.
    // Deferred: never call showCalReminderScreen from an LVGL callback.
    cal_reminder_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_skip_b = lv_label_create(btn_skip_bottom);
  char skip_buf[32];
  snprintf(skip_buf, sizeof(skip_buf), "%s  " LV_SYMBOL_RIGHT, T(STR_EXTRA_FIELDS_SKIP));
  lv_label_set_text(lbl_skip_b, skip_buf);
  lv_obj_set_style_text_color(lbl_skip_b, lv_color_hex(0x4a6fa0), 0);
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
        lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
      }
      return;
    }
    int code = backendCreateSpoolField(cfg_spoolman_base, "spoolscale_test", 1500);
    Serial.printf("Test field create: %d\n", code);
    if (lbl_extra_fields_status) {
      if (code == 200 || code == 201) {
        { char sb[96]; backendText(T(STR_EF_TEST_CREATED), sb, sizeof(sb)); lv_label_set_text(lbl_extra_fields_status, sb); }
        lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xf0b838), 0);
      } else if (code == 409) {
        { char sb[96]; backendText(T(STR_EF_TEST_EXISTS), sb, sizeof(sb)); lv_label_set_text(lbl_extra_fields_status, sb); }
        lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xf0b838), 0);
      } else {
        lv_label_set_text(lbl_extra_fields_status, T(STR_EF_TEST_FAIL));
        lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
      }
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_test = lv_label_create(btn_test);
  lv_label_set_text(lbl_test, T(STR_EF_TEST_BTN));
  lv_obj_set_style_text_color(lbl_test, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_test, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_test);
}

// Check existing fields, optionally create missing ones
void checkAndCreateExtraFields(bool create_missing) {
  if (!lbl_extra_fields_status) return;

  if (!wifi_ok) {
    lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_NO_WIFI));
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
    return;
  }
  if (cfg_spoolman_base[0] == '\0' || strcmp(cfg_spoolman_base, "http://") == 0) {
    { char sb[64]; backendText(T(STR_EXTRA_FIELDS_NO_SPOOLMAN), sb, sizeof(sb)); lv_label_set_text(lbl_extra_fields_status, sb); }
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
    return;
  }

  lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_CHECKING));
  lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0x4a6fa0), 0);
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
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
    return;
  }

  // Parse existing field names
  const char* required[REQUIRED_EXTRA_FIELDS_MAX];
  int ef_count = requiredExtraFields(required, REQUIRED_EXTRA_FIELDS_MAX);
  bool field_exists[REQUIRED_EXTRA_FIELDS_MAX] = {false};
  if (code == 200 && !err) {
    JsonArray arr = doc.as<JsonArray>();
    for (JsonObject f : arr) {
      const char* fname = f["key"] | "";
      for (int i = 0; i < ef_count; i++) {
        if (strcmp(fname, required[i]) == 0) {
          field_exists[i] = true;
        }
      }
    }
  }

  { char have[96] = "";
    for (int i = 0; i < ef_count; i++) {
      char one[40];
      snprintf(one, sizeof(one), "%s%s=%d", i ? " " : "", required[i], field_exists[i] ? 1 : 0);
      strncat(have, one, sizeof(have) - strlen(have) - 1);
    }
    logSDf("extra fields: need %d (%s), create=%d", ef_count, have, create_missing ? 1 : 0); }

  // The menu rows above say per field what the server has. Same data as the
  // list below, shown where the user is looking rather than only as a summary.
  for (int i = 0; i < ef_count && i < FIELD_ROW_COUNT; i++) {
    if (!lbl_field_state[i]) continue;
    lv_label_set_text(lbl_field_state[i], field_exists[i] ? LV_SYMBOL_OK : LV_SYMBOL_WARNING);
    lv_obj_set_style_text_color(lbl_field_state[i],
      lv_color_hex(field_exists[i] ? 0x28d49a : 0xf0b838), 0);
  }

  // Build missing list
  char missing_buf[64] = "";
  int missing_count = 0;
  for (int i = 0; i < ef_count; i++) {
    if (!field_exists[i]) {
      if (missing_count > 0) strncat(missing_buf, ", ", sizeof(missing_buf)-1);
      strncat(missing_buf, required[i], sizeof(missing_buf)-1);
      missing_count++;
    }
  }

  if (missing_count == 0) {
    // Naming them rather than saying "all fields": the list is last_dried plus
    // whichever tag field is selected, so "all" meant different things on
    // different days and read as a promise about fields it never looked at.
    char have_buf[64] = "";
    for (int i = 0; i < ef_count; i++) {
      if (i) strncat(have_buf, ", ", sizeof(have_buf) - strlen(have_buf) - 1);
      strncat(have_buf, required[i], sizeof(have_buf) - strlen(have_buf) - 1);
    }
    char ok_buf[128];
    snprintf(ok_buf, sizeof(ok_buf), T(STR_EXTRA_FIELDS_ALL_OK), have_buf);
    lv_label_set_text(lbl_extra_fields_status, ok_buf);
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0x40c080), 0);
    if (btn_extra_fields_create) lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
    // Turn skip/next button green with "Next →" label
    if (btn_extra_fields_next) {
      lv_obj_set_style_bg_color(btn_extra_fields_next, lv_color_hex(0x1a3020), 0);
      lv_obj_set_style_bg_color(btn_extra_fields_next, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(btn_extra_fields_next, lv_color_hex(0x2a5030), 0);
      lv_obj_t *lbl = lv_obj_get_child(btn_extra_fields_next, 0);
      if (lbl) {
        char next_lbl[32];
        snprintf(next_lbl, sizeof(next_lbl), "%s  " LV_SYMBOL_RIGHT, T(STR_CONFIRM));
        lv_label_set_text(lbl, next_lbl);
        lv_obj_set_style_text_color(lbl, lv_color_hex(0x40c080), 0);
      }
    }
    Serial.println("Extra fields: all present");
    return;
  }

  if (!create_missing) {
    char status_buf[128];
    snprintf(status_buf, sizeof(status_buf), T(STR_EXTRA_FIELDS_MISSING), missing_buf);
    lv_label_set_text(lbl_extra_fields_status, status_buf);
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xf0b838), 0);
    if (btn_extra_fields_create) lv_obj_clear_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
    return;
  }

  // Create missing fields
  lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_CREATING));
  lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0x4a6fa0), 0);
  lv_timer_handler();
  yield();

  char fail_fields[64] = "";
  int fail_count = 0;
  for (int i = 0; i < ef_count; i++) {
    if (field_exists[i]) continue;
    lv_timer_handler();  // keep LVGL alive between HTTP calls
    yield();             // feed watchdog
    int c2 = backendCreateSpoolField(cfg_spoolman_base, required[i], 3000);
    lv_timer_handler();  // update display after each POST
    yield();
    Serial.printf("Create field '%s': %d\n", required[i], c2);
    logSDf("extra fields: create '%s' HTTP %d", required[i], c2);
    if (c2 != 200 && c2 != 201) {
      if (fail_count > 0) strncat(fail_fields, ", ", sizeof(fail_fields)-1);
      strncat(fail_fields, required[i], sizeof(fail_fields)-1);
      fail_count++;
    }
  }

  if (fail_count > 0) {
    char fail_buf[128];
    snprintf(fail_buf, sizeof(fail_buf), T(STR_EXTRA_FIELDS_CREATE_FAIL), fail_fields);
    lv_label_set_text(lbl_extra_fields_status, fail_buf);
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
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

