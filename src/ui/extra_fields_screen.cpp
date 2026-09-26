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
#include "theme.h"

// The screen's geometry. One screen's pixel positions may stay literal; these
// are the ones the layout computes with.
#define EF_HEADER_H     48    // buildSubHeader()
#define EF_MARGIN        8
#define EF_ROW_H        64    // makeListBtn()
#define EF_ROW_GAP       6
#define EF_CARD_FULL_H  96    // under this the verdict is a single line
#define EF_TEXT_X       52
#define EF_TEXT_W      270
#define EF_BTN_W       110
#define EF_BTN_H        40

// The verdict at the top: an icon, a headline, the line naming the fields,
// and the button that creates what is missing. The rows below say per field.
static lv_obj_t *box_extra_fields_verdict = nullptr;
static lv_obj_t *lbl_extra_fields_icon    = nullptr;
static lv_obj_t *lbl_extra_fields_head    = nullptr;
static lv_obj_t *lbl_extra_fields_status  = nullptr;
static lv_obj_t *btn_extra_fields_create  = nullptr;
// Which screen opened this one, so the back button can return there.
static bool extra_fields_from_options = false;
static bool extra_fields_check_pending = false;
static bool extra_fields_create_pending = false;

// The arrow label of each menu row, which carries whether the server has that
// field. Filled in by checkAndCreateExtraFields(), which already has the
// answer and does not need a second request for it.
enum FieldRow {
  FIELD_ROW_DRIED  = 0,
  FIELD_ROW_TAG    = 1,
  FIELD_ROW_HW_UID = 2,   // only built while the switch for it is on
  FIELD_ROW_COUNT  = 3
};
static lv_obj_t *lbl_field_state[FIELD_ROW_COUNT] = { nullptr, nullptr, nullptr };

void resetExtraFieldsScreenState() {
  for (int i = 0; i < FIELD_ROW_COUNT; i++) lbl_field_state[i] = nullptr;
  box_extra_fields_verdict = nullptr;
  lbl_extra_fields_icon = nullptr;
  lbl_extra_fields_head = nullptr;
  lbl_extra_fields_status = nullptr;
  btn_extra_fields_create = nullptr;
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
//  Which Spoolman extra fields the scale writes, whether the server has them,
//  and the one button that creates what is missing. Settings only: the setup
//  has no step for it since the tag source is picked on the first scan and a
//  missing field is created on its first write (Nikolai, 25.09.2026).
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
// The native source has no field at all, so last_dried is then the only thing
// the scale needs. tagFieldKey() is null in that case and would be a null
// pointer in every strcmp below.
static int requiredExtraFields(const char* out[], int max) {
  int n = 0;
  if (n < max) out[n++] = LAST_DRIED_FIELD;
  const char* key = tagFieldKey();
  if (key && n < max) out[n++] = key;
  // Only with the switch on, for the same reason the unselected tag fields are
  // left out: creating a column nobody asked for is worse than not having it.
  // With the switch on it is not optional at all - Spoolman answers a PATCH on
  // a field it does not know with HTTP 400, so without it the setting is on
  // and silently does nothing.
  //
  // Happy Hare creates the field itself on any server it runs against, so this
  // is for the case where the scale is set up first.
  if (g_hw_uid_write && n < max) out[n++] = RFID_TAG_FIELD;
  // extra.tag beside the native tags, for OpenSpoolman, behind its switch.
  if (tagFieldIsNative() && g_osm_tag && n < max) out[n++] = tagFieldSpec(TAG_FIELD_TAG).key;
  return n;
}

// Which menu row shows the state of a required field, or -1 for one that has
// no row of its own.
//
// By name rather than by position. The list is built from what is needed right
// now - last_dried always, the selected tag field only when it has a key, the
// Happy Hare field only behind its switch - so an index into it means a
// different field on different days, and the native source already shifts
// everything after it by one.
static int fieldRowFor(const char* key) {
  if (strcmp(key, LAST_DRIED_FIELD) == 0) return FIELD_ROW_DRIED;
  if (strcmp(key, RFID_TAG_FIELD)   == 0) return FIELD_ROW_HW_UID;
  // Beside the native tags extra.tag is OpenSpoolman's, not the tag row's:
  // that row speaks for the relation, which has no field.
  if (tagFieldIsNative()) return -1;
  return FIELD_ROW_TAG;   // whichever one is selected
}

void showExtraFieldsScreen(bool is_setup_flow, bool from_options) {
  (void)is_setup_flow;   // the setup no longer comes here
  extra_fields_from_options = from_options;
  logSD("SHOW: ExtraFieldsScreen");
  hideAllOverlays();
  resetExtraFieldsScreenState();
  buildExtraFieldsScreen(false);
  lv_obj_clear_flag(scr_extra_fields, LV_OBJ_FLAG_HIDDEN);
  // Check straight away instead of waiting to be asked: the rows have nothing
  // to say until it has run, and "which fields are missing" is the only reason
  // to be on this screen. Deferred, so the HTTP work happens in appLoop().
  extra_fields_check_pending = true;
}

// One row: the house list row, its arrow label left for the field's state.
static lv_obj_t* fieldRow(lv_obj_t* list, const char* icon, int title_id, const char* sub,
                          int info_id, FieldRow row) {
  char title[40];
  copyT(title, sizeof(title), title_id);
  lv_obj_t *help = nullptr;
  lv_obj_t *btn = makeListBtn(list, icon, title, sub, false, &help);
  if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                INFO_POPUP_ARG(title_id, info_id));
  lbl_field_state[row] = lv_obj_get_child(btn, -1);
  lv_label_set_text(lbl_field_state[row], "");
  lv_obj_set_style_text_font(lbl_field_state[row], UI_FONT_BODY, 0);
  return btn;
}

void buildExtraFieldsScreen(bool is_setup_flow) {
  (void)is_setup_flow;
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
  lv_obj_set_style_bg_color(scr_extra_fields, lv_color_hex(UI_COL_GROUND), 0);

  // The house header: title centred and green, back to whichever screen
  // opened this one. Deferred either way: the target screen is built from
  // appLoop(), never from inside the callback of the screen it replaces.
  { char hdr_b[40]; backendText(T(STR_EXTRA_FIELDS_TITLE), hdr_b, sizeof(hdr_b));
    buildSubHeader(scr_extra_fields, hdr_b,
      [](lv_event_t *e) {
        if (extra_fields_from_options) show_spoolman_options_pending = true;
        else                           show_backend_pending = true;
      }); }

  // Two rows or three, and nothing scrolls: the rows sit at the bottom and
  // the verdict takes what is left above them. With the third row it is a
  // single line, the rows say per field what the line would have listed.
  const int rows   = g_hw_uid_write ? 3 : 2;
  const int rows_h = rows * EF_ROW_H + (rows - 1) * EF_ROW_GAP;
  const int list_y = 320 - EF_MARGIN - rows_h;
  const int card_y = EF_HEADER_H + EF_MARGIN;
  const int card_h = list_y - EF_MARGIN - card_y;
  const bool compact = card_h < EF_CARD_FULL_H;

  box_extra_fields_verdict = lv_obj_create(scr_extra_fields);
  lv_obj_t *card = box_extra_fields_verdict;
  lv_obj_set_pos(card, 12, card_y);
  lv_obj_set_size(card, 456, card_h);
  lv_obj_set_style_bg_color(card, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_radius(card, UI_RADIUS_BOX, 0);
  lv_obj_set_style_border_width(card, 1, 0);
  lv_obj_set_style_border_color(card, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_pad_all(card, 0, 0);
  lv_obj_set_style_shadow_width(card, 0, 0);
  lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

  lbl_extra_fields_icon = lv_label_create(card);
  lv_label_set_text(lbl_extra_fields_icon, LV_SYMBOL_REFRESH);
  lv_obj_set_style_text_font(lbl_extra_fields_icon, UI_FONT_ICON, 0);
  lv_obj_set_style_text_color(lbl_extra_fields_icon, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_align(lbl_extra_fields_icon, compact ? LV_ALIGN_LEFT_MID : LV_ALIGN_TOP_LEFT,
               16, compact ? 0 : 16);

  lbl_extra_fields_head = lv_label_create(card);
  lv_label_set_text(lbl_extra_fields_head, T(STR_EXTRA_FIELDS_CHECKING));
  lv_obj_set_style_text_font(lbl_extra_fields_head, UI_FONT_HEADLINE, 0);
  lv_obj_set_style_text_color(lbl_extra_fields_head, lv_color_hex(UI_COL_INK), 0);
  lv_label_set_long_mode(lbl_extra_fields_head, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_extra_fields_head, EF_TEXT_W);
  lv_obj_align(lbl_extra_fields_head, compact ? LV_ALIGN_LEFT_MID : LV_ALIGN_TOP_LEFT,
               EF_TEXT_X, compact ? 0 : 16);

  // The line naming the fields, and where a check or a create says how it
  // went. Absent in the compact card, whose rows carry the same news.
  lbl_extra_fields_status = lv_label_create(card);
  lv_label_set_text(lbl_extra_fields_status, "");
  lv_obj_set_style_text_font(lbl_extra_fields_status, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_label_set_long_mode(lbl_extra_fields_status, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_extra_fields_status, EF_TEXT_W);
  lv_obj_align(lbl_extra_fields_status, LV_ALIGN_TOP_LEFT, EF_TEXT_X, 46);
  if (compact) lv_obj_add_flag(lbl_extra_fields_status, LV_OBJ_FLAG_HIDDEN);

  // Creates what is missing, no question first: only fields the scale itself
  // writes are ever on the list, and each is an empty column.
  btn_extra_fields_create = lv_btn_create(card);
  lv_obj_set_size(btn_extra_fields_create, EF_BTN_W, EF_BTN_H);
  lv_obj_align(btn_extra_fields_create, compact ? LV_ALIGN_RIGHT_MID : LV_ALIGN_BOTTOM_RIGHT,
               -12, compact ? 0 : -12);
  lv_obj_set_style_bg_color(btn_extra_fields_create, lv_color_hex(UI_COL_OK_BG), 0);
  lv_obj_set_style_bg_color(btn_extra_fields_create, lv_color_hex(UI_COL_OK_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_extra_fields_create, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn_extra_fields_create, 0, 0);
  lv_obj_set_style_border_width(btn_extra_fields_create, 0, 0);
  lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
  lv_obj_add_event_cb(btn_extra_fields_create, [](lv_event_t *e) {
    logSD("BTN: Extra fields -> create");
    extra_fields_create_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_create = lv_label_create(btn_extra_fields_create);
  lv_label_set_text(lbl_create, T(STR_EF_BTN_CREATE));
  lv_obj_set_style_text_color(lbl_create, lv_color_hex(UI_COL_OK_TEXT), 0);
  lv_obj_set_style_text_font(lbl_create, UI_FONT_BODY, 0);
  lv_obj_center(lbl_create);

  // The rows, in the same list idiom as every other option screen. Each
  // arrow carries whether the server has that field. It is filled in by
  // checkAndCreateExtraFields() rather than probed here: this builder can run
  // straight from a button callback, and HTTP there is not allowed.
  lv_obj_t *list = lv_obj_create(scr_extra_fields);
  lv_obj_set_size(list, 480, rows_h);
  lv_obj_set_pos(list, 0, list_y);
  lv_obj_set_style_bg_opa(list, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_left(list, 12, 0);
  lv_obj_set_style_pad_right(list, 12, 0);
  lv_obj_set_style_pad_top(list, 0, 0);
  lv_obj_set_style_pad_bottom(list, 0, 0);
  lv_obj_set_style_pad_row(list, EF_ROW_GAP, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_clear_flag(list, LV_OBJ_FLAG_SCROLLABLE);

  // Where the tag UID lives. The subtitle names the choice, so it can be read
  // without opening it; the native tags need no field at all.
  { char sub[48];
    if (tagFieldIsNative()) snprintf(sub, sizeof(sub), "%s - %s", T(STR_TF_NATIVE), T(STR_EF_NATIVE_SUB));
    else                    snprintf(sub, sizeof(sub), "%s", tagFieldKeyName());
    lv_obj_t *btn = fieldRow(list, LV_SYMBOL_GPS, STR_TAG_FIELD, sub, STR_TAG_FIELD_INFO,
                             FIELD_ROW_TAG);
    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      logSD("BTN: Extra fields -> tag field");
      setTagFieldSetupFlow(false);
      show_tag_field_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // The drying date. Nothing to choose, so tapping it re-runs the check.
  { lv_obj_t *btn = fieldRow(list, LV_SYMBOL_TINT, STR_EF_LAST_DRIED, LAST_DRIED_FIELD,
                             STR_EF_LAST_DRIED_INFO, FIELD_ROW_DRIED);
    lv_obj_add_event_cb(btn, [](lv_event_t *e) { extra_fields_check_pending = true; },
                        LV_EVENT_CLICKED, NULL); }

  // The field an MMU's gate readers resolve against, only while the switch
  // that writes it is on - with it off there is no field to have.
  if (g_hw_uid_write) {
    lv_obj_t *btn = fieldRow(list, LV_SYMBOL_UPLOAD, STR_HW_UID_WRITE, RFID_TAG_FIELD,
                             STR_HW_UID_WRITE_INFO, FIELD_ROW_HW_UID);
    lv_obj_add_event_cb(btn, [](lv_event_t *e) { extra_fields_check_pending = true; },
                        LV_EVENT_CLICKED, NULL);
  }
}

// The verdict card in one of its three looks: checking, all there, missing.
static void setVerdict(const char* icon, uint32_t colour, uint32_t bg, uint32_t border,
                       const char* head, bool offer_create) {
  if (!box_extra_fields_verdict) return;
  lv_label_set_text(lbl_extra_fields_icon, icon);
  lv_obj_set_style_text_color(lbl_extra_fields_icon, lv_color_hex(colour), 0);
  lv_label_set_text(lbl_extra_fields_head, head);
  lv_obj_set_style_bg_color(box_extra_fields_verdict, lv_color_hex(bg), 0);
  lv_obj_set_style_border_color(box_extra_fields_verdict, lv_color_hex(border), 0);
  if (offer_create) lv_obj_clear_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
  else              lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
}
// A check that could not run: the reason is the headline.
static void setVerdictError(const char* why) {
  setVerdict(LV_SYMBOL_WARNING, UI_COL_BAD_TEXT, UI_COL_ROW, UI_COL_BAD, why, false);
}

// Check existing fields, optionally create missing ones
void checkAndCreateExtraFields(bool create_missing) {
  if (!lbl_extra_fields_status) return;

  if (!wifi_ok) {
    setVerdictError(T(STR_EXTRA_FIELDS_NO_WIFI));
    return;
  }
  if (cfg_spoolman_base[0] == '\0' || strcmp(cfg_spoolman_base, "http://") == 0) {
    char sb[64]; backendText(T(STR_EXTRA_FIELDS_NO_SPOOLMAN), sb, sizeof(sb));
    setVerdictError(sb);
    return;
  }

  setVerdict(LV_SYMBOL_REFRESH, UI_COL_CAPTION, UI_COL_ROW, UI_COL_LINE,
             T(STR_EXTRA_FIELDS_CHECKING), false);
  lv_label_set_text(lbl_extra_fields_status, "");
  lv_timer_handler();
  yield();

  // GET /api/v1/field/spool - list all existing extra fields
  JsonDocument doc;
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
    setVerdictError(buf);
    return;
  }

  // Settles which source is in force before asking what it needs. Without it
  // this screen can be the first thing that runs on a given server - during
  // setup there has been no scan yet - and the native source would still look
  // selected on a server that does not have it, so the tag field would be
  // left out of the list entirely and nothing would offer to create it.
  //
  // Reaches the network, which is allowed here: this function is deferred out
  // of the pending flag and runs from appLoop(), never from the callback.
  tagFieldAutoSelect();

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
  for (int i = 0; i < ef_count; i++) {
    const int row = fieldRowFor(required[i]);
    if (row < 0 || !lbl_field_state[row]) continue;
    lv_label_set_text(lbl_field_state[row], field_exists[i] ? LV_SYMBOL_OK : LV_SYMBOL_WARNING);
    lv_obj_set_style_text_color(lbl_field_state[row],
      lv_color_hex(field_exists[i] ? UI_COL_ACCENT : UI_COL_WARN), 0);
  }

  // The native tags have no field; their row says whether the relation is
  // there, as the probe that picked them found it.
  if (tagFieldIsNative() && lbl_field_state[FIELD_ROW_TAG]) {
    const bool rel = backendNativeTagsCached() == 1;
    lv_label_set_text(lbl_field_state[FIELD_ROW_TAG], rel ? LV_SYMBOL_OK : LV_SYMBOL_WARNING);
    lv_obj_set_style_text_color(lbl_field_state[FIELD_ROW_TAG],
      lv_color_hex(rel ? UI_COL_ACCENT : UI_COL_WARN), 0);
  }

  // Build missing list
  char missing_buf[64] = "";
  int missing_count = 0;
  for (int i = 0; i < ef_count; i++) {
    if (!field_exists[i]) {
      if (missing_count > 0) strncat(missing_buf, ", ", sizeof(missing_buf) - strlen(missing_buf) - 1);
      strncat(missing_buf, required[i], sizeof(missing_buf) - strlen(missing_buf) - 1);
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
    setVerdict(LV_SYMBOL_OK, UI_COL_ACCENT, UI_COL_ACCENT_DIM, UI_COL_OK_BG_PRESSED,
               T(STR_EF_HEAD_OK), false);
    Serial.println("Extra fields: all present");
    return;
  }

  if (!create_missing) {
    char status_buf[128];
    snprintf(status_buf, sizeof(status_buf), T(STR_EXTRA_FIELDS_MISSING), missing_buf);
    lv_label_set_text(lbl_extra_fields_status, status_buf);
    setVerdict(LV_SYMBOL_WARNING, UI_COL_WARN, UI_COL_ROW, UI_COL_WARN,
               T(STR_EF_HEAD_MISSING), true);
    return;
  }

  // Create missing fields
  setVerdict(LV_SYMBOL_REFRESH, UI_COL_CAPTION, UI_COL_ROW, UI_COL_LINE,
             T(STR_EXTRA_FIELDS_CREATING), false);
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
      if (fail_count > 0) strncat(fail_fields, ", ", sizeof(fail_fields) - strlen(fail_fields) - 1);
      strncat(fail_fields, required[i], sizeof(fail_fields) - strlen(fail_fields) - 1);
      fail_count++;
    }
  }

  if (fail_count > 0) {
    char fail_buf[128];
    snprintf(fail_buf, sizeof(fail_buf), T(STR_EXTRA_FIELDS_CREATE_FAIL), fail_fields);
    // The loop above pumps LVGL between the requests, and the X on the setup
    // variant of this screen goes through showMainScreen(), which nulls this
    // label. Unguarded, that was LV_ASSERT_NULL and a frozen device.
    if (lbl_extra_fields_status) {
      lv_label_set_text(lbl_extra_fields_status, fail_buf);
      setVerdict(LV_SYMBOL_WARNING, UI_COL_BAD_TEXT, UI_COL_ROW, UI_COL_BAD,
                 T(STR_EF_HEAD_MISSING), true);
    }
  } else {
    yield();
    lv_timer_handler();
    checkAndCreateExtraFields(false);  // verify fields were created
  }
}


// ============================================================
//  OTA - BROWSER UPLOAD
// ============================================================

