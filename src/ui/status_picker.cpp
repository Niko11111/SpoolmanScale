#include "status_picker.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "services/filaman_api.h"
#include "ui_common.h"

// Last, and after everything that pulls in ArduinoJson.
#include "lang.h"

// The literals are the ones this came over with. Deliberately not translated
// into theme.h tokens in the same step: the whole point of the move was that
// the two screens look identical, and a palette conversion done alongside it
// is exactly the kind of change that shifts a colour by one shade and makes
// the move look like the cause. That conversion is its own commit.
#define SP_BOX_W     400
#define SP_BOX_H     280
#define SP_HDR_H     44
#define SP_CELL_W    186
#define SP_CELL_H    66

static lv_obj_t*    s_scr = nullptr;
static StatusPickCb s_cb  = nullptr;
static int          s_pick_id = 0;
// Two stages on purpose. releaseScreen() frees asynchronously and appLoop()
// runs lv_timer_handler() before it reaches the handlers, so the answer is
// delivered one pass after the close - by which time the overlay is really
// gone and a blocking PATCH cannot freeze the screen with the picker on it.
static bool s_close_pending   = false;
static bool s_deliver_pending = false;

bool isStatusPickerOpen() { return s_scr != nullptr; }

void closeStatusPicker() {
  releaseScreen(&s_scr);
  s_cb = nullptr;
  s_pick_id = 0;
  s_close_pending = false;
  s_deliver_pending = false;
}

static void cellCb(lv_event_t* e) {
  s_pick_id = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
  s_close_pending = true;
}

static void cancelCb(lv_event_t* e) {
  s_pick_id = 0;
  s_close_pending = true;
}

lv_obj_t* buildStatusChip(lv_obj_t* parent, int x, int y, int status_id,
                          lv_event_cb_t cb) {
  const uint32_t col = filamanStatusColor(status_id);

  lv_obj_t* chip = cb ? lv_btn_create(parent) : lv_obj_create(parent);
  if (!chip) return nullptr;
  lv_obj_set_size(chip, 150, 44);
  lv_obj_set_pos(chip, x, y);
  lv_obj_set_style_bg_color(chip, lv_color_hex(0x0d2040), 0);
  lv_obj_set_style_bg_color(chip, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_border_color(chip, lv_color_hex(col), 0);
  lv_obj_set_style_border_width(chip, 1, 0);
  lv_obj_set_style_radius(chip, 8, 0);
  lv_obj_set_style_shadow_width(chip, 0, 0);
  lv_obj_set_style_pad_all(chip, 0, 0);
  lv_obj_clear_flag(chip, LV_OBJ_FLAG_SCROLLABLE);
  if (cb) lv_obj_add_event_cb(chip, cb, LV_EVENT_CLICKED, nullptr);

  // Cap is identical in both languages, like "Filament" and "Material".
  lv_obj_t* cap = lv_label_create(chip);
  if (cap) {
    lv_label_set_text(cap, "Status");
    lv_obj_set_style_text_color(cap, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(cap, &lv_font_montserrat_ext_12, 0);
    lv_obj_align(cap, LV_ALIGN_CENTER, 0, -10);
  }

  lv_obj_t* val = lv_label_create(chip);
  if (val) {
    char buf[24];
    copyT(buf, sizeof(buf), filamanStatusStrId(status_id));
    lv_label_set_text(val, buf);
    lv_obj_set_style_text_color(val, lv_color_hex(col), 0);
    lv_obj_set_style_text_font(val, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(val, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(val, 134);
    lv_label_set_long_mode(val, LV_LABEL_LONG_DOT);
    lv_obj_align(val, LV_ALIGN_CENTER, 0, 8);
  }
  return chip;
}

void showStatusPicker(int current_status_id, StatusPickCb cb) {
  releaseScreen(&s_scr);
  s_cb = cb;
  s_pick_id = 0;
  if (!lvPoolHasRoomForRow()) return;

  // Backdrop
  s_scr = lv_obj_create(lv_scr_act());
  if (!s_scr) return;
  lv_obj_set_size(s_scr, 480, 320);
  lv_obj_set_pos(s_scr, 0, 0);
  lv_obj_set_style_bg_color(s_scr, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(s_scr, LV_OPA_70, 0);
  lv_obj_set_style_border_width(s_scr, 0, 0);
  lv_obj_set_style_radius(s_scr, 0, 0);
  lv_obj_set_style_pad_all(s_scr, 0, 0);
  lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_SCROLLABLE);

  // Inner box - same dimensions as the location picker so both read alike
  lv_obj_t* box = lv_obj_create(s_scr);
  if (!box) { releaseScreen(&s_scr); return; }
  lv_obj_set_size(box, SP_BOX_W, SP_BOX_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0b1525), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, 10, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Header
  lv_obj_t* hdr = lv_obj_create(box);
  if (hdr) {
    lv_obj_set_size(hdr, SP_BOX_W, SP_HDR_H);
    lv_obj_set_pos(hdr, 0, 0);
    lv_obj_set_style_bg_color(hdr, lv_color_hex(0x0a1020), 0);
    lv_obj_set_style_border_width(hdr, 0, 0);
    lv_obj_set_style_radius(hdr, 0, 0);
    lv_obj_set_style_pad_all(hdr, 0, 0);
    lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* title = lv_label_create(hdr);
    if (title) {
      char buf[48];
      copyT(buf, sizeof(buf), STR_STATUS_TITLE);
      lv_label_set_text(title, buf);
      lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
      lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
      lv_obj_align(title, LV_ALIGN_CENTER, 0, 0);
    }

    lv_obj_t* btn_x = lv_btn_create(hdr);
    if (btn_x) {
      lv_obj_set_size(btn_x, 40, 40);
      lv_obj_align(btn_x, LV_ALIGN_RIGHT_MID, -4, 0);
      lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
      lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
      lv_obj_set_style_border_width(btn_x, 1, 0);
      lv_obj_set_style_border_color(btn_x, lv_color_hex(0x601010), 0);
      lv_obj_set_style_radius(btn_x, 8, 0);
      lv_obj_set_style_shadow_width(btn_x, 0, 0);
      lv_obj_add_event_cb(btn_x, cancelCb, LV_EVENT_CLICKED, nullptr);
      lv_obj_t* lbl_x = lv_label_create(btn_x);
      if (lbl_x) {
        lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
        lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
        lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
        lv_obj_center(lbl_x);
      }
    }
  }

  // 2x3 grid. Six fixed values do not earn a scroll list, and a grid saves
  // the mis-tap a narrow row invites on a touchscreen.
  const int COL_X[2] = { 10, 204 };
  const int ROW_Y[3] = { 54, 128, 202 };

  for (int id = FILAMAN_STATUS_NEW; id <= FILAMAN_STATUS_COUNT; id++) {
    const int idx = id - 1;
    const bool is_current = (id == current_status_id);
    const bool is_archive = (id == FILAMAN_STATUS_ARCHIVED);

    lv_obj_t* cell = lv_btn_create(box);
    if (!cell) break;
    lv_obj_set_size(cell, SP_CELL_W, SP_CELL_H);
    lv_obj_set_pos(cell, COL_X[idx % 2], ROW_Y[idx / 2]);
    lv_obj_set_style_radius(cell, 8, 0);
    lv_obj_set_style_shadow_width(cell, 0, 0);
    lv_obj_set_style_border_width(cell, 1, 0);
    lv_obj_set_style_pad_all(cell, 0, 0);

    uint32_t txt_col;
    if (is_current) {
      // Same "this is the one you have" language as the location rows.
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x0d3020), 0);
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(cell, lv_color_hex(0x28d49a), 0);
      txt_col = 0x28d49a;
    } else if (is_archive) {
      // The archive vocabulary from the weight popup, so the one cell that
      // asks a question before it acts announces itself.
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x3a1a00), 0);
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x6a3000), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(cell, lv_color_hex(0x6a3000), 0);
      txt_col = 0xffb060;
    } else {
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x0d2040), 0);
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(cell, lv_color_hex(0x0f1e30), 0);
      txt_col = 0xf0f0f0;
    }

    lv_obj_set_user_data(cell, (void*)(intptr_t)id);
    lv_obj_add_event_cb(cell, cellCb, LV_EVENT_CLICKED, nullptr);

    lv_obj_t* lbl = lv_label_create(cell);
    if (lbl) {
      char buf[32];
      copyT(buf, sizeof(buf), filamanStatusStrId(id));
      lv_label_set_text(lbl, buf);
      lv_obj_set_style_text_color(lbl, lv_color_hex(txt_col), 0);
      lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
      lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
      lv_obj_set_width(lbl, SP_CELL_W - 12);
      lv_label_set_long_mode(lbl, LV_LABEL_LONG_DOT);
      lv_obj_center(lbl);
    }
  }
}

void handleStatusPickerDeferredActions() {
  // Delivery first, so one pass never does both stages.
  if (s_deliver_pending) {
    s_deliver_pending = false;
    StatusPickCb cb = s_cb;
    const int id = s_pick_id;
    s_cb = nullptr;
    s_pick_id = 0;
    if (cb) cb(id);
    return;
  }
  if (s_close_pending) {
    s_close_pending = false;
    releaseScreen(&s_scr);
    s_deliver_pending = true;
  }
}
