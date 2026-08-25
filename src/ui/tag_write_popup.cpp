#include "tag_write_popup.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/tag_write.h"
#include "ui_common.h"

static lv_obj_t *scr_tag_write = nullptr;
static bool close_pending   = false;
static bool confirm_pending = false;
static int  s_spool_id      = 0;

// Set while a write is on its way, so the result is picked up once and the
// status line is not repainted on every loop pass afterwards.
static bool s_watching = false;

bool isTagWritePopupOpen() { return scr_tag_write != nullptr; }

// The result codes tag_write.cpp reports, as something the screen can say. Its
// own messages are English prose for the web page; this file is where they
// turn into a translated line.
static StringID resultString(uint8_t code) {
  switch (code) {
    case TW_OK:            return STR_TW_OK;
    case TW_ERR_NO_TAG:    return STR_TW_ERR_NO_TAG;
    case TW_ERR_NOT_NTAG:  return STR_TW_ERR_NOT_NTAG;
    case TW_ERR_BACKEND:   return STR_TW_ERR_BACKEND;
    case TW_ERR_SPACE:     return STR_TW_ERR_SPACE;
    default:               return STR_TW_ERR_WRITE;
  }
}

static void showResult(uint8_t code) {
  if (!lbl_status) return;
  char buf[64];
  strncpy(buf, T(resultString(code)), sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  lv_label_set_text(lbl_status, buf);
  lv_obj_set_style_text_color(lbl_status,
    code == TW_OK ? lv_color_hex(0x28d49a) : lv_color_hex(0xff8080), 0);
}

void showTagWriteAskPopup(int spool_id) {
  if (scr_tag_write || spool_id <= 0) return;
  s_spool_id = spool_id;

  logSDf("SHOW: TagWriteAskPopup spool=%d", spool_id);

  scr_tag_write = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_tag_write, 480, 320);
  lv_obj_set_pos(scr_tag_write, 0, 0);
  lv_obj_set_style_bg_color(scr_tag_write, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_tag_write, LV_OPA_80, 0);
  lv_obj_set_style_border_width(scr_tag_write, 0, 0);
  lv_obj_set_style_radius(scr_tag_write, 0, 0);
  lv_obj_set_style_pad_all(scr_tag_write, 0, 0);
  lv_obj_clear_flag(scr_tag_write, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_tag_write);
  lv_obj_set_size(box, 440, 220);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(box);
  { char tb[48]; strncpy(tb, T(STR_TW_ASK_TITLE), sizeof(tb) - 1);
    tb[sizeof(tb) - 1] = '\0'; lv_label_set_text(lbl_title, tb); }
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 14);

  lv_obj_t *line = lv_obj_create(box);
  lv_obj_set_size(line, 420, 1);
  lv_obj_set_pos(line, 10, 44);
  lv_obj_set_style_bg_color(line, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(line, 0, 0);
  lv_obj_set_style_radius(line, 0, 0);
  lv_obj_set_style_pad_all(line, 0, 0);

  // The warning is the whole point of asking: the tag may already carry an ACE
  // or OpenSpool record, and writing replaces it.
  lv_obj_t *lbl_hint = lv_label_create(box);
  { char hb[128]; strncpy(hb, T(STR_TW_ASK_HINT), sizeof(hb) - 1);
    hb[sizeof(hb) - 1] = '\0'; lv_label_set_text(lbl_hint, hb); }
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, 400);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 58);

  lv_obj_t *btn_ok = lv_btn_create(box);
  lv_obj_set_size(btn_ok, 420, 48);
  lv_obj_align(btn_ok, LV_ALIGN_TOP_MID, 0, 116);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x0d3d2e), 0);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x18705a), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok, 8, 0);
  lv_obj_set_style_shadow_width(btn_ok, 0, 0);
  lv_obj_set_style_border_width(btn_ok, 0, 0);
  lv_obj_add_event_cb(btn_ok, [](lv_event_t *e) {
    // Flags only. The NFC write takes as long as a write takes and must not
    // run inside the callback, and the overlay cannot delete itself here.
    confirm_pending = true;
    close_pending   = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok = lv_label_create(btn_ok);
  { char bb[40]; strncpy(bb, T(STR_TW_BTN_WRITE), sizeof(bb) - 1);
    bb[sizeof(bb) - 1] = '\0'; lv_label_set_text(lbl_ok, bb); }
  lv_obj_set_style_text_color(lbl_ok, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_ok, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_ok);

  lv_obj_t *btn_skip = lv_btn_create(box);
  lv_obj_set_size(btn_skip, 420, 44);
  lv_obj_align(btn_skip, LV_ALIGN_TOP_MID, 0, 170);
  lv_obj_set_style_bg_color(btn_skip, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_skip, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_skip, 8, 0);
  lv_obj_set_style_shadow_width(btn_skip, 0, 0);
  lv_obj_set_style_border_width(btn_skip, 1, 0);
  lv_obj_set_style_border_color(btn_skip, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_skip, [](lv_event_t *e) {
    close_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_skip = lv_label_create(btn_skip);
  { char cb[32]; strncpy(cb, T(STR_TW_BTN_SKIP), sizeof(cb) - 1);
    cb[sizeof(cb) - 1] = '\0'; lv_label_set_text(lbl_skip, cb); }
  lv_obj_set_style_text_color(lbl_skip, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_skip, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_skip);
}

void handleTagWritePopupDeferredActions() {
  // The result of a write that is already running. tagWriteTick() carries it
  // out on this same loop task, so the state settles within a pass or two.
  if (s_watching && strcmp(tagWriteState(), "pending") != 0) {
    s_watching = false;
    const uint8_t code = tagWriteResultCode();
    showResult(code);
    logSDf("TagWritePopup: spool %d finished, code %u", s_spool_id,
           (unsigned)code);
  }

  if (!close_pending) return;
  close_pending = false;

  if (scr_tag_write) { lv_obj_del(scr_tag_write); scr_tag_write = nullptr; }

  if (!confirm_pending) {
    logSDf("TagWritePopup: declined for spool %d", s_spool_id);
    return;
  }
  confirm_pending = false;

  // No link flag: the spool was linked before this popup was ever offered.
  // OpenSpool rather than ACE, because it is the format the filament managers
  // and the printers read - ACE stays a choice the tag page offers.
  if (tagWriteRequest(s_spool_id, TAG_FMT_OPENSPOOL, false)) {
    s_watching = true;
  } else {
    // Only reachable when another write is still parked, which the tag page
    // could have started. Saying so beats a popup that closes and does nothing.
    showResult(TW_ERR_WRITE);
    logSDf("TagWritePopup: writer busy, spool %d not queued", s_spool_id);
  }
}
