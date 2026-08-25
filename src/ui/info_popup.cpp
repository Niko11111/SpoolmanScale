#include "info_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"

// Twice now a text has outgrown this buffer and been cut mid sentence, at 256
// and again at 352. The reason it keeps happening is that nothing complains:
// strncpy truncates silently, and a shortened explanation still looks like a
// finished one. 768 is well past the longest text in lang.cpp, which is around
// 470 bytes with its umlauts counted as the two bytes they are.
//
// The box no longer sets the narrower limit either - the text area scrolls
// now, so length is a question of this buffer alone.
// Long enough for the longest text in the table with room to spare. It was
// 768, which silently truncated the card_uids explanation mid sentence - the
// scroll container below exists so a paragraph can be read, and a buffer that
// quietly drops the end defeats it. Static storage, so the extra bytes cost
// nothing that matters.
#define INFO_TEXT_BUF   1024
#define INFO_TITLE_BUF   48

void showInfoPopup(int title_id, int text_id, uint8_t tone) {
  if (title_id < 0 || title_id >= STR_COUNT) return;
  if (text_id  < 0 || text_id  >= STR_COUNT) return;

  lv_obj_t *pop = lv_obj_create(lv_scr_act());
  lv_obj_set_size(pop, 480, 320);
  lv_obj_set_pos(pop, 0, 0);
  lv_obj_set_style_bg_color(pop, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(pop, LV_OPA_70, 0);
  lv_obj_set_style_border_width(pop, 0, 0);
  lv_obj_set_style_radius(pop, 0, 0);
  lv_obj_set_style_pad_all(pop, 0, 0);
  lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(pop);
  lv_obj_set_size(box, 440, 250);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x2a4080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // The glyph is what says which of the two happened before a word is read.
  // Only for a result: a warning triangle over a settings explanation would be
  // a lie, and a tick over one would be meaningless.
  const bool is_result = (tone != INFO_PLAIN);
  if (is_result) {
    lv_obj_t *icon = lv_label_create(box);
    lv_label_set_text(icon, tone == INFO_DONE ? LV_SYMBOL_OK : LV_SYMBOL_WARNING);
    lv_obj_set_style_text_color(icon,
      lv_color_hex(tone == INFO_DONE ? 0x80ffb0 : 0xf0b838), 0);
    lv_obj_set_style_text_font(icon, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, 12);
  }
  // Everything below the icon moves down by its height plus a little air, so
  // one layout serves both shapes.
  const int y_off = is_result ? 34 : 0;

  // Title: the name of the setting, so the popup is anchored to the row the
  // user tapped rather than being a floating paragraph.
  lv_obj_t *title = lv_label_create(box);
  char tbuf[INFO_TITLE_BUF];
  strncpy(tbuf, T(title_id), sizeof(tbuf) - 1);
  tbuf[sizeof(tbuf) - 1] = '\0';
  lv_label_set_text(title, tbuf);
  lv_obj_set_style_text_color(title,
    lv_color_hex(is_result ? 0xe8f0ff : 0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(title, 424);
  lv_obj_set_pos(title, 8, 14 + y_off);

  // The text scrolls instead of being clipped. Some settings genuinely need a
  // paragraph to explain, and a reader who can flick is better served than one
  // who silently loses the last third.
  lv_obj_t *scroll = lv_obj_create(box);
  lv_obj_set_size(scroll, 424, 128 - y_off);
  lv_obj_set_pos(scroll, 8, 48 + y_off);
  lv_obj_set_style_bg_opa(scroll, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(scroll, 0, 0);
  lv_obj_set_style_pad_all(scroll, 0, 0);
  lv_obj_set_scroll_dir(scroll, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(scroll, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(scroll, LV_OBJ_FLAG_SCROLL_ELASTIC);

  lv_obj_t *info = lv_label_create(scroll);
  // Static, not on the stack: this runs from an LVGL event callback nested in
  // lv_timer_handler(), and the buffer only has to survive until
  // lv_label_set_text() has copied it into the label's own storage.
  static char ibuf[INFO_TEXT_BUF];
  // Say so rather than drop the end in silence: a truncated explanation still
  // looks like a finished one on screen, so nothing would ever point at it.
  const size_t len = strlen(T(text_id));
  if (len >= sizeof(ibuf))
    logSDf("InfoPopup: text %d is %u bytes, buffer holds %u - truncated",
           text_id, (unsigned)len, (unsigned)(sizeof(ibuf) - 1));
  strncpy(ibuf, T(text_id), sizeof(ibuf) - 1);
  ibuf[sizeof(ibuf) - 1] = '\0';
  lv_label_set_text(info, ibuf);
  lv_obj_set_style_text_color(info,
    lv_color_hex(is_result ? 0x4a6fa0 : 0xc8d8f0), 0);
  lv_obj_set_style_text_font(info, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
  // 14 px narrower than the container so the scrollbar has somewhere to sit.
  lv_obj_set_width(info, 410);
  lv_obj_set_pos(info, 0, 0);

  lv_obj_t *btn = lv_btn_create(box);
  lv_obj_set_size(btn, 200, 48);
  lv_obj_set_pos(btn, 120, 188);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x2a4080), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    // Two levels up from the button: box, then the scrim that owns everything.
    // Deleted asynchronously because this runs inside the dispatch of an event
    // belonging to a child of what is being freed.
    lv_obj_t *box = lv_obj_get_parent(lv_event_get_target(e));
    lv_obj_del_async(lv_obj_get_parent(box));
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *l = lv_label_create(btn);
  char bbuf[24];
  strncpy(bbuf, T(is_result ? STR_BTN_OK : STR_BACK), sizeof(bbuf) - 1);
  bbuf[sizeof(bbuf) - 1] = '\0';
  lv_label_set_text(l, bbuf);
  lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
}

void infoPopupEventCb(lv_event_t *e) {
  const intptr_t packed = (intptr_t)lv_event_get_user_data(e);
  showInfoPopup((int)(packed >> 16), (int)(packed & 0xFFFF));
}
