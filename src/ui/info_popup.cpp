#include "info_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/theme.h"

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

// How long a success stands before it closes itself. Long enough to read a
// title and a line from arm's length, short enough that nobody has to reach
// for the screen after a write that simply worked. A warning has no countdown:
// it names something that did not happen, and that must not pass unread.
#define INFO_DONE_CLOSE_MS  4000

// Whether one of these is up. It has a button and no timer, so it waits for an
// answer like every other modal - and a blocking lookup underneath it takes
// the touch panel away for as long as it runs. Tracked here rather than
// guessed from the screen tree, which is what uiModalWaiting() needs.
static lv_obj_t *s_info_pop = nullptr;

bool isInfoPopupOpen() { return s_info_pop != nullptr; }

// Static, not on the stack: this runs from an LVGL event callback nested in
// lv_timer_handler(), and the buffer only has to survive until
// lv_label_set_text() has copied it into the label's own storage.
static char s_text_buf[INFO_TEXT_BUF];

// The text by id into s_text_buf. Says so rather than drop the end in silence:
// a truncated explanation still looks like a finished one on screen, so
// nothing would ever point at it.
static const char *infoText(int text_id) {
  const size_t len = strlen(T(text_id));
  if (len >= sizeof(s_text_buf))
    logSDf("InfoPopup: text %d is %u bytes, buffer holds %u - truncated",
           text_id, (unsigned)len, (unsigned)(sizeof(s_text_buf) - 1));
  copyT(s_text_buf, sizeof(s_text_buf), text_id);
  return s_text_buf;
}

// Closes the popup that `obj` sits in, whatever depth it sits at. Only when it
// is still the current one: a second popup replaces the first by deleting it,
// and the first one's countdown or OK must not take the second one down.
// Asynchronously, because both callers run inside an event or an animation
// that belongs to a child of what is being freed.
static void closeInfoPopupOf(lv_obj_t *obj) {
  lv_obj_t *scrim = obj;
  while (scrim && lv_obj_get_parent(scrim) != lv_scr_act())
    scrim = lv_obj_get_parent(scrim);
  if (!scrim || scrim != s_info_pop) return;
  // Cleared here, not in a delete callback: the async free happens a pass
  // later, and anything asking in between has to be told the question is
  // already answered.
  s_info_pop = nullptr;
  lv_obj_del_async(scrim);
}

// A result: the card the question and the waiting card stand on, so the answer
// takes the place of what came before without moving. The glyph says which of
// the two happened before a word is read. A success counts down in its OK
// button and closes itself; a warning waits for the OK.
static void buildResultCard(lv_obj_t *pop, int title_id, int text_id, uint8_t tone) {
  const bool done = (tone == INFO_DONE);

  lv_obj_t *box = lv_obj_create(pop);
  lv_obj_set_size(box, UI_POPUP_W, UI_CARD_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *icon = lv_label_create(box);
  lv_label_set_text(icon, done ? LV_SYMBOL_OK : LV_SYMBOL_WARNING);
  lv_obj_set_style_text_color(icon, lv_color_hex(done ? UI_COL_OK_TEXT : UI_COL_WARN), 0);
  lv_obj_set_style_text_font(icon, UI_FONT_ICON, 0);
  lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, UI_CARD_ICON_Y);

  lv_obj_t *title = lv_label_create(box);
  lv_label_set_text(title, T(title_id));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(title, UI_FONT_HEADLINE, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(title, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(title, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, UI_CARD_TITLE_Y);

  // Starts where the question's hint and the waiting card's hint start, so
  // the line does not jump when the card changes. Scrolls for the one warning
  // that explains at length (the missing tag relation); every other result is
  // a line or two.
  lv_obj_t *scroll = lv_obj_create(box);
  lv_obj_set_size(scroll, UI_POPUP_W - UI_CARD_TEXT_PAD / 2, UI_CARD_ROW_Y - UI_CARD_TEXT_Y - 6);
  lv_obj_align(scroll, LV_ALIGN_TOP_MID, 0, UI_CARD_TEXT_Y);
  lv_obj_set_style_bg_opa(scroll, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(scroll, 0, 0);
  lv_obj_set_style_pad_all(scroll, 0, 0);
  lv_obj_set_scroll_dir(scroll, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(scroll, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(scroll, LV_OBJ_FLAG_SCROLL_ELASTIC);

  lv_obj_t *info = lv_label_create(scroll);
  lv_label_set_text(info, infoText(text_id));
  lv_obj_set_style_text_color(info, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(info, UI_FONT_BODY, 0);
  lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(info, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(info, LV_ALIGN_TOP_MID, 0, 0);

  // The whole row of answers, where the waiting card's bar ran.
  const lv_coord_t btn_w = UI_POPUP_W - 2 * UI_CARD_ROW_X;
  lv_obj_t *btn = lv_btn_create(box);
  lv_obj_set_size(btn, btn_w, UI_POPUP_BTN_H);
  lv_obj_set_pos(btn, UI_CARD_ROW_X, UI_CARD_ROW_Y);
  lv_obj_set_style_bg_color(btn, lv_color_hex(done ? UI_COL_OK_BG : UI_COL_LINE), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(done ? UI_COL_OK_BG_PRESSED : UI_COL_POPUP_BORDER),
                            LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_set_style_pad_all(btn, 0, 0);
  lv_obj_clear_flag(btn, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    closeInfoPopupOf(lv_event_get_target(e));
  }, LV_EVENT_CLICKED, NULL);

  if (done) {
    // The countdown: a lighter fill that drains from the right. Behind the
    // label, and not clickable, so a tap anywhere on the button still lands
    // on the button. When it is empty the card closes as if OK was pressed.
    lv_obj_t *fill = lv_obj_create(btn);
    lv_obj_remove_style_all(fill);
    lv_obj_set_size(fill, btn_w, UI_POPUP_BTN_H);
    lv_obj_set_pos(fill, 0, 0);
    lv_obj_set_style_bg_color(fill, lv_color_hex(UI_COL_OK_BG_PRESSED), 0);
    lv_obj_set_style_bg_opa(fill, LV_OPA_COVER, 0);
    lv_obj_set_style_radius(fill, UI_RADIUS_BTN, 0);
    lv_obj_clear_flag(fill, LV_OBJ_FLAG_CLICKABLE);
    lv_anim_t a;
    lv_anim_init(&a);
    lv_anim_set_var(&a, fill);
    lv_anim_set_values(&a, btn_w, 0);
    lv_anim_set_time(&a, INFO_DONE_CLOSE_MS);
    lv_anim_set_exec_cb(&a, [](void *obj, int32_t v) {
      lv_obj_set_width((lv_obj_t *)obj, (lv_coord_t)v);
    });
    lv_anim_set_ready_cb(&a, [](lv_anim_t *anim) {
      closeInfoPopupOf((lv_obj_t *)anim->var);
    });
    lv_anim_start(&a);
  }

  lv_obj_t *l = lv_label_create(btn);
  lv_label_set_text(l, T(STR_BTN_OK));
  lv_obj_set_style_text_color(l, lv_color_hex(done ? UI_COL_OK_TEXT : UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(l, UI_FONT_TITLE, 0);
  lv_obj_center(l);
}

void showInfoPopup(int title_id, int text_id, uint8_t tone) {
  if (title_id < 0 || title_id >= STR_COUNT) return;
  if (text_id  < 0 || text_id  >= STR_COUNT) return;

  lv_obj_t *pop = lv_obj_create(lv_scr_act());
  // One at a time. A second one over the first would leave the pointer below
  // naming the newer and the older standing there forever.
  if (s_info_pop) lv_obj_del_async(s_info_pop);
  s_info_pop = pop;
  lv_obj_set_size(pop, 480, 320);
  lv_obj_set_pos(pop, 0, 0);
  lv_obj_set_style_bg_color(pop, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(pop, LV_OPA_70, 0);
  lv_obj_set_style_border_width(pop, 0, 0);
  lv_obj_set_style_radius(pop, 0, 0);
  lv_obj_set_style_pad_all(pop, 0, 0);
  lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

  if (tone != INFO_PLAIN) {
    buildResultCard(pop, title_id, text_id, tone);
    return;
  }

  // Help text behind a settings row from here on.
  lv_obj_t *box = lv_obj_create(pop);
  lv_obj_set_size(box, 440, 250);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x2a4080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Title: the name of the setting, so the popup is anchored to the row the
  // user tapped rather than being a floating paragraph.
  lv_obj_t *title = lv_label_create(box);
  char tbuf[INFO_TITLE_BUF];
  copyT(tbuf, sizeof(tbuf), title_id);
  lv_label_set_text(title, tbuf);
  lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(title, 424);
  lv_obj_set_pos(title, 8, 14);

  // The text scrolls instead of being clipped. Some settings genuinely need a
  // paragraph to explain, and a reader who can flick is better served than one
  // who silently loses the last third.
  lv_obj_t *scroll = lv_obj_create(box);
  lv_obj_set_size(scroll, 424, 128);
  lv_obj_set_pos(scroll, 8, 48);
  lv_obj_set_style_bg_opa(scroll, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(scroll, 0, 0);
  lv_obj_set_style_pad_all(scroll, 0, 0);
  lv_obj_set_scroll_dir(scroll, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(scroll, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(scroll, LV_OBJ_FLAG_SCROLL_ELASTIC);

  lv_obj_t *info = lv_label_create(scroll);
  lv_label_set_text(info, infoText(text_id));
  lv_obj_set_style_text_color(info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(info, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
  // 14 px narrower than the container so the scrollbar has somewhere to sit.
  lv_obj_set_width(info, 410);
  lv_obj_set_pos(info, 0, 0);
  // A short text sits in the middle of the area, not against its top edge: a
  // one line result over half a box of nothing read as unfinished. A long one
  // keeps the top, so the scroll starts at its first word.
  lv_obj_update_layout(info);
  if (lv_obj_get_height(info) <= lv_obj_get_height(scroll))
    lv_obj_align(info, LV_ALIGN_CENTER, 0, 0);

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
    lv_obj_t *scrim = lv_obj_get_parent(box);
    // Cleared here, not in a delete callback: the async free happens a pass
    // later, and anything asking in between has to be told the question is
    // already answered.
    if (scrim == s_info_pop) s_info_pop = nullptr;
    lv_obj_del_async(scrim);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *l = lv_label_create(btn);
  char bbuf[24];
  copyT(bbuf, sizeof(bbuf), STR_BACK);
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
