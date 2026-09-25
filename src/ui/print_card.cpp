#include "print_card.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ble_service.h"
#include "ui/theme.h"

// Busy, the card is as short as the wait card, which looked empty at the
// house card's height (Nikolai, 23.09.2026). The answer takes the house
// card's height and rows: icon, title, text, a button across.
#define PC_BUSY_H          170
#define PC_ARC_SIZE        44
#define PC_ARC_Y           18
#define PC_ARC_W           6
#define PC_ARC_DEG         70
#define PC_ARC_STEP_DEG    18
#define PC_BUSY_TITLE_Y    76
#define PC_BUSY_TEXT_Y     120
#define PC_TEXT_W          (UI_POPUP_W - UI_CARD_TEXT_PAD)

// The session calls back far more often than a frame is worth drawing.
#define PC_TICK_MS         60

// A confirmed print closes on its own after this long; a problem waits.
#define PC_AUTOCLOSE_MS    4000

static lv_obj_t* s_scr    = nullptr;
static lv_obj_t* s_box    = nullptr;
static lv_obj_t* s_arc    = nullptr;
static lv_obj_t* s_title  = nullptr;
static lv_obj_t* s_text   = nullptr;
static lv_obj_t* s_btn_l  = nullptr;

static unsigned long s_last_tick  = 0;
static uint16_t      s_angle      = 0;
static int           s_shown_phase = -1;
static int           s_shown_pct   = -1;
static bool          s_close_req  = false;

static lv_obj_t* makeLabel(lv_obj_t* parent, const lv_font_t* font, uint32_t color,
                           lv_coord_t y) {
  lv_obj_t* l = lv_label_create(parent);
  lv_label_set_text(l, "");
  lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, PC_TEXT_W);
  lv_obj_align(l, LV_ALIGN_TOP_MID, 0, y);
  return l;
}

void printCardShow() {
  if (s_scr) return;
  logSD("SHOW: PrintCard");
  s_shown_phase = -1;
  s_shown_pct   = -1;
  s_close_req   = false;
  s_btn_l       = nullptr;

  s_scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(s_scr, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(s_scr, 0, 0);
  lv_obj_set_style_bg_color(s_scr, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_scr, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_scr, 0, 0);
  lv_obj_set_style_radius(s_scr, 0, 0);
  lv_obj_set_style_pad_all(s_scr, 0, 0);
  lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_SCROLLABLE);
  // Swallows touches meant for the screen underneath.
  lv_obj_add_flag(s_scr, LV_OBJ_FLAG_CLICKABLE);

  s_box = lv_obj_create(s_scr);
  lv_obj_set_size(s_box, UI_POPUP_W, PC_BUSY_H);
  lv_obj_align(s_box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(s_box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(s_box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(s_box, 2, 0);
  lv_obj_set_style_radius(s_box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(s_box, 0, 0);
  lv_obj_clear_flag(s_box, LV_OBJ_FLAG_SCROLLABLE);

  // An arc turned by hand rather than a spinner: LVGL's animations do not
  // run while the session holds the loop, printCardTick() does.
  s_arc = lv_arc_create(s_box);
  lv_obj_set_size(s_arc, PC_ARC_SIZE, PC_ARC_SIZE);
  lv_obj_align(s_arc, LV_ALIGN_TOP_MID, 0, PC_ARC_Y);
  lv_arc_set_bg_angles(s_arc, 0, 360);
  lv_arc_set_angles(s_arc, 0, PC_ARC_DEG);
  lv_obj_remove_style(s_arc, NULL, LV_PART_KNOB);
  lv_obj_clear_flag(s_arc, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_set_style_arc_width(s_arc, PC_ARC_W, LV_PART_MAIN);
  lv_obj_set_style_arc_width(s_arc, PC_ARC_W, LV_PART_INDICATOR);
  lv_obj_set_style_arc_color(s_arc, lv_color_hex(UI_COL_LINE), LV_PART_MAIN);
  lv_obj_set_style_arc_color(s_arc, lv_color_hex(UI_COL_ACCENT), LV_PART_INDICATOR);

  s_title = makeLabel(s_box, UI_FONT_HEADLINE, UI_COL_INK, PC_BUSY_TITLE_Y);
  lv_label_set_text(s_title, T(STR_PRN_PH_RENDER));
  s_text = makeLabel(s_box, UI_FONT_BODY, UI_COL_INK_SOFT, PC_BUSY_TEXT_Y);

  s_last_tick = millis();
  lv_refr_now(NULL);
}

static int phaseText(BleSessionPhase p) {
  switch (p) {
    case BLE_PHASE_FIND:    return STR_PRN_PH_FIND;
    case BLE_PHASE_CONNECT: return STR_PRN_PH_CONNECT;
    case BLE_PHASE_SEND:    return STR_PRN_PH_SEND;
    case BLE_PHASE_AWAIT:   return STR_PRN_PH_AWAIT;
    default:                return STR_PRN_PH_RENDER;
  }
}

void printCardTick() {
  if (!s_scr || !s_arc) return;
  const unsigned long now = millis();
  if (now - s_last_tick < PC_TICK_MS) return;
  s_last_tick = now;

  s_angle = (uint16_t)((s_angle + PC_ARC_STEP_DEG) % 360);
  lv_arc_set_angles(s_arc, s_angle, (s_angle + PC_ARC_DEG) % 360);

  const BleSessionPhase phase = bleSessionPhase();
  if ((int)phase != s_shown_phase) {
    s_shown_phase = (int)phase;
    lv_label_set_text(s_title, T(phaseText(phase)));
    lv_label_set_text(s_text, "");
    s_shown_pct = -1;
  }
  if (phase == BLE_PHASE_SEND) {
    size_t sent = 0, total = 0;
    bleSessionBytes(&sent, &total);
    const int pct = total ? (int)(sent * 100 / total) : 0;
    if (pct != s_shown_pct) {
      s_shown_pct = pct;
      char buf[12];
      snprintf(buf, sizeof(buf), "%d %%", pct);
      lv_label_set_text(s_text, buf);
    }
  }
  lv_refr_now(NULL);
}

void printCardResult(LabelPrintResult result) {
  if (!s_scr) printCardShow();
  if (s_arc) { lv_obj_del(s_arc); s_arc = nullptr; }

  const bool ok = (result == LP_OK);
  const bool unconfirmed = (result == LP_SENT_UNCONFIRMED);
  const char* symbol = ok ? LV_SYMBOL_OK : LV_SYMBOL_WARNING;
  const uint32_t tone = ok ? UI_COL_ACCENT : (unconfirmed ? UI_COL_WARN : UI_COL_BAD);
  const int title = ok ? STR_PRN_DONE_TITLE
                  : unconfirmed ? STR_PRN_UNCONF_TITLE : STR_PRN_FAIL_TITLE;
  const int text = ok ? STR_PRN_DONE_MSG : labelPrintResultString(result);

  lv_obj_set_size(s_box, UI_POPUP_W, UI_CARD_H);
  lv_obj_align(s_box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_border_color(s_box, lv_color_hex(tone), 0);

  lv_obj_t* icon = lv_label_create(s_box);
  lv_label_set_text(icon, symbol);
  lv_obj_set_style_text_color(icon, lv_color_hex(tone), 0);
  lv_obj_set_style_text_font(icon, UI_FONT_ICON, 0);
  lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, UI_CARD_ICON_Y);

  lv_label_set_text(s_title, T(title));
  lv_obj_align(s_title, LV_ALIGN_TOP_MID, 0, UI_CARD_TITLE_Y);
  lv_label_set_text(s_text, T(text));
  lv_obj_set_style_text_color(s_text, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_align(s_text, LV_ALIGN_TOP_MID, 0, UI_CARD_TEXT_Y);

  lv_obj_t* btn = lv_btn_create(s_box);
  lv_obj_set_size(btn, UI_POPUP_W - 2 * UI_CARD_ROW_X, UI_POPUP_BTN_H);
  lv_obj_set_pos(btn, UI_CARD_ROW_X, UI_CARD_ROW_Y);
  lv_obj_set_style_bg_color(btn, lv_color_hex(ok ? UI_COL_OK_BG : UI_COL_LINE), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(ok ? UI_COL_OK_BG_PRESSED : UI_COL_POPUP_BORDER),
                            LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_set_style_pad_all(btn, 0, 0);
  lv_obj_clear_flag(btn, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(btn, [](lv_event_t*) { s_close_req = true; }, LV_EVENT_CLICKED, NULL);

  if (ok) {
    // The house countdown (ui/info_popup.cpp): a lighter fill that drains
    // from the right behind the label; empty, it closes the card as OK does.
    // Closing itself stays with printCardLoop().
    const lv_coord_t btn_w = UI_POPUP_W - 2 * UI_CARD_ROW_X;
    lv_obj_t* fill = lv_obj_create(btn);
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
    lv_anim_set_time(&a, PC_AUTOCLOSE_MS);
    lv_anim_set_exec_cb(&a, [](void* obj, int32_t v) {
      lv_obj_set_width((lv_obj_t*)obj, (lv_coord_t)v);
    });
    lv_anim_set_ready_cb(&a, [](lv_anim_t*) { s_close_req = true; });
    lv_anim_start(&a);
  }

  s_btn_l = lv_label_create(btn);
  lv_label_set_text(s_btn_l, T(STR_BTN_OK));
  lv_obj_set_style_text_color(s_btn_l, lv_color_hex(ok ? UI_COL_OK_TEXT : UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(s_btn_l, UI_FONT_TITLE, 0);
  lv_obj_center(s_btn_l);
  logSDf("PrintCard: result=%d", (int)result);
}

bool printCardOpen() { return s_scr != nullptr; }

void printCardLoop() {
  if (!s_scr || !s_close_req) return;
  // lv_obj_del() takes the running countdown animation with the fill.
  lv_obj_del(s_scr);
  s_scr = s_box = s_arc = s_title = s_text = s_btn_l = nullptr;
  s_close_req = false;
}
