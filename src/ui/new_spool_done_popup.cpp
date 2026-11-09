#include "ui/new_spool_done_popup.h"

#include <Arduino.h>
#include <stdio.h>

// backend_api.h brings ArduinoJson, whose templates have a parameter T:
// before lang.h, which defines T().
#include "services/backend_api.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ble_service.h"
#include "services/label_printer.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// Under the title, the number; under the number, the sentence.
#define NSD_NUMBER_Y   84
#define NSD_HINT_Y    128

static lv_obj_t* s_popup    = nullptr;
static lv_obj_t* s_lbl_icon = nullptr;
static int       s_spool_id = 0;
static bool      s_tag_at_open = false;   // a tag that lay there already does not close it

lv_obj_t* newSpoolDoneScreen() { return s_popup; }

static lv_obj_t* cardText(lv_obj_t* box, const char* text, const lv_font_t* font, uint32_t col, int y) {
  lv_obj_t* l = lv_label_create(box);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(l, LV_ALIGN_TOP_MID, 0, y);
  return l;
}

// The green one goes ahead, the plain one only closes.
static lv_obj_t* cardButton(lv_obj_t* box, int x, int w, const char* text, bool green) {
  lv_obj_t* b = padButton(box, x, UI_CARD_ROW_Y, w, UI_POPUP_BTN_H, green ? UI_COL_OK_BG : UI_COL_ROW,
                          green ? UI_COL_OK_BG_PRESSED : UI_COL_ROW_PRESS_FILL);
  padLabel(b, text, UI_COL_INK, UI_FONT_BODY);
  return b;
}

// As the More info header decides it: a Bluetooth printer that is set up,
// or without one FilaMan, which prints on the PC.
static bool btPrinterReady() {
  return bleEnabled() && labelPrinterConfigured(labelPrinterLoadConfig());
}

static void onLabel(lv_event_t*) {
  logSDf("BTN: NewSpoolDone -> label for spool %d", s_spool_id);
  if (!btPrinterReady()) show_pc_print_pending = true;
  else if (labelPrinterAskFirst()) show_print_sheet_pending = true;
  else print_spool_label_pending = true;
  releaseScreen(&s_popup);
}

static void onDone(lv_event_t*) {
  logSD("BTN: NewSpoolDone -> done");
  releaseScreen(&s_popup);
}

void showNewSpoolDone(int spool_id, bool shown) {
  logSDf("SHOW: NewSpoolDone (spool %d, shown %d)", spool_id, (int)shown);
  s_spool_id = spool_id;
  s_tag_at_open = tag_present;
  const bool bt_print = btPrinterReady();
  // Read here, so the tap finds it cached and never opens NVS itself.
  labelPrinterAskFirst();
  const bool can_print = shown && (bt_print || backendIsFilaMan());

  lv_obj_t* box = uiPopupBox(&s_popup, UI_POPUP_W, UI_CARD_H);
  s_lbl_icon = cardText(box, LV_SYMBOL_OK, UI_FONT_ICON, UI_COL_GOOD, UI_CARD_ICON_Y);
  cardText(box, T(STR_NEWSPOOL_DONE), UI_FONT_HEADLINE, UI_COL_INK, UI_CARD_TITLE_Y);
  char num[16];
  snprintf(num, sizeof(num), "#%d", spool_id);
  cardText(box, num, UI_FONT_BIG_NUMBER, UI_COL_ACCENT, NSD_NUMBER_Y);
  const int hint = !shown ? STR_NEWSPOOL_HINT_NOT_SHOWN
                 : can_print ? STR_NEWSPOOL_HINT_LABEL : STR_NEWSPOOL_HINT_WRITE;
  cardText(box, T(hint), UI_FONT_BODY, UI_COL_INK_2, NSD_HINT_Y);

  if (can_print) {
    lv_obj_t* label = cardButton(box, UI_CARD_ROW_X, UI_POPUP_BTN_W, T(STR_PRN_LABEL_PRINT), true);
    lv_obj_add_event_cb(label, onLabel, LV_EVENT_CLICKED, NULL);
    lv_obj_t* done = cardButton(box, UI_POPUP_W - UI_POPUP_BTN_W - UI_CARD_ROW_X, UI_POPUP_BTN_W,
                                T(STR_W_T2_DONE_BTN), false);
    lv_obj_add_event_cb(done, onDone, LV_EVENT_CLICKED, NULL);
    return;
  }
  lv_obj_t* done = cardButton(box, UI_CARD_ROW_X, UI_POPUP_W - 2 * UI_CARD_ROW_X, T(STR_W_T2_DONE_BTN), true);
  lv_obj_add_event_cb(done, onDone, LV_EVENT_CLICKED, NULL);
}

void newSpoolDonePriceLost() {
  if (!s_popup || !s_lbl_icon) return;
  lv_label_set_text(s_lbl_icon, T(STR_TAGNEW_PRICE_LOST));
  lv_obj_set_style_text_font(s_lbl_icon, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_color(s_lbl_icon, lv_color_hex(UI_COL_WARN), 0);
}

void newSpoolDoneTick() {
  if (!s_popup) return;
  if (!tag_present) s_tag_at_open = false;
  // A spool that did not load leaves sm_id at 0: the card stays for its
  // number until a tag put down after it or another spool takes the display.
  const bool new_tag = tag_present && !s_tag_at_open;
  const bool replaced = new_tag || (sm_id != 0 && sm_id != s_spool_id);
  if (!replaced) return;
  logSDf("UI: new spool card for %d closed, spool %d is shown now", s_spool_id, sm_id);
  releaseScreen(&s_popup);
}
