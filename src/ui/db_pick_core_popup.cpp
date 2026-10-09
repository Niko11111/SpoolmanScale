#include "ui/db_pick_core_popup.h"

#include <Arduino.h>
#include <lvgl.h>
#include <stdio.h>

// filament_db.h brings tag_create.h; lang.h after it, which defines T().
#include "services/filament_db.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/entry_tile.h"
#include "ui/tag_create_popup.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// The most a maker has is four (Sunlu, 09.10.2026); three rows of two fit.
#define DBC_CHOICES_MAX   6
#define DBC_COLS          2
#define DBC_GAP           8
#define DBC_BTN_W         ((UI_POPUP_W - 2 * UI_CARD_ROW_X - DBC_GAP) / 2)
#define DBC_CHOICE_H      52
#define DBC_BOTTOM_H      44
#define DBC_NAME_Y        6
#define DBC_WEIGHT_Y      28

// What the buttons park: a choice's index, or one of these.
#define DBC_ANSWER_NONE    (-1)
#define DBC_ANSWER_WITHOUT (-2)
#define DBC_ANSWER_CANCEL  (-3)

static lv_obj_t*      s_scr = nullptr;
static TagCreateInput s_in;
static FdbCore        s_choices[DBC_CHOICES_MAX];
static int            s_n = 0;
static int            s_answer = DBC_ANSWER_NONE;

bool dbPickCoreOpen() { return s_scr != nullptr; }

void dbPickCoreClose() {
  releaseScreen(&s_scr);
  s_answer = DBC_ANSWER_NONE;
}

static void take(const FdbCore& c) {
  s_in.spool_weight_g   = c.weight_g;
  s_in.spool_catalog_id = c.id;
}

static void park(lv_event_t* e) {
  s_answer = (int)(intptr_t)lv_event_get_user_data(e);
  logSDf("BTN: DbPickCore -> %d", s_answer);
  // Hidden here, deleted by the loop: this is the button's own callback.
  if (s_scr) lv_obj_add_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
}

static lv_obj_t* button(lv_obj_t* box, const EntryRect& r, bool first, int answer) {
  lv_obj_t* b = lv_btn_create(box);
  lv_obj_set_size(b, r.w, r.h);
  lv_obj_set_pos(b, r.x, r.y);
  lv_obj_set_style_bg_color(b, lv_color_hex(first ? UI_COL_OK_BG : UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(first ? UI_COL_OK_BG_PRESSED : UI_COL_ROW_PRESS_FILL),
                            LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, first ? 0 : 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_LINE), 0);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  // Name and weight are placed in the button's own height.
  lv_obj_set_style_pad_all(b, 0, 0);
  lv_obj_add_event_cb(b, park, LV_EVENT_CLICKED, (void*)(intptr_t)answer);
  return b;
}

static lv_obj_t* text(lv_obj_t* parent, const char* s, const lv_font_t* font, uint32_t color) {
  lv_obj_t* l = lv_label_create(parent);
  lv_label_set_text(l, s);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
  return l;
}

// One empty spool: its kind over its weight.
static void choice(lv_obj_t* box, int i, const char* maker) {
  const EntryRect r = { (lv_coord_t)(UI_CARD_ROW_X + (i % DBC_COLS) * (DBC_BTN_W + DBC_GAP)),
                        (lv_coord_t)(UI_CARD_TITLE_Y + (i / DBC_COLS) * (DBC_CHOICE_H + DBC_GAP)),
                        DBC_BTN_W, DBC_CHOICE_H };
  const bool first = i == 0 && s_choices[0].last_spool > 0;
  lv_obj_t* b = button(box, r, first, i);
  char name[FDB_CORE_NAME_MAX];
  fdbCoreShortName(s_choices[i], maker, name, sizeof(name));
  lv_obj_t* l = text(b, name[0] ? name : s_choices[i].name, UI_FONT_BODY, first ? UI_COL_OK_TEXT : UI_COL_INK);
  // A catalog name is the user's to edit: it may run long.
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  lv_obj_set_width(l, DBC_BTN_W - 2 * DBC_GAP);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(l, LV_ALIGN_TOP_MID, 0, DBC_NAME_Y);
  char grams[12];
  snprintf(grams, sizeof(grams), "%u g", (unsigned)s_choices[i].weight_g);
  lv_obj_t* w = text(b, grams, UI_FONT_SMALL, first ? UI_COL_OK_TEXT_2 : UI_COL_INK_SOFT);
  lv_obj_align(w, LV_ALIGN_TOP_MID, 0, DBC_WEIGHT_Y);
}

static void bottomButton(lv_obj_t* box, int col, int y, int answer, int caption) {
  const EntryRect r = { (lv_coord_t)(UI_CARD_ROW_X + col * (DBC_BTN_W + DBC_GAP)), (lv_coord_t)y,
                        DBC_BTN_W, DBC_BOTTOM_H };
  lv_obj_t* b = button(box, r, false, answer);
  const bool cancel = answer == DBC_ANSWER_CANCEL;
  // Red like every other cancel button (ui/entry_tile.cpp).
  if (cancel) {
    lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_BAD_BG), 0);
    lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_BAD_BG_PRESSED), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(b, 0, 0);
  }
  lv_obj_center(text(b, T(caption), UI_FONT_BODY, cancel ? UI_COL_BAD_TEXT : UI_COL_INK));
}

static void build() {
  const int rows = (s_n + DBC_COLS - 1) / DBC_COLS;
  const int bottom_y = UI_CARD_TITLE_Y + rows * (DBC_CHOICE_H + DBC_GAP);
  s_scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(s_scr, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(s_scr, 0, 0);
  lv_obj_set_style_bg_color(s_scr, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_scr, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_scr, 0, 0);
  lv_obj_set_style_radius(s_scr, 0, 0);
  lv_obj_set_style_pad_all(s_scr, 0, 0);
  lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* box = lv_obj_create(s_scr);
  lv_obj_set_size(box, UI_POPUP_W, bottom_y + DBC_BOTTOM_H + UI_CARD_ROW_X);
  lv_obj_center(box);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* title = text(box, T(STR_DBPICK_CORE_TITLE), UI_FONT_HEADLINE, UI_COL_INK);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, UI_CARD_ICON_Y);
  for (int i = 0; i < s_n; i++) choice(box, i, s_in.vendor);
  bottomButton(box, 0, bottom_y, DBC_ANSWER_WITHOUT, STR_DBPICK_CORE_NONE);
  bottomButton(box, 1, bottom_y, DBC_ANSWER_CANCEL, STR_CANCEL);
}

bool dbPickCoreAsk(TagCreateInput* in) {
  if (!in || in->spool_weight_g > 0) return false;
  const FdbCore* found[DBC_CHOICES_MAX];
  const int n = fdbCoreChoices(in->vendor, found, DBC_CHOICES_MAX);
  logSDf("DbPickCore: %s has %d empty spool(s) in the catalog", in->vendor, n);
  if (n == 0) return false;
  if (n == 1) {
    in->spool_weight_g   = found[0]->weight_g;
    in->spool_catalog_id = found[0]->id;
    return false;
  }
  dbPickCoreClose();
  s_in = *in;
  s_n = n;
  for (int i = 0; i < n; i++) s_choices[i] = *found[i];
  logSD("SHOW: DbPickCore");
  build();
  return true;
}

void dbPickCoreTick() {
  if (s_answer == DBC_ANSWER_NONE) return;
  const int answer = s_answer;
  dbPickCoreClose();
  if (answer == DBC_ANSWER_CANCEL) return;
  if (answer >= 0 && answer < s_n) take(s_choices[answer]);
  logSDf("DbPickCore: empty spool %d g, catalog id %d", s_in.spool_weight_g, s_in.spool_catalog_id);
  showTagCreatePopupFor(s_in);
}
