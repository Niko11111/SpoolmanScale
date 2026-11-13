#include "choice_grid.h"

#include <Arduino.h>
#include <lvgl.h>

#include "ui_common.h"

// Last, like everywhere else.
#include "lang.h"
#include "theme.h"

#define CG_BOX_W        460
#define CG_HDR_H        44
#define CG_PAD          8
#define CG_GAP          6
#define CG_CELL_H       72    // caption, value, tag
#define CG_CELL_H_SHAPE 124   // the same with a label outline above the value
#define CG_SHAPE_PX_PER_MM_X10 12   // 50 mm draws 60 px
// The slot holds the largest outline and its border: 60 mm across (the
// 60 x 30 roll), 50 mm tall (the 50 x 50 one).
#define CG_SHAPE_SLOT_W_PX 74
#define CG_SHAPE_SLOT_H_PX 62
#define CG_SHAPE_LINE_PX 2          // the outline's stroke
#define CG_CLOSE_SIZE   40
#define CG_SCREEN_W     480
#define CG_SCREEN_H     320
#define CG_MARGIN       8     // between the box and the screen's edge

static lv_obj_t*    s_scr = nullptr;
static ChoicePickCb s_cb  = nullptr;
static int          s_pick = -1;
// Two stages, as in the status picker: the overlay is freed in one pass and
// the answer delivered in the next, so whatever the answer starts never runs
// with the grid still on screen.
static bool s_close_pending   = false;
static bool s_deliver_pending = false;

void closeChoiceGrid() {
  releaseScreen(&s_scr);
  s_cb = nullptr;
  s_pick = -1;
  s_close_pending = false;
  s_deliver_pending = false;
}

static void cardCb(lv_event_t* e) {
  s_pick = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
  s_close_pending = true;
}

static void cancelCb(lv_event_t* e) {
  s_pick = -1;
  s_close_pending = true;
}

static lv_obj_t* addText(lv_obj_t* parent, const char* text, const lv_font_t* font,
                         uint32_t colour, int width) {
  lv_obj_t* l = lv_label_create(parent);
  if (!l) return nullptr;
  lv_label_set_text(l, text);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(colour), 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(l, width);
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  return l;
}

// The outline sits centred in a slot as tall as the tallest one, so the
// values below line up whatever the shapes.
static void addShape(lv_obj_t* card, const ChoiceCard& c, uint32_t colour) {
  lv_obj_t* slot = lv_obj_create(card);
  if (!slot) return;
  lv_obj_set_size(slot, CG_SHAPE_SLOT_W_PX, CG_SHAPE_SLOT_H_PX);
  lv_obj_set_style_bg_opa(slot, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(slot, 0, 0);
  lv_obj_set_style_pad_all(slot, 0, 0);
  lv_obj_clear_flag(slot, (lv_obj_flag_t)(LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE));
  lv_obj_t* r = lv_obj_create(slot);
  if (!r) return;
  lv_obj_center(r);
  lv_obj_set_size(r, c.shape_w_mm * CG_SHAPE_PX_PER_MM_X10 / 10,
                  c.shape_h_mm * CG_SHAPE_PX_PER_MM_X10 / 10);
  lv_obj_set_style_bg_opa(r, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_color(r, lv_color_hex(colour), 0);
  lv_obj_set_style_border_width(r, CG_SHAPE_LINE_PX, 0);
  lv_obj_set_style_radius(r, UI_RADIUS_OUTLINE, 0);
  lv_obj_set_style_pad_all(r, 0, 0);
  lv_obj_clear_flag(r, (lv_obj_flag_t)(LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE));
}

// The look of a card: the current one in the "this is yours" green of the
// status picker, a disabled one greyed, the rest plain.
static uint32_t styleCard(lv_obj_t* card, bool current, bool enabled) {
  lv_obj_set_style_radius(card, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(card, 0, 0);
  lv_obj_set_style_border_width(card, 1, 0);
  lv_obj_set_style_pad_all(card, 4, 0);
  if (!enabled) {
    lv_obj_set_style_bg_color(card, lv_color_hex(UI_COL_DISABLED_BG), 0);
    lv_obj_set_style_border_color(card, lv_color_hex(UI_COL_DIVIDER), 0);
    return UI_COL_DISABLED_TEXT;
  }
  const uint32_t bg = current ? UI_COL_GO_BG : UI_COL_CHIP;
  lv_obj_set_style_bg_color(card, lv_color_hex(bg), 0);
  lv_obj_set_style_bg_color(card, lv_color_hex(UI_COL_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_color(card, lv_color_hex(current ? UI_COL_ACCENT : UI_COL_DIVIDER), 0);
  return current ? UI_COL_ACCENT : UI_COL_INK_BRIGHT;
}

static lv_obj_t* buildCard(lv_obj_t* parent, const ChoiceCard& c, int index, bool current,
                           const lv_area_t& at) {
  lv_obj_t* card = lv_btn_create(parent);
  if (!card) return nullptr;
  lv_obj_set_pos(card, at.x1, at.y1);
  lv_obj_set_size(card, lv_area_get_width(&at), lv_area_get_height(&at));
  const uint32_t ink = styleCard(card, current, c.enabled);
  lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(card, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  if (c.enabled) {
    lv_obj_set_user_data(card, (void*)(intptr_t)index);
    lv_obj_add_event_cb(card, cardCb, LV_EVENT_CLICKED, nullptr);
  } else {
    lv_obj_clear_flag(card, LV_OBJ_FLAG_CLICKABLE);
  }

  const int text_w = lv_area_get_width(&at) - 8;
  if (c.caption)
    addText(card, c.caption, UI_FONT_CAPTION, c.enabled ? UI_COL_CAPTION : ink, text_w);
  if (c.shape_w_mm) addShape(card, c, ink);
  addText(card, c.value, UI_FONT_BODY, ink, text_w);
  // An empty tag line still takes its place, so every value sits at the
  // same height across the grid.
  const uint32_t tag_col = !c.enabled ? ink
                         : c.tag == CHOICE_TAG_GOOD ? UI_COL_GOOD : UI_COL_WARN;
  addText(card, c.tag == CHOICE_TAG_NONE ? "" : T((StringID)c.tag_text),
          UI_FONT_CAPTION, tag_col, text_w);
  return card;
}

static void buildHeader(lv_obj_t* box, int title) {
  lv_obj_t* hdr = lv_obj_create(box);
  if (!hdr) return;
  lv_obj_set_size(hdr, CG_BOX_W, CG_HDR_H);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(UI_COL_GROUND), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* t = lv_label_create(hdr);
  if (t) {
    lv_label_set_text(t, T((StringID)title));
    lv_obj_set_style_text_color(t, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_text_font(t, UI_FONT_TITLE, 0);
    lv_obj_align(t, LV_ALIGN_CENTER, 0, 0);
  }

  lv_obj_t* x = lv_btn_create(hdr);
  if (!x) return;
  lv_obj_set_size(x, CG_CLOSE_SIZE, CG_CLOSE_SIZE);
  lv_obj_align(x, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(x, lv_color_hex(UI_COL_BAD_BG), 0);
  lv_obj_set_style_bg_color(x, lv_color_hex(UI_COL_BAD_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(x, 1, 0);
  lv_obj_set_style_border_color(x, lv_color_hex(UI_COL_CLOSE_LINE), 0);
  lv_obj_set_style_radius(x, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(x, 0, 0);
  lv_obj_add_event_cb(x, cancelCb, LV_EVENT_CLICKED, nullptr);
  lv_obj_t* lx = lv_label_create(x);
  if (!lx) return;
  lv_label_set_text(lx, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lx, lv_color_hex(UI_COL_BAD_TEXT), 0);
  lv_obj_set_style_text_font(lx, UI_FONT_TITLE, 0);
  lv_obj_center(lx);
}

static lv_obj_t* buildBox(int height) {
  s_scr = lv_obj_create(lv_scr_act());
  if (!s_scr) return nullptr;
  lv_obj_set_size(s_scr, CG_SCREEN_W, CG_SCREEN_H);
  lv_obj_set_pos(s_scr, 0, 0);
  lv_obj_set_style_bg_color(s_scr, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_scr, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_scr, 0, 0);
  lv_obj_set_style_radius(s_scr, 0, 0);
  lv_obj_set_style_pad_all(s_scr, 0, 0);
  lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* box = lv_obj_create(s_scr);
  if (!box) return nullptr;
  lv_obj_set_size(box, CG_BOX_W, height);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_clip_corner(box, true, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  return box;
}

// The cards' area below the header. As tall as the cards need, up to what the
// screen leaves; beyond that it scrolls, and the row cut off at its bottom
// edge shows that there is more.
static lv_obj_t* buildArea(lv_obj_t* box, int content_h, int height) {
  lv_obj_t* area = lv_obj_create(box);
  if (!area) return nullptr;
  lv_obj_set_pos(area, 0, CG_HDR_H);
  lv_obj_set_size(area, CG_BOX_W, height);
  lv_obj_set_style_bg_opa(area, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(area, 0, 0);
  lv_obj_set_style_radius(area, 0, 0);
  lv_obj_set_style_pad_all(area, 0, 0);
  lv_obj_set_style_pad_bottom(area, CG_PAD, 0);
  if (content_h <= height) lv_obj_clear_flag(area, LV_OBJ_FLAG_SCROLLABLE);
  else lv_obj_set_scroll_dir(area, LV_DIR_VER);
  return area;
}

void showChoiceGrid(int title, const ChoiceCard* cards, int count,
                    int current, int cols, ChoicePickCb cb) {
  closeChoiceGrid();
  if (count < 1 || count > CHOICE_GRID_MAX || cols < 1 || !lvPoolHasRoomForRow()) return;
  s_cb = cb;

  bool shapes = false;
  for (int i = 0; i < count; i++) shapes = shapes || cards[i].shape_w_mm;
  const int cell_h = shapes ? CG_CELL_H_SHAPE : CG_CELL_H;
  const int cell_w = (CG_BOX_W - 2 * CG_PAD - (cols - 1) * CG_GAP) / cols;
  const int rows = (count + cols - 1) / cols;
  const int content_h = 2 * CG_PAD + rows * cell_h + (rows - 1) * CG_GAP;
  const int room_h = CG_SCREEN_H - 2 * CG_MARGIN - CG_HDR_H;
  const int area_h = content_h < room_h ? content_h : room_h;
  lv_obj_t* box = buildBox(CG_HDR_H + area_h);
  lv_obj_t* area = box ? buildArea(box, content_h, area_h) : nullptr;
  if (!area) { closeChoiceGrid(); return; }
  buildHeader(box, title);

  lv_obj_t* picked = nullptr;
  for (int i = 0; i < count; i++) {
    lv_area_t at;
    at.x1 = CG_PAD + (i % cols) * (cell_w + CG_GAP);
    at.y1 = CG_PAD + (i / cols) * (cell_h + CG_GAP);
    at.x2 = at.x1 + cell_w - 1;
    at.y2 = at.y1 + cell_h - 1;
    lv_obj_t* card = buildCard(area, cards[i], i, i == current, at);
    if (i == current) picked = card;
  }
  // The current choice in view, also when it sits further down.
  if (picked) lv_obj_scroll_to_view(picked, LV_ANIM_OFF);
}

void handleChoiceGridDeferredActions() {
  // Delivery first, so one pass never does both stages.
  if (s_deliver_pending) {
    s_deliver_pending = false;
    ChoicePickCb cb = s_cb;
    const int pick = s_pick;
    s_cb = nullptr;
    s_pick = -1;
    if (cb) cb(pick);
    return;
  }
  if (s_close_pending) {
    s_close_pending = false;
    releaseScreen(&s_scr);
    s_deliver_pending = true;
  }
}
