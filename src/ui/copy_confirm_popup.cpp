#include "ui/spool_flow_internal.h"
#include "spool_flow.h"
#include "ui_common.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/theme.h"

// ============================================================
//  THE COPY CONFIRMATION
//
//  The last question of the copy flow, whichever way the template was
//  chosen: the Bambu copy list, the picker, or its id. Out of copy_flow.cpp
//  since v0.8.0-beta.49, when it moved onto the house card.
// ============================================================

// The lines of the card.
#define COPY_CARD_LINE_H   26
#define COPY_CARD_SWATCH   18
#define COPY_CARD_GAP      8

lv_obj_t *scr_copy_confirm = nullptr;  // confirm popup

// Template selected for copy
static int   copy_template_filament_id = 0;
static int   copy_template_spool_id    = 0;
static float copy_template_initial     = 0;
static float copy_template_spool_w     = 0;
static char  copy_template_name[64]    = "";

void closeCopyConfirmPopup() {
  releaseScreen(&scr_copy_confirm);
}

// The copy confirmation, on the house card for a question (400 x 260, the
// answers in its bottom row): the template as a colour and a name, where it
// comes from, and what the new spool will weigh. It used to be one block of
// text on a box of its own, and the picker asked a second question first.
void showCopyConfirmPopup(int template_spool_id, int template_filament_id,
                          const char* template_name,
                          float template_remaining, float template_initial, float template_spool_w,
                          const CopyLook* look) {
  closeCopyConfirmPopup();
  copy_template_spool_id    = template_spool_id;
  copy_template_filament_id = template_filament_id;
  copy_template_initial      = template_initial;
  copy_template_spool_w      = template_spool_w;
  strncpy(copy_template_name, template_name, sizeof(copy_template_name)-1);
  copy_template_name[sizeof(copy_template_name)-1] = '\0';

  (void)template_remaining;   // the weight the template had is not the new spool's

  scr_copy_confirm = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_copy_confirm, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(scr_copy_confirm, 0, 0);
  lv_obj_set_style_bg_color(scr_copy_confirm, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(scr_copy_confirm, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(scr_copy_confirm, 0, 0);
  lv_obj_set_style_radius(scr_copy_confirm, 0, 0);
  lv_obj_set_style_pad_all(scr_copy_confirm, 0, 0);
  lv_obj_clear_flag(scr_copy_confirm, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_copy_confirm);
  lv_obj_set_size(box, UI_POPUP_W, UI_CARD_H);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *icon = lv_label_create(box);
  lv_label_set_text(icon, LV_SYMBOL_COPY);
  lv_obj_set_style_text_color(icon, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(icon, UI_FONT_ICON, 0);
  lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, UI_CARD_ICON_Y);

  lv_obj_t *title = lv_label_create(box);
  lv_label_set_text(title, T(STR_COPY_CONFIRM_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(title, UI_FONT_HEADLINE, 0);
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(title, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, UI_CARD_TITLE_Y);

  // Line 1: the colour and the filament, as one centred group.
  lv_obj_t *row = lv_obj_create(box);
  lv_obj_remove_style_all(row);
  lv_obj_set_size(row, UI_POPUP_W - UI_CARD_TEXT_PAD, COPY_CARD_LINE_H);
  lv_obj_align(row, LV_ALIGN_TOP_MID, 0, UI_CARD_TEXT_Y - 4);
  lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(row, COPY_CARD_GAP, 0);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_CLICKABLE);

  if (look && look->color_hex[0]) {
    lv_obj_t *sw = lv_obj_create(row);
    lv_obj_set_size(sw, COPY_CARD_SWATCH, COPY_CARD_SWATCH);
    lv_obj_set_style_radius(sw, 4, 0);
    lv_obj_set_style_border_width(sw, 1, 0);
    lv_obj_set_style_border_color(sw, lv_color_hex(UI_COL_POPUP_BORDER), 0);
    lv_obj_set_style_pad_all(sw, 0, 0);
    lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
    swatchPaintHex(sw, look->color_hex);
  }

  char line1[80];
  if (look) {
    if (nameStartsWithMaterial(look->name, look->material))
      snprintf(line1, sizeof(line1), "%s", look->name);
    else
      snprintf(line1, sizeof(line1), "%s %s", look->material, look->name);
  } else {
    snprintf(line1, sizeof(line1), "%s", template_name ? template_name : "");
  }
  lv_obj_t *lbl1 = lv_label_create(row);
  lv_label_set_text(lbl1, line1);
  lv_obj_set_style_text_color(lbl1, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(lbl1, UI_FONT_TITLE, 0);
  lv_label_set_long_mode(lbl1, LV_LABEL_LONG_DOT);
  lv_obj_set_style_max_width(lbl1, UI_POPUP_W - UI_CARD_TEXT_PAD - COPY_CARD_SWATCH - COPY_CARD_GAP, 0);

  // Line 2: whose it is and which spool it is copied from.
  char line2[64];
  snprintf(line2, sizeof(line2), T(STR_COPY_CARD_TEMPLATE),
           (look && look->vendor[0]) ? look->vendor : "-", template_spool_id);
  lv_obj_t *lbl2 = lv_label_create(box);
  lv_label_set_text(lbl2, line2);
  lv_obj_set_style_text_color(lbl2, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_text_font(lbl2, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_align(lbl2, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl2, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl2, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(lbl2, LV_ALIGN_TOP_MID, 0, UI_CARD_TEXT_Y - 4 + COPY_CARD_LINE_H + 4);

  // Line 3: what the new spool starts with - the scale minus the template's
  // empty spool, as it will be saved.
  float display_netto = scale_weight_g - template_spool_w;
  if (display_netto < 0) display_netto = 0;
  char line3[64];
  snprintf(line3, sizeof(line3), T(STR_COPY_CARD_WEIGHT), display_netto, template_spool_w);
  lv_obj_t *lbl3 = lv_label_create(box);
  lv_label_set_text(lbl3, line3);
  lv_obj_set_style_text_color(lbl3, lv_color_hex(UI_COL_INK_2), 0);
  lv_obj_set_style_text_font(lbl3, UI_FONT_BODY, 0);
  lv_obj_set_style_text_align(lbl3, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(lbl3, UI_POPUP_W - UI_CARD_TEXT_PAD);
  lv_obj_align(lbl3, LV_ALIGN_TOP_MID, 0, UI_CARD_TEXT_Y - 4 + 2 * COPY_CARD_LINE_H + 8);

  // The answers: create on the left in green, as every confirming answer is.
  lv_obj_t *btn_ok = lv_btn_create(box);
  lv_obj_set_size(btn_ok, UI_POPUP_BTN_W, UI_POPUP_BTN_H);
  lv_obj_set_pos(btn_ok, UI_CARD_ROW_X, UI_CARD_ROW_Y);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(UI_COL_OK_BG), 0);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(UI_COL_OK_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn_ok, 0, 0);
  lv_obj_add_event_cb(btn_ok, [](lv_event_t *e) {
    // The handler closes the three popups - this button's own among them -
    // and then creates the spool from the loop.
    copyCreateRequest(copy_template_spool_id, copy_template_filament_id,
                      copy_template_initial, copy_template_spool_w);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok = lv_label_create(btn_ok);
  lv_label_set_text(lbl_ok, T(STR_COPY_CARD_CREATE));
  lv_obj_set_style_text_color(lbl_ok, lv_color_hex(UI_COL_OK_TEXT), 0);
  lv_obj_set_style_text_font(lbl_ok, UI_FONT_TITLE, 0);
  lv_obj_center(lbl_ok);

  lv_obj_t *btn_no = lv_btn_create(box);
  lv_obj_set_size(btn_no, UI_POPUP_BTN_W, UI_POPUP_BTN_H);
  lv_obj_set_pos(btn_no, UI_POPUP_W - UI_POPUP_BTN_W - UI_CARD_ROW_X, UI_CARD_ROW_Y);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(UI_COL_BAD_BG), 0);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(UI_COL_BAD_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_no, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(btn_no, 0, 0);
  lv_obj_add_event_cb(btn_no, [](lv_event_t *e) {
    logSD("BTN: CopyConfirm -> Cancel (back to list)");
    closeCopyConfirmPopup();
    // Back to whichever list the template came from.
    if (scr_copy_list) lv_obj_clear_flag(scr_copy_list, LV_OBJ_FLAG_HIDDEN);
    linkPickerShowList();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_no = lv_label_create(btn_no);
  lv_label_set_text(lbl_no, T(STR_CANCEL));
  lv_obj_set_style_text_color(lbl_no, lv_color_hex(UI_COL_BAD_TEXT), 0);
  lv_obj_set_style_text_font(lbl_no, UI_FONT_TITLE, 0);
  lv_obj_center(lbl_no);
}
