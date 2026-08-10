#include "bag_screen.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstdlib>
#include <cstring>

#include "hardware/scale_state.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "scale_menu.h"
#include "ui_common.h"



static char bag_input[16] = "";
static lv_obj_t *lbl_bag_display = nullptr;
static lv_obj_t *lbl_bag_result_global = nullptr;

void buildBagScreen() {
  logSD("BUILD: BagScreen");
  releaseScreen(&scr_bag);
  scr_bag = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_bag, 480, 320);
  lv_obj_set_pos(scr_bag, 0, 0);
  lv_obj_add_flag(scr_bag, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_bag, 0, 0);
  lv_obj_set_style_border_width(scr_bag, 0, 0);
  lv_obj_set_style_pad_all(scr_bag, 0, 0);
  lv_obj_clear_flag(scr_bag, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_bag, lv_color_hex(0x0a1020), 0);

  lbl_bag_display = nullptr;
  lbl_bag_result_global = nullptr;
  snprintf(bag_input, sizeof(bag_input), "%.1f", bag_weight_g);

  buildSubHeader(scr_bag, T(STR_BTN_BAGWEIGHT),
    [](lv_event_t *e){
      logSD("BTN: Back -> Scale (from Bag)");
      hideAllOverlays();
      if (scr_scale_sub) { lv_obj_del(scr_scale_sub); scr_scale_sub = nullptr; }
      buildScaleSubScreen();
      lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
    });

  lv_obj_t *lbl_desc = lv_label_create(scr_bag);
  lv_label_set_text(lbl_desc, T(STR_BAG_DESC));
  lv_obj_set_style_text_color(lbl_desc, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_desc, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_desc, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_desc, LV_ALIGN_TOP_MID, 0, 58);

  lbl_bag_result_global = lv_label_create(scr_bag);
  lv_label_set_text(lbl_bag_result_global, "");
  lv_obj_set_style_text_color(lbl_bag_result_global, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_bag_result_global, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_bag_result_global, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_bag_result_global, LV_ALIGN_TOP_MID, 0, 78);

  lv_obj_t *input_box_b = lv_obj_create(scr_bag);
  lv_obj_set_size(input_box_b, 260, 38);
  lv_obj_align(input_box_b, LV_ALIGN_TOP_MID, 0, 98);
  lv_obj_set_style_bg_color(input_box_b, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_border_color(input_box_b, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(input_box_b, 1, 0);
  lv_obj_set_style_radius(input_box_b, 6, 0);
  lv_obj_set_style_pad_all(input_box_b, 0, 0);
  lv_obj_clear_flag(input_box_b, LV_OBJ_FLAG_SCROLLABLE);

  lbl_bag_display = lv_label_create(input_box_b);
  lv_label_set_text(lbl_bag_display, bag_input);
  lv_obj_set_style_text_color(lbl_bag_display, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bag_display, &lv_font_montserrat_ext_20, 0);
  lv_obj_set_style_text_align(lbl_bag_display, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(lbl_bag_display);

  const int NP_W = 104, NP_H = 30, NP_GAP = 4;
  const int NP_PAD_X = (480 - 3*NP_W - 2*NP_GAP) / 2;
  const int NP_START_Y = 144;
  const char* np_labels_b[] = { "1","2","3","4","5","6","7","8","9",".","0","" };

  for (int i = 0; i < 12; i++) {
    if (np_labels_b[i][0] == '\0') continue;
    int col = i % 3, row = i / 3;
    lv_obj_t *btn = lv_btn_create(scr_bag);
    lv_obj_set_size(btn, NP_W, NP_H);
    lv_obj_set_pos(btn, NP_PAD_X + col*(NP_W+NP_GAP), NP_START_Y + row*(NP_H+NP_GAP));
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn, 6, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_set_style_border_width(btn, 1, 0);
    lv_obj_set_style_border_color(btn, lv_color_hex(0x1a2840), 0);
    lv_obj_t *lbl = lv_label_create(btn);
    lv_label_set_text(lbl, np_labels_b[i]);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl);
    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      if (!lbl_bag_display) return;
      const char* ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
      if (ch[0] == '.' && strchr(bag_input, '.')) return;
      int len = strlen(bag_input);
      if (len < (int)sizeof(bag_input)-1) { bag_input[len]=ch[0]; bag_input[len+1]='\0'; }
      lv_label_set_text(lbl_bag_display, bag_input[0] ? bag_input : "_");
      if (lbl_bag_result_global) lv_label_set_text(lbl_bag_result_global, "");
    }, LV_EVENT_CLICKED, NULL);
  }

  int by5_b = NP_START_Y + 4*(NP_H+NP_GAP);
  int bw5_b = (3*NP_W + 2*NP_GAP - NP_GAP) / 2;

  lv_obj_t *btn_del_b = lv_btn_create(scr_bag);
  lv_obj_set_size(btn_del_b, bw5_b, NP_H);
  lv_obj_set_pos(btn_del_b, NP_PAD_X, by5_b);
  lv_obj_set_style_bg_color(btn_del_b, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_del_b, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_del_b, 6, 0);
  lv_obj_set_style_shadow_width(btn_del_b, 0, 0);
  lv_obj_set_style_border_width(btn_del_b, 1, 0);
  lv_obj_set_style_border_color(btn_del_b, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_del_b, [](lv_event_t *e) {
    if (!lbl_bag_display) return;
    int len = strlen(bag_input);
    if (len > 0) bag_input[len-1] = '\0';
    lv_label_set_text(lbl_bag_display, bag_input[0] ? bag_input : "_");
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_del_b = lv_label_create(btn_del_b);
  lv_label_set_text(lbl_del_b, LV_SYMBOL_BACKSPACE);
  lv_obj_set_style_text_color(lbl_del_b, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_del_b, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_del_b);

  lv_obj_t *btn_ok_b = lv_btn_create(scr_bag);
  lv_obj_set_size(btn_ok_b, bw5_b, NP_H);
  lv_obj_set_pos(btn_ok_b, NP_PAD_X + bw5_b + NP_GAP, by5_b);
  lv_obj_set_style_bg_color(btn_ok_b, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_ok_b, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok_b, 6, 0);
  lv_obj_set_style_shadow_width(btn_ok_b, 0, 0);
  lv_obj_set_style_border_width(btn_ok_b, 1, 0);
  lv_obj_set_style_border_color(btn_ok_b, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_ok_b, [](lv_event_t *e) {
    if (!lbl_bag_result_global) return;
    float w = atof(bag_input);
    if (w >= 0 && w < 1000) {
      saveBagWeight(w);
      char buf[32];
      snprintf(buf, sizeof(buf), T(STR_BAG_SAVED), w);
      lv_label_set_text(lbl_bag_result_global, buf);
    } else {
      lv_label_set_text(lbl_bag_result_global, T(STR_BAG_INVALID));
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok2_b = lv_label_create(btn_ok_b);
  lv_label_set_text(lbl_ok2_b, T(STR_BTN_SAVE));
  lv_obj_set_style_text_color(lbl_ok2_b, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_ok2_b, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_ok2_b);
}
