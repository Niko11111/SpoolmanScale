#include "cal_reminder_screen.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "extra_fields_screen.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui_common.h"



// ============================================================
//  CALIBRATION REMINDER SCREEN (end of first setup)
// ============================================================
void showCalReminderScreen() {
  logSD("SHOW: CalReminderScreen");
  logSD("UI: Screen -> CalReminder: start");
  Serial.println("showCalReminderScreen: start");
  // Free all setup screens to release LVGL heap before building
  if (scr_welcome)       { lv_obj_del(scr_welcome);       scr_welcome       = nullptr; }
  if (scr_first_boot)    { lv_obj_del(scr_first_boot);    scr_first_boot    = nullptr; }
  if (scr_wifi_setup)    { lv_obj_del(scr_wifi_setup);    scr_wifi_setup    = nullptr; }
  if (scr_wifi_pass)     { lv_obj_del(scr_wifi_pass);     scr_wifi_pass     = nullptr; }
  if (scr_spoolman)      { lv_obj_del(scr_spoolman);      scr_spoolman      = nullptr; }
  if (scr_extra_fields)  { lv_obj_del(scr_extra_fields);  scr_extra_fields  = nullptr;
                           resetExtraFieldsScreenState(); }
  if (scr_tag_field)     { lv_obj_del(scr_tag_field);     scr_tag_field     = nullptr; }
  hideAllOverlays();
  logSD("UI: Screen -> CalReminder: hideAllOverlays done");
  Serial.println("showCalReminderScreen: hideAllOverlays done");
  if (scr_cal_reminder) { lv_obj_del(scr_cal_reminder); scr_cal_reminder = nullptr; }
  logSD("UI: Screen -> CalReminder: building");
  Serial.println("showCalReminderScreen: building");
  buildCalReminderScreen();
  logSD("UI: Screen -> CalReminder: build done");
  Serial.println("showCalReminderScreen: build done");
  lv_obj_clear_flag(scr_cal_reminder, LV_OBJ_FLAG_HIDDEN);
  logSD("UI: Screen -> CalReminder: visible");
  Serial.println("showCalReminderScreen: visible OK");
}

void buildCalReminderScreen() {
  logSD("BUILD: CalReminderScreen");
  Serial.println("buildCalReminderScreen: start");
  releaseScreen(&scr_cal_reminder);
  scr_cal_reminder = lv_obj_create(lv_scr_act());
  Serial.println("buildCalReminderScreen: obj created");
  lv_obj_set_size(scr_cal_reminder, 480, 320);
  lv_obj_set_pos(scr_cal_reminder, 0, 0);
  lv_obj_add_flag(scr_cal_reminder, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_cal_reminder, 0, 0);
  lv_obj_set_style_border_width(scr_cal_reminder, 0, 0);
  lv_obj_set_style_pad_all(scr_cal_reminder, 0, 0);
  lv_obj_clear_flag(scr_cal_reminder, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_cal_reminder, lv_color_hex(0x0a1020), 0);

  // Static buffers — must outlive the function since LVGL holds pointers to them
  static char buf_title[48], buf_msg[256], buf_later[32], buf_now[48];
  strncpy(buf_title, T(STR_CAL_REMINDER_TITLE), sizeof(buf_title)-1); buf_title[sizeof(buf_title)-1]=0;
  strncpy(buf_msg,   T(STR_CAL_REMINDER_MSG),   sizeof(buf_msg)-1);   buf_msg[sizeof(buf_msg)-1]=0;
  strncpy(buf_later, T(STR_CAL_REMINDER_LATER), sizeof(buf_later)-1); buf_later[sizeof(buf_later)-1]=0;
  strncpy(buf_now,   T(STR_CAL_REMINDER_NOW),   sizeof(buf_now)-1);   buf_now[sizeof(buf_now)-1]=0;
  Serial.println("buildCalReminderScreen: strings copied");

  // Title
  lv_obj_t *lbl_title = lv_label_create(scr_cal_reminder);
  lv_label_set_text(lbl_title, buf_title);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 20);

  // No back button in setup flow — CalReminder is the last setup step
  addCloseButton(scr_cal_reminder);

  // Icon
  lv_obj_t *lbl_icon = lv_label_create(scr_cal_reminder);
  lv_label_set_text(lbl_icon, LV_SYMBOL_EDIT);
  lv_obj_set_style_text_color(lbl_icon, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_icon, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_icon, LV_ALIGN_TOP_MID, 0, 52);

  // Message
  lv_obj_t *lbl_msg = lv_label_create(scr_cal_reminder);
  lv_label_set_text(lbl_msg, buf_msg);
  lv_obj_set_style_text_color(lbl_msg, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_msg, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_msg, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_msg, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_msg, 440);
  lv_obj_align(lbl_msg, LV_ALIGN_TOP_MID, 0, 88);

  // Single "Got it" button — centers, leads to main screen
  lv_obj_t *btn_got = lv_btn_create(scr_cal_reminder);
  lv_obj_set_size(btn_got, 280, 48);
  lv_obj_align(btn_got, LV_ALIGN_BOTTOM_MID, 0, -20);
  lv_obj_set_style_bg_color(btn_got, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_got, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_got, 8, 0);
  lv_obj_set_style_shadow_width(btn_got, 0, 0);
  lv_obj_set_style_border_width(btn_got, 1, 0);
  lv_obj_set_style_border_color(btn_got, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_got, [](lv_event_t *e) {
    showMainScreen();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_got = lv_label_create(btn_got);
  lv_label_set_text(lbl_got, buf_later);
  lv_obj_set_style_text_color(lbl_got, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_got, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_got);
}
