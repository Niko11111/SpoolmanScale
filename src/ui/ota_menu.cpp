#include "ota_menu.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <lvgl.h>
#include <stdio.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "ota_browser.h"
#include "services/ota_state.h"
#include "ui_common.h"
#include "update_badges.h"
#include "theme.h"


void showOtaGithubScreen();

void showOtaScreen() {
  logSD("SHOW: OtaScreen");
  logSD("UI: Screen -> OTA Selection");
  hideAllOverlays();
  if (!scr_ota) buildOtaScreen();
  lv_obj_clear_flag(scr_ota, LV_OBJ_FLAG_HIDDEN);
}

void buildOtaScreen() {
  logSD("BUILD: OtaScreen");
  releaseScreen(&scr_ota);
  scr_ota = buildOverlayScreen();
  buildSubHeader(scr_ota, T(STR_OTA_TITLE),
    [](lv_event_t *e){
      logSD("BTN: OTA -> Back");
      show_system_pending = true;
    });

  lv_obj_t *btn_browser = lv_btn_create(scr_ota);
  lv_obj_set_size(btn_browser, 456, 80);
  lv_obj_set_pos(btn_browser, 12, 58);
  lv_obj_set_style_bg_color(btn_browser, tc(TH_TILE_BG), 0);
  lv_obj_set_style_bg_color(btn_browser, tc(TH_BORDER), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_browser, 10, 0);
  lv_obj_set_style_shadow_width(btn_browser, 0, 0);
  lv_obj_set_style_border_width(btn_browser, 1, 0);
  lv_obj_set_style_border_color(btn_browser, tc(TH_BORDER), 0);
  { lv_obj_t *ico = lv_label_create(btn_browser);
    lv_label_set_text(ico, LV_SYMBOL_UPLOAD);
    lv_obj_set_style_text_color(ico, tc(TH_ACCENT), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_browser);
    lv_label_set_text(lbl, T(STR_OTA_BROWSER));
    lv_obj_set_style_text_color(lbl, tc(TH_TEXT_BRIGHT), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_browser);
    lv_label_set_text(sub, T(STR_OTA_BROWSER_SUB));
    lv_obj_set_style_text_color(sub, tc(TH_TEXT_MUTED), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_browser, [](lv_event_t *e){
    showOtaBrowserScreen();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_gh = lv_btn_create(scr_ota);
  lv_obj_set_size(btn_gh, 456, 80);
  lv_obj_set_pos(btn_gh, 12, 150);
  lv_obj_set_style_bg_color(btn_gh, tc(TH_TILE_BG), 0);
  lv_obj_set_style_bg_color(btn_gh, tc(TH_BORDER), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_gh, 10, 0);
  lv_obj_set_style_shadow_width(btn_gh, 0, 0);
  lv_obj_set_style_border_width(btn_gh, 1, 0);
  lv_obj_set_style_border_color(btn_gh, tc(TH_BORDER), 0);
  { lv_obj_t *ico = lv_label_create(btn_gh);
    lv_label_set_text(ico, LV_SYMBOL_DOWNLOAD);
    lv_obj_set_style_text_color(ico, tc(TH_ACCENT), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_gh);
    lv_label_set_text(lbl, T(STR_OTA_GITHUB));
    lv_obj_set_style_text_color(lbl, tc(TH_TEXT_BRIGHT), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_gh);
    lv_label_set_text(sub, T(STR_OTA_GITHUB_SUB));
    lv_obj_set_style_text_color(sub, tc(TH_TEXT_MUTED), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_gh, [](lv_event_t *e){
    showOtaGithubScreen();
  }, LV_EVENT_CLICKED, NULL);

  lbl_gh_btn_badge = createUpdateBadge(scr_ota, btn_gh);

  lv_obj_t *ver_ota = lv_label_create(scr_ota);
  char ver_buf[32]; snprintf(ver_buf, sizeof(ver_buf), T(STR_OTA_CURRENT), FW_VERSION);
  lv_label_set_text(ver_ota, ver_buf);
  lv_obj_set_style_text_color(ver_ota, tc(TH_TEXT_DIM), 0);
  lv_obj_set_style_text_font(ver_ota, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(ver_ota, LV_ALIGN_BOTTOM_MID, 0, -8);
}
