#include "info_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "extra/libs/qrcode/lv_qrcode.h"
#include "theme.h"



static const char* QR_TITLES[] = { "Ko-fi", "GitHub", "Discord", "MakerWorld" };
static const char* QR_URLS[]   = {
  "https://ko-fi.com/formfollowsfunction",
  "https://github.com/Niko11111/SpoolmanScale",
  "https://discord.gg/GzQzGa5pBG",
  "https://makerworld.com/de/@FormFollowsF/upload"
};
static const char* QR_URLS_DISPLAY[] = {
  "ko-fi.com/formfollowsfunction",
  "github.com/Niko11111/SpoolmanScale",
  "discord.gg/GzQzGa5pBG",
  "makerworld.com/de/@FormFollowsF/upload"
};

static const char* getQRDesc(int idx) {
  switch(idx) {
    case 0: return T(STR_QR_KOFI_DESC);
    case 1: return T(STR_QR_GITHUB_DESC);
    case 2: return T(STR_QR_DISCORD_DESC);
    case 3: return T(STR_QR_MAKER_DESC);
    default: return "";
  }
}

void showQRPopup(int idx) {
  if (idx < 0 || idx >= 4) return;

  logSDf("SHOW: QRPopup idx=%d", idx);
  const char* names[4] = {"Ko-fi", "GitHub", "Discord", "MakerWorld"};
  logSDf("UI: Screen -> QR Popup (%s)", names[idx]);
  lv_obj_t *popup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(popup, 480, 320);
  lv_obj_set_pos(popup, 0, 0);
  lv_obj_set_style_bg_color(popup, tc(TH_BG), 0);
  lv_obj_set_style_border_width(popup, 0, 0);
  lv_obj_set_style_radius(popup, 0, 0);
  lv_obj_set_style_pad_all(popup, 0, 0);
  lv_obj_clear_flag(popup, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *btn_back = lv_btn_create(popup);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, tc(TH_SURFACE), 0);
  lv_obj_set_style_bg_color(btn_back, tc(TH_SURFACE_2), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, tc(TH_ACCENT), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_bk);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e){
    lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_title = lv_label_create(popup);
  lv_label_set_text(lbl_title, QR_TITLES[idx]);
  lv_obj_set_style_text_color(lbl_title, tc(TH_ACCENT), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

  lv_obj_t *btn_x = lv_btn_create(popup);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn_x, tc(TH_DANGER_BG), 0);
  lv_obj_set_style_bg_color(btn_x, tc(TH_DANGER_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_set_style_border_width(btn_x, 0, 0);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, tc(TH_DANGER_TEXT), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){
    lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
    if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
    showMainScreen();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_desc = lv_label_create(popup);
  lv_label_set_text(lbl_desc, getQRDesc(idx));
  lv_obj_set_style_text_color(lbl_desc, tc(TH_TEXT), 0);
  lv_obj_set_style_text_font(lbl_desc, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_desc, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_desc, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_desc, 440);
  lv_obj_align(lbl_desc, LV_ALIGN_TOP_MID, 0, 50);

  lv_obj_t *lbl_url = lv_label_create(popup);
  lv_label_set_text(lbl_url, QR_URLS_DISPLAY[idx]);
  lv_obj_set_style_text_color(lbl_url, tc(TH_ACCENT), 0);
  lv_obj_set_style_text_font(lbl_url, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_url, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_url, LV_ALIGN_TOP_MID, 0, 84);

  size_t url_len = strlen(QR_URLS[idx]);
  logSDf("QR: %s about to create url_len=%u heap=%d PSRAM=%d",
    names[idx], (unsigned)url_len, ESP.getFreeHeap(), ESP.getFreePsram());
  lv_obj_t *qr = lv_qrcode_create(popup, 160, lv_color_hex(0x000000), lv_color_hex(0xffffff));
  logSDf("QR: %s create OK heap=%d", names[idx], ESP.getFreeHeap());
  lv_res_t qr_res = lv_qrcode_update(qr, QR_URLS[idx], url_len);
  logSDf("QR: %s update done res=%d heap=%d", names[idx], (int)qr_res, ESP.getFreeHeap());
  lv_obj_align(qr, LV_ALIGN_BOTTOM_MID, 0, -20);
  logSDf("QR: %s align done", names[idx]);
}

void showInfoScreen() {
  logSD("SHOW: InfoScreen");
  logSD("UI: Screen -> Info");
  if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
  scr_info = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_info, 480, 320);
  lv_obj_set_pos(scr_info, 0, 0);
  lv_obj_set_style_bg_color(scr_info, tc(TH_BG), 0);
  lv_obj_set_style_border_width(scr_info, 0, 0);
  lv_obj_set_style_radius(scr_info, 0, 0);
  lv_obj_set_style_pad_all(scr_info, 0, 0);
  lv_obj_clear_flag(scr_info, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *btn_back = lv_btn_create(scr_info);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, tc(TH_SURFACE), 0);
  lv_obj_set_style_bg_color(btn_back, tc(TH_SURFACE_2), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, tc(TH_ACCENT), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_bk);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e){
    logSD("BTN: Info -> Back");
    show_system_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *hdr = lv_label_create(scr_info);
  lv_label_set_text(hdr, T(STR_BTN_INFO));
  lv_obj_set_style_text_color(hdr, tc(TH_ACCENT), 0);
  lv_obj_set_style_text_font(hdr, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(hdr, LV_ALIGN_TOP_MID, 0, 12);

  lv_obj_t *btn_x = lv_btn_create(scr_info);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn_x, tc(TH_DANGER_BG), 0);
  lv_obj_set_style_bg_color(btn_x, tc(TH_DANGER_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_set_style_border_width(btn_x, 0, 0);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, tc(TH_DANGER_TEXT), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){
    if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
    showMainScreen();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *ver_lbl = lv_label_create(scr_info);
  char ver_buf[40];
  snprintf(ver_buf, sizeof(ver_buf), T(STR_INFO_VERSION), FW_VERSION);
  lv_label_set_text(ver_lbl, ver_buf);
  lv_obj_set_style_text_color(ver_lbl, tc(TH_ACCENT), 0);
  lv_obj_set_style_text_font(ver_lbl, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(ver_lbl, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(ver_lbl, LV_ALIGN_TOP_MID, 0, 54);

  const int QB_W = 228, QB_H = 90, QB_GAP = 8;
  const int QB_X0 = (480 - 2*QB_W - QB_GAP) / 2;
  const int QB_Y0 = 82;
  const uint32_t QB_COLS[] = { 0x1a2800, g_theme[TH_SURFACE], 0x12103a, 0x1a0a18 };
  const uint32_t QB_TEXT[] = { 0xa0d840, g_theme[TH_ACCENT], 0x8090ff, 0xc060e0 };

  lv_obj_t *btn_kofi = lv_btn_create(scr_info);
  lv_obj_set_size(btn_kofi, QB_W, QB_H);
  lv_obj_set_pos(btn_kofi, QB_X0, QB_Y0);
  lv_obj_set_style_bg_color(btn_kofi, lv_color_hex(QB_COLS[0]), 0);
  lv_obj_set_style_bg_color(btn_kofi, lv_color_hex(QB_COLS[0]+0x101010), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_kofi, 12, 0); lv_obj_set_style_shadow_width(btn_kofi, 0, 0);
  lv_obj_set_style_border_width(btn_kofi, 1, 0); lv_obj_set_style_border_color(btn_kofi, lv_color_hex(QB_TEXT[0]), 0);
  { lv_obj_t *ico = lv_label_create(btn_kofi); lv_label_set_text(ico, LV_SYMBOL_BELL);
    lv_obj_set_style_text_color(ico, lv_color_hex(QB_TEXT[0]), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_20, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -14);
    lv_obj_t *l = lv_label_create(btn_kofi); lv_label_set_text(l, "Ko-fi");
    lv_obj_set_style_text_color(l, lv_color_hex(QB_TEXT[0]), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 14); }
  lv_obj_add_event_cb(btn_kofi, [](lv_event_t *e){ logSD("BTN: Info -> QR kofi"); showQRPopup(0); }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_gh = lv_btn_create(scr_info);
  lv_obj_set_size(btn_gh, QB_W, QB_H);
  lv_obj_set_pos(btn_gh, QB_X0 + QB_W + QB_GAP, QB_Y0);
  lv_obj_set_style_bg_color(btn_gh, lv_color_hex(QB_COLS[1]), 0);
  lv_obj_set_style_bg_color(btn_gh, lv_color_hex(QB_COLS[1]+0x101010), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_gh, 12, 0); lv_obj_set_style_shadow_width(btn_gh, 0, 0);
  lv_obj_set_style_border_width(btn_gh, 1, 0); lv_obj_set_style_border_color(btn_gh, lv_color_hex(QB_TEXT[1]), 0);
  { lv_obj_t *ico = lv_label_create(btn_gh); lv_label_set_text(ico, LV_SYMBOL_DOWNLOAD);
    lv_obj_set_style_text_color(ico, lv_color_hex(QB_TEXT[1]), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_20, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -14);
    lv_obj_t *l = lv_label_create(btn_gh); lv_label_set_text(l, "GitHub");
    lv_obj_set_style_text_color(l, lv_color_hex(QB_TEXT[1]), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 14); }
  lv_obj_add_event_cb(btn_gh, [](lv_event_t *e){ logSD("BTN: Info -> QR github"); showQRPopup(1); }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_dc = lv_btn_create(scr_info);
  lv_obj_set_size(btn_dc, QB_W, QB_H);
  lv_obj_set_pos(btn_dc, QB_X0, QB_Y0 + QB_H + QB_GAP);
  lv_obj_set_style_bg_color(btn_dc, lv_color_hex(QB_COLS[2]), 0);
  lv_obj_set_style_bg_color(btn_dc, lv_color_hex(QB_COLS[2]+0x101010), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_dc, 12, 0); lv_obj_set_style_shadow_width(btn_dc, 0, 0);
  lv_obj_set_style_border_width(btn_dc, 1, 0); lv_obj_set_style_border_color(btn_dc, lv_color_hex(QB_TEXT[2]), 0);
  { lv_obj_t *ico = lv_label_create(btn_dc); lv_label_set_text(ico, LV_SYMBOL_BELL);
    lv_obj_set_style_text_color(ico, lv_color_hex(QB_TEXT[2]), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_20, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -14);
    lv_obj_t *l = lv_label_create(btn_dc); lv_label_set_text(l, "Discord");
    lv_obj_set_style_text_color(l, lv_color_hex(QB_TEXT[2]), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 14); }
  lv_obj_add_event_cb(btn_dc, [](lv_event_t *e){ logSD("BTN: Info -> QR discord"); showQRPopup(2); }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_mw = lv_btn_create(scr_info);
  lv_obj_set_size(btn_mw, QB_W, QB_H);
  lv_obj_set_pos(btn_mw, QB_X0 + QB_W + QB_GAP, QB_Y0 + QB_H + QB_GAP);
  lv_obj_set_style_bg_color(btn_mw, lv_color_hex(QB_COLS[3]), 0);
  lv_obj_set_style_bg_color(btn_mw, lv_color_hex(QB_COLS[3]+0x101010), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_mw, 12, 0); lv_obj_set_style_shadow_width(btn_mw, 0, 0);
  lv_obj_set_style_border_width(btn_mw, 1, 0); lv_obj_set_style_border_color(btn_mw, lv_color_hex(QB_TEXT[3]), 0);
  { lv_obj_t *ico = lv_label_create(btn_mw); lv_label_set_text(ico, LV_SYMBOL_UPLOAD);
    lv_obj_set_style_text_color(ico, lv_color_hex(QB_TEXT[3]), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_20, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -14);
    lv_obj_t *l = lv_label_create(btn_mw); lv_label_set_text(l, "MakerWorld");
    lv_obj_set_style_text_color(l, lv_color_hex(QB_TEXT[3]), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 14); }
  lv_obj_add_event_cb(btn_mw, [](lv_event_t *e){ logSD("BTN: Info -> QR makerworld"); showQRPopup(3); }, LV_EVENT_CLICKED, NULL);

  // The disclaimer only existed in the web interface and the README, so
  // anyone who never opened either never saw it. The device is called
  // SpoolmanScale, which is exactly why it needs to say this somewhere the
  // user actually looks. Both names appear regardless of the active backend.
  lv_obj_t *disc = lv_label_create(scr_info);
  { char db[64]; strncpy(db, T(STR_NOT_AFFILIATED), sizeof(db) - 1); db[sizeof(db) - 1] = '\0';
    lv_label_set_text(disc, db); }
  lv_obj_set_style_text_color(disc, tc(TH_TEXT_DIM), 0);
  lv_obj_set_style_text_font(disc, &lv_font_montserrat_ext_10, 0);
  lv_obj_set_style_text_align(disc, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(disc, LV_ALIGN_BOTTOM_MID, 0, -6);

  lv_obj_t *hint = lv_label_create(scr_info);
  lv_label_set_text(hint, T(STR_INFO_HINT));
  lv_obj_set_style_text_color(hint, tc(TH_TEXT_DIM), 0);
  lv_obj_set_style_text_font(hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -22);
}
