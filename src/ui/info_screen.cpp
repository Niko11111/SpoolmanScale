#include "info_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/theme.h"
#include "extra/libs/qrcode/lv_qrcode.h"



// The manual is last in the arrays and first on the screen: most questions
// people ask are answered there (Nikolai, 25.09.2026).
#define QR_COUNT 5
#define QR_DOCS  4
static const char* QR_TITLES[QR_COUNT] = { "Ko-fi", "GitHub", "Discord", "MakerWorld", nullptr };
static const char* QR_URLS[QR_COUNT]   = {
  "https://ko-fi.com/formfollowsfunction",
  "https://github.com/Niko11111/SpoolmanScale",
  "https://discord.gg/xadskCrPFu",
  "https://makerworld.com/de/@FormFollowsF/upload",
  "https://niko11111.github.io/SpoolmanScale-Docs/"
};
static const char* QR_URLS_DISPLAY[QR_COUNT] = {
  "ko-fi.com/formfollowsfunction",
  "github.com/Niko11111/SpoolmanScale",
  "discord.gg/xadskCrPFu",
  "makerworld.com/de/@FormFollowsF/upload",
  "niko11111.github.io/SpoolmanScale-Docs"
};

static const char* qrTitle(int idx) {
  return idx == QR_DOCS ? T(STR_QR_DOCS_TITLE) : QR_TITLES[idx];
}

static const char* getQRDesc(int idx) {
  switch(idx) {
    case 0: return T(STR_QR_KOFI_DESC);
    case 1: return T(STR_QR_GITHUB_DESC);
    case 2: return T(STR_QR_DISCORD_DESC);
    case 3: return T(STR_QR_MAKER_DESC);
    case QR_DOCS: return T(STR_QR_DOCS_DESC);
    default: return "";
  }
}

void showQRPopup(int idx) {
  if (idx < 0 || idx >= QR_COUNT) return;

  logSDf("SHOW: QRPopup idx=%d", idx);
  const char* names[QR_COUNT] = {"Ko-fi", "GitHub", "Discord", "MakerWorld", "Docs"};
  logSDf("UI: Screen -> QR Popup (%s)", names[idx]);
  lv_obj_t *popup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(popup, 480, 320);
  lv_obj_set_pos(popup, 0, 0);
  lv_obj_set_style_bg_color(popup, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(popup, 0, 0);
  lv_obj_set_style_radius(popup, 0, 0);
  lv_obj_set_style_pad_all(popup, 0, 0);
  lv_obj_clear_flag(popup, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *btn_back = lv_btn_create(popup);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_bk);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e){
    lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_title = lv_label_create(popup);
  lv_label_set_text(lbl_title, qrTitle(idx));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

  lv_obj_t *btn_x = lv_btn_create(popup);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_set_style_border_width(btn_x, 0, 0);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){
    lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
    if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
    showMainScreen();
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_desc = lv_label_create(popup);
  lv_label_set_text(lbl_desc, getQRDesc(idx));
  lv_obj_set_style_text_color(lbl_desc, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_desc, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_desc, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_desc, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_desc, 440);
  lv_obj_align(lbl_desc, LV_ALIGN_TOP_MID, 0, 50);

  lv_obj_t *lbl_url = lv_label_create(popup);
  lv_label_set_text(lbl_url, QR_URLS_DISPLAY[idx]);
  lv_obj_set_style_text_color(lbl_url, lv_color_hex(0x28d49a), 0);
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

// One target: a framed tile in its own colour, icon and name on one line.
static void qrTile(lv_obj_t* parent, int x, int y, int w, int h, int idx,
                   const char* symbol, uint32_t bg, uint32_t fg) {
  lv_obj_t* b = lv_btn_create(parent);
  lv_obj_set_size(b, w, h);
  lv_obj_set_pos(b, x, y);
  lv_obj_set_style_bg_color(b, lv_color_hex(bg), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(bg + 0x101010), LV_STATE_PRESSED);
  lv_obj_set_style_radius(b, UI_RADIUS_BOX, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(fg), 0);
  char text[48];
  snprintf(text, sizeof(text), "%s   %s", symbol, qrTitle(idx));
  lv_obj_t* l = lv_label_create(b);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(fg), 0);
  lv_obj_set_style_text_font(l, idx == QR_DOCS ? UI_FONT_TITLE : UI_FONT_BODY, 0);
  lv_obj_center(l);
  lv_obj_add_event_cb(b, [](lv_event_t* e) {
    const int i = (int)(intptr_t)lv_event_get_user_data(e);
    logSDf("BTN: Info -> QR %d", i);
    showQRPopup(i);
  }, LV_EVENT_CLICKED, (void*)(intptr_t)idx);
}

void showInfoScreen() {
  logSD("SHOW: InfoScreen");
  logSD("UI: Screen -> Info");
  if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
  scr_info = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_info, 480, 320);
  lv_obj_set_pos(scr_info, 0, 0);
  lv_obj_set_style_bg_color(scr_info, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr_info, 0, 0);
  lv_obj_set_style_radius(scr_info, 0, 0);
  lv_obj_set_style_pad_all(scr_info, 0, 0);
  lv_obj_clear_flag(scr_info, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *btn_back = lv_btn_create(scr_info);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_bk);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e){
    logSD("BTN: Info -> Back");
    show_system_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *hdr = lv_label_create(scr_info);
  lv_label_set_text(hdr, T(STR_BTN_INFO));
  lv_obj_set_style_text_color(hdr, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(hdr, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(hdr, LV_ALIGN_TOP_MID, 0, 12);

  lv_obj_t *btn_x = lv_btn_create(scr_info);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_set_style_border_width(btn_x, 0, 0);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
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
  lv_obj_set_style_text_color(ver_lbl, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(ver_lbl, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(ver_lbl, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(ver_lbl, LV_ALIGN_TOP_MID, 0, 54);

  // The manual across the top, the four others in two rows under it: five
  // targets in the room the four had. Icon and name side by side, so a tile
  // needs only a line's height.
  const int QB_GAP = 8, QB_Y0 = 78, QB_DOCS_H = 56, QB_H = 62;
  const int QB_W = (480 - 16 - QB_GAP) / 2;
  const int QB_X0 = 8;
  qrTile(scr_info, QB_X0, QB_Y0, 2 * QB_W + QB_GAP, QB_DOCS_H, QR_DOCS,
         LV_SYMBOL_LIST, UI_COL_ACCENT_DIM, UI_COL_ACCENT);
  const int y1 = QB_Y0 + QB_DOCS_H + QB_GAP, y2 = y1 + QB_H + QB_GAP;
  qrTile(scr_info, QB_X0, y1, QB_W, QB_H, 0, LV_SYMBOL_BELL, 0x1a2800, 0xa0d840);
  qrTile(scr_info, QB_X0 + QB_W + QB_GAP, y1, QB_W, QB_H, 1, LV_SYMBOL_DOWNLOAD, 0x0a1828, 0x28d49a);
  qrTile(scr_info, QB_X0, y2, QB_W, QB_H, 2, LV_SYMBOL_BELL, 0x12103a, 0x8090ff);
  qrTile(scr_info, QB_X0 + QB_W + QB_GAP, y2, QB_W, QB_H, 3, LV_SYMBOL_UPLOAD, 0x1a0a18, 0xc060e0);

  // The disclaimer only existed in the web interface and the README, so
  // anyone who never opened either never saw it. The device is called
  // SpoolmanScale, which is exactly why it needs to say this somewhere the
  // user actually looks. Both names appear regardless of the active backend.
  lv_obj_t *disc = lv_label_create(scr_info);
  { char db[64]; copyT(db, sizeof(db), STR_NOT_AFFILIATED);
    lv_label_set_text(disc, db); }
  lv_obj_set_style_text_color(disc, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(disc, &lv_font_montserrat_ext_10, 0);
  lv_obj_set_style_text_align(disc, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(disc, LV_ALIGN_BOTTOM_MID, 0, -6);

  lv_obj_t *hint = lv_label_create(scr_info);
  lv_label_set_text(hint, T(STR_INFO_HINT));
  lv_obj_set_style_text_color(hint, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -22);
}
