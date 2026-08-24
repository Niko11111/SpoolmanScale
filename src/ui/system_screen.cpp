#include "system_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <SD.h>
#include <lvgl.h>
#include <nvs_flash.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/ota_state.h"
#include "ui_common.h"
#include "update_badges.h"
#include "web_screen.h"


void showLanguageScreen();

// Wipes every setting, so it asks first. Lifted out of the button callback
// unchanged when the screen became a list - the dialog itself is the same one
// that has always been there.
static void showFactoryResetPopup() {
  lv_obj_t *pop = lv_obj_create(lv_scr_act());
  lv_obj_set_size(pop, 480, 320);
  lv_obj_set_pos(pop, 0, 0);
  lv_obj_set_style_bg_color(pop, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(pop, LV_OPA_80, 0);
  lv_obj_set_style_border_width(pop, 0, 0);
  lv_obj_set_style_radius(pop, 0, 0);
  lv_obj_set_style_pad_all(pop, 0, 0);
  lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(pop);
  lv_obj_set_size(box, 440, 240);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x1a0808), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x602020), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_t = lv_label_create(box);
  char buf_t[48]; strncpy(buf_t, T(STR_FACTORY_RESET_TITLE), sizeof(buf_t)-1);
  lv_label_set_text(lbl_t, buf_t);
  lv_obj_set_style_text_color(lbl_t, lv_color_hex(0xff6060), 0);
  lv_obj_set_style_text_font(lbl_t, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_t, LV_ALIGN_TOP_MID, 0, 16);

  lv_obj_t *lbl_m = lv_label_create(box);
  char buf_m[256]; backendText(T(STR_FACTORY_RESET_MSG), buf_m, sizeof(buf_m));
  lv_label_set_text(lbl_m, buf_m);
  lv_obj_set_style_text_color(lbl_m, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_m, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_m, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_m, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_m, 400);
  lv_obj_align(lbl_m, LV_ALIGN_TOP_MID, 0, 50);

  // Cancel, left
  lv_obj_t *btn_c = lv_btn_create(box);
  lv_obj_set_size(btn_c, 180, 44);
  lv_obj_set_pos(btn_c, 12, 184);
  lv_obj_set_style_bg_color(btn_c, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_c, lv_color_hex(0x1a2840), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_c, 8, 0);
  lv_obj_set_style_shadow_width(btn_c, 0, 0);
  lv_obj_set_style_border_width(btn_c, 1, 0);
  lv_obj_set_style_border_color(btn_c, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_c, [](lv_event_t *e){
    lv_obj_del(lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e))));
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_c = lv_label_create(btn_c);
  char buf_c[32]; strncpy(buf_c, T(STR_CANCEL), sizeof(buf_c)-1);
  lv_label_set_text(lbl_c, buf_c);
  lv_obj_set_style_text_color(lbl_c, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_c, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(lbl_c, LV_ALIGN_CENTER, 0, 0);

  // Confirm, right, red
  lv_obj_t *btn_ok = lv_btn_create(box);
  lv_obj_set_size(btn_ok, 228, 44);
  lv_obj_set_pos(btn_ok, 200, 184);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok, 8, 0);
  lv_obj_set_style_shadow_width(btn_ok, 0, 0);
  lv_obj_set_style_border_width(btn_ok, 1, 0);
  lv_obj_set_style_border_color(btn_ok, lv_color_hex(0x602020), 0);
  lv_obj_add_event_cb(btn_ok, [](lv_event_t *e){
    logSD("Factory Reset: erasing NVS flash partition");
    Serial.println("Factory Reset: erasing NVS flash partition");
    // Close SD logging before erase to avoid corruption
    if (sd_available) SD.end();
    delay(100);
    // Full NVS partition erase - more reliable than p.clear()
    nvs_flash_erase();
    nvs_flash_init();
    delay(200);
    ESP.restart();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok = lv_label_create(btn_ok);
  char buf_ok[48]; strncpy(buf_ok, T(STR_FACTORY_RESET_CONFIRM), sizeof(buf_ok)-1);
  lv_label_set_text(lbl_ok, buf_ok);
  lv_obj_set_style_text_color(lbl_ok, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_ok, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(lbl_ok, LV_ALIGN_CENTER, 0, 0);
}

// How loudly a row warns. A restart costs the user twenty seconds and takes
// nothing away; a factory reset erases every setting on the device. Painting
// both red would say they are the same kind of mistake to make.
enum RowTone { TONE_PLAIN, TONE_WARN, TONE_DANGER };

// One row of the list. All six entries differ only in icon, text and what
// they do, so the row is built once instead of six times by hand. The toned
// rows replace the separate pair of half width buttons that used to sit at
// the bottom and made this screen end at y=313 of 320.
static lv_obj_t* addRow(lv_obj_t *list, const char *ico, const char *title,
                        const char *sub, lv_event_cb_t cb,
                        RowTone tone = TONE_PLAIN) {
  char buf_t[40]; strncpy(buf_t, title, sizeof(buf_t) - 1); buf_t[sizeof(buf_t)-1] = '\0';
  char buf_s[48]; strncpy(buf_s, sub,   sizeof(buf_s) - 1); buf_s[sizeof(buf_s)-1] = '\0';

  lv_obj_t *btn = makeListBtn(list, ico, buf_t, buf_s);
  if (tone != TONE_PLAIN) {
    // Amber is the same one the status bar and the web UI already warn in,
    // red the same one the reset dialog uses, so neither introduces a colour.
    const uint32_t border  = (tone == TONE_DANGER) ? 0x602020 : 0x3a2800;
    const uint32_t bg      = (tone == TONE_DANGER) ? 0x180a0e : 0x161206;
    const uint32_t pressed = (tone == TONE_DANGER) ? 0x3a1010 : 0x3a2c10;
    const uint32_t text    = (tone == TONE_DANGER) ? 0xff6060 : 0xf0b838;
    lv_obj_set_style_border_color(btn, lv_color_hex(border), 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(bg), 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(pressed), LV_STATE_PRESSED);
    // Child 0 is the icon, child 1 the title. Both take the tone so the row
    // reads as a warning before the text is read.
    lv_obj_t *ico_lbl = lv_obj_get_child(btn, 0);
    lv_obj_t *ttl_lbl = lv_obj_get_child(btn, 1);
    if (ico_lbl) lv_obj_set_style_text_color(ico_lbl, lv_color_hex(text), 0);
    if (ttl_lbl) lv_obj_set_style_text_color(ttl_lbl, lv_color_hex(text), 0);
  }
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, NULL);
  return btn;
}

void buildSystemScreen() {
  logSD("BUILD: SystemScreen");
  if (sd_verbose) logSD("[verbose] buildSystemScreen: start");
  releaseScreen(&scr_system);
  scr_system = buildOverlayScreen();
  buildSubHeader(scr_system, T(STR_SYSTEM_TITLE),
    [](lv_event_t *e){ logSD("BTN: Back -> Settings"); showSettingsScreen(); });

  // The list body every settings screen uses. This screen used to build its
  // own 52 px buttons, which left the content exactly as tall as the button
  // and the screen ending at y=313 of 320 - no room for a seventh entry and
  // none to spare for a longer translation. A scrolling list has neither
  // problem, and the order below is a choice rather than what still fitted.
  lv_obj_t *list = lv_obj_create(scr_system);
  lv_obj_set_size(list, 480, 263);
  lv_obj_set_pos(list, 0, 57);
  lv_obj_set_style_bg_opa(list, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_left(list, 12, 0);
  lv_obj_set_style_pad_right(list, 12, 0);
  lv_obj_set_style_pad_top(list, 6, 0);
  lv_obj_set_style_pad_bottom(list, 6, 0);
  lv_obj_set_style_pad_row(list, 6, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(list, LV_OBJ_FLAG_SCROLL_ELASTIC);

  // Ordered by how often it is reached, with the two that cannot be taken
  // back at the bottom behind their own styling.
  addRow(list, LV_SYMBOL_WIFI, T(STR_WEB_TITLE), T(STR_BTN_WEB_SUB),
    [](lv_event_t *e){ logSD("BTN: System -> Web"); showWebScreen(); });

  lv_obj_t *row_fw =
  addRow(list, LV_SYMBOL_DOWNLOAD, T(STR_BTN_FW_UPDATE), T(STR_BTN_FW_SUB),
    [](lv_event_t *e){ logSD("BTN: -> OTA"); show_ota_pending = true; });

  addRow(list, LV_SYMBOL_LIST, T(STR_LANG_TITLE), T(STR_BTN_LANG_SUB),
    [](lv_event_t *e){ logSD("BTN: System -> Language"); showLanguageScreen(); });

  addRow(list, LV_SYMBOL_BELL, T(STR_BTN_INFO), T(STR_BTN_INFO_SUB),
    [](lv_event_t *e){ logSD("BTN: System -> Info"); show_info_pending = true; });

  addRow(list, LV_SYMBOL_REFRESH, T(STR_BTN_REBOOT), T(STR_BTN_REBOOT_SUB),
    [](lv_event_t *e){
      logSD("BTN: System -> Reboot");
      if (sd_available) SD.end();
      delay(100);
      ESP.restart();
    }, TONE_WARN);

  addRow(list, LV_SYMBOL_TRASH, T(STR_BTN_FACTORY_RESET), T(STR_BTN_FACTORY_RESET_SUB),
    [](lv_event_t *e){ showFactoryResetPopup(); }, TONE_DANGER);

  // The badge is placed with lv_obj_align_to(), which reads the anchor's
  // coordinates as they are right now. Under a flex layout those are not
  // computed until the layout runs, so without this the dot would sit at the
  // list's origin instead of on the firmware row.
  lv_obj_update_layout(list);
  lbl_fw_badge = createUpdateBadge(list, row_fw);

  if (sd_verbose) logSD("[verbose] buildSystemScreen: done");
}
