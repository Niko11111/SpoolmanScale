#include "spoolman_options_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/prefs_store.h"
#include "services/user_options.h"
#include "info_popup.h"
#include "extra_fields_screen.h"
#include "ui_common.h"

// ============================================================
//  MORE OPTIONS
//
//  A list of settings, not the settings themselves. One entry
//  today, which is exactly why each one gets its own screen
//  rather than being unfolded here.
// ============================================================
void buildSpoolmanOptionsScreen() {
  logSD("BUILD: SpoolmanOptionsScreen");
  releaseScreen(&scr_spoolman_options);
  scr_spoolman_options = buildOverlayScreen();
  buildSubHeader(scr_spoolman_options, T(STR_BTN_MORE_OPTIONS),
    [](lv_event_t *e){
      logSD("BTN: Back -> Backend");
      // Deferred: the backend screen must not be built from inside the
      // callback of the screen it replaces.
      show_backend_pending = true;
    });

  // The list body every screen in here uses. makeListBtn() never positions its
  // button and relies on the parent's flex flow - without these four lines
  // every row lands on the content origin and only the last one is visible.
  lv_obj_t *list = lv_obj_create(scr_spoolman_options);
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

  // Extra fields. The subtitle names the two the scale needs rather than
  // describing them, because the field names are what the user sees on the
  // Spoolman side and are not translated.
  { char buf_t[40];
    backendText(T(STR_EXTRA_FIELDS_TITLE), buf_t, sizeof(buf_t));

    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_LIST, buf_t, "tag, last_dried");
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Spoolman Options -> Extra Fields");
      // Called straight from the callback, the way the backend screen used to
      // do it. showExtraFieldsScreen() releases through lv_obj_del_async() and
      // never touches the screen this button sits on, so there is nothing here
      // that needs deferring.
      showExtraFieldsScreen(false, /*from_options=*/true);
    }, LV_EVENT_CLICKED, NULL); }

  // Writing card_uids. Below the extra fields because it depends on one of
  // them existing, and because it is the rarer setting of the two.
  { char buf_t[40]; strncpy(buf_t, T(STR_CU_WRITE), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[48]; strncpy(buf_s, T(STR_CU_WRITE_SUB), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_PLUS, buf_t, buf_s, g_card_uids_write, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_CU_WRITE, STR_CU_WRITE_INFO));

    // Last child is the arrow, which a toggle turns into ON/OFF.
    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) {
      char buf_v[8]; strncpy(buf_v, T(g_card_uids_write ? STR_ON : STR_OFF), sizeof(buf_v)-1);
      buf_v[sizeof(buf_v)-1] = '\0';
      lv_label_set_text(arr_lbl, buf_v);
      lv_obj_set_style_text_color(arr_lbl,
        g_card_uids_write ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
      lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_14, 0);
    }

    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      g_card_uids_write = !g_card_uids_write;
      prefsPutBool("cu_write", g_card_uids_write);
      logSDf("BTN: Spoolman Options -> write card_uids %s",
             g_card_uids_write ? "ON" : "OFF");
      // Rebuild rather than patch the labels, same as the other option screens.
      if (scr_spoolman_options) { lv_obj_del(scr_spoolman_options); scr_spoolman_options = nullptr; }
      buildSpoolmanOptionsScreen();
      lv_obj_clear_flag(scr_spoolman_options, LV_OBJ_FLAG_HIDDEN);
    }, LV_EVENT_CLICKED, NULL); }
}
