#include "filaman_options_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "services/user_options.h"
#include "ui_common.h"
#include "theme.h"


void buildFilaManOptionsScreen() {
  logSD("BUILD: FilaManOptionsScreen");
  releaseScreen(&scr_filaman_options);
  scr_filaman_options = buildOverlayScreen();
  buildSubHeader(scr_filaman_options, T(STR_BTN_MORE_OPTIONS),
    [](lv_event_t *e){
      logSD("BTN: Back -> Backend");
      // Deferred: the backend screen must not be built from inside the
      // callback of the screen it replaces.
      show_backend_pending = true;
    });

  lv_obj_t *list = lv_obj_create(scr_filaman_options);
  lv_obj_set_size(list, 480, 263);
  lv_obj_set_pos(list, 0, 57);
  lv_obj_set_style_bg_opa(list, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_left(list, 12, 0);
  lv_obj_set_style_pad_right(list, 12, 0);
  lv_obj_set_style_pad_top(list, 6, 0);
  lv_obj_set_style_pad_bottom(list, 6, 0);
  lv_obj_set_style_pad_row(list, 6, 0);

  // Link without asking. The subtitle carries the condition, because the
  // setting only ever acts when the spool was already on the scale.
  { char buf_t[40]; strncpy(buf_t, T(STR_FLM_AUTOLINK), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[40]; strncpy(buf_s, T(STR_FLM_AUTOLINK_SUB), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_OK, buf_t, buf_s, g_flm_autolink);

    // Last child is the arrow, which a toggle turns into ON/OFF.
    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) {
      char buf_v[8]; strncpy(buf_v, T(g_flm_autolink ? STR_ON : STR_OFF), sizeof(buf_v)-1);
      buf_v[sizeof(buf_v)-1] = '\0';
      lv_label_set_text(arr_lbl, buf_v);
      lv_obj_set_style_text_color(arr_lbl,
        g_flm_autolink ? tc(TH_ACCENT) : tc(TH_TEXT_MUTED), 0);
      lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_14, 0);
    }

    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      g_flm_autolink = !g_flm_autolink;
      prefsPutBool("flm_autolink", g_flm_autolink);
      logSDf("BTN: FilaMan Options -> auto link %s", g_flm_autolink ? "ON" : "OFF");
      // Rebuild rather than patch the labels, same as the scale menu toggles.
      if (scr_filaman_options) { lv_obj_del(scr_filaman_options); scr_filaman_options = nullptr; }
      buildFilaManOptionsScreen();
      lv_obj_clear_flag(scr_filaman_options, LV_OBJ_FLAG_HIDDEN);
    }, LV_EVENT_CLICKED, NULL); }
}
