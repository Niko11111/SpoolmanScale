#include "filaman_fields_screen.h"
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
#include "info_popup.h"
#include "ui_common.h"

// The field the scale writes a tag into. Not a setting, and the row says so -
// see STR_FLM_TAGFIELD_INFO for why there is nothing to choose here.
#define FLM_TAG_FIELD  "rfid_uid"

// Turns the arrow at the end of a row into ON/OFF, the way the FilaMan
// options screen does it. The label is the last child of the button.
static void rowAsToggle(lv_obj_t *btn, bool on) {
  lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
  if (!arr_lbl) return;
  char buf_v[8];
  strncpy(buf_v, T(on ? STR_ON : STR_OFF), sizeof(buf_v) - 1);
  buf_v[sizeof(buf_v) - 1] = '\0';
  lv_label_set_text(arr_lbl, buf_v);
  lv_obj_set_style_text_color(arr_lbl,
    on ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_14, 0);
}

// Rebuild rather than patch the labels, same as every other toggle in the
// firmware. Deferred, because this runs from the callback of the screen it
// is about to delete.
static void rebuild() {
  if (scr_filaman_fields) { lv_obj_del(scr_filaman_fields); scr_filaman_fields = nullptr; }
  buildFilaManFieldsScreen();
  lv_obj_clear_flag(scr_filaman_fields, LV_OBJ_FLAG_HIDDEN);
}

void buildFilaManFieldsScreen() {
  logSD("BUILD: FilaManFieldsScreen");
  releaseScreen(&scr_filaman_fields);
  scr_filaman_fields = buildOverlayScreen();
  buildSubHeader(scr_filaman_fields, T(STR_FLM_FIELDS),
    [](lv_event_t *e){
      logSD("BTN: Back -> FilaMan options");
      show_filaman_options_pending = true;
    });

  lv_obj_t *list = lv_obj_create(scr_filaman_fields);
  lv_obj_set_size(list, 480, 263);
  lv_obj_set_pos(list, 0, 57);
  lv_obj_set_style_bg_opa(list, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_left(list, 12, 0);
  lv_obj_set_style_pad_right(list, 12, 0);
  lv_obj_set_style_pad_top(list, 6, 0);
  lv_obj_set_style_pad_bottom(list, 6, 0);
  lv_obj_set_style_pad_row(list, 6, 0);
  // makeListBtn() never positions its button, it relies on the parent's
  // layout - without a flex flow every row lands on the content origin.
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(list, LV_OBJ_FLAG_SCROLL_ELASTIC);

  // Where the tag goes. A row without a switch, because the answer is fixed
  // and the question is a fair one to ask on the device - Spoolman has the
  // same row and there it opens a choice.
  { char buf_t[40]; strncpy(buf_t, T(STR_FLM_TAGFIELD), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    lv_obj_t *help = nullptr;
    // Not a toggle, so it gets the neutral border: green here would read as
    // "switched on" next to the two rows below that really do switch.
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_GPS, buf_t, FLM_TAG_FIELD, false, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_FLM_TAGFIELD, STR_FLM_TAGFIELD_INFO));
    // The arrow would promise a screen behind the row, and there is none.
    lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
    if (arr_lbl) lv_label_set_text(arr_lbl, "");
    lv_obj_clear_flag(btn, LV_OBJ_FLAG_CLICKABLE); }

  // The two chip fields the plugin keeps.
  { char buf_t[40]; strncpy(buf_t, T(STR_FLM_BTAGS), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[48]; strncpy(buf_s, T(STR_FLM_BTAGS_SUB), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_SD_CARD, buf_t, buf_s, g_flm_bambu_tags, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_FLM_BTAGS, STR_FLM_BTAGS_INFO));
    rowAsToggle(btn, g_flm_bambu_tags);

    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      g_flm_bambu_tags = !g_flm_bambu_tags;
      prefsPutBool("flm_btags", g_flm_bambu_tags);
      logSDf("BTN: FilaMan Fields -> Bambu tag fields %s", g_flm_bambu_tags ? "ON" : "OFF");
      rebuild();
    }, LV_EVENT_CLICKED, NULL); }

  // external_id, which is what stops the plugin creating the spool twice.
  { char buf_t[40]; strncpy(buf_t, T(STR_FLM_EXTID), sizeof(buf_t)-1);
    buf_t[sizeof(buf_t)-1] = '\0';
    char buf_s[48]; strncpy(buf_s, T(STR_FLM_EXTID_SUB), sizeof(buf_s)-1);
    buf_s[sizeof(buf_s)-1] = '\0';
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_COPY, buf_t, buf_s, g_flm_ext_id, &help);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_FLM_EXTID, STR_FLM_EXTID_INFO));
    rowAsToggle(btn, g_flm_ext_id);

    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      g_flm_ext_id = !g_flm_ext_id;
      prefsPutBool("flm_extid", g_flm_ext_id);
      logSDf("BTN: FilaMan Fields -> write external_id %s", g_flm_ext_id ? "ON" : "OFF");
      rebuild();
    }, LV_EVENT_CLICKED, NULL); }
}
