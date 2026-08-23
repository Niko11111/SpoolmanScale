#include "tag_field_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>
#include <cstring>

// backend_api.h pulls in ArduinoJson, which must be parsed before lang.h
// defines the T() macro - ArduinoJson uses T as a template parameter and the
// macro turns its headers into nonsense. Same ordering rule as everywhere
// else in this project that needs both.
#include "services/backend_api.h"

#include "extra_fields_screen.h"
#include "hardware/sd_logger.h"
#include "info_popup.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "services/tag_field.h"
#include "services/user_options.h"
#include "ui_common.h"

// Set by the extra fields menu before it defers to this screen, so the header
// can leave the back button out during first setup the way every other setup
// screen does.
static bool tag_field_setup_flow = false;

void setTagFieldSetupFlow(bool in_setup) { tag_field_setup_flow = in_setup; }

// The list body every option screen uses. makeListBtn() never positions its
// button and relies on the parent's flex flow - without these lines every row
// lands on the content origin and only the last one is visible.
static lv_obj_t* buildList(lv_obj_t *parent) {
  lv_obj_t *list = lv_obj_create(parent);
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
  return list;
}

// ============================================================
//  TAG FIELD
//
//  One of three conventions, so the rows carry no icon of
//  their own: a tick in front of every entry would read as
//  "all three are on". The active one is marked on the right
//  and by its border, the way the other pickers do it.
//
//  Every row has its own help button, because the whole point
//  of the choice is which other program the user wants to line
//  up with, and that is not something a subtitle can carry.
// ============================================================
static void addFieldRow(lv_obj_t *list, uint8_t value) {
  const TagFieldSpec& spec = tagFieldSpec(value);
  const bool active = (g_tag_field == value);

  char buf_t[40];
  strncpy(buf_t, T((StringID)spec.str_name), sizeof(buf_t) - 1);
  buf_t[sizeof(buf_t) - 1] = '\0';

  // The subtitle names who else writes the field, and adds whether the server
  // actually has it. A field that is missing is the one thing that stops the
  // choice from working, so it belongs where the choice is made rather than
  // one screen away.
  //
  // The native source is either supported or it is not, and there is nothing
  // to create - so it says which, and nothing else.
  const bool available = spec.is_native ? backendHasNativeTags()
                                        : backendHasExtraField(spec.key);
  char buf_s[64];
  if (spec.is_native) {
    strncpy(buf_s, T(available ? STR_TF_NATIVE_SUB : STR_TF_NATIVE_NA), sizeof(buf_s) - 1);
    buf_s[sizeof(buf_s) - 1] = '\0';
  } else {
    char who[40];
    strncpy(who, T((StringID)spec.str_sub), sizeof(who) - 1);
    who[sizeof(who) - 1] = '\0';
    char state[32];
    strncpy(state, T(available ? STR_EF_PRESENT : STR_EF_MISSING), sizeof(state) - 1);
    state[sizeof(state) - 1] = '\0';
    snprintf(buf_s, sizeof(buf_s), "%s - %s", who, state);
  }

  lv_obj_t *help = nullptr;
  lv_obj_t *btn = makeListBtn(list, "", buf_t, buf_s, active, &help);
  if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                INFO_POPUP_ARG(spec.str_name, spec.str_info));

  // Last child is the arrow, which here shows which entry is the chosen one.
  // makeListBtn() creates the help button before the arrow on purpose, so this
  // still finds the arrow on a row that has both.
  lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
  if (arr_lbl) {
    lv_label_set_text(arr_lbl, active ? LV_SYMBOL_OK : "");
    lv_obj_set_style_text_color(arr_lbl, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(arr_lbl, &lv_font_montserrat_ext_16, 0);
  }

  // A source the server cannot serve stays visible but inert: the reason it
  // cannot be picked is more use than an entry that simply is not there. An
  // extra field is different - it can be created, so it stays selectable.
  if (spec.is_native && !available) {
    lv_obj_add_state(btn, LV_STATE_DISABLED);
    lv_obj_set_style_opa(btn, LV_OPA_50, 0);
    return;
  }

  lv_obj_set_user_data(btn, (void *)(intptr_t)value);
  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    uint8_t v = (uint8_t)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
    if (v == g_tag_field) return;
    g_tag_field = v;
    g_tag_field_chosen = true;
    prefsPutUChar("tag_field", v);

    // The multi tag switch only means anything on a list field. Clearing it
    // here rather than leaving it set keeps a stale "on" from reaching a write
    // that would put a comma separated value into a single valued field.
    if (!tagFieldIsList() && g_card_uids_write) {
      g_card_uids_write = false;
      prefsPutBool("cu_write", false);
      logSD("Tag field: not a list, multi tag switched off");
    }
    logSDf("BTN: Tag field -> %s", tagFieldKeyName());

    // Rebuild rather than patch the ticks, same as the other option screens -
    // but through the loop, not from here. The rebuild asks whether the newly
    // selected field exists on the server, and that can reach the network.
    show_tag_field_pending = true;
  }, LV_EVENT_CLICKED, NULL);
}

// The row that creates the selected field, shown only while the server does
// not have it. Once it is there this row would be a button with nothing to do,
// and the field's own row above already says "present".
static void addCreateRow(lv_obj_t *list) {
  const TagFieldSpec& spec = tagFieldSelected();
  // Nothing to create for the native source: it is a relation, not a field.
  if (spec.is_native || !spec.key) return;
  if (backendHasExtraField(spec.key)) return;

  char buf_t[48];
  strncpy(buf_t, T(STR_EF_CREATE_ROW), sizeof(buf_t) - 1);
  buf_t[sizeof(buf_t) - 1] = '\0';

  lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_WARNING, buf_t, spec.key);

  lv_obj_t *arr_lbl = lv_obj_get_child(btn, -1);
  if (arr_lbl) lv_label_set_text(arr_lbl, LV_SYMBOL_RIGHT);

  lv_obj_add_event_cb(btn, [](lv_event_t *e) {
    logSDf("BTN: Tag field -> create '%s'", tagFieldKeyName());
    // Creates it, rather than sending the user to the assistant to tap
    // "create" a second time. The row says what it does. Deferred because it
    // reaches the network and this is a button callback.
    create_tag_field_pending = true;
  }, LV_EVENT_CLICKED, NULL);
}

void buildTagFieldScreen() {
  logSD("BUILD: TagFieldScreen");
  releaseScreen(&scr_tag_field);
  scr_tag_field = buildOverlayScreen();

  if (tag_field_setup_flow) {
    // Setup has one way onwards and no way back, same as every other screen in
    // that chain: title plus the red close button, no back arrow.
    lv_obj_t *title = lv_label_create(scr_tag_field);
    char buf[40];
    strncpy(buf, T(STR_TAG_FIELD), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    lv_label_set_text(title, buf);
    lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 12);
    addCloseButton(scr_tag_field);
  } else {
    buildSubHeader(scr_tag_field, T(STR_TAG_FIELD), [](lv_event_t *e) {
      logSD("BTN: Back -> Extra fields");
      show_extra_fields_pending = true;
    });
  }

  lv_obj_t *list = buildList(scr_tag_field);

  // Native first: it is the one the scale picks by itself where it can, and
  // the extra fields below it are the compatibility choices. The enum order is
  // the other way round because those values live in NVS and could not be
  // renumbered, so the order is spelled out here instead.
  static const uint8_t ORDER[TAG_FIELD_COUNT] = {
    TAG_FIELD_NATIVE, TAG_FIELD_TAG, TAG_FIELD_NFC_ID, TAG_FIELD_CARD_UIDS
  };
  for (uint8_t i = 0; i < TAG_FIELD_COUNT; i++) addFieldRow(list, ORDER[i]);
  addCreateRow(list);
}
