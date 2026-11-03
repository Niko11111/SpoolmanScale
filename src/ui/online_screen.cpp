#include "ui/online_screen.h"

#include <Arduino.h>
#include <lvgl.h>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "app/setup_flow.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/backend_profiles.h"
#include "ui/setup_frame.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// makeListBtn() builds icon, title, then this line.
#define ONLINE_ROW_SUB_CHILD 2
#define ONLINE_NOTE_PAD_TOP  8
#define ONLINE_NOTE_W        440

static void onServiceRow(lv_event_t *e) {
  const uint8_t id = (uint8_t)(intptr_t)lv_event_get_user_data(e);
  logSDf("BTN: Online -> %s", backendProfile(id).key);
  // The switch and the browser run on the loop, in that order and in one pass.
  pending_backend_profile = id;
  online_pick_pending = true;
}

static void addServiceRow(lv_obj_t *list, uint8_t id) {
  const BackendProfile &p = backendProfile(id);
  const bool chosen = backendProfileId() == id;
  // The first letter until the services have icons, as on the setup's tiles.
  char letter[2] = { p.name ? p.name[0] : '\0', '\0' };
  lv_obj_t *row = makeListBtn(list, p.name ? letter : LV_SYMBOL_EDIT,
                              p.name ? p.name : T(STR_ONLINE_OTHER), T(p.sub_str), chosen);
  if (backendProfileIsOnline()) markListBtnChosen(row, chosen);
  lv_obj_add_event_cb(row, onServiceRow, LV_EVENT_CLICKED, (void *)(intptr_t)id);

  // The row's own line is a caption, 3.1:1 at 12 px on the dark palette. What a
  // service asks for has to be read before someone signs up for it: font 14,
  // amber where an account is needed (9.0:1), else the soft ink (6.7:1).
  lv_obj_t *sub = lv_obj_get_child(row, ONLINE_ROW_SUB_CHILD);
  lv_obj_set_style_text_font(sub, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_color(sub, lv_color_hex(p.account_url[0] ? UI_COL_WARN : UI_COL_INK_SOFT), 0);
}

void buildOnlineScreen() {
  logSD("BUILD: OnlineScreen");
  releaseScreen(&scr_online);
  scr_online = buildOverlayScreen();
  setupOrSettingsHeader(scr_online, T(STR_ONLINE_TITLE), SETUP_STEP_ONLINE, [](lv_event_t *e) {
    logSD("BTN: Online -> Back");
    show_backend_pending = true;
  });

  lv_obj_t *list = buildOptionList(scr_online);
  for (size_t i = 0; i < BACKEND_ONLINE_COUNT; i++) addServiceRow(list, BACKEND_ONLINE_ORDER[i]);

  lv_obj_t *note = lv_label_create(list);
  lv_obj_set_width(note, ONLINE_NOTE_W);
  lv_label_set_long_mode(note, LV_LABEL_LONG_WRAP);
  lv_label_set_text(note, T(STR_ONLINE_NOTE));
  lv_obj_set_style_text_font(note, UI_FONT_SMALL, 0);
  lv_obj_set_style_text_color(note, lv_color_hex(UI_COL_INK_SOFT), 0);
  lv_obj_set_style_pad_top(note, ONLINE_NOTE_PAD_TOP, 0);
}
