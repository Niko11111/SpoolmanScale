#include "filaman_options_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui_common.h"

// ============================================================
//  MORE OPTIONS
//
//  Every row comes from the one table in
//  services/settings_registry.h - which one belongs here is the
//  scope on the descriptor, not a list kept in this file. An
//  option added there appears in the web interface at the same
//  time, which is the whole point: the hand written version of
//  this screen was ~27 lines of LVGL per switch, and none of it
//  existed in the browser at all.
// ============================================================
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

  addSettingRows(buildOptionList(scr_filaman_options));
}
