#include "ui/tare_offset.h"

#include <Arduino.h>
#include <math.h>
#include <stdio.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/spool_options_popup.h"
#include "ui/theme.h"

// Longer than any tap on Tare, so the lists never open by accident.
#define TARE_HOLD_MS          800
// Where the mark sits: centred under the word TARE (main_screen.cpp puts
// it 12 px below the middle), where the button has the most room.
#define TARE_OFFSET_MARK_DY   26

static uint32_t    s_pressed_at = 0;
static bool        s_fired = false;
static lv_obj_t*   s_mark = nullptr;
static float       s_shown_g = -1.0f;
// The spool picked last, so the lists show it chosen; cleared with the offset.
static SpoolChoice s_choice;

static void onListClosed(bool) {
  const float g = spoolChoiceActive(s_choice) ? (float)s_choice.weight_g : 0.0f;
  g_spool_offset_g = g;
  logSDf("UI: Tare held -> empty spool offset %.0f g", g);
}

static void holdCb(lv_event_t* e) {
  if (lv_event_get_code(e) == LV_EVENT_PRESSED) {
    s_pressed_at = lv_tick_get();
    s_fired = false;
    return;
  }
  if (s_fired || lv_tick_elaps(s_pressed_at) < TARE_HOLD_MS || spoolOptionsOpen()) return;
  s_fired = true;
  // A tare since the last pick has cleared the offset: the lists start on
  // "No offset" then.
  if (g_spool_offset_g == 0.0f) spoolChoiceClear(&s_choice);
  SpoolOptionsSpec spec = {};
  spec.choice    = &s_choice;
  spec.maker     = "";
  spec.auto_name = STR_SPICK_NO_OFFSET;
  spec.on_close  = onListClosed;
  showSpoolPickList(spec);   // built on the loop's next pass
}

void tareOffsetAttach(lv_obj_t* tare_button) {
  if (!tare_button) return;
  lv_obj_add_event_cb(tare_button, holdCb, LV_EVENT_PRESSED, nullptr);
  lv_obj_add_event_cb(tare_button, holdCb, LV_EVENT_LONG_PRESSED_REPEAT, nullptr);
  s_mark = lv_label_create(tare_button);
  lv_obj_set_style_text_color(s_mark, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(s_mark, UI_FONT_CAPTION, 0);
  lv_obj_align(s_mark, LV_ALIGN_CENTER, 0, TARE_OFFSET_MARK_DY);
  s_shown_g = -1.0f;
  tareOffsetTick();
}

bool tareOffsetTookClick() {
  if (!s_fired) return false;
  s_fired = false;
  return true;
}

void tareOffsetTick() {
  if (!s_mark || g_spool_offset_g == s_shown_g) return;
  s_shown_g = g_spool_offset_g;
  if (g_spool_offset_g <= 0.0f) {
    lv_obj_add_flag(s_mark, LV_OBJ_FLAG_HIDDEN);
    return;
  }
  char buf[12];
  snprintf(buf, sizeof(buf), "-%.0f", g_spool_offset_g);
  lv_label_set_text(s_mark, buf);
  lv_obj_clear_flag(s_mark, LV_OBJ_FLAG_HIDDEN);
}
