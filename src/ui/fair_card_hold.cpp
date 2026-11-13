#include "ui/fair_card_hold.h"

#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/fair_card.h"

// Longer than any tap on Tare, so the card never comes out by accident.
#define FAIR_CARD_HOLD_MS 1500

static uint32_t s_pressed_at = 0;
static bool s_fired = false;

// The print blocks the loop for seconds, so the handler only parks it.
static void holdCb(lv_event_t* e) {
  const lv_event_code_t code = lv_event_get_code(e);
  if (code == LV_EVENT_PRESSED) {
    s_pressed_at = lv_tick_get();
    s_fired = false;
    return;
  }
  if (s_fired || !fairCardEnabled()) return;
  if (lv_tick_elaps(s_pressed_at) < FAIR_CARD_HOLD_MS) return;
  s_fired = true;
  print_fair_card_pending = true;
  logSD("UI: Tare held -> fair card");
}

void fairCardHoldAttach(lv_obj_t* tare_button) {
  if (!tare_button) return;
  lv_obj_add_event_cb(tare_button, holdCb, LV_EVENT_PRESSED, nullptr);
  lv_obj_add_event_cb(tare_button, holdCb, LV_EVENT_LONG_PRESSED_REPEAT, nullptr);
}

bool fairCardHoldTookClick() {
  if (!s_fired) return false;
  s_fired = false;
  return true;
}
