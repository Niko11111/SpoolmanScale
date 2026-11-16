#pragma once

#include <lvgl.h>

// Formnext 2026 only, removed with 0.8.5: holding More info prints the
// business card (services/fair_card.h) while its hidden switch is on. It
// held Tare until 16.11.2026; Tare's hold sets an empty spool offset now.

// Adds the hold to a button. Without the switch the button behaves as
// before; a hold shorter than FAIR_CARD_HOLD_MS is a plain tap.
void fairCardHoldAttach(lv_obj_t* button);

// True once for the click LVGL sends when a hold that printed is let go:
// the button's own handler returns on it.
bool fairCardHoldTookClick();
