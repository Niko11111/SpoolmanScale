#pragma once

#include <lvgl.h>

// Formnext 2026 only, removed with 0.8.5: holding Tare prints the business
// card (services/fair_card.h) while its hidden switch is on.

// Adds the hold to the Tare button. Without the switch the button behaves as
// before; a hold shorter than FAIR_CARD_HOLD_MS is a plain tap.
void fairCardHoldAttach(lv_obj_t* tare_button);

// True once for the click LVGL sends when a hold that printed is let go:
// Tare's own handler returns on it instead of taring.
bool fairCardHoldTookClick();
