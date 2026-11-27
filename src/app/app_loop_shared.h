#pragma once

// What appLoop() and the tag scan (app/tag_scan*.cpp) both work with: the
// weight that witnesses a removal, the moment the tag was last seen, and the
// questions a removal raises. Included by app_loop.cpp and the tag_scan files
// only (check.sh); everything else reaches the loop through app_loop.h.

namespace apploop {

// ── Weight cross-check for the location-on-removal popup ────────
//
// The NFC reader loses an NTAG now and then even when the spool has not
// moved, and every one of those glitches used to look like a removal. The
// scale is a second, independent witness: if the spool is still sitting on
// it, the weight has not changed, and there was no removal no matter what
// the reader says.
//
// Below this the scale carries nothing meaningful, so it cannot testify
// either way and the timer alone decides, exactly as before.
constexpr float LOC_WEIGHT_MIN_G = 50.0f;
// Noise of the moving average plus a nudge of the table.
constexpr float LOC_WEIGHT_TOLERANCE_G = 30.0f;
// Losing more than half the reference is unambiguous: nothing but taking the
// spool off does that. Then the popup need not wait for the full debounce.
constexpr float LOC_WEIGHT_GONE_FRACTION = 0.5f;

extern unsigned long last_tag_seen_ms;
extern float loc_weight_ref;
extern bool loc_left_pad;
extern bool tag_kept_by_weight;

bool weightSaysSpoolStayed();
bool weightSaysSpoolGone();

// The location, AMS and bay questions a removal schedules. Called by the scan
// the moment it declares the tag removed; asked later by appLoop() once the
// debounce and the weight agree.
void onTagRemoved();

}  // namespace apploop
