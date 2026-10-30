#pragma once

extern bool g_auto_weight;
extern bool g_auto_loc_popup;
extern bool g_auto_tare;
extern float auto_weight_last_val;
extern unsigned long auto_weight_stable_ms;
// This spool is dealt with - written, found unchanged, or held back - until
// it comes off the pad. A send from the weight popup sets it too.
extern bool auto_weight_done;

#define AUTO_WEIGHT_STABLE_MS 3000
// The strict test for a settled weight (AMS report, BamBuddy's "stable").
#define AUTO_WEIGHT_THRESH_G 0.5f
// The automatic weighing's own window: the weight has to stay within
// AUTO_WEIGHT_BAND_G of where it started. For AUTO_WEIGHT_QUIET_MS nothing
// shows, then the button counts AUTO_WEIGHT_STABLE_MS down. With 0.5 g and
// no quiet phase the countdown started the moment a spool touched the pad
// and broke off again and again while the average was still climbing; 2 g
// ignores a reading that wobbles by a gram, and still restarts for a spool
// that is really moving.
#define AUTO_WEIGHT_BAND_G    2.0f
#define AUTO_WEIGHT_QUIET_MS  1000
// Auto-tare until it is switched off in the scale menu: an empty pad that
// drifts a few grams is fixed without anyone noticing.
#define AUTO_TARE_DEFAULT     true
// Below this much change against the backend nothing is written: the value
// is the same, and a write would only cost a request.
#define AUTO_WEIGHT_MIN_CHANGE_G 1.0f
// A spool that reads this much heavier than stored is not written on its
// own. Filament only ever leaves a spool; more weight means a bag, another
// spool, or a refill, and the user is asked (Nikolai, 26.10.2026: 5 g).
#define AUTO_WEIGHT_RISE_G 5.0f
// Below this much nothing is on the pad, whatever the spool: a tag held to
// the reader alone reads a few grams of drift at most.
#define AUTO_WEIGHT_EMPTY_PAD_G 20.0f

// True while the pad holds too little for any spool to be on it: less than
// AUTO_WEIGHT_EMPTY_PAD_G. Nothing is written while this holds. The spool's
// stored empty weight is not used: it is often a default rather than measured
// (BamBuddy keeps 250 g for every spool without its own), and a lighter
// cardboard spool with little filament left would read as missing.
bool autoWeightPadTooLight(float grams);
