#pragma once

#define FW_VERSION  "v0.7.0-beta.87"
#define DONATION_URL "ko-fi.com/formfollowsfunction"

// Backlight PWM duty on GPIO45, 8 bit, straight through to LovyanGFX. Not a
// percentage: 255 is full output.
//
// Min and max describe what the panel is driven at, the default only describes
// what a fresh device starts with. They happen to share the value 255 today,
// which is exactly why they stay separate: tying the slider to the default
// would silently cap it if that default ever changed.
#define BRIGHT_MIN                10   // not 0: the screen has to stay usable
#define BRIGHT_MAX               255
#define BRIGHT_NORMAL_DEFAULT    255
#define DIM_TIMEOUT_DEFAULT   300000
#define SLEEP_TIMEOUT_DEFAULT 1200000
#define OFF_TIMEOUT_DEFAULT        0   // 0 = stage skipped

// Main screen zone 4: the fill of the remaining-filament bar is written from
// two places in spoolman_lookup.cpp and created in main_screen.cpp. It used to
// be a bare 190 in all three, which is how the bar and its background came to
// disagree the moment one of them was widened.
#define MAIN_BAR_W  194

#define CAL_FACTOR_DEFAULT  1.0f
#define SCALE_FILTER_SIZE   8

// Remote link, triggered from the FilaMan web UI. The window matches the 60
// seconds the FilaMan frontend polls for a result, so both sides give up at
// the same time instead of one waiting on the other.
#define REMOTE_LINK_TIMEOUT_MS  60000

// Deriving the empty-spool weight from a brand new spool: the reading minus
// the nominal filament weight. Outside these bounds the reading is not a full
// spool of the expected filament - a half-used one, or a nominal weight that
// is wrong - and a derived tare would be nonsense written to a filament or an
// entire brand.
#define NEW_SPOOL_TARE_MIN_G     30.0f
#define NEW_SPOOL_TARE_MAX_G    600.0f
// How long a remote link waits for a tag before falling back to adopting the
// spool for weighing only. Long enough that someone reaching for a tag is not
// cut off, far short of the full timeout, which otherwise ends in a failure
// for a spool that simply has no tag on it.
#define REMOTE_LINK_TAGLESS_MS  10000

// A spool that reads a few grams over its label weight is simply full, not
// mislabelled. Only a real difference is worth interrupting the weighing for.
#define BB_CAP_TOLERANCE_G   2.0f

// Creating a spool straight from a Bambu tag. The tag carries material,
// brand, colour and temperatures, but no weights at all - a Bambu Lab core
// weighs 250 g, which is also BamBuddy's own default, so a spool created here
// matches what its web UI would have produced.
// Bambu tags carry no vendor string - block 16 reads back empty even on a
// tag whose 48 blocks all decrypt cleanly. The name is implicit: only Bambu
// Lab makes tags that derive with this KDF. The main screen has always shown
// this fallback, so creating a spool uses the same one rather than sending an
// empty brand the server would turn into a filament with no vendor at all.
#define BAMBU_VENDOR_NAME     "Bambu Lab"
#define BAMBU_CORE_WEIGHT_G      250
// The nominal filament weights Bambu sells. The scale picks whichever is
// closest to what it reads and the user can correct it before saving, which
// beats guessing 1000 g for a 250 g refill.
#define NEWTAG_LABEL_COUNT         4
#define NEWTAG_LABEL_CHOICES  { 250, 500, 750, 1000 }

// The verbose heartbeat is checked every 5 s but only written when something
// moved by at least this much, plus one line per keepalive interval so the
// last timestamp still marks how far the loop got. Measured on a real day:
// 90 % of heartbeat lines repeated the previous one byte for byte.
#define HEARTBEAT_QUIET_DELTA_B   1024
#define HEARTBEAT_KEEPALIVE_MS   60000

// How long to wait before re-announcing a tag that the auto-link has just made
// resolvable. Spoolman suppresses a repeat of the same UID from the same
// reader within 3 seconds (DEBOUNCE_WINDOW in its scanrelay.py), so an
// immediate second scan would be swallowed and never reach a paired browser.
#define TAG_RESCAN_DELAY_MS  3500
