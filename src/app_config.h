#pragma once

#define FW_VERSION  "v0.7.0-beta.1"
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
