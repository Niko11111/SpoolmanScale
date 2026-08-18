#pragma once

#define FW_VERSION  "v0.6.2-beta"
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

#define CAL_FACTOR_DEFAULT  1.0f
#define SCALE_FILTER_SIZE   8

// Remote link, triggered from the FilaMan web UI. The window matches the 60
// seconds the FilaMan frontend polls for a result, so both sides give up at
// the same time instead of one waiting on the other.
#define REMOTE_LINK_TIMEOUT_MS  60000
