#pragma once

#define FW_VERSION  "v0.6.1-beta.13"
#define DONATION_URL "ko-fi.com/formfollowsfunction"

#define BRIGHT_NORMAL_DEFAULT  255
#define BRIGHT_DIM_DEFAULT       77
#define DIM_TIMEOUT_DEFAULT   300000
#define SLEEP_TIMEOUT_DEFAULT 1200000

#define CAL_FACTOR_DEFAULT  1.0f
#define SCALE_FILTER_SIZE   8

// Remote link, triggered from the FilaMan web UI. The window matches the 60
// seconds the FilaMan frontend polls for a result, so both sides give up at
// the same time instead of one waiting on the other.
#define REMOTE_LINK_TIMEOUT_MS  60000
