#pragma once

#include <stdint.h>

extern uint8_t last_used_mode;
extern bool g_whole_gram;

// Which address the main screen status bar shows next to the scan counter.
// 0 = nothing, 1 = this device's IP, 2 = the filament manager's address.
// Backend mode is useful when running more than one instance and you want to
// see at a glance which one the scale is talking to.
enum IpBarMode : uint8_t {
  IP_BAR_OFF     = 0,
  IP_BAR_DEVICE  = 1,
  IP_BAR_BACKEND = 2,
  IP_BAR_COUNT   = 3
};
extern uint8_t g_ip_bar_mode;

// Skip the confirmation popup for a FilaMan remote link, but only when the
// spool was already on the scale when the request came in. A material or
// colour mismatch always asks regardless - see showRemoteLinkPopup().
extern bool g_flm_autolink;

// Adopt a remotely linked spool for weighing when no tag turns up. The spool
// was chosen deliberately in the web UI, so the useful answer to "no tag" is
// to weigh it anyway rather than report a failure. Nothing is written to any
// tag and no binding is stored; it lasts until the next scan.
extern bool g_flm_tagless;
// Wake the panel when the load on the scale changes. On by default: putting a
// spool down is the action the device exists to answer, so having to touch the
// screen first to read the result is the wrong way round. Switchable for a
// scale that shares a bench with something that knocks it.
extern bool g_wake_on_load;
