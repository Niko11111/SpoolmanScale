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
