#pragma once

#include <stddef.h>
#include <stdio.h>

// What the scale calls itself to a Spoolman server: its name and version and
// nothing else. Pure logic: no Arduino, no state.

#define USER_AGENT_PRODUCT  "SpoolmanScale"
// Room for the name, a slash and a version such as "0.10.12-beta.99".
#define USER_AGENT_LEN      40

// "v0.8.4-beta.54" becomes "SpoolmanScale/0.8.4-beta.54".
inline void userAgentFor(const char* fw_version, char* out, size_t out_len) {
  const char* version = fw_version;
  if (version[0] == 'v') version++;
  snprintf(out, out_len, USER_AGENT_PRODUCT "/%s", version);
}
