#pragma once

#include <stdint.h>

// Turn a firmware tag such as "v0.6.0-beta.4" into a number that can be
// compared with >. Shared by the manual check on the GitHub OTA screen and by
// the background check, so both agree on what counts as newer.
uint64_t parseVersion(const char* v);
