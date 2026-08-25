#include "list_limits.h"

// Measured on hardware, v0.7.0-beta.95: a spool row costs 1090 bytes of the
// LVGL pool and there are 56 kB free when the list opens on a device that has
// been navigated around for a minute. 30 rows take 33 kB of that and leave
// 24 kB - more than the whole main screen needs.
//
// The 16 this replaces dates from April, when the pool was 48 kB and every
// visited screen stayed resident (30 kB free falling to 4.5 kB in a session).
// Both of those were fixed in August and nothing re-checked the number.
//
// A location row costs 716 bytes, which is why its limit is the same 30 for
// less than a third of the memory.
int spool_list_limit = 30;
int location_list_limit = 30;
