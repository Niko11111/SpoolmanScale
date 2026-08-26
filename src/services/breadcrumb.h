#pragma once

#include <stdint.h>

// ============================================================
//  WHERE THE FIRMWARE WAS WHEN IT DIED
//
//  A panic reboot writes its backtrace to the serial console, which nobody is
//  watching when the scale sits on a bench with an SD card in it. What the
//  card gets is "Reset reason: PANIC" and the last log line before the fault,
//  and that line is regularly a long way from the fault itself - a lookup that
//  logs when it starts and crashes eight seconds later names the wrong place.
//
//  So the firmware leaves a note in RTC memory instead. That memory is not
//  cleared by a panic reset, only by a power cycle, so the next boot can read
//  what the last one was doing and put it in the boot block.
//
//  The note is deliberately cheap: one strncpy into a fixed buffer, no
//  allocation, no logging, no timing. Marking a spot costs nothing, so spots
//  can be marked generously along the paths that are actually suspected.
// ============================================================

// Marks the current spot. `where` should name a step, not an event: "link list
// build", "loc fetch". Safe to call from anywhere including an ISR context.
void crumbSet(const char* where);

// Reads the note the previous boot left, and re-arms for this one. Call once,
// early, before anything sets a crumb of its own.
void crumbBegin();

// What the previous boot was doing, or "" when there was nothing to read -
// a cold start, or a reset that cleared RTC memory. Only meaningful after
// crumbBegin().
const char* crumbPrevious();

// Milliseconds the previous boot had been up when its crumb was set. Zero when
// there is no crumb. Says whether the fault came seconds or hours after start.
uint32_t crumbPreviousUptimeMs();
