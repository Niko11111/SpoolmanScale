#pragma once

#include <Arduino.h>

extern bool sd_available;
// Whether the verbose lines are produced at all. Derived from the level
// below rather than stored: 36 call sites ask it before they even build
// their message, and that has to stay a plain read.
extern bool sd_verbose;

// ---- where the lines are kept and how many of them ------------------
//
// One destination at a time. Writing to the card and to the flash at once
// would cost both, and the card alone already costs 26 to 28 ms of loop time
// per line; the flash ring costs 0.43 ms. The session ring below fills
// whatever is chosen, including OFF.
enum LogDest : uint8_t {
  LOG_DEST_OFF      = 0,
  LOG_DEST_SD       = 1,
  LOG_DEST_INTERNAL = 2,
};

// The scope, smallest first. MIN leaves out the screen trace - which screen
// was built, which one was shown - and keeps everything a fault report needs,
// the button presses included. NORMAL is what the card has always written.
// VERBOSE adds the lines the firmware only produces when it is asked to.
enum LogLevel : uint8_t {
  LOG_LVL_MIN     = 0,
  LOG_LVL_NORMAL  = 1,
  LOG_LVL_VERBOSE = 2,
};

// What the owner asked for, and what this boot can actually do: a card that
// is not in is not a setting that changed, so the stored value stays put and
// only the effective one falls back.
LogDest  logDestStored();
LogDest  logDestEffective();
LogLevel logLevel();

// Store and apply. False when NVS refused the write, and then nothing
// changed: a switch that flips for this boot only would come back at the next
// restart without a word.
bool logDestSet(LogDest d);
bool logLevelSet(LogLevel l);

String getCurrentLogFilename();
void logSD(const char* msg);
void logSDf(const char* fmt, ...);
// Writes the lines other tasks queued. From appLoop().
void sdLoggerTick();
// The longest a single line held up the loop since the last call, in
// milliseconds, then reset. Zero without a card. Loop task only.
uint32_t sdWriteMaxTakeMs();
void initSD();


// ---- session log --------------------------------------------------
//
// Every line also lands in a ring buffer in PSRAM, whether or not a card is
// fitted. Without one that ring is the only log the device has, which is
// exactly the case where somebody is trying to find out why something did
// not work. The card is for keeping logs, not for having them.
//
// Allocated once at boot and lost on restart. The mutex costs nothing and is
// kept because the web handler is the reader: it runs from appLoop() today,
// but that is a scheduling detail this file should not depend on.
void   logRingInit();
size_t logRingCount();

// Lines written since boot, counting the ones already overwritten. A reader
// that remembers this number can ask for what it has not seen instead of
// fetching the whole ring, which is what makes following the log cheap.
uint32_t logRingSeq();

// One line by its absolute sequence number. False when that line has already
// been overwritten, which tells a reader its cursor is stale.
//
// The line comes back without a timestamp: when is the UTC moment it was
// written, or 0 if the clock was not set yet, in which case up_s holds
// seconds since boot instead. Rendering is the caller's business.
bool   logRingGetSeq(uint32_t seq, char *out, size_t out_len,
                     time_t *when, uint32_t *up_s);
void cleanOldLogs();

// Makes the writer forget how big it believes today's log to be, so the next
// line asks the card again. Whoever deletes a log file calls this: the cap is
// a megabyte per file, and without it the old count keeps standing over a
// file that is no longer there - card free, log mute all the same.
void sdLogResetSize();
void writeBootBlock(const char* boot_or_reboot);
