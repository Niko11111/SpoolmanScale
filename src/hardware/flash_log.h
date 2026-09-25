#pragma once

#include <Arduino.h>
#include <time.h>

// ============================================================
//  THE LOG THAT NEEDS NO CARD
// ============================================================
//
//  The scale has a data partition it never used: 5.875 MB behind the label
//  "spiffs" on the table shipped since September 2026, 9.938 MB at the same
//  label on every device flashed before it. This file takes the first 2 MB of
//  it and runs a ring of fixed records through it, without a filesystem.
//
//  Why no filesystem. LittleFS was measured on the device against the shape
//  the card uses, open and append and close per line: 66 ms. Holding the
//  handle open and flushing every line, which is the same durability the card
//  gives, still cost 45 ms. Both are worse than the 26 to 28 ms of the SD
//  card, and the point of writing into flash was to be cheaper. A record
//  written straight to the partition costs 0.43 ms, with 2 ms the worst of
//  two hundred. That is the whole reason this is not a filesystem.
//
//  What it costs instead: a sector has to be erased before it can be written
//  again, and that takes 54 ms. flashLogTick() keeps one erased sector ahead
//  of the write head, so a log line never pays for it. Only a burst that
//  crosses a sector boundary between two loop passes does, and even then it
//  is one 54 ms erase per 32 lines instead of 27 ms per line.
//
//  Oldest out, newest in: when the head reaches the end of the 2 MB it wraps
//  to the start, and the sector it is about to enter is erased ahead of it.
//  Nothing has to be swept, and there is no moment where the log is full and
//  goes quiet - the reason the card path rotates rather than stopping.
//
//  A line longer than one record spills into the next ones and is put back
//  together when it is read, so nothing is truncated that the card would
//  have kept.

// How much of the partition the log owns. The rest stays free for whatever
// comes next; both partition tables are far larger than this.
#define FLASH_LOG_BYTES      (2UL * 1024UL * 1024UL)

// How many lines fit before the oldest is overwritten. A line of ordinary
// length takes one 128 byte record; a long one takes two, so this is the
// upper bound and the figure the browser shows.
#define FLASH_LOG_LINE_CAPACITY  (FLASH_LOG_BYTES / 128UL)

// Opens the ring and finds the write head. False when the device has no data
// partition, which is no error: the firmware then logs the way it always did.
bool flashLogBegin();
bool flashLogAvailable();

// One line. `when` is the UTC moment it happened, or 0 when the clock was not
// set yet, in which case `up_s` names the seconds since boot instead - the
// same pair the session ring stores. Loop task only, like the card: the queue
// in sd_logger.cpp parks lines from anywhere else.
void flashLogWrite(time_t when, uint32_t up_s, const char* msg);

// Keeps a sector erased ahead of the head and carries out a pending clear, a
// sector per call. From appLoop(), next to sdLoggerTick().
void flashLogTick();

// What is stored right now.
uint32_t flashLogLines();
uint32_t flashLogUsedBytes();
uint32_t flashLogCapacityBytes();

// Hides every line written so far and starts erasing them in the background,
// a sector per flashLogTick(). Returns at once: the reader stops showing them
// immediately, the flash is clean a few seconds later.
void flashLogClear();
bool flashLogClearBusy();

// Hands every stored line to `emit`, oldest first, already rendered as
// "[HH:MM:SS] text" the way the card writes it. Returns the number of lines.
// The callback must not log: it would write into the ring it is reading.
uint32_t flashLogEmit(void (*emit)(const char* line, void* ctx), void* ctx);

// Sector erases since the last call and the longest of them, then reset. For
// the perf window.
void flashLogEraseStatsTake(uint32_t* count, uint32_t* max_us);
