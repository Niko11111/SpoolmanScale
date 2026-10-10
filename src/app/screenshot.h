#pragma once

#include <stddef.h>
#include <stdint.h>

#include "hardware/display.h"

// Pictures of the display for bug reports and pull requests. Taken from the
// logs page or by holding two fingers on the panel, kept in PSRAM until the
// next restart, at most SCREENSHOT_MAX of them: a new one pushes the oldest
// out. Each is run-length coded while the frame is drawn - the flat UI packs
// to about 50 KB of the 300 KB a raw frame takes - and handed out as a 24 bit
// BMP: every browser decodes that, and the page turns it into the PNG GitHub
// accepts, so the device needs no image encoder.

enum ScreenshotSource : uint8_t {
  SCREENSHOT_FROM_WEB   = 0,
  SCREENSHOT_FROM_PANEL = 1,
};

static constexpr int SCREENSHOT_MAX = 6;

// The BMP as screenshotBmpHeader() and screenshotBmpRow() hand it out.
static constexpr size_t SCREENSHOT_BMP_HEADER_BYTES = 54;
static constexpr size_t SCREENSHOT_BMP_ROW_BYTES    = (size_t)DISPLAY_W_PX * 3;
static constexpr size_t SCREENSHOT_BMP_FILE_BYTES   =
    SCREENSHOT_BMP_HEADER_BYTES + SCREENSHOT_BMP_ROW_BYTES * DISPLAY_H_PX;

struct ScreenshotInfo {
  uint32_t         id;       // from a random start per boot, counting up, never reused
  uint32_t         age_ms;
  uint32_t         bytes;    // what it holds in PSRAM
  ScreenshotSource source;
};

// Hooks the two-finger hold into the touch driver. Once, after the display.
void screenshotBegin();

// Takes a picture now, at the cost of one full redraw. Loop task, outside
// every LVGL callback; a web handler qualifies. The new id, or 0 when there
// was no room for it even after dropping every older picture.
uint32_t screenshotTake(ScreenshotSource src);

// From appLoop(), right after lv_timer_handler(): takes the picture a
// two-finger hold asked for once every finger is off the panel, and ends the
// blink that confirms it.
void screenshotTick();

// Held pictures, index 0 the oldest.
int  screenshotCount();
bool screenshotInfoAt(int index, ScreenshotInfo& out);
void screenshotDrop(uint32_t id);
void screenshotDropAll();

// A held picture as a BMP file: the header, then DISPLAY_H_PX rows in file
// order. BMP stores the bottom row first; screenshotBmpRow() takes care of
// it. False for an id that is not held.
void screenshotBmpHeader(uint8_t out[SCREENSHOT_BMP_HEADER_BYTES]);
bool screenshotBmpRow(uint32_t id, int file_row, uint8_t out[SCREENSHOT_BMP_ROW_BYTES]);
