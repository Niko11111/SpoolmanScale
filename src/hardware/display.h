#pragma once

#include <Arduino.h>

// The panel as LVGL sees it, after the rotation in displayHardwareBegin().
static constexpr int DISPLAY_W_PX = 480;
static constexpr int DISPLAY_H_PX = 320;

bool displayHardwareBegin(void (*touch_activity_cb)() = nullptr);
void displaySetBrightness(uint8_t brightness);
void displayPrepareDeepSleep();

// Backlight fully off, and back again. Not the same as brightness 0.
void displayBacklightOff();
void displayBacklightOn(uint8_t brightness);
// Gamma lift applied to every pixel on its way to the panel. 100 = off.
// Values above that raise shadows and midtones without touching white, which
// brightens the whole UI at once. Separate from backlight brightness: the
// backlight is already at its ceiling at 255, so this is the only remaining
// lever on perceived brightness.
void displaySetUiGain(uint16_t gamma_x100);
uint16_t displayGetUiGain();

// What flushing to the panel cost since the last call, then reset: the longest
// single flush, the time spent in all of them, and how many there were. Loop
// task only, like the flush itself.
struct DisplayFlushStats {
  uint32_t max_us;
  uint32_t sum_us;
  uint32_t count;
};
DisplayFlushStats displayFlushStatsTake();

// Where LVGL's draw buffer lives and how many lines it holds, as "int/20" or
// "psram/40". For the log, so that a timing line says what it was measured on.
const char* displayDrawBufInfo();

// Takes one row of a captured frame: DISPLAY_W_PX RGB565 pixels and its
// number from the top. False stops the capture.
typedef bool (*DisplayRowSink)(const uint16_t* px, int y, void* ctx);

// Draws the whole screen once more and hands every row to sink, top to
// bottom. Every layer, popups and lv_layer_top() included, before the gamma
// lift. Loop task only, outside every LVGL callback. False without a
// display, when the sink refused a row, or when the rows did not arrive
// whole and in order.
bool displayCaptureFrame(DisplayRowSink sink, void* ctx);

// Called on every touch poll with the number of fingers down. While it
// returns true the touch belongs to the gesture: LVGL sees a release, and
// what the first finger had pressed is dropped without a click.
void displaySetTouchGestureHook(bool (*hook)(uint8_t points));
