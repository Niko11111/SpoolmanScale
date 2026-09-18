#include "app/perf_monitor.h"

#include <Arduino.h>
#include <esp_heap_caps.h>

#include "hardware/display.h"
#include "hardware/sd_logger.h"

static unsigned long s_last_mark_ms    = 0;
static unsigned long s_window_start_ms = 0;
static uint32_t      s_loop_gap_max_ms = 0;

// Time inside the main lv_timer_handler(): reading the touch, LVGL's timers,
// rendering and flushing. Less the flush figures it says what rendering costs.
static uint32_t s_ui_start_us = 0;
static uint32_t s_ui_max_us   = 0;
static uint32_t s_ui_sum_us   = 0;
static uint32_t s_ui_calls    = 0;

void perfLoopMark() {
  s_ui_start_us = micros();
  const unsigned long now = millis();
  if (s_last_mark_ms != 0) {
    const uint32_t gap_ms = (uint32_t)(now - s_last_mark_ms);
    if (gap_ms > s_loop_gap_max_ms) s_loop_gap_max_ms = gap_ms;
  }
  s_last_mark_ms = now;
}

void perfUiDone() {
  const uint32_t ui_us = micros() - s_ui_start_us;
  if (ui_us > s_ui_max_us) s_ui_max_us = ui_us;
  s_ui_sum_us += ui_us;
  s_ui_calls++;
}

void perfLogWindow() {
  const unsigned long now = millis();
  const DisplayFlushStats flush = displayFlushStatsTake();
  const uint32_t sd_write_max_ms = sdWriteMaxTakeMs();
  const uint32_t loop_gap_max_ms = s_loop_gap_max_ms;
  const uint32_t window_s = (uint32_t)((now - s_window_start_ms) / 1000UL);
  s_loop_gap_max_ms = 0;
  s_window_start_ms = now;

  // heap_min is the lowest the internal heap has been since boot, and
  // dma_biggest the largest block a DMA buffer could still get. Both decide
  // how large the draw buffers may become.
  logSDf("[verbose] perf: win=%us loop_gap_max=%ums flush_max=%uus "
         "flush_sum=%ums flushes=%u sd_write_max=%ums heap_min=%u dma_biggest=%u "
         "ui_max=%uus ui_sum=%ums loops=%u buf=%s",
    (unsigned)window_s, (unsigned)loop_gap_max_ms, (unsigned)flush.max_us,
    (unsigned)(flush.sum_us / 1000UL), (unsigned)flush.count,
    (unsigned)sd_write_max_ms, (unsigned)ESP.getMinFreeHeap(),
    (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA),
    (unsigned)s_ui_max_us, (unsigned)(s_ui_sum_us / 1000UL), (unsigned)s_ui_calls,
    displayDrawBufInfo());
  s_ui_max_us = 0;
  s_ui_sum_us = 0;
  s_ui_calls  = 0;

  // The heartbeat and this line are two writes to the card in one pass, some
  // 55 ms that exist only because verbose logging is on. Dropping the mark
  // keeps that pass out of the next window: the figure is meant to say what
  // the firmware does, not what measuring it costs. sd_write_max still shows
  // what a single line takes.
  s_last_mark_ms = 0;
  sdWriteMaxTakeMs();
}
