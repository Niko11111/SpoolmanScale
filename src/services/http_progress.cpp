#include "http_progress.h"

#include <Arduino.h>

static HttpProgressFn s_progress = nullptr;

static uint32_t s_stall_total_ms = 0;
static uint32_t s_stall_started   = 0;
static uint8_t  s_stall_depth     = 0;

void httpStallBegin() {
  if (s_stall_depth == 0) s_stall_started = millis();
  if (s_stall_depth < 255) s_stall_depth++;
}

void httpStallEnd() {
  if (s_stall_depth == 0) return;
  s_stall_depth--;
  // Only the outermost bracket adds anything: the inner ones are already
  // inside the span it is measuring.
  if (s_stall_depth == 0) s_stall_total_ms += millis() - s_stall_started;
}

uint32_t httpStallTotalMs() {
  // A bracket that is still open counts as far as it has come, so a clock
  // asked in the middle of one - which cannot happen from the loop, but can
  // from a progress hook - sees the truth rather than the last total.
  if (s_stall_depth > 0) return s_stall_total_ms + (millis() - s_stall_started);
  return s_stall_total_ms;
}

void           httpSetProgressHook(HttpProgressFn fn) { s_progress = fn; }
HttpProgressFn httpProgressHook()                     { return s_progress; }
bool           httpProgressActive()                   { return s_progress != nullptr; }

// The hook is called every PROGRESS_STEP bytes rather than per byte: the count
// itself is free, but a hook that redraws is not, and ArduinoJson pulls one
// byte at a time often enough to matter. The hook throttles again by time -
// this only keeps the call out of the innermost loop.
#define PROGRESS_STEP  512

void HttpProgressStream::count(size_t n) {
  total_ += n;
  if (total_ - last_ < PROGRESS_STEP) return;
  last_ = total_;
  if (s_progress) s_progress(total_);
}
