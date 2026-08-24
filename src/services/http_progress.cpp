#include "http_progress.h"

static HttpProgressFn s_progress = nullptr;

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
