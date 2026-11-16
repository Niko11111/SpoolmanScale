#pragma once

#include <new>
#include <stdlib.h>
#include <esp_heap_caps.h>

// One long-lived object built in PSRAM instead of BSS. Internal RAM is what
// WiFi, the worker stacks and LVGL share, and every kilobyte held there for
// good is a kilobyte a screen cannot use: the AMS view's state alone is
// 3.7 kB since an AMS 3H brought nine bays (16.11.2026).
//
// Falls back to the internal heap on a board without PSRAM, and gives
// nullptr only when neither has room. Callers keep the object for the life
// of the firmware and never free it.
template <typename T>
T* psramNew() {
  void* p = heap_caps_malloc(sizeof(T), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!p) p = malloc(sizeof(T));
  return p ? new (p) T() : nullptr;
}
