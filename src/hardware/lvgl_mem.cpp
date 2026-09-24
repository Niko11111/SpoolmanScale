#include "hardware/lvgl_mem.h"

#include <string.h>
#include <esp_heap_caps.h>

#include "lv_conf.h"

// Why this exists, in numbers (Core 2, dev beta.52, idle): 117 kB of internal
// heap free, 96 kB of it sitting in LVGL's fixed pool, of which the idle UI
// used about 20 kB. The pool kept LVGL from starving anything else - that was
// its virtue - but it also kept 76 kB idle that nothing else could reach.
//
// The pool's virtue is kept by the budget and the reserve in lvgl_mem.h. What
// happens past them:
// - A list stops, as it did at the end of the pool: lvPoolHasRoomForRow()
//   asks lvMemInternalRoom(), so no list row is ever built in PSRAM. Rows in
//   PSRAM are what made scrolling stutter when the whole pool lived there
//   (24.09.2026, ui_max 141 to 320 ms against 13 to 21 ms).
// - Anything else - a popup, a draw buffer, a label's text - goes to PSRAM,
//   where the pool used to answer NULL and the device froze or panicked.
//
// No header in front of the blocks: the heap already knows their size
// (heap_caps_get_allocated_size) and the address says which RAM they are in.

#define LVGL_MEM_CAPS_INT  (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)
#define LVGL_MEM_CAPS_PS   (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)

static uint32_t s_int_used  = 0;
static uint32_t s_int_peak  = 0;
static uint32_t s_ps_used   = 0;
static uint32_t s_ps_peak   = 0;
static uint32_t s_blocks    = 0;
static uint32_t s_ps_allocs = 0;
static uint32_t s_fails     = 0;

#ifdef SPOOLMANSCALE_SIM
// The host has one heap and no PSRAM addresses, so the simulator remembers
// which blocks it handed out as PSRAM. That keeps the fallback testable there
// with a small LVGL_MEM_INTERNAL_BUDGET.
#include <malloc/malloc.h>
#include <unordered_set>
static std::unordered_set<void*> s_sim_ps;
static size_t blockSize(void *p)   { return malloc_size(p); }
static bool   blockInPsram(void *p) { return s_sim_ps.count(p) != 0; }
static void   simMarkPsram(void *p, bool ps) { if (ps) s_sim_ps.insert(p); else s_sim_ps.erase(p); }
#else
#if __has_include(<esp_memory_utils.h>)
#include <esp_memory_utils.h>
#else
#include <soc/soc_memory_types.h>
#endif
static size_t blockSize(void *p)   { return heap_caps_get_allocated_size(p); }
static bool   blockInPsram(void *p) { return esp_ptr_external_ram(p); }
static void   simMarkPsram(void *, bool) {}
#endif

bool lvMemInternalRoom(size_t bytes) {
  if (s_int_used + bytes > LVGL_MEM_INTERNAL_BUDGET) return false;
  return heap_caps_get_free_size(LVGL_MEM_CAPS_INT) >= bytes + LVGL_MEM_INTERNAL_RESERVE;
}

static void account(void *p, bool add) {
  const uint32_t size = (uint32_t)(blockSize(p) + LVGL_MEM_BLOCK_OVERHEAD);
  if (blockInPsram(p)) {
    if (add) {
      s_ps_used += size;
      if (s_ps_used > s_ps_peak) s_ps_peak = s_ps_used;
    } else {
      s_ps_used = s_ps_used > size ? s_ps_used - size : 0;
    }
  } else {
    if (add) {
      s_int_used += size;
      if (s_int_used > s_int_peak) s_int_peak = s_int_used;
    } else {
      s_int_used = s_int_used > size ? s_int_used - size : 0;
    }
  }
  if (add) s_blocks++;
  else if (s_blocks > 0) s_blocks--;
}

extern "C" void *lvMemAlloc(size_t size) {
  void *p = nullptr;
  if (lvMemInternalRoom(size + LVGL_MEM_BLOCK_OVERHEAD)) p = heap_caps_malloc(size, LVGL_MEM_CAPS_INT);
  if (!p) {
    p = heap_caps_malloc(size, LVGL_MEM_CAPS_PS);
    if (!p) {
      s_fails++;
      return nullptr;
    }
    simMarkPsram(p, true);
    s_ps_allocs++;
  }
  account(p, true);
  return p;
}

extern "C" void lvMemFree(void *p) {
  if (!p) return;
  account(p, false);
  simMarkPsram(p, false);
  heap_caps_free(p);
}

extern "C" void *lvMemRealloc(void *p, size_t size) {
  if (!p) return lvMemAlloc(size);
  const size_t old_size = blockSize(p);

  // An internal block that may grow where it is: the heap can often extend it
  // in place, and nothing needs copying. On failure p is left untouched.
  if (!blockInPsram(p) && lvMemInternalRoom(size > old_size ? size - old_size : 0)) {
    account(p, false);
    void *q = heap_caps_realloc(p, size, LVGL_MEM_CAPS_INT);
    account(q ? q : p, true);
    if (q) return q;
  }

  // Otherwise a new block by the usual rule, which also brings a PSRAM block
  // back inside once there is room again.
  void *q = lvMemAlloc(size);
  if (!q) return nullptr;
  memcpy(q, p, old_size < size ? old_size : size);
  lvMemFree(p);
  return q;
}

LvMemStats lvMemStats() {
  LvMemStats s;
  s.int_used  = s_int_used;
  s.int_peak  = s_int_peak;
  s.ps_used   = s_ps_used;
  s.ps_peak   = s_ps_peak;
  s.blocks    = s_blocks;
  s.ps_allocs = s_ps_allocs;
  s.fails     = s_fails;
  s.used_pct  = (uint8_t)((uint64_t)s_int_used * 100u / LVGL_MEM_INTERNAL_BUDGET);
  return s;
}
