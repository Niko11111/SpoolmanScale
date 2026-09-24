#pragma once

#include <stddef.h>
#include <stdint.h>

// LVGL's memory, taken from the system heap on demand (LV_MEM_CUSTOM in
// lv_conf.h). lvMemAlloc(), lvMemFree() and lvMemRealloc() are declared in
// lv_conf.h, because LVGL's own sources have to find them there.
//
// Internal RAM first, under two limits: LVGL's share of it stays within
// LVGL_MEM_INTERNAL_BUDGET, and the internal heap keeps LVGL_MEM_INTERNAL_RESERVE
// free for WiFi, TLS, the worker stacks and Bluetooth. Past either limit a
// block comes from PSRAM: slower to draw from, but a screen that would have
// run the old pool dry now gets built instead of freezing the device.
//
// Loop task only, like everything else that touches LVGL.

// What the old fixed pool held, so LVGL never holds more internal RAM than it
// did before. Counted with the heap's bookkeeping per block, see
// LVGL_MEM_BLOCK_OVERHEAD, because the old pool paid its own out of the 96 kB.
#ifndef LVGL_MEM_INTERNAL_BUDGET
#define LVGL_MEM_INTERNAL_BUDGET  (96u * 1024u)
#endif

// What the heap adds to every block: on the device 12 bytes of light poisoning
// (CONFIG_HEAP_POISONING_LIGHT, canary and size in front, canary behind) and
// the 4 byte TLSF header. A list row is some 30 blocks, so left out, a row
// cost 13 % less than in the old pool and lists grew past what the pool
// allowed (simulator, 24.09.2026). The simulator's malloc keeps no header of
// its own; it counts the 8 bytes LVGL's pool paid there, so its lists stay
// comparable with the old figures.
#ifdef SPOOLMANSCALE_SIM
#define LVGL_MEM_BLOCK_OVERHEAD   8u
#else
#define LVGL_MEM_BLOCK_OVERHEAD   16u
#endif

// Internal heap that has to stay free after an LVGL block. The worker tasks
// refuse to start below 60000 bytes (WEB_JOB_MIN_HEAP and its siblings), so
// LVGL stops short of that and leaves them some room on top.
#ifndef LVGL_MEM_INTERNAL_RESERVE
#define LVGL_MEM_INTERNAL_RESERVE (64u * 1024u)
#endif

struct LvMemStats {
  uint32_t int_used;    // bytes LVGL holds in internal RAM, overhead included
  uint32_t int_peak;    // highest int_used since boot
  uint32_t ps_used;     // bytes LVGL holds in PSRAM
  uint32_t ps_peak;     // highest ps_used since boot
  uint32_t blocks;      // live blocks in both
  uint32_t ps_allocs;   // blocks that went to PSRAM since boot
  uint32_t fails;       // requests neither could serve since boot
  uint8_t  used_pct;    // int_used of LVGL_MEM_INTERNAL_BUDGET
};
LvMemStats lvMemStats();

// Whether `bytes` more would still come from internal RAM, within the budget
// and above the reserve. What a list asks before it builds another row.
bool lvMemInternalRoom(size_t bytes);
