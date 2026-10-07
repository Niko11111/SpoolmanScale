#include "app/screenshot.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <esp_random.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"

// Two fingers on the panel this long take a picture. Long enough that a
// pinch or a palm brushing the glass does not, short enough to hold still.
static constexpr uint32_t SHOT_HOLD_MS  = 1000;
// The backlight goes dark this long once the picture is taken: the
// confirmation, without an LVGL object on a pool that is near its limit.
static constexpr uint32_t SHOT_BLINK_MS = 150;

// PSRAM all held pictures may take together. Measured on the 86 screens of
// the simulator's catalogue, a picture packs to 47 KB in the median and 76 KB
// at worst (the diagnostics popup), so six of the worst still fit. A screen
// busier than any of those pushes out one more of the older pictures.
static constexpr size_t SHOT_BUDGET_BYTES = SCREENSHOT_MAX * 80 * 1024;
static constexpr size_t SHOT_GROW_BYTES   = 16 * 1024;

// A picture in memory: the offset of every row first, so a row can be read
// without decoding the ones before it, then the rows as runs of one colour,
// each a 16 bit length and a 16 bit RGB565 value. A run never crosses a row.
static constexpr size_t SHOT_ROW_TABLE_BYTES = DISPLAY_H_PX * sizeof(uint32_t);
static constexpr size_t SHOT_RUN_BYTES       = 4;
static constexpr size_t SHOT_ROW_MAX_BYTES   = DISPLAY_W_PX * SHOT_RUN_BYTES;
static_assert(SHOT_ROW_MAX_BYTES <= SHOT_GROW_BYTES, "one growth step must hold a row");

static constexpr uint32_t BMP_INFO_HEADER_BYTES = 40;
static constexpr uint16_t BMP_BITS_PER_PX       = 24;
static constexpr uint32_t BMP_PX_PER_METRE      = 2835;   // 72 dpi
// BMP pads every row to four bytes; a row of this width needs none.
static_assert(SCREENSHOT_BMP_ROW_BYTES % 4 == 0, "BMP rows would need padding");

struct Shot {
  uint8_t*         buf;
  size_t           len;
  size_t           cap;
  uint32_t         id;
  uint32_t         taken_ms;
  ScreenshotSource source;
};

static Shot     s_shots[SCREENSHOT_MAX];   // index 0 the oldest
static int      s_count    = 0;
static uint32_t s_last_id  = 0;
static Shot*    s_building = nullptr;      // counts against the budget too

// The two-finger hold, fed by the touch driver on every poll.
struct TwoFingerHold {
  uint32_t since_ms;
  bool     timing;
  bool     fired;
};
static TwoFingerHold s_hold          = {0, false, false};
static bool          s_panel_wanted  = false;
static bool          s_fingers_down  = false;
static bool          s_blinking      = false;
static uint32_t      s_blink_from_ms = 0;

// One touch poll. True while the touch belongs to the gesture: from the poll
// on which two fingers complete SHOT_HOLD_MS until every finger is off again.
// fire is set once, on the poll the hold completes. A second finger that
// lifts early starts the count over.
static bool twoFingerStep(TwoFingerHold& h, uint8_t points, uint32_t now_ms, bool& fire) {
  fire = false;
  if (points == 0) {
    h = {0, false, false};
    return false;
  }
  if (h.fired) return true;
  if (points < 2) {
    h.timing = false;
    return false;
  }
  if (!h.timing) {
    h.timing   = true;
    h.since_ms = now_ms;
    return false;
  }
  if (now_ms - h.since_ms < SHOT_HOLD_MS) return false;
  h.fired = true;
  fire    = true;
  return true;
}

static bool onTouchPoll(uint8_t points) {
  bool fire = false;
  const bool held = twoFingerStep(s_hold, points, millis(), fire);
  if (fire) s_panel_wanted = true;
  s_fingers_down = points > 0;
  return held;
}

// Ids start at a random point on every boot. A browser tab keeps the images
// it has fetched by id, and ids that began at 1 again after a restart had it
// show an image from before the restart under the new one's id. Below 2^30,
// so a String::toInt() on the way back reads it whole.
#define SCREENSHOT_ID_SEED_MASK  0x3FFF0000UL

void screenshotBegin() {
  s_last_id = esp_random() & SCREENSHOT_ID_SEED_MASK;
  displaySetTouchGestureHook(onTouchPoll);
}

static void putLe16(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
}

static void putLe32(uint8_t* p, uint32_t v) {
  putLe16(p, (uint16_t)v);
  putLe16(p + 2, (uint16_t)(v >> 16));
}

static uint16_t getLe16(const uint8_t* p) {
  return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t getLe32(const uint8_t* p) {
  return (uint32_t)getLe16(p) | ((uint32_t)getLe16(p + 2) << 16);
}

static size_t bytesInUse() {
  size_t sum = s_building ? s_building->cap : 0;
  for (int i = 0; i < s_count; i++) sum += s_shots[i].cap;
  return sum;
}

static void dropAt(int index) {
  heap_caps_free(s_shots[index].buf);
  for (int i = index; i + 1 < s_count; i++) s_shots[i] = s_shots[i + 1];
  s_count--;
}

// Room for need more bytes in the picture being built. Older pictures go,
// oldest first, while the budget would not hold one more growth step.
static bool ensureRoom(Shot& sh, size_t need) {
  if (sh.len + need <= sh.cap) return true;
  while (s_count > 0 && bytesInUse() + SHOT_GROW_BYTES > SHOT_BUDGET_BYTES) dropAt(0);
  if (bytesInUse() + SHOT_GROW_BYTES > SHOT_BUDGET_BYTES) return false;
  uint8_t* grown = (uint8_t*)heap_caps_realloc(sh.buf, sh.cap + SHOT_GROW_BYTES,
                                               MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!grown) return false;
  sh.buf  = grown;
  sh.cap += SHOT_GROW_BYTES;
  return true;
}

// The display's row sink: notes where row y starts, then writes its runs.
static bool encodeRow(const uint16_t* px, int y, void* ctx) {
  Shot& sh = *(Shot*)ctx;
  if (!ensureRoom(sh, SHOT_ROW_MAX_BYTES)) return false;
  putLe32(sh.buf + (size_t)y * sizeof(uint32_t), (uint32_t)sh.len);
  uint8_t* out = sh.buf + sh.len;
  int x = 0;
  while (x < DISPLAY_W_PX) {
    const uint16_t colour = px[x];
    int run = 1;
    while (x + run < DISPLAY_W_PX && px[x + run] == colour) run++;
    putLe16(out, (uint16_t)run);
    putLe16(out + 2, colour);
    out += SHOT_RUN_BYTES;
    x   += run;
  }
  sh.len = (size_t)(out - sh.buf);
  return true;
}

// Draws the frame into a new Shot. False, with nothing left allocated, when
// the budget or PSRAM ran out on the way.
static bool captureInto(Shot& sh) {
  s_building = &sh;
  bool ok = ensureRoom(sh, SHOT_ROW_TABLE_BYTES);
  if (ok) {
    sh.len = SHOT_ROW_TABLE_BYTES;
    ok = displayCaptureFrame(encodeRow, &sh);
  }
  s_building = nullptr;
  if (!ok) {
    heap_caps_free(sh.buf);
    return false;
  }
  // Hands the unused end of the last growth step back.
  uint8_t* fitted = (uint8_t*)heap_caps_realloc(sh.buf, sh.len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (fitted) {
    sh.buf = fitted;
    sh.cap = sh.len;
  }
  return true;
}

uint32_t screenshotTake(ScreenshotSource src) {
  const uint32_t start_ms = millis();
  Shot sh = {nullptr, 0, 0, 0, 0, src};
  if (!captureInto(sh)) {
    logSDf("Screenshot: capture failed, %d held in %u KB, PSRAM free %u KB", s_count,
           (unsigned)(bytesInUse() / 1024),
           (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024));
    return 0;
  }
  if (s_count == SCREENSHOT_MAX) dropAt(0);
  sh.id       = ++s_last_id;
  sh.taken_ms = millis();
  s_shots[s_count++] = sh;
  logSDf("Screenshot #%lu: %u KB in %lu ms (%s), %d held in %u KB", (unsigned long)sh.id,
         (unsigned)(sh.len / 1024), (unsigned long)(sh.taken_ms - start_ms),
         src == SCREENSHOT_FROM_PANEL ? "panel" : "web", s_count,
         (unsigned)(bytesInUse() / 1024));
  return sh.id;
}

void screenshotTick() {
  if (s_blinking && millis() - s_blink_from_ms >= SHOT_BLINK_MS) {
    s_blinking = false;
    displaySetBrightness((uint8_t)bright_normal);
  }
  // Waits for the fingers to go: a picture taken under them would show the
  // button they rest on as pressed.
  if (!s_panel_wanted || s_fingers_down) return;
  s_panel_wanted = false;
  if (!screenshotTake(SCREENSHOT_FROM_PANEL)) return;
  displaySetBrightness(0);
  s_blinking      = true;
  s_blink_from_ms = millis();
}

int screenshotCount() { return s_count; }

bool screenshotInfoAt(int index, ScreenshotInfo& out) {
  if (index < 0 || index >= s_count) return false;
  const Shot& sh = s_shots[index];
  out = {sh.id, (uint32_t)(millis() - sh.taken_ms), (uint32_t)sh.cap, sh.source};
  return true;
}

static int indexOf(uint32_t id) {
  for (int i = 0; i < s_count; i++) {
    if (s_shots[i].id == id) return i;
  }
  return -1;
}

void screenshotDrop(uint32_t id) {
  const int index = indexOf(id);
  if (index >= 0) dropAt(index);
}

void screenshotDropAll() {
  while (s_count > 0) dropAt(0);
}

void screenshotBmpHeader(uint8_t out[SCREENSHOT_BMP_HEADER_BYTES]) {
  memset(out, 0, SCREENSHOT_BMP_HEADER_BYTES);
  out[0] = 'B';
  out[1] = 'M';
  putLe32(out + 2,  (uint32_t)SCREENSHOT_BMP_FILE_BYTES);
  putLe32(out + 10, (uint32_t)SCREENSHOT_BMP_HEADER_BYTES);   // pixel data offset
  putLe32(out + 14, BMP_INFO_HEADER_BYTES);
  putLe32(out + 18, (uint32_t)DISPLAY_W_PX);
  putLe32(out + 22, (uint32_t)DISPLAY_H_PX);                  // positive: bottom row first
  putLe16(out + 26, 1);                                       // colour planes
  putLe16(out + 28, BMP_BITS_PER_PX);
  putLe32(out + 34, (uint32_t)(SCREENSHOT_BMP_ROW_BYTES * DISPLAY_H_PX));
  putLe32(out + 38, BMP_PX_PER_METRE);
  putLe32(out + 42, BMP_PX_PER_METRE);
}

// RGB565 to the blue, green, red bytes BMP stores. The top bits are repeated
// into the low ones, so white stays 255 and not 248.
static void putBgr(uint8_t* out, uint16_t c) {
  const uint8_t r5 = (c >> 11) & 0x1F, g6 = (c >> 5) & 0x3F, b5 = c & 0x1F;
  out[0] = (uint8_t)((b5 << 3) | (b5 >> 2));
  out[1] = (uint8_t)((g6 << 2) | (g6 >> 4));
  out[2] = (uint8_t)((r5 << 3) | (r5 >> 2));
}

bool screenshotBmpRow(uint32_t id, int file_row, uint8_t out[SCREENSHOT_BMP_ROW_BYTES]) {
  const int index = indexOf(id);
  if (index < 0 || file_row < 0 || file_row >= DISPLAY_H_PX) return false;
  const Shot& sh = s_shots[index];
  const int y = DISPLAY_H_PX - 1 - file_row;
  const uint8_t* in = sh.buf + getLe32(sh.buf + (size_t)y * sizeof(uint32_t));
  int x = 0;
  while (x < DISPLAY_W_PX) {
    const int run = getLe16(in);
    const uint16_t colour = getLe16(in + 2);
    in += SHOT_RUN_BYTES;
    if (run == 0 || x + run > DISPLAY_W_PX) return false;
    for (int i = 0; i < run; i++) putBgr(out + (x + i) * 3, colour);
    x += run;
  }
  return true;
}
