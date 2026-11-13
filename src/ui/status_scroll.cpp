#include "ui/status_scroll.h"

#include <Arduino.h>
#include <string.h>

// How long a long message stands with "..." before it scrolls: a new one, so
// its beginning can be read, and between two passes.
#define STATUS_SCROLL_FIRST_WAIT_MS 1500
#define STATUS_SCROLL_PAUSE_MS      5000
// Passes a message gets before it stays dotted; 0 keeps it cycling for as long
// as it is shown.
#define STATUS_SCROLL_MAX_PASSES    0
// Enough for every status text; a longer one is compared by its beginning.
#define STATUS_TEXT_COPY_LEN        160
// LV_LABEL_DOT_END_INV in LVGL 8.3, private to lv_label.c: no dots applied.
static constexpr uint32_t LABEL_NOT_DOTTED = 0xFFFFFFFF;

enum StatusScrollState : uint8_t { SCROLL_RESTING, SCROLL_RUNNING };

static lv_obj_t         *s_label     = nullptr;
static StatusScrollState s_state     = SCROLL_RESTING;
static unsigned long     s_since_ms  = 0;
static unsigned long     s_wait_ms   = STATUS_SCROLL_FIRST_WAIT_MS;
static int32_t           s_prev_act  = 0;
static uint16_t          s_passes    = 0;
// The label's text as last seen. While it rests, that is the dotted text LVGL
// made of it, so a new message shows as a difference and a repaint of the
// same one does not.
static char              s_seen[STATUS_TEXT_COPY_LEN] = "";

static void rememberText() {
  const char *t = lv_label_get_text(s_label);
  snprintf(s_seen, sizeof(s_seen), "%s", t ? t : "");
}

static bool textChanged() {
  const char *t = lv_label_get_text(s_label);
  return strncmp(t ? t : "", s_seen, sizeof(s_seen) - 1) != 0;
}

static bool isDotted() {
  return ((lv_label_t *)s_label)->dot_end != LABEL_NOT_DOTTED;
}

static void rest(unsigned long wait_ms) {
  lv_label_set_long_mode(s_label, LV_LABEL_LONG_DOT);
  rememberText();
  s_state    = SCROLL_RESTING;
  s_since_ms = millis();
  s_wait_ms  = wait_ms;
}

static void scroll() {
  lv_label_set_long_mode(s_label, LV_LABEL_LONG_SCROLL_CIRCULAR);
  rememberText();
  s_state    = SCROLL_RUNNING;
  s_prev_act = 0;
}

// One pass is over when LVGL's animation starts its next round: its elapsed
// time falls back. Read from the animation rather than timed with millis(),
// because a loop pass that blocks holds the animation back as well.
static bool passOver() {
  lv_anim_t *a = lv_anim_get(s_label, nullptr);
  if (!a) return true;   // the text fits now, nothing scrolls
  const bool wrapped = a->act_time < s_prev_act;
  s_prev_act = a->act_time;
  return wrapped;
}

void statusScrollAttach(lv_obj_t *label) {
  s_label  = label;
  s_passes = 0;
  if (s_label) rest(STATUS_SCROLL_FIRST_WAIT_MS);
}

void statusScrollTick() {
  if (!s_label) return;
  if (textChanged()) {
    // A new message, set by whoever: its beginning first, from a standstill.
    s_passes = 0;
    rest(STATUS_SCROLL_FIRST_WAIT_MS);
    return;
  }
  if (s_state == SCROLL_RUNNING) {
    if (passOver()) {
      s_passes++;
      rest(STATUS_SCROLL_PAUSE_MS);
    }
    return;
  }
  if (!isDotted()) return;   // it fits, nothing to scroll
  if (STATUS_SCROLL_MAX_PASSES && s_passes >= STATUS_SCROLL_MAX_PASSES) return;
  if (millis() - s_since_ms >= s_wait_ms) scroll();
}
