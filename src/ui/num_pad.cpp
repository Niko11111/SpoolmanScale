#include "ui/num_pad.h"

#include <Arduino.h>
#include <lvgl.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "ui/theme.h"
#include "ui/ui_common.h"

// The geometry of the price and tare pads (price_pad.cpp, tare_entry.cpp),
// moved down under the header.
#define NP_KEY_W    90
#define NP_KEY_H    48
#define NP_GAP       6
#define NP_EDGE     10
#define NP_FIELD_Y  52
#define NP_FIELD_H  44
#define NP_KEYS_Y  102
#define NP_PAD_W   (3 * NP_KEY_W + 2 * NP_GAP)
#define NP_COL_X   (NP_EDGE + NP_PAD_W + NP_EDGE)
#define NP_COL_W   (480 - NP_COL_X - NP_EDGE)
#define NP_CANCEL_H (UI_TOUCH_MIN + 10)
#define NP_INPUT_MAX 15
// The same pad as the large popup (NumPadSpec.popup): its parts are placed
// inside the box's 2 px border, the keys 2 px lower than on the screen so
// four rows, the value and the title fit in 300.
#define NPP_INNER_W  (UI_POPUP_LARGE_W - 4)
#define NPP_INNER_H  (UI_POPUP_LARGE_H - 4)
#define NPP_TITLE_Y   8
#define NPP_FIELD_Y  32
#define NPP_KEY_H    46
#define NPP_KEYS_Y   (NPP_INNER_H - NP_EDGE - (4 * NPP_KEY_H + 3 * NP_GAP))
#define NPP_COL_W    (NPP_INNER_W - NP_COL_X - NP_EDGE)

// Where the parts of the pad go, on the screen or in the popup.
struct NpGeom {
  int field_y;
  int keys_y;
  int key_h;
  int col_w;
  uint32_t key_bg;   // the keys stand out from what is behind them
  uint32_t field_bg;
};
static const NpGeom NP_ON_SCREEN = { NP_FIELD_Y, NP_KEYS_Y, NP_KEY_H, NP_COL_W,
                                     UI_COL_SURFACE, UI_COL_SURFACE };
static const NpGeom NP_IN_POPUP  = { NPP_FIELD_Y, NPP_KEYS_Y, NPP_KEY_H, NPP_COL_W,
                                     UI_COL_ROW, UI_COL_GROUND };

static lv_obj_t*  s_scr   = nullptr;
// What the parts are built on: the screen itself, or the popup's box.
static lv_obj_t*  s_root  = nullptr;
static const NpGeom *s_geo = &NP_ON_SCREEN;
static lv_obj_t*  s_value = nullptr;
static lv_obj_t*  s_hint  = nullptr;
static NumPadSpec s_spec  = {};
// The texts are copied: a caller may build them in a buffer of its own.
static char       s_title[48], s_hint_text[160], s_unit[16], s_primary[32];
static char       s_input[NP_INPUT_MAX + 1] = "";
// The value it opened with is shown, and the first digit replaces it rather
// than being appended: nobody wants 30 to become 305.
static bool       s_fresh = false;
// Left or saved, waiting for its owner's loop to replace it: takes no input.
static bool       s_parked = false;

bool numPadOpen() { return s_scr != nullptr; }

void numPadHide() {
  if (s_scr) lv_obj_add_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
}

void numPadClose() {
  releaseScreen(&s_scr);
  s_root = nullptr;
  s_value = nullptr;
  s_hint = nullptr;
  s_parked = false;
}

void numPadDropParked() {
  if (!s_scr || !s_parked) return;
  lv_obj_del(s_scr);
  s_scr = nullptr;
  s_root = nullptr;
  s_value = nullptr;
  s_hint = nullptr;
  s_parked = false;
}

// From one of the pad's own buttons: the screen goes on the next pass.
static void closeFromHandler() {
  if (!s_scr) return;
  if (s_spec.replaced_from_loop) {
    s_parked = true;
    return;
  }
  lv_obj_del_async(s_scr);
  s_scr = nullptr;
  s_root = nullptr;
  s_value = nullptr;
  s_hint = nullptr;
}

static void refreshValue() {
  if (!s_value) return;
  char buf[NP_INPUT_MAX + 16];
  snprintf(buf, sizeof(buf), "%s%s%s", s_input[0] ? s_input : "_", s_unit[0] ? " " : "", s_unit);
  lv_label_set_text(s_value, buf);
}

void numPadSetHint(const char *text, bool refusal) {
  if (!s_hint) return;
  lv_label_set_text(s_hint, text);
  // Amber, not red: a refused entry asks for another try, nothing broke.
  lv_obj_set_style_text_color(s_hint, lv_color_hex(refusal ? UI_COL_WARN : UI_COL_CAPTION), 0);
}

void numPadSetHintGood(const char *text) {
  if (!s_hint) return;
  lv_label_set_text(s_hint, text);
  lv_obj_set_style_text_color(s_hint, lv_color_hex(UI_COL_GOOD), 0);
}

static void inputChanged() {
  refreshValue();
  if (s_spec.on_input) s_spec.on_input(s_input);
}

static void onKey(lv_event_t *e) {
  if (s_parked) return;
  const char *ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
  if (s_fresh) { s_input[0] = '\0'; s_fresh = false; }
  const size_t len = strlen(s_input);
  if (ch[0] == '.' && (len == 0 || strchr(s_input, '.'))) return;   // one point, not first
  if (len >= s_spec.max_chars || len >= NP_INPUT_MAX) return;
  s_input[len] = ch[0];
  s_input[len + 1] = '\0';
  numPadSetHint(s_spec.hint, false);
  inputChanged();
}

static void onBackspace(lv_event_t *) {
  if (s_parked) return;
  s_fresh = false;
  const size_t len = strlen(s_input);
  if (len) s_input[len - 1] = '\0';
  inputChanged();
}

static void onLeave(lv_event_t *) {
  if (s_parked) return;
  logSDf("BTN: NumPad '%s' -> back", s_spec.title);
  void (*leave)() = s_spec.on_leave;
  closeFromHandler();
  if (leave) leave();
}

static void onDone(lv_event_t *) {
  if (s_parked || !s_spec.on_done) return;
  if (s_spec.secret) logSDf("BTN: NumPad '%s' -> %u digits", s_spec.title, (unsigned)strlen(s_input));
  else               logSDf("BTN: NumPad '%s' -> %s", s_spec.title, s_input);
  if (s_spec.on_done(s_input)) closeFromHandler();
}

// The pad as a screen of its own: the house header with back and close.
static void buildScreenFrame() {
  s_geo = &NP_ON_SCREEN;
  s_scr = buildOverlayScreen();
  s_root = s_scr;
  buildSubHeader(s_scr, s_title, onLeave);
  if (s_spec.help_title >= 0) addHeaderHelp(s_scr, s_spec.help_title, s_spec.help_text);
}

// The pad as the large popup over a card's Options: the title on top, no
// header, nothing to close but Back.
static void buildPopupFrame() {
  s_geo = &NP_IN_POPUP;
  s_root = uiPopupBox(&s_scr, UI_POPUP_LARGE_W, UI_POPUP_LARGE_H);
  lv_obj_t *title = lv_label_create(s_root);
  lv_label_set_text(title, s_title);
  lv_obj_set_style_text_color(title, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(title, UI_FONT_SMALL, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, NPP_TITLE_Y);
}

static void buildField() {
  lv_obj_t *box = lv_obj_create(s_root);
  lv_obj_set_size(box, NP_PAD_W, NP_FIELD_H);
  lv_obj_set_pos(box, NP_EDGE, s_geo->field_y);
  lv_obj_set_style_bg_color(box, lv_color_hex(s_geo->field_bg), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  s_value = lv_label_create(box);
  lv_obj_set_style_text_color(s_value, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(s_value, UI_FONT_ICON, 0);
  lv_obj_center(s_value);
  refreshValue();

  s_hint = lv_label_create(s_root);
  lv_label_set_long_mode(s_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(s_hint, s_geo->col_w);
  lv_obj_set_pos(s_hint, NP_COL_X, s_geo->field_y);
  lv_obj_set_style_text_font(s_hint, UI_FONT_CAPTION, 0);
  numPadSetHint(s_hint_text, false);
}

static void buildKeys() {
  static const char *const KEYS[12] = { "1","2","3","4","5","6","7","8","9",".","0","" };
  for (int i = 0; i < 12; i++) {
    const int x = NP_EDGE + (i % 3) * (NP_KEY_W + NP_GAP);
    const int y = s_geo->keys_y + (i / 3) * (s_geo->key_h + NP_GAP);
    const bool point = KEYS[i][0] == '.';
    lv_obj_t *b = padButton(s_root, x, y, NP_KEY_W, s_geo->key_h, s_geo->key_bg, UI_COL_LINE);
    if (point && !s_spec.decimal) {
      lv_obj_clear_flag(b, LV_OBJ_FLAG_CLICKABLE);   // the slot stays, empty
    } else if (KEYS[i][0]) {
      padLabel(b, KEYS[i], UI_COL_INK, UI_FONT_HEADLINE);
      lv_obj_add_event_cb(b, onKey, LV_EVENT_CLICKED, NULL);
    } else {
      padLabel(b, LV_SYMBOL_BACKSPACE, UI_COL_INK_2, UI_FONT_BODY);
      lv_obj_add_event_cb(b, onBackspace, LV_EVENT_CLICKED, NULL);
    }
  }
}

static void buildAnswers() {
  // The main action starts level with the second row of keys, so the hint
  // above it has room to breathe; Cancel keeps the bottom.
  const int keys_h = 4 * s_geo->key_h + 3 * NP_GAP;
  const int done_y = s_geo->keys_y + s_geo->key_h + NP_GAP;
  const int cancel_y = s_geo->keys_y + keys_h - NP_CANCEL_H;
  const int done_h = cancel_y - NP_GAP - done_y;
  lv_obj_t *ok = padButton(s_root, NP_COL_X, done_y, s_geo->col_w, done_h,
                           UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  padLabel(ok, s_spec.primary, UI_COL_INK, UI_FONT_BODY);
  uiBtnRole(ok, BTN_CONFIRM);
  lv_obj_add_event_cb(ok, onDone, LV_EVENT_CLICKED, NULL);

  // In the popup the way out leads back to the step before, not out of it.
  lv_obj_t *no = padButton(s_root, NP_COL_X, cancel_y, s_geo->col_w, NP_CANCEL_H,
                           UI_COL_ROW, UI_COL_ROW_PRESS_FILL);
  padLabel(no, T(s_spec.popup ? STR_BACK : STR_CANCEL), UI_COL_INK_2, UI_FONT_SMALL);
  if (s_spec.popup) styleLeaveButton(no, LV_SYMBOL_LEFT);
  else              styleLeaveButton(no);
  lv_obj_add_event_cb(no, onLeave, LV_EVENT_CLICKED, NULL);
}

void showNumPad(const NumPadSpec &spec) {
  logSDf("SHOW: NumPad '%s'", spec.title ? spec.title : "");
  numPadClose();
  s_spec = spec;
  snprintf(s_title, sizeof(s_title), "%s", spec.title ? spec.title : "");
  snprintf(s_hint_text, sizeof(s_hint_text), "%s", spec.hint ? spec.hint : "");
  snprintf(s_unit, sizeof(s_unit), "%s", spec.unit ? spec.unit : "");
  snprintf(s_primary, sizeof(s_primary), "%s", spec.primary ? spec.primary : "");
  s_spec.title = s_title;
  s_spec.hint = s_hint_text;
  s_spec.unit = s_unit;
  s_spec.primary = s_primary;
  snprintf(s_input, sizeof(s_input), "%s", spec.initial ? spec.initial : "");
  s_fresh = s_input[0] != '\0';
  if (spec.popup) buildPopupFrame();
  else            buildScreenFrame();
  buildField();
  buildKeys();
  buildAnswers();
  lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
  // The pad is built over a screen that stays, hidden: this line shows what
  // the two cost together at their peak (verbose log only).
  logLvMem("numpad/post", 0);
}
