#include "ui/buttons.h"

#include "ui/theme.h"

// The edge of a destructive button: brighter than its fill, so the warning is
// seen before the caption is read, and unlike the dimmer red outline of the
// way out.
#define BTN_DANGER_BORDER_W        2
#define BTN_DANGER_BORDER_RED_PCT  70
#define BTN_NEUTRAL_BORDER_W       1

static lv_style_t s_frame[BTN_ROLE_COUNT];
static lv_style_t s_pressed[BTN_ROLE_COUNT];
static lv_style_t s_text[BTN_ROLE_COUNT];
static bool       s_ready = false;

lv_color_t uiMixRed(uint32_t red, uint32_t base, int red_pct) {
  return lv_color_mix(lv_color_hex(red), lv_color_hex(base), (uint8_t)(red_pct * 255 / 100));
}

static void initRole(BtnRole role, uint32_t fill, uint32_t pressed, lv_color_t ink) {
  lv_style_init(&s_frame[role]);
  lv_style_set_bg_color(&s_frame[role], lv_color_hex(fill));
  lv_style_set_bg_opa(&s_frame[role], LV_OPA_COVER);
  lv_style_set_border_width(&s_frame[role], 0);
  lv_style_set_shadow_width(&s_frame[role], 0);
  // Also on the button, so a label added after uiBtnRole() inherits it.
  lv_style_set_text_color(&s_frame[role], ink);
  lv_style_init(&s_pressed[role]);
  lv_style_set_bg_color(&s_pressed[role], lv_color_hex(pressed));
  lv_style_init(&s_text[role]);
  lv_style_set_text_color(&s_text[role], ink);
}

static void setBorder(BtnRole role, int width, lv_color_t colour) {
  lv_style_set_border_width(&s_frame[role], width);
  lv_style_set_border_color(&s_frame[role], colour);
  lv_style_set_border_opa(&s_frame[role], LV_OPA_COVER);
}

static void initNeutral() {
  // Dark: an outline on the surface it stands on, so it never outweighs the
  // green beside it. Light: the row fill with the row's border, as before.
  if (uiThemeIsDark()) {
    initRole(BTN_NEUTRAL, UI_COL_SURFACE, UI_COL_PRESS_FILL, lv_color_hex(UI_COL_INK_2));
    setBorder(BTN_NEUTRAL, BTN_NEUTRAL_BORDER_W, lv_color_hex(UI_COL_LINE));
    return;
  }
  initRole(BTN_NEUTRAL, UI_COL_ROW, UI_COL_ROW_PRESS_FILL, lv_color_hex(UI_COL_INK_2));
  setBorder(BTN_NEUTRAL, BTN_NEUTRAL_BORDER_W, lv_color_hex(UI_COL_ROW_PRESSED));
}

// Once, on the first button: the palette is chosen at boot and fixed until a
// restart, so the styles never need to follow it.
static void initStyles() {
  if (s_ready) return;
  initRole(BTN_CONFIRM, UI_COL_OK_BG, UI_COL_OK_BG_PRESSED, lv_color_hex(UI_COL_OK_TEXT));
  initRole(BTN_DANGER, UI_COL_BAD_BG, UI_COL_BAD_BG_PRESSED, lv_color_hex(UI_COL_BAD_TEXT));
  setBorder(BTN_DANGER, BTN_DANGER_BORDER_W,
            uiMixRed(UI_COL_BAD_TEXT, UI_COL_BAD_BG, BTN_DANGER_BORDER_RED_PCT));
  initNeutral();
  // The close X wears the way-out look of styleLeaveButton(), icon only.
  initRole(BTN_CLOSE, UI_COL_ROW, UI_COL_ROW_PRESS_FILL,
           uiMixRed(UI_COL_BAD_TEXT, UI_COL_INK_2, UI_LEAVE_ICON_RED_PCT));
  setBorder(BTN_CLOSE, UI_LEAVE_BORDER_W, uiMixRed(UI_COL_BAD_TEXT, UI_COL_ROW, UI_LEAVE_BORDER_RED_PCT));
  s_ready = true;
}

static void dropLocalColours(lv_obj_t* btn) {
  static const lv_style_prop_t PROPS[] = {
    LV_STYLE_BG_COLOR, LV_STYLE_BG_OPA, LV_STYLE_BORDER_WIDTH, LV_STYLE_BORDER_COLOR,
    LV_STYLE_BORDER_OPA, LV_STYLE_SHADOW_WIDTH,
  };
  for (lv_style_prop_t p : PROPS) {
    lv_obj_remove_local_style_prop(btn, p, LV_PART_MAIN | LV_STATE_DEFAULT);
    lv_obj_remove_local_style_prop(btn, p, LV_PART_MAIN | LV_STATE_PRESSED);
  }
}

// lv_obj_add_style() does not look for the style already being there, so a
// button that changes its role (or is given the same one twice) would pile
// them up. Every role's styles go first; then the one asked for is added.
static void dropRoleStyles(lv_obj_t* obj) {
  for (int r = 0; r < BTN_ROLE_COUNT; r++) {
    lv_obj_remove_style(obj, &s_frame[r], 0);
    lv_obj_remove_style(obj, &s_pressed[r], LV_STATE_PRESSED);
    lv_obj_remove_style(obj, &s_text[r], 0);
  }
}

void uiBtnRole(lv_obj_t* btn, BtnRole role) {
  if (!btn || role >= BTN_ROLE_COUNT) return;
  initStyles();
  dropLocalColours(btn);
  dropRoleStyles(btn);
  lv_obj_add_style(btn, &s_frame[role], 0);
  lv_obj_add_style(btn, &s_pressed[role], LV_STATE_PRESSED);
  const uint32_t n = lv_obj_get_child_cnt(btn);
  for (uint32_t i = 0; i < n; i++) {
    lv_obj_t* c = lv_obj_get_child(btn, i);
    if (!lv_obj_check_type(c, &lv_label_class)) continue;
    lv_obj_remove_local_style_prop(c, LV_STYLE_TEXT_COLOR, LV_PART_MAIN | LV_STATE_DEFAULT);
    dropRoleStyles(c);
    lv_obj_add_style(c, &s_text[role], 0);
  }
}
