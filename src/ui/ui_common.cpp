#include "ui_common.h"
#include "navigation.h"

#include <cstdio>
#include <cstring>

#include "hardware/lvgl_mem.h"
#include "hardware/sd_logger.h"
#include <esp_heap_caps.h>
#include "app/deferred_actions.h"
#include "ams_assign_popup.h"
#include "ams_detail_popup.h"
#include "confirm_popup.h"
#include "info_popup.h"
#include "second_tag_popup.h"
#include "spool_flow.h"
#include "tag_write_popup.h"
#include "tare_entry.h"
#include "tare_missing_popup.h"
#include "services/backend.h"
#include "services/filaman_api.h"
#include "services/settings_registry.h"
#include "theme.h"
#include "lang.h"


bool uiModalWaiting() {
  // Every popup that asks something and has no countdown of its own to fall
  // back on, plus the AMS question, which does have one but whose buttons are
  // just as dead while the loop is busy.
  //
  // info_popup belongs in here too. It closes itself, but only when the button
  // is pressed - so it waits exactly like the rest, and the result of an erase
  // was the one nobody could dismiss.
  return isInfoPopupOpen()
      || isTagWritePopupOpen()
      || isConfirmPopupOpen()
      || isTareEntryOpen()
      || isTareMissingOpen()
      || isSpoolWeightScopeOpen()
      || isSpoolFlowIdInputOpen()
      || isSpoolFlowLinkEntryOpen()
      || isSecondTagPopupOpen()
      || isSpoolFlowTagMoveOpen()
      || isAmsAssignPopupOpen()
      || isAmsDetailPopupOpen();
}

// The hue a swatch is drawn in: its own, or glass for a filament that names
// none.
static uint32_t swatchHue(const SpoolColor& c) {
  return spoolColorNamesHue(c) ? c.rgb : SWATCH_GLASS_COLOR;
}

static uint8_t swatchFade(const SpoolColor& c) {
  return c.alpha == SPOOL_ALPHA_CLEAR ? SWATCH_FADE_CLEAR : SWATCH_FADE_TRANSLUCENT;
}

// a * mix + b * (255 - mix), per channel, as lv_color_mix() does it but on
// 24 bit values, so the result can be judged before it is drawn.
static uint32_t rgbMix(uint32_t a, uint32_t b, uint8_t mix) {
  uint32_t out = 0;
  for (int shift = 0; shift <= 16; shift += 8) {
    const uint32_t ca = (a >> shift) & 0xFF;
    const uint32_t cb = (b >> shift) & 0xFF;
    out |= ((ca * mix + cb * (255u - mix)) / 255u) << shift;
  }
  return out;
}

void swatchPaint(lv_obj_t* obj, const SpoolColor& c) {
  if (!obj) return;
  if (!spoolColorSeeThrough(c)) {
    lv_obj_set_style_bg_color(obj, lv_color_hex(c.valid ? c.rgb : SWATCH_FALLBACK_COLOR), 0);
    lv_obj_remove_local_style_prop(obj, LV_STYLE_BG_GRAD_DIR, LV_PART_MAIN);
    return;
  }
  const lv_color_t hue = lv_color_hex(swatchHue(c));
  lv_obj_set_style_bg_color(obj, hue, 0);
  lv_obj_set_style_bg_grad_color(obj,
    lv_color_mix(hue, lv_color_hex(UI_COL_GROUND), swatchFade(c)), 0);
  lv_obj_set_style_bg_grad_dir(obj, LV_GRAD_DIR_VER, 0);
}

void swatchPaintHex(lv_obj_t* obj, const char* hex) {
  SpoolColor c;
  spoolColorParse(hex, &c);
  swatchPaint(obj, c);
}

uint32_t swatchCenterRgb(const SpoolColor& c) {
  if (!c.valid) return SWATCH_FALLBACK_COLOR;
  if (!spoolColorSeeThrough(c)) return c.rgb;
  // Halfway down the fade: the hue weighted (255 + fade) / 2 against the ground.
  const uint8_t mix = (uint8_t)((255u + swatchFade(c)) / 2u);
  return rgbMix(swatchHue(c), UI_COL_GROUND, mix);
}


lv_obj_t* addInfoRow(lv_obj_t* parent, int y, const char* label,
                     lv_obj_t** out_label) {
  lv_obj_t *l = lv_label_create(parent);
  lv_label_set_text(l, label);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(l, INFO_ROW_LABEL_X, y + 3);
  if (out_label) *out_label = l;

  lv_obj_t *v = lv_label_create(parent);
  lv_label_set_text(v, "-");
  lv_obj_set_style_text_color(v, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(v, &lv_font_montserrat_ext_16, 0);
  lv_label_set_long_mode(v, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v, INFO_ROW_VALUE_W);
  lv_obj_set_pos(v, INFO_ROW_VALUE_X, y);
  return v;
}

lv_obj_t* makeListBtn(lv_obj_t* list, const char* ico_sym, const char* title,
                      const char* sub, bool toggle_active,
                      lv_obj_t** out_help) {
  // The help button eats 30 px on the right, so the text has to give way.
  // Only when there is one - a row without help keeps its old width and its
  // old line breaks.
  const int text_w = out_help ? 290 : 320;
  lv_obj_t *btn = lv_btn_create(list);
  lv_obj_set_size(btn, 456, 64);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 10, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 1, 0);
  lv_obj_set_style_border_color(btn, toggle_active ? lv_color_hex(UI_COL_ACCENT) : lv_color_hex(UI_COL_ROW_PRESSED), 0);
  lv_obj_set_style_pad_all(btn, 0, 0);

  lv_obj_t *ico = lv_label_create(btn);
  lv_label_set_text(ico, ico_sym);
  lv_obj_set_style_text_color(ico, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(ico, &lv_font_montserrat_ext_20, 0);
  lv_obj_align(ico, LV_ALIGN_LEFT_MID, 14, 0);

  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, title);
  lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_INK), 0);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_width(lbl, text_w);
  lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 52, sub && strlen(sub) > 0 ? -10 : 0);

  if (sub && strlen(sub) > 0) {
    lv_obj_t *slbl = lv_label_create(btn);
    lv_label_set_text(slbl, sub);
    lv_obj_set_style_text_color(slbl, toggle_active ? lv_color_hex(UI_COL_ACCENT) : lv_color_hex(UI_COL_CAPTION), 0);
    lv_obj_set_style_text_font(slbl, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_width(slbl, text_w);
    lv_obj_align(slbl, LV_ALIGN_LEFT_MID, 52, 12);
  }

  // Built BEFORE the arrow on purpose. Three call sites reach for the arrow
  // with lv_obj_get_child(btn, -1) to turn it into ON/OFF; appending here
  // instead would hand them this button and the toggles would lose their
  // state display.
  //
  // A circled ASCII "?" rather than an icon: FontAwesome's question-circle is
  // in none of the 23 generated fonts and adding it would mean regenerating
  // all of them, while 0x20-0x7F is in every one. The web UI already draws its
  // help trigger exactly like this, so the two now match.
  if (out_help) {
    lv_obj_t *help = lv_btn_create(btn);
    lv_obj_set_size(help, 34, 34);
    lv_obj_align(help, LV_ALIGN_RIGHT_MID, -56, 0);
    lv_obj_set_style_bg_opa(help, LV_OPA_TRANSP, 0);
    lv_obj_set_style_bg_color(help, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
    lv_obj_set_style_bg_opa(help, LV_OPA_COVER, LV_STATE_PRESSED);
    lv_obj_set_style_border_color(help, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_border_width(help, 1, 0);
    lv_obj_set_style_radius(help, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_shadow_width(help, 0, 0);
    lv_obj_set_style_pad_all(help, 0, 0);
    // Below the 44 px touch minimum by design - a circle that big crowds the
    // row. The hit area is widened instead, which costs nothing visually.
    lv_obj_set_ext_click_area(help, 6);
    lv_obj_t *q = lv_label_create(help);
    lv_label_set_text(q, "?");
    lv_obj_set_style_text_color(q, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_text_font(q, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(q, LV_ALIGN_CENTER, 0, 0);
    *out_help = help;
  }

  lv_obj_t *arr = lv_label_create(btn);
  lv_label_set_text(arr, LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_color(arr, lv_color_hex(UI_COL_INK_FAINT), 0);
  lv_obj_set_style_text_font(arr, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(arr, LV_ALIGN_RIGHT_MID, -14, 0);
  // Bounded, because callers overwrite this with words. Without a width the
  // label is LV_SIZE_CONTENT pinned to the right edge, so it grows leftwards
  // and walks straight through the help circle - which sits 42 px away. The
  // text stays right aligned inside the box, so every existing row with its
  // ON/OFF or symbol renders exactly as before.
  lv_obj_set_width(arr, out_help ? 42 : 120);
  lv_obj_set_style_text_align(arr, LV_TEXT_ALIGN_RIGHT, 0);
  lv_label_set_long_mode(arr, LV_LABEL_LONG_DOT);
  return btn;
}

void markListBtnChosen(lv_obj_t* btn, bool active) {
  lv_obj_t* arr_lbl = lv_obj_get_child(btn, -1);
  if (!arr_lbl) return;
  lv_label_set_text(arr_lbl, active ? LV_SYMBOL_OK : "");
  lv_obj_set_style_text_color(arr_lbl, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(arr_lbl, UI_FONT_BODY, 0);
}

void addBackButton(lv_obj_t *parent, lv_event_cb_t cb) {
  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, 44, 44);
  lv_obj_align(btn, LV_ALIGN_TOP_LEFT, 4, 2);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_center(lbl);
}

lv_obj_t* addCloseButton(lv_obj_t *parent) {
  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, 44, 44);
  lv_obj_align(btn, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_BAD_BG), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_BAD_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_BAD_TEXT), 0);
  lv_obj_center(lbl);
  return btn;
}

void uiSecondaryFill(lv_obj_t *btn) {
  if (uiThemeIsDark()) {
    lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_LINE), 0);
    return;
  }
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_border_width(btn, 1, 0);
  lv_obj_set_style_border_color(btn, lv_color_hex(UI_COL_ROW_PRESSED), 0);
  // Under the finger a shade darker than the row, not the dark frame colour
  // the callers set for the dark palettes: on a light one that flashed black.
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
}

void uiCountdownFillSet(lv_obj_t *fill, lv_coord_t full_w, lv_coord_t *drawn_w,
                        uint32_t remaining_ms, uint32_t total_ms) {
  if (!fill || total_ms == 0) return;
  if (remaining_ms > total_ms) remaining_ms = total_ms;
  const lv_coord_t w = (lv_coord_t)((uint64_t)full_w * remaining_ms / total_ms);
  if (w == *drawn_w) return;
  *drawn_w = w;
  lv_obj_set_width(fill, w);
  lv_obj_set_x(fill, full_w - w);
}

bool uiMainScreenCovered() {
  lv_obj_t* const layers[] = { lv_scr_act(), lv_layer_top() };
  for (lv_obj_t* layer : layers) {
    const uint32_t n = lv_obj_get_child_cnt(layer);
    for (uint32_t i = 0; i < n; i++) {
      lv_obj_t* o = lv_obj_get_child(layer, i);
      if (lv_obj_has_flag(o, LV_OBJ_FLAG_HIDDEN)) continue;
      if (lv_obj_get_width(o) >= LV_HOR_RES && lv_obj_get_height(o) >= LV_VER_RES) return true;
    }
  }
  return false;
}

void buildSubHeader(lv_obj_t *parent, const char *title,
                    lv_event_cb_t back_cb, const char *back_hint) {
  (void)back_hint;
  addBackButton(parent, back_cb);

  lv_obj_t *lbl_title = lv_label_create(parent);
  lv_label_set_text(lbl_title, title);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

  addCloseButton(parent);
}

void logLvMem(const char* tag, int rows) {
  if (!sd_verbose) return;
  const LvMemStats m = lvMemStats();
  logSDf("[verbose] lvmem %s rows=%d free=%u used=%u%% int=%u ps=%u blocks=%u heap=%u",
    tag, rows, (unsigned)(LVGL_MEM_INTERNAL_BUDGET - m.int_used), (unsigned)m.used_pct,
    (unsigned)m.int_used, (unsigned)m.ps_used, (unsigned)m.blocks,
    (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
}

bool lvPoolHasRoomForRow() {
  // Fragmentation, the second thing the old pool check watched, is the heap's
  // business now: a row's blocks are small enough for any gap it has, and a
  // block that finds none goes to PSRAM instead of failing.
  return lvMemInternalRoom(LV_ROW_RESERVE_BYTES);
}

int filamanStatusStrId(int status_id) {
  switch (status_id) {
    case FILAMAN_STATUS_NEW:      return STR_STATUS_NEW;
    case FILAMAN_STATUS_OPENED:   return STR_STATUS_OPENED;
    case FILAMAN_STATUS_DRYING:   return STR_STATUS_DRYING;
    case FILAMAN_STATUS_ACTIVE:   return STR_STATUS_ACTIVE;
    case FILAMAN_STATUS_EMPTY:    return STR_STATUS_EMPTY;
    case FILAMAN_STATUS_ARCHIVED: return STR_ARCHIVED;
    default:                      return STR_STATUS_UNKNOWN;
  }
}

uint32_t filamanStatusColor(int status_id) {
  switch (status_id) {
    case FILAMAN_STATUS_NEW:      return UI_COL_VALUE_BLUE;
    case FILAMAN_STATUS_OPENED:   return UI_COL_GOOD;
    case FILAMAN_STATUS_DRYING:   return UI_COL_WARN;
    case FILAMAN_STATUS_ACTIVE:   return UI_COL_GOOD;
    case FILAMAN_STATUS_EMPTY:    return UI_COL_BAD;
    case FILAMAN_STATUS_ARCHIVED: return UI_COL_ARCHIVED;
    default:                      return UI_COL_CAPTION;
  }
}

lv_obj_t* addHeaderHelp(lv_obj_t *scr, int title_id, int text_id) {
  lv_obj_t *help = lv_btn_create(scr);
  lv_obj_set_size(help, 34, 34);
  lv_obj_set_pos(help, 386, 5);
  lv_obj_set_style_bg_opa(help, LV_OPA_TRANSP, 0);
  lv_obj_set_style_bg_color(help, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_bg_opa(help, LV_OPA_COVER, LV_STATE_PRESSED);
  lv_obj_set_style_border_color(help, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_border_width(help, 1, 0);
  lv_obj_set_style_radius(help, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_shadow_width(help, 0, 0);
  lv_obj_set_style_pad_all(help, 0, 0);
  // Below the 44 px touch minimum by design, like the row help: the hit area
  // is widened instead.
  lv_obj_set_ext_click_area(help, 6);
  lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                      INFO_POPUP_ARG(title_id, text_id));
  lv_obj_t *q = lv_label_create(help);
  lv_label_set_text(q, "?");
  lv_obj_set_style_text_color(q, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(q, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(q, LV_ALIGN_CENTER, 0, 0);
  return help;
}

void releaseScreen(lv_obj_t **scr) {
  if (!scr || !*scr) return;
  // Hidden first: the object lives until the next timer pass, and a released
  // screen must take no tap and paint nothing in the meantime - the list it
  // rendered from may be freed by the line after this call.
  lv_obj_add_flag(*scr, LV_OBJ_FLAG_HIDDEN);
  lv_obj_del_async(*scr);
  *scr = nullptr;
}

lv_obj_t* buildOverlayScreen() {
  // One reading per screen built, taken before anything is allocated for it.
  // Every overlay screen in the firmware comes through here, so the sequence
  // of these lines is the pool's trend across a navigation session - which is
  // the shape the problem has: not one screen that is too expensive, but free
  // memory that does not come back. Read it next to the "BUILD: xScreen" line
  // the caller logs immediately before.
  logLvMem("screen", 0);

  lv_obj_t *scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr, 480, 320);
  lv_obj_set_pos(scr, 0, 0);
  lv_obj_add_flag(scr, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr, 0, 0);
  lv_obj_set_style_border_width(scr, 0, 0);
  lv_obj_set_style_pad_all(scr, 0, 0);
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr, lv_color_hex(UI_COL_GROUND), 0);
  return scr;
}


// ---------------------------------------------------------------------------
//  Settings rows, built from the registry
// ---------------------------------------------------------------------------

// The list body every settings screen uses. These fourteen lines stood word
// for word in seven files, each with the same warning comment attached.
lv_obj_t* buildOptionList(lv_obj_t *parent) {
  lv_obj_t *list = lv_obj_create(parent);
  lv_obj_set_size(list, 480, 263);
  lv_obj_set_pos(list, 0, 57);
  lv_obj_set_style_bg_opa(list, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_left(list, 12, 0);
  lv_obj_set_style_pad_right(list, 12, 0);
  lv_obj_set_style_pad_top(list, 6, 0);
  lv_obj_set_style_pad_bottom(list, 6, 0);
  lv_obj_set_style_pad_row(list, 6, 0);
  // makeListBtn() never positions its button, it relies on the parent's
  // layout. Without a flex flow every entry lands on the content origin and
  // only the last one added is visible.
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_clear_flag(list, LV_OBJ_FLAG_SCROLL_ELASTIC);
  return list;
}

// Asks for the options screen of whichever backend is active to be rebuilt.
// Through the pending flag rather than by deleting here: this runs inside the
// callback of a button on the very screen that would be deleted, and the flag
// path goes through releaseScreen(), which uses lv_obj_del_async(). The hand
// written toggles this replaces called lv_obj_del() straight from the callback
// - the one thing the project's own rules say never to do.
static void requestOptionsRebuild() {
  if (backendIsFilaMan())       show_filaman_options_pending  = true;
  else if (backendIsBamBuddy()) show_bambuddy_options_pending = true;
  else                          show_spoolman_options_pending = true;
}

static void settingRowClicked(lv_event_t *e) {
  const SettingDesc *s =
    (const SettingDesc *)lv_obj_get_user_data(lv_event_get_target(e));
  if (!s) return;

  // A row that leads somewhere hands over instead of changing anything. The
  // screens behind these carry logic a table cannot hold - a create assistant,
  // a numeric window, a reason why one choice is unavailable.
  if (s->opens != OPEN_NONE) {
    switch (s->opens) {
      case OPEN_SP_EXTRA_FIELDS: show_extra_fields_pending    = true; break;
      case OPEN_FLM_FIELDS:      show_filaman_fields_pending  = true; break;
      case OPEN_AMS_ASSIGN:      show_ams_assign_pending      = true; break;
      case OPEN_BB_DRIED:        show_bambuddy_dried_pending  = true; break;
      case OPEN_TAG_COMP:        show_tag_comp_pending        = true; break;
      default: break;
    }
    logSDf("BTN: Options -> %s", s->id);
    return;
  }

  if (s->kind != SET_BOOL) return;
  const uint8_t now = settingGet(*s);
  settingSet(*s, now ? 0 : 1);
  logSDf("BTN: Options -> %s %s", s->id, now ? "OFF" : "ON");
  requestOptionsRebuild();
}

lv_obj_t* addSettingRow(lv_obj_t *list, const SettingDesc &s) {
  char buf_t[40];
  copyT(buf_t, sizeof(buf_t), (StringID)s.str_name);

  char buf_s[64];
  settingSubtitle(s, buf_s, sizeof(buf_s));

  // A switch shows its own state. Anything else is plain, except the AMS row,
  // which is not a switch but should still read as active while a mode is set.
  const bool active = (s.kind == SET_BOOL) ? (settingGet(s) != 0)
                                           : (s.active_if_set && settingGet(s) != 0);

  lv_obj_t *help = nullptr;
  lv_obj_t *btn = makeListBtn(list, s.icon, buf_t, buf_s, active,
                              s.str_info ? &help : nullptr);
  if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                INFO_POPUP_ARG(s.str_name, s.str_info));

  // Last child is the arrow, which a switch turns into ON/OFF. makeListBtn()
  // builds the help button before the arrow on purpose, so this still finds
  // the arrow on a row that has both.
  if (s.kind == SET_BOOL) {
    lv_obj_t *arr = lv_obj_get_child(btn, -1);
    if (arr) {
      char buf_v[8];
      copyT(buf_v, sizeof(buf_v), active ? STR_ON : STR_OFF);
      lv_label_set_text(arr, buf_v);
      lv_obj_set_style_text_color(arr,
        lv_color_hex(active ? UI_COL_ACCENT : UI_COL_CAPTION), 0);
      lv_obj_set_style_text_font(arr, &lv_font_montserrat_ext_14, 0);
    }
  }

  // The descriptor lives in ROM, so the pointer stays valid for as long as the
  // row does and nothing has to be freed with it.
  lv_obj_set_user_data(btn, (void *)&s);
  lv_obj_add_event_cb(btn, settingRowClicked, LV_EVENT_CLICKED, NULL);
  return btn;
}

// One screen's worth of rows: everything in the table that belongs to this
// backend and applies right now, in table order.
void addSettingRows(lv_obj_t *list) {
  int rows = 0;
  for (size_t i = 0; i < SETTINGS_COUNT; i++) {
    if (!settingVisible(SETTINGS[i])) continue;
    addSettingRow(list, SETTINGS[i]);
    rows++;
  }
  // What the rows themselves cost, against the reading buildOverlayScreen()
  // took a moment earlier. The difference is one screen's worth of rows.
  logLvMem("options", rows);
}

lv_obj_t* labelOneLine(lv_obj_t* parent, const char* text, const lv_font_t* font, int max_w) {
  lv_obj_t* l = lv_label_create(parent);
  lv_obj_set_style_text_font(l, font, 0);
  lv_label_set_text(l, text);
  lv_point_t size;
  lv_txt_get_size(&size, text, font, 0, 0, LV_COORD_MAX, LV_TEXT_FLAG_NONE);
  lv_obj_set_size(l, LV_MIN(size.x, max_w), lv_font_get_line_height(font));
  lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
  return l;
}

lv_obj_t* padButton(lv_obj_t* parent, int x, int y, int w, int h, uint32_t bg, uint32_t bg_pressed) {
  lv_obj_t* b = lv_btn_create(parent);
  lv_obj_set_size(b, w, h);
  lv_obj_set_pos(b, x, y);
  lv_obj_set_style_bg_color(b, lv_color_hex(bg), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(bg_pressed), LV_STATE_PRESSED);
  lv_obj_set_style_radius(b, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(UI_COL_LINE_SOFT), 0);
  return b;
}

lv_obj_t* uiPopupBox(lv_obj_t** slot, int w, int h) {
  releaseScreen(slot);
  lv_obj_t* scrim = lv_obj_create(lv_scr_act());
  *slot = scrim;
  lv_obj_set_size(scrim, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(scrim, 0, 0);
  lv_obj_set_style_bg_color(scrim, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(scrim, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(scrim, 0, 0);
  lv_obj_set_style_radius(scrim, 0, 0);
  lv_obj_set_style_pad_all(scrim, 0, 0);
  lv_obj_clear_flag(scrim, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t* box = lv_obj_create(scrim);
  lv_obj_set_size(box, w, h);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(UI_COL_POPUP_BORDER), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  return box;
}

lv_obj_t* padLabel(lv_obj_t* btn, const char* text, uint32_t col, const lv_font_t* font) {
  lv_obj_t* l = lv_label_create(btn);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_color(l, lv_color_hex(col), 0);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(l);
  return l;
}

lv_obj_t* uiIconDisc(lv_obj_t* parent, const lv_img_dsc_t* icon, int diameter,
                     uint32_t bg, uint32_t ink) {
  lv_obj_t* disc = lv_obj_create(parent);
  lv_obj_remove_style_all(disc);
  lv_obj_set_size(disc, diameter, diameter);
  lv_obj_set_style_radius(disc, LV_RADIUS_CIRCLE, 0);
  lv_obj_set_style_bg_color(disc, lv_color_hex(bg), 0);
  lv_obj_set_style_bg_opa(disc, LV_OPA_COVER, 0);
  lv_obj_clear_flag(disc, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_flag(disc, LV_OBJ_FLAG_EVENT_BUBBLE);
  lv_obj_t* img = lv_img_create(disc);
  lv_img_set_src(img, icon);
  lv_obj_set_style_img_recolor(img, lv_color_hex(ink), 0);
  lv_obj_set_style_img_recolor_opa(img, LV_OPA_COVER, 0);
  lv_obj_center(img);
  return disc;
}

void spoolStartText(const SpoolStart& s, bool tare_inherited, char* out, size_t out_size) {
  if (s.verdict == START_NOT_WEIGHED) {
    snprintf(out, out_size, T(STR_TAGNEW_W_NOT), s.label_g);
  } else if (s.verdict == START_NO_TARE) {
    snprintf(out, out_size, T(STR_TAGNEW_W_NO_TARE), s.label_g);
  } else if (s.verdict == START_OVER && tare_inherited) {
    snprintf(out, out_size, T(STR_TAGNEW_W_OVER_TARE), s.net_g, s.tare_g);
  } else if (s.verdict == START_OVER) {
    snprintf(out, out_size, T(STR_TAGNEW_W_OVER), s.net_g, s.label_g);
  } else if (s.verdict == START_FULL && s.initial_g != s.label_g) {
    snprintf(out, out_size, T(STR_TAGNEW_W_FULL), s.remaining_g);
  } else {
    // Used, or full on a default core: the label stays the full weight.
    snprintf(out, out_size, T(STR_TAGNEW_W_OF), s.remaining_g, s.label_g);
  }
}

void listBtnTone(lv_obj_t* btn, ListTone tone) {
  if (tone == TONE_PLAIN) return;
  // Amber is the same one the status bar and the web UI already warn in,
  // red the same one the reset dialog uses, so neither introduces a colour.
  const uint32_t border  = (tone == TONE_DANGER) ? UI_COL_BAD_BG_PRESSED : UI_COL_CAUTION_BG;
  const uint32_t bg      = (tone == TONE_DANGER) ? UI_COL_DANGER_ROW : UI_COL_CAUTION_ROW;
  const uint32_t pressed = (tone == TONE_DANGER) ? UI_COL_BAD_BG : UI_COL_AMBER_LINE;
  const uint32_t text    = (tone == TONE_DANGER) ? UI_COL_DANGER_TEXT : UI_COL_WARN;
  lv_obj_set_style_border_color(btn, lv_color_hex(border), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(bg), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(pressed), LV_STATE_PRESSED);
  // Child 0 is the icon, child 1 the title. Both take the tone so the row
  // reads as a warning before the text is read.
  lv_obj_t *ico_lbl = lv_obj_get_child(btn, 0);
  lv_obj_t *ttl_lbl = lv_obj_get_child(btn, 1);
  if (ico_lbl) lv_obj_set_style_text_color(ico_lbl, lv_color_hex(text), 0);
  if (ttl_lbl) lv_obj_set_style_text_color(ttl_lbl, lv_color_hex(text), 0);
}

// red_pct of `red`, the rest of `base`.
static lv_color_t leaveMix(uint32_t red, uint32_t base, int red_pct) {
  return lv_color_mix(lv_color_hex(red), lv_color_hex(base), (uint8_t)(red_pct * 255 / 100));
}

void styleLeaveButton(lv_obj_t* btn, const char* icon) {
  if (!btn) return;
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn, UI_LEAVE_BORDER_W, 0);
  lv_obj_set_style_border_color(btn, leaveMix(UI_COL_BAD_TEXT, UI_COL_ROW, UI_LEAVE_BORDER_RED_PCT), 0);
  lv_obj_set_style_border_opa(btn, LV_OPA_COVER, 0);
  lv_obj_t* lbl = nullptr;
  for (uint32_t i = 0; i < lv_obj_get_child_cnt(btn) && !lbl; i++) {
    lv_obj_t* c = lv_obj_get_child(btn, i);
    if (lv_obj_check_type(c, &lv_label_class)) lbl = c;
  }
  if (!lbl) return;
  // LVGL 8.3 counts the recolour markup below when it shortens a line, so a
  // caption with room to spare came out as "x ..." (the entry tiles). Sized
  // to its text instead; the button clips one that really is too long.
  const lv_label_long_mode_t mode = lv_label_get_long_mode(lbl);
  if (mode == LV_LABEL_LONG_DOT || mode == LV_LABEL_LONG_SCROLL ||
      mode == LV_LABEL_LONG_SCROLL_CIRCULAR) {
    lv_label_set_long_mode(lbl, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(lbl, LV_SIZE_CONTENT);
  }
  // The icon in red through LVGL's recolour markup, the caption in the
  // label's own colour; one label, so the pair stays centred as before.
  char text[64];
  const lv_color_t ic = leaveMix(UI_COL_BAD_TEXT, UI_COL_INK_2, UI_LEAVE_ICON_RED_PCT);
  snprintf(text, sizeof(text), "#%06x %s#  %s", (unsigned)(lv_color_to32(ic) & 0xFFFFFFu), icon,
           lv_label_get_text(lbl));
  lv_label_set_recolor(lbl, true);
  lv_label_set_text(lbl, text);
  lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_INK_2), 0);
}
