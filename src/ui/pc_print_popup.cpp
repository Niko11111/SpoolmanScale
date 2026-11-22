#include "ui/pc_print_popup.h"

#include <Arduino.h>
#include <lvgl.h>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "hardware/sound.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/filaman_labels.h"
#include "services/server_reach.h"
#include "services/text_util.h"
#include "ui/theme.h"
#include "ui/ui_common.h"
// Last: backend_api.h brings ArduinoJson, whose templates have a parameter T.
#include "lang.h"

// The house card (UI_CARD_* in theme.h) for the answer; the question uses
// its height and answer row too, with the two kinds of label above that row.
#define PCP_TEXT_W        (UI_POPUP_W - UI_CARD_TEXT_PAD)
#define PCP_ROW_W         (UI_POPUP_W - 2 * UI_CARD_ROW_X)
#define PCP_GAP            8
#define PCP_KIND_W        ((PCP_ROW_W - PCP_GAP) / 2)
#define PCP_ASK_TITLE_Y   20
#define PCP_ASK_SUB_Y     56
#define PCP_KIND_Y        112
// While the request runs: one line, as short as the card can be.
#define PCP_BUSY_H        110
// Filing the request is one small POST; FilaMan answers it at once.
#define PCP_TIMEOUT_MS    5000
// FilaMan's reason, cut to the lines the card has room for above the button.
#define PCP_REASON_CUT    96

enum PcpAction : uint8_t { PCP_NONE = 0, PCP_SPOOL, PCP_FILAMENT, PCP_CLOSE };

static lv_obj_t* s_scr    = nullptr;
static PcpAction s_action = PCP_NONE;
// The spool the card was opened for, kept: a lookup that replaces sm_id
// meanwhile must not send another spool's label.
static int s_spool_id = 0, s_filament_id = 0;

void closePcPrintPopup() {
  releaseScreen(&s_scr);
  s_action = PCP_NONE;
}

static void onTap(lv_event_t* e) {
  s_action = (PcpAction)(intptr_t)lv_event_get_user_data(e);
  logSDf("BTN: PcPrint -> %d", (int)s_action);
}

// ------------------------------------------------------------
//  Building blocks
// ------------------------------------------------------------

static lv_obj_t* textLine(lv_obj_t* box, const char* text, const lv_font_t* font,
                          uint32_t color, int y) {
  lv_obj_t* l = lv_label_create(box);
  lv_label_set_text(l, text);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
  lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(l, PCP_TEXT_W);
  lv_obj_align(l, LV_ALIGN_TOP_MID, 0, y);
  return l;
}

// A button whose tap is parked for the loop; the look comes after.
static lv_obj_t* makeButton(lv_obj_t* box, int x, int y, int w, int text_id, PcpAction a) {
  lv_obj_t* b = lv_btn_create(box);
  lv_obj_set_size(b, w, UI_POPUP_BTN_H);
  lv_obj_set_pos(b, x, y);
  lv_obj_set_style_radius(b, UI_RADIUS_BTN, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_set_style_border_width(b, 0, 0);
  lv_obj_set_style_pad_all(b, 0, 0);
  lv_obj_clear_flag(b, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(b, onTap, LV_EVENT_CLICKED, (void*)(intptr_t)a);
  lv_obj_t* l = lv_label_create(b);
  lv_label_set_text(l, T(text_id));
  lv_obj_set_style_text_font(l, UI_FONT_TITLE, 0);
  lv_obj_center(l);
  return b;
}

static void setButtonInk(lv_obj_t* b, uint32_t color) {
  lv_obj_set_style_text_color(lv_obj_get_child(b, 0), lv_color_hex(color), 0);
}

// A kind of label, in the look of the header's print button. A filament the
// scale has no id for cannot be asked for: shown, so the card keeps its
// shape, but it takes no tap.
static void styleKind(lv_obj_t* b, bool enabled) {
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW), 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(b, 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(enabled ? UI_COL_ACCENT : UI_COL_LINE), 0);
  setButtonInk(b, enabled ? UI_COL_ACCENT : UI_COL_INK_SOFT);
  if (!enabled) lv_obj_clear_flag(b, LV_OBJ_FLAG_CLICKABLE);
}

// Cancel, and OK under a refusal: the print card's quiet button.
static void styleQuiet(lv_obj_t* b) {
  uiBtnRole(b, BTN_NEUTRAL);
}

static void styleGood(lv_obj_t* b) {
  uiBtnRole(b, BTN_CONFIRM);
}

// Each stage replaces the one before in the same place.
static lv_obj_t* buildFrame(int height, uint32_t border) {
  releaseScreen(&s_scr);
  s_scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(s_scr, LV_HOR_RES, LV_VER_RES);
  lv_obj_set_pos(s_scr, 0, 0);
  lv_obj_set_style_bg_color(s_scr, lv_color_hex(UI_COL_SCRIM), 0);
  lv_obj_set_style_bg_opa(s_scr, UI_OPA_SCRIM, 0);
  lv_obj_set_style_border_width(s_scr, 0, 0);
  lv_obj_set_style_radius(s_scr, 0, 0);
  lv_obj_set_style_pad_all(s_scr, 0, 0);
  lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_SCROLLABLE);
  // Swallows touches meant for the More info screen underneath.
  lv_obj_add_flag(s_scr, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t* box = lv_obj_create(s_scr);
  lv_obj_set_size(box, UI_POPUP_W, height);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(UI_COL_SURFACE), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(border), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, UI_RADIUS_BOX, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);
  return box;
}

// ------------------------------------------------------------
//  The three stages
// ------------------------------------------------------------

static void buildQuestion() {
  lv_obj_t* box = buildFrame(UI_CARD_H, UI_COL_POPUP_BORDER);
  textLine(box, T(STR_PCP_TITLE), UI_FONT_HEADLINE, UI_COL_INK, PCP_ASK_TITLE_Y);
  textLine(box, T(STR_PCP_SUB), UI_FONT_SMALL, UI_COL_INK_SOFT, PCP_ASK_SUB_Y);
  styleKind(makeButton(box, UI_CARD_ROW_X, PCP_KIND_Y, PCP_KIND_W, STR_PCP_SPOOL, PCP_SPOOL),
            true);
  styleKind(makeButton(box, UI_CARD_ROW_X + PCP_KIND_W + PCP_GAP, PCP_KIND_Y, PCP_KIND_W,
                       STR_PCP_FILAMENT, PCP_FILAMENT),
            s_filament_id > 0);
  styleLeaveButton(makeButton(box, UI_CARD_ROW_X, UI_CARD_ROW_Y, PCP_ROW_W, STR_CANCEL, PCP_CLOSE));
  logSDf("SHOW: PcPrint spool=%d filament=%d", s_spool_id, s_filament_id);
}

// Painted before the request blocks the loop, which draws nothing meanwhile.
static void showSending() {
  lv_obj_t* box = buildFrame(PCP_BUSY_H, UI_COL_POPUP_BORDER);
  lv_obj_t* l = textLine(box, T(STR_PCP_SENDING), UI_FONT_HEADLINE, UI_COL_INK, 0);
  lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
  lv_refr_now(NULL);
}

// No countdown on success, unlike the print card: the text is what to do
// next at the PC, and it has to stand until it was read.
static void showResult(bool ok, const char* text) {
  soundPlay(ok ? SND_PRINT_OK : SND_PRINT_FAIL);
  const uint32_t tone = ok ? UI_COL_GOOD : UI_COL_BAD;
  lv_obj_t* box = buildFrame(UI_CARD_H, tone);
  lv_obj_t* icon = lv_label_create(box);
  lv_label_set_text(icon, ok ? LV_SYMBOL_OK : LV_SYMBOL_WARNING);
  lv_obj_set_style_text_color(icon, lv_color_hex(tone), 0);
  lv_obj_set_style_text_font(icon, UI_FONT_ICON, 0);
  lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, UI_CARD_ICON_Y);
  textLine(box, T(ok ? STR_PCP_SENT_TITLE : STR_PCP_FAIL_TITLE), UI_FONT_HEADLINE, UI_COL_INK,
           UI_CARD_TITLE_Y);
  textLine(box, text, UI_FONT_BODY, UI_COL_INK_2, UI_CARD_TEXT_Y);
  lv_obj_t* b = makeButton(box, UI_CARD_ROW_X, UI_CARD_ROW_Y, PCP_ROW_W, STR_BTN_OK, PCP_CLOSE);
  if (ok) styleGood(b);
  else    styleQuiet(b);
}

static void send(bool filament) {
  const int id = filament ? s_filament_id : s_spool_id;
  if (id <= 0) return;
  showSending();
  char reason[FM_LABEL_REASON_LEN];
  const int code = serverReachNote(
    backendLabelPrintRequest(filament, id, reason, sizeof(reason), PCP_TIMEOUT_MS), true);
  if (serverReachIsNetworkFailure(code)) {
    // serverReachNote() opens its own popup for that; a card would say it twice.
    closePcPrintPopup();
    return;
  }
  if (code == 201) {
    showResult(true, T(STR_PCP_SENT_TEXT));
    return;
  }
  if (code == FM_LABEL_NO_PC_PRINT) {
    showResult(false, T(STR_PCP_NO_ROUTE));
    return;
  }
  if (!reason[0]) snprintf(reason, sizeof(reason), "HTTP %d", code);
  char cut[PCP_REASON_CUT + 1];
  utf8Cut(reason, PCP_REASON_CUT, cut, sizeof(cut));
  showResult(false, cut);
}

// ------------------------------------------------------------
//  The loop's part
// ------------------------------------------------------------

void pcPrintTick() {
  if (show_pc_print_pending) {
    show_pc_print_pending = false;
    if (sm_found && sm_id > 0 && backendIsFilaMan()) {
      s_spool_id = sm_id;
      s_filament_id = sm_filament_id;
      buildQuestion();
    }
  }
  if (!s_scr || s_action == PCP_NONE) return;
  const PcpAction a = s_action;
  s_action = PCP_NONE;
  if (a == PCP_CLOSE) closePcPrintPopup();
  else                send(a == PCP_FILAMENT);
}
