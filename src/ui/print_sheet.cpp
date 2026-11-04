#include "ui/print_sheet.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <lvgl.h>

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "app/label_server.h"
#include "app/label_spool.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/label_layout.h"
#include "services/label_printer.h"
#include "services/label_render.h"
#include "services/label_thumb.h"
#include "services/device_name.h"
#include "ui/more_info_screen.h"
#include "ui/navigation.h"
#include "ui/printer_screen.h"
#include "ui/theme.h"
#include "ui_common.h"

// The sheet, 480 x 320, under the sub header: a row with the kind and the
// print button, the label on white paper, then the rows a scroll away.
#define PS_ROW_W          456   // what buildOptionList() leaves inside its padding
#define PS_TOP_H           56
#define PS_KIND_W         110
#define PS_GAP              8
#define PS_PRINT_W        (PS_ROW_W - 2 * PS_KIND_W - 2 * PS_GAP)
#define PS_PAPER_PAD        6
#define PS_THUMB_MAX_W    (PS_ROW_W - 2 * PS_PAPER_PAD)
// The first screen's room under the print row: the whole label shows without
// a scroll, scaled down with grey edges where it is larger (Nikolai, 21.10.2026).
#define PS_THUMB_MAX_H    176
#define PS_MSG_W          300
#define PS_MSG_H          120
#define PS_POLL_MS        500   // how often a server label still on its way is asked for

// What a tap asked for, carried out by the next loop pass.
enum SheetAction : uint8_t {
  PS_NONE, PS_KIND_SPOOL, PS_KIND_FILAMENT, PS_NEXT_PRESET, PS_TURN, PS_NEXT_MEDIA
};

static lv_obj_t* s_scr = nullptr;
static lv_obj_t* s_kind_btn[LABEL_KIND_COUNT] = {};
static lv_obj_t* s_img = nullptr;
static lv_obj_t* s_msg = nullptr;
static lv_obj_t* s_row_preset = nullptr;
static lv_obj_t* s_row_turn = nullptr;
static lv_obj_t* s_row_server = nullptr;
static lv_obj_t* s_sub_preset = nullptr;
static lv_obj_t* s_sub_turn = nullptr;
static lv_obj_t* s_sub_media = nullptr;
static lv_obj_t* s_sub_printer = nullptr;
// The picture LVGL draws: an 8-bit coverage map in PSRAM, owned here.
static lv_img_dsc_t s_dsc{};
static uint8_t* s_px = nullptr;
// Kept across openings: whoever printed a filament's label last likely does again.
static LabelKind s_kind = LABEL_KIND_SPOOL;
static SheetAction s_action = PS_NONE;
static bool s_waiting = false;       // a server label or the dates still on their way
static uint32_t s_poll_ms = 0;
// The back button's way out: the More info card the sheet was opened from,
// built a pass after the sheet is gone.
static bool s_reopen_more_info = false;

static int presetCaption(uint8_t preset) {
  static const int CAPTIONS[LABEL_PRESET_COUNT] = {
    STR_W_L_P_STANDARD, STR_W_L_P_COMPACT, STR_W_L_P_BIG_QR, STR_W_L_P_MATERIAL_BIG,
    STR_W_L_P_TEXT_ONLY, STR_W_L_P_BIG_ID, STR_W_L_P_BIG_ID_SIDE,
  };
  return CAPTIONS[preset < LABEL_PRESET_COUNT ? preset : LABEL_PRESET_STANDARD];
}

static bool serverLabel() { return s_kind == LABEL_KIND_SPOOL && labelServerInUse(); }

static void freePicture() {
  if (s_img) lv_img_set_src(s_img, nullptr);
  lv_img_cache_invalidate_src(&s_dsc);
  if (s_px) heap_caps_free(s_px);
  s_px = nullptr;
  s_dsc = lv_img_dsc_t{};
}

// The message in place of the picture: loading, or why there is none.
static void showMessage(const char* text) {
  freePicture();
  lv_obj_add_flag(s_img, LV_OBJ_FLAG_HIDDEN);
  lv_obj_clear_flag(s_msg, LV_OBJ_FLAG_HIDDEN);
  lv_label_set_text(s_msg, text);
}

static void showPicture(const LabelRaster& r, const LabelThumbSpec& spec) {
  uint16_t w = 0, h = 0;
  labelThumbSize(r, spec, &w, &h);
  freePicture();
  s_px = w && h ? (uint8_t*)heap_caps_malloc(size_t(w) * h, MALLOC_CAP_SPIRAM) : nullptr;
  if (!s_px) { logSD("Print sheet: no PSRAM for the preview"); showMessage(T(STR_W_L_PREVIEW_FAIL)); return; }
  labelThumbFill(r, spec, w, h, s_px);
  s_dsc.header.cf = LV_IMG_CF_ALPHA_8BIT;
  s_dsc.header.w = w;
  s_dsc.header.h = h;
  s_dsc.data_size = uint32_t(w) * h;
  s_dsc.data = s_px;
  lv_img_set_src(s_img, &s_dsc);
  lv_obj_clear_flag(s_img, LV_OBJ_FLAG_HIDDEN);
  lv_obj_add_flag(s_msg, LV_OBJ_FLAG_HIDDEN);
}

// The label FilaMan draws for the spool, once it is in; asked again later
// while it is on its way.
static void previewFromServer(const LabelPrinterConfig& c, int spool_id) {
  const LabelRaster* r = nullptr;
  const char* reason = "";
  switch (labelServerPreview(c, spool_id, &r, &reason)) {
    case LSP_READY:
      showPicture(*r, LabelThumbSpec{ 0, r->content_width, false, PS_THUMB_MAX_W, PS_THUMB_MAX_H });
      s_waiting = false;
      return;
    case LSP_LOADING:
      showMessage(T(STR_W_L_PREVIEW_LOADING));
      s_waiting = true;
      return;
    default:
      showMessage(reason[0] ? reason : T(STR_W_L_PREVIEW_FAIL));
      s_waiting = false;
  }
}

// The label as it will print, from the spool the More info card is about.
static void renderPreview() {
  SpoolLabelData spool{};
  if (!labelSpoolLast(&spool)) { showMessage(T(STR_PRN_ERR_NO_SPOOL)); return; }
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  if (serverLabel()) { previewFromServer(c, spool.id); return; }
  // The dates come a moment later; the picture is drawn again then.
  s_waiting = !labelSpoolDatesKnown();
  if (s_waiting) label_dates_pending = true;
  const LabelLayout layout = labelLayoutLoad(s_kind);
  LabelRaster r{};
  const bool ok = s_kind == LABEL_KIND_FILAMENT ? labelRenderFilament(c, layout, spool, &r)
                                               : labelRenderSpool(c, layout, spool, &r);
  if (ok) showPicture(r, LabelThumbSpec{ labelPrinterContentX(c), r.content_width,
                                         labelLayoutOption(layout, LO_PORTRAIT) ||
                                             labelPrinterIsTape(c.model),
                                         PS_THUMB_MAX_W, PS_THUMB_MAX_H });
  else showMessage(T(STR_W_L_PREVIEW_FAIL));
  labelRasterFree(&r);
}

// The two kind buttons, the chosen one green, as on the backend screen.
static void styleKind(lv_obj_t* b, bool on) {
  lv_obj_set_style_bg_color(b, lv_color_hex(on ? UI_COL_PICKED_BG : UI_COL_SURFACE), 0);
  lv_obj_set_style_border_width(b, on ? 2 : 1, 0);
  lv_obj_set_style_border_color(b, lv_color_hex(on ? UI_COL_ACCENT : UI_COL_LINE_SOFT), 0);
  lv_obj_t* l = lv_obj_get_child(b, 0);
  if (l) lv_obj_set_style_text_color(l, lv_color_hex(on ? UI_COL_ACCENT : UI_COL_OFF_TEXT), 0);
}

// The rows that change our layout: the arrangement and upright or flat.
static void showLayoutRows(bool show) {
  lv_obj_t* const rows[] = { s_row_preset, s_row_turn };
  for (lv_obj_t* r : rows) {
    if (show) lv_obj_clear_flag(r, LV_OBJ_FLAG_HIDDEN);
    else lv_obj_add_flag(r, LV_OBJ_FLAG_HIDDEN);
  }
}

// Everything the sheet says, from what is saved now.
static void refresh() {
  if (!s_scr) return;
  for (int k = 0; k < LABEL_KIND_COUNT; k++) styleKind(s_kind_btn[k], k == s_kind);
  const bool server = serverLabel();
  const LabelLayout l = labelLayoutLoad(s_kind);
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  const LabelPrinterProfile& p = labelPrinterProfile(c.model);
  // FilaMan's preset has its own layout, and so has a tape printer: the rows
  // that change ours step aside.
  showLayoutRows(!server && !labelPrinterIsTape(c.model));
  if (server) lv_obj_clear_flag(s_row_server, LV_OBJ_FLAG_HIDDEN);
  else lv_obj_add_flag(s_row_server, LV_OBJ_FLAG_HIDDEN);
  lv_label_set_text(s_sub_preset, T(presetCaption(l.preset)));
  lv_label_set_text(s_sub_turn, T(labelLayoutOption(l, LO_PORTRAIT) ? STR_W_L_UPRIGHT : STR_W_L_FLAT));
  char buf[64];
  snprintf(buf, sizeof(buf), T(STR_PRN_MEDIA_FMT), (unsigned)c.media_width_mm,
           (unsigned)c.media_length_mm);
  lv_label_set_text(s_sub_media, buf);
  snprintf(buf, sizeof(buf), "%s %s  \xE2\x80\xA2  %u dpi", p.brand, p.name, (unsigned)p.dpi);
  lv_label_set_text(s_sub_printer, buf);
  renderPreview();
}

// What a tap parked: the layout of the kind on show, or the stock.
static void applyAction() {
  const SheetAction a = s_action;
  s_action = PS_NONE;
  if (a == PS_KIND_SPOOL || a == PS_KIND_FILAMENT) {
    s_kind = a == PS_KIND_FILAMENT ? LABEL_KIND_FILAMENT : LABEL_KIND_SPOOL;
    return;
  }
  if (a == PS_NEXT_MEDIA) {
    LabelPrinterConfig c = labelPrinterLoadConfig();
    labelPrinterNextMedia(c);
    if (!labelPrinterSaveConfig(c)) logSD("Print sheet: label stock NOT saved");
    return;
  }
  if (a != PS_NEXT_PRESET && a != PS_TURN) return;
  LabelLayout l = labelLayoutLoad(s_kind);
  if (a == PS_NEXT_PRESET) l.preset = (uint8_t)((l.preset + 1) % LABEL_PRESET_COUNT);
  else l.options ^= 1u << LO_PORTRAIT;
  if (!labelLayoutSave(l, s_kind)) logSD("Print sheet: layout NOT saved");
}

static void park(SheetAction a) {
  s_action = a;
  print_sheet_refresh_pending = true;
}

static lv_obj_t* kindButton(lv_obj_t* parent, lv_coord_t x, LabelKind kind, int caption) {
  lv_obj_t* b = lv_btn_create(parent);
  lv_obj_set_size(b, PS_KIND_W, PS_TOP_H);
  lv_obj_set_pos(b, x, 0);
  lv_obj_set_style_bg_color(b, lv_color_hex(UI_COL_PRESS_FILL), LV_STATE_PRESSED);
  lv_obj_set_style_radius(b, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(b, 0, 0);
  lv_obj_t* l = lv_label_create(b);
  lv_label_set_text(l, T(caption));
  lv_obj_set_style_text_font(l, UI_FONT_BODY, 0);
  lv_obj_center(l);
  lv_obj_add_event_cb(b, [](lv_event_t* e) {
    const bool fil = (intptr_t)lv_event_get_user_data(e) == LABEL_KIND_FILAMENT;
    logSD(fil ? "BTN: Print sheet -> filament" : "BTN: Print sheet -> spool");
    park(fil ? PS_KIND_FILAMENT : PS_KIND_SPOOL);
  }, LV_EVENT_CLICKED, (void*)(intptr_t)kind);
  return b;
}

// The kind on the left, the print button on the right: the one thing most
// visits are for stays where the finger lands first.
static void buildTopRow(lv_obj_t* list) {
  lv_obj_t* row = lv_obj_create(list);
  lv_obj_set_size(row, PS_ROW_W, PS_TOP_H);
  lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(row, 0, 0);
  lv_obj_set_style_pad_all(row, 0, 0);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
  s_kind_btn[LABEL_KIND_SPOOL] = kindButton(row, 0, LABEL_KIND_SPOOL, STR_W_L_KIND_SPOOL);
  s_kind_btn[LABEL_KIND_FILAMENT] =
      kindButton(row, PS_KIND_W + PS_GAP, LABEL_KIND_FILAMENT, STR_W_L_KIND_FILAMENT);
  lv_obj_t* go = lv_btn_create(row);
  lv_obj_set_size(go, PS_PRINT_W, PS_TOP_H);
  lv_obj_set_pos(go, PS_ROW_W - PS_PRINT_W, 0);
  lv_obj_set_style_bg_color(go, lv_color_hex(UI_COL_GO_BG), 0);
  lv_obj_set_style_bg_color(go, lv_color_hex(UI_COL_GO_BG_PRESSED), LV_STATE_PRESSED);
  lv_obj_set_style_radius(go, UI_RADIUS_ROW, 0);
  lv_obj_set_style_shadow_width(go, 0, 0);
  lv_obj_set_style_border_width(go, 1, 0);
  lv_obj_set_style_border_color(go, lv_color_hex(UI_COL_GO_BG_PRESSED), 0);
  lv_obj_t* l = lv_label_create(go);
  lv_label_set_text(l, T(STR_PS_PRINT));
  lv_obj_set_style_text_font(l, UI_FONT_HEADLINE, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_OK_TEXT_2), 0);
  lv_obj_center(l);
  lv_obj_add_event_cb(go, [](lv_event_t*) {
    logSD("BTN: Print sheet -> print");
    print_sheet_print_pending = true;
  }, LV_EVENT_CLICKED, NULL);
}

// The label on white, as it comes off the roll: black is the coverage map,
// recoloured, so a scaled-down picture keeps its strokes as grey.
static void buildPaper(lv_obj_t* list) {
  lv_obj_t* paper = lv_obj_create(list);
  lv_obj_set_size(paper, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
  lv_obj_set_style_bg_color(paper, lv_color_hex(UI_COL_QR_LIGHT), 0);
  lv_obj_set_style_border_width(paper, 0, 0);
  lv_obj_set_style_radius(paper, UI_RADIUS_INPUT, 0);
  lv_obj_set_style_pad_all(paper, PS_PAPER_PAD, 0);
  lv_obj_clear_flag(paper, LV_OBJ_FLAG_SCROLLABLE);
  s_img = lv_img_create(paper);
  lv_obj_set_style_img_recolor(s_img, lv_color_hex(UI_COL_QR_DARK), 0);
  lv_obj_set_style_img_recolor_opa(s_img, LV_OPA_COVER, 0);
  s_msg = lv_label_create(paper);
  lv_obj_set_size(s_msg, PS_MSG_W, PS_MSG_H);
  lv_label_set_long_mode(s_msg, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(s_msg, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_color(s_msg, lv_color_hex(UI_COL_QR_DARK), 0);
  lv_obj_set_style_text_font(s_msg, UI_FONT_BODY, 0);
  lv_obj_add_flag(s_msg, LV_OBJ_FLAG_HIDDEN);
}

// Under the rows: what the scale leaves to the browser, and where it is.
static void buildWebHint(lv_obj_t* list) {
  lv_obj_t* hint = lv_label_create(list);
  lv_obj_set_width(hint, PS_ROW_W);
  lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_color(hint, lv_color_hex(UI_COL_CAPTION), 0);
  lv_obj_set_style_text_font(hint, UI_FONT_SMALL, 0);
  lv_label_set_text(hint, T(STR_PS_MORE_WEB));
  char base[DEVICE_FQDN_MAX + 16];
  deviceBrowserUrl(base, sizeof(base));
  char url[DEVICE_FQDN_MAX + 24];
  snprintf(url, sizeof(url), "%s/label", base);
  lv_obj_t* addr = lv_label_create(list);
  lv_obj_set_width(addr, PS_ROW_W);
  lv_label_set_long_mode(addr, LV_LABEL_LONG_DOT);
  lv_obj_set_style_text_align(addr, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_color(addr, lv_color_hex(UI_COL_ACCENT), 0);
  lv_obj_set_style_text_font(addr, UI_FONT_BODY, 0);
  lv_label_set_text(addr, url);
}

// One settings row; hands back the label its value is shown in.
static lv_obj_t* settingRow(lv_obj_t* list, const char* sym, int title, SheetAction action,
                            lv_obj_t** row) {
  char buf_t[40];
  copyT(buf_t, sizeof(buf_t), title);
  // A placeholder, so the row gets its value line; refresh() fills it.
  lv_obj_t* btn = makeListBtn(list, sym, buf_t, " ");
  if (row) *row = btn;
  lv_obj_add_event_cb(btn, [](lv_event_t* e) {
    const SheetAction a = (SheetAction)(intptr_t)lv_event_get_user_data(e);
    logSDf("BTN: Print sheet -> row %d", (int)a);
    if (a == PS_NONE) print_sheet_printer_pending = true;
    else park(a);
  }, LV_EVENT_CLICKED, (void*)(intptr_t)action);
  return lv_obj_get_child(btn, 2);   // 0 the icon, 1 the title, 2 the value
}

static void buildSheet() {
  logSD("BUILD: PrintSheet");
  releaseScreen(&s_scr);
  s_scr = buildOverlayScreen();
  buildSubHeader(s_scr, T(STR_PRN_LABEL_PRINT), [](lv_event_t*) {
    logSD("BTN: Print sheet -> back");
    print_sheet_close_pending = true;
  });
  lv_obj_t* list = buildOptionList(s_scr);
  lv_obj_set_flex_align(list, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  buildTopRow(list);
  buildPaper(list);
  s_sub_preset = settingRow(list, LV_SYMBOL_LIST, STR_W_L_ARRANGE, PS_NEXT_PRESET, &s_row_preset);
  s_sub_turn = settingRow(list, LV_SYMBOL_REFRESH, STR_W_L_ORIENT, PS_TURN, &s_row_turn);
  s_sub_media = settingRow(list, LV_SYMBOL_IMAGE, STR_PRN_MEDIA, PS_NEXT_MEDIA, nullptr);
  s_sub_printer = settingRow(list, LV_SYMBOL_SETTINGS, STR_PRN_TITLE, PS_NONE, nullptr);
  // In place of the two layout rows while FilaMan draws the label: where
  // that layout is changed. No tap: it is a note.
  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_PS_SERVER);
    char buf_s[64]; copyT(buf_s, sizeof(buf_s), STR_PS_SERVER_SUB);
    s_row_server = makeListBtn(list, LV_SYMBOL_LIST, buf_t, buf_s);
    lv_obj_clear_flag(s_row_server, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t* arrow = lv_obj_get_child(s_row_server, -1);   // the chevron, built last
    if (arrow) lv_obj_add_flag(arrow, LV_OBJ_FLAG_HIDDEN);
    lv_obj_move_to_index(s_row_server, 2); }
  buildWebHint(list);
  refresh();
  lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_HIDDEN);
}

void closePrintSheet() {
  // The picture first, while the image still exists to let go of it; the
  // screen then goes at the end of this LVGL pass, whoever called.
  freePicture();
  releaseScreen(&s_scr);
  s_img = s_msg = nullptr;
  s_row_preset = s_row_turn = s_row_server = nullptr;
  s_sub_preset = s_sub_turn = s_sub_media = s_sub_printer = nullptr;
  s_kind_btn[LABEL_KIND_SPOOL] = s_kind_btn[LABEL_KIND_FILAMENT] = nullptr;
  s_waiting = false;
}

// The picture again once what it waited for may be in.
static void pollPreview() {
  if (!s_scr || !s_waiting || millis() - s_poll_ms < PS_POLL_MS) return;
  s_poll_ms = millis();
  if (serverLabel() || labelSpoolDatesKnown()) renderPreview();
}

void printSheetTick() {
  // The sheet was released at the end of the last pass; the card is large,
  // so the two never share the pool.
  if (s_reopen_more_info && !s_scr) {
    s_reopen_more_info = false;
    if (sm_found && sm_id > 0) showMoreInfoScreen();
  }
  if (show_print_sheet_pending) {
    show_print_sheet_pending = false;
    hideAllOverlays();
    buildSheet();
  }
  if (print_sheet_close_pending) {
    print_sheet_close_pending = false;
    closePrintSheet();
    s_reopen_more_info = true;
  }
  if (print_sheet_refresh_pending) {
    print_sheet_refresh_pending = false;
    applyAction();
    refresh();
  }
  if (print_sheet_print_pending) {
    print_sheet_print_pending = false;
    const LabelKind kind = s_kind;
    closePrintSheet();
    printerPrintLastLabel(kind);   // the spool the picture showed
  }
  if (print_sheet_printer_pending) {
    print_sheet_printer_pending = false;
    closePrintSheet();
    printerScreenFromSheet();
    show_printer_pending = true;
  }
  pollPreview();
}
