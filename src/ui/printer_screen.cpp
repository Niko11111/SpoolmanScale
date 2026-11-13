#include "printer_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "app/label_server.h"
#include "app/label_spool.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ble_service.h"
#include "services/label_layout.h"
#include "services/label_printer.h"
#include "services/label_render.h"
#include "services/fair_card.h"
#include "ui/choice_grid.h"
#include "ui/info_popup.h"
#include "ui/print_card.h"
#include "ui/print_sheet.h"
#include "ui/printer_offset_screen.h"
#include "ui/theme.h"
#include "ui_common.h"


static int s_last_test = -1;

// A label that needs no spool, the test label or the calibration page, under
// the print card; the verdict is kept for the browser's last-print line.
static void printFixedLabel(bool (*render)(const LabelPrinterConfig&, LabelRaster*),
                            const char* what) {
  printerOffsetFlush();
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  LabelPrintResult result = LP_NO_PRINTER;
  if (labelPrinterConfigured(c)) {
    if (!bleEnabled()) result = LP_BLE_OFF;
    else {
      printCardShow();
      LabelRaster raster{};
      if (!render(c, &raster)) result = LP_BAD_RASTER;
      else result = labelPrinterPrint(c, raster, printCardTick);
      labelRasterFree(&raster);
    }
  }
  logSDf("Printer: %s result=%d", what, (int)result);
  s_last_test = labelPrintResultString(result);
  printCardResult(result);
}
int printerLastTestResult() { return s_last_test; }

static int s_last_label = -1;
int printerLastLabelResult() { return s_last_label; }

// Where the back button leads: the print sheet, when that opened the screen.
static bool s_back_to_sheet = false;
void printerScreenFromSheet() { s_back_to_sheet = true; }

// The spool whose server label failed, for the card's "own layout" answer.
static SpoolLabelData s_own_layout_spool{};

// The raster of a spool's label: the FilaMan preset the editor chose, or the
// saved template. The scale's own needs the dates first; a slow backend only
// costs the label its date. The server draws its label with what it holds.
// The filament's label is always the scale's own; it wants the temperatures.
static LabelPrintResult spoolRaster(const LabelPrinterConfig& c, SpoolLabelData& spool,
                                    bool server, LabelKind kind, LabelRaster* raster) {
  if (server)
    return labelServerPrintRaster(c, spool.id, raster, printCardTick) == 200 ? LP_OK
                                                                             : LP_SERVER_LABEL;
  labelSpoolFetchDates(&spool);
  const bool ok = kind == LABEL_KIND_FILAMENT
      ? labelRenderFilament(c, labelLayoutLoad(LABEL_KIND_FILAMENT), spool, raster)
      : labelRenderSpool(c, labelLayoutLoad(), spool, raster);
  return ok ? LP_OK : LP_BAD_RASTER;
}

// A spool's label under the print card. The card comes first, so the wait
// for the dates or the server has something on screen. own_layout: the
// scale's template even where a FilaMan preset is chosen.
static void printSpoolLabel(SpoolLabelData spool, bool own_layout = false,
                            LabelKind kind = LABEL_KIND_SPOOL) {
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  const bool server = !own_layout && kind == LABEL_KIND_SPOOL && labelServerInUse();
  LabelPrintResult result = LP_NO_PRINTER;
  if (labelPrinterConfigured(c)) {
    if (!bleEnabled()) result = LP_BLE_OFF;
    else {
      printCardShow();
      LabelRaster raster{};
      result = spoolRaster(c, spool, server, kind, &raster);
      if (result == LP_OK) result = labelPrinterPrint(c, raster, printCardTick);
      labelRasterFree(&raster);
    }
  }
  logSDf("Printer: spool #%d %s label (%s) result=%d", spool.id,
         kind == LABEL_KIND_FILAMENT ? "filament" : "spool",
         server ? "FilaMan preset" : "own layout", (int)result);
  s_last_label = labelPrintResultString(result);
  // Never switched over unasked: the card offers the scale's own layout.
  if (result == LP_SERVER_LABEL) {
    s_own_layout_spool = spool;
    printCardResult(result, labelServerLastReason(), true);
  } else {
    printCardResult(result);
  }
}

void printerPrintPadLabel(LabelKind kind) {
  printerOffsetFlush();
  SpoolLabelData spool{};
  if (!labelSpoolFromScan(&spool)) {
    showInfoPopup(STR_PRN_TITLE, STR_PRN_ERR_NO_SPOOL, INFO_WARN);
    return;
  }
  printSpoolLabel(spool, false, kind);
}

// The label of the last spool scanned, on the pad or not: the print sheet
// and the browser's editor print what they showed.
void printerPrintLastLabel(LabelKind kind) {
  printerOffsetFlush();
  SpoolLabelData spool{};
  if (!labelSpoolLast(&spool)) {
    showInfoPopup(STR_PRN_TITLE, STR_PRN_ERR_NO_SPOOL, INFO_WARN);
    return;
  }
  printSpoolLabel(spool, false, kind);
}

void closePrinterScreen() {
  if (scr_printer) { lv_obj_del(scr_printer); scr_printer = nullptr; }
  closeChoiceGrid();
  // Closed by the X or by "Devices" as well as by its back button: the next
  // opening, from the Bluetooth screen, must lead back there.
  s_back_to_sheet = false;
}

static void rebuild();

// Saves a picked model or stock and redraws the rows that name it.
static void saveAndRebuild(const LabelPrinterConfig& c) {
  if (!labelPrinterSaveConfig(c)) showInfoPopup(STR_PRN_TITLE, STR_ERR_SAVE, INFO_WARN);
  rebuild();
}

static void modelPicked(int index) {
  if (index < 0 || index >= LABEL_PRINTER_MODEL_COUNT) return;
  LabelPrinterConfig c = labelPrinterLoadConfig();
  if (c.model == LABEL_PRINTER_MODELS[index]) return;
  c.model = LABEL_PRINTER_MODELS[index];
  logSDf("Printer: model -> %s", labelPrinterProfile(c.model).name);
  // A stock the new model cannot take falls back to its default in the save.
  saveAndRebuild(c);
}

// Every model in the table's order: recommended ones say so, experimental
// ones warn.
static void showModelPicker() {
  const LabelPrinterModel now = labelPrinterLoadConfig().model;
  ChoiceCard cards[CHOICE_GRID_MAX] = {};
  int current = -1;
  const int n = LABEL_PRINTER_MODEL_COUNT < CHOICE_GRID_MAX ? LABEL_PRINTER_MODEL_COUNT : CHOICE_GRID_MAX;
  for (int i = 0; i < n; i++) {
    const LabelPrinterProfile& p = labelPrinterProfile(LABEL_PRINTER_MODELS[i]);
    ChoiceCard& card = cards[i];
    card.caption = p.brand;
    snprintf(card.value, sizeof(card.value), "%s", p.name);
    card.enabled = true;
    if (labelPrinterRecommended(p.model)) {
      card.tag = CHOICE_TAG_GOOD; card.tag_text = STR_PRN_TAG_RECOMMENDED;
    } else if (p.experimental) {
      card.tag = CHOICE_TAG_WARN; card.tag_text = STR_PRN_TAG_EXPERIMENTAL;
    }
    if (p.model == now) current = i;
  }
  showChoiceGrid(STR_PRN_MODEL, cards, n, current, 3, modelPicked);
}

// The sizes offered in the grid, in its order; filled when it opens.
static LabelMediaSize s_media_offer[CHOICE_GRID_MAX];

static void mediaPicked(int index) {
  if (index < 0 || index >= CHOICE_GRID_MAX) return;
  LabelPrinterConfig c = labelPrinterLoadConfig();
  c.media_width_mm = s_media_offer[index].width_mm;
  c.media_length_mm = s_media_offer[index].length_mm;
  logSDf("Printer: label stock -> %ux%u mm", (unsigned)c.media_width_mm, (unsigned)c.media_length_mm);
  saveAndRebuild(c);
}

static void addMediaCard(ChoiceCard* cards, int* n, const LabelMediaSize& s, bool enabled) {
  if (*n >= CHOICE_GRID_MAX) return;
  ChoiceCard& card = cards[*n];
  card.caption = nullptr;   // the outline says enough
  snprintf(card.value, sizeof(card.value), T(STR_PRN_MEDIA_FMT),
           (unsigned)s.width_mm, (unsigned)s.length_mm);
  card.shape_w_mm = s.width_mm;
  card.shape_h_mm = s.length_mm;
  card.enabled = enabled;
  s_media_offer[*n] = s;
  (*n)++;
}

// The sizes the model takes, each drawn to scale, then the planned ones it
// would take, greyed.
static void showMediaPicker() {
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  ChoiceCard cards[CHOICE_GRID_MAX] = {};
  int n = 0, current = -1;
  for (int i = 0; i < LABEL_MEDIA_SIZE_COUNT; i++) {
    const LabelMediaSize& s = LABEL_MEDIA_SIZES[i];
    if (!labelPrinterTakesMedia(c.model, s.width_mm, s.length_mm)) continue;
    if (s.width_mm == c.media_width_mm && s.length_mm == c.media_length_mm) current = n;
    addMediaCard(cards, &n, s, true);
  }
  for (int i = 0; i < LABEL_MEDIA_PLANNED_COUNT && n < CHOICE_GRID_MAX; i++) {
    const LabelMediaSize& s = LABEL_MEDIA_SIZES_PLANNED[i];
    if (!labelPrinterTakesMedia(c.model, s.width_mm, s.length_mm)) continue;
    cards[n].tag = CHOICE_TAG_WARN;
    cards[n].tag_text = STR_PRN_MEDIA_NO_LAYOUT;
    addMediaCard(cards, &n, s, false);
  }
  // Two or three cards share the width rather than leaving a gap.
  showChoiceGrid(STR_PRN_MEDIA, cards, n, current, n < 3 ? n : 3, mediaPicked);
}

void buildPrinterScreen() {
  logSD("BUILD: PrinterScreen");
  releaseScreen(&scr_printer);
  scr_printer = buildOverlayScreen();
  buildSubHeader(scr_printer, T(STR_PRN_TITLE),
    [](lv_event_t *e){
      if (s_back_to_sheet) {
        logSD("BTN: Back -> Print sheet");
        s_back_to_sheet = false;
        show_print_sheet_pending = true;
        return;
      }
      logSD("BTN: Back -> Bluetooth");
      // Deferred and a rebuild: the Bluetooth screen's row names the printer.
      show_bluetooth_pending = true;
    });
  addHeaderHelp(scr_printer, STR_PRN_TITLE, STR_PRN_HELP);

  const LabelPrinterConfig c = labelPrinterLoadConfig();
  const LabelPrinterProfile& p = labelPrinterProfile(c.model);
  const bool have = labelPrinterConfigured(c);
  lv_obj_t *list = buildOptionList(scr_printer);

  // The device: what was picked on the device card, and the way there.
  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_PRN_DEVICE);
    char buf_s[64];
    if (!have) copyT(buf_s, sizeof(buf_s), STR_PRN_DEVICE_NONE);
    else snprintf(buf_s, sizeof(buf_s), "%s  %s", c.name[0] ? c.name : T(STR_BT_UNNAMED), c.address);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_BLUETOOTH, buf_t, buf_s, have);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Printer -> Devices");
      show_ble_devices_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // The model, picked from a grid.
  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_PRN_MODEL);
    char buf_s[64];
    if (p.experimental) snprintf(buf_s, sizeof(buf_s), "%s %s  %s", p.brand, p.name, T(STR_PRN_EXPERIMENTAL));
    else snprintf(buf_s, sizeof(buf_s), "%s %s", p.brand, p.name);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_SETTINGS, buf_t, buf_s);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Printer -> model grid");
      showModelPicker();
    }, LV_EVENT_CLICKED, NULL); }

  // The label stock, picked from a grid of what the model takes. On
  // thermal paper its "?" says what a dryer does to it.
  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_PRN_MEDIA);
    char buf_s[48];
    snprintf(buf_s, sizeof(buf_s), T(STR_PRN_MEDIA_FMT),
             (unsigned)c.media_width_mm, (unsigned)c.media_length_mm);
    lv_obj_t *help = nullptr;
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_IMAGE, buf_t, buf_s, false,
                                p.direct_thermal ? &help : nullptr);
    if (help) lv_obj_add_event_cb(help, infoPopupEventCb, LV_EVENT_CLICKED,
                                  INFO_POPUP_ARG(STR_PRN_MEDIA, STR_PRN_HEAT_HELP));
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Printer -> label stock grid");
      showMediaPicker();
    }, LV_EVENT_CLICKED, NULL); }

  // Whether "Print label" shows the print sheet first or prints at once.
  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_PS_ASK);
    char buf_sub[48]; copyT(buf_sub, sizeof(buf_sub), STR_PS_ASK_SUB);
    const bool ask = labelPrinterAskFirst();
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_EYE_OPEN, buf_t, buf_sub, ask);
    lv_obj_t *state = lv_obj_get_child(btn, -1);
    if (state) {
      lv_label_set_text(state, T(ask ? STR_ON : STR_OFF));
      lv_obj_set_style_text_color(state, lv_color_hex(ask ? UI_COL_ACCENT : UI_COL_CAPTION), 0);
      lv_obj_set_style_text_font(state, UI_FONT_SMALL, 0);
    }
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Printer -> print sheet on/off");
      printer_toggle_ask_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // The test print: the first thing to try with a new printer.
  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_PRN_TEST);
    char buf_s[64]; copyT(buf_s, sizeof(buf_s), STR_PRN_TEST_SUB);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_OK, buf_t, buf_s);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Printer -> test print");
      // Renders and prints from the loop: the print blocks for seconds.
      printer_test_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // Where the roll runs under the head: its own screen, with the
  // calibration page. The row says the offset and, at an edge or the
  // middle, which one. Only with a printer: the offset is kept per device
  // (its address is the key), and without one a value set here was reported
  // saved and was 0 again after a restart.
  if (have) { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_W_P_CAL_TITLE);
    int16_t lo, hi;
    labelPrinterOffsetRange(c, &lo, &hi);
    const int off = labelPrinterOffset(c);
    const int per = labelPrinterDotsForMm(c.model, 1);
    const int mm = (off + (off < 0 ? -per / 2 : per / 2)) / per;
    int where = -1;
    if (off == 0) where = STR_W_P_CAL_CENTER;
    else if (off == hi && hi > 0) where = STR_W_P_CAL_RIGHT;
    else if (off == lo && lo < 0) where = STR_W_P_CAL_LEFT;
    char buf_s[64];
    if (where < 0) snprintf(buf_s, sizeof(buf_s), "%s%d mm", mm > 0 ? "+" : "", mm);
    else snprintf(buf_s, sizeof(buf_s), "%s%d mm  \xE2\x80\xA2  %s", mm > 0 ? "+" : "", mm, T(where));
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_EDIT, buf_t, buf_s);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Printer -> print position");
      show_printer_offset_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  if (have) {
    char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_PRN_FORGET);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_TRASH, buf_t, "");
    // In the red of every row that deletes something, like the factory reset
    // in the system screen: set apart from the green rows, not shouting.
    lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_DANGER_ROW), 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_BAD_BG), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(btn, lv_color_hex(UI_COL_BAD_BG_PRESSED), 0);
    for (uint32_t i = 0; i < 2; i++) {   // child 0 the icon, 1 the title
      lv_obj_t *l = lv_obj_get_child(btn, i);
      if (l) lv_obj_set_style_text_color(l, lv_color_hex(UI_COL_DANGER_TEXT), 0);
    }
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Printer -> forget");
      printer_forget_pending = true;
    }, LV_EVENT_CLICKED, NULL);
  }
}

static void rebuild() {
  if (!scr_printer) return;
  buildPrinterScreen();            // releases the previous instance itself
  lv_obj_clear_flag(scr_printer, LV_OBJ_FLAG_HIDDEN);
}

void handlePrinterDeferredActions() {
  handleChoiceGridDeferredActions();
  printCardLoop();
  printSheetTick();
  printerOffsetTick();
  if (show_printer_offset_pending) {
    show_printer_offset_pending = false;
    buildPrinterOffsetScreen();
    hideAllOverlays();
    // Built hidden like every overlay; shown once the others are down.
    showPrinterOffsetScreen();
  }
  if (printer_toggle_ask_pending) {
    printer_toggle_ask_pending = false;
    if (!labelPrinterSetAskFirst(!labelPrinterAskFirst()))
      showInfoPopup(STR_PRN_TITLE, STR_ERR_SAVE, INFO_WARN);
    rebuild();
  }
  if (printer_forget_pending) {
    printer_forget_pending = false;
    labelPrinterForget();
    rebuild();
  }
  if (printer_test_pending) {
    printer_test_pending = false;
    printFixedLabel(labelRenderTest, "test print");
  }
  if (printer_calib_pending) {
    printer_calib_pending = false;
    printFixedLabel(labelRenderCalibration, "calibration page");
  }
  // Formnext 2026 only, removed with 0.8.5.
  if (print_fair_card_pending) {
    print_fair_card_pending = false;
    printFixedLabel(labelRenderFairCard, "fair card");
  }
  if (print_spool_label_pending) {
    print_spool_label_pending = false;
    printerPrintPadLabel(LABEL_KIND_SPOOL);
  }
  // The label editor's print: the last spool scanned, on the pad or not,
  // its own label or its filament's.
  if (print_last_label_pending || print_last_filament_label_pending) {
    const LabelKind kind = print_last_label_pending ? LABEL_KIND_SPOOL : LABEL_KIND_FILAMENT;
    print_last_label_pending = false;
    print_last_filament_label_pending = false;
    printerPrintLastLabel(kind);
  }
  if (print_own_layout_pending) {
    print_own_layout_pending = false;
    printSpoolLabel(s_own_layout_spool, true);
  }
  labelSpoolTick();
  labelServerTick();
}
