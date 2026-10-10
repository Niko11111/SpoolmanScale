#include "printer_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "app/label_spool.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ble_service.h"
#include "services/label_layout.h"
#include "services/label_printer.h"
#include "services/label_render.h"
#include "ui/info_popup.h"
#include "ui/print_card.h"
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

// A spool's label with the saved template, under the print card; the dates
// are asked of the backend first, a slow one only costs the label its date.
// The card comes first, so the wait for them has something on screen.
static void printSpoolLabel(SpoolLabelData spool) {
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  LabelPrintResult result = LP_NO_PRINTER;
  if (labelPrinterConfigured(c)) {
    if (!bleEnabled()) result = LP_BLE_OFF;
    else {
      printCardShow();
      labelSpoolFetchDates(&spool);
      LabelRaster raster{};
      if (!labelRenderSpool(c, labelLayoutLoad(), spool, &raster)) result = LP_BAD_RASTER;
      else result = labelPrinterPrint(c, raster, printCardTick);
      labelRasterFree(&raster);
    }
  }
  logSDf("Printer: spool #%d label result=%d", spool.id, (int)result);
  s_last_label = labelPrintResultString(result);
  printCardResult(result);
}

void closePrinterScreen() {
  if (scr_printer) { lv_obj_del(scr_printer); scr_printer = nullptr; }
}

// The next model in the table's order, NONE never included.
static LabelPrinterModel nextModel(LabelPrinterModel m) {
  for (int i = 0; i < LABEL_PRINTER_MODEL_COUNT; i++)
    if (LABEL_PRINTER_MODELS[i] == m)
      return LABEL_PRINTER_MODELS[(i + 1) % LABEL_PRINTER_MODEL_COUNT];
  return LABEL_PRINTER_MODELS[0];
}

// The next stock size the model can take, after the current one; the first
// fitting one when the current one is not in the table.
static void nextMedia(LabelPrinterConfig& c) {
  const LabelPrinterProfile& p = labelPrinterProfile(c.model);
  int at = -1;
  for (int i = 0; i < LABEL_MEDIA_SIZE_COUNT; i++)
    if (LABEL_MEDIA_SIZES[i].width_mm == c.media_width_mm &&
        LABEL_MEDIA_SIZES[i].length_mm == c.media_length_mm) { at = i; break; }
  for (int step = 1; step <= LABEL_MEDIA_SIZE_COUNT; step++) {
    const LabelMediaSize& s = LABEL_MEDIA_SIZES[(at + step) % LABEL_MEDIA_SIZE_COUNT];
    if (s.width_mm >= p.min_width_mm && s.width_mm <= p.max_width_mm &&
        s.length_mm >= p.min_length_mm && s.length_mm <= p.max_length_mm) {
      c.media_width_mm = s.width_mm;
      c.media_length_mm = s.length_mm;
      return;
    }
  }
}

void buildPrinterScreen() {
  logSD("BUILD: PrinterScreen");
  releaseScreen(&scr_printer);
  scr_printer = buildOverlayScreen();
  buildSubHeader(scr_printer, T(STR_PRN_TITLE),
    [](lv_event_t *e){
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

  // The model, cycled with a tap.
  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_PRN_MODEL);
    char buf_s[64];
    if (p.experimental) snprintf(buf_s, sizeof(buf_s), "%s %s  %s", p.brand, p.name, T(STR_PRN_EXPERIMENTAL));
    else snprintf(buf_s, sizeof(buf_s), "%s %s", p.brand, p.name);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_SETTINGS, buf_t, buf_s);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Printer -> next model");
      printer_cycle_model_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // The label stock, cycled with a tap through what the model takes. On
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
      logSD("BTN: Printer -> next media");
      printer_cycle_media_pending = true;
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
  printCardLoop();
  printerOffsetTick();
  if (show_printer_offset_pending) {
    show_printer_offset_pending = false;
    buildPrinterOffsetScreen();
    hideAllOverlays();
    // Built hidden like every overlay; shown once the others are down.
    showPrinterOffsetScreen();
  }
  if (printer_cycle_model_pending) {
    printer_cycle_model_pending = false;
    LabelPrinterConfig c = labelPrinterLoadConfig();
    c.model = nextModel(c.model);
    // A stock the new model cannot take falls back to its default in the save.
    if (!labelPrinterSaveConfig(c)) showInfoPopup(STR_PRN_TITLE, STR_ERR_SAVE, INFO_WARN);
    rebuild();
  }
  if (printer_cycle_media_pending) {
    printer_cycle_media_pending = false;
    LabelPrinterConfig c = labelPrinterLoadConfig();
    nextMedia(c);
    if (!labelPrinterSaveConfig(c)) showInfoPopup(STR_PRN_TITLE, STR_ERR_SAVE, INFO_WARN);
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
  if (print_spool_label_pending) {
    print_spool_label_pending = false;
    printerOffsetFlush();
    SpoolLabelData spool{};
    if (!labelSpoolFromScan(&spool)) {
      showInfoPopup(STR_PRN_TITLE, STR_PRN_ERR_NO_SPOOL, INFO_WARN);
      return;
    }
    printSpoolLabel(spool);
  }
  // The label editor's print: the last spool scanned, on the pad or not.
  if (print_last_label_pending) {
    print_last_label_pending = false;
    printerOffsetFlush();
    SpoolLabelData spool{};
    if (!labelSpoolLast(&spool)) {
      showInfoPopup(STR_PRN_TITLE, STR_PRN_ERR_NO_SPOOL, INFO_WARN);
      return;
    }
    printSpoolLabel(spool);
  }
  labelSpoolTick();
}
