#include "printer_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "bambu/bambu_tag.h"

#include <Arduino.h>
#include <lvgl.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/ble_service.h"
#include "services/label_printer.h"
#include "services/label_render.h"
#include "ui/info_popup.h"
#include "ui/print_card.h"
#include "ui/theme.h"
#include "ui_common.h"

static int s_last_test = -1;
int printerLastTestResult() { return s_last_test; }

void closePrinterScreen() {
  if (scr_printer) { lv_obj_del(scr_printer); scr_printer = nullptr; }
}

// The next model in the profile order, NONE never included.
static LabelPrinterModel nextModel(LabelPrinterModel m) {
  return m == LP_MODEL_M220 ? LP_MODEL_M110 : LP_MODEL_M220;
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
    if (p.experimental) snprintf(buf_s, sizeof(buf_s), "%s  %s", p.name, T(STR_PRN_EXPERIMENTAL));
    else snprintf(buf_s, sizeof(buf_s), "%s", p.name);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_SETTINGS, buf_t, buf_s);
    lv_obj_add_event_cb(btn, [](lv_event_t *e){
      logSD("BTN: Printer -> next model");
      printer_cycle_model_pending = true;
    }, LV_EVENT_CLICKED, NULL); }

  // The label stock, cycled with a tap through what the model takes.
  { char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_PRN_MEDIA);
    char buf_s[48];
    snprintf(buf_s, sizeof(buf_s), T(STR_PRN_MEDIA_FMT),
             (unsigned)c.media_width_mm, (unsigned)c.media_length_mm);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_IMAGE, buf_t, buf_s);
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

  if (have) {
    char buf_t[40]; copyT(buf_t, sizeof(buf_t), STR_PRN_FORGET);
    lv_obj_t *btn = makeListBtn(list, LV_SYMBOL_TRASH, buf_t, "");
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
    const LabelPrinterConfig c = labelPrinterLoadConfig();
    LabelPrintResult result = LP_NO_PRINTER;
    if (labelPrinterConfigured(c)) {
      if (!bleEnabled()) result = LP_BLE_OFF;
      else {
        printCardShow();
        LabelRaster raster{};
        if (!labelRenderTest(c, &raster)) result = LP_BAD_RASTER;
        else result = labelPrinterPrint(c, raster, printCardTick);
        labelRasterFree(&raster);
      }
    }
    logSDf("Printer: test print result=%d", (int)result);
    s_last_test = labelPrintResultString(result);
    printCardResult(result);
  }
  if (print_spool_label_pending) {
    print_spool_label_pending = false;
    const LabelPrinterConfig c = labelPrinterLoadConfig();
    LabelPrintResult result = LP_NO_PRINTER;
    if (!(sm_found && sm_id > 0)) {
      showInfoPopup(STR_PRN_TITLE, STR_PRN_ERR_NO_SPOOL, INFO_WARN);
      return;
    }
    if (!labelPrinterConfigured(c)) result = LP_NO_PRINTER;
    else if (!bleEnabled()) result = LP_BLE_OFF;
    else {
      // What the scan left in the globals, as the backend named it.
      SpoolLabelData spool{};
      spool.id = sm_id;
      snprintf(spool.name, sizeof(spool.name), "%s", sm_filament_name);
      snprintf(spool.vendor, sizeof(spool.vendor), "%s", sm_vendor_g);
      // Like the More info card: the backend's material when it named one,
      // else what the Bambu tag says.
      snprintf(spool.material, sizeof(spool.material), "%s",
               sm_material_global[0] ? sm_material_global : g_tag.material);
      snprintf(spool.location, sizeof(spool.location), "%s", sm_location_name);
      snprintf(spool.color, sizeof(spool.color), "%s", sm_color_global);
      spool.remaining_g = sm_remaining;
      printCardShow();
      LabelRaster raster{};
      if (!labelRenderSpool(c, spool, &raster)) result = LP_BAD_RASTER;
      else result = labelPrinterPrint(c, raster, printCardTick);
      labelRasterFree(&raster);
    }
    logSDf("Printer: spool #%d label result=%d", sm_id, (int)result);
    printCardResult(result);
  }
}
