#include "services/label_printer.h"

#include <stdio.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/phomemo_m_series.h"
#include "services/prefs_store.h"

// 203 dpi: dots per millimetre, as a ratio so the rounding stays exact.
#define LP_DOTS_PER_254MM 2030

// The NVS keys. 15 characters at most, and never renamed: they sit in the
// NVS of every device that ever picked a printer.
#define LP_KEY_MODEL "printer_model"
#define LP_KEY_ADDR  "printer_addr"
#define LP_KEY_NAME  "printer_name"
#define LP_KEY_W     "printer_w"
#define LP_KEY_H     "printer_h"

static const LabelPrinterProfile PROFILE_NONE = {};
// M220: 2 inch head, 576 dots, takes stock from 20 to 75 mm wide; the vendor
// app pads narrower rows to 576 and wider ones to 648. Hardware proven.
static const LabelPrinterProfile PROFILE_M220 = {
  LP_MODEL_M220, "M220", 40, 30, 20, 75, 10, 150, 576, 648, false
};
// M110: 48 mm head, 384 dots. Same transport, own preamble, nobody here has
// printed on one yet.
static const LabelPrinterProfile PROFILE_M110 = {
  LP_MODEL_M110, "M110", 40, 30, 20, 48, 10, 150, 384, 384, true
};

const LabelMediaSize LABEL_MEDIA_SIZES[] = {
  {40, 30}, {30, 40}, {50, 30}, {60, 40}, {30, 20}, {40, 60}, {50, 50}, {50, 80}, {75, 50},
};
const int LABEL_MEDIA_SIZE_COUNT = sizeof(LABEL_MEDIA_SIZES) / sizeof(LABEL_MEDIA_SIZES[0]);

static LabelPrinterConfig s_config{};
static bool s_loaded = false;

const LabelPrinterProfile& labelPrinterProfile(LabelPrinterModel model) {
  switch (model) {
    case LP_MODEL_M220: return PROFILE_M220;
    case LP_MODEL_M110: return PROFILE_M110;
    default:            return PROFILE_NONE;
  }
}

static bool mediaFits(const LabelPrinterProfile& p, uint16_t w, uint16_t h) {
  return p.model != LP_MODEL_NONE &&
         w >= p.min_width_mm && w <= p.max_width_mm &&
         h >= p.min_length_mm && h <= p.max_length_mm;
}

// What is stored is taken as it is, except for two things that would leave
// the printer unusable: no model becomes the M220, and a label size the model
// cannot take becomes its default.
static LabelPrinterConfig normalized(const LabelPrinterConfig& in) {
  LabelPrinterConfig c = in;
  const LabelPrinterProfile& p = labelPrinterProfile(c.model);
  const LabelPrinterProfile& use = p.model == LP_MODEL_NONE ? PROFILE_M220 : p;
  c.model = use.model;
  c.name[sizeof(c.name) - 1] = '\0';
  c.address[sizeof(c.address) - 1] = '\0';
  if (!mediaFits(use, c.media_width_mm, c.media_length_mm)) {
    c.media_width_mm  = use.default_width_mm;
    c.media_length_mm = use.default_length_mm;
  }
  return c;
}

LabelPrinterConfig labelPrinterLoadConfig() {
  if (s_loaded) return s_config;
  LabelPrinterConfig c{};
  c.model = (LabelPrinterModel)prefsGetInt(LP_KEY_MODEL, LP_MODEL_M220);
  snprintf(c.name, sizeof(c.name), "%s", prefsGetString(LP_KEY_NAME, "").c_str());
  snprintf(c.address, sizeof(c.address), "%s", prefsGetString(LP_KEY_ADDR, "").c_str());
  c.media_width_mm  = prefsGetInt(LP_KEY_W, PROFILE_M220.default_width_mm);
  c.media_length_mm = prefsGetInt(LP_KEY_H, PROFILE_M220.default_length_mm);
  s_config = normalized(c);
  s_loaded = true;
  return s_config;
}

bool labelPrinterSaveConfig(const LabelPrinterConfig& in) {
  const LabelPrinterConfig c = normalized(in);
  bool ok = true;
  ok = prefsPutInt(LP_KEY_MODEL, (int)c.model) && ok;
  ok = prefsPutString(LP_KEY_ADDR, c.address) && ok;
  ok = prefsPutString(LP_KEY_NAME, c.name) && ok;
  ok = prefsPutInt(LP_KEY_W, c.media_width_mm) && ok;
  ok = prefsPutInt(LP_KEY_H, c.media_length_mm) && ok;
  if (ok) { s_config = c; s_loaded = true; }
  logSDf("Printer: config %s %s '%s' %ux%u mm %s", labelPrinterProfile(c.model).name,
         c.address[0] ? c.address : "-", c.name, (unsigned)c.media_width_mm,
         (unsigned)c.media_length_mm, ok ? "saved" : "NOT saved");
  return ok;
}

bool labelPrinterConfigured(const LabelPrinterConfig& c) { return c.address[0] != '\0'; }

bool labelPrinterForget() {
  LabelPrinterConfig c = labelPrinterLoadConfig();
  c.address[0] = '\0';
  c.name[0] = '\0';
  return labelPrinterSaveConfig(c);
}

bool labelPrinterIsDevice(const char* address) {
  if (!address || !address[0]) return false;
  const LabelPrinterConfig c = labelPrinterLoadConfig();
  return c.address[0] && strcmp(c.address, address) == 0;
}

uint16_t labelPrinterDotsForMm(uint16_t mm) {
  return (uint32_t(mm) * LP_DOTS_PER_254MM + 127) / 254;
}

uint16_t labelPrinterRasterWidth(LabelPrinterModel model, uint16_t media_width_mm) {
  const LabelPrinterProfile& p = labelPrinterProfile(model);
  if (p.model == LP_MODEL_NONE) return 0;
  const uint16_t content = labelPrinterDotsForMm(media_width_mm);
  const uint16_t canvas = content > p.base_raster_width ? content : p.base_raster_width;
  const uint16_t width = (canvas + 7) & ~uint16_t(7);
  return width > p.max_raster_width ? p.max_raster_width : width;
}

// The renderer works in whole dots from the same conversion, so the content
// matches exactly; one dot of slack is left for a raster from elsewhere.
static bool nearDots(uint16_t px, uint16_t mm) {
  const uint16_t d = labelPrinterDotsForMm(mm);
  return px + 1 >= d && px <= d + 1;
}

bool labelPrinterRasterFits(LabelPrinterModel model, const LabelRaster& image,
                            uint16_t media_width_mm, uint16_t media_length_mm) {
  const LabelPrinterProfile& p = labelPrinterProfile(model);
  return mediaFits(p, media_width_mm, media_length_mm) &&
         image.width == labelPrinterRasterWidth(model, media_width_mm) &&
         nearDots(image.content_width, media_width_mm) &&
         nearDots(image.height, media_length_mm);
}

LabelPrintResult labelPrinterPrint(const LabelPrinterConfig& c, const LabelRaster& image,
                                   BleProgressFn progress) {
  const LabelPrinterProfile& p = labelPrinterProfile(c.model);
  if (p.model == LP_MODEL_NONE || !labelPrinterConfigured(c)) return LP_NO_PRINTER;
  if (!labelRasterValid(image)) return LP_BAD_RASTER;
  if (image.width > p.max_raster_width) return LP_TOO_WIDE;
  if (!labelPrinterRasterFits(c.model, image, c.media_width_mm, c.media_length_mm))
    return LP_MEDIA_MISMATCH;
  const PhomemoModel pm = c.model == LP_MODEL_M110 ? PHOMEMO_M110 : PHOMEMO_M220;
  switch (phomemoMSeriesPrint(pm, c.address, image, progress)) {
    case BLE_WRITE_OK:                return LP_OK;
    case BLE_WRITE_OFF:               return LP_BLE_OFF;
    case BLE_WRITE_INIT_FAILED:       return LP_BLE_INIT;
    case BLE_WRITE_CONNECT_FAILED:    return LP_BLE_CONNECT;
    case BLE_WRITE_NO_CHARACTERISTIC: return LP_BLE_CHARACTERISTIC;
    case BLE_WRITE_STUCK:             return LP_BLE_STUCK;
    case BLE_WRITE_SENT_UNCONFIRMED:  return LP_SENT_UNCONFIRMED;
    default:                          return LP_BLE_WRITE;
  }
}

int labelPrintResultString(LabelPrintResult r) {
  switch (r) {
    case LP_OK:                 return STR_PRN_OK;
    case LP_NO_PRINTER:         return STR_PRN_ERR_NO_PRINTER;
    case LP_BAD_RASTER:         return STR_PRN_ERR_RASTER;
    case LP_TOO_WIDE:           return STR_PRN_ERR_TOO_WIDE;
    case LP_MEDIA_MISMATCH:     return STR_PRN_ERR_MEDIA;
    case LP_BLE_OFF:            return STR_PRN_ERR_BLE_OFF;
    case LP_BLE_INIT:           return STR_BT_INIT_FAILED;
    case LP_BLE_CONNECT:        return STR_PRN_ERR_CONNECT;
    case LP_BLE_CHARACTERISTIC: return STR_PRN_ERR_NOT_PRINTER;
    case LP_BLE_STUCK:          return STR_PRN_ERR_STUCK;
    case LP_SENT_UNCONFIRMED:   return STR_PRN_UNCONF_MSG;
    default:                    return STR_PRN_ERR_WRITE;
  }
}
