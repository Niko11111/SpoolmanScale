#include "services/label_printer.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/phomemo_m_series.h"
#include "services/prefs_store.h"

// The NVS keys. 15 characters at most, and never renamed: they sit in the
// NVS of every device that ever picked a printer.
#define LP_KEY_MODEL "printer_model"
#define LP_KEY_ADDR  "printer_addr"
#define LP_KEY_NAME  "printer_name"
#define LP_KEY_W     "printer_w"
#define LP_KEY_H     "printer_h"
// The offset belongs to one printer, not to the scale: "px" and the device's
// address without colons, 14 characters. A second printer starts at 0, and
// the first gets its own back when it is picked again (Nikolai, 30.09.2026).
#define LP_KEY_XOFF_PREFIX "px"

static const LabelPrinterProfile PROFILE_NONE = {};
// M220: 2 inch head, 576 dots, takes stock from 20 to 75 mm wide; the vendor
// app pads narrower rows to 576 and wider ones to 648. Hardware proven.
static const LabelPrinterProfile PROFILE_M220 = {
  LP_MODEL_M220, "Phomemo", "M220", 40, 30, 20, 75, 10, 150, 576, 648, false, true,
  203, LP_PROTO_PHOMEMO_M220
};
// M110: 48 mm head, 384 dots. Same transport, own preamble. A user printed
// with this profile on an M100 (09.2026), which proves the M110 bytes.
static const LabelPrinterProfile PROFILE_M110 = {
  LP_MODEL_M110, "Phomemo", "M110", 40, 30, 20, 48, 10, 150, 384, 384, false, true,
  203, LP_PROTO_PHOMEMO_M110
};
// M100: the M110's head and bytes under its own name, so a user finds it.
static const LabelPrinterProfile PROFILE_M100 = {
  LP_MODEL_M100, "Phomemo", "M100", 40, 30, 20, 48, 10, 150, 384, 384, false, true,
  203, LP_PROTO_PHOMEMO_M110
};
// The siblings Phomemo sells the same label rolls for. phomemo-tools shows
// the M120 speaking the M110 protocol; the M200 and M221 take the M220's
// 20 to 80 mm stock at 203 dpi. Experimental until a user has printed.
static const LabelPrinterProfile PROFILE_M120 = {
  LP_MODEL_M120, "Phomemo", "M120", 40, 30, 20, 48, 10, 150, 384, 384, true, true,
  203, LP_PROTO_PHOMEMO_M110
};
static const LabelPrinterProfile PROFILE_M200 = {
  LP_MODEL_M200, "Phomemo", "M200", 40, 30, 20, 75, 10, 150, 576, 648, true, true,
  203, LP_PROTO_PHOMEMO_M220
};
static const LabelPrinterProfile PROFILE_M221 = {
  LP_MODEL_M221, "Phomemo", "M221", 40, 30, 20, 75, 10, 150, 576, 648, true, true,
  203, LP_PROTO_PHOMEMO_M220
};

const LabelPrinterModel LABEL_PRINTER_MODELS[] = {
  LP_MODEL_M220, LP_MODEL_M110, LP_MODEL_M100, LP_MODEL_M120, LP_MODEL_M200, LP_MODEL_M221,
};
const int LABEL_PRINTER_MODEL_COUNT = sizeof(LABEL_PRINTER_MODELS) / sizeof(LABEL_PRINTER_MODELS[0]);

// The two sizes printed and checked on the M220 for 0.8.0 (Nikolai,
// 26.09.2026). 40 x 20 and 30 x 20 leave no room for the code; the larger
// ones come back with the label presets.
const LabelMediaSize LABEL_MEDIA_SIZES[] = {
  {40, 30}, {50, 30},
};
const int LABEL_MEDIA_SIZE_COUNT = sizeof(LABEL_MEDIA_SIZES) / sizeof(LABEL_MEDIA_SIZES[0]);

static LabelPrinterConfig s_config{};
static bool s_loaded = false;

// The NVS key of a printer's offset; false for no printer. An address is
// 17 characters, six pairs of hex digits and five colons.
static bool offsetKey(const char* address, char* key, size_t n) {
  if (!address || !address[0]) return false;
  size_t k = snprintf(key, n, "%s", LP_KEY_XOFF_PREFIX);
  for (const char* a = address; *a && k + 1 < n; a++)
    if (*a != ':') key[k++] = (char)tolower((unsigned char)*a);
  key[k] = '\0';
  return true;
}

static int16_t loadOffset(const char* address) {
  char key[20];
  return offsetKey(address, key, sizeof(key)) ? (int16_t)prefsGetInt(key, 0) : 0;
}
// The label size the user picked, which is what NVS keeps. The config holds
// the size in effect: the picked one, or the model's default while the model
// cannot take it. Going M220 -> M110 -> M220 lost a picked 50 x 30 for good
// before this (30.09.2026): the M110 took 40 x 30 and that was saved.
static uint16_t s_want_w = 0, s_want_l = 0;

const LabelPrinterProfile& labelPrinterProfile(LabelPrinterModel model) {
  switch (model) {
    case LP_MODEL_M220: return PROFILE_M220;
    case LP_MODEL_M110: return PROFILE_M110;
    case LP_MODEL_M100: return PROFILE_M100;
    case LP_MODEL_M120: return PROFILE_M120;
    case LP_MODEL_M200: return PROFILE_M200;
    case LP_MODEL_M221: return PROFILE_M221;
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
// cannot take becomes the picked one where it fits, else the model's default.
static LabelPrinterConfig normalized(const LabelPrinterConfig& in) {
  LabelPrinterConfig c = in;
  const LabelPrinterProfile& p = labelPrinterProfile(c.model);
  const LabelPrinterProfile& use = p.model == LP_MODEL_NONE ? PROFILE_M220 : p;
  c.model = use.model;
  c.name[sizeof(c.name) - 1] = '\0';
  c.address[sizeof(c.address) - 1] = '\0';
  if (c.x_offset > LP_OFFSET_RIGHT) c.x_offset = LP_OFFSET_RIGHT;
  if (c.x_offset < LP_OFFSET_LEFT)  c.x_offset = LP_OFFSET_LEFT;
  if (mediaFits(use, s_want_w, s_want_l)) {
    c.media_width_mm  = s_want_w;
    c.media_length_mm = s_want_l;
  } else if (!mediaFits(use, c.media_width_mm, c.media_length_mm)) {
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
  c.x_offset = loadOffset(c.address);
  s_want_w = c.media_width_mm;
  s_want_l = c.media_length_mm;
  s_config = normalized(c);
  s_loaded = true;
  return s_config;
}

bool labelPrinterSaveConfig(const LabelPrinterConfig& in) {
  const LabelPrinterConfig before = labelPrinterLoadConfig();
  // A size other than the one in effect is a new pick; the same size with
  // another model is not, and leaves the picked one as it was.
  const uint16_t want_w = s_want_w, want_l = s_want_l;
  if (in.media_width_mm != before.media_width_mm ||
      in.media_length_mm != before.media_length_mm) {
    s_want_w = in.media_width_mm;
    s_want_l = in.media_length_mm;
  }
  LabelPrinterConfig c = normalized(in);
  // Another device is another printer: its own offset, whatever the caller
  // carried over from the one before.
  if (strcmp(in.address, before.address) != 0) c.x_offset = loadOffset(c.address);
  bool ok = true;
  ok = prefsPutInt(LP_KEY_MODEL, (int)c.model) && ok;
  ok = prefsPutString(LP_KEY_ADDR, c.address) && ok;
  ok = prefsPutString(LP_KEY_NAME, c.name) && ok;
  ok = prefsPutInt(LP_KEY_W, s_want_w) && ok;
  ok = prefsPutInt(LP_KEY_H, s_want_l) && ok;
  char key[20];
  if (offsetKey(c.address, key, sizeof(key))) ok = prefsPutInt(key, c.x_offset) && ok;
  if (ok) { s_config = c; s_loaded = true; }
  else { s_want_w = want_w; s_want_l = want_l; }
  logSDf("Printer: config %s %s '%s' %ux%u mm offset %d (%d) %s",
         labelPrinterProfile(c.model).name, c.address[0] ? c.address : "-", c.name,
         (unsigned)c.media_width_mm, (unsigned)c.media_length_mm, (int)c.x_offset,
         (int)labelPrinterOffset(c), ok ? "saved" : "NOT saved");
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

// As a ratio so the rounding stays exact: at 203 dpi this is the 8 dots to
// the millimetre the M220 was measured with, bit for bit.
uint16_t labelPrinterDotsForMm(LabelPrinterModel model, uint16_t mm) {
  const uint32_t dpi = labelPrinterProfile(model).dpi;
  return (uint32_t(mm) * dpi * 10 + 127) / 254;
}

uint16_t labelPrinterRasterWidth(LabelPrinterModel model, uint16_t media_width_mm) {
  const LabelPrinterProfile& p = labelPrinterProfile(model);
  if (p.model == LP_MODEL_NONE) return 0;
  const uint16_t content = labelPrinterDotsForMm(model, media_width_mm);
  const uint16_t canvas = content > p.base_raster_width ? content : p.base_raster_width;
  const uint16_t width = (canvas + 7) & ~uint16_t(7);
  return width > p.max_raster_width ? p.max_raster_width : width;
}

// Every Phomemo head is at least as wide as its widest stock, so there this
// is the plain conversion; a 50 mm roll on a 48 mm head prints 48 mm of it.
uint16_t labelPrinterContentWidth(LabelPrinterModel model, uint16_t media_width_mm) {
  const uint16_t dots = labelPrinterDotsForMm(model, media_width_mm);
  const uint16_t row = labelPrinterRasterWidth(model, media_width_mm);
  return dots > row ? row : dots;
}

// A ruler across the M220's 576 dots put Nikolai's 40 mm roll under dots 128
// to 448, the middle (24.09.2026); a user's roll sat 16 mm further right, at
// the fixed wall of the roll holder (30.09.2026). Where the roll runs is how
// it sits in the holder, not the model, so it is a setting of its own.
void labelPrinterOffsetRange(const LabelPrinterConfig& c, int16_t* min, int16_t* max) {
  const uint16_t row = labelPrinterRasterWidth(c.model, c.media_width_mm);
  const uint16_t content = labelPrinterContentWidth(c.model, c.media_width_mm);
  const int16_t slack = content < row ? int16_t(row - content) : 0;
  const int16_t centre = slack / 2;
  if (min) *min = -centre;
  if (max) *max = slack - centre;
}

int16_t labelPrinterOffset(const LabelPrinterConfig& c) {
  int16_t lo, hi;
  labelPrinterOffsetRange(c, &lo, &hi);
  return c.x_offset < lo ? lo : c.x_offset > hi ? hi : c.x_offset;
}

uint16_t labelPrinterContentX(const LabelPrinterConfig& c) {
  int16_t lo;
  labelPrinterOffsetRange(c, &lo, nullptr);
  return uint16_t(labelPrinterOffset(c) - lo);
}

// The renderer works in whole dots from the same conversion, so the content
// matches exactly; one dot of slack is left for a raster from elsewhere.
static bool nearDots(uint16_t px, uint16_t d) {
  return px + 1 >= d && px <= d + 1;
}

bool labelPrinterRasterFits(LabelPrinterModel model, const LabelRaster& image,
                            uint16_t media_width_mm, uint16_t media_length_mm) {
  const LabelPrinterProfile& p = labelPrinterProfile(model);
  return mediaFits(p, media_width_mm, media_length_mm) &&
         image.width == labelPrinterRasterWidth(model, media_width_mm) &&
         nearDots(image.content_width, labelPrinterContentWidth(model, media_width_mm)) &&
         nearDots(image.height, labelPrinterDotsForMm(model, media_length_mm));
}

LabelPrintResult labelPrinterPrint(const LabelPrinterConfig& c, const LabelRaster& image,
                                   BleProgressFn progress) {
  const LabelPrinterProfile& p = labelPrinterProfile(c.model);
  if (p.model == LP_MODEL_NONE || !labelPrinterConfigured(c)) return LP_NO_PRINTER;
  if (!labelRasterValid(image)) return LP_BAD_RASTER;
  if (image.width > p.max_raster_width) return LP_TOO_WIDE;
  if (!labelPrinterRasterFits(c.model, image, c.media_width_mm, c.media_length_mm))
    return LP_MEDIA_MISMATCH;
  const PhomemoModel pm = p.protocol == LP_PROTO_PHOMEMO_M220 ? PHOMEMO_M220 : PHOMEMO_M110;
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
