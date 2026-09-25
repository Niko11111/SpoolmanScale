#pragma once

#include <stdint.h>

#include "services/ble_service.h"
#include "services/label_raster.h"

// ============================================================
//  THE LABEL PRINTER
//
//  Which printer the scale has, what label stock is in it, and
//  the one call that puts a raster on paper. The printer is a
//  BLE device picked on the device card; the model and the
//  loaded label size are set on the printer screen or in the
//  browser. Models are profiles: head width, the label sizes
//  they take, whether anyone has printed on one yet.
//
//  Millimetres are what a person reads off the label roll; dots
//  are what the head wants, at 203 dpi. The conversions live
//  here so the renderer and the screens agree on them.
// ============================================================

enum LabelPrinterModel : uint8_t { LP_MODEL_NONE = 0, LP_MODEL_M220 = 1, LP_MODEL_M110 = 2 };

struct LabelPrinterProfile {
  LabelPrinterModel model;
  const char* name;
  uint16_t default_width_mm, default_length_mm;
  uint16_t min_width_mm, max_width_mm;
  uint16_t min_length_mm, max_length_mm;
  uint16_t base_raster_width, max_raster_width;   // dots in one print row
  bool     experimental;
};

struct LabelPrinterConfig {
  LabelPrinterModel model;
  char     name[BLE_NAME_LEN];
  char     address[BLE_ADDR_LEN];
  uint16_t media_width_mm, media_length_mm;      // across the head, along the feed
};

// The label sizes offered on the printer screen: width across the head by
// length along the feed, in mm. What the vendors sell for these printers.
struct LabelMediaSize { uint8_t width_mm, length_mm; };
extern const LabelMediaSize LABEL_MEDIA_SIZES[];
extern const int LABEL_MEDIA_SIZE_COUNT;

enum LabelPrintResult : uint8_t {
  LP_OK = 0,
  LP_NO_PRINTER,        // no device picked, or no model
  LP_BAD_RASTER,        // shape or padding wrong
  LP_TOO_WIDE,          // wider than the head
  LP_MEDIA_MISMATCH,    // not the loaded label size
  LP_BLE_OFF,
  LP_BLE_INIT,
  LP_BLE_CONNECT,
  LP_BLE_CHARACTERISTIC,
  LP_BLE_WRITE,
  LP_BLE_STUCK,
  LP_SENT_UNCONFIRMED,  // all sent, the printer never said done
};

const LabelPrinterProfile& labelPrinterProfile(LabelPrinterModel model);

// Cached after the first read; every write goes through the save.
LabelPrinterConfig labelPrinterLoadConfig();
bool labelPrinterSaveConfig(const LabelPrinterConfig& config);
bool labelPrinterConfigured(const LabelPrinterConfig& config);
// Drops the device, keeps model and label size.
bool labelPrinterForget();
// True when this address is the picked printer.
bool labelPrinterIsDevice(const char* address);

uint16_t labelPrinterDotsForMm(uint16_t mm);
// The print row for this model and label width: the head's base width or
// the label, whichever is wider, rounded up to whole bytes, capped at the head.
uint16_t labelPrinterRasterWidth(LabelPrinterModel model, uint16_t media_width_mm);
bool labelPrinterRasterFits(LabelPrinterModel model, const LabelRaster& image,
                            uint16_t media_width_mm, uint16_t media_length_mm);

// Blocking, from appLoop() only: checks the raster against the printer and
// the loaded label, then prints. progress keeps an overlay moving.
LabelPrintResult labelPrinterPrint(const LabelPrinterConfig& config,
                                   const LabelRaster& image, BleProgressFn progress);
// The StringID that says what a result means, for a popup or a status line.
int labelPrintResultString(LabelPrintResult result);
