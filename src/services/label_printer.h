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
//  are what the head wants, at the profile's resolution. The
//  conversions live here so the renderer and the screens agree.
// ============================================================

// The values are NVS content (printer_model): a new model goes at the end,
// none is ever renumbered or reused.
enum LabelPrinterModel : uint8_t {
  LP_MODEL_NONE = 0, LP_MODEL_M220 = 1, LP_MODEL_M110 = 2, LP_MODEL_M100 = 3,
  LP_MODEL_NIIMBOT_B = 4,     // the 50 mm NIIMBOT class: B1, B21, B203 ...
  LP_MODEL_NIIMBOT_M2 = 5,    // NIIMBOT M2, 300 dpi, thermal transfer
  LP_MODEL_M120 = 6, LP_MODEL_M200 = 7, LP_MODEL_M221 = 8,
  LP_MODEL_M110S = 9,         // the M110's bytes, a row as wide as the label
  LP_MODEL_NIIMBOT_D110 = 10, // NIIMBOT D110 and D110 M: 12 mm tape, 96 dots, the label turned
  LP_MODEL_PM241 = 11         // Phomemo PM241-BT and PM245-BT, 4 x 6 inch shipping label printers, TSPL
};

// Which bytes a model takes. Phomemo's two preambles share one write-only
// transport; a NIIMBOT talks back and gets a driver of its own.
enum LabelPrinterProtocol : uint8_t {
  LP_PROTO_PHOMEMO_M220 = 0, LP_PROTO_PHOMEMO_M110 = 1, LP_PROTO_NIIMBOT = 2,
  LP_PROTO_TSPL = 3           // text commands, see services/tspl_printer.h
};

struct LabelPrinterProfile {
  LabelPrinterModel model;
  const char* brand;
  const char* name;
  uint16_t default_width_mm, default_length_mm;
  uint16_t min_width_mm, max_width_mm;
  uint16_t min_length_mm, max_length_mm;
  uint16_t base_raster_width, max_raster_width;   // dots in one print row
  bool     experimental;
  // Prints by heat on heat-sensitive paper, no ribbon: the label turns black
  // wherever it gets hot enough, a spool in the dryer included.
  bool     direct_thermal;
  uint16_t dpi;                 // the head's resolution: 203 or 300
  LabelPrinterProtocol protocol;
  // Models in the name nobody has printed on yet, written as in the name
  // and separated the same way (services/printer_names.h); null when every
  // one has been tried. The browser marks them one by one.
  const char* untried;
};

struct LabelPrinterConfig {
  LabelPrinterModel model;
  char     name[BLE_NAME_LEN];
  char     address[BLE_ADDR_LEN];
  uint16_t media_width_mm, media_length_mm;      // across the head, along the feed
  // Where the stock runs under the head, in dots from the middle of the print
  // row, positive to the right as the label reads. Stored as set and clamped
  // to the row when used, so LP_OFFSET_RIGHT keeps a roll against the right
  // wall there for every label width.
  int16_t  x_offset;
};

// "Against the wall": beyond any head, clamped to the row's edge when used.
#define LP_OFFSET_RIGHT  LABEL_RASTER_MAX_W
#define LP_OFFSET_LEFT  (-LABEL_RASTER_MAX_W)

// The label sizes offered on the printer screen: width across the head by
// length along the feed, in mm. What the vendors sell for these printers.
struct LabelMediaSize { uint8_t width_mm, length_mm; };
extern const LabelMediaSize LABEL_MEDIA_SIZES[];
extern const int LABEL_MEDIA_SIZE_COUNT;
// Sizes on sale for these printers that no layout of ours fits yet: the
// printer screen shows them greyed, so the step to them is visible.
extern const LabelMediaSize LABEL_MEDIA_SIZES_PLANNED[];
extern const int LABEL_MEDIA_PLANNED_COUNT;

// The models in the order the printer screen's grid and the browser list
// them: proven first, experimental after. NONE is never in it.
extern const LabelPrinterModel LABEL_PRINTER_MODELS[];
extern const int LABEL_PRINTER_MODEL_COUNT;

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
  // What a printer that talks back can say, see services/niimbot.h.
  LP_BLE_NOT_NIIMBOT,   // nothing of the protocol's shape on the device
  LP_PRN_COVER,
  LP_PRN_NO_PAPER,
  LP_PRN_NO_RIBBON,
  LP_PRN_BUSY,
  LP_PRN_ERROR,         // another error code; it is in the log
  LP_MODEL_MISMATCH,    // a known printer, but not of the picked class
  LP_MODEL_UNKNOWN,     // an id the table does not have; it is in the log
  LP_SERVER_LABEL,      // the server did not draw the chosen preset; why is in the log
};

const LabelPrinterProfile& labelPrinterProfile(LabelPrinterModel model);

// Cached after the first read; every write goes through the save.
LabelPrinterConfig labelPrinterLoadConfig();
bool labelPrinterSaveConfig(const LabelPrinterConfig& config);
bool labelPrinterConfigured(const LabelPrinterConfig& config);
// The models we have on the desk and test every label feature on first; the
// manual's page of recommended printers names the same ones.
bool labelPrinterRecommended(LabelPrinterModel model);
// Drops the device, keeps model and label size.
bool labelPrinterForget();
// True when this address is the picked printer.
bool labelPrinterIsDevice(const char* address);

// Millimetres to dots at the model's resolution; 0 for no model.
uint16_t labelPrinterDotsForMm(LabelPrinterModel model, uint16_t mm);
// The print row for this model and label width: the head's base width or
// the label, whichever is wider, rounded up to whole bytes, capped at the head.
uint16_t labelPrinterRasterWidth(LabelPrinterModel model, uint16_t media_width_mm);
// The label's dots across the head, never more than the print row: a roll
// wider than the head prints the head's width of it.
uint16_t labelPrinterContentWidth(LabelPrinterModel model, uint16_t media_width_mm);
// The first dot of the label in the print row: the middle plus the offset,
// clamped so the label stays in the row.
uint16_t labelPrinterContentX(const LabelPrinterConfig& config);
// The offsets the loaded stock allows: the label at the row's left edge and
// at its right edge. Both 0 when the label fills the row.
void labelPrinterOffsetRange(const LabelPrinterConfig& config, int16_t* min, int16_t* max);
// The offset in effect: the stored one, clamped to that range.
int16_t labelPrinterOffset(const LabelPrinterConfig& config);
bool labelPrinterRasterFits(LabelPrinterModel model, const LabelRaster& image,
                            uint16_t media_width_mm, uint16_t media_length_mm);

// Blocking, from appLoop() only: checks the raster against the printer and
// the loaded label, then prints. progress keeps an overlay moving.
LabelPrintResult labelPrinterPrint(const LabelPrinterConfig& config,
                                   const LabelRaster& image, BleProgressFn progress);
// The StringID that says what a result means, for a popup or a status line.
int labelPrintResultString(LabelPrintResult result);

// A tape printer: a head as narrow as the label is high (the D110's 12 mm),
// so the label is drawn lying, as it reads, and turned onto the roll. Its
// own small arrangement, not the label editor's: see labelRenderSpool().
bool labelPrinterIsTape(LabelPrinterModel model);

// Whether the model takes label stock of this size.
bool labelPrinterTakesMedia(LabelPrinterModel model, uint16_t width_mm, uint16_t length_mm);

// The next stock size the model can take, after the current one; the first
// fitting one when the current one is not in the table. Only the config.
void labelPrinterNextMedia(LabelPrinterConfig& c);

// Whether "Print label" on the scale shows the print sheet first (preview,
// kind, arrangement) or prints at once. On until switched off.
bool labelPrinterAskFirst();
bool labelPrinterSetAskFirst(bool ask);
