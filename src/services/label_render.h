#pragma once

#include "services/label_layout.h"
#include "services/label_printer.h"
#include "services/label_raster.h"

// ============================================================
//  RENDERING A LABEL ON THE SCALE
//
//  The scale draws the label itself, on an LVGL canvas in PSRAM
//  that nothing ever shows, and packs it into the raster the
//  printer takes. No server is asked: the data is what the
//  scale already knows. The layout is the one FilaMan's
//  standard label settled on, and it uses the whole label: the
//  maker's name large at the top, a black band with the
//  material in white, the filament's name as the title, the
//  facts in small lines on the left, the QR code on the right,
//  under the facts when the roll is narrow. With few facts and
//  room to spare, each takes two lines: the caption small, the
//  value large under it, never at the cost of the code's size.
//  The test label is
//  the same layout with sample data, so a print says at once
//  whether the head, the size and the alignment are right.
// ============================================================

#define LABEL_LINE_LEN 48
#define LABEL_QR_LEN  128    // an 80-character server address plus the spool path

struct SpoolLabelData {
  int   id;
  int   filament_id;                // 0 where the backend has no filament (BamBuddy)
  char  name[LABEL_NAME_BYTES];     // the filament, as the backend names it
  char  vendor[LABEL_LINE_LEN];
  char  material[LABEL_LINE_LEN];
  char  color[16];                  // hex or a name, whatever the backend gave
  char  article[32];                // the maker's article number, empty when unknown
  // dd.mm.yyyy, each empty when the backend has none. The layout picks one.
  char  first_used[12];
  char  added[12];
  // From the scan: 0 or empty where it knows none. The empty spool only when
  // its weight came from somewhere, never the 0 g of an unknown tare.
  float spool_weight_g;
  float net_weight_g;               // the filament when new
  char  location[LABEL_LINE_LEN];
  char  dried[12];                  // the last drying, in the date format
  // Asked of the backend with the dates, 0 where it has none. Spoolman keeps
  // one nozzle temperature (nozzle_max), BamBuddy a range and no bed.
  int16_t nozzle_min, nozzle_max, bed_temp;
  // The drying the filament wants, 0 where neither backend nor tag names one.
  int16_t dry_temp_c, dry_hours;
  // The link the server itself names for this spool, asked with the dates.
  // Empty where it names none: the QR code is then built from the id.
  char  page_url[LABEL_QR_LEN];
};

// The test label for the printer's loaded stock. The raster is allocated in
// PSRAM; labelRasterFree() gives it back. False when there is no PSRAM for
// the canvas or the printer has no usable stock.
bool labelRenderTest(const LabelPrinterConfig& printer, LabelRaster* out);

// The calibration page: a ruler across the whole print row, numbered in the
// offset that would put the label's left edge there, and a frame where the
// scale takes the label to be now. Read the number at the label's left edge,
// or check that the frame sits evenly.
bool labelRenderCalibration(const LabelPrinterConfig& printer, LabelRaster* out);

// A spool's label as the layout has it, with a QR code carrying what the
// active backend's own scanner reads.
bool labelRenderSpool(const LabelPrinterConfig& printer, const LabelLayout& layout,
                      const SpoolLabelData& spool, LabelRaster* out);

// What the QR code on a spool label carries for the active backend: the
// spool's page on Spoolman, FilaMan and BamBuddy, so a phone opens it.
// How far the number's share does anything on this printer's label, for this
// spool: see labelBigIdShareLimit(). 0 outside the big number arrangements.
int labelIdShareLimit(const LabelPrinterConfig& printer, const LabelLayout& layout,
                      const SpoolLabelData& spool);
void labelQrForSpool(int spool_id, char* out, size_t n);

// The filament's label for the spool's filament, with a code to the
// filament's page where the backend has one: Spoolman and FilaMan, not
// BamBuddy, whose filament is a few words on the spool.
bool labelRenderFilament(const LabelPrinterConfig& printer, const LabelLayout& layout,
                         const SpoolLabelData& spool, LabelRaster* out);
// The filament's page, empty when there is none to open.
void labelQrForFilament(const SpoolLabelData& spool, char* out, size_t n);
