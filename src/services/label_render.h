#pragma once

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
//  under the facts when the roll is narrow. The test label is
//  the same layout with sample data, so a print says at once
//  whether the head, the size and the alignment are right.
// ============================================================

#define LABEL_LINE_LEN 48
#define LABEL_QR_LEN   96

struct SpoolLabelData {
  int   id;
  char  name[LABEL_LINE_LEN];       // the filament, as the backend names it
  char  vendor[LABEL_LINE_LEN];
  char  material[LABEL_LINE_LEN];
  char  color[16];                  // hex or a name, whatever the backend gave
  char  location[LABEL_LINE_LEN];   // empty when the spool has none
  float remaining_g;                // below zero when unknown
};

// The test label for the printer's loaded stock. The raster is allocated in
// PSRAM; labelRasterFree() gives it back. False when there is no PSRAM for
// the canvas or the printer has no usable stock.
bool labelRenderTest(const LabelPrinterConfig& printer, LabelRaster* out);

// A spool's label, with a QR code carrying what the active backend's own
// scanner reads.
bool labelRenderSpool(const LabelPrinterConfig& printer, const SpoolLabelData& spool,
                      LabelRaster* out);

// What the QR code on a spool label carries for the active backend:
// Spoolman's own tag format, FilaMan's and BamBuddy's spool page.
void labelQrForSpool(int spool_id, char* out, size_t n);
