#pragma once

#include "services/label_printer.h"
#include "services/label_raster.h"

// ============================================================
//  THE FORMNEXT CARD (Formnext 2026 only, removed with 0.8.5)
//
//  A business card the scale prints at the fair: a long press on
//  Tare, while the hidden switch is on. Off by default and nowhere
//  in the interface; the maintenance route /api/fair-card turns it
//  on. The card is a fixed 1-bit picture for the NIIMBOT M2 on a
//  50 x 30 roll, so it prints only where it fits dot for dot.
// ============================================================

// The switch, cached after the first read.
bool fairCardEnabled();
bool fairCardSetEnabled(bool on);

// The card as the printer takes it. False, and nothing allocated, unless the
// printer runs 300 dpi with 50 x 30 loaded: the picture is drawn for that.
bool labelRenderFairCard(const LabelPrinterConfig& printer, LabelRaster* out);
