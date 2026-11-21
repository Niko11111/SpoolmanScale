#pragma once

#include <stdint.h>

#include "services/label_layout.h"
#include "services/label_media.h"
#include "services/label_printer.h"

// ============================================================
//  HOW MANY FACT LINES A LABEL HOLDS
//
//  On a checked size the table measured in the simulator
//  (labelFactCapacity() in label_layout.cpp), unchanged. On any
//  other size the renderer lays a reference spool's label out
//  without drawing it, six lines down to one, and the first count
//  whose lines fit the height, with the code at a readable size, is
//  the budget. A line too long for the width is cut, as on the
//  checked sizes. The reference spool is the worst case of the spools
//  the table was measured with, its code the link this scale
//  prints, for the shortest and the longest spool number: a
//  shorter link draws a larger code, so neither alone bounds it.
//  From the loop task only, like the renderer.
// ============================================================

// The fact lines this layout keeps on the printer's loaded stock.
int labelFactCapacityFor(const LabelPrinterConfig& printer, const LabelLayout& layout);
// The same measured, whatever the size: what an unchecked size gets, and what
// the simulator compares with the table on the checked ones.
int labelFactCapacityMeasured(const LabelPrinterConfig& printer, const LabelLayout& layout);
// labelMediaStatus() for this model, and TOO_SMALL where even the standard
// arrangement without a code keeps no fact line under its header.
LabelMediaStatus labelMediaStatusFor(LabelPrinterModel model, uint16_t width_mm, uint16_t length_mm);
