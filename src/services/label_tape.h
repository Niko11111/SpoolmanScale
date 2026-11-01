#pragma once

#include "services/label_printer.h"
#include "services/label_raster.h"
#include "services/label_render.h"

// ============================================================
//  A LABEL FOR A TAPE PRINTER
//
//  The NIIMBOT D110's tape is 12 mm high and 40 mm long, too
//  small for any arrangement of the label editor: no code, no
//  band, no fact lines. It carries the maker, the material and
//  the filament's name on the left, one above the other, each
//  as large as the height and the width allow, and the spool's
//  number large on the right, the number alone, behind a rule.
//  The maker goes on as label_tape_name.h writes it.
//
//  The label is drawn lying, as it reads, and turned onto the
//  roll as an upright label is (LO_PORTRAIT), so the previews
//  turn it back the same way. NIIMBOT's app turns the other way
//  round; on the spool that is the same label.
// ============================================================

// The label for the printer's tape, the spool's number on it where
// `with_id` and the spool has one. `what` names it in the log. The raster
// is allocated in PSRAM; labelRasterFree() gives it back.
bool labelRenderTape(const LabelPrinterConfig& printer, const SpoolLabelData& d, bool with_id,
                     const char* what, LabelRaster* out);
