#pragma once

#include <stddef.h>
#include <stdint.h>

#include "services/label_layout.h"

// ============================================================
//  LABEL PRINTER
//
//  The screen behind the "Printer" row of the Bluetooth
//  screen: which device is the printer (picked on the device
//  card), its model, the label stock in it, a test print, and
//  the way to drop it. The one-time settings; the browser gets
//  the same ones for those who set up from the desk.
//
//  Every change and the test print run from appLoop(): a
//  change rebuilds the screen the row sits on, and the print
//  starts the BLE stack and blocks for seconds.
// ============================================================

void buildPrinterScreen();
void closePrinterScreen();
void handlePrinterDeferredActions();
// What the last test print came back with, as a StringID, or -1 for none
// since boot. The browser page shows it; the device shows a popup.
int printerLastTestResult();
// The same for the last spool label, printed from the device or the browser.
int printerLastLabelResult();
// The label of the spool on the pad, its own or its filament's, under the
// print card. From the loop: it starts the BLE stack and blocks.
void printerPrintPadLabel(LabelKind kind);
// The label of the last spool scanned, on the pad or not: what the print
// sheet and the browser's editor showed. From the loop, like the one above.
void printerPrintLastLabel(LabelKind kind);
// The next build of the screen is entered from the print sheet: its back
// button leads there instead of to the Bluetooth screen.
void printerScreenFromSheet();
// The loaded stock as a row shows it, "60 x 40 mm", and on a size nobody has
// checked "60 x 40 mm  \xE2\x80\xA2  unchecked".
void printerMediaText(char* buf, size_t n, uint16_t width_mm, uint16_t length_mm);
