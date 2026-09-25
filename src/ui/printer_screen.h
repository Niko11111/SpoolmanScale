#pragma once

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
