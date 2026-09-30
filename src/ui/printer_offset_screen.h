#pragma once

// ============================================================
//  PRINT POSITION
//
//  The screen behind the "Print position" row of the printer
//  screen: where the roll runs under the head, set in whole
//  millimetres with - and +, and the calibration page that says
//  which number to set. The same setting as the card on the
//  browser's printer page, for a scale with no computer next to
//  it; the preset buttons stay in the browser.
//
//  The buttons change the number on screen at once and the loop
//  saves it once they rest: holding + would otherwise write NVS
//  ten times a second.
// ============================================================

void buildPrinterOffsetScreen();
void closePrinterOffsetScreen();
// Hides it with the other overlays; navigation calls this.
void hidePrinterOffsetScreen();
void showPrinterOffsetScreen();
// From the loop: saves a changed offset once the buttons have rested.
void printerOffsetTick();
// Saves a changed offset now, before a print that has to use it.
void printerOffsetFlush();
