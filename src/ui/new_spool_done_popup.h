#pragma once

#include <lvgl.h>

// ============================================================
//  NEW SPOOL WITHOUT A TAG: THE CARD AT THE END
//
//  Says the number of the spool just created, large, since without a tag it
//  is the only way back to it ("Spool by ID"). With a label printer, or on
//  FilaMan with its PC print, a Label button prints the spool shown, which
//  is this one once the id spool took it. Built from the loop
//  (finishCopyFlow()), closed by its buttons and when another spool comes
//  onto the display.
// ============================================================

// Loop task only: it reads the printer settings. `shown` is whether the
// spool made it onto the display, without which there is nothing to print.
void showNewSpoolDone(int spool_id, bool shown);

// The price did not reach the server: the card says so in place of its tick.
// Nothing happens when the card is not open.
void newSpoolDonePriceLost();

void newSpoolDoneTick();
lv_obj_t* newSpoolDoneScreen();
