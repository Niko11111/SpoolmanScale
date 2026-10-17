#pragma once
// ============================================================
//  label_buttons.h - the print buttons in the More info header
//  sdfp fork addition (SPOOLMANSCALE-SDFP.md, section 5b)
// ============================================================
#include <lvgl.h>

// Left of the X. Without a label service: upstream's single "Print label".
// With one (services/label_fetch.h): "Spool label" and "Filament label", and
// the title moves to the left edge to make room. The caller checks that a
// print can happen at all (Bluetooth, a printer, a known spool).
void addLabelPrintButtons(lv_obj_t* hdr, lv_obj_t* title);
