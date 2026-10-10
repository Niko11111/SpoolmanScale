#pragma once

#include "services/label_render.h"

// ============================================================
//  THE SPOOL A LABEL IS FOR
//
//  The data a spool label carries, taken from what the scan left
//  in the globals. The display forgets a spool as soon as it
//  leaves the pad; the label editor in the browser shows the last
//  one scanned, so a copy is kept here when the display lets go.
//  The dates are not part of the scan: they are asked of the
//  backend once per spool and kept with the copy.
// ============================================================

// The spool on the pad as the backend named it. False when none was found.
bool labelSpoolFromScan(SpoolLabelData* out);

// Keeps the spool on the pad, if any, as the last one scanned. Called right
// before the scan state is cleared.
void labelSpoolRemember();

// The spool on the pad, else the last one remembered, with the dates as far
// as they are known. False when no spool has been found since boot.
bool labelSpoolLast(SpoolLabelData* out);

// Whether the dates of the last spool have been asked for. When not, the
// next labelSpoolTick() asks the backend, once.
bool labelSpoolDatesKnown();

// Asks the backend for a spool's dates and fills both into `d`. Makes an HTTP
// request: from the loop only, never from a handler.
void labelSpoolFetchDates(SpoolLabelData* d);

// From the loop: fetches the dates the browser's preview is waiting for.
void labelSpoolTick();
