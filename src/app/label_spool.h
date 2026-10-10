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

// Drops the last spool and its dates: they belong to the server the scale
// just stopped talking to. From a switch of backend or host.
void labelSpoolForget();

// The spool on the pad, else the last one remembered, with the dates as far
// as they are known. False when no spool has been found since boot.
bool labelSpoolLast(SpoolLabelData* out);

// Whether the dates of the last spool have been asked for. When not, the
// next labelSpoolTick() asks the backend, once.
bool labelSpoolDatesKnown();

// Fills a spool's dates into `d`: from the last spool's copy where it knows
// them, else from the backend, and only on an answer. Makes an HTTP request:
// from the loop only, never from a handler.
void labelSpoolFetchDates(SpoolLabelData* d);

// From the loop: starts the fetch of the dates the browser's preview is
// waiting for on a task of its own, and takes its answer on a later pass.
void labelSpoolTick();
