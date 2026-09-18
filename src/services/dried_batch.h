#pragma once

#include <stdint.h>

#include "services/ams_slots.h"

// ============================================================
//  DRIED BATCH
//
//  Records one drying date on several spools at once, on a task of
//  its own. The AMS card offers it for an AMS 2 Pro, which dries up
//  to four spools in one cycle: written one after the other on the
//  loop that would be up to eight requests on FilaMan with the
//  panel frozen, so the requests run here while the loop keeps
//  drawing.
//
//  Same shape as the web jobs and the update check: core 0, below
//  the loop in priority, stack from the heap for as long as it
//  runs, one batch at a time. The task touches no LVGL and no NVS;
//  the loop collects the result with driedBatchResult() and draws
//  it. The timestamp is taken on the loop at the moment of the
//  answer and handed in, so every spool gets the same one.
// ============================================================

#define DRIED_BATCH_MAX      AMS_MAX_TRAYS
// The code of a spool the batch never got to, because it was cancelled.
#define DRIED_BATCH_NOT_RUN  0

enum DriedBatchState : uint8_t {
  DBS_IDLE = 0,
  DBS_RUNNING,
  DBS_DONE
};

struct DriedBatchResult {
  int     spool_id[DRIED_BATCH_MAX];
  int     code[DRIED_BATCH_MAX];   // HTTP per spool, DRIED_BATCH_NOT_RUN when skipped
  char    iso[32];                 // the one stamp every spool was given
  int     printer_id;
  uint8_t ams_id;
  uint8_t count;
  uint8_t ok;                      // spools answered with 200
};

// Starts the batch. False when one is still running or not yet collected,
// when there is nothing to write, or when the heap is too low for the task.
bool driedBatchStart(int printer_id, uint8_t ams_id, const int* spool_ids,
                     uint8_t n, const char* iso);

DriedBatchState driedBatchState();

// Running, or done and not yet collected. Either way the spools in it are
// spoken for, and nothing else may write their drying date.
bool driedBatchBusy();

// Whether this spool is part of a batch that is still busy.
bool driedBatchContains(int spool_id);

// The codes and ok are valid once the state is DBS_DONE. The spools, the
// unit and the stamp are written before the batch starts and hold for as
// long as it is busy, so a card can ask whose batch is running.
const DriedBatchResult& driedBatchResult();

// Hands the slot back. Only from DBS_DONE.
void driedBatchTake();

// Skips the spools not yet started. A request already on the wire cannot be
// called back; it finishes against the settings it started with.
void driedBatchCancel();
