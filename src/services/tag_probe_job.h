#pragma once

#include <stdint.h>

// ============================================================
//  TAG PROBE JOB
//
//  The recheck asks every few seconds whether an unknown tag on the pad has
//  been linked in the meantime. Asked on the loop, each probe held touch,
//  display and scale for its whole round trip: 514 ms median, 1.7 s p90 and
//  4.3 s p99 over 518 windows on 24./25.09.2026, every 4 s for as long as the
//  tag lay there.
//
//  This runs the probe on its own task, the shape of backend_job.cpp: core 0,
//  below the loop in priority, the stack taken from the heap for as long as
//  it runs. The loop starts it, keeps looping, and collects the answer on a
//  later pass.
//
//  Nothing in here touches LVGL, NVS or the lookup's state. The result
//  carries the query and the backend generation it was asked under, so the
//  loop can drop an answer about a tag or a server that is no longer current.
// ============================================================

enum TagProbeState : uint8_t {
  TPS_IDLE = 0,
  TPS_RUNNING,
  TPS_DONE
};

struct TagProbeResult {
  bool     hit;           // the backend knows a spool by this tag
  bool     unanswered;    // the server never answered
  int      spool_id;      // the spool that matched, 0 without a hit
  uint32_t gen;           // backendGeneration() at the start
  uint32_t ms;            // how long the probe took
  char     query[80];     // the tag it asked about
};

// Starts a probe for `query` against the current backend. False when one is
// already running or waiting to be collected, the heap is too low for the
// task's stack, or the task could not be created.
bool tagProbeStart(const char* query);

TagProbeState tagProbeState();

// Valid while the state is TPS_DONE.
const TagProbeResult& tagProbeResult();

// Frees the slot. Once per result, after reading it.
void tagProbeTake();
