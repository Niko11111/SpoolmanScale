#pragma once

#include <Arduino.h>
#include <stdint.h>

// ============================================================
//  WEB JOBS
//
//  Four things a browser can ask for take seconds to answer: a test of the
//  backend address, the spool list for the tags page, the GitHub check and
//  the release notes. Answered inside the HTTP handler they held the loop
//  task - display, scale, NFC, FilaMan's device protocol - for up to eight
//  seconds, because the handler runs on that task.
//
//  Now the handler starts a job and answers 202. The job runs on its own
//  task, the same shape as the daily update check (core 0, below the loop
//  in priority, stack from the heap for as long as it runs), and the
//  browser asks the same URL again until the answer is ready. One job at a
//  time: a second TLS handshake beside the first is 40 kB the device does
//  not have twice.
//
//  What must not run on the second task stays out of it: LVGL, NVS and the
//  badges are touched by the handler that collects the result, on the loop
//  task; logSD() queues lines from other tasks; the stall counters only
//  count the loop task's own waits.
// ============================================================

enum WebJobKind : uint8_t {
  WJ_NONE = 0,
  WJ_HOST_TEST,   // GET the backend's health, 4 s
  WJ_SPOOLS,      // the spool list for the tags page, 8 s
  WJ_GH_CHECK,    // the latest tag on the chosen channel, TLS
  WJ_GH_NOTES     // one release's notes, TLS
};

enum WebJobState : uint8_t {
  WJS_IDLE = 0,
  WJS_RUNNING,
  WJS_DONE
};

struct WebJobResult {
  WebJobKind kind;
  bool   ok;
  int    code;        // the HTTP code behind the answer, where there is one
  char   err[80];     // why not, when ok is false
  char   tag[40];     // GH check: the tag found
  char   pub[24];     // GH check: when it was published
  uint32_t image_size; // GH check: the firmware image's size, 0 when unknown
  String body;        // a ready made reply body, for the jobs that have one
};

// Starts a job. `arg` is the release tag for WJ_GH_NOTES, unused otherwise;
// `flag` is the pre-release channel for WJ_GH_CHECK. False when a job is
// already running or the heap is too low for a second task.
bool webJobStart(WebJobKind kind, const char* arg, bool flag);

WebJobState webJobState();
WebJobKind  webJobKind();

// The result, valid while the state is WJS_DONE. webJobTake() hands the slot
// back; a handler calls it once it has sent the answer.
const WebJobResult& webJobResult();
void webJobTake();

// From appLoop(): drops a result no browser came back for.
void webJobsTick();
