#pragma once

#include <stdint.h>

#include "services/ble_service.h"
#include "services/label_raster.h"

// ============================================================
//  NIIMBOT LABEL PRINTERS
//
//  The protocol the NIIMBOT app speaks over BLE, as niimbluelib
//  documents it (MIT; the facts, none of the code): framed packets
//  both ways, a model id the printer tells, and a print sequence
//  that differs by family, its "print task". The scale offers two
//  classes, the 50 mm direct thermal printers (B1, B21, B203 ...)
//  and the M2, a 300 dpi thermal transfer printer, and the id says
//  whether the printer at the other end is one of the picked class.
//
//  Every request and reply goes to the SD log by command id: no
//  NIIMBOT is on the desk here, so a tester's log is all there is.
// ============================================================

enum NiimbotClass : uint8_t { NB_CLASS_B = 0, NB_CLASS_M2 = 1 };
enum NiimbotTask  : uint8_t { NB_TASK_B1 = 0, NB_TASK_D110 = 1, NB_TASK_B21_V1 = 2 };
enum NiimbotDir   : uint8_t { NB_DIR_TOP = 0, NB_DIR_LEFT = 1 };

struct NiimbotModelInfo {
  uint16_t    id;
  const char* name;
  NiimbotTask task;
  uint16_t    head_px;          // dots in one print row
  uint16_t    dpi;
  NiimbotDir  dir;              // LEFT: a tape printer, the image runs along the feed
  bool        thermal_transfer; // prints through a ribbon
  bool        task_is_guess;    // niimbluelib maps no task to this id; see the table
};
const NiimbotModelInfo* niimbotModelById(uint16_t id);

enum NiimbotResult : uint8_t {
  NB_OK = 0,
  NB_TRANSPORT,        // the session failed; NiimbotJobInfo::transport says how
  NB_NO_REPLY,         // a request went unanswered
  NB_REJECTED,         // the printer answered "not supported"
  NB_MODEL_UNKNOWN,    // an id not in the table; it is in the log
  NB_MODEL_MISMATCH,   // a known printer, but not of the picked class
  NB_PRN_COVER,
  NB_PRN_NO_PAPER,
  NB_PRN_NO_RIBBON,    // none, the wrong one, or used up
  NB_PRN_BUSY,
  NB_PRN_ERROR,        // any other error code; it is in the log
  NB_UNCONFIRMED,      // all sent, the printer never reported the page done
};

struct NiimbotJobInfo {
  uint16_t model_id;
  const NiimbotModelInfo* info;
  uint8_t  connect_result, protocol_version, error_code;
  BleWriteResult transport;
  uint16_t packets_tx, packets_rx;
};

// Blocking, from appLoop() only, under the print card: opens the talk
// session, identifies the printer, prints the raster once, closes.
NiimbotResult niimbotPrint(const char* address, const LabelRaster& image, NiimbotClass cls,
                           BleProgressFn progress, NiimbotJobInfo* info);
// The error code's name for the log; "?" for one not in the list.
const char* niimbotErrorName(uint8_t code);
