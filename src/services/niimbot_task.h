#pragma once

#include <stdint.h>

// ============================================================
//  WHICH PRINT SEQUENCE A NIIMBOT GETS
//
//  The NIIMBOT driver's decisions that need no Bluetooth: the
//  protocol version a printer's status data tells, the print
//  task ("print sequence") for a model at that version, and
//  which model ids are the D110. All of it as niimbluelib has it
//  (packet_parser.ts, print_tasks/index.ts). Pure: no Arduino.
// ============================================================

enum NiimbotTask : uint8_t {
  NB_TASK_B1 = 0, NB_TASK_D110 = 1, NB_TASK_B21_V1 = 2,
  // niimbluelib's D110M_V4: a D110 M whose firmware speaks protocol 4.
  // Never in the model table; niimbotTaskFor() picks it from the version.
  NB_TASK_V4 = 3,
};

#define NB_ID_D110_A   2304
#define NB_ID_D110_B   2305
#define NB_ID_D110_M   2320

// The protocol version from the status data's version number (its two
// bytes as hi * 100 + lo): 3, 4 or 5, 0 below protocol 3.
uint8_t niimbotProtocolFromStatus(unsigned version);

// The task for a model at a protocol version: the model table's, except
// where niimbluelib matches a model and a version exactly. Only the D110 M
// on protocol 4 so far; on 5 it falls back to the table, as there.
NiimbotTask niimbotTaskFor(uint16_t model_id, NiimbotTask table_task, uint8_t proto);

// The D110 and the D110 M, the printers of the D110 class.
bool niimbotIsD110(uint16_t model_id);
