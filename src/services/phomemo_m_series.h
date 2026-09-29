#pragma once

#include <stdint.h>

#include "services/ble_service.h"
#include "services/label_raster.h"

// ============================================================
//  PHOMEMO M-SERIES OVER BLE
//
//  The byte protocol of the M220 and its siblings: ESC/POS-like
//  raster commands into one GATT characteristic. The M220 is
//  hardware proven (Dan's fork, 2026-09); the M110 and M100
//  speak the same transport with their own preamble, proven
//  on an M100 by a user (09.2026). The transport is
//  ble_service's write session; this file only assembles the
//  blocks. Informed by the MIT-licensed myphomemo project.
// ============================================================

// PHOMEMO_M110 is a byte set: the M110 and the M100 both take it.
enum PhomemoModel : uint8_t { PHOMEMO_NONE = 0, PHOMEMO_M220 = 1, PHOMEMO_M110 = 2 };

// The GATT endpoint every M-series printer exposes.
#define PHOMEMO_SERVICE_UUID 0xff00
#define PHOMEMO_WRITE_UUID   0xff02
// Status from the printer: "01 01" per chunk taken, "1A 0F 0C" when a job
// has printed (read off the M220, 24.09.2026).
#define PHOMEMO_STATUS_UUID  0xff03

// Sends one raster. The raster must already fit the head; the printer
// service checks that. Returns the transport's verdict.
BleWriteResult phomemoMSeriesPrint(PhomemoModel model, const char* address,
                                   const LabelRaster& image, BleProgressFn progress);
