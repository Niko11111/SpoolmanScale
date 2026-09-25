#pragma once

#include <stdint.h>

#include "services/ble_service.h"
#include "services/label_raster.h"

// ============================================================
//  PHOMEMO M-SERIES OVER BLE
//
//  The byte protocol of the M220 and its siblings: ESC/POS-like
//  raster commands into one GATT characteristic. The M220 is
//  hardware proven (Dan's fork, 2026-09); the M110 speaks the
//  same transport with its own preamble and is carried as
//  experimental until someone prints on one. The transport is
//  ble_service's write session; this file only assembles the
//  blocks. Informed by the MIT-licensed myphomemo project.
// ============================================================

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
