#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "services/ble_service.h"
#include "services/label_raster.h"

// ============================================================
//  TSPL LABEL PRINTERS OVER BLE
//
//  The 4 x 6 inch class of shipping label printers (Phomemo PM241-BT
//  and PM245-BT) takes TSPL, the text command language of TSC
//  printers: SIZE, GAP, DIRECTION, DENSITY, CLS, then one BITMAP and
//  PRINT. Over USB and Bluetooth Classic that is the whole story.
//  The ESP32-S3 has no Bluetooth Classic, so the job goes the way
//  the vendor's browser extension reaches the printer: BLE, the
//  Phomemo ff00 service, characteristic ff02.
//
//  Printed on a PM245-BT (09.11.2026), so the BLE side takes a job on ff02
//  as it is. Known: TSPL is the language of the family, a bit of 0 is black
//  in BITMAP mode 0 (the scale's rasters are 1 = black, so they are inverted
//  on the way out). Not known: the PM241-BT, which has not been tried, and
//  what the printer reports on ff03. If a print comes out mirrored or upside
//  down, TSPL_DIRECTION is the first thing to flip.
//
//  The header carries the pure parts (command text, bit inversion)
//  so a host test can compile them; the BLE part is in the .cpp.
// ============================================================

#define TSPL_SERVICE_UUID 0xff00
#define TSPL_WRITE_UUID   0xff02
#define TSPL_STATUS_UUID  0xff03
// How long the link stays open after the last byte, in ms.
#define TSPL_WAIT_MS      6000

// 0 or 1: which way the label leaves the printer. 1 is what USB users of
// 4 x 6 TSPL printers send with a bitmap.
#define TSPL_DIRECTION 1
// 0..15, 8 is the middle. Direct thermal paper wants more than a ribbon.
#define TSPL_DENSITY   8
// The gap between labels on the roll, in mm. Die-cut stock has 2 to 3.
#define TSPL_GAP_MM    3

// What the header says about the label and its bitmap.
struct TsplJob {
  uint16_t width_mm, length_mm;   // the loaded stock
  uint16_t row_bytes, height;     // the bitmap: bytes per row, rows
};

// Everything before the pixels, as text. Returns the length, or -1 when it
// did not fit.
inline int tsplHeader(char* out, size_t cap, const TsplJob& job) {
  const int n = snprintf(out, cap,
                         "SIZE %u mm,%u mm\r\n"
                         "GAP %u mm,0 mm\r\n"
                         "DIRECTION %u\r\n"
                         "DENSITY %u\r\n"
                         "CLS\r\n"
                         "BITMAP 0,0,%u,%u,0,",
                         (unsigned)job.width_mm, (unsigned)job.length_mm, (unsigned)TSPL_GAP_MM,
                         (unsigned)TSPL_DIRECTION, (unsigned)TSPL_DENSITY,
                         (unsigned)job.row_bytes, (unsigned)job.height);
  return (n < 0 || size_t(n) >= cap) ? -1 : n;
}

// After the pixels: ends the BITMAP line and prints one copy.
inline int tsplFooter(char* out, size_t cap) {
  const int n = snprintf(out, cap, "\r\nPRINT 1,1\r\n");
  return (n < 0 || size_t(n) >= cap) ? -1 : n;
}

// The scale draws 1 = black, TSPL's BITMAP mode 0 takes 0 = black. The unused
// bits at the end of a row turn into 1, which is white there.
inline void tsplInvert(const uint8_t* in, uint8_t* out, size_t n) {
  for (size_t i = 0; i < n; ++i) out[i] = (uint8_t)~in[i];
}

// Blocking, from appLoop() only. The raster must already fit the label: the
// printer service checks that. width_mm and length_mm are the loaded stock.
BleWriteResult tsplPrint(const char* address, const LabelRaster& image,
                         uint16_t width_mm, uint16_t length_mm, BleProgressFn progress);
