#pragma once

#include <stddef.h>
#include <stdint.h>

#include "services/label_raster.h"

// ============================================================
//  A LABEL AS A PICTURE FOR THE BROWSER
//
//  The label part of a print raster as a 1-bit BMP: the bytes the
//  printer would get, cut to the label, so the preview in the
//  browser is the print and not a drawing of it. BMP because
//  every browser decodes it and it needs no encoder; at one bit
//  per dot a 50 x 30 label is 12 KB. Pure: no LVGL, no network.
// ============================================================

#define LABEL_BMP_HEADER_BYTES 62   // file and info header, two palette entries

// BMP pads every row to four bytes.
inline uint32_t labelBmpRowBytes(uint16_t width) { return ((uint32_t(width) + 31) / 32) * 4; }
inline uint32_t labelBmpFileBytes(uint16_t width, uint16_t height) {
  return LABEL_BMP_HEADER_BYTES + labelBmpRowBytes(width) * height;
}

void labelBmpHeader(uint16_t width, uint16_t height, uint8_t out[LABEL_BMP_HEADER_BYTES]);

// File row `file_row` (0 is the bottom row, as BMP stores it) of the raster's
// columns x0 .. x0 + width - 1, into labelBmpRowBytes(width) bytes. Columns
// outside the raster come out white.
void labelBmpRow(const LabelRaster& image, uint16_t x0, uint16_t width,
                 uint16_t file_row, uint8_t* out);
