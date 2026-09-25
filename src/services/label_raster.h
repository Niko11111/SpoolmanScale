#pragma once

#include <stddef.h>
#include <stdint.h>

// ============================================================
//  A LABEL AS THE PRINTER TAKES IT
//
//  One bit per pixel, rows top to bottom, each row starting on
//  a byte, most significant bit first, 1 is black. Width is the
//  print row the head expects (576 dots on an M220), and the
//  label's content sits right-aligned in it, because that is
//  where the label stock runs on the M-series: content_width
//  says how much of the row is label. The pixels live in PSRAM
//  and belong to whoever built the raster; labelRasterFree()
//  gives them back.
// ============================================================

#define LABEL_RASTER_MIN_W  384
#define LABEL_RASTER_MAX_W  1024
#define LABEL_RASTER_MAX_BYTES (256u * 1024u)

struct LabelRaster {
  uint16_t width, height, row_bytes;
  uint8_t* pixels;
  size_t   length;
  uint16_t content_width;
};

inline bool labelRasterShapeValid(uint16_t width, uint16_t height,
                                  uint16_t row_bytes, size_t length) {
  return width >= LABEL_RASTER_MIN_W && width <= LABEL_RASTER_MAX_W && height > 0 &&
         row_bytes == (width + 7) / 8 &&
         length <= LABEL_RASTER_MAX_BYTES && length == size_t(row_bytes) * height;
}

// True when the shape holds and the unused low bits at the end of every row
// are zero: a printer reads them as pixels.
inline bool labelRasterValid(const LabelRaster& image) {
  if (!image.pixels || !labelRasterShapeValid(image.width, image.height,
                                              image.row_bytes, image.length)) return false;
  const unsigned unused = (8 - image.width % 8) % 8;
  if (!unused) return true;
  const uint8_t mask = (1u << unused) - 1;
  for (uint16_t y = 0; y < image.height; ++y)
    if (image.pixels[size_t(y + 1) * image.row_bytes - 1] & mask) return false;
  return true;
}

void labelRasterFree(LabelRaster* image);
