#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// ============================================================
//  A LABEL AS THE PRINTER TAKES IT
//
//  One bit per pixel, rows top to bottom, each row starting on
//  a byte, most significant bit first, 1 is black. Width is the
//  print row the head expects (576 dots on an M220), and the
//  label's content sits where the stock runs in it, see
//  labelPrinterContentX(): content_width says how much of the
//  row is label. The pixels live in PSRAM
//  and belong to whoever built the raster; labelRasterFree()
//  gives them back.
// ============================================================

// The narrowest print row any profile sends: the D110's 96 dot head, 12 mm
// at 203 dpi. Was 160 (20 mm, the M110S's narrowest label, issue #55)
// before the tape printers.
#define LABEL_RASTER_MIN_W  96
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

// Moves every row `dots` to the right in place, white coming in from the
// left and whatever passes the row's end dropped. A raster drawn at the row's
// left edge, as a server sends it, lands where the stock runs. The unused low
// bits stay zero, so a valid raster stays valid.
inline void labelRasterShiftRight(LabelRaster* image, uint16_t dots) {
  if (!image || !image->pixels || dots == 0) return;
  const int bytes = dots / 8, bits = dots % 8;
  const unsigned unused = (8 - image->width % 8) % 8;
  const uint8_t tail = (uint8_t)~((1u << unused) - 1);
  for (uint16_t y = 0; y < image->height; ++y) {
    uint8_t* row = image->pixels + size_t(y) * image->row_bytes;
    for (int i = image->row_bytes - 1; i >= 0; --i) {
      const int src = i - bytes;
      uint8_t v = src >= 0 ? (uint8_t)(row[src] >> bits) : 0;
      if (bits && src - 1 >= 0) v |= (uint8_t)(row[src - 1] << (8 - bits));
      row[i] = v;
    }
    row[image->row_bytes - 1] &= tail;
  }
}

// Keeps the leftmost `width` dots of every row, in place: a raster drawn for
// a wider row with its label at the left edge becomes one `width` wide. False,
// and nothing changed, when the label itself is wider than that.
inline bool labelRasterCropWidth(LabelRaster* image, uint16_t width) {
  if (!image || !image->pixels || width < LABEL_RASTER_MIN_W || width > image->width ||
      image->content_width > width) return false;
  const uint16_t row_bytes = (width + 7) / 8;
  const unsigned unused = (8 - width % 8) % 8;
  const uint8_t tail = (uint8_t)~((1u << unused) - 1);
  for (uint16_t y = 0; y < image->height; ++y) {
    uint8_t* row = image->pixels + size_t(y) * row_bytes;
    memmove(row, image->pixels + size_t(y) * image->row_bytes, row_bytes);
    row[row_bytes - 1] &= tail;
  }
  image->width = width;
  image->row_bytes = row_bytes;
  image->length = size_t(row_bytes) * image->height;
  return true;
}

void labelRasterFree(LabelRaster* image);
