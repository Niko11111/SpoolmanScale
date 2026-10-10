#include "services/label_bmp.h"

#include <string.h>

#define BMP_FILE_HEADER_BYTES 14
#define BMP_INFO_HEADER_BYTES 40
#define BMP_PX_PER_METRE      7992   // 203 dpi; only a hint for whoever saves it

static void putLe16(uint8_t* p, uint16_t v) { p[0] = v & 0xff; p[1] = v >> 8; }
static void putLe32(uint8_t* p, uint32_t v) {
  for (int i = 0; i < 4; i++) p[i] = (v >> (8 * i)) & 0xff;
}

void labelBmpHeader(uint16_t width, uint16_t height, uint8_t out[LABEL_BMP_HEADER_BYTES]) {
  memset(out, 0, LABEL_BMP_HEADER_BYTES);
  out[0] = 'B';
  out[1] = 'M';
  putLe32(out + 2, labelBmpFileBytes(width, height));
  putLe32(out + 10, LABEL_BMP_HEADER_BYTES);              // pixel data offset
  uint8_t* info = out + BMP_FILE_HEADER_BYTES;
  putLe32(info, BMP_INFO_HEADER_BYTES);
  putLe32(info + 4, width);
  putLe32(info + 8, height);                               // positive: bottom row first
  putLe16(info + 12, 1);                                   // planes
  putLe16(info + 14, 1);                                   // bits per pixel
  putLe32(info + 20, labelBmpRowBytes(width) * height);
  putLe32(info + 24, BMP_PX_PER_METRE);
  putLe32(info + 28, BMP_PX_PER_METRE);
  putLe32(info + 32, 2);                                   // colours in the palette
  // Index 0 white, index 1 black: a set bit is a black dot, as in the raster.
  uint8_t* palette = info + BMP_INFO_HEADER_BYTES;
  palette[0] = palette[1] = palette[2] = 0xff;
}

static bool rasterBit(const LabelRaster& image, uint32_t x, uint16_t y) {
  if (x >= image.width || y >= image.height || !image.pixels) return false;
  return (image.pixels[size_t(y) * image.row_bytes + x / 8] >> (7 - x % 8)) & 1;
}

void labelBmpRow(const LabelRaster& image, uint16_t x0, uint16_t width,
                 uint16_t file_row, uint8_t* out) {
  const uint32_t bytes = labelBmpRowBytes(width);
  memset(out, 0, bytes);
  if (file_row >= image.height) return;
  const uint16_t y = image.height - 1 - file_row;
  for (uint32_t x = 0; x < width; x++)
    if (rasterBit(image, uint32_t(x0) + x, y)) out[x / 8] |= 0x80 >> (x % 8);
}
