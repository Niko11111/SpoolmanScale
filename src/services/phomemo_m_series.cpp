#include "services/phomemo_m_series.h"

#include "hardware/sd_logger.h"

// GS v 0: raster bit image, width in bytes and height in dots, both little
// endian, followed by the rows.
static void rasterHeader(uint8_t out[8], uint16_t width, uint16_t height) {
  const uint16_t bytes = (width + 7) / 8;
  out[0] = 0x1d; out[1] = 0x76; out[2] = 0x30; out[3] = 0x00;
  out[4] = uint8_t(bytes);  out[5] = uint8_t(bytes >> 8);
  out[6] = uint8_t(height); out[7] = uint8_t(height >> 8);
}

// M220: ESC @ resets, ESC 7 sets the heat (the values the vendor app sends),
// ESC J feeds the label out past the tear bar.
static const uint8_t M220_INIT[]    = { 0x1b, 0x40 };
static const uint8_t M220_DENSITY[] = { 0x1b, 0x37, 0x07, 0x64, 0x64 };
static const uint8_t M220_FEED[]    = { 0x1b, 0x4a, 0x20 };

// M110: speed, density and media type in its own ESC N and US commands, and
// a footer pair that ends the print. Untested on hardware, see the header.
static const uint8_t M110_SPEED[]   = { 0x1b, 0x4e, 0x0d, 0x05 };
static const uint8_t M110_DENSITY[] = { 0x1b, 0x4e, 0x04, 0x0a };
static const uint8_t M110_MEDIA[]   = { 0x1f, 0x11, 0x0a };
static const uint8_t M110_FOOT_A[]  = { 0x1f, 0xf0, 0x05, 0x00 };
static const uint8_t M110_FOOT_B[]  = { 0x1f, 0xf0, 0x03, 0x00 };

// The printer's "job printed". It prints a 30 mm label in about 1.5 s after
// the last byte; the wait covers the longest roll with room to spare.
static const uint8_t PHOMEMO_DONE[] = { 0x1a, 0x0f, 0x0c };
#define PHOMEMO_DONE_WAIT_MS 15000
static const BleDone PHOMEMO_AWAIT = {
  PHOMEMO_STATUS_UUID, PHOMEMO_DONE, sizeof(PHOMEMO_DONE), PHOMEMO_DONE_WAIT_MS
};

BleWriteResult phomemoMSeriesPrint(PhomemoModel model, const char* address,
                                   const LabelRaster& image, BleProgressFn progress) {
  if (model == PHOMEMO_NONE || !labelRasterValid(image)) return BLE_WRITE_FAILED;
  uint8_t header[8];
  rasterHeader(header, image.width, image.height);
  logSDf("Phomemo: %s %ux%u (%u bytes) to %s",
         model == PHOMEMO_M220 ? "M220" : "M110",
         (unsigned)image.width, (unsigned)image.height, (unsigned)image.length, address);

  if (model == PHOMEMO_M220) {
    const BleBlock blocks[] = {
      { M220_INIT, sizeof(M220_INIT) },
      { M220_DENSITY, sizeof(M220_DENSITY) },
      { header, sizeof(header) },
      { image.pixels, image.length },
      { M220_FEED, sizeof(M220_FEED) },
    };
    return bleWriteBlocks(address, PHOMEMO_SERVICE_UUID, PHOMEMO_WRITE_UUID,
                          blocks, sizeof(blocks) / sizeof(blocks[0]), progress, &PHOMEMO_AWAIT);
  }
  const BleBlock blocks[] = {
    { M110_SPEED, sizeof(M110_SPEED) },
    { M110_DENSITY, sizeof(M110_DENSITY) },
    { M110_MEDIA, sizeof(M110_MEDIA) },
    { header, sizeof(header) },
    { image.pixels, image.length },
    { M110_FOOT_A, sizeof(M110_FOOT_A) },
    { M110_FOOT_B, sizeof(M110_FOOT_B) },
  };
  return bleWriteBlocks(address, PHOMEMO_SERVICE_UUID, PHOMEMO_WRITE_UUID,
                        blocks, sizeof(blocks) / sizeof(blocks[0]), progress, &PHOMEMO_AWAIT);
}
