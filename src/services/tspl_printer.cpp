#include "services/tspl_printer.h"

#include <stdlib.h>

#include <esp_heap_caps.h>
#include "hardware/sd_logger.h"

BleWriteResult tsplPrint(const char* address, const LabelRaster& image,
                         uint16_t width_mm, uint16_t length_mm, BleProgressFn progress) {
  if (!address || !address[0] || !labelRasterValid(image)) return BLE_WRITE_FAILED;

  char header[160], footer[24];
  const TsplJob job = { width_mm, length_mm, image.row_bytes, image.height };
  const int hn = tsplHeader(header, sizeof(header), job);
  const int fn = tsplFooter(footer, sizeof(footer));
  if (hn < 0 || fn < 0) return BLE_WRITE_FAILED;

  // The caller keeps its raster as it is; the inverted copy lives in PSRAM
  // like the raster does, internal RAM when there is none.
  uint8_t* inverted = (uint8_t*)heap_caps_malloc(image.length, MALLOC_CAP_SPIRAM);
  if (!inverted) inverted = (uint8_t*)malloc(image.length);
  if (!inverted) {
    logSDf("TSPL: no memory for %u bytes", (unsigned)image.length);
    return BLE_WRITE_FAILED;
  }
  tsplInvert(image.pixels, inverted, image.length);

  logSDf("TSPL: %ux%u dots (%u bytes) on %ux%u mm to %s", (unsigned)image.width,
         (unsigned)image.height, (unsigned)image.length, (unsigned)width_mm,
         (unsigned)length_mm, address);

  const BleBlock blocks[] = {
    { (const uint8_t*)header, (size_t)hn },
    { inverted, image.length },
    { (const uint8_t*)footer, (size_t)fn },
  };
  // The printer notifies on ff03 (seen with nRF Connect on a PM245-BT, which
  // advertises as QR380A-245-xxxx). What its notifications mean is not
  // documented, so none of them is taken as "done": the session subscribes
  // (some printers want that before they take data), logs what arrives, and
  // stays a few seconds so the printer can take the whole job. Printed on a
  // PM245-BT this way (09.11.2026). With no done signal to wait for, "sent" is
  // the whole truth and is reported as a success, not as "unconfirmed".
  static const uint8_t NEVER[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
  static const BleDone AWAIT = { TSPL_STATUS_UUID, NEVER, sizeof(NEVER), TSPL_WAIT_MS };
  const BleWriteResult r = bleWriteBlocks(address, TSPL_SERVICE_UUID, TSPL_WRITE_UUID, blocks,
                                          sizeof(blocks) / sizeof(blocks[0]), progress, &AWAIT);
  heap_caps_free(inverted);   // frees PSRAM and internal memory alike
  return r == BLE_WRITE_SENT_UNCONFIRMED ? BLE_WRITE_OK : r;
}
