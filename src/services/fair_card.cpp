#include "services/fair_card.h"

#include <esp_heap_caps.h>

#include "hardware/sd_logger.h"
#include "services/fair_card_bitmap.h"
#include "services/prefs_store.h"

// NVS content: 15 characters at most.
#define FC_KEY "fair_card"
// What the picture is drawn for.
#define FC_DPI       300
#define FC_ROLL_W_MM 50
#define FC_ROLL_H_MM 30

static bool s_loaded = false;
static bool s_on = false;

bool fairCardEnabled() {
  if (!s_loaded) {
    s_on = prefsGetBool(FC_KEY, false);
    s_loaded = true;
  }
  return s_on;
}

bool fairCardSetEnabled(bool on) {
  if (!prefsPutBool(FC_KEY, on)) return false;
  s_on = on;
  s_loaded = true;
  logSDf("Fair card: %s", on ? "on" : "off");
  return true;
}

// Only the setup the picture is drawn for: any other would print it cut off
// or out of scale, so the print card says the raster failed instead.
static bool fitsPrinter(const LabelPrinterConfig& p) {
  if (labelPrinterProfile(p.model).dpi != FC_DPI) return false;
  if (p.media_width_mm != FC_ROLL_W_MM || p.media_length_mm != FC_ROLL_H_MM) return false;
  return labelPrinterContentWidth(p.model, p.media_width_mm) == FAIR_CARD_W &&
         labelPrinterDotsForMm(p.model, p.media_length_mm) == FAIR_CARD_H;
}

bool labelRenderFairCard(const LabelPrinterConfig& printer, LabelRaster* out) {
  if (!out) return false;
  *out = LabelRaster{};
  if (!fitsPrinter(printer)) {
    logSD("Fair card: drawn for a 300 dpi printer with 50 x 30 loaded, not printed");
    return false;
  }
  const uint16_t row_w = labelPrinterRasterWidth(printer.model, printer.media_width_mm);
  const uint16_t x0 = labelPrinterContentX(printer);
  const uint16_t row_bytes = (row_w + 7) / 8;
  const size_t length = size_t(row_bytes) * FAIR_CARD_H;
  uint8_t* px = (uint8_t*)heap_caps_calloc(length, 1, MALLOC_CAP_SPIRAM);
  if (!px) { logSD("Fair card: no PSRAM for the raster"); return false; }
  // Dot by dot, so the picture lands where the stock runs in the row.
  for (uint16_t y = 0; y < FAIR_CARD_H; y++) {
    const uint8_t* src = FAIR_CARD_BITS + size_t(y) * FAIR_CARD_ROW_BYTES;
    uint8_t* row = px + size_t(y) * row_bytes;
    for (uint16_t x = 0; x < FAIR_CARD_W && x0 + x < row_w; x++) {
      if (!(src[x / 8] & (0x80 >> (x % 8)))) continue;
      const uint16_t rx = x0 + x;
      row[rx / 8] |= 0x80 >> (rx % 8);
    }
  }
  out->width = row_w;
  out->height = FAIR_CARD_H;
  out->row_bytes = row_bytes;
  out->pixels = px;
  out->length = length;
  out->content_width = FAIR_CARD_W;
  if (labelRasterValid(*out)) return true;
  labelRasterFree(out);
  return false;
}
