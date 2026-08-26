#include "i2c_scan.h"

#include <stdio.h>

#include "app_config.h"

// 0x00-0x07 and 0x78-0x7F are reserved by the I2C specification. Probing them
// is not just pointless, it is how a scan puts a bus into a state that only a
// power cycle leaves again.
#define I2C_SCAN_FIRST  0x08
#define I2C_SCAN_LAST   0x77

static char scan_last[I2C_SCAN_LINE_LEN] = "not scanned";

uint8_t i2cScan(TwoWire &wire, uint8_t *found, uint8_t max_found) {
  if (!found || max_found == 0) return 0;
  uint8_t n = 0;
  for (uint8_t addr = I2C_SCAN_FIRST; addr <= I2C_SCAN_LAST && n < max_found; addr++) {
    wire.beginTransmission(addr);
    if (wire.endTransmission() == 0) found[n++] = addr;
  }
  return n;
}

const char *i2cKnownName(uint8_t addr) {
  if (addr == I2C_ADDR_PN532)   return "PN532";
  if (addr == I2C_ADDR_NAU7802) return "NAU7802";
  return nullptr;
}

uint8_t i2cScanFormat(TwoWire &wire, char *out, size_t out_len) {
  uint8_t found[I2C_SCAN_MAX_FOUND];
  const uint8_t n = i2cScan(wire, found, I2C_SCAN_MAX_FOUND);

  if (!out || out_len == 0) return n;
  out[0] = '\0';
  if (n == 0) {
    snprintf(out, out_len, "nothing answers");
    return 0;
  }

  size_t used = 0;
  for (uint8_t i = 0; i < n; i++) {
    if (used + 1 >= out_len) break;
    const char *name = i2cKnownName(found[i]);
    const int w = snprintf(out + used, out_len - used, "%s0x%02X%s%s",
                           i ? ", " : "", found[i],
                           name ? " " : "", name ? name : "");
    if (w <= 0) break;
    used += (size_t)w;
    if (used >= out_len) break;   // truncated, snprintf has terminated it
  }
  return n;
}

void i2cScanRefresh(TwoWire &wire) {
  i2cScanFormat(wire, scan_last, sizeof(scan_last));
}

const char *i2cScanLast() {
  return scan_last;
}
