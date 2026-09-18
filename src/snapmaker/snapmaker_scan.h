#pragma once
#include <stdint.h>

enum SnapmakerScanResult {
  SNAPMAKER_SCAN_OK,
  SNAPMAKER_SCAN_NO_AUTH,
  SNAPMAKER_SCAN_PARTIAL
};

SnapmakerScanResult scanSnapmakerTag(uint8_t *uid, uint8_t uid_len);
