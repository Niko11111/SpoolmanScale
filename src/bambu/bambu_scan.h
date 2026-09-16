#pragma once

#include <stdint.h>

#include "bambu_tag.h"

enum BambuScanResult {
  BAMBU_SCAN_OK = 0,
  BAMBU_SCAN_FAIL_SECTOR_0,
  BAMBU_SCAN_FAIL_OTHER
};

int countBambuDataBlocksRead(const BambuTagData& tag);
BambuScanResult scanTag(uint8_t *uid, uint8_t uid_len);
