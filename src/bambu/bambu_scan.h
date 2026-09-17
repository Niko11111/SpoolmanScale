#pragma once

#include <stdint.h>

#include "bambu_tag.h"

// What a scan ended with. The loop does not branch on it today - its retry
// logic works from the blocks that made it into g_tag - but the log inside
// scanTag() says which of these it was.
enum BambuScanResult {
  BAMBU_SCAN_OK = 0,    // every sector read
  BAMBU_SCAN_PARTIAL,   // some sectors refused, the rest is in g_tag
  BAMBU_SCAN_NO_AUTH    // the probe sectors all refused, scan aborted early
};

int countBambuDataBlocksRead(const BambuTagData& tag);
BambuScanResult scanTag(uint8_t *uid, uint8_t uid_len);
