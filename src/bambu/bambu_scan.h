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

// Whether the card itself refused a Bambu key in the last scanTag() - it
// answered and turned the key down - rather than never answering. A Bambu chip
// opens with these keys, so a refusal says "no Bambu chip"; silence says
// nothing, a weak Bambu chip on the edge of the field is silent too.
bool bambuScanCardRefused();

// One SD line for the attempts scanTag() made on the tag since the last
// report: read, how complete, after how many attempts, and what it says.
// From the NFC poll once the placement has settled - read in full or out of
// retries - and when the tag leaves before that. Nothing when no attempt ran
// since the last call. The per attempt lines are verbose only.
void bambuScanReport();
