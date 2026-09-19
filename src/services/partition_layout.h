#pragma once

#include <stdint.h>

// ============================================================
//  FLASH LAYOUT, AS THE RUNNING FIRMWARE SEES IT
// ============================================================
//
// The partition table is written once, over USB, and OTA never touches it.
// Every device flashed before September 2026 therefore keeps two 3 MB app
// slots for good, while the table shipped since then gives 5 MB per slot, a
// core dump partition and a data area. One firmware runs on both, as long as
// it fits the smaller slot, and the only way onto the new table is a flash
// over USB. This tells the owner that, once, and shows the state on the
// status page. Nothing here changes anything.

struct PartitionLayout {
  uint32_t app_slot_bytes;   // one OTA slot; both are the same size by design
  uint32_t app_used_bytes;   // the image that is running
  uint32_t data_bytes;       // the data partition labelled spiffs, 0 without one
  bool     has_coredump;
  bool     current;          // slots as large as the table this firmware ships with
};

// Read once, on first use, and logged that one time.
const PartitionLayout& partitionLayout();

// The hint on the device: an old layout, not dismissed for good, and not yet
// shown this boot. OK closes it until the next boot, never keeps that in NVS.
bool partitionHintDue();
void partitionHintShown();
void partitionHintNever();
