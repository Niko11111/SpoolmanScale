#pragma once

#include <stdint.h>

// ============================================================
//  FLASH LAYOUT, AS THE RUNNING FIRMWARE SEES IT
// ============================================================
//
// The partition table is written once, over USB, and OTA never touches it.
// Every device flashed before September 2026 therefore keeps two 3 MB app
// slots for good, while the table shipped since then gives 6 MB per slot, a
// core dump partition and a data area. One firmware runs on both, as long as
// it fits the smaller slot, and the only way onto the new table is a flash
// over USB. This tells the owner that, with every boot, and shows the state on the
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

// Whether an image of this many bytes fits the running device's app slot.
// 0 means the size is unknown, and that is let through: the download itself
// is refused by Update.begin() when it does not fit, without harm.
bool partitionImageFits(uint32_t image_bytes);

// An update was found that does not fit this device's slot. The hint then
// names it and comes up again, even when it was closed earlier this boot.
void partitionNoteTooBig(const char* version, uint32_t image_bytes);
// The version noted above, "" while none was.
const char* partitionTooBigVersion();
// Whether this tag is the one noted as too large. Asked wherever a version is
// about to be installed or remembered: gh_latest_version can hold one a check
// found too large while an earlier, fitting one keeps the badge lit.
bool partitionTagTooBig(const char* tag);

// The hint on the device: an old layout and not yet closed this boot. It comes
// back with every boot until the scale is on the current layout - more
// insistent than before on purpose, because the next update may no longer fit
// (Nikolai, 26.09.2026). There is no "never again".
bool partitionHintDue();
void partitionHintShown();
