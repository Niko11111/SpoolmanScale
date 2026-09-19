#pragma once

// The one time note that this device still runs on the old partition table
// and what a flash over USB would give it - see services/partition_layout.h.
// Two ways out, as with the NFC reset hint: OK until the next boot, or never
// again.
void showPartitionHint();
void closePartitionHint();
