#pragma once

// The NFC scan of the loop task. The NFC bus belongs to this task: both run
// from appLoop() only, in their places there.

// The way back for a reader that failed at boot or locked up. Before
// diagnosticsTick(), as it always ran.
void tagReaderRecoverTick();

// One pass of the scan: the read-rate measurement, the poll and what the tag
// it found (or the lack of one) leads to. Called on every pass, after the
// scale and before the link button bar.
void tagScanTick();
