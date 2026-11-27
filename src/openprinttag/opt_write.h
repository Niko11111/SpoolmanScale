#pragma once

// The remaining weight onto an OpenPrintTag (PN7160 only), as the format
// keeps it: consumed_weight in the aux region, the tag's full weight minus
// what is left. With the switch g_opt_write_weight on, after a weight the
// backend took for the spool of the tag on the reader ("Update weight", the
// automatic send, the questions in front of them). Off by default: a Prusa
// printer writes the same field (Nikolai, 26.11.2026).
//
// Only the aux region is written, only the blocks that change, each read
// back; maker data, meta and workgroup are never touched (opt_aux.h). The NFC
// bus belongs to the loop task: the backend call parks the write, the loop
// carries it out.

// The weight the backend has just taken. Parked only while the switch is on
// and a decoded OpenPrintTag lies on a PN7160.
void optWeightWritePark(float remaining_g);

// Loop task: carries out a parked write. 0 when there was none or it worked,
// else the STR_ id of what went wrong, for an info popup the caller shows.
int optWeightWriteTick();
