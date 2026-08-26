#pragma once

// Widths of the two labels that share the status bar, in the order they sit:
// the status text on the left, the optional address on the right, hanging off
// the scan counter. They add up to what fits between the bullet and that
// counter, so a change to one has to be a change to the other.
//
// The port mode needs the extra 30 px - "192.168.4.100:7913" is about 113 px
// in font 12 and would otherwise be cut to "192.168.4.1...", which is exactly
// the thing that mode exists to show.
#define HDR_IP_W             94
#define HDR_IP_W_PORT        124
#define HDR_STATUS_W         292
#define HDR_STATUS_W_NARROW  262

void updateHeaderStatus();

// Packs the header chips right to left with one gap each. Call after any
// change to their texts - updateHeaderStatus() does it itself.
void layoutHeaderChips();
