#pragma once

// Widths of the two labels that share the status bar, in the order they sit:
// the status text on the left, right of the bullet, and the optional address
// flush with the right edge. The status text takes whatever the address
// leaves, so a change to one is a change to the other.
//
// The port mode needs the extra 30 px - "192.168.4.100:7913" is about 113 px
// in font 12 and would otherwise be cut to "192.168.4.1...", which is exactly
// the thing that mode exists to show.
//
// An https address carries its scheme and needs 32 px more again:
// "https://192.168.4.100:8443" measures 152 px in font 12, plus 4 px of
// reserve. A status text longer than what is left scrolls (ui/status_scroll.h).
#define HDR_IP_W             94
#define HDR_IP_W_PORT        124
#define HDR_IP_W_HTTPS       156
// The status text starts right of the bullet; the row ends HDR_ROW_MARGIN
// before the right edge of the 480 px panel, where the chips above end too.
#define HDR_STATUS_X         24
#define HDR_ROW_MARGIN       8
#define HDR_ROW_END_X        (480 - HDR_ROW_MARGIN)
#define HDR_ADDR_GAP         10
// No address shown: the status text runs to the end of the row, 448 px.
#define HDR_STATUS_W_FULL    (HDR_ROW_END_X - HDR_STATUS_X)
// Beside an address of width ip_w: 344 px next to a plain IP, 282 next to https.
#define HDR_STATUS_W_BESIDE(ip_w) (HDR_STATUS_W_FULL - HDR_ADDR_GAP - (ip_w))

void updateHeaderStatus();

// Packs the header chips right to left with one gap each. Call after any
// change to their texts - updateHeaderStatus() does it itself.
void layoutHeaderChips();
