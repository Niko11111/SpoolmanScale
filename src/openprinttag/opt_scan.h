#pragma once

// Reading an ISO 15693 tag the scan path found (PN7160 only): its memory up to
// the end of the NDEF message, decoded as an OpenPrintTag (opt_tag.h), and a
// tag that decodes put into g_tag the way the other families fill it - looked
// up by its UID, as a Creality tag is. Also what the tag page and the debug
// route show about the last one read.

#include <stddef.h>
#include <stdint.h>

#include "openprinttag/opt_tag.h"

struct TagInfo;

enum OptScanResult : uint8_t {
  OPT_SCAN_DECODED,   // an OpenPrintTag, g_tag filled
  OPT_SCAN_OTHER,     // read, but no OpenPrintTag on it (g_tag holds the UID only)
  OPT_SCAN_RETRY,     // the read broke off; ask again on the next poll
};

// uid_wire: the UID as the reader returned it (LSB first). uid_str: the
// MSB-first form (optUidString()), which becomes g_tag.uid_str.
OptScanResult optScanTag(const uint8_t uid_wire[OPT_UID_BYTES], const char* uid_str);

// Whether g_tag holds a decoded OpenPrintTag that is on the reader now.
bool optTagOnReader();

// The last tag read, decoded (valid when optTagOnReader()).
const OptTag& optLastTag();
// Whether the last tag read was the simulated one (opt_sim.h): no tag to write.
bool optLastReadSimulated();
// The last tag's UID as the reader returned it (LSB first), for a command
// addressed to that tag alone.
void optLastUidWire(uint8_t out[OPT_UID_BYTES]);
// What opt_write.cpp has just written to the tag on the reader, so the screens
// show the tag as it now is.
void optNoteConsumed(float consumed_g);

// What the tag page and the tag view show for it.
void optFillTagInfo(TagInfo* ti);
// The decoded fields as a JSON object for the tag page's raw view.
void optSummaryJson(char* out, size_t cap);
// Everything about the last read for the debug route: UID, read report,
// decode result, fields, memory as hex.
void optScanJson(char* out, size_t cap);
