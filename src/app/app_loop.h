#pragma once

#include <stdint.h>

void appLoop();

// What the read of the tag on the reader came to, once it has settled - the
// same moment the "Tag placed" line is written. TV_NONE while the scan is
// still running or after the tag left.
//
// TV_BAMBU as soon as one sector opened with the keys derived from the UID:
// only a Bambu chip has them, so the rest of its read is not waited for.
// TV_OTHER for a tag that read as something else. TV_REFUSED for a 4 byte
// card that answered and refused the Bambu keys, and opened with nothing
// else: a foreign card, or a weak Bambu chip, which can answer the same way
// (15.11.2026). TV_NO_ANSWER for a 4 byte card that used up its retries
// without ever answering an authentication: a weak or halted chip, which may
// well be a Bambu chip (07.11.2026, #77).
enum TagVerdict : uint8_t {
  TV_NONE = 0,
  TV_BAMBU,
  TV_NO_ANSWER,
  TV_OTHER,              // NTAG, Creality, Snapmaker, blank
  TV_REFUSED,
};
TagVerdict tagSettledVerdict(const char* uid_str);
