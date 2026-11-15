#pragma once

#include <stdint.h>

void appLoop();

// What the read of the tag on the reader came to, once it has settled - the
// same moment the "Tag placed" line is written. TV_NONE while the scan is
// still running or after the tag left. A Bambu tag whose sectors partly read
// but whose tray uuid never did is TV_BAMBU_INCOMPLETE: it is a Bambu tag,
// but there is nothing to link it by yet.
enum TagVerdict : uint8_t {
  TV_NONE = 0,
  TV_BAMBU,
  TV_BAMBU_INCOMPLETE,
  TV_OTHER,              // NTAG, Creality, Snapmaker, blank or plain MIFARE
};
TagVerdict tagSettledVerdict(const char* uid_str);
