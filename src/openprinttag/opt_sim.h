#pragma once

// A simulated OpenPrintTag for trying the display, the lookup and "New from
// tag" without a tag: one of the format's test vectors, offered to the scan
// path as an ISO 15693 tag for a few seconds. Armed only over the web
// (web/web_nfc_test.cpp, maintenance gate), kept in RAM, off after a restart.
// A test aid for the PN7160 bring-up, to go once real tags are at hand.

#include <stddef.h>
#include <stdint.h>

#include "openprinttag/opt_tag.h"

// key: "sample", "01", "03" or "04" (optSimKeys()). False for any other.
bool optSimArm(const char* key, uint16_t seconds);
void optSimOff();
const char* optSimKeys();

// For the scan path's poll: true and the simulated tag while one is armed.
bool optSimPoll(uint8_t* uid, uint8_t* uid_len, uint8_t* tech);
// The simulated tag's memory when uid_wire is its UID: bytes as a reader
// would get them, 0 otherwise.
size_t optSimMemory(const uint8_t uid_wire[OPT_UID_BYTES], uint8_t* out, size_t cap);
