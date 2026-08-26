#pragma once

#include <Wire.h>
#include <stddef.h>
#include <stdint.h>

// Who actually answers on a bus.
//
// Both external chips report "not found" the same way whether they are broken,
// unpowered, wired to the wrong pin or not there at all, and from a serial log
// that question used to be unanswerable. It is worse than it looks: a failed
// register read comes back as all ones through Adafruit_BusIO, so an absent
// chip reads like a present one talking nonsense. A plain address probe cannot
// be fooled that way - it either gets an ACK or it does not.

// How many addresses a scan will report. Well past the two this device has.
#define I2C_SCAN_MAX_FOUND  16
// Enough for every address a scan can report, with its name.
#define I2C_SCAN_LINE_LEN  160

// Probes the 7 bit range and writes the addresses that acknowledge into
// found[]. Returns how many were written, never more than max_found.
uint8_t i2cScan(TwoWire &wire, uint8_t *found, uint8_t max_found);

// The chip this project expects at an address, or nullptr for anything else.
const char *i2cKnownName(uint8_t addr);

// One line for a log or a status page: "0x24 PN532, 0x2A NAU7802", or
// "nothing answers" on a silent bus. Returns how many devices were found.
uint8_t i2cScanFormat(TwoWire &wire, char *out, size_t out_len);

// The last scan, remembered so a status page can show it without probing 112
// addresses every time it is polled - that is around 10 ms of bus time the NFC
// reader and the ADC would have to wait for.
void i2cScanRefresh(TwoWire &wire);
const char *i2cScanLast();
