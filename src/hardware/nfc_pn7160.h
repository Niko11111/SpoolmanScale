#pragma once

// The PN7160 side of hardware/nfc.h. Only nfc.cpp includes this; everything
// else talks to the reader through nfc.h, whichever chip it is.

#include <Arduino.h>
#include <Wire.h>
#include <stdint.h>

// Switches VEN on and asks whether 0x28 answers. VEN is left high when it does
// and the pin handed back as an input when it does not. A weak pull-up is
// tried before the pin is driven, see the comment in the .cpp.
bool pn7160Probe(TwoWire* wire);
// Whether 0x28 answers, with the same retries as every other bus access here:
// a chip in standby may refuse its address once.
bool pn7160OnBus(TwoWire* wire);

// Brings the chip up from VEN: reset, init, the library's RF and power
// settings, discovery. Returns false and logs the step that failed.
bool pn7160Begin(TwoWire* wire, uint32_t* firmware_version);
bool pn7160Reinit(uint32_t* firmware_version);
bool pn7160Ping();

// The tag in the field, if any, with its technology (NFC_TECH_A/NFC_TECH_V).
// Never waits past timeout_ms; with discovery already running and nothing
// reported it does not wait at all.
bool pn7160ReadTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms, uint8_t* tech);
// The same for ISO 14443A only. An ISO 15693 tag is logged once and reported
// as no tag: the scan path handles 4 and 7 byte UIDs and has no reader for
// an 8 byte one yet.
bool pn7160ReadIso14443a(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms);

uint8_t pn7160RfFieldCycle();
bool pn7160Release();

// Reads from the tag selected by the last poll. Each is one exchange of at
// most TAG_CMD_TIMEOUT_MS (see the .cpp). key_type is NFC_KEY_A or NFC_KEY_B.
bool pn7160AuthMifare(uint8_t sector, const uint8_t key[6], uint8_t key_type);
bool pn7160ReadMifareBlock(uint8_t block, uint8_t data[16]);
// nfcReadMifareSector() for the PN7160: up to three attempts, the later ones
// after a fresh selection of the same UID, as the PN532 path does it.
bool pn7160ReadMifareSector(uint8_t sector, const uint8_t key[6], const uint8_t uid[4],
                            uint8_t blocks[4][16], uint8_t key_type);
bool pn7160ReadNtagPage(uint8_t page, uint8_t data[4]);
bool pn7160ReadVicinityBlock(uint8_t block, uint8_t data[4]);

// For the wake test: discovery running and nothing left to read, so IRQ is
// low and rises only for the next tag. False when that state was not reached.
bool pn7160ArmForWake();

struct NfcRfCounts;
// The counters since the last call, then zero.
void pn7160RfCountsTake(NfcRfCounts* out);
