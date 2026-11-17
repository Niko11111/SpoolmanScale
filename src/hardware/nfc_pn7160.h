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
