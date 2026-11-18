#pragma once

#include <Arduino.h>
#include <Wire.h>
#include <stdint.h>

#include "hardware/nfc_rf_counts.h"

// Which reader chip sits on the bus. Every function below speaks to the one
// nfcDetectChip() chose at boot; a PN7160 is driven by hardware/nfc_pn7160.cpp.
enum NfcChip : uint8_t {
  NFC_CHIP_PN532  = 0,   // the default, and what an empty bus is treated as
  NFC_CHIP_PN7160 = 1,
};
// Decides once, before nfcHardwareBegin(). A PN532 is recognised from the boot
// scan alone (i2cScanRefresh() must have run), so its path sends nothing new
// on the bus. Only when 0x24 did not answer is a PN7160 looked for at 0x28,
// which first needs its VEN line high - see nfc_pn7160.h.
NfcChip nfcDetectChip(TwoWire* wire);
NfcChip nfcChip();
const char* nfcChipName();
// Whether the chosen reader acknowledges its address right now. A PN532 gets
// one probe, as before; a PN7160 a few, since in standby it may refuse once.
bool nfcChipOnBus(TwoWire& wire);

// irq_pin is not a wire, it is what the library's constructor is given so it
// does not call pinMode() on an invalid pin - see hw_pins::PN532_IRQ_UNUSED.
// A PN7160 ignores reset_pin and irq_pin and uses hw_pins::NFC_VEN/NFC_IRQ.
// firmware_version: the PN532's GetFirmwareVersion word; for a PN7160 the same
// layout built from its CORE_RESET notification (major << 16 | minor << 8).
bool nfcHardwareBegin(TwoWire* wire, int8_t reset_pin, int8_t irq_pin,
                      uint32_t* firmware_version = nullptr);
bool nfcHardwarePing();
bool nfcHardwareReinit(uint32_t* firmware_version = nullptr);
// What a uid buffer handed to nfcReadPassiveTarget() has to hold. ISO 14443-3A
// knows three sizes - 4, 7 and 10 bytes - and the library copies whatever the
// chip reports without looking at the buffer. Every buffer used to be 7 or 8:
// a triple size card wrote three bytes past it, onto the loop task's stack.
// An ISO 15693 UID (PN7160 only) is 8 bytes and fits as well.
#define NFC_UID_MAX 10
// ISO 14443A only, which is all the scan path knows. With a PN7160 an ISO 15693
// tag on the reader answers false here; nfcReadAnyTarget() reports it.
bool nfcReadPassiveTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms);
// Either technology. tech receives NFC_TECH_A or NFC_TECH_V. An ISO 15693 UID
// comes in the order it was received, least significant byte first, so a
// printed one ("E0 04 ...") reads it backwards. The PN532 only knows A.
#define NFC_TECH_A 0   // ISO 14443A: NTAG, MIFARE Classic
#define NFC_TECH_V 1   // ISO 15693: ICODE SLIX, OpenPrintTag
bool nfcReadAnyTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms, uint8_t* tech);
// One 4 byte block (READ SINGLE BLOCK) of the ISO 15693 tag the last poll
// found. PN7160 only; false on a PN532.
bool nfcReadVicinityBlock(uint8_t block, uint8_t data[4]);
// Switches the RF field off and on again, which resets a card that a refused
// key has left halted (a plain wake no longer reaches it). Returns which steps
// worked, as NFC_RF_* bits, for the caller's log line.
// PN7160: RF_DEACTIVATE to idle (field off), 20 ms, RF_DISCOVER (field on).
#define NFC_RF_OFF_OK  0x01
#define NFC_RF_ON_OK   0x02
#define NFC_RF_CHIP_OK 0x04   // the reader still answers afterwards
uint8_t nfcRfFieldCycle();
// Drops every target the reader still holds (InRelease). After a refused key
// the reader may keep the card as its current target and not list it again.
// PN7160: RF_DEACTIVATE back to discovery, which drops the activated target.
bool nfcInRelease();
// Which of a sector's two keys to authenticate with. The library takes zero
// for key A and anything else for key B.
#define NFC_KEY_A 0
#define NFC_KEY_B 1
// NFC_KEY_B is what every caller has always had and what Bambu tags read
// with, including its second attempt, left exactly as it was. NFC_KEY_A is a
// single attempt with key A, which no caller used before Snapmaker tags.
bool nfcReadMifareSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16],
                         uint8_t key_type = NFC_KEY_B);
// Whether the card itself refused a key during the last nfcReadMifareSector():
// it answered the authentication and turned the key down (PN532 status 0x14).
// False when every attempt went unanswered - a weak or halted card, which may
// well hold that key. Only what the read already did; no command of its own.
// Always false on a PN7160: which of its status codes means "refused by the
// card" is not measured yet, and false is the side that tries again.
bool nfcLastSectorRefusedByCard();
// The PN532 status of the last failed authentication in that read, for the
// log; NFC_AUTH_STATUS_NONE when none failed or no response frame came back.
// Always NFC_AUTH_STATUS_NONE on a PN7160, whose codes mean something else;
// its driver logs them itself.
#define NFC_AUTH_STATUS_NONE 0xFF
uint8_t nfcLastAuthStatus();
bool nfcReadMifareBlock(uint8_t block, uint8_t data[16]);
// One authentication of a sector trailer, no retry and no reselect: the
// Creality writer probes which key a blank tag opens with, and a second try
// on a refused key only halts the card a second time.
bool nfcAuthMifareSector(int sector, const uint8_t key[6], const uint8_t uid[4],
                         uint8_t key_type);
// Writes one 16 byte block of the sector authenticated last.
bool nfcWriteMifareBlock(uint8_t block, const uint8_t data[16]);
bool nfcReadNtagPage(uint8_t page, uint8_t* data);
bool nfcWriteNtagPage(uint8_t page, uint8_t* data);

// Leaves the reader searching, for a tag to wake the ESP from deep sleep over
// its IRQ line (the wake test, services/nfc_wake_test.h). PN532: an
// InListPassiveTarget whose answer is left pending, so IRQ falls when a card
// comes. PN7160: discovery with nothing left to read, so IRQ rises then.
bool nfcArmForWake();

// How the tag commands since the last call went, by cause (PN7160 only, see
// nfc_rf_counts.h); then zero. False on a PN532, out left zeroed.
bool nfcRfCountsTake(NfcRfCounts* out);
