#pragma once

#include <Arduino.h>
#include <Wire.h>
#include <stdint.h>

// irq_pin is not a wire, it is what the library's constructor is given so it
// does not call pinMode() on an invalid pin - see hw_pins::PN532_IRQ_UNUSED.
bool nfcHardwareBegin(TwoWire* wire, int8_t reset_pin, int8_t irq_pin,
                      uint32_t* firmware_version = nullptr);
bool nfcHardwarePing();
bool nfcHardwareReinit(uint32_t* firmware_version = nullptr);
// What a uid buffer handed to nfcReadPassiveTarget() has to hold. ISO 14443-3A
// knows three sizes - 4, 7 and 10 bytes - and the library copies whatever the
// chip reports without looking at the buffer. Every buffer used to be 7 or 8:
// a triple size card wrote three bytes past it, onto the loop task's stack.
#define NFC_UID_MAX 10
#define NFC_KEY_A 0
#define NFC_KEY_B 1

bool nfcReadPassiveTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms);
bool nfcReadMifareSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16], uint8_t key_type = NFC_KEY_B);
bool nfcReadMifareBlock(uint8_t block, uint8_t data[16]);
bool nfcReadNtagPage(uint8_t page, uint8_t* data);
bool nfcWriteNtagPage(uint8_t page, uint8_t* data);
