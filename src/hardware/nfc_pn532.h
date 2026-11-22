#pragma once

// The PN532 side of hardware/nfc.h (Adafruit library). Only nfc.cpp includes
// this; everything else talks to the reader through nfc.h, whichever chip it
// is. Each function here is the nfc.h function of the same name for a PN532.

#include <Arduino.h>
#include <Wire.h>
#include <stdint.h>

bool pn532Begin(TwoWire* wire, int8_t reset_pin, int8_t irq_pin, uint32_t* firmware_version);
bool pn532Ping();
bool pn532Reinit(uint32_t* firmware_version);

bool pn532ReadPassiveTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms);
bool pn532InRelease();
uint8_t pn532RfFieldCycle();

// Clears what the authentications of the last sector read came to. Called by
// nfcReadMifareSector() before it picks the chip, so the two answers below
// start fresh for a PN7160 too.
void pn532SectorReadStart();
bool pn532ReadMifareSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16],
                           uint8_t key_type);
bool pn532LastSectorRefusedByCard();
uint8_t pn532LastAuthStatus();

bool pn532ReadMifareBlock(uint8_t block, uint8_t data[16]);
bool pn532AuthMifareSector(int sector, const uint8_t key[6], const uint8_t uid[4],
                           uint8_t key_type);
bool pn532WriteMifareBlock(uint8_t block, const uint8_t data[16]);
bool pn532ReadNtagPage(uint8_t page, uint8_t* data);
bool pn532WriteNtagPage(uint8_t page, uint8_t* data);

bool pn532ArmForWake();
bool pn532PowerCycle(TwoWire* wire, int8_t rstpdn_pin);
