#pragma once

#include <Arduino.h>
#include <Wire.h>
#include <stdint.h>

bool nfcHardwareBegin(TwoWire* wire, int8_t reset_pin, uint32_t* firmware_version = nullptr);
bool nfcHardwarePing();
bool nfcHardwareReinit(uint32_t* firmware_version = nullptr);
bool nfcReadPassiveTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms);
bool nfcReadMifareSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16]);
bool nfcReadMifareBlock(uint8_t block, uint8_t data[16]);
bool nfcReadNtagPage(uint8_t page, uint8_t* data);
bool nfcWriteNtagPage(uint8_t page, uint8_t* data);
