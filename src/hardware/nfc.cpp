#include "nfc.h"

#include "app_config.h"
#include "hardware/i2c_scan.h"
#include "hardware/nfc_pn532.h"
#include "hardware/nfc_pn7160.h"

// Which chip every function below talks to. Each one asks it first and hands
// a PN7160 to hardware/nfc_pn7160.cpp and a PN532 to hardware/nfc_pn532.cpp,
// which holds the PN532 path exactly as it was before the PN7160 existed.
static NfcChip s_chip = NFC_CHIP_PN532;

NfcChip nfcDetectChip(TwoWire* wire) {
  // A PN532 in the boot scan settles it without a byte more on the bus.
  if (i2cScanSaw(I2C_ADDR_PN532)) return s_chip = NFC_CHIP_PN532;
  if (pn7160Probe(wire)) return s_chip = NFC_CHIP_PN7160;
  // Nothing answers: the PN532 path, which reports the failure as it always has.
  return s_chip = NFC_CHIP_PN532;
}

NfcChip nfcChip() { return s_chip; }

const char* nfcChipName() { return s_chip == NFC_CHIP_PN7160 ? "PN7160" : "PN532"; }

bool nfcChipOnBus(TwoWire& wire) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160OnBus(&wire);
  return i2cPresent(wire, I2C_ADDR_PN532);
}

bool nfcHardwareBegin(TwoWire* wire, int8_t reset_pin, int8_t irq_pin,
                      uint32_t* firmware_version) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160Begin(wire, firmware_version);
  return pn532Begin(wire, reset_pin, irq_pin, firmware_version);
}

bool nfcHardwarePing() {
  if (s_chip == NFC_CHIP_PN7160) return pn7160Ping();
  return pn532Ping();
}

bool nfcHardwareReinit(uint32_t* firmware_version) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160Reinit(firmware_version);
  return pn532Reinit(firmware_version);
}

bool nfcReadAnyTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms, uint8_t* tech) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160ReadTarget(uid, uid_len, timeout_ms, tech);
  if (tech) *tech = NFC_TECH_A;
  return pn532ReadPassiveTarget(uid, uid_len, timeout_ms);
}

bool nfcReadVicinityBlock(uint8_t block, uint8_t data[4]) {
  return s_chip == NFC_CHIP_PN7160 && pn7160ReadVicinityBlock(block, data);
}

bool nfcReadVicinityBlocks(uint8_t first, uint16_t count, uint8_t* out) {
  return s_chip == NFC_CHIP_PN7160 && pn7160ReadVicinityBlocks(first, count, out);
}

bool nfcReadPassiveTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160ReadIso14443a(uid, uid_len, timeout_ms);
  return pn532ReadPassiveTarget(uid, uid_len, timeout_ms);
}

bool nfcInRelease() {
  if (s_chip == NFC_CHIP_PN7160) return pn7160Release();
  return pn532InRelease();
}

uint8_t nfcRfFieldCycle() {
  if (s_chip == NFC_CHIP_PN7160) return pn7160RfFieldCycle();
  return pn532RfFieldCycle();
}

bool nfcReadMifareSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16],
                         uint8_t key_type) {
  // Cleared for either chip: a PN7160 read leaves both answers at "nothing
  // known", as it did while they lived in this file.
  pn532SectorReadStart();
  if (s_chip == NFC_CHIP_PN7160) return pn7160ReadMifareSector(sector, key, uid, blocks, key_type);
  return pn532ReadMifareSector(sector, key, uid, blocks, key_type);
}

bool nfcLastSectorRefusedByCard() { return pn532LastSectorRefusedByCard(); }

uint8_t nfcLastAuthStatus() { return pn532LastAuthStatus(); }

bool nfcReadMifareBlock(uint8_t block, uint8_t data[16]) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160ReadMifareBlock(block, data);
  return pn532ReadMifareBlock(block, data);
}

bool nfcAuthMifareSector(int sector, const uint8_t key[6], const uint8_t uid[4],
                         uint8_t key_type) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160AuthMifare(sector, key, key_type);
  return pn532AuthMifareSector(sector, key, uid, key_type);
}

bool nfcWriteMifareBlock(uint8_t block, const uint8_t data[16]) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160WriteMifareBlock(block, data);
  return pn532WriteMifareBlock(block, data);
}

bool nfcReadNtagPage(uint8_t page, uint8_t* data) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160ReadNtagPage(page, data);
  return pn532ReadNtagPage(page, data);
}

bool nfcWriteNtagPage(uint8_t page, uint8_t* data) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160WriteNtagPage(page, data);
  return pn532WriteNtagPage(page, data);
}

bool nfcArmForWake() {
  if (s_chip == NFC_CHIP_PN7160) return pn7160ArmForWake();
  return pn532ArmForWake();
}

bool nfcPn532PowerCycle(TwoWire* wire, int8_t rstpdn_pin) {
  return pn532PowerCycle(wire, rstpdn_pin);
}

bool nfcRfCountsTake(NfcRfCounts* out) {
  if (out) *out = {};
  if (s_chip != NFC_CHIP_PN7160) return false;
  pn7160RfCountsTake(out);
  return true;
}
