#include "nfc.h"

#include <Adafruit_PN532.h>
#include <string.h>

static Adafruit_PN532* nfc = nullptr;
static constexpr uint8_t MIFARE_SECTOR_READ_ATTEMPTS = 3;

// Remembered so the reader can be brought back up without the caller having to
// hand the wiring in again - see nfcHardwareReinit().
static TwoWire* nfc_wire = nullptr;
static int8_t   nfc_reset_pin = -1;

bool nfcHardwareBegin(TwoWire* wire, int8_t reset_pin, int8_t irq_pin,
                      uint32_t* firmware_version) {
  if (!nfc) nfc = new Adafruit_PN532(irq_pin, reset_pin, wire);
  if (!nfc) return false;
  nfc_wire = wire;
  nfc_reset_pin = reset_pin;
  nfc->begin();
  delay(100);
  uint32_t version = nfc->getFirmwareVersion();
  if (firmware_version) *firmware_version = version;
  if (!version) return false;
  nfc->SAMConfig();
  return true;
}

// Cheap liveness probe. A PN532 that has locked up stops answering
// GetFirmwareVersion, which is the same symptom that takes the shared I2C bus
// (and with it the scale) down with it.
bool nfcHardwarePing() {
  return nfc && nfc->getFirmwareVersion() != 0;
}

// Re-runs begin() and SAMConfig() on the existing instance. Returns true once
// the reader answers again.
bool nfcHardwareReinit(uint32_t* firmware_version) {
  if (!nfc) return false;
  nfc->begin();
  delay(100);
  uint32_t version = nfc->getFirmwareVersion();
  if (firmware_version) *firmware_version = version;
  if (!version) return false;
  nfc->SAMConfig();
  return true;
}

bool nfcReadPassiveTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms) {
  return nfc && nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, uid_len, timeout_ms);
}

// Sends one command the library has no function for and reads its response
// off the bus. sendCommandCheckAck() returns once the response is ready but
// leaves it unread (its own callers read it with a private function); left
// unread, the next command would be written over a pending response, which is
// the likely reason the first field reset (12.10.2026) left the chip hanging.
// resp_len is the frame length without the leading ready byte; the check is
// on the response code (command + 1) at frame byte 6.
static bool rawCommand(uint8_t* cmd, uint8_t cmd_len, uint8_t resp_len) {
  if (!nfc || !nfc_wire) return false;
  if (!nfc->sendCommandCheckAck(cmd, cmd_len)) return false;
  uint8_t rx[16] = {0};
  const uint8_t want = (uint8_t)(resp_len + 1);
  if (want > sizeof(rx)) return false;
  size_t got = nfc_wire->requestFrom((uint8_t)PN532_I2C_ADDRESS, want);
  for (size_t i = 0; i < got && i < sizeof(rx); i++) rx[i] = nfc_wire->read();
  while (nfc_wire->available()) nfc_wire->read();
  return got == want && rx[0] == PN532_I2C_READY && rx[6] == 0xD5 &&
         rx[7] == (uint8_t)(cmd[0] + 1);
}

bool nfcInRelease() {
  // InRelease, Tg 0 = every target. Response: 00 00 FF 03 FD D5 53 st DCS 00.
  uint8_t cmd[2] = { 0x52, 0x00 };
  return rawCommand(cmd, 2, 10);
}

uint8_t nfcRfFieldCycle() {
  if (!nfc) return 0;
  // RFConfiguration, item 1 (RF field). Response: 00 00 FF 02 FE D5 33 F8 00.
  // 20 ms off woke a halted Creality tag about every second time; 100 ms off
  // did worse (12.10.2026), so the short gap stays.
  uint8_t r = 0;
  uint8_t off[3] = { 0x32, 0x01, 0x00 };
  uint8_t on[3]  = { 0x32, 0x01, 0x01 };
  if (rawCommand(off, 3, 9)) r |= NFC_RF_OFF_OK;
  delay(20);
  if (rawCommand(on, 3, 9))  r |= NFC_RF_ON_OK;
  delay(10);
  if (nfc->getFirmwareVersion() != 0) r |= NFC_RF_CHIP_OK;
  return r;
}

static bool reselectMifareUid(const uint8_t expected_uid[4], uint16_t timeout_ms) {
  uint8_t uid[NFC_UID_MAX] = {0};
  uint8_t uid_len = 0;
  return nfcReadPassiveTarget(uid, &uid_len, timeout_ms) &&
         uid_len == 4 &&
         memcmp(uid, expected_uid, 4) == 0;
}

static bool authenticateMifareTrailer(uint8_t trailer_block, uint8_t key[6], uint8_t uid[4],
                                      uint8_t key_type) {
  if (key_type == NFC_KEY_A) {
    return nfc->mifareclassic_AuthenticateBlock(uid, 4, trailer_block, NFC_KEY_A, key);
  }
  // Reads as "key B, then key A" and never was: the library turns its key
  // argument into a command with (keyNumber) ? AUTH_B : AUTH_A, and both
  // opcodes passed here are non-zero, so the second call is key B once more.
  // Bambu tags read with key B and have been proven on hardware with exactly
  // these two calls, so they stay as they are.
  if (nfc->mifareclassic_AuthenticateBlock(uid, 4, trailer_block, MIFARE_CMD_AUTH_B, key)) {
    return true;
  }
  return nfc->mifareclassic_AuthenticateBlock(uid, 4, trailer_block, MIFARE_CMD_AUTH_A, key);
}

bool nfcReadMifareSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16],
                         uint8_t key_type) {
  uint8_t trailer_block = sector * 4 + 3;

  if (!nfc) return false;

  for (uint8_t attempt = 0; attempt < MIFARE_SECTOR_READ_ATTEMPTS; attempt++) {
    if (attempt > 0) {
      delay(20);
      if (!reselectMifareUid(uid, 120)) {
        continue;
      }
    }

    if (!authenticateMifareTrailer(trailer_block, key, uid, key_type)) {
      continue;
    }

    bool ok = true;
    for (int b = 0; b < 3; b++) {
      int block_num = sector * 4 + b;
      if (!nfc->mifareclassic_ReadDataBlock(block_num, blocks[b])) {
        memset(blocks[b], 0, 16);
        ok = false;
        break;
      }
    }
    if (ok) return true;
  }

  memset(blocks, 0, 4 * 16);
  return false;
}

bool nfcReadMifareBlock(uint8_t block, uint8_t data[16]) {
  return nfc && nfc->mifareclassic_ReadDataBlock(block, data);
}

bool nfcAuthMifareSector(int sector, const uint8_t key[6], const uint8_t uid[4],
                         uint8_t key_type) {
  if (!nfc) return false;
  uint8_t k[6], u[4];
  memcpy(k, key, 6);
  memcpy(u, uid, 4);
  return nfc->mifareclassic_AuthenticateBlock(u, 4, sector * 4 + 3,
                                              key_type == NFC_KEY_A ? 0 : 1, k);
}

bool nfcWriteMifareBlock(uint8_t block, const uint8_t data[16]) {
  if (!nfc) return false;
  uint8_t d[16];
  memcpy(d, data, 16);
  return nfc->mifareclassic_WriteDataBlock(block, d);
}

bool nfcReadNtagPage(uint8_t page, uint8_t* data) {
  if (!nfc) return false;
  for (int retry = 0; retry < 3; retry++) {
    if (nfc->ntag2xx_ReadPage(page, data)) return true;
    delay(2);
  }
  return false;
}

bool nfcWriteNtagPage(uint8_t page, uint8_t* data) {
  return nfc && nfc->ntag2xx_WritePage(page, data);
}
