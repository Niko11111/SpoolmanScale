#include "nfc.h"

#include <Adafruit_PN532.h>
#include <string.h>

static Adafruit_PN532* nfc = nullptr;
static constexpr uint8_t MIFARE_SECTOR_READ_ATTEMPTS = 3;

// Remembered so the reader can be brought back up without the caller having to
// hand the wiring in again - see nfcHardwareReinit().
static TwoWire* nfc_wire = nullptr;
static int8_t   nfc_reset_pin = -1;

bool nfcHardwareBegin(TwoWire* wire, int8_t reset_pin, uint32_t* firmware_version) {
  if (!nfc) nfc = new Adafruit_PN532(-1, reset_pin, wire);
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

static bool reselectMifareUid(const uint8_t expected_uid[4], uint16_t timeout_ms) {
  uint8_t uid[7] = {0};
  uint8_t uid_len = 0;
  return nfcReadPassiveTarget(uid, &uid_len, timeout_ms) &&
         uid_len == 4 &&
         memcmp(uid, expected_uid, 4) == 0;
}

static bool authenticateMifareTrailer(uint8_t trailer_block, uint8_t key[6], uint8_t uid[4]) {
  if (nfc->mifareclassic_AuthenticateBlock(uid, 4, trailer_block, MIFARE_CMD_AUTH_B, key)) {
    return true;
  }
  return nfc->mifareclassic_AuthenticateBlock(uid, 4, trailer_block, MIFARE_CMD_AUTH_A, key);
}

bool nfcReadMifareSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16]) {
  uint8_t trailer_block = sector * 4 + 3;

  if (!nfc) return false;

  for (uint8_t attempt = 0; attempt < MIFARE_SECTOR_READ_ATTEMPTS; attempt++) {
    if (attempt > 0) {
      delay(20);
      if (!reselectMifareUid(uid, 120)) {
        continue;
      }
    }

    if (!authenticateMifareTrailer(trailer_block, key, uid)) {
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

bool nfcReadNtagPage(uint8_t page, uint8_t* data) {
  return nfc && nfc->ntag2xx_ReadPage(page, data);
}

bool nfcWriteNtagPage(uint8_t page, uint8_t* data) {
  return nfc && nfc->ntag2xx_WritePage(page, data);
}
