#include "nfc.h"

#include <Adafruit_PN532.h>
#include <string.h>

static Adafruit_PN532* nfc = nullptr;

bool nfcHardwareBegin(TwoWire* wire, int8_t reset_pin, uint32_t* firmware_version) {
  if (!nfc) nfc = new Adafruit_PN532(-1, reset_pin, wire);
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

bool nfcReadMifareSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16]) {
  uint8_t trailer_block = sector * 4 + 3;

  if (!nfc) return false;
  if (!nfc->mifareclassic_AuthenticateBlock(uid, 4, trailer_block, MIFARE_CMD_AUTH_B, key)) {
    if (!nfc->mifareclassic_AuthenticateBlock(uid, 4, trailer_block, MIFARE_CMD_AUTH_A, key)) {
      return false;
    }
  }

  bool ok = true;
  for (int b = 0; b < 3; b++) {
    int block_num = sector * 4 + b;
    if (!nfc->mifareclassic_ReadDataBlock(block_num, blocks[b])) {
      memset(blocks[b], 0, 16);
      ok = false;
    }
  }
  return ok;
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
