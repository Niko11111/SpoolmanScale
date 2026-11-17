#include "nfc.h"

#include <Adafruit_PN532.h>
#include <string.h>

#include "app_config.h"
#include "hardware/i2c_scan.h"
#include "hardware/nfc_pn7160.h"
#include "hardware/sd_logger.h"

static Adafruit_PN532* nfc = nullptr;
static constexpr uint8_t MIFARE_SECTOR_READ_ATTEMPTS = 3;

// Remembered so the reader can be brought back up without the caller having to
// hand the wiring in again - see nfcHardwareReinit().
static TwoWire* nfc_wire = nullptr;
static int8_t   nfc_reset_pin = -1;

// Which chip every function below talks to. Each one asks it first and hands
// a PN7160 to hardware/nfc_pn7160.cpp; what follows that line is the PN532
// path exactly as it was before the PN7160 existed.
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

bool nfcChipCanWrite() { return s_chip == NFC_CHIP_PN532; }

// The PN7160 build reads only. Every write lands here and says so in the log,
// so a refused write is never mistaken for a tag that would not take it.
static bool pn7160WriteRefused(const char* what) {
  logSDf("NFC: %s not written - writing tags is not supported with the PN7160 in this build", what);
  return false;
}

bool nfcHardwareBegin(TwoWire* wire, int8_t reset_pin, int8_t irq_pin,
                      uint32_t* firmware_version) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160Begin(wire, firmware_version);
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
  if (s_chip == NFC_CHIP_PN7160) return pn7160Ping();
  return nfc && nfc->getFirmwareVersion() != 0;
}

// Re-runs begin() and SAMConfig() on the existing instance. Returns true once
// the reader answers again.
bool nfcHardwareReinit(uint32_t* firmware_version) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160Reinit(firmware_version);
  if (!nfc) return false;
  nfc->begin();
  delay(100);
  uint32_t version = nfc->getFirmwareVersion();
  if (firmware_version) *firmware_version = version;
  if (!version) return false;
  nfc->SAMConfig();
  return true;
}

bool nfcReadAnyTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms, uint8_t* tech) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160ReadTarget(uid, uid_len, timeout_ms, tech);
  if (tech) *tech = NFC_TECH_A;
  return nfcReadPassiveTarget(uid, uid_len, timeout_ms);
}

bool nfcReadVicinityBlock(uint8_t block, uint8_t data[4]) {
  return s_chip == NFC_CHIP_PN7160 && pn7160ReadVicinityBlock(block, data);
}

bool nfcReadPassiveTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160ReadIso14443a(uid, uid_len, timeout_ms);
  return nfc && nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, uid_len, timeout_ms);
}

// Sends one command the library has no function for and reads its response
// off the bus. sendCommandCheckAck() returns once the response is ready but
// leaves it unread (its own callers read it with a private function); left
// unread, the next command would be written over a pending response, which is
// the likely reason the first field reset (12.10.2026) left the chip hanging.
// resp_len is the frame length without the leading ready byte; the check is
// on the response code (command + 1) at frame byte 6. `status`, when given,
// receives the byte after it: the card's own answer for InDataExchange.
static bool rawCommand(uint8_t* cmd, uint8_t cmd_len, uint8_t resp_len,
                       uint8_t* status = nullptr) {
  if (!nfc || !nfc_wire) return false;
  if (!nfc->sendCommandCheckAck(cmd, cmd_len)) return false;
  uint8_t rx[16] = {0};
  const uint8_t want = (uint8_t)(resp_len + 1);
  if (want > sizeof(rx)) return false;
  size_t got = nfc_wire->requestFrom((uint8_t)PN532_I2C_ADDRESS, want);
  for (size_t i = 0; i < got && i < sizeof(rx); i++) rx[i] = nfc_wire->read();
  while (nfc_wire->available()) nfc_wire->read();
  const bool ok = got == want && rx[0] == PN532_I2C_READY && rx[6] == 0xD5 &&
                  rx[7] == (uint8_t)(cmd[0] + 1);
  if (ok && status) *status = rx[8];
  return ok;
}

bool nfcInRelease() {
  if (s_chip == NFC_CHIP_PN7160) return pn7160Release();
  // InRelease, Tg 0 = every target. Response: 00 00 FF 03 FD D5 53 st DCS 00.
  uint8_t cmd[2] = { 0x52, 0x00 };
  return rawCommand(cmd, 2, 10);
}

uint8_t nfcRfFieldCycle() {
  if (s_chip == NFC_CHIP_PN7160) return pn7160RfFieldCycle();
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

// The library answers an authentication with true or false only, and keeps
// the PN532's response in this buffer of its own (Adafruit PN532, pinned in
// platformio.ini). Its status byte says why a key failed: the card answered
// and refused it, or it never answered at all. Read here, never written.
extern byte pn532_packetbuffer[];

// The PN532's InDataExchange status for a card that took part in the
// authentication and refused the key ("MIFARE authentication error"). A card
// that did not answer reports a time out (0x01) instead.
static constexpr uint8_t PN532_STATUS_AUTH_ERROR = 0x14;

// What the authentications of the last nfcReadMifareSector() came to, see
// nfcLastSectorRefusedByCard() in nfc.h.
static bool    s_sector_refused_by_card = false;
static uint8_t s_last_auth_status = NFC_AUTH_STATUS_NONE;

// The status of the authentication the library has just run, when its buffer
// holds a response frame (00 00 FF len lcs D5 41 status). When the command was
// never acknowledged the buffer still holds the command, which starts 0x40.
static void noteAuthStatus() {
  const byte* b = pn532_packetbuffer;
  const bool response = b[0] == 0x00 && b[1] == 0x00 && b[2] == 0xFF &&
                        b[5] == 0xD5 && b[6] == 0x41;
  s_last_auth_status = response ? b[7] : NFC_AUTH_STATUS_NONE;
  if (s_last_auth_status == PN532_STATUS_AUTH_ERROR) s_sector_refused_by_card = true;
}

static bool authenticateTrailerOnce(uint8_t trailer_block, uint8_t key[6], uint8_t uid[4],
                                    uint8_t cmd) {
  if (nfc->mifareclassic_AuthenticateBlock(uid, 4, trailer_block, cmd, key)) return true;
  noteAuthStatus();
  return false;
}

static bool authenticateMifareTrailer(uint8_t trailer_block, uint8_t key[6], uint8_t uid[4],
                                      uint8_t key_type) {
  if (key_type == NFC_KEY_A) {
    return authenticateTrailerOnce(trailer_block, key, uid, NFC_KEY_A);
  }
  // Reads as "key B, then key A" and never was: the library turns its key
  // argument into a command with (keyNumber) ? AUTH_B : AUTH_A, and both
  // opcodes passed here are non-zero, so the second call is key B once more.
  // Bambu tags read with key B and have been proven on hardware with exactly
  // these two calls, so they stay as they are.
  if (authenticateTrailerOnce(trailer_block, key, uid, MIFARE_CMD_AUTH_B)) {
    return true;
  }
  return authenticateTrailerOnce(trailer_block, key, uid, MIFARE_CMD_AUTH_A);
}

bool nfcReadMifareSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16],
                         uint8_t key_type) {
  uint8_t trailer_block = sector * 4 + 3;

  s_sector_refused_by_card = false;
  s_last_auth_status = NFC_AUTH_STATUS_NONE;
  if (s_chip == NFC_CHIP_PN7160) return pn7160ReadMifareSector(sector, key, uid, blocks, key_type);
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

bool nfcLastSectorRefusedByCard() { return s_sector_refused_by_card; }

uint8_t nfcLastAuthStatus() { return s_last_auth_status; }

bool nfcReadMifareBlock(uint8_t block, uint8_t data[16]) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160ReadMifareBlock(block, data);
  return nfc && nfc->mifareclassic_ReadDataBlock(block, data);
}

bool nfcAuthMifareSector(int sector, const uint8_t key[6], const uint8_t uid[4],
                         uint8_t key_type) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160AuthMifare(sector, key, key_type);
  if (!nfc) return false;
  uint8_t k[6], u[4];
  memcpy(k, key, 6);
  memcpy(u, uid, 4);
  return nfc->mifareclassic_AuthenticateBlock(u, 4, sector * 4 + 3,
                                              key_type == NFC_KEY_A ? 0 : 1, k);
}

// The library's mifareclassic_WriteDataBlock() returns 1 once the PN532
// acknowledges the command and never looks at the card's answer, so a block
// the card refused (wrong key for writing, the tag leaving the field) read as
// written. The same InDataExchange here, with the status byte checked: 0x00
// is the card's "done". Response: 00 00 FF 03 FD D5 41 st DCS 00.
bool nfcWriteMifareBlock(uint8_t block, const uint8_t data[16]) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160WriteRefused("MIFARE block");
  if (!nfc) return false;
  uint8_t cmd[4 + 16] = { 0x40, 0x01, 0xA0, block };   // InDataExchange, Tg 1, MIFARE WRITE
  memcpy(cmd + 4, data, 16);
  uint8_t status = 0xFF;
  if (!rawCommand(cmd, sizeof(cmd), 10, &status)) return false;
  return status == 0x00;
}

bool nfcReadNtagPage(uint8_t page, uint8_t* data) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160ReadNtagPage(page, data);
  if (!nfc) return false;
  for (int retry = 0; retry < 3; retry++) {
    if (nfc->ntag2xx_ReadPage(page, data)) return true;
    delay(2);
  }
  return false;
}

bool nfcWriteNtagPage(uint8_t page, uint8_t* data) {
  if (s_chip == NFC_CHIP_PN7160) return pn7160WriteRefused("NTAG page");
  return nfc && nfc->ntag2xx_WritePage(page, data);
}

bool nfcArmForWake() {
  if (s_chip == NFC_CHIP_PN7160) return pn7160ArmForWake();
  return nfc && nfc->startPassiveTargetIDDetection(PN532_MIFARE_ISO14443A);
}
