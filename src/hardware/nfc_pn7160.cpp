// The PN7160 behind hardware/nfc.h.
//
// The Elechouse library (pinned in platformio.ini) is used for what NXP tuned
// for this chip: configureSettings() writes its RF and power settings,
// configMode() maps each tag protocol to the interface that speaks it. What
// runs while the scale is in use is done here instead, on the library's raw
// transport (writeData/readData): its own calls wait in fixed loops -
// readerTagCmd() up to a second, connectNCI() 3 x 500 ms for a chip that does
// not answer, waitForTagRemoval() until the tag leaves. Here every wait watches
// the IRQ line, which the chip raises while it has a frame for the host, and
// gives up at a deadline the caller set.
//
// The RF state follows what the chip reports, never what was asked of it:
//   OFF        not brought up, or lost
//   IDLE       field off (after a field cycle, or a selection that failed)
//   DISCOVERY  the chip polls the field on its own
//   ACTIVE     one tag is selected; commands go to it
// A poll in ACTIVE keeps a tag that is still there: an NTAG is asked for
// page 0, an ISO 15693 tag for block 0, a MIFARE Classic card is put to sleep
// and selected again (how NXP re-activates a tag). One that does not answer,
// and any other tag, goes back to DISCOVERY, and the chip selects it again if
// it is still there. The PN532 selects anew on every poll as well, and the
// scan path relies on that after a refused key.

#include "nfc_pn7160.h"

#include <string.h>

#include <driver/gpio.h>

#include "app_config.h"
#include "hardware/i2c_scan.h"
#include "hardware/nfc.h"
#include "hardware/nfc_rf_counts.h"
#include "hardware/pins.h"
#include "hardware/sd_logger.h"

// Last, and only here: the library's headers define SUCCESS, ERROR and some
// WIFI_* names as macros.
#include <Electroniccats_PN7150.h>

namespace {

// NCI frame: header (message type and group, opcode, payload length) and up
// to 255 bytes of payload.
constexpr uint8_t  NCI_HDR          = 3;
constexpr uint8_t  NCI_MT_DATA      = 0x00;
constexpr size_t   NCI_PAYLOAD_MAX  = 255;
constexpr size_t   NCI_FRAME_MAX    = NCI_HDR + NCI_PAYLOAD_MAX;
constexpr uint8_t  NCI_MT_MASK      = 0xE0;
constexpr uint8_t  NCI_MT_CMD       = 0x20;
constexpr uint8_t  NCI_MT_RSP       = 0x40;
constexpr uint8_t  NCI_MT_NTF       = 0x60;
constexpr uint8_t  NCI_GID_MASK     = 0x0F;
constexpr uint8_t  NCI_OID_MASK     = 0x3F;
constexpr uint8_t  NCI_STATUS_OK    = 0x00;
constexpr size_t   NCI_STATUS_AT    = 3;      // first payload byte of a response

constexpr uint8_t  GID_CORE = 0x00;
constexpr uint8_t  GID_RF   = 0x01;
constexpr uint8_t  OID_CORE_RESET          = 0x00;
constexpr uint8_t  OID_CORE_GENERIC_ERROR  = 0x07;
constexpr uint8_t  OID_CORE_INTERFACE_ERROR = 0x08;
constexpr uint8_t  OID_RF_DISCOVER         = 0x03;
constexpr uint8_t  OID_RF_DISCOVER_SELECT  = 0x04;
constexpr uint8_t  OID_RF_INTF_ACTIVATED   = 0x05;
constexpr uint8_t  OID_RF_DEACTIVATE       = 0x06;

constexpr uint8_t  DEACTIVATE_TO_IDLE      = 0x00;
constexpr uint8_t  DEACTIVATE_TO_SLEEP     = 0x01;   // the tag is halted, the chip waits for a select
constexpr uint8_t  DEACTIVATE_TO_DISCOVERY = 0x03;
constexpr uint8_t  DISCOVER_NTF_MORE       = 0x02;   // last byte: more tags follow
// RF_DEACTIVATE_NTF: [3] the type. RF_DISCOVER_NTF: [3] discovery id, [4] protocol.
constexpr size_t   DEACTIVATE_TYPE_AT      = 3;
constexpr size_t   DISCOVER_ID_AT          = 3;
constexpr size_t   DISCOVER_PROTO_AT       = 4;

// RF technology and mode, protocol and interface codes (NCI 2.0).
constexpr uint8_t  TECH_A_POLL       = 0x00;
constexpr uint8_t  TECH_V_POLL       = 0x06;
constexpr uint8_t  NCI_PROT_T2T      = 0x02;
constexpr uint8_t  NCI_PROT_ISODEP   = 0x04;
constexpr uint8_t  NCI_PROT_T5T      = 0x06;
constexpr uint8_t  NCI_PROT_MIFARE   = 0x80;
constexpr uint8_t  NCI_INTF_FRAME    = 0x01;
constexpr uint8_t  NCI_INTF_ISODEP   = 0x02;
constexpr uint8_t  NCI_INTF_TAGCMD   = 0x80;
constexpr uint8_t  ISO15693_UID_BYTES = 8;

// Tag commands. MIFARE Classic goes through NXP's TAG-CMD interface, which
// wraps each command in a request code of its own (PN7160 user manual; the
// same frames as the library's MifareClassic examples). Its answers end in a
// status byte, as do the Frame interface's for NTAG and ISO 15693.
constexpr uint8_t  MFC_AUTH_REQ       = 0x40;   // answer: 0x40, status
constexpr uint8_t  MFC_XCHG_REQ       = 0x10;   // answer: 0x10, data, status
constexpr uint8_t  MFC_KEY_EMBEDDED   = 0x10;   // the key travels in the command
// Key B is bit 7 of the key selector; bits 0-3 index a key stored in the
// chip. 0x80 as ESPHome's pn71xx driver has it (MFC_AUTHENTICATE_PARAM_KS_B).
// The library's example sends 0x11, which never reached key B: its key A,
// tried first, always opened the FF..FF test card.
constexpr uint8_t  MFC_KEY_SELECT_B   = 0x80;
constexpr uint8_t  MFC_KEY_BYTES      = 6;
constexpr uint8_t  MFC_BLOCK_BYTES    = 16;
constexpr uint8_t  MFC_BLOCKS_PER_SECTOR = 4;
constexpr uint8_t  MFC_DATA_BLOCKS    = 3;      // the trailer is not read
constexpr uint8_t  CMD_READ           = 0x30;   // MIFARE and NTAG READ
constexpr uint8_t  NTAG_PAGE_BYTES    = 4;
constexpr uint8_t  NTAG_READ_BYTES    = 16;     // READ returns four pages
constexpr uint8_t  ISO15693_FLAGS     = 0x02;   // high data rate, not addressed
constexpr uint8_t  ISO15693_READ_SINGLE = 0x20;
constexpr uint8_t  ISO15693_READ_MULTIPLE = 0x23;   // first block, count - 1
constexpr uint8_t  ISO15693_WRITE_SINGLE = 0x21;    // block, then its 4 bytes
// High data rate, addressed: the 8 UID bytes follow the command, and only that
// tag answers.
constexpr uint8_t  ISO15693_FLAGS_ADDRESSED = 0x22;
constexpr uint8_t  ISO15693_CC_BLOCK  = 0;       // the capability container
constexpr uint8_t  ISO15693_ERROR_FLAG = 0x01;   // response flags: an error code follows
// Blocks per READ MULTIPLE: 32 bytes, far below the 255-byte NCI payload and
// what ICODE SLIX2 returns in one go (it allows all 80).
constexpr uint8_t  ISO15693_CHUNK_BLOCKS = 8;
constexpr uint16_t ISO15693_BLOCK_LAST = 255;      // block numbers are one byte
constexpr uint8_t  ISO15693_BLOCK_BYTES = 4;    // ICODE SLIX and SLIX2
constexpr uint8_t  TAG_STATUS_OK      = 0x00;
// What the PN7160 reports for a WRITE the tag acknowledged, MIFARE Classic and
// NTAG alike: the library's write examples check for 0x14 on the PN7160 and
// 0x00 on the PN7150. Both are taken; the callers read the data back.
constexpr uint8_t  TAG_STATUS_WRITE_ACK = 0x14;
constexpr uint8_t  CMD_MFC_WRITE      = 0xA0;   // then the 16 bytes, as a second exchange
constexpr uint8_t  CMD_NTAG_WRITE     = 0xA2;
constexpr uint8_t  NTAG_FIRST_WRITABLE_PAGE = 4;
constexpr uint8_t  MFC_MANUFACTURER_BLOCK = 0;
constexpr uint8_t  TAG_CMD_MAX        = 1 + 16; // longest command sent here: a block's data
// One exchange with a tag. A MIFARE authentication is the slowest, a few ms
// on the air; 100 ms is the PN532 path's fast poll budget.
constexpr uint16_t TAG_CMD_TIMEOUT_MS = 100;
// Retry rhythm of a sector read, the PN532 path's numbers.
constexpr uint8_t  SECTOR_READ_ATTEMPTS = 3;
constexpr uint16_t RESELECT_PAUSE_MS  = 20;
constexpr uint16_t RESELECT_TIMEOUT_MS = 120;
constexpr uint8_t  MIFARE_UID_BYTES   = 4;

// CORE_RESET (reset the configuration too; configureSettings() writes it
// again) and CORE_INIT in its NCI 2.0 form, as the library sends them.
const uint8_t CMD_CORE_RESET[] = {0x20, 0x00, 0x01, 0x01};
const uint8_t CMD_CORE_INIT[]  = {0x20, 0x01, 0x02, 0x00, 0x00};
// CORE_GET_CONFIG of TOTAL_DURATION: a core command, answered in every RF
// state, and it changes nothing. The liveness probe.
const uint8_t CMD_GET_TOTAL_DURATION[] = {0x20, 0x03, 0x02, 0x01, 0x00};
// Polls NFC-A and NFC-V on every period. The library's own list adds NFC-B
// and NFC-F, which no spool tag uses and which only make each period longer.
const uint8_t CMD_RF_DISCOVER[] = {0x21, 0x03, 0x05, 0x02, TECH_A_POLL, 0x01, TECH_V_POLL, 0x01};
// TOTAL_DURATION, the length of one discovery period: 100 ms (0x0064, LSB
// first). The library sets 510 ms, after which a tag that was missed once is
// only polled again half a second later - longer than the PN532 path's poll
// interval, and in the measurement three misses for one.
const uint8_t CMD_SET_DISCOVERY_PERIOD[] = {0x20, 0x02, 0x05, 0x01, 0x00, 0x02, 0x64, 0x00};

// VEN timing as the library's hardwareReset() has it.
constexpr uint16_t VEN_LOW_MS          = 5;
constexpr uint16_t VEN_SETTLE_MS       = 5;
// VEN high to the first probe. The library allows 5 ms; unmeasured on our
// boards, so twice that.
constexpr uint16_t PROBE_SETTLE_MS     = 10;
// Pad drive while the probe drives VEN high. On scales built before September
// 2026 pin 7 meets an output of the PN532 module (hardware/pins.h); when that
// PN532 is broken, unplugged or hung, the probe drives against it. The weakest
// step (about 5 mA instead of about 20 mA) is still plenty for a CMOS input
// like VEN. The default step comes back after the probe, either way.
constexpr gpio_drive_cap_t PROBE_VEN_DRIVE   = GPIO_DRIVE_CAP_0;
constexpr gpio_drive_cap_t DEFAULT_PIN_DRIVE = GPIO_DRIVE_CAP_2;
// An NCI chip waking from standby may refuse its address (NXP's Linux driver
// retries for the same reason, after a longer pause), so every write and probe
// gets three goes. Unmeasured: the verbose log counts the retries.
constexpr uint8_t  BUS_TRIES           = 3;
constexpr uint16_t BUS_RETRY_MS        = 10;
// Every loop that reads frames stops after this many: readFrame() still reads
// what is pending after the deadline, and an IRQ line stuck high would
// otherwise keep the loop task here.
constexpr uint8_t  FRAMES_PER_WAIT_MAX = 16;
// A control response. Upper bound, not the usual time: during discovery the
// chip may answer only after its current poll phase, and the first CORE_RESET
// and every ping went unanswered within 20 ms on the bench (17.11.2026).
// A little over one discovery period.
constexpr uint16_t CTRL_TIMEOUT_MS     = 120;
constexpr uint16_t RESET_NTF_TIMEOUT_MS = 50;   // the library reads it within 45 ms
// CORE_RESET is sent again when it goes unanswered: the chip may still be
// starting after VEN. The library retries too, 3 x 500 ms; 100 ms here.
constexpr uint8_t  RESET_TRIES         = 3;
constexpr uint16_t RESET_RETRY_MS      = 100;
constexpr uint8_t  PEEK_BYTES          = 3;     // an NCI header
constexpr uint16_t INIT_TIMEOUT_MS     = 150;   // the library's own value for CORE_INIT
constexpr uint16_t FIELD_OFF_MS        = 20;    // as the PN532's field cycle
constexpr uint8_t  ARM_DRAIN_FRAMES_MAX = 8;
// CORE_RESET_NTF: [7] length of the manufacturer data, [8..] the data.
constexpr size_t   RESET_NTF_NCI_VERSION = 5;
constexpr size_t   RESET_NTF_INFO_LEN  = 7;
constexpr size_t   RESET_NTF_INFO      = 8;
constexpr uint8_t  FW_INFO_MIN         = 4;
// RF_INTF_ACTIVATED_NTF: [3] discovery id, [4] interface, [5] protocol,
// [6] technology and mode, [9] length of the technology parameters, [10..].
constexpr size_t   ACT_DISCOVERY_ID    = 3;
constexpr size_t   ACT_INTERFACE       = 4;
constexpr size_t   ACT_PROTOCOL        = 5;
constexpr size_t   ACT_TECH            = 6;
constexpr size_t   ACT_PARAMS_LEN      = 9;
constexpr size_t   ACT_PARAMS          = 10;

enum class RfState : uint8_t { Off, Idle, Discovery, Active };

struct Target {
  uint8_t discovery_id;   // what RF_DISCOVER_SELECT names it by
  uint8_t intf;
  uint8_t proto;
  uint8_t tech;
  uint8_t sak;
  uint8_t uid_len;
  uint8_t uid[NFC_UID_MAX];
};

}  // namespace

static Electroniccats_PN7150* s_lib = nullptr;
static TwoWire* s_wire = nullptr;
static RfState  s_state = RfState::Off;
static Target   s_target = {};
static uint8_t  s_frame[NCI_FRAME_MAX];
static uint32_t s_frame_len = 0;
static uint32_t s_fw_version = 0;
// What the exchanges came to since the last pn7160RfCountsTake().
static NfcRfCounts s_rf = {};
// The ISO 15693 UID logged last, so a tag lying on the reader is one line.
static uint8_t  s_vicinity_logged[NFC_UID_MAX];
// The ISO 15693 tag whose first refused read was logged, so one tag is one line.
static uint8_t  s_vicinity_fail_logged[NFC_UID_MAX];

static bool passed(uint32_t deadline_ms) {
  return (int32_t)(millis() - deadline_ms) >= 0;
}

static bool waitIrq(uint32_t deadline_ms) {
  while (digitalRead(hw_pins::NFC_IRQ) != HIGH) {
    if (passed(deadline_ms)) return false;
    delay(1);
  }
  return true;
}

static bool isMsg(uint8_t mt, uint8_t gid, uint8_t oid) {
  return s_frame_len >= NCI_HDR && (s_frame[0] & NCI_MT_MASK) == mt &&
         (s_frame[0] & NCI_GID_MASK) == gid && (s_frame[1] & NCI_OID_MASK) == oid;
}

// NFC-A: SENS_RES (2), NFCID1 length, NFCID1, SEL_RES length, SEL_RES.
// NFC-V: RES_FLAG, DSFID, UID (8, least significant byte first).
static bool parseUid(Target& t, const uint8_t* p, uint8_t len) {
  if (t.tech == TECH_A_POLL) {
    if (len < 3 || p[2] > NFC_UID_MAX || 3u + p[2] > len) return false;
    t.uid_len = p[2];
    memcpy(t.uid, p + 3, t.uid_len);
    if (3u + t.uid_len + 1 < len) t.sak = p[3 + t.uid_len + 1];
    return true;
  }
  if (t.tech == TECH_V_POLL) {
    if (len < 2 + ISO15693_UID_BYTES) return false;
    t.uid_len = ISO15693_UID_BYTES;
    memcpy(t.uid, p + 2, ISO15693_UID_BYTES);
    return true;
  }
  return false;
}

// The chip has selected a tag, whatever this host makes of the frame: a
// frame too short to read still means ACTIVE, with no UID, so the next poll
// sends the chip back to discovery instead of waiting for a report that
// already came.
static void noteActivation() {
  Target t = {};
  const bool whole = s_frame_len >= ACT_PARAMS &&
                     ACT_PARAMS + s_frame[ACT_PARAMS_LEN] <= s_frame_len;
  if (whole) {
    t.discovery_id = s_frame[ACT_DISCOVERY_ID];
    t.intf  = s_frame[ACT_INTERFACE];
    t.proto = s_frame[ACT_PROTOCOL];
    t.tech  = s_frame[ACT_TECH];
  }
  if (!whole || !parseUid(t, s_frame + ACT_PARAMS, s_frame[ACT_PARAMS_LEN])) {
    logSDf("PN7160: activated a tag it gave no usable UID for (tech 0x%02X, protocol 0x%02X)",
           t.tech, t.proto);
  }
  s_target = t;
  s_state = RfState::Active;
}

// An error notification, counted by its status wherever it turns up: during
// a tag command, or from discovery on its own (a tag it could not select).
static void noteCoreError() {
  const uint8_t status = s_frame_len > NCI_STATUS_AT ? s_frame[NCI_STATUS_AT] : 0;
  nfcRfCountError(s_rf, status);
  if (sd_verbose) {
    logSDf("[verbose] PN7160: chip reports %s (0x%02X)", nfcRfStatusName(status), status);
  }
}

static bool isCoreError();

// Keeps s_state in step with what the chip says happened.
static void trackRfState() {
  if (isCoreError()) {
    noteCoreError();
  } else if (isMsg(NCI_MT_NTF, GID_RF, OID_RF_INTF_ACTIVATED)) {
    noteActivation();
  } else if (isMsg(NCI_MT_NTF, GID_RF, OID_RF_DEACTIVATE) && s_frame_len > NCI_HDR) {
    s_state = (s_frame[DEACTIVATE_TYPE_AT] == DEACTIVATE_TO_DISCOVERY) ? RfState::Discovery
                                                                       : RfState::Idle;
  }
}

// One frame, once IRQ is up. False at the deadline or on a short read.
static bool readFrame(uint32_t deadline_ms) {
  if (!s_lib || !waitIrq(deadline_ms)) return false;
  s_frame_len = s_lib->readData(s_frame);
  if (s_frame_len < NCI_HDR) return false;
  trackRfState();
  return true;
}

static bool writeFrame(const uint8_t* frame, uint8_t len) {
  for (uint8_t i = 0; i < BUS_TRIES; i++) {
    // writeData() takes a non-const buffer and only reads it.
    if (s_lib->writeData(const_cast<uint8_t*>(frame), len) == 0) {
      if (i > 0 && sd_verbose) logSDf("[verbose] PN7160: write took %u tries", i + 1);
      return true;
    }
    delay(BUS_RETRY_MS);
  }
  logSDf("PN7160: write of %02X %02X not acknowledged after %u tries", frame[0], frame[1], BUS_TRIES);
  return false;
}

// Sends a control command and reads frames until its response. Whatever comes
// first (notifications, a late answer) still updates the RF state on the way.
static bool control(const uint8_t* cmd, uint8_t len, uint32_t deadline_ms) {
  if (!s_lib || !writeFrame(cmd, len)) return false;
  const uint8_t gid = cmd[0] & NCI_GID_MASK;
  const uint8_t oid = cmd[1] & NCI_OID_MASK;
  for (uint8_t i = 0; i < FRAMES_PER_WAIT_MAX && readFrame(deadline_ms); i++) {
    if (isMsg(NCI_MT_RSP, gid, oid)) {
      return s_frame_len > NCI_STATUS_AT && s_frame[NCI_STATUS_AT] == NCI_STATUS_OK;
    }
  }
  return false;
}

static bool awaitNtf(uint8_t gid, uint8_t oid, uint32_t deadline_ms) {
  for (uint8_t i = 0; i < FRAMES_PER_WAIT_MAX && readFrame(deadline_ms); i++) {
    if (isMsg(NCI_MT_NTF, gid, oid)) return true;
  }
  return false;
}

static uint32_t deadlineIn(uint16_t ms) { return millis() + ms; }

// The PN7160's manufacturer data in CORE_RESET_NTF is hardware version, ROM
// code, firmware major, firmware minor (NXP UM11495; logged raw below to check
// it on the chip). Packed like the PN532's version word, so a log line that
// prints (v >> 16).(v >> 8) shows the firmware there too.
static void noteFirmware() {
  if (s_frame_len < RESET_NTF_INFO) return;
  const uint8_t n = s_frame[RESET_NTF_INFO_LEN];
  if (n < FW_INFO_MIN || RESET_NTF_INFO + n > s_frame_len) return;
  const uint8_t* m = s_frame + RESET_NTF_INFO;
  s_fw_version = ((uint32_t)m[0] << 24) | ((uint32_t)m[2] << 16) |
                 ((uint32_t)m[3] << 8) | m[1];
  logSDf("PN7160: NCI %u.%u, hw 0x%02X, rom 0x%02X, fw %02X.%02X",
         s_frame[RESET_NTF_NCI_VERSION] >> 4, s_frame[RESET_NTF_NCI_VERSION] & 0x0F,
         m[0], m[1], m[2], m[3]);
}

static void venPulse() {
  pinMode(hw_pins::NFC_VEN, OUTPUT);
  digitalWrite(hw_pins::NFC_VEN, LOW);
  delay(VEN_LOW_MS);
  digitalWrite(hw_pins::NFC_VEN, HIGH);
  delay(VEN_SETTLE_MS);
}

// Why a CORE_RESET went unanswered: the IRQ level, and what the chip hands
// out when read without waiting for IRQ. A response there with IRQ low means
// the IRQ wire does not reach GPIO 21; nothing there, the chip did not answer.
static void logResetSilence(uint8_t attempt) {
  uint8_t got[PEEK_BYTES] = {0};
  size_t n = 0;
  if (s_wire && s_wire->requestFrom((uint8_t)I2C_ADDR_PN7160, PEEK_BYTES) == PEEK_BYTES) {
    for (; n < PEEK_BYTES && s_wire->available(); n++) got[n] = s_wire->read();
  }
  while (s_wire && s_wire->available()) s_wire->read();
  logSDf("PN7160: CORE_RESET unanswered (try %u), IRQ %s, read without IRQ: %u bytes %02X %02X %02X",
         attempt, digitalRead(hw_pins::NFC_IRQ) == HIGH ? "high" : "low", (unsigned)n,
         got[0], got[1], got[2]);
}

static bool resetChip() {
  for (uint8_t attempt = 1; attempt <= RESET_TRIES; attempt++) {
    if (control(CMD_CORE_RESET, sizeof(CMD_CORE_RESET), deadlineIn(CTRL_TIMEOUT_MS))) return true;
    logResetSilence(attempt);
    delay(RESET_RETRY_MS);
  }
  return false;
}

// What the library's connectNCI() does, without its two side effects: it
// restarts the I2C bus (with default pins, unless told otherwise) and waits
// 3 x 500 ms for a chip that does not answer. Returns the failed step or null.
static const char* connect() {
  venPulse();
  if (!resetChip()) return "reset";
  if (awaitNtf(GID_CORE, OID_CORE_RESET, deadlineIn(RESET_NTF_TIMEOUT_MS))) noteFirmware();
  if (!control(CMD_CORE_INIT, sizeof(CMD_CORE_INIT), deadlineIn(INIT_TIMEOUT_MS))) return "init";
  return nullptr;
}

static bool startDiscovery(uint32_t deadline_ms) {
  if (!control(CMD_RF_DISCOVER, sizeof(CMD_RF_DISCOVER), deadline_ms)) return false;
  s_state = RfState::Discovery;
  return true;
}

// The library answers 0 for success, also where its return type is bool.
static bool libOk(int result) { return result == SUCCESS; }

static const char* bringUp() {
  const char* failed = connect();
  if (failed) return failed;
  if (!libOk(s_lib->configureSettings())) return "settings";
  if (!libOk(s_lib->configMode())) return "mode";
  if (!control(CMD_SET_DISCOVERY_PERIOD, sizeof(CMD_SET_DISCOVERY_PERIOD),
               deadlineIn(CTRL_TIMEOUT_MS))) return "period";
  if (!startDiscovery(deadlineIn(CTRL_TIMEOUT_MS))) return "discovery";
  return nullptr;
}

static bool answersOnBus(TwoWire* wire) {
  for (uint8_t i = 0; i < BUS_TRIES; i++) {
    if (i2cPresent(*wire, I2C_ADDR_PN7160)) return true;
    delay(BUS_RETRY_MS);
  }
  return false;
}

bool pn7160OnBus(TwoWire* wire) { return wire && answersOnBus(wire); }

// Drives VEN high at PROBE_VEN_DRIVE and asks for the chip once. Set after
// pinMode(), which rewrites the pin's configuration. The level goes high
// before the pin becomes an output, so the moment until the weak step holds
// drives the level an idle PN532 output holds too. A PN7160 that answered
// keeps VEN high at the default drive; otherwise the pin is an input again
// before the drive goes back up.
static bool probeWithWeakDrive(TwoWire* wire) {
  const gpio_num_t ven = (gpio_num_t)hw_pins::NFC_VEN;
  gpio_set_level(ven, 1);
  pinMode(hw_pins::NFC_VEN, OUTPUT);
  gpio_set_drive_capability(ven, PROBE_VEN_DRIVE);
  gpio_drive_cap_t applied = DEFAULT_PIN_DRIVE;
  gpio_get_drive_capability(ven, &applied);
  logSDf("NFC: PN7160 probe drives pin 7 at drive step %d", (int)applied);
  digitalWrite(hw_pins::NFC_VEN, HIGH);
  delay(PROBE_SETTLE_MS);
  const bool found = answersOnBus(wire);
  if (!found) pinMode(hw_pins::NFC_VEN, INPUT);
  gpio_set_drive_capability(ven, DEFAULT_PIN_DRIVE);
  return found;
}

bool pn7160Probe(TwoWire* wire) {
  if (!wire) return false;
  // Pin 7 may still be wired the old PN532 way, to a module output
  // (hardware/pins.h). A pull-up never fights that, and may already be enough
  // for VEN; driving the pin comes second, for the length of one probe.
  pinMode(hw_pins::NFC_VEN, INPUT_PULLUP);
  delay(PROBE_SETTLE_MS);
  if (answersOnBus(wire)) return true;
  if (probeWithWeakDrive(wire)) return true;
  pinMode(hw_pins::NFC_VEN, INPUT);
  return false;
}

bool pn7160Begin(TwoWire* wire, uint32_t* firmware_version) {
  if (!s_lib) {
    // Four arguments always: the short form picks the PN7150 code paths.
    s_lib = new Electroniccats_PN7150(hw_pins::NFC_IRQ, hw_pins::NFC_VEN, I2C_ADDR_PN7160,
                                      PN7160, wire);
  }
  if (!s_lib) return false;
  s_wire = wire;
  // VCC (MINI) and VANT (module) hang on the 5 V of connector pin 1. The
  // 3.3 V preset is for boards that feed the antenna driver from 3.3 V.
  s_lib->setPn7160FixedVbat3V3(false);
  return pn7160Reinit(firmware_version);
}

bool pn7160Reinit(uint32_t* firmware_version) {
  if (!s_lib) return false;
  s_state = RfState::Off;
  s_fw_version = 0;
  const char* failed = bringUp();
  // The first bring-up after power on failed at "settings" on the bench and
  // the next one worked: one more go at once, not five seconds later.
  if (failed) {
    logSDf("PN7160: bring-up failed at %s, trying once more", failed);
    failed = bringUp();
  }
  if (failed) {
    s_state = RfState::Off;
    logSDf("PN7160: bring-up failed at %s", failed);
  }
  if (firmware_version) *firmware_version = s_fw_version;
  return failed == nullptr;
}

bool pn7160Ping() {
  if (!s_lib || s_state == RfState::Off) return false;
  const uint32_t t0 = millis();
  s_frame_len = 0;
  if (control(CMD_GET_TOTAL_DURATION, sizeof(CMD_GET_TOTAL_DURATION),
              deadlineIn(CTRL_TIMEOUT_MS))) return true;
  // What came back instead, for the bench: nothing, a refusal, or late.
  logSDf("PN7160: ping unanswered after %lu ms, last frame %u bytes %02X %02X %02X %02X, IRQ %s",
         (unsigned long)(millis() - t0), (unsigned)s_frame_len, s_frame[0], s_frame[1],
         s_frame[2], s_frame[3], digitalRead(hw_pins::NFC_IRQ) == HIGH ? "high" : "low");
  return false;
}

static bool deactivate(uint8_t type, uint32_t deadline_ms) {
  const uint8_t cmd[] = {NCI_MT_CMD | GID_RF, OID_RF_DEACTIVATE, 1, type};
  if (!control(cmd, sizeof(cmd), deadline_ms)) return false;
  // The notification that confirms it may come after the deadline; it is read
  // with the next frame and says the same.
  s_state = (type == DEACTIVATE_TO_DISCOVERY) ? RfState::Discovery : RfState::Idle;
  return true;
}

// Back to polling from wherever the chip is: an active tag is dropped to
// discovery, anything else goes through idle and starts discovery anew.
static bool rediscover(uint32_t deadline_ms) {
  if (s_state == RfState::Active && deactivate(DEACTIVATE_TO_DISCOVERY, deadline_ms)) return true;
  deactivate(DEACTIVATE_TO_IDLE, deadline_ms);   // refused when already idle, which is fine
  return startDiscovery(deadline_ms);
}

// Several tags in the field: the chip lists them (RF_DISCOVER_NTF, whose last
// byte says whether more follow) and waits for the host to pick one. The first
// is taken, as the PN532 takes the first it finds. Until the activation comes
// the state is IDLE, so a selection that fails is restarted by the next poll.
static void selectDiscovered(uint32_t deadline_ms) {
  const uint8_t id = s_frame[DISCOVER_ID_AT];
  const uint8_t proto = s_frame[DISCOVER_PROTO_AT];
  bool more = s_frame[s_frame_len - 1] == DISCOVER_NTF_MORE;
  for (uint8_t i = 0; more && i < FRAMES_PER_WAIT_MAX && readFrame(deadline_ms); i++) {
    more = isMsg(NCI_MT_NTF, GID_RF, OID_RF_DISCOVER) && s_frame[s_frame_len - 1] == DISCOVER_NTF_MORE;
  }
  const uint8_t intf = (proto == NCI_PROT_MIFARE) ? NCI_INTF_TAGCMD
                     : (proto == NCI_PROT_ISODEP) ? NCI_INTF_ISODEP : NCI_INTF_FRAME;
  const uint8_t cmd[] = {NCI_MT_CMD | GID_RF, OID_RF_DISCOVER_SELECT, 3, id, proto, intf};
  s_state = RfState::Idle;
  control(cmd, sizeof(cmd), deadline_ms);
}

static void collectActivation(uint32_t deadline_ms) {
  for (uint8_t i = 0; i < FRAMES_PER_WAIT_MAX && s_state != RfState::Active &&
                      readFrame(deadline_ms); i++) {
    if (isMsg(NCI_MT_NTF, GID_RF, OID_RF_DISCOVER)) selectDiscovered(deadline_ms);
  }
}

static bool exchange(const uint8_t* cmd, uint8_t len, uint8_t resp[NCI_PAYLOAD_MAX],
                     uint8_t* resp_len);

// An NTAG that is still selected answers a READ of page 0, the presence check
// Android sends to a Type 2 tag. Put to sleep and selected again it never came
// back: the chip reported "activation failed" every time (bench, 18.11.2026).
static bool ntagAnswers() {
  const uint8_t cmd[] = {CMD_READ, 0};
  uint8_t resp[NCI_PAYLOAD_MAX];
  uint8_t n = 0;
  return exchange(cmd, sizeof(cmd), resp, &n) && n >= NTAG_READ_BYTES + 1 &&
         resp[n - 1] == TAG_STATUS_OK;
}

// A MIFARE Classic card takes no READ before it is authenticated, so it is put
// to sleep and selected again: RF_DEACTIVATE to sleep, then RF_DISCOVER_SELECT,
// as the library's readerReActivate() does. The chip wakes the card with WUPA,
// which a halted card answers too. Dropped to discovery instead, a card lying
// still on the reader came back only every second poll, and at times not
// within the scan path's removal delay (bench, 18.11.2026).
static bool mifareWakes(uint32_t deadline_ms) {
  if (!deactivate(DEACTIVATE_TO_SLEEP, deadline_ms)) return false;
  // The select is only taken once the chip has said the tag sleeps.
  if (!awaitNtf(GID_RF, OID_RF_DEACTIVATE, deadline_ms)) return false;
  const uint8_t cmd[] = {NCI_MT_CMD | GID_RF, OID_RF_DISCOVER_SELECT, 3,
                         s_target.discovery_id, s_target.proto, s_target.intf};
  if (!control(cmd, sizeof(cmd), deadline_ms)) return false;
  collectActivation(deadline_ms);
  return s_state == RfState::Active;
}

bool pn7160ReadVicinityBlock(uint8_t block, uint8_t data[4]);

// An ISO 15693 tag still selected answers a READ of block 0, as an NTAG does
// its page 0. Dropped to discovery instead it would be found only every
// second poll, as a MIFARE card was. Untested on a tag (18.11.2026): one
// that does not answer falls back to discovery, as before.
static bool vicinityAnswers() {
  uint8_t block[ISO15693_BLOCK_BYTES];
  return pn7160ReadVicinityBlock(0, block);
}

// The tag selected at the last poll, kept if it is still there. ISO-DEP tags
// go back to discovery as before.
static bool keepSelected(uint32_t deadline_ms) {
  if (s_target.uid_len == 0) return false;
  if (s_target.proto == NCI_PROT_T2T) return ntagAnswers();
  if (s_target.proto == NCI_PROT_T5T) return vicinityAnswers();
  if (s_target.proto == NCI_PROT_MIFARE) return mifareWakes(deadline_ms);
  return false;
}

bool pn7160ReadTarget(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms, uint8_t* tech) {
  if (!s_lib || s_state == RfState::Off || !uid || !uid_len) return false;
  const uint32_t deadline = deadlineIn(timeout_ms);
  // Discovery that is already running needs no wait: a tag that came meanwhile
  // has raised IRQ. After a restart the tag needs time to be selected again.
  const bool was_active = s_state == RfState::Active;
  const bool reselected = was_active && keepSelected(deadline);
  // A tag that did not wake is most likely gone: back to discovery, with the
  // time a control command needs rather than what is left of this poll's.
  const uint32_t restart_by = was_active ? deadlineIn(CTRL_TIMEOUT_MS) : deadline;
  const bool restarted = !reselected && s_state != RfState::Discovery && rediscover(restart_by);
  collectActivation(restarted ? deadline : millis());
  if (was_active && s_state != RfState::Active) s_rf.reselect_miss++;
  if (s_state != RfState::Active || s_target.uid_len == 0) return false;
  memcpy(uid, s_target.uid, s_target.uid_len);
  *uid_len = s_target.uid_len;
  if (tech) *tech = (s_target.tech == TECH_V_POLL) ? NFC_TECH_V : NFC_TECH_A;
  return true;
}

static void noteVicinitySkipped(const uint8_t* uid, uint8_t uid_len) {
  if (memcmp(s_vicinity_logged, uid, uid_len) == 0) return;
  memcpy(s_vicinity_logged, uid, uid_len);
  // Printed most significant byte first, the way the tag's own label has it.
  logSDf("PN7160: ISO 15693 tag %02X%02X%02X%02X%02X%02X%02X%02X on the reader - not an ISO 14443A tag, passed over here",
         uid[7], uid[6], uid[5], uid[4], uid[3], uid[2], uid[1], uid[0]);
}

bool pn7160ReadIso14443a(uint8_t* uid, uint8_t* uid_len, uint16_t timeout_ms) {
  uint8_t tech = NFC_TECH_A;
  if (!pn7160ReadTarget(uid, uid_len, timeout_ms, &tech)) return false;
  if (tech == NFC_TECH_A) return true;
  if (*uid_len == ISO15693_UID_BYTES) noteVicinitySkipped(uid, *uid_len);
  return false;
}

uint8_t pn7160RfFieldCycle() {
  if (!s_lib || s_state == RfState::Off) return 0;
  uint8_t r = 0;
  if (deactivate(DEACTIVATE_TO_IDLE, deadlineIn(CTRL_TIMEOUT_MS))) r |= NFC_RF_OFF_OK;
  delay(FIELD_OFF_MS);
  if (startDiscovery(deadlineIn(CTRL_TIMEOUT_MS))) r |= NFC_RF_ON_OK;
  if (pn7160Ping()) r |= NFC_RF_CHIP_OK;
  return r;
}

bool pn7160Release() {
  if (!s_lib || s_state == RfState::Off) return false;
  if (s_state == RfState::Discovery) return true;   // nothing held
  return rediscover(deadlineIn(CTRL_TIMEOUT_MS));
}

static bool isCoreError() {
  return isMsg(NCI_MT_NTF, GID_CORE, OID_CORE_GENERIC_ERROR) ||
         isMsg(NCI_MT_NTF, GID_CORE, OID_CORE_INTERFACE_ERROR);
}

static bool noteExchangeFailed(uint8_t cmd0, const char* why, uint32_t* counter) {
  (*counter)++;
  if (sd_verbose) logSDf("[verbose] PN7160: tag command 0x%02X failed: %s", cmd0, why);
  return false;
}

// Every answer ends in a status byte (Frame and TAG-CMD interfaces alike);
// not 0 (or a write's acknowledgement) is the tag or the chip turning the
// command down.
static void noteAnswer(uint8_t cmd0, const uint8_t* resp, uint8_t n) {
  const uint8_t status = n ? resp[n - 1] : 0xFF;
  if (status == TAG_STATUS_OK || status == TAG_STATUS_WRITE_ACK) {
    s_rf.answered_ok++;
    return;
  }
  s_rf.tag_status++;
  if (sd_verbose) logSDf("[verbose] PN7160: tag command 0x%02X answered with status 0x%02X", cmd0, status);
}

// One command to the selected tag, one answer back. resp is always the full
// NCI payload size: the length comes from the chip, and the library's
// readerTagCmd() copies it into whatever it is handed. Credit notifications
// on the way are read and passed over; an error notification or the tag
// being dropped ends the exchange.
static bool exchange(const uint8_t* cmd, uint8_t len, uint8_t resp[NCI_PAYLOAD_MAX],
                     uint8_t* resp_len) {
  *resp_len = 0;
  if (!s_lib || s_state != RfState::Active || len > TAG_CMD_MAX) return false;
  // A late answer to an exchange that gave up must not pass for this one's.
  for (uint8_t i = 0; i < FRAMES_PER_WAIT_MAX && readFrame(millis()); i++) {}
  if (s_state != RfState::Active) return false;
  uint8_t frame[NCI_HDR + TAG_CMD_MAX] = {NCI_MT_DATA, 0x00, len};
  memcpy(frame + NCI_HDR, cmd, len);
  if (!writeFrame(frame, NCI_HDR + len)) return false;
  s_rf.commands++;
  const uint32_t deadline = deadlineIn(TAG_CMD_TIMEOUT_MS);
  for (uint8_t i = 0; i < FRAMES_PER_WAIT_MAX && readFrame(deadline); i++) {
    if (s_state != RfState::Active) return noteExchangeFailed(cmd[0], "tag dropped", &s_rf.dropped);
    if (isCoreError()) return false;   // counted and logged by trackRfState()
    if ((s_frame[0] & NCI_MT_MASK) != NCI_MT_DATA) continue;
    // The header's length, unless the read came back shorter than it says.
    const uint32_t got = s_frame_len - NCI_HDR;
    *resp_len = (uint8_t)(s_frame[2] < got ? s_frame[2] : got);
    memcpy(resp, s_frame + NCI_HDR, *resp_len);
    noteAnswer(cmd[0], resp, *resp_len);
    return true;
  }
  return noteExchangeFailed(cmd[0], "no answer", &s_rf.no_answer);
}

bool pn7160AuthMifare(uint8_t sector, const uint8_t key[6], uint8_t key_type) {
  if (s_target.proto != NCI_PROT_MIFARE) return false;
  const uint8_t select = MFC_KEY_EMBEDDED | (key_type == NFC_KEY_A ? 0 : MFC_KEY_SELECT_B);
  uint8_t cmd[3 + MFC_KEY_BYTES] = {MFC_AUTH_REQ, sector, select};
  memcpy(cmd + 3, key, MFC_KEY_BYTES);
  uint8_t resp[NCI_PAYLOAD_MAX];
  uint8_t n = 0;
  const bool answered = exchange(cmd, sizeof(cmd), resp, &n);
  const bool ok = answered && n >= 2 && resp[0] == MFC_AUTH_REQ && resp[n - 1] == TAG_STATUS_OK;
  // Which status means "the card refused the key" is to be read off these
  // lines on the bench (nfcLastSectorRefusedByCard() stays false until then).
  if (!ok && sd_verbose) {
    logSDf("[verbose] PN7160: sector %u key %c %s (status 0x%02X)", sector,
           key_type == NFC_KEY_A ? 'A' : 'B', answered ? "refused" : "unanswered",
           answered && n ? resp[n - 1] : 0xFF);
  }
  return ok;
}

bool pn7160ReadMifareBlock(uint8_t block, uint8_t data[16]) {
  if (s_target.proto != NCI_PROT_MIFARE) return false;
  const uint8_t cmd[] = {MFC_XCHG_REQ, CMD_READ, block};
  uint8_t resp[NCI_PAYLOAD_MAX];
  uint8_t n = 0;
  if (!exchange(cmd, sizeof(cmd), resp, &n)) return false;
  if (n < MFC_BLOCK_BYTES + 2 || resp[0] != MFC_XCHG_REQ || resp[n - 1] != TAG_STATUS_OK) return false;
  memcpy(data, resp + 1, MFC_BLOCK_BYTES);
  return true;
}

static bool reselect(const uint8_t uid[4]) {
  uint8_t got[NFC_UID_MAX] = {0};
  uint8_t got_len = 0;
  return pn7160ReadIso14443a(got, &got_len, RESELECT_TIMEOUT_MS) &&
         got_len == MIFARE_UID_BYTES && memcmp(got, uid, MIFARE_UID_BYTES) == 0;
}

static bool readDataBlocks(uint8_t sector, uint8_t blocks[4][16]) {
  for (uint8_t b = 0; b < MFC_DATA_BLOCKS; b++) {
    if (!pn7160ReadMifareBlock(sector * MFC_BLOCKS_PER_SECTOR + b, blocks[b])) {
      memset(blocks[b], 0, MFC_BLOCK_BYTES);
      return false;
    }
  }
  return true;
}

// The PN532 path tries key B twice within one attempt. Not here: a card that
// refused a key does not take another until it is selected again, and the
// attempt loop does exactly that.
bool pn7160ReadMifareSector(uint8_t sector, const uint8_t key[6], const uint8_t uid[4],
                            uint8_t blocks[4][16], uint8_t key_type) {
  for (uint8_t attempt = 0; attempt < SECTOR_READ_ATTEMPTS; attempt++) {
    if (attempt > 0) {
      delay(RESELECT_PAUSE_MS);
      if (!reselect(uid)) continue;
    }
    if (pn7160AuthMifare(sector, key, key_type) && readDataBlocks(sector, blocks)) return true;
  }
  memset(blocks, 0, MFC_BLOCKS_PER_SECTOR * MFC_BLOCK_BYTES);
  return false;
}

bool pn7160ReadNtagPage(uint8_t page, uint8_t data[4]) {
  if (s_target.proto != NCI_PROT_T2T) return false;
  const uint8_t cmd[] = {CMD_READ, page};
  uint8_t resp[NCI_PAYLOAD_MAX];
  uint8_t n = 0;
  if (!exchange(cmd, sizeof(cmd), resp, &n)) return false;
  if (n < NTAG_READ_BYTES + 1 || resp[n - 1] != TAG_STATUS_OK) return false;
  memcpy(data, resp, NTAG_PAGE_BYTES);
  return true;
}

// The first read a tag turns down, in the normal log: no real ISO 15693 tag
// had been on the bench when this was written, and the first ones are read
// where the verbose switch is out of reach.
static void noteVicinityRefusal(uint8_t command, const uint8_t* resp, uint8_t n) {
  if (memcmp(s_vicinity_fail_logged, s_target.uid, ISO15693_UID_BYTES) == 0) return;
  memcpy(s_vicinity_fail_logged, s_target.uid, ISO15693_UID_BYTES);
  logSDf("PN7160: ISO 15693 command 0x%02X %s, %u bytes, flags 0x%02X, second 0x%02X, last 0x%02X",
         command, n ? "refused" : "unanswered", (unsigned)n, n ? resp[0] : 0,
         n > 1 ? resp[1] : 0, n ? resp[n - 1] : 0);
}

// A read command; the answer is the response flags (0 = no error), the data
// (want bytes) and the interface's status byte.
static bool vicinityRead(const uint8_t* cmd, uint8_t len, size_t want, uint8_t* out) {
  if (s_target.proto != NCI_PROT_T5T) return false;
  uint8_t resp[NCI_PAYLOAD_MAX];
  uint8_t n = 0;
  const bool answered = exchange(cmd, len, resp, &n);
  if (!answered || n < want + 2 || resp[0] != 0 || resp[n - 1] != TAG_STATUS_OK) {
    noteVicinityRefusal(cmd[1], resp, answered ? n : 0);
    return false;
  }
  memcpy(out, resp + 1, want);
  return true;
}

bool pn7160ReadVicinityBlock(uint8_t block, uint8_t data[4]) {
  const uint8_t cmd[] = {ISO15693_FLAGS, ISO15693_READ_SINGLE, block};
  return vicinityRead(cmd, sizeof(cmd), ISO15693_BLOCK_BYTES, data);
}

// READ MULTIPLE BLOCKS for count (1..ISO15693_CHUNK_BLOCKS) blocks from first.
static bool readVicinityChunk(uint8_t first, uint8_t count, uint8_t* out) {
  const uint8_t cmd[] = {ISO15693_FLAGS, ISO15693_READ_MULTIPLE, first, (uint8_t)(count - 1)};
  return vicinityRead(cmd, sizeof(cmd), (size_t)count * ISO15693_BLOCK_BYTES, out);
}

bool pn7160ReadVicinityBlocks(uint8_t first, uint16_t count, uint8_t* out) {
  if (s_target.proto != NCI_PROT_T5T || count == 0 ||
      first + count - 1 > ISO15693_BLOCK_LAST) return false;
  for (uint16_t done = 0; done < count;) {
    const uint16_t left = count - done;
    const uint8_t n = left < ISO15693_CHUNK_BLOCKS ? (uint8_t)left : ISO15693_CHUNK_BLOCKS;
    uint8_t* at = out + (size_t)done * ISO15693_BLOCK_BYTES;
    const uint8_t block = (uint8_t)(first + done);
    // A tag without READ MULTIPLE (the CC says so in byte 3) still answers singles.
    if (!readVicinityChunk(block, n, at)) {
      for (uint8_t i = 0; i < n; i++) {
        if (!pn7160ReadVicinityBlock((uint8_t)(block + i), at + i * ISO15693_BLOCK_BYTES)) return false;
      }
    }
    done += n;
  }
  return true;
}

// One write command, true when the chip passes on the tag's acknowledgement.
static bool writeAcked(const uint8_t* cmd, uint8_t len) {
  uint8_t resp[NCI_PAYLOAD_MAX];
  uint8_t n = 0;
  if (!exchange(cmd, len, resp, &n) || n == 0) return false;
  const uint8_t status = resp[n - 1];
  if (status == TAG_STATUS_OK || status == TAG_STATUS_WRITE_ACK) return true;
  logSDf("PN7160: write 0x%02X 0x%02X refused, status 0x%02X", cmd[0], cmd[1], status);
  return false;
}

bool pn7160WriteNtagPage(uint8_t page, const uint8_t data[4]) {
  if (s_target.proto != NCI_PROT_T2T || page < NTAG_FIRST_WRITABLE_PAGE) return false;
  uint8_t cmd[2 + NTAG_PAGE_BYTES] = {CMD_NTAG_WRITE, page};
  memcpy(cmd + 2, data, NTAG_PAGE_BYTES);
  return writeAcked(cmd, sizeof(cmd));
}

// WRITE SINGLE BLOCK, addressed to uid (as received, LSB first). The tag
// answers with its response flags (0: written, else an error code follows,
// 0x12 for a locked block), the interface adds its status byte.
bool pn7160WriteVicinityBlock(const uint8_t uid[8], uint8_t block, const uint8_t data[4]) {
  if (s_target.proto != NCI_PROT_T5T || block == ISO15693_CC_BLOCK) return false;
  uint8_t cmd[2 + ISO15693_UID_BYTES + 1 + ISO15693_BLOCK_BYTES] = {ISO15693_FLAGS_ADDRESSED,
                                                                     ISO15693_WRITE_SINGLE};
  memcpy(cmd + 2, uid, ISO15693_UID_BYTES);
  cmd[2 + ISO15693_UID_BYTES] = block;
  memcpy(cmd + 3 + ISO15693_UID_BYTES, data, ISO15693_BLOCK_BYTES);
  uint8_t resp[NCI_PAYLOAD_MAX];
  uint8_t n = 0;
  if (!exchange(cmd, sizeof(cmd), resp, &n) || n < 2) return false;
  const uint8_t status = resp[n - 1];
  const bool tag_ok = (resp[0] & ISO15693_ERROR_FLAG) == 0;
  if (tag_ok && (status == TAG_STATUS_OK || status == TAG_STATUS_WRITE_ACK)) return true;
  logSDf("PN7160: ISO 15693 write of block %u refused, flags 0x%02X, error 0x%02X, status 0x%02X",
         block, resp[0], tag_ok ? 0 : resp[1], status);
  return false;
}

// A MIFARE Classic WRITE is two exchanges, each acknowledged by the card:
// the command with the block number, then the 16 bytes.
bool pn7160WriteMifareBlock(uint8_t block, const uint8_t data[16]) {
  if (s_target.proto != NCI_PROT_MIFARE || block == MFC_MANUFACTURER_BLOCK) return false;
  const uint8_t announce[] = {MFC_XCHG_REQ, CMD_MFC_WRITE, block};
  if (!writeAcked(announce, sizeof(announce))) return false;
  uint8_t payload[1 + MFC_BLOCK_BYTES] = {MFC_XCHG_REQ};
  memcpy(payload + 1, data, MFC_BLOCK_BYTES);
  return writeAcked(payload, sizeof(payload));
}

// Discovery running, and every frame the chip still holds read, so IRQ only
// rises again for a tag that comes while the ESP sleeps. A tag lying on the
// reader is selected again at once and leaves IRQ high: false then, and the
// test has to be run with the reader empty.
bool pn7160ArmForWake() {
  if (!s_lib || s_state == RfState::Off) return false;
  const uint32_t deadline = deadlineIn(CTRL_TIMEOUT_MS);
  if (s_state != RfState::Discovery && !rediscover(deadline)) return false;
  // Bounded by count too: readFrame() still reads a pending frame after the
  // deadline, and a chip that kept sending would hold the loop here.
  for (uint8_t i = 0; i < ARM_DRAIN_FRAMES_MAX && readFrame(deadline); i++) {}
  return s_state == RfState::Discovery && digitalRead(hw_pins::NFC_IRQ) != HIGH;
}

void pn7160RfCountsTake(NfcRfCounts* out) {
  if (out) *out = s_rf;
  s_rf = {};
}
