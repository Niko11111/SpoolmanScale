#include "services/niimbot.h"

#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#include "hardware/sd_logger.h"

// The printer's service; the characteristic is whichever one in it notifies
// and takes writes without response (niimbluelib picks it the same way).
#define NB_SERVICE_UUID "e7810a71-73ae-499d-8c15-faa9aef0c3f2"

// niimbluelib's timing: 10 ms between packets, a second for a reply (two
// here, the loop task reads slower), a status poll every 300 ms with 10 s
// for a page, 500 ms between print-end polls.
#define NB_PACKET_GAP_MS       10
#define NB_REPLY_TIMEOUT_MS  2000
#define NB_STATUS_POLL_MS     300
#define NB_PAGE_TIMEOUT_MS  10000
#define NB_END_POLL_MS        500
#define NB_DENSITY              2   // 1 to 5 on the 50 mm class; the app's default
#define NB_LABEL_WITH_GAPS      1   // die-cut labels with a gap between them
#define NB_DATA_MAX           255   // one length byte
#define NB_FRAME_OVERHEAD       7   // 55 55 CMD LEN ... CHK AA AA
#define NB_RX_MAX             600   // unframed bytes kept at most
#define NB_LOG_HEX              8   // reply bytes shown in the log
#define NB_ROW_REPEAT_MAX     255
#define NB_PROGRESS_EVERY       8   // row packets between two overlay ticks
#define NB_CONNECTED_V3         3   // a connect result that comes with a protocol version

// Requests and the replies they get (niimbluelib packets/commands.ts).
#define NB_CMD_CONNECT        0xC1
#define NB_RPL_CONNECT        0xC2
#define NB_CMD_STATUS_DATA    0xA5
#define NB_RPL_STATUS_DATA    0xB5
#define NB_CMD_PRINTER_INFO   0x40   // the reply is 0x40 plus the info type
#define NB_INFO_MODEL_ID         8
#define NB_INFO_SOFTWARE         9
#define NB_INFO_BATTERY         10
#define NB_INFO_HARDWARE        12
#define NB_CMD_SET_DENSITY    0x21
#define NB_RPL_SET_DENSITY    0x31
#define NB_CMD_SET_LABEL_TYPE 0x23
#define NB_RPL_SET_LABEL_TYPE 0x33
#define NB_CMD_PRINT_START    0x01
#define NB_RPL_PRINT_START    0x02
#define NB_CMD_PRINT_CLEAR    0x20
#define NB_RPL_PRINT_CLEAR    0x30
#define NB_CMD_PAGE_START     0x03
#define NB_RPL_PAGE_START     0x04
#define NB_CMD_PAGE_SIZE      0x13
#define NB_RPL_PAGE_SIZE      0x14
#define NB_CMD_PRINT_QUANTITY 0x15
#define NB_RPL_PRINT_QUANTITY 0x16
#define NB_CMD_BITMAP_ROW     0x85
#define NB_CMD_EMPTY_ROWS     0x84
#define NB_CMD_PAGE_END       0xE3
#define NB_RPL_PAGE_END       0xE4
#define NB_CMD_PRINT_STATUS   0xA3
#define NB_RPL_PRINT_STATUS   0xB3
#define NB_CMD_PRINT_END      0xF3
#define NB_RPL_PRINT_END      0xF4
#define NB_RPL_ERROR          0xDB
#define NB_RPL_NOT_SUPPORTED  0x00
// The codes an error reply carries.
#define NB_ERR_COVER_OPEN     0x01
#define NB_ERR_NO_PAPER       0x02
#define NB_ERR_BUSY           0x09
#define NB_ERR_NO_RIBBON      0x0D
#define NB_ERR_WRONG_RIBBON   0x0E
#define NB_ERR_USED_RIBBON    0x0F
// Where the replies keep what is read out of them.
#define NB_STATUS_DATA_MIN_LEN  13  // the status data up to its version bytes
#define NB_STATUS_DATA_VER_HI   11  // the version as hi * 100 + lo
#define NB_STATUS_DATA_VER_LO   12
#define NB_PROTO_V4_FROM       300  // the first status version of protocol 4
#define NB_PROTO_V3_FROM       204  // and of protocol 3
#define NB_PRINT_STATUS_ERR_LEN 10  // a print status this long carries an error code
#define NB_PRINT_STATUS_ERR_AT   6

// id, name, task, head dots, dpi, direction, ribbon, task guessed. Ids and
// heads from niimbluelib printer_models.ts, the task from its print_tasks
// table; "guess" where that table has no entry for the id, so the B1's
// sequence goes as the most common one. The tape printers (LEFT) are here
// only so a mismatch can say what was found.
static const NiimbotModelInfo NB_MODELS[] = {
  { 4096, "B1",       NB_TASK_B1,     384, 203, NB_DIR_TOP,  false, false },
  { 4098, "B1 SE",    NB_TASK_B1,     384, 203, NB_DIR_TOP,  false, true  },
  {  768, "B21",      NB_TASK_B21_V1, 384, 203, NB_DIR_TOP,  false, false },
  {  771, "B21 C2B",  NB_TASK_B1,     384, 203, NB_DIR_TOP,  false, false },
  {  775, "B21 C2B",  NB_TASK_B1,     384, 203, NB_DIR_TOP,  false, false },
  {  777, "B21S",     NB_TASK_D110,   384, 203, NB_DIR_TOP,  false, false },
  {  776, "B21S C2B", NB_TASK_D110,   384, 203, NB_DIR_TOP,  false, false },
  { 2816, "B203",     NB_TASK_B1,     400, 203, NB_DIR_TOP,  false, true  },
  { 6913, "B2",       NB_TASK_B1,     384, 203, NB_DIR_TOP,  false, true  },
  { 4608, "M2",       NB_TASK_B1,     567, 300, NB_DIR_TOP,  true,  false },
  { 2304, "D110",     NB_TASK_D110,    96, 203, NB_DIR_LEFT, false, false },
  { 2305, "D110",     NB_TASK_D110,    96, 203, NB_DIR_LEFT, false, false },
  {  512, "D11",      NB_TASK_D110,    96, 203, NB_DIR_LEFT, false, false },
  { 2560, "D101",     NB_TASK_B1,     192, 203, NB_DIR_LEFT, false, false },
  { 3584, "B18",      NB_TASK_B1,      96, 203, NB_DIR_LEFT, true,  true  },
  {  256, "B3S",      NB_TASK_B1,     576, 203, NB_DIR_TOP,  false, true  },
  { 4864, "K3",       NB_TASK_B1,     640, 203, NB_DIR_TOP,  false, true  },
};

const NiimbotModelInfo* niimbotModelById(uint16_t id) {
  for (const NiimbotModelInfo& m : NB_MODELS)
    if (m.id == id) return &m;
  return nullptr;
}

const char* niimbotErrorName(uint8_t code) {
  switch (code) {
    case 0x01: return "cover open";
    case 0x02: return "no paper";
    case 0x03: return "low battery";
    case 0x04: return "battery fault";
    case 0x05: return "cancelled";
    case 0x06: return "data error";
    case 0x07: return "overheated";
    case 0x08: return "paper out fault";
    case 0x09: return "busy";
    case 0x0A: return "no print head";
    case 0x0B: return "too cold";
    case 0x0C: return "print head loose";
    case 0x0D: return "no ribbon";
    case 0x0E: return "wrong ribbon";
    case 0x0F: return "ribbon used up";
    case 0x10: return "wrong paper";
    case 0x11: return "set paper failed";
    case 0x12: return "set print mode failed";
    case 0x13: return "set density failed";
    case 0x16: return "communication fault";
    case 0x17: return "disconnected";
    default:   return "?";
  }
}

// One job at a time, and its buffers are better off the loop task's stack.
struct NbJob {
  NiimbotJobInfo* info;
  const NiimbotModelInfo* model;
  BleProgressFn progress;
  uint32_t t0;
  bool     connect_prefix;      // the 0x03 the app sends before its connect frame
  bool     first_row_logged;
  uint8_t  chunk;               // bytes per third for the row counts, 0 = total mode
  uint16_t tx, rx_frames;
  uint8_t  rx[NB_RX_MAX];
  size_t   rx_len;
  uint8_t  cmd, len;            // the frame last taken
  uint8_t  data[NB_DATA_MAX];
};
static NbJob s_job;

static uint8_t checksum(uint8_t cmd, const uint8_t* data, uint8_t len) {
  uint8_t c = cmd ^ len;
  for (uint8_t i = 0; i < len; i++) c ^= data[i];
  return c;
}

static void putU16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

// 55 55 CMD LEN DATA CHK AA AA, the connect frame alone with the app's 0x03
// in front. Rows go quiet: a label is a few hundred of them.
static bool nbSend(NbJob& job, uint8_t cmd, const uint8_t* data, uint8_t len, bool quiet) {
  uint8_t pkt[1 + NB_FRAME_OVERHEAD + NB_DATA_MAX];
  size_t n = 0;
  if (cmd == NB_CMD_CONNECT && job.connect_prefix) pkt[n++] = 0x03;
  pkt[n++] = 0x55; pkt[n++] = 0x55;
  pkt[n++] = cmd;  pkt[n++] = len;
  memcpy(pkt + n, data, len);
  n += len;
  pkt[n++] = checksum(cmd, data, len);
  pkt[n++] = 0xAA; pkt[n++] = 0xAA;
  if (!quiet) logSDf("NIIMBOT: tx %02X len=%u", cmd, (unsigned)len);
  if (!bleTalkSend(pkt, n)) return false;
  job.tx++;
  delay(NB_PACKET_GAP_MS);
  return true;
}

static void nbPump(NbJob& job, uint32_t wait_ms) {
  if (job.rx_len >= sizeof(job.rx)) return;
  job.rx_len += bleTalkRead(job.rx + job.rx_len, sizeof(job.rx) - job.rx_len, wait_ms);
}

static void nbDrop(NbJob& job, size_t n) {
  memmove(job.rx, job.rx + n, job.rx_len - n);
  job.rx_len -= n;
}

// The next whole frame off the buffer into cmd/len/data. Bytes before a
// header and a frame with a wrong checksum or tail go one byte at a time,
// so the stream finds its footing again, and the log says so.
static bool nbTakeFrame(NbJob& job) {
  while (job.rx_len >= NB_FRAME_OVERHEAD) {
    if (job.rx[0] != 0x55 || job.rx[1] != 0x55) { nbDrop(job, 1); continue; }
    const uint8_t len = job.rx[3];
    const size_t need = NB_FRAME_OVERHEAD + len;
    if (job.rx_len < need) return false;      // the rest is still on its way
    const uint8_t cmd = job.rx[2];
    const uint8_t chk = job.rx[4 + len];
    const bool tail_ok = job.rx[5 + len] == 0xAA && job.rx[6 + len] == 0xAA;
    if (chk != checksum(cmd, job.rx + 4, len) || !tail_ok) {
      logSDf("NIIMBOT: bad frame cmd=%02X len=%u chk=%02X tail=%u, resyncing",
             cmd, len, chk, (unsigned)tail_ok);
      nbDrop(job, 1);
      continue;
    }
    job.cmd = cmd;
    job.len = len;
    memcpy(job.data, job.rx + 4, len);
    nbDrop(job, need);
    job.rx_frames++;
    return true;
  }
  return false;
}

static void nbLogFrame(const NbJob& job, const char* what) {
  char hex[3 * NB_LOG_HEX + 1] = "";
  const uint8_t n = job.len < NB_LOG_HEX ? job.len : NB_LOG_HEX;
  for (uint8_t i = 0; i < n; i++) snprintf(hex + 3 * i, sizeof(hex) - 3 * i, "%02X ", job.data[i]);
  logSDf("NIIMBOT: %s %02X len=%u [%s] at %u ms", what, job.cmd, (unsigned)job.len, hex,
         (unsigned)(millis() - job.t0));
}

static NiimbotResult nbErrorResult(NbJob& job, uint8_t code) {
  if (job.info) job.info->error_code = code;
  logSDf("NIIMBOT: printer error %02X (%s)", code, niimbotErrorName(code));
  switch (code) {
    case NB_ERR_COVER_OPEN:   return NB_PRN_COVER;
    case NB_ERR_NO_PAPER:     return NB_PRN_NO_PAPER;
    case NB_ERR_BUSY:         return NB_PRN_BUSY;
    case NB_ERR_NO_RIBBON:
    case NB_ERR_WRONG_RIBBON:
    case NB_ERR_USED_RIBBON:  return NB_PRN_NO_RIBBON;
    default:                  return NB_PRN_ERROR;
  }
}

// Waits for the reply to a request. An error ends the wait; any other
// frame is logged and skipped, which is how an unknown reply reaches a
// tester's log without stopping the print.
static NiimbotResult nbAwait(NbJob& job, uint8_t expect, uint32_t timeout_ms) {
  const uint32_t from = millis();
  for (;;) {
    const uint32_t spent = millis() - from;
    if (spent >= timeout_ms) break;
    nbPump(job, timeout_ms - spent);
    while (nbTakeFrame(job)) {
      if (job.cmd == expect) { nbLogFrame(job, "rx"); return NB_OK; }
      if (job.cmd == NB_RPL_ERROR && job.len >= 1) {
        nbLogFrame(job, "rx error");
        return nbErrorResult(job, job.data[0]);
      }
      if (job.cmd == NB_RPL_NOT_SUPPORTED) { nbLogFrame(job, "rx not supported"); return NB_REJECTED; }
      nbLogFrame(job, "rx unexpected");
    }
    if (!bleTalkConnected()) { logSD("NIIMBOT: link gone while waiting"); return NB_TRANSPORT; }
  }
  logSDf("NIIMBOT: no %02X within %u ms, %u unframed byte(s) dropped",
         expect, (unsigned)timeout_ms, (unsigned)job.rx_len);
  job.rx_len = 0;
  return NB_NO_REPLY;
}

static NiimbotResult nbRequest(NbJob& job, uint8_t cmd, const uint8_t* data, uint8_t len,
                               uint8_t expect) {
  if (!nbSend(job, cmd, data, len, false)) return NB_TRANSPORT;
  return nbAwait(job, expect, NB_REPLY_TIMEOUT_MS);
}

static NiimbotResult nbRequest1(NbJob& job, uint8_t cmd, uint8_t value, uint8_t expect) {
  return nbRequest(job, cmd, &value, 1, expect);
}

// Newer firmware answers the connect with 3 and tells its protocol version
// in the status data; nothing here depends on it yet, the log keeps it.
static void nbLogProtocolVersion(NbJob& job) {
  if (nbRequest1(job, NB_CMD_STATUS_DATA, 1, NB_RPL_STATUS_DATA) != NB_OK ||
      job.len < NB_STATUS_DATA_MIN_LEN) return;
  const unsigned n = job.data[NB_STATUS_DATA_VER_HI] * 100u + job.data[NB_STATUS_DATA_VER_LO];
  const uint8_t v = n >= NB_PROTO_V4_FROM ? 4 : n >= NB_PROTO_V3_FROM ? 3 : 0;
  if (job.info) job.info->protocol_version = v;
  logSDf("NIIMBOT: protocol version %u (status %u)", (unsigned)v, n);
}

static NiimbotResult nbHello(NbJob& job) {
  NiimbotResult r = nbRequest1(job, NB_CMD_CONNECT, 1, NB_RPL_CONNECT);
  if (r == NB_NO_REPLY) {
    // The 0x03 the app puts before its connect frame may be what this
    // firmware chokes on: once more without it, and the log says which went.
    logSD("NIIMBOT: no connect reply, once more without the 0x03 prefix");
    job.connect_prefix = false;
    r = nbRequest1(job, NB_CMD_CONNECT, 1, NB_RPL_CONNECT);
  }
  if (r != NB_OK) return r;
  const uint8_t connect = job.len ? job.data[0] : 0;
  if (job.info) job.info->connect_result = connect;
  logSDf("NIIMBOT: connected, result=%u prefix=%u", (unsigned)connect, (unsigned)job.connect_prefix);
  if (connect == NB_CONNECTED_V3) nbLogProtocolVersion(job);
  return NB_OK;
}

// Software, hardware and battery: for the log, and a model may refuse one.
static void nbLogExtras(NbJob& job) {
  static const struct { uint8_t type; const char* what; } EXTRAS[] = {
    { NB_INFO_SOFTWARE, "software" }, { NB_INFO_HARDWARE, "hardware" }, { NB_INFO_BATTERY, "battery" },
  };
  for (const auto& e : EXTRAS)
    if (nbRequest1(job, NB_CMD_PRINTER_INFO, e.type, NB_CMD_PRINTER_INFO + e.type) != NB_OK)
      logSDf("NIIMBOT: no %s info, going on", e.what);
}

static const char* taskName(NiimbotTask t) {
  return t == NB_TASK_B1 ? "B1" : t == NB_TASK_D110 ? "D110" : "B21_V1";
}

static bool classFits(NiimbotClass cls, const NiimbotModelInfo& m) {
  if (m.dir != NB_DIR_TOP) return false;
  if (cls == NB_CLASS_M2) return m.dpi == 300 && m.head_px <= 568;
  return m.dpi == 203 && m.head_px >= 384 && m.head_px <= 400;
}

static NiimbotResult nbCheckModel(NbJob& job, NiimbotClass cls, uint16_t id) {
  const NiimbotModelInfo* m = niimbotModelById(id);
  if (job.info) { job.info->model_id = id; job.info->info = m; }
  if (!m) {
    logSDf("NIIMBOT: model id=0x%04X (%u) not in the table, please report it", id, id);
    return NB_MODEL_UNKNOWN;
  }
  logSDf("NIIMBOT: model id=0x%04X %s task=%s%s head=%u dpi=%u dir=%s%s", id, m->name,
         taskName(m->task), m->task_is_guess ? " (guess)" : "", m->head_px, m->dpi,
         m->dir == NB_DIR_TOP ? "top" : "left", m->thermal_transfer ? " ribbon" : "");
  if (!classFits(cls, *m)) {
    logSDf("NIIMBOT: %s is not of the picked class %s", m->name, cls == NB_CLASS_M2 ? "M2" : "B");
    return NB_MODEL_MISMATCH;
  }
  job.model = m;
  return NB_OK;
}

// A hello, then what the printer is: the id decides the task and the row.
static NiimbotResult nbIdentify(NbJob& job, NiimbotClass cls) {
  NiimbotResult r = nbHello(job);
  if (r != NB_OK) return r;
  r = nbRequest1(job, NB_CMD_PRINTER_INFO, NB_INFO_MODEL_ID, NB_CMD_PRINTER_INFO + NB_INFO_MODEL_ID);
  if (r != NB_OK) return r;
  if (job.len < 1) return NB_NO_REPLY;
  // Older firmware sends the high byte alone (niimbluelib).
  const uint16_t id = job.len == 1 ? (uint16_t)(job.data[0] << 8)
                                   : (uint16_t)((job.data[0] << 8) | job.data[1]);
  nbLogExtras(job);
  return nbCheckModel(job, cls, id);
}

static NiimbotResult nbInit(NbJob& job) {
  NiimbotResult r = nbRequest1(job, NB_CMD_SET_DENSITY, NB_DENSITY, NB_RPL_SET_DENSITY);
  if (r != NB_OK) return r;
  r = nbRequest1(job, NB_CMD_SET_LABEL_TYPE, NB_LABEL_WITH_GAPS, NB_RPL_SET_LABEL_TYPE);
  if (r != NB_OK) return r;
  if (job.model->task == NB_TASK_B1) {
    // One page, single colour: u16 pages, four zero bytes, the colour.
    static const uint8_t start[7] = { 0, 1, 0, 0, 0, 0, 0 };
    return nbRequest(job, NB_CMD_PRINT_START, start, sizeof(start), NB_RPL_PRINT_START);
  }
  return nbRequest1(job, NB_CMD_PRINT_START, 1, NB_RPL_PRINT_START);
}

static NiimbotResult nbPageStart(NbJob& job, uint16_t rows, uint16_t cols) {
  const NiimbotTask task = job.model->task;
  NiimbotResult r = NB_OK;
  if (task == NB_TASK_D110) r = nbRequest1(job, NB_CMD_PRINT_CLEAR, 1, NB_RPL_PRINT_CLEAR);
  if (r != NB_OK) return r;
  r = nbRequest1(job, NB_CMD_PAGE_START, 1, NB_RPL_PAGE_START);
  if (r != NB_OK) return r;
  // rows along the feed, cols across the head, and on the B1's task the
  // copies as well. The D110's task sends the quantity in a packet of its
  // own after this; the B21's sends none and repeats the page for a second
  // copy (niimbluelib's B21V1PrintTask).
  uint8_t size[6];
  putU16(size, rows);
  putU16(size + 2, cols);
  putU16(size + 4, 1);
  r = nbRequest(job, NB_CMD_PAGE_SIZE, size, task == NB_TASK_B1 ? 6 : 4, NB_RPL_PAGE_SIZE);
  if (r != NB_OK) return r;
  if (task != NB_TASK_D110) return NB_OK;
  static const uint8_t one[2] = { 0, 1 };
  return nbRequest(job, NB_CMD_PRINT_QUANTITY, one, 2, NB_RPL_PRINT_QUANTITY);
}

// The three count bytes of a row: black dots per third of the head while
// the row fits three whole thirds (384 dots: 16 bytes each), else, and on
// the B21's task always, the total as a big-endian u16 behind a zero.
// From niimbluelib's countPixelsForBitmapPacket. chunk is the bytes per
// third, 0 for the total form.
static void nbRowCounts(const uint8_t* row, uint8_t nbytes, uint8_t chunk, uint8_t out[3]) {
  uint16_t total = 0, parts[3] = { 0, 0, 0 };
  for (uint8_t b = 0; b < nbytes; b++) {
    uint8_t bits = 0;
    for (uint8_t v = row[b]; v; v &= (uint8_t)(v - 1)) bits++;
    total += bits;
    if (chunk && b / chunk < 3) parts[b / chunk] += bits;
  }
  if (!chunk) {
    out[0] = 0;
    putU16(out + 1, total);
    return;
  }
  for (int i = 0; i < 3; i++) out[i] = parts[i] > 255 ? 255 : (uint8_t)parts[i];
}

static bool nbSendBitmapRow(NbJob& job, uint16_t y, uint8_t repeat, const uint8_t* row, uint8_t nbytes) {
  uint8_t data[6 + NB_DATA_MAX];
  putU16(data, y);
  nbRowCounts(row, nbytes, job.chunk, data + 2);
  data[5] = repeat;
  memcpy(data + 6, row, nbytes);
  if (!job.first_row_logged) {
    job.first_row_logged = true;
    logSDf("NIIMBOT: first row y=%u counts %02X %02X %02X repeat=%u bytes=%u (chunk %u)",
           y, data[2], data[3], data[4], repeat, nbytes, job.chunk);
  }
  return nbSend(job, NB_CMD_BITMAP_ROW, data, (uint8_t)(6 + nbytes), true);
}

static bool nbSendEmptyRows(NbJob& job, uint16_t y, uint8_t repeat) {
  uint8_t data[3];
  putU16(data, y);
  data[2] = repeat;
  return nbSend(job, NB_CMD_EMPTY_ROWS, data, 3, true);
}

static bool rowBlank(const uint8_t* row, uint8_t nbytes) {
  for (uint8_t i = 0; i < nbytes; i++)
    if (row[i]) return false;
  return true;
}

// How many rows from y on are the same as row y, this one included.
static uint16_t nbRunLength(const LabelRaster& image, uint16_t y, uint8_t copy) {
  const uint8_t* first = image.pixels + (size_t)y * image.row_bytes;
  uint16_t run = 1;
  while (y + run < image.height && run < NB_ROW_REPEAT_MAX &&
         memcmp(image.pixels + (size_t)(y + run) * image.row_bytes, first, copy) == 0)
    run++;
  return run;
}

// The raster row by row into a row buffer the head's width: zeros fill what
// the raster leaves (a B203's 400 dots take the 384 wide raster). A run of
// equal rows goes once with its count, a blank run as empty rows.
static NiimbotResult nbSendRows(NbJob& job, const LabelRaster& image) {
  const uint8_t nbytes = (uint8_t)((job.model->head_px + 7) / 8);
  const uint8_t copy = image.row_bytes < nbytes ? (uint8_t)image.row_bytes : nbytes;
  const uint8_t third = (uint8_t)(job.model->head_px / 8 / 3);
  job.chunk = job.model->task != NB_TASK_B21_V1 && nbytes <= third * 3 ? third : 0;
  uint8_t row[NB_DATA_MAX];
  unsigned packets = 0, blank = 0, merged = 0;
  bleTalkSetPhase(BLE_PHASE_SEND);
  const uint32_t from = millis();
  for (uint16_t y = 0; y < image.height;) {
    memset(row, 0, nbytes);
    memcpy(row, image.pixels + (size_t)y * image.row_bytes, copy);
    const uint16_t run = nbRunLength(image, y, copy);
    bool ok;
    if (rowBlank(row, nbytes)) { blank += run; ok = nbSendEmptyRows(job, y, (uint8_t)run); }
    else ok = nbSendBitmapRow(job, y, (uint8_t)run, row, nbytes);
    if (!ok) return NB_TRANSPORT;
    packets++;
    merged += run - 1;
    y += run;
    bleTalkSetProgress(y, image.height);
    if (job.progress && packets % NB_PROGRESS_EVERY == 0) job.progress();
  }
  logSDf("NIIMBOT: %u rows, %u packets (%u blank, %u merged) in %u ms",
         (unsigned)image.height, packets, blank, merged, (unsigned)(millis() - from));
  return NB_OK;
}

// The B21's task: ask for the print's end until the printer agrees.
static NiimbotResult nbFinishByEnd(NbJob& job) {
  const uint32_t from = millis();
  while (millis() - from < NB_PAGE_TIMEOUT_MS) {
    const NiimbotResult r = nbRequest1(job, NB_CMD_PRINT_END, 1, NB_RPL_PRINT_END);
    if (r != NB_OK) return r;
    if (job.len >= 1 && job.data[0] == 1) return NB_OK;
    delay(NB_END_POLL_MS);
    if (job.progress) job.progress();
  }
  return NB_UNCONFIRMED;
}

// The others: poll the status until the page count says the page is out,
// then end the print. A refused end after a printed page is only logged.
static NiimbotResult nbFinishByStatus(NbJob& job) {
  const uint32_t from = millis();
  unsigned polls = 0;
  bool printed = false;
  while (!printed && millis() - from < NB_PAGE_TIMEOUT_MS) {
    const NiimbotResult r = nbRequest1(job, NB_CMD_PRINT_STATUS, 1, NB_RPL_PRINT_STATUS);
    if (r != NB_OK) return r;
    polls++;
    const uint16_t page = job.len >= 2 ? (uint16_t)((job.data[0] << 8) | job.data[1]) : 0;
    logSDf("NIIMBOT: status page=%u print=%u feed=%u (poll %u)", page,
           job.len >= 3 ? job.data[2] : 0, job.len >= 4 ? job.data[3] : 0, polls);
    if (job.len == NB_PRINT_STATUS_ERR_LEN && job.data[NB_PRINT_STATUS_ERR_AT])
      return nbErrorResult(job, job.data[NB_PRINT_STATUS_ERR_AT]);
    printed = page >= 1;
    if (!printed) delay(NB_STATUS_POLL_MS);
    if (job.progress) job.progress();
  }
  if (nbRequest1(job, NB_CMD_PRINT_END, 1, NB_RPL_PRINT_END) != NB_OK)
    logSD("NIIMBOT: print end not acknowledged");
  return printed ? NB_OK : NB_UNCONFIRMED;
}

static NiimbotResult nbFinish(NbJob& job) {
  bleTalkSetPhase(BLE_PHASE_AWAIT);
  return job.model->task == NB_TASK_B21_V1 ? nbFinishByEnd(job) : nbFinishByStatus(job);
}

static NiimbotResult nbRun(NbJob& job, const LabelRaster& image, NiimbotClass cls) {
  NiimbotResult r = nbIdentify(job, cls);
  if (r != NB_OK) return r;
  r = nbInit(job);
  if (r != NB_OK) return r;
  // The page is as wide as the row bytes say, as niimbluelib sends it.
  const uint16_t cols = (uint16_t)(((job.model->head_px + 7) / 8) * 8);
  r = nbPageStart(job, image.height, cols);
  if (r != NB_OK) return r;
  r = nbSendRows(job, image);
  if (r != NB_OK) return r;
  r = nbRequest1(job, NB_CMD_PAGE_END, 1, NB_RPL_PAGE_END);
  if (r == NB_OK) r = nbFinish(job);
  // Every row went out: a printer that falls silent now may well have
  // printed, which is what "unconfirmed" says, not "no NIIMBOT".
  return r == NB_NO_REPLY ? NB_UNCONFIRMED : r;
}

NiimbotResult niimbotPrint(const char* address, const LabelRaster& image, NiimbotClass cls,
                           BleProgressFn progress, NiimbotJobInfo* info) {
  NbJob& job = s_job;
  memset(&job, 0, sizeof(job));
  job.info = info;
  job.progress = progress;
  job.t0 = millis();
  job.connect_prefix = true;
  if (info) *info = NiimbotJobInfo{};
  if (!labelRasterValid(image)) return NB_TRANSPORT;

  const BleTalkEndpoint ep = { NB_SERVICE_UUID, (uint8_t)(BLE_PROP_NOTIFY | BLE_PROP_WRITE_NR) };
  const BleWriteResult open = bleTalkOpen(address, ep, progress);
  if (info) info->transport = open;
  if (open != BLE_WRITE_OK) {
    logSDf("NIIMBOT: session not opened, transport=%d", (int)open);
    bleTalkClose();
    return NB_TRANSPORT;
  }
  const NiimbotResult r = nbRun(job, image, cls);
  const BleWriteResult closed = bleTalkClose();
  if (info) {
    if (closed == BLE_WRITE_STUCK) info->transport = closed;
    else if (r == NB_TRANSPORT) info->transport = BLE_WRITE_FAILED;
    info->packets_tx = job.tx;
    info->packets_rx = job.rx_frames;
  }
  logSDf("NIIMBOT: result=%d after %u ms, tx=%u rx=%u", (int)r, (unsigned)(millis() - job.t0),
         (unsigned)job.tx, (unsigned)job.rx_frames);
  return r;
}
