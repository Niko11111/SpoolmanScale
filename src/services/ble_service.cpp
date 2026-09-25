#include "services/ble_service.h"

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <esp_heap_caps.h>
#include <nvs.h>
#include <stdio.h>

#include "hardware/sd_logger.h"
#include "services/backend_job.h"
#include "services/breadcrumb.h"
#include "services/prefs_store.h"
#include "services/user_options.h"

// A scan runs in slices so the loading overlay can be advanced between them.
// NimBLE keeps the results across slices when getResults() is told to
// continue rather than start over.
#define BLE_SCAN_SLICE_MS 1000

// See bleStackStuck() in the header: set once, cleared by a restart.
static bool s_stuck = false;

// Arduino gives the Bluetooth controller's memory back to the heap at boot,
// about 36 kB of internal RAM, unless a Bluetooth library is linked in -
// NimBLE is, so it kept it whether the switch was on or not: 141 instead of
// 174 kB free at idle (25.09.2026). bleInUse() is the core's hook for that
// decision, asked in initArduino() before setup(). It answers with the
// switch, read straight from NVS because nothing else is up yet. Memory given
// back cannot be taken again, so switching Bluetooth on later needs a restart
// (ui/bluetooth_screen.cpp asks for it).
#define BLE_PREFS_NS  "spoolscale"
#define BLE_PREFS_KEY "ble_on"

static bool s_mem_kept = false;

extern "C" bool bleInUse(void) {
  uint8_t on = 0;
  nvs_handle_t h;
  if (nvs_open(BLE_PREFS_NS, NVS_READONLY, &h) == ESP_OK) {
    if (nvs_get_u8(h, BLE_PREFS_KEY, &on) != ESP_OK) on = 0;
    nvs_close(h);
  }
  s_mem_kept = (on != 0);
  return s_mem_kept;
}

bool bleStackAvailable() { return s_mem_kept; }
bool bleEnabled() { return g_ble_enabled; }
bool bleStackStuck() { return s_stuck; }

void bleSetEnabled(bool on) {
  g_ble_enabled = on;
  prefsPutBool(BLE_PREFS_KEY, on);
}

// WiFi runs without modem sleep (services/wifi_manager.cpp), and ESP-IDF
// wants it on while Bluetooth shares the radio. So it is on for exactly as
// long as the stack is up.
static void radioShare(bool bt_up) {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  WiFi.setSleep(bt_up);
#else
  (void)bt_up;
#endif
}

// The stack is started and released in these two places only, so the radio
// sharing and the crumbs cannot be forgotten on one of the ways out.
static bool stackUp() {
  radioShare(true);
  if (NimBLEDevice::init("")) return true;
  radioShare(false);
  return false;
}

static void stackDown() {
  NimBLEDevice::deinit(true);
  radioShare(false);
}

// The numbers the RAM question is decided on: how much internal heap the
// stack takes while it is up, and whether all of it comes back afterwards.
// Internal only, because that is where the controller and the host allocate;
// PSRAM is of no use to them.
static void logHeap(const char* when) {
  logSDf("BLE: heap %s internal free=%u largest=%u", when,
         (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
         (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
}

// The stack took about 41 kB of internal heap on core 3 (25.09.2026: 110 kB
// free before, 69 kB with it up, all of it back afterwards). It is started
// only with that and a margin for WiFi and TLS free, and not while the backend
// worker has a list in flight: the two ran into each other on the device, so a
// session waits for the worker first, under the overlay.
#define BLE_MIN_FREE_INTERNAL  (64u * 1024u)
#define BLE_WORKER_WAIT_MS     20000
#define BLE_WORKER_POLL_MS       100

static bool stackMayStart(BleProgressFn progress) {
  uint32_t waited = 0;
  while (backendListBusy() && waited < BLE_WORKER_WAIT_MS) {
    delay(BLE_WORKER_POLL_MS);
    waited += BLE_WORKER_POLL_MS;
    if (progress && waited % 1000 == 0) progress();
  }
  if (waited) logSDf("BLE: waited %u ms for the backend worker", (unsigned)waited);
  if (backendListBusy()) {
    logSD("BLE: backend worker still busy, not starting the stack");
    return false;
  }
  if (!s_mem_kept) {
    logSD("BLE: controller memory was given back at boot, a restart is needed");
    return false;
  }
  const size_t free_int = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  if (free_int < BLE_MIN_FREE_INTERNAL) {
    logSDf("BLE: internal heap %u below %u, not starting the stack",
           (unsigned)free_int, (unsigned)BLE_MIN_FREE_INTERNAL);
    return false;
  }
  return true;
}

static void copyDevice(BleDevice& out, const NimBLEAdvertisedDevice* dev) {
  snprintf(out.name, sizeof(out.name), "%s", dev->getName().c_str());
  snprintf(out.address, sizeof(out.address), "%s", dev->getAddress().toString().c_str());
  out.rssi = dev->getRSSI();
}

int bleScan(BleDevice* out, int capacity, uint32_t duration_ms, BleProgressFn progress) {
  if (!out || capacity <= 0) return 0;
  if (!g_ble_enabled || s_stuck) return -1;
  if (!stackMayStart(progress)) return -1;

  crumbSet("ble scan init");
  logHeap("before init");
  if (!stackUp()) {
    crumbSet("loop");
    logHeap("after failed init");
    logSD("BLE: init failed");
    return -1;
  }
  logHeap("after init");

  int count = 0;
  NimBLEScan* scan = NimBLEDevice::getScan();
  if (!scan) {
    logSD("BLE: no scan object");
  } else {
    // Active: the scan response is where most devices carry their name.
    scan->setActiveScan(true);
    // One report per device: a phone next door advertises ten times a
    // second, and every report is work on the host task.
    scan->setDuplicateFilter(true);
    scan->setMaxResults(capacity > 255 ? 255 : (uint8_t)capacity);

    uint32_t elapsed = 0;
    while (elapsed < duration_ms) {
      uint32_t slice = duration_ms - elapsed;
      if (slice > BLE_SCAN_SLICE_MS) slice = BLE_SCAN_SLICE_MS;
      crumbSet("ble scan slice");
      scan->getResults(slice, elapsed > 0);
      elapsed += slice;
      if (progress) progress();
    }
    crumbSet("ble scan read");

    // The results are read here on the loop task, not in a callback on the
    // host task with its 4 kB of stack. Named devices first: they are the
    // ones a person can recognise, and the list shows only them unless asked
    // for all (ui/ble_devices_screen.cpp).
    NimBLEScanResults results = scan->getResults();
    for (int pass = 0; pass < 2 && count < capacity; pass++) {
      for (int i = 0; i < results.getCount() && count < capacity; i++) {
        const NimBLEAdvertisedDevice* dev = results.getDevice(i);
        if (!dev) continue;
        const bool named = dev->haveName() && dev->getName().length() > 0;
        if ((pass == 0) != named) continue;
        copyDevice(out[count++], dev);
      }
    }
    scan->clearResults();
  }

  crumbSet("ble scan deinit");
  stackDown();
  crumbSet("loop");
  logHeap("after deinit");
  logSDf("BLE: scan %u ms, %d devices", (unsigned)duration_ms, count);
  return count;
}

// How long a chunk is given to settle before the next one. The printers do
// not flow-control; without a pause the link drops mid raster.
#define BLE_WRITE_CHUNK_GAP_MS 20
// A write never exceeds the MTU minus the 3 byte ATT header, and never 128
// bytes: what the M-series printers take in one go.
#define BLE_WRITE_CHUNK_MAX    128
// A write without response is refused, not queued, while the controller's
// buffers are full. Seen on the M220 after 15 chunks (23.09.2026): that is
// back pressure, not a fault, so a refused chunk waits and goes again.
#define BLE_WRITE_RETRIES       40
#define BLE_WRITE_RETRY_MS      25
#define BLE_WRITE_CHUNK_MIN    20
// Asked for at connect; the printer answers with what it can do.
#define BLE_PREFERRED_MTU      185
// How long a disconnect may take before the client is declared stuck.
#define BLE_DISCONNECT_WAIT_MS 3000
// A device is connected to as the scan saw it, address type included: the
// M-series printers advertise with a random address, and a connect to it as
// a public one fails at once. So a session looks for the device first, in
// short slices, and gives up on a printer that is not in range.
#define BLE_FIND_MS            4000
#define BLE_FIND_SLICE_MS       500
#define BLE_FIND_MAX_RESULTS     20
#define BLE_CONNECT_TIMEOUT_MS 8000
// Events of a failed connect may still be in flight when the client goes.
#define BLE_SETTLE_MS           200
// HCI 0x3E, "connection failed to be established": the request went out and
// the peripheral did not answer. Transient when its advertising is sparse,
// so a few tries; lasting when it is connected elsewhere, which the log
// then shows as the same code every time.
#define BLE_ERR_CONN_NOT_ESTABLISHED (0x200 + 0x3E)
#define BLE_CONNECT_TRIES       3
#define BLE_CONNECT_RETRY_MS    400
// How often a session looks for the done signal while it waits.
#define BLE_DONE_POLL_MS         50

static volatile BleSessionPhase s_phase = BLE_PHASE_IDLE;
static size_t s_sent = 0, s_total = 0;

BleSessionPhase bleSessionPhase() { return s_phase; }
void bleSessionBytes(size_t* sent, size_t* total) {
  if (sent)  *sent  = s_sent;
  if (total) *total = s_total;
}

static size_t chunkFor(uint16_t mtu) {
  if (mtu <= 3) return BLE_WRITE_CHUNK_MIN;
  const size_t n = mtu - 3;
  return n < BLE_WRITE_CHUNK_MAX ? n : BLE_WRITE_CHUNK_MAX;
}

// Set from the host task when the awaited notification comes in; read on
// the loop task. A plain flag, the payload is compared in the callback.
static volatile bool s_done_seen = false;
static const BleDone* s_done = nullptr;

// Anything else the device says on that characteristic is kept for the log:
// the M-series report more than "done" there (paper, cover), and the codes are
// not documented, so the log is how they get learned.
#define BLE_NOTE_KEEP 8
static volatile uint8_t s_note[BLE_NOTE_KEEP];
static volatile uint8_t s_note_len = 0;
static volatile uint16_t s_note_count = 0;

static void onStatusNotify(NimBLERemoteCharacteristic*, uint8_t* data, size_t len, bool) {
  const BleDone* d = s_done;
  if (d && len >= d->len && memcmp(data, d->bytes, d->len) == 0) {
    s_done_seen = true;
    return;
  }
  const size_t n = len < BLE_NOTE_KEEP ? len : BLE_NOTE_KEEP;
  for (size_t i = 0; i < n; i++) s_note[i] = data[i];
  s_note_len = (uint8_t)n;
  s_note_count++;
}

BleWriteResult bleWriteBlocks(const char* address, uint16_t service_uuid,
                              uint16_t char_uuid, const BleBlock* blocks,
                              int count, BleProgressFn progress,
                              const BleDone* done) {
  if (!g_ble_enabled) return BLE_WRITE_OFF;
  if (s_stuck) return BLE_WRITE_STUCK;
  if (!address || !address[0] || !blocks || count <= 0) return BLE_WRITE_FAILED;
  if (!stackMayStart(progress)) return BLE_WRITE_INIT_FAILED;

  crumbSet("ble init");
  logHeap("before init");
  if (!stackUp()) {
    crumbSet("loop");
    logHeap("after failed init");
    logSD("BLE: init failed");
    return BLE_WRITE_INIT_FAILED;
  }
  logHeap("after init");
  NimBLEDevice::setMTU(BLE_PREFERRED_MTU);

  // The device as it advertises right now, so the connect carries its
  // address type. A printer that is off or out of range ends here.
  crumbSet("ble find");
  s_phase = BLE_PHASE_FIND;
  s_sent = s_total = 0;
  const NimBLEAdvertisedDevice* found = nullptr;
  NimBLEScan* scan = NimBLEDevice::getScan();
  if (scan) {
    scan->setActiveScan(false);
    scan->setMaxResults(BLE_FIND_MAX_RESULTS);
    uint32_t elapsed = 0;
    while (!found && elapsed < BLE_FIND_MS) {
      scan->getResults(BLE_FIND_SLICE_MS, elapsed > 0);
      elapsed += BLE_FIND_SLICE_MS;
      if (progress) progress();
      const NimBLEScanResults results = scan->getResults();
      for (int i = 0; i < results.getCount() && !found; i++) {
        const NimBLEAdvertisedDevice* dev = results.getDevice(i);
        if (dev && strcmp(dev->getAddress().toString().c_str(), address) == 0) found = dev;
      }
    }
  }
  if (!found) {
    s_phase = BLE_PHASE_IDLE;
    logSDf("BLE: %s not seen within %u ms", address, (unsigned)BLE_FIND_MS);
    if (scan) scan->clearResults();
    crumbSet("ble deinit");
    stackDown();
    crumbSet("loop");
    logHeap("after deinit");
    return BLE_WRITE_CONNECT_FAILED;
  }
  logSDf("BLE: %s seen, type=%u rssi=%d", address, (unsigned)found->getAddressType(), found->getRSSI());
  // The scan is over before the connect: a connect while the controller
  // still scans is refused, and a moment between the two does no harm.
  scan->stop();
  delay(BLE_SETTLE_MS);

  BleWriteResult result = BLE_WRITE_FAILED;
  NimBLEClient* client = NimBLEDevice::createClient();
  if (!client) {
    s_phase = BLE_PHASE_IDLE;
    logSD("BLE: no client");
    scan->clearResults();
    stackDown();
    crumbSet("loop");
    logHeap("after deinit");
    return BLE_WRITE_INIT_FAILED;
  }
  client->setConnectTimeout(BLE_CONNECT_TIMEOUT_MS);

  do {
    crumbSet("ble connect");
    s_phase = BLE_PHASE_CONNECT;
    if (progress) progress();
    bool connected = false;
    for (int attempt = 1; attempt <= BLE_CONNECT_TRIES && !connected; attempt++) {
      connected = client->connect(found);
      if (connected) break;
      const int rc = client->getLastError();
      logSDf("BLE: connect to %s failed, rc=%d (try %d/%d)", address, rc, attempt, BLE_CONNECT_TRIES);
      if (rc != BLE_ERR_CONN_NOT_ESTABLISHED) break;
      delay(BLE_CONNECT_RETRY_MS);
    }
    if (!connected) {
      result = BLE_WRITE_CONNECT_FAILED;
      break;
    }
    crumbSet("ble services");
    NimBLERemoteService* service = client->getService(NimBLEUUID(service_uuid));
    NimBLERemoteCharacteristic* chr = service ? service->getCharacteristic(NimBLEUUID(char_uuid)) : nullptr;
    if (!chr || (!chr->canWrite() && !chr->canWriteNoResponse())) {
      logSDf("BLE: %s has no writable %04x/%04x", address, service_uuid, char_uuid);
      result = BLE_WRITE_NO_CHARACTERISTIC;
      break;
    }
    NimBLERemoteCharacteristic* status = nullptr;
    s_done_seen = false;
    s_note_len = 0;
    s_note_count = 0;
    s_done = done;
    if (done && done->notify_uuid) {
      status = service->getCharacteristic(NimBLEUUID(done->notify_uuid));
      if (!status || !status->canNotify() || !status->subscribe(true, onStatusNotify)) {
        logSDf("BLE: %s: no status notifications on %04x", address, done->notify_uuid);
        status = nullptr;
      }
    }
    const size_t chunk = chunkFor(client->getMTU());
    const bool response = !chr->canWriteNoResponse();
    size_t total = 0;
    for (int b = 0; b < count; b++) total += blocks[b].len;
    logSDf("BLE: connected %s mtu=%u chunk=%u response=%u bytes=%u",
           address, (unsigned)client->getMTU(), (unsigned)chunk, (unsigned)response, (unsigned)total);

    crumbSet("ble write");
    s_phase = BLE_PHASE_SEND;
    s_total = total;
    const uint32_t started = millis();
    unsigned retried = 0;
    bool ok = true;
    for (int b = 0; ok && b < count; b++) {
      const BleBlock& blk = blocks[b];
      for (size_t pos = 0; pos < blk.len; pos += chunk) {
        const size_t n = (blk.len - pos) < chunk ? (blk.len - pos) : chunk;
        int tries = 0;
        for (;;) {
          if (!client->isConnected()) {
            logSDf("BLE: link dropped in block %d at %u/%u", b, (unsigned)pos, (unsigned)blk.len);
            ok = false;
            break;
          }
          if (chr->writeValue(blk.data + pos, n, response)) break;
          if (++tries > BLE_WRITE_RETRIES) {
            logSDf("BLE: write refused in block %d at %u/%u, rc=%d, gave up after %d tries",
                   b, (unsigned)pos, (unsigned)blk.len, client->getLastError(), tries - 1);
            ok = false;
            break;
          }
          retried++;
          delay(BLE_WRITE_RETRY_MS);
        }
        if (!ok) break;
        s_sent += n;
        delay(BLE_WRITE_CHUNK_GAP_MS);
        if (progress) progress();
      }
    }
    if (ok) logSDf("BLE: %u bytes sent in %u ms, %u chunks waited", (unsigned)total,
                   (unsigned)(millis() - started), retried);
    if (ok && done) {
      // Without the status characteristic there is nothing to wait for but
      // time; with it, the device says when it is through.
      crumbSet("ble await");
      s_phase = BLE_PHASE_AWAIT;
      const uint32_t wait_from = millis();
      while (!s_done_seen && client->isConnected() && millis() - wait_from < done->wait_ms) {
        delay(BLE_DONE_POLL_MS);
        if (progress) progress();
      }
      if (s_done_seen) logSDf("BLE: device done after %u ms", (unsigned)(millis() - wait_from));
      else logSDf("BLE: no done signal within %u ms", (unsigned)done->wait_ms);
    }
    if (s_note_count) {
      char hex[3 * BLE_NOTE_KEEP + 1] = "";
      for (uint8_t i = 0; i < s_note_len; i++)
        snprintf(hex + 3 * i, sizeof(hex) - 3 * i, "%02X ", s_note[i]);
      logSDf("BLE: %u other status note(s), last: %s", (unsigned)s_note_count, hex);
    }
    if (!ok) result = BLE_WRITE_FAILED;
    else if (done && status && !s_done_seen) result = BLE_WRITE_SENT_UNCONFIRMED;
    else result = BLE_WRITE_OK;
  } while (false);

  s_done = nullptr;
  s_phase = BLE_PHASE_IDLE;
  crumbSet("ble disconnect");
  if (client->isConnected()) client->disconnect();
  const uint32_t until = millis() + BLE_DISCONNECT_WAIT_MS;
  while (client->isConnected() && (int32_t)(until - millis()) > 0) delay(10);
  if (client->isConnected()) {
    // The link would not close. The client stays, and so does the stack: a
    // late callback into a deleted client is a crash, a stack that stays up
    // is 40 kB until the next restart. The lesser evil, and it is logged.
    s_stuck = true;
    logSD("BLE: disconnect timed out, stack kept up until restart");
    logHeap("stuck");
    return BLE_WRITE_STUCK;
  }
  // The client goes first and on its own, then the events of the session
  // get a moment to drain, then the stack. Deleting everything in one go
  // right after a failed connect is where a session ended in a panic.
  scan->clearResults();
  NimBLEDevice::deleteClient(client);
  delay(BLE_SETTLE_MS);
  crumbSet("ble deinit");
  stackDown();
  logHeap("after deinit");
  logSDf("BLE: write session %s result=%d", address, (int)result);
  crumbSet("loop");
  return result;
}
