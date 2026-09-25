#include "services/ble_service.h"

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <esp_heap_caps.h>
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

bool bleEnabled() { return g_ble_enabled; }

void bleSetEnabled(bool on) {
  g_ble_enabled = on;
  prefsPutBool("ble_on", on);
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

// The stack took about 41 kB of internal heap on core 3 (24.09.2026). It is
// started only with that and a margin for WiFi and TLS free, and not while
// the backend worker has a list in flight: the two ran into each other on the
// device. The wait runs under the overlay, for as long as a list takes.
#define BLE_MIN_FREE_INTERNAL  (64u * 1024u)
#define BLE_WORKER_WAIT_MS     20000
#define BLE_WORKER_POLL_MS     100

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
  const size_t free_int = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  if (free_int < BLE_MIN_FREE_INTERNAL) {
    logSDf("BLE: internal heap %u below %u, not starting the stack",
           (unsigned)free_int, (unsigned)BLE_MIN_FREE_INTERNAL);
    return false;
  }
  return true;
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

static void copyDevice(BleDevice& out, const NimBLEAdvertisedDevice* dev) {
  snprintf(out.name, sizeof(out.name), "%s", dev->getName().c_str());
  snprintf(out.address, sizeof(out.address), "%s", dev->getAddress().toString().c_str());
  out.rssi = dev->getRSSI();
}

int bleScan(BleDevice* out, int capacity, uint32_t duration_ms, BleProgressFn progress) {
  if (!out || capacity <= 0) return 0;
  if (!g_ble_enabled) return -1;
  if (!stackMayStart(progress)) return -1;

  crumbSet("ble scan init");
  logHeap("before init");
  radioShare(true);
  if (!NimBLEDevice::init("")) {
    radioShare(false);
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

    // The results are read here on the loop task, not in a callback on the
    // host task with its 4 kB of stack. Named devices first: they are the
    // ones a person can recognise in a list.
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
  NimBLEDevice::deinit(true);
  radioShare(false);
  crumbSet("loop");
  logHeap("after deinit");
  logSDf("BLE: scan %u ms, %d devices", (unsigned)duration_ms, count);
  return count;
}
