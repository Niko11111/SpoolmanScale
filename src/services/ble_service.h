#pragma once

#include <stdint.h>

// ============================================================
//  BLUETOOTH LOW ENERGY
//
//  The one place the firmware talks to the BLE stack. Behind the
//  master switch nothing runs: the stack is started when a
//  feature needs it and released right after, so a device with
//  the switch off, or one that never scans, pays nothing at run
//  time. The label printer and any later BLE device (a detached
//  reader, say) come in through here and nowhere else.
//
//  This header stays free of NimBLE on purpose: the screens
//  include it, and the simulator builds them against a fake.
// ============================================================

#define BLE_NAME_LEN 32
#define BLE_ADDR_LEN 18   // "aa:bb:cc:dd:ee:ff" and the terminator

struct BleDevice {
  char   name[BLE_NAME_LEN];      // empty when the device did not say
  char   address[BLE_ADDR_LEN];
  int8_t rssi;
};

typedef void (*BleProgressFn)();

// The master switch, cached from NVS at boot (services/app_settings.cpp).
bool bleEnabled();
// Sets it and writes the key. Called from an LVGL callback, so the write is
// parked by prefs_store and lands on the next loop pass like every other one.
void bleSetEnabled(bool on);

// Blocking, from appLoop() only: starts the stack, scans for duration_ms,
// copies what it saw into out (named devices first) and releases the stack
// again. progress, when given, is called about once a second so an overlay
// can keep moving. Returns the number of devices written, or -1 when the
// stack could not be started; the SD log says why.
int bleScan(BleDevice* out, int capacity, uint32_t duration_ms, BleProgressFn progress);
