#pragma once

#include <stddef.h>
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

// Whether this boot kept the Bluetooth controller's memory, which it does only
// when the switch was on at boot. False means switching on takes a restart.
bool bleStackAvailable();
// Sets it and writes the key. Called from an LVGL callback, so the write is
// parked by prefs_store and lands on the next loop pass like every other one.
void bleSetEnabled(bool on);

// Blocking, from appLoop() only: starts the stack, scans for duration_ms,
// copies what it saw into out (named devices first) and releases the stack
// again. progress, when given, is called about once a second so an overlay
// can keep moving. Returns the number of devices written, or -1 when the
// stack could not be started; the SD log says why.
int bleScan(BleDevice* out, int capacity, uint32_t duration_ms, BleProgressFn progress);

// A write session to one characteristic of one device: start the stack,
// connect, negotiate the MTU, write the blocks in order and in chunks the
// link accepts, disconnect, release the stack. This is what a label printer
// is to the scale: bytes into one characteristic. The protocol stays with
// the driver; this only carries it.
enum BleWriteResult : uint8_t {
  BLE_WRITE_OK = 0,
  BLE_WRITE_OFF,             // the master switch is off
  BLE_WRITE_INIT_FAILED,     // the stack did not start (memory)
  BLE_WRITE_CONNECT_FAILED,  // the device did not answer
  BLE_WRITE_NO_CHARACTERISTIC,
  BLE_WRITE_FAILED,          // a chunk was refused or the link dropped
  BLE_WRITE_STUCK,           // see bleStackStuck()
  BLE_WRITE_SENT_UNCONFIRMED,// all sent, but the device never said done
};
struct BleBlock { const uint8_t* data; size_t len; };
// What says the device is done with the data. A printer takes the whole job
// before it prints and drops it when the link closes first (measured on the
// M220, 24.09.2026: disconnecting right after the last chunk printed
// nothing), so the session subscribes to its status characteristic and
// stays until this notification arrives or wait_ms runs out.
struct BleDone { uint16_t notify_uuid; const uint8_t* bytes; size_t len; uint32_t wait_ms; };
BleWriteResult bleWriteBlocks(const char* address, uint16_t service_uuid,
                              uint16_t char_uuid, const BleBlock* blocks,
                              int count, BleProgressFn progress,
                              const BleDone* done = nullptr);

// Where a write session stands, for a card to show while it blocks the loop.
// Read from the session's progress callback; idle outside a session.
enum BleSessionPhase : uint8_t {
  BLE_PHASE_IDLE = 0,
  BLE_PHASE_FIND,      // looking for the device's advertisement
  BLE_PHASE_CONNECT,
  BLE_PHASE_SEND,      // bleSessionBytes() says how far
  BLE_PHASE_AWAIT,     // all sent, waiting for the device to say done
};
BleSessionPhase bleSessionPhase();
void bleSessionBytes(size_t* sent, size_t* total);

// True when a session ended with a link that would not close. The client is
// then kept rather than deleted, because a late callback could still reach
// it, and the stack stays up until the next restart: nothing else may start
// or stop it in that state.
bool bleStackStuck();
