#pragma once

// ============================================================
//  BLUETOOTH
//
//  The screen behind the Bluetooth tile on the Connection
//  screen: the master switch, and while it is on, the row into
//  the device list (ui/ble_devices_screen.cpp).
// ============================================================

void buildBluetoothScreen();
void closeBluetoothScreen();
// The rebuild after a toggle, from appLoop(): it deletes the screen the row
// sits on, so not from the row's own callback.
void handleBluetoothDeferredActions();
