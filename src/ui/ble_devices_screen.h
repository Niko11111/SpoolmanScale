#pragma once

// ============================================================
//  BLUETOOTH DEVICES
//
//  The list behind the "Devices" row of the Bluetooth screen:
//  one row per device the last scan saw, name, address and
//  signal, and a scan button in the header. A row opens a card
//  with the details; the actions on that card belong to the
//  features that need a device, the label printer first.
//
//  The scan blocks for seconds and starts the BLE stack, so it
//  runs from appLoop() under the loading overlay, never from a
//  button. The card is built and closed from the loop for the
//  same reason every popup is: the button that asked sits on
//  the object that would go.
// ============================================================

void buildBleDevicesScreen();
void closeBleDevicesScreen();
void handleBleDevicesDeferredActions();

// The card over the list. Closed, not hidden, by the navigation.
void closeBleDeviceCard();
bool isBleDeviceCardOpen();

// What the last scan saw, for the row on the Bluetooth screen.
bool bleDevicesScanned();
int  bleDevicesCount();
// Called when the switch goes off: what the list knew is no longer true.
void bleDevicesForget();
// The devices themselves, for the browser page: null past the end.
struct BleDevice;
const BleDevice* bleDevicesAt(int index);
// True while a scan is parked or running: the browser page polls on it.
bool bleDevicesScanning();
