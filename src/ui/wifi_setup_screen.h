#pragma once

void showWifiSetupScreen();
// Runs the scan and the connect attempt the setup screens parked. From appLoop().
void handleWifiSetupDeferredActions();
void buildWifiSetupScreen();
void doWifiScan();
void showWifiPassScreen();
void buildWifiPassScreen();
void showWifiConnectingScreen();
void buildWifiConnectingScreen();
// Deletes the connecting screen and drops the label pointers the connect
// result writes, so a later result cannot reach a screen that is gone.
void closeWifiConnectingScreen();
