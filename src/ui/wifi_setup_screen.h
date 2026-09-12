#pragma once

void showWifiSetupScreen();
void buildWifiSetupScreen();
void doWifiScan();
void showWifiPassScreen();
void buildWifiPassScreen();
void showWifiConnectingScreen();
void buildWifiConnectingScreen();
// Deletes the connecting screen and drops the label pointers the connect
// result writes, so a later result cannot reach a screen that is gone.
void closeWifiConnectingScreen();
