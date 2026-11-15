#pragma once

#include <Arduino.h>
#include <WebServer.h>

// The WiFi card of the settings page: the network the scale is on, the ones
// it remembers, a search for others, and switching to one. The switching
// itself is services/wifi_remote.h. Stored passwords never reach the browser.
String configWifiCard();
void   configWifiRoutes(WebServer &srv);
