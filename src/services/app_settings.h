#pragma once

void loadPrefs();
void saveWifiCredentials(const char* ssid, const char* pass);
// Makes the network the scale is on the preferred one, with the password the
// list holds and no new connection (services/wifi_known_rules.h,
// wifiCanPrefer). False when the rule says no. Loop task only.
bool preferConnectedNetwork(const char* ssid);
void saveSpoolmanIP(const char* ip);
