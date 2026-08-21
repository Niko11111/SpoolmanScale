#pragma once

#include <WebServer.h>

// master off -> port 80 does not answer. Landing page is always served while
// master is on. Maintenance gates /ota, /update, /logs, /log, /deletelog,
// /verbose, /filaman/*, /listlimit, /loclimit, /drying*, /api/gain.
//
// Gates are checked inside each handler: WebServer::stop() does not free
// handlers, so re-registering would pile up duplicates.

bool webMasterEnabled();
bool webMaintenanceEnabled();

void webSetMasterEnabled(bool on);
void webSetMaintenanceEnabled(bool on);

void webAccessLoad();

// Also re-arms the server if something else stopped it: the OTA browser screen
// calls stopOtaServer() when it closes.
void webServerTick();

void webSendDisabled(WebServer &srv, const char *what, const char *menu);
