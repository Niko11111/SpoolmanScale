#pragma once

#include <WebServer.h>

// Three levels of web access, all persisted to NVS.
//
//   master   off -> port 80 does not answer at all
//   landing  always served while master is on: status only, changes nothing
//   maintenance gate -> /ota, /update, /logs, /log, /deletelog, /verbose,
//                       /filaman/*, /listlimit, /loclimit, /drying*
//   theme gate       -> /theme, /theme/*
//
// The maintenance group is gated as a whole rather than just the upload page:
// several of those routes change state (/deletelog, /filaman/key,
// /drying/reset) and previously could only be reached while the user was
// physically standing on the OTA screen. Leaving them open whenever the server
// runs would widen exposure without anyone asking for it.
//
// Gates are checked inside each handler rather than by registering different
// route sets, because WebServer::stop() does not free handlers -- re-running
// the registration would pile up duplicates.

bool webMasterEnabled();
bool webMaintenanceEnabled();
bool webThemeEnabled();

void webSetMasterEnabled(bool on);
void webSetMaintenanceEnabled(bool on);
void webSetThemeEnabled(bool on);

void webAccessLoad();

// Starts the server when the master switch is on and WiFi is up, stops it when
// the switch goes off. Also re-arms it if something else stopped it: the OTA
// browser screen calls stopOtaServer() when it closes.
void webServerTick();

// Serves the "this section is switched off" page. `what` names the section and
// `menu` is where to go on the device to turn it on.
void webSendDisabled(WebServer &srv, const char *what, const char *menu);
