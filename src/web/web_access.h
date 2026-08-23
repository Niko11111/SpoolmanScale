#pragma once

#include <WebServer.h>
#include <stdint.h>

// How exposed a route is. Every handler names its level and nothing else
// decides: the gate a route sits behind is a property of the route, not of
// what some screen happens to be showing.
//
// This replaces the old pair of "is the web screen open" and "is maintenance
// on". Those were two independent systems - the pages checked one, the
// endpoints behind them the other - so switching maintenance off hid the
// upload form while /update kept flashing the device.
enum WebGate : uint8_t {
  // Answers whenever the socket is up, even with the master switch off.
  // Only FilaMan's device protocol lives here: it drives the scale from the
  // server side and would break silently if the master switch took it down.
  GATE_ALWAYS = 0,
  // Reads nothing but public state: the status page, its JSON and the icons.
  GATE_OPEN   = 1,
  // Changes how the scale behaves - limits, drying, gain, device name,
  // backend credentials.
  GATE_CONFIG = 2,
  // Writes firmware, deletes logs, restarts, writes NFC tags.
  GATE_MAINT  = 3
};

bool webMasterEnabled();
bool webConfigEnabled();
bool webMaintenanceEnabled();

void webSetMasterEnabled(bool on);
void webSetConfigEnabled(bool on);
void webSetMaintenanceEnabled(bool on);

void webAccessLoad();

bool webGateOpen(WebGate g);

// The one line every handler starts with. Answers by itself and returns
// false when the gate is shut, so a caller that forgets to return has still
// not leaked anything - the reply is already sent.
//
// A page request gets the HTML page that says where to switch it on, an
// /api/* request gets a plain 403, told apart by the request path.
bool webRequire(WebServer &srv, WebGate g, const char *what);

void webSendDisabled(WebServer &srv, const char *what, const char *menu);
