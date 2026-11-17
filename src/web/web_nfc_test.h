#pragma once

#include <WebServer.h>

// Maintenance routes for testing a reader, without a page of their own.
// Registered by the logs page, like the network probe.
//
// POST /api/nfc/measure?s=10  parks a read-rate measurement (1-60 s, default
//                             10), see services/nfc_measure.h; 202, or 409
//                             while one runs or s is out of range.
// GET  /api/nfc/measure       its state and, once done, its result as JSON.
// GET  /api/nfc/waketest      whether the wake test is on, and the last wake.
// POST /api/nfc/waketest?on=1 switches it on (0: off), see
//                             services/nfc_wake_test.h. Configuration gate:
//                             it changes what deep sleep does.
// POST /api/nfc/sleep         deep sleep now, so a wake test need not wait out
//                             the idle timeout. Maintenance gate.
void nfcTestRoutes(WebServer& srv);
