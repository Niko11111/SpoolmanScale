#pragma once

// The wake test (Notes, PN7160 6.11): can a tag put on the reader wake the
// scale from deep sleep over connector pin 8 (GPIO 21)? Off unless switched on
// over the web (web/web_nfc_test.cpp); off, nothing here does anything and
// deep sleep is exactly what it was. Touch (ext0) wakes as before either way.
//
// Before sleeping: the reader is left searching (nfcArmForWake()), pin 7
// (GPIO 14, the PN532's RSTPDN, the PN7160's VEN) is held high through the
// sleep, and ext1 waits on GPIO 21 - for a high level on a PN7160, whose IRQ
// is active high, a low one on a PN532. After waking: the hold is released,
// the pin handed back, and the cause and pin are logged.

#include <stdint.h>

bool nfcWakeTestEnabled();
void nfcWakeTestSet(bool on);

// Right before deep sleep, ahead of displayPrepareDeepSleep().
void nfcWakeTestBeforeSleep();
// Early in appSetup(), before the reader is brought up: a held VEN cannot be
// pulsed. Logs nothing after a cold boot.
void nfcWakeTestAfterBoot();
// The cause of the last wake as text for the web ("ext1 GPIO21"), or "".
const char* nfcWakeTestLastWake();
