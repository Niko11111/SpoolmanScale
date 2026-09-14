#pragma once

#include <stdbool.h>

// Improv WiFi over the USB serial port.
//
// The web flasher (ESP Web Tools) speaks this protocol: right after an install,
// and whenever someone connects to an installed scale, it offers to send the
// WiFi credentials from the browser. Nobody has to type a long password on
// the touchscreen, and a password with characters the keyboard lacks is no
// obstacle. Typing it on the device still works exactly as before.
//
// Everything runs on the loop task. The connect attempt is not blocking: it is
// started here and polled on every pass, so the screen stays usable meanwhile.

// Reads what arrived on Serial, answers it, and follows a running connect
// attempt. From appLoop(), every pass.
void improvSerialTick();

// True while a connect attempt started from the browser is running. The
// reconnect watchdog stays out of the way until it is decided.
bool improvSerialBusy();

// True once after the browser brought a connection up, then false again until
// the next one. The UI uses it to move off a setup screen that is now moot.
bool improvSerialTakeProvisioned();
