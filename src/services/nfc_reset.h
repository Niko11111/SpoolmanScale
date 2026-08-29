#pragma once

#include <stdint.h>

// ============================================================
//  PN532 RESET LINE
// ============================================================
//
// Whether this device can reset its NFC reader in hardware, and the one time
// hint that tells its owner the modification exists.
//
// Every SpoolmanScale built before September 2026 has the orange RST wire on a
// pad that is an output of the module rather than its RSTPD_N input, so the
// reset never reached the chip. Moving the wire to RSTPDN makes it work, but
// that is a soldering job on a glued enclosure and most of the fleet will
// never do it. Driving the line on a device that still has the old wiring
// would be one driver against another, so nothing is driven until a
// measurement on this very device says otherwise.
//
// Nothing here talks to LVGL. The popup decides what the hint looks like.

// Reads the flags and counts this boot. Call once, before nfcHardwareBegin().
void nfcResetLoad();

// The pin nfcHardwareBegin() should be handed this boot: the real wire once it
// has been verified, otherwise a pin no published build has ever connected.
int8_t nfcResetPinForBoot();

bool nfcResetVerified();

// Drives the candidate line open drain for a few milliseconds and asks the
// reader whether it noticed, then puts it back. Open drain only sinks, so on
// unmodified hardware it cannot fight the module's output - which is the whole
// reason this is safe to offer to everyone.
//
// Persists the outcome. Takes effect on the next boot, because the library
// binds its reset pin in the constructor.
bool nfcResetSelfTest();

// Whether the reader has ever had to be re-initialised on this device. The
// hint is only worth showing to people this has actually happened to: on a
// scale whose reader has never stumbled, the modification buys nothing.
bool nfcReaderNeededRecovery();
void nfcReaderNoteRecovery();

// The modification hint. Due only when the reader has needed recovery, the
// line is not already verified, and the user has neither deferred it recently
// nor dismissed it for good.
bool nfcResetHintDue();
void nfcResetHintLater();   // ask again in a while
void nfcResetHintNever();   // never again; it stays under System > Info
