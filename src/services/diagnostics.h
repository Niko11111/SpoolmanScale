#pragma once

#include <stdint.h>

// ============================================================
//  HARDWARE SELF DIAGNOSIS
// ============================================================
//
// Everything here answers one question: if this device is misbehaving, what is
// the single most likely reason, and what should its owner do about it?
//
// The firmware already knew the answer in almost every support case that
// reached the Discord - it just never said so. The two red header chips
// ("SCL!", "NFC!") are four characters wide, carry no explanation and lead
// nowhere, so a wiring mistake and a missing calibration look identical from
// the outside.
//
// Nothing in here talks to LVGL or the network. It reads state the loop keeps
// anyway, probes exactly one I2C address per tick, and hands back a code. The
// banner and the popup decide what that looks like.

enum DiagCode : uint8_t {
  DIAG_NONE = 0,
  DIAG_BUS_EMPTY,           // neither chip acknowledges: power or the I/O plug
  DIAG_NAU_MISSING,         // 0x2A silent, 0x24 answers
  DIAG_PN532_MISSING,       // 0x24 silent, 0x2A answers
  DIAG_PN532_MUTE,          // 0x24 acknowledges but answers no command
  DIAG_SCALE_UNCALIBRATED,  // cal_factor still CAL_FACTOR_DEFAULT
  DIAG_SCALE_INVERTED,      // A+ and A- swapped
  DIAG_SCALE_NOISY,         // spread far too wide for a settled pad
};

// What the popup offers besides "Later". Deliberately small: an action the
// diagnosis cannot carry out is worse than none, because it teaches the user
// that the button does nothing.
enum DiagAction : uint8_t {
  DIAG_ACT_NONE = 0,
  DIAG_ACT_CALIBRATE,   // -> show_factor_pending
  DIAG_ACT_RECHECK,     // -> i2c_rescan_pending
};

// One sample of the moving average, fed from the scale block in appLoop().
// spread_g is the peak to peak of the filter window, which that block already
// walks to build its average - min and max fall out of the same pass for free.
//
// The sustain timers and the "has read positive" latch live behind this call
// rather than in the loop, so the loop keeps one line and the thresholds stay
// next to the code that interprets them.
void diagnosticsNoteSample(float weight_g, float spread_g);

// Re-evaluates at most every DIAG_TICK_MS. Safe to call every pass.
void diagnosticsTick();

// Forces the next tick to evaluate immediately instead of waiting out the
// interval - for the "Check again" button, where the whole point is that the
// answer arrives while the user is still looking at the screen.
void diagnosticsRecheckNow();

// The highest priority finding, or DIAG_NONE. Missing hardware outranks a
// missing calibration, which outranks measurement quality: showing three
// warnings at once gets none of them fixed.
DiagCode diagnosticsCurrent();

// Mapping to the T() table. Returned as int so this header does not have to
// drag lang.h - and with it the T() macro, which collides with ArduinoJson's
// template parameter - into everything that only wants the code.
int diagBannerString(DiagCode c);
int diagTitleString(DiagCode c);
int diagTextString(DiagCode c);
DiagAction diagAction(DiagCode c);

// Plain ASCII for the serial log, the SD log and the status page. Never
// translated: a log line has one reader and it is not the device's owner.
const char *diagName(DiagCode c);
