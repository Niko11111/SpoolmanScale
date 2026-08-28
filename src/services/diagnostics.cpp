#include "services/diagnostics.h"

#include <Arduino.h>
#include <math.h>

#include "app/app_state.h"
#include "app_config.h"
#include "hardware/i2c_scan.h"
#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "lang.h"

// ---- observed state ---------------------------------------------------
// Written by diagnosticsNoteSample() every 200 ms, read by the tick.

// Since when the spread has been above DIAG_NOISE_G without a break. Zero
// means it is currently below it.
static unsigned long noisy_since = 0;
// Since when the reading has been below DIAG_INVERTED_G without a break.
static unsigned long inverted_since = 0;
// Has this device ever read a real positive load since it booted? A cell with
// A+ and A- swapped never does, which is what separates it from the far more
// common case of someone taring with a spool on the pad and then lifting it.
// Latched for the session on purpose: it is evidence, and evidence does not
// expire when the pad goes quiet.
static bool seen_positive = false;

static bool     pn532_on_bus = false;
static DiagCode current      = DIAG_NONE;
static unsigned long last_tick_ms = 0;
static bool     first_tick   = true;

void diagnosticsNoteSample(float weight_g, float spread_g) {
  const unsigned long now = millis();

  if (weight_g > DIAG_POSITIVE_SEEN_G) seen_positive = true;

  // Both of these are "how long has this been true without interruption", and
  // both are armed rather than fired here. A hand on the pad produces one or
  // two seconds of either; only the tick decides, and only after the sustain
  // window has run out.
  if (spread_g > DIAG_NOISE_G) {
    if (noisy_since == 0) noisy_since = now;
  } else {
    noisy_since = 0;
  }

  if (weight_g < DIAG_INVERTED_G) {
    if (inverted_since == 0) inverted_since = now;
  } else {
    inverted_since = 0;
  }
}

void diagnosticsRecheckNow() {
  first_tick = true;
}

// Long enough, and still running? A sustain window that was never armed reads
// as zero and must not count as "since the epoch".
static bool held(unsigned long since, unsigned long ms) {
  return since != 0 && millis() - since >= ms;
}

void diagnosticsTick() {
  const unsigned long now = millis();
  if (!first_tick && now - last_tick_ms < DIAG_TICK_MS) return;
  last_tick_ms = now;
  first_tick   = false;

  // Probed live rather than read from the boot scan, so a connector that is
  // pushed back in takes effect without a restart. 0x2A is already answered by
  // the scale watchdog every 5 s, so only the reader costs a transaction here.
  pn532_on_bus = i2cPresent(I2C_EXT, I2C_ADDR_PN532);
  const bool nau_on_bus = scl_ok;

  DiagCode next = DIAG_NONE;

  if (!pn532_on_bus && !nau_on_bus) {
    next = DIAG_BUS_EMPTY;
  } else if (!nau_on_bus) {
    next = DIAG_NAU_MISSING;
  } else if (!pn532_on_bus) {
    next = DIAG_PN532_MISSING;
  } else if (!nfc_ok) {
    // Acknowledging its address and still not talking. Note what this rules
    // out: a module switched to HSU or SPI does not answer an I2C probe at
    // all, so it lands one branch above as PN532_MISSING - reaching here
    // proves the DIP switches are on I2C and that SDA and SCL are sound.
    // What is left is the reset line, which holds the chip mute when it is
    // missing, and that is what the text sends people to first.
    next = DIAG_PN532_MUTE;
  } else if (scale_ready && cal_factor == CAL_FACTOR_DEFAULT) {
    // The exact comparison is sound: the value is assigned literally from this
    // constant in app_state.cpp and app_settings.cpp, and a real calibration
    // lands between 100 and 2000 counts per gram (see app_config.h). This is
    // also why there is no "calibrated" flag in NVS - one would read false for
    // every device that was calibrated before this code existed.
    next = DIAG_SCALE_UNCALIBRATED;
  } else if (scale_ready && !seen_positive &&
             held(inverted_since, DIAG_INVERTED_SUSTAIN_MS)) {
    next = DIAG_SCALE_INVERTED;
  } else if (scale_ready && scale_filter_full &&
             held(noisy_since, DIAG_NOISE_SUSTAIN_MS)) {
    next = DIAG_SCALE_NOISY;
  }

  if (next != current) {
    // One line per change, never per tick. A device sitting on a stable
    // finding has to leave the log quiet, or the log stops being readable
    // exactly when someone needs to read it.
    Serial.printf("Diag: %s -> %s\n", diagName(current), diagName(next));
    logSDf("Diag: %s -> %s", diagName(current), diagName(next));
    current = next;
  }
}

DiagCode diagnosticsCurrent() {
  // Nothing is reported while the first time setup is running. The setup
  // screens are overlays and would cover a banner anyway, but someone halfway
  // through choosing a language has not wired anything wrong yet - they have
  // simply not finished, and a warning at that point reads as a failure.
  if (setup_active) return DIAG_NONE;
  return current;
}

int diagBannerString(DiagCode c) {
  switch (c) {
    case DIAG_BUS_EMPTY:          return STR_DIAG_BUS_EMPTY_BANNER;
    case DIAG_NAU_MISSING:        return STR_DIAG_NAU_MISSING_BANNER;
    case DIAG_PN532_MISSING:      return STR_DIAG_PN532_MISSING_BANNER;
    case DIAG_PN532_MUTE:         return STR_DIAG_PN532_MUTE_BANNER;
    case DIAG_SCALE_UNCALIBRATED: return STR_DIAG_UNCAL_BANNER;
    case DIAG_SCALE_INVERTED:     return STR_DIAG_INVERTED_BANNER;
    case DIAG_SCALE_NOISY:        return STR_DIAG_NOISY_BANNER;
    default:                      return STR_DIAG_UNCAL_BANNER;
  }
}

int diagTitleString(DiagCode c) {
  switch (c) {
    case DIAG_BUS_EMPTY:          return STR_DIAG_BUS_EMPTY_TITLE;
    case DIAG_NAU_MISSING:        return STR_DIAG_NAU_MISSING_TITLE;
    case DIAG_PN532_MISSING:      return STR_DIAG_PN532_MISSING_TITLE;
    case DIAG_PN532_MUTE:         return STR_DIAG_PN532_MUTE_TITLE;
    case DIAG_SCALE_UNCALIBRATED: return STR_DIAG_UNCAL_TITLE;
    case DIAG_SCALE_INVERTED:     return STR_DIAG_INVERTED_TITLE;
    case DIAG_SCALE_NOISY:        return STR_DIAG_NOISY_TITLE;
    default:                      return STR_DIAG_UNCAL_TITLE;
  }
}

int diagTextString(DiagCode c) {
  switch (c) {
    case DIAG_BUS_EMPTY:          return STR_DIAG_BUS_EMPTY_TEXT;
    case DIAG_NAU_MISSING:        return STR_DIAG_NAU_MISSING_TEXT;
    case DIAG_PN532_MISSING:      return STR_DIAG_PN532_MISSING_TEXT;
    case DIAG_PN532_MUTE:         return STR_DIAG_PN532_MUTE_TEXT;
    case DIAG_SCALE_UNCALIBRATED: return STR_DIAG_UNCAL_TEXT;
    case DIAG_SCALE_INVERTED:     return STR_DIAG_INVERTED_TEXT;
    case DIAG_SCALE_NOISY:        return STR_DIAG_NOISY_TEXT;
    default:                      return STR_DIAG_UNCAL_TEXT;
  }
}

DiagAction diagAction(DiagCode c) {
  switch (c) {
    // The one finding the device can fix from the inside.
    case DIAG_SCALE_UNCALIBRATED: return DIAG_ACT_CALIBRATE;
    // Everything the user has to fix with their hands gets the same offer:
    // look again once you have touched it.
    case DIAG_BUS_EMPTY:
    case DIAG_NAU_MISSING:
    case DIAG_PN532_MISSING:
    case DIAG_PN532_MUTE:         return DIAG_ACT_RECHECK;
    // A swapped pair and a loose wire both mean opening the enclosure. There
    // is nothing to press here, and a button that only closes the popup would
    // pretend otherwise.
    default:                      return DIAG_ACT_NONE;
  }
}

const char *diagName(DiagCode c) {
  switch (c) {
    case DIAG_NONE:               return "none";
    case DIAG_BUS_EMPTY:          return "i2c bus empty";
    case DIAG_NAU_MISSING:        return "NAU7802 missing";
    case DIAG_PN532_MISSING:      return "PN532 missing";
    case DIAG_PN532_MUTE:         return "PN532 mute";
    case DIAG_SCALE_UNCALIBRATED: return "scale uncalibrated";
    case DIAG_SCALE_INVERTED:     return "load cell reversed";
    case DIAG_SCALE_NOISY:        return "load cell noisy";
  }
  return "?";
}
