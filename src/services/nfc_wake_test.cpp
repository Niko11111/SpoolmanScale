#include "nfc_wake_test.h"

#include <Arduino.h>
#include <driver/gpio.h>
#include <driver/rtc_io.h>
#include <esp_sleep.h>
#include <stdio.h>

#include "app/app_state.h"
#include "hardware/nfc.h"
#include "hardware/pins.h"
#include "hardware/sd_logger.h"
#include "services/nfc_reset.h"
#include "services/prefs_store.h"

// NVS keys are limited to 15 characters. On unless switched off: a test away
// from a computer has no way to send the switch. A new key, because the old
// "nfc_waketest" was left off after the first test (18.11.2026).
#define KEY_WAKE_TEST "nfc_wake_on"
#define WAKE_TEST_DEFAULT true

static const size_t WAKE_TEXT_LEN = 48;
static char s_last_wake[WAKE_TEXT_LEN] = "";

bool nfcWakeTestEnabled() { return prefsGetBool(KEY_WAKE_TEST, WAKE_TEST_DEFAULT); }

void nfcWakeTestSet(bool on) {
  prefsPutBool(KEY_WAKE_TEST, on);
  logSDf("NFC wake test: switched %s", on ? "on" : "off");
}

// Pin 7 high through the sleep: low, the PN7160 is off and the PN532 powered
// down, and neither would see a tag. Both GPIOs are RTC pads, so gpio_hold_en()
// takes the RTC hold, which lasts through deep sleep on its own.
static void holdReaderPowered() {
  pinMode(hw_pins::NFC_VEN, OUTPUT);
  digitalWrite(hw_pins::NFC_VEN, HIGH);
  gpio_hold_en((gpio_num_t)hw_pins::NFC_VEN);
}

// A PN532 wakes the scale only with RSTPDN on pin 7, verified by the reset
// probe: after the wake it has to be switched off and on over that wire, or it
// does not start again (21.11.2026). On the old wiring pin 7 meets a module
// output (hardware/pins.h) and must not be driven at all.
static bool readerCanWake() {
  return nfcChip() == NFC_CHIP_PN7160 || nfcResetVerified();
}

// The PN7160 drives its IRQ push-pull, so the pull-down only keeps an
// unplugged pin from floating into a wake. The PN532's is open drain with a
// pull-up on the module; the internal one is there in case that is missing.
static esp_err_t armExt1(bool active_high) {
  const gpio_num_t irq = (gpio_num_t)hw_pins::NFC_IRQ;
  const esp_err_t err = esp_sleep_enable_ext1_wakeup(
      1ULL << hw_pins::NFC_IRQ, active_high ? ESP_EXT1_WAKEUP_ANY_HIGH : ESP_EXT1_WAKEUP_ANY_LOW);
  if (active_high) {
    rtc_gpio_pullup_dis(irq);
    rtc_gpio_pulldown_en(irq);
  } else {
    rtc_gpio_pulldown_dis(irq);
    rtc_gpio_pullup_en(irq);
  }
  return err;
}

void nfcWakeTestBeforeSleep() {
  if (!nfcWakeTestEnabled()) return;
  if (!nfc_ok) {
    logSDf("NFC wake test: the %s is not ready - sleeping without NFC wake", nfcChipName());
    return;
  }
  if (!readerCanWake()) {
    logSD("NFC wake test: PN532 reset wire not verified - sleeping without NFC wake");
    return;
  }
  const bool active_high = nfcChip() == NFC_CHIP_PN7160;
  const bool searching = nfcArmForWake();
  holdReaderPowered();
  const int irq_level = digitalRead(hw_pins::NFC_IRQ);
  const esp_err_t err = armExt1(active_high);
  // The IRQ level before sleeping: already at the wake level, the scale wakes
  // at once, which tells as much as a tag that does not wake it.
  logSDf("NFC wake test: %s %s, pin 7 held high, IRQ now %s, ext1 GPIO%d %s -> %s (%d)",
         nfcChipName(), searching ? "searching" : "NOT searching", irq_level ? "high" : "low",
         hw_pins::NFC_IRQ, active_high ? "ANY_HIGH" : "ANY_LOW", esp_err_to_name(err), (int)err);
}

static void noteWake(esp_sleep_wakeup_cause_t cause) {
  if (cause == ESP_SLEEP_WAKEUP_EXT1) {
    const uint64_t pins = esp_sleep_get_ext1_wakeup_status();
    const bool by_irq = (pins >> hw_pins::NFC_IRQ) & 1ULL;
    snprintf(s_last_wake, sizeof(s_last_wake), "ext1 %s", by_irq ? "GPIO21 (NFC IRQ)" : "other pin");
    logSDf("NFC wake test: woken by ext1, pin mask 0x%llX - %s", (unsigned long long)pins,
           by_irq ? "the reader's IRQ on GPIO21" : "not GPIO21");
  } else if (cause == ESP_SLEEP_WAKEUP_EXT0) {
    snprintf(s_last_wake, sizeof(s_last_wake), "ext0 touch");
    logSD("NFC wake test: woken by ext0 (touch), not by the reader");
  } else {
    snprintf(s_last_wake, sizeof(s_last_wake), "cause %d", (int)cause);
    logSDf("NFC wake test: woken by cause %d", (int)cause);
  }
}

void nfcWakeTestAfterBoot() {
  const esp_sleep_wakeup_cause_t cause = esp_sleep_get_wakeup_cause();
  if (cause == ESP_SLEEP_WAKEUP_UNDEFINED) return;   // a cold boot or a reset
  if (!nfcWakeTestEnabled()) return;                 // nothing of ours was armed
  gpio_hold_dis((gpio_num_t)hw_pins::NFC_VEN);
  rtc_gpio_deinit((gpio_num_t)hw_pins::NFC_IRQ);
  noteWake(cause);
  // The check again: only a verified wire may be pulled low (readerCanWake()).
  if (cause == ESP_SLEEP_WAKEUP_EXT1 && nfcResetVerified() &&
      nfcPn532PowerCycle(&I2C_EXT, hw_pins::PN532_RESET_WIRE)) {
    logSD("NFC wake test: PN532 switched off and on over pin 7");
  }
}

const char* nfcWakeTestLastWake() { return s_last_wake; }
