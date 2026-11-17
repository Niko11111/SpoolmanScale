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

#define KEY_WAKE_TEST "nfc_waketest"   // NVS keys are limited to 15 characters

static const size_t WAKE_TEXT_LEN = 48;
static char s_last_wake[WAKE_TEXT_LEN] = "";

bool nfcWakeTestEnabled() { return prefsGetBool(KEY_WAKE_TEST, false); }

void nfcWakeTestSet(bool on) {
  prefsPutBool(KEY_WAKE_TEST, on);
  logSDf("NFC wake test: switched %s", on ? "on" : "off");
}

// Pin 7 high through the sleep: low, the PN7160 is off and the PN532 powered
// down, and neither would see a tag. Both GPIOs are RTC pads, so gpio_hold_en()
// takes the RTC hold, which lasts through deep sleep on its own. On a PN532
// only where the reset probe found the wire on RSTPDN: on the old wiring the
// pin meets a module output (hardware/pins.h), and RSTPDN has the module's
// own pull-up anyway.
static bool holdReaderPowered() {
  if (nfcChip() == NFC_CHIP_PN532 && !nfcResetVerified()) return false;
  pinMode(hw_pins::NFC_VEN, OUTPUT);
  digitalWrite(hw_pins::NFC_VEN, HIGH);
  gpio_hold_en((gpio_num_t)hw_pins::NFC_VEN);
  return true;
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
  const bool active_high = nfcChip() == NFC_CHIP_PN7160;
  const bool searching = nfcArmForWake();
  const bool held = holdReaderPowered();
  const int irq_level = digitalRead(hw_pins::NFC_IRQ);
  const esp_err_t err = armExt1(active_high);
  // The IRQ level before sleeping: already at the wake level, the scale wakes
  // at once, which tells as much as a tag that does not wake it.
  logSDf("NFC wake test: %s %s, pin 7 %s, IRQ now %s, ext1 GPIO%d %s -> %s (%d)",
         nfcChipName(), searching ? "searching" : "NOT searching",
         held ? "held high" : "not held (PN532 reset wire not verified)", irq_level ? "high" : "low",
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
}

const char* nfcWakeTestLastWake() { return s_last_wake; }
