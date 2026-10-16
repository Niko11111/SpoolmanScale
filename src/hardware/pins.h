#pragma once

#include <stdint.h>
#include "app_config.h"

namespace hw_pins {

constexpr int8_t I2C_EXT_SDA = 10;   // PN532 + NAU7802 (NAU7802 profile)
constexpr int8_t I2C_EXT_SCL = 11;   // PN532 + NAU7802 (NAU7802 profile)

// The PN532's reset line exists in two places, and which one is used is a
// property of the device rather than of the firmware.
//
// Every SpoolmanScale built before September 2026 has the orange RST wire on
// the header opposite the labelled one, where the module brings out an output
// rather than its RSTPD_N input. Measured on the bench: with the wire there,
// holding any connector GPIO low leaves the reader answering
// GetFirmwareVersion with a healthy 0x32010607 - the reset simply never
// reached the chip, on any unit, since May 2026.
//
// Moving the wire to RSTPDN makes it work; verified on 2026-08-29, where the
// same probe returned SILENT while held and the reader came back after. But
// that is a soldering job, most of the fleet will never do it, and driving
// PN532_RESET_WIRE on a device that still has the old wiring puts the ESP32's
// output against the module's. So the pin is only handed to the library after
// a measurement on this very device says the wire was moved - see
// services/nfc_reset.h.
constexpr int8_t PN532_RESET_WIRE = 14;   // EXT_IO5, connector pin 7, brown
// The HX711 build has no placeholder: it always uses PN532_RESET_WIRE, and
// GPIO12 is the HX711's clock there - see nfcResetPinForBoot().
#if !SCALE_ADC_HX711
constexpr int8_t PN532_RESET_SAFE = 12;   // EXT_IO3, pin 5; not wired to PN532 RST in documented layout
#endif

// The PN532's IRQ line is not wired, and in I2C mode the library never reads
// it: isready() answers from the bus, and the branch that would call
// digitalRead(_irq) sits behind that check and is unreachable. Its constructor
// still calls pinMode() on whatever pin number it is handed though, and -1
// arrives there as 255, which logs "Invalid pin selected" on every single boot.
// That line reads like a fault and is not one, so the constructor gets a pin
// that exists and costs nothing. In the NAU7802 profile it is EXT_IO4 and
// remains an input; GPIO13 is HX711 DOUT in the HX711 profile, which uses
// GPIO2 (RS485 RTS on this board) instead. pinMode(INPUT) only, so it stays
// high-impedance exactly as it is after reset.
#if SCALE_ADC_HX711
constexpr int8_t PN532_IRQ_UNUSED = 2;
#else
constexpr int8_t PN532_IRQ_UNUSED = 13;
#endif

// HX711 uses the otherwise-unused extension connector signals: GPIO12 on
// connector pin 5 for SCK and GPIO13 on pin 6 for DOUT. The PN532 driver's
// IRQ placeholder moves to GPIO2 in that profile; it has no reset placeholder.
constexpr int8_t HX711_SCK = 12;
constexpr int8_t HX711_DOUT = 13;

constexpr int8_t TOUCH_SDA = 6;      // FT6336U internal board bus
constexpr int8_t TOUCH_SCL = 5;      // FT6336U internal board bus
constexpr int8_t TOUCH_INT = 7;      // FT6336U INT for wake-up

constexpr int8_t LCD_BACKLIGHT = 45;

constexpr int8_t SD_CS = 41;
constexpr int8_t SD_SCK = 39;
constexpr int8_t SD_MOSI = 40;
constexpr int8_t SD_MISO = 38;

}
