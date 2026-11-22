#pragma once

#include <stdint.h>

namespace hw_pins {

constexpr int8_t I2C_EXT_SDA = 10;   // PN532 + NAU7802 bus
constexpr int8_t I2C_EXT_SCL = 11;   // PN532 + NAU7802 bus

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
// No pin: the library skips its reset pulse for -1. It used to be GPIO12
// (pin 5), which nothing was wired to, but pin 5 is the HX711's SCK now, and a
// pulse that ends high powers the HX711 down. The price is one "Invalid pin
// selected" line from the core's pinMode() at boot, which is no fault.
constexpr int8_t PN532_RESET_SAFE = -1;

// Each connector pin has one role for every reader; only the chip differs
// (Notes, PN7160 6.11). Pin 7 is the PN532's RSTPDN (low = power down) and the
// PN7160's VEN (low = off, high = on). Pin 8 is the reader's IRQ: active low on
// the PN532, active high on the PN7160, where it is mandatory - an NCI chip
// raises it while it has something to read. The 7 wire cable leaves pin 8 empty.
// The PN532 library only sets the IRQ pin to input: in I2C mode it asks the
// bus whether an answer is ready. The wake test reads the line in deep sleep.
constexpr int8_t NFC_VEN = 14;       // EXT_IO5, connector pin 7, orange
constexpr int8_t NFC_IRQ = 21;       // EXT_IO6, connector pin 8, violet

// The HX711, tried when no NAU7802 answers on I2C_EXT (hardware/scale.cpp).
// Side by side on the 7 wire cable, so it needs no 8 pin one (Notes, pin plan).
constexpr int8_t HX711_SCK  = 12;    // EXT_IO3, connector pin 5
constexpr int8_t HX711_DOUT = 13;    // EXT_IO4, connector pin 6

constexpr int8_t TOUCH_SDA = 6;      // FT6336U internal board bus
constexpr int8_t TOUCH_SCL = 5;      // FT6336U internal board bus
constexpr int8_t TOUCH_INT = 7;      // FT6336U INT for wake-up

constexpr int8_t LCD_BACKLIGHT = 45;
// Resets the ST7796 panel and, on this board, the FT6336U touch chip as well.
constexpr int8_t LCD_RESET = 4;

constexpr int8_t SD_CS = 41;
constexpr int8_t SD_SCK = 39;
constexpr int8_t SD_MOSI = 40;
constexpr int8_t SD_MISO = 38;

// The onboard I2S amplifier and its 2-pin SPK connector, per the
// WT32-SC01 Plus datasheet. Driven low from boot until a tone plays, and
// held low across deep sleep, see sound.h.
constexpr int8_t SPK_LRCK = 35;
constexpr int8_t SPK_BCLK = 36;
constexpr int8_t SPK_DOUT = 37;

}
