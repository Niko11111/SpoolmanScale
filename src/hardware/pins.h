#pragma once

#include <stdint.h>

namespace hw_pins {

constexpr int8_t I2C_EXT_SDA = 10;   // PN532 + NAU7802 bus
constexpr int8_t I2C_EXT_SCL = 11;   // PN532 + NAU7802 bus

constexpr int8_t PN532_RESET = 12;

// The PN532's IRQ line is not wired, and in I2C mode the library never reads
// it: isready() answers from the bus, and the branch that would call
// digitalRead(_irq) sits behind that check and is unreachable. Its constructor
// still calls pinMode() on whatever pin number it is handed though, and -1
// arrives there as 255, which logs "Invalid pin selected" on every single boot.
// That line reads like a fault and is not one, so the constructor gets a pin
// that exists and costs nothing: EXT_IO4 on the extension connector, unused by
// this firmware and an input after reset anyway.
constexpr int8_t PN532_IRQ_UNUSED = 13;

constexpr int8_t TOUCH_SDA = 6;      // FT6336U internal board bus
constexpr int8_t TOUCH_SCL = 5;      // FT6336U internal board bus
constexpr int8_t TOUCH_INT = 7;      // FT6336U INT for wake-up

constexpr int8_t LCD_BACKLIGHT = 45;

constexpr int8_t SD_CS = 41;
constexpr int8_t SD_SCK = 39;
constexpr int8_t SD_MOSI = 40;
constexpr int8_t SD_MISO = 38;

}
