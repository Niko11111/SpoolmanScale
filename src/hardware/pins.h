#pragma once

#include <stdint.h>

namespace hw_pins {

constexpr int8_t I2C_EXT_SDA = 10;   // PN532 + NAU7802 bus
constexpr int8_t I2C_EXT_SCL = 11;   // PN532 + NAU7802 bus

constexpr int8_t PN532_RESET = 12;

constexpr int8_t TOUCH_SDA = 6;      // FT6336U internal board bus
constexpr int8_t TOUCH_SCL = 5;      // FT6336U internal board bus
constexpr int8_t TOUCH_INT = 7;      // FT6336U INT for wake-up

constexpr int8_t LCD_BACKLIGHT = 45;

constexpr int8_t SD_CS = 41;
constexpr int8_t SD_SCK = 39;
constexpr int8_t SD_MOSI = 40;
constexpr int8_t SD_MISO = 38;

}
