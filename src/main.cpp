// ============================================================
//  SpoolmanScale – Bambu NFC Tag Reader & Decoder
//  Board:   WT32-SC01 Plus (ESP32-S3)
//  Version: v0.6.3-beta.8
//
//  Reads Bambu Lab MIFARE Classic tags, derives keys via KDF
//  (HKDF/SHA256, master key from Bambu-Research-Group/RFID-Tag-Guide),
//  displays all decoded data on screen and queries
//  Spoolman for weight + last_dried after each scan.
//
//  Wiring:
//    Pin 1 (+5V)  -> PN532 VCC
//    Pin 2 (GND)  -> PN532 GND
//    Pin 3 (IO1)  -> PN532 SDA (GPIO 10)
//    Pin 4 (IO2)  -> PN532 SCL (GPIO 11)
//    Pin 5 (IO3)  -> PN532 RST (GPIO 12)
//
//  PN532 DIP-Switches: SW1=ON, SW2=OFF -> I2C mode
//
//  Libraries:
//    - Adafruit PN532    by Adafruit
//    - Adafruit BusIO    by Adafruit
//    - LovyanGFX         by lovyan03
//    - lvgl              by lvgl (Version 8.3.11!)
//    - ArduinoJson       by Benoit Blanchon (Version 7.x)
//  mbedTLS + WiFi + HTTPClient are included in the ESP32 framework.
// ============================================================

#include <Arduino.h>
#include "app/app_boot.h"
#include "app/app_loop.h"

// The Arduino loop task defaults to 8 kB. Everything in this firmware runs on
// it, and the deepest paths are LVGL button callbacks: loop() calls
// lv_timer_handler(), which dispatches touch input, which calls the callback,
// which may build a whole screen or do HTTP with JSON parsing. That nesting
// has overflowed the stack before, see the deferred lookups in spool_flow.cpp.
// Doubling it costs internal RAM once and removes a whole class of panic
// reboots. The heartbeat logs the watermark so the real usage stays visible.
SET_LOOP_TASK_STACK_SIZE(16 * 1024);

void setup() {
  appSetup();
}

void loop() {
  appLoop();
}
