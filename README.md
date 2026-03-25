# SpoolmanScale

> ⚠️ **Work in Progress** – Hardware complete, firmware in Beta. Public release coming soon.

**SpoolmanScale** is an open-source ESP32-based filament scale with NFC reader, integrating directly with [Spoolman](https://github.com/Donkie/Spoolman).

Place a spool on the scale – it reads the NFC tag, pulls the spool data from Spoolman, and lets you update the remaining weight, log a drying date, or archive empty spools. All from a 3.5" touchscreen. No phone needed.

---

## Status

The hardware is complete: enclosure printed, all components installed, fully assembled and working.
The firmware is stable. A few important backend features are missing before I'll publish a public beta (see roadmap below).

<p>
  <img src="images/SpoolmanScale_1.jpeg" width="48%">
  <img src="images/SpoolmanScale_2.jpeg" width="48%">
</p>


---

## Features so far

- 🏷️ **Bambu Lab NFC tags** – automatic read & KDF decryption, material/color/vendor shown instantly
- 🔗 **Third-party spool linking** – place any NTAG sticker → select spool from on-screen list → linked in Spoolman via `extra.tag`
- ⚖️ **Live weight (NAU7802)** – moving average filter, TARE, live diff vs. Spoolman remaining weight
- 📡 **Spoolman REST API** – log drying date, update remaining weight, set initial weight, set spool weight (per spool / filament / vendor), archive spools
- 📱 **Touchscreen UI (LVGL 8.3, 480×320)** – settings menu, confirmation popups, sleep/wake, no-tag timer
- ⚙️ **On-device settings** – Spoolman IP:Port, scale calibration, bag weight (stored in NVS)
- 🌙 **Power management** – display dimming after 5 min, deep sleep after 20 min, wake via touch

---

## Hardware

| Component | Model |
|---|---|
| MCU + Display | WT32-SC01 Plus (ESP32-S3, 480×320, ST7796) |
| NFC Reader | PN532 |
| Scale ADC | NAU7802 (Adafruit) |
| Touch Controller | FT6336U (built-in) |

---

## Before Public Beta (remaining work)

- [ ] **Wi-Fi setup via UI** – scan networks, enter credentials on-device (currently hardcoded)
- [ ] **OTA firmware updates** – browser-based upload + partition table restructure
- [ ] **Info/firmware screen** – version number, instructions
- [ ] **DE/EN language support**

---

## Roadmap

**V2 (planned after release)**
- UI overhaul – layout, typography, icons
- GitHub OTA auto-check

---

## Inspiration

- [PandaBalance 2](https://makerworld.com) by the Makerworld community  
- [SpoolEase](https://github.com/yanshay/SpoolEase) by yanshay

---

*Full wiring diagrams, BOM, and build guide will be published with the first public beta.*
