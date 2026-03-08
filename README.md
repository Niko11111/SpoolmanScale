# OpenSpoolScale

> ⚠️ **Work in Progress** – This project is in early development. Updates are coming.

**OpenSpoolScale** is an open-source ESP32-based device that combines a filament scale and NFC reader into a single unit, integrating directly with [Spoolman](https://github.com/Donkie/Spoolman).

Place a spool on the scale, it reads the NFC tag, pulls the spool data from Spoolman, and lets you update the remaining weight or log a drying date – all from a 3.5" touchscreen, no phone needed.

---

## Planned Features

- 🏷️ Automatic NFC tag reading (PN532) – supports Bambu Lab NFC tags
- ⚖️ Live weight measurement (HX711 + load cell)
- 📡 Direct Spoolman REST API integration
- 📱 On-device touchscreen UI (LVGL on WT32-SC01 Plus)
- ⚙️ On-screen configuration (Wi-Fi, server URL, scale calibration)

---

## Roadmap

**V1** – Primarily focused on Bambu Lab spools with existing NFC tags

**V2** – Support for writing universal NFC tags (for third-party filaments)

---

## Inspiration

This project is inspired by:
- [PandaBalance 2](https://makerworld.com) by the Makerworld community
- [SpoolEase](https://github.com/yanshay/SpoolEase) by yanshay

---

*Hardware list, wiring diagrams, and firmware coming soon.*
