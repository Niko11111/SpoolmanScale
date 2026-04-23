<img src="images/logo_2.jpeg" width="400">

# SpoolmanScale

> 🚀 **Public Beta** – This is beta software, provided as-is. Expect bugs, rough edges, and missing documentation. Use at your own risk.

**SpoolmanScale** is an open-source ESP32-based filament scale with NFC reader, integrating directly with [Spoolman](https://github.com/Donkie/Spoolman).

Place a spool on the scale – it reads the NFC tag, pulls the spool data from Spoolman, and lets you update the remaining weight, log a drying date, or archive empty spools. All from a 3.5" touchscreen. No phone needed.

> A running [Spoolman](https://github.com/Donkie/Spoolman) instance on your local network is required – this is what stores all your spool data.

---

## Status

🎉 **Public Beta is live!** Firmware **v0.5.0-beta** is released and available via the [Web Flasher](https://niko11111.github.io/SpoolmanScale) or as a direct download from [Releases](https://github.com/Niko11111/SpoolmanScale/releases).

> **Please note:** This is a beta release. A full assembly and wiring guide is currently being written and will be published soon. The 3D files will be available on MakerWorld shortly. If you run into issues in the meantime, join the [Discord](https://discord.gg/GzQzGa5pBG) – happy to help.

---

<img src="images/SpoolmanScale_1.jpeg" width="400"> <img src="images/SpoolmanScale_2.jpeg" width="400">

[![SpoolmanScale Demo](https://img.youtube.com/vi/D8xdF68sX_A/maxresdefault.jpg)](https://youtube.com/shorts/D8xdF68sX_A)

---

## Features

* 🏷️ **Bambu Lab NFC tags** – automatic read & KDF decryption, material/color/vendor shown instantly
* 🔗 **Third-party spool linking** – place any NTAG sticker → select spool from on-screen list → linked in Spoolman via `extra.tag`
* ⚖️ **Live weight (NAU7802)** – moving average filter, TARE, live diff vs. Spoolman remaining weight
* 📡 **Spoolman REST API** – update remaining weight, set initial weight, set spool weight (per spool / filament / vendor), log drying date, archive spools
* 📱 **Touchscreen UI (LVGL 8.3, 480×320)** – settings menu, confirmation popups, sleep/wake, no-tag timer
* ⚙️ **On-device Wi-Fi setup** – scan networks, enter credentials and Spoolman IP directly on the touchscreen
* 🔄 **OTA firmware updates** – upload new firmware via browser, or update directly from GitHub releases – no IDE needed
* ⚡ **Web Flasher** – first-time flash via browser over USB, no IDE needed: [niko11111.github.io/SpoolmanScale](https://niko11111.github.io/SpoolmanScale)
* 🌍 **DE / EN language support** – language selection on first boot, switchable in settings
* 🌙 **Power management** – display dimming, deep sleep, wake via touch

---

## Hardware

| Component | Model | Link |
| --- | --- | --- |
| MCU + Display | WT32-SC01 Plus (ESP32-S3, 480×320, ST7796) | [AliExpress](https://a.aliexpress.com/_Ey1VKfI) |
| Debug Board (recommended) | ZXACC-ESPDB | [AliExpress](https://a.aliexpress.com/_Eu5Y0Ug) |
| NFC Reader | PN532 | [AliExpress](https://a.aliexpress.com/_ExScN8M) |
| Scale ADC | NAU7802 (Adafruit) | [AliExpress](https://a.aliexpress.com/_EvlFNj2) |
| Load Cell | YZC-133 2 kg beam cell (5 kg works as well) | [AliExpress](https://a.aliexpress.com/_EuhhVF2) |
| Connector Cables | STEMMA QT / JST cables | [AliExpress](https://a.aliexpress.com/_Ezjg6fQ) |
| Connector Cables (recommended) | Micro JST 1.0 SH 5-pin – for easier assembly and maintenance | [Amazon](https://amzn.eu/d/0aKJ4Va9) |
| USB-C Panel Mount 90° Extension | 90°, 30 cm – tested and working with full USB-C PD and data support | [AliExpress](https://a.aliexpress.com/_EjQ6sma) |

**Additional materials:**

* Thin stranded wire in 5 different colors (black, red, yellow, white, ~30–40 cm each)
* 2× M5×25 socket head screws, 2× M4×15 socket head screws
* 9× M2.5×5 self-tapping screws, 2–4× M2×4.4 self-tapping screws ([something like this](https://a.aliexpress.com/_EyCD3rS))
  + Self-tapping screws are recommended, but standard machine screws (M2.5×5, M2×4) will likely work as well if you have them on hand.

## 3D Files

The printable enclosure files will be available soon on MakerWorld:
👉 [makerworld.com/@FormFollowsF](https://makerworld.com/@FormFollowsF)

---

## Roadmap

**V0.6.0 (ideas & community requests)**

* Drying reminder – notify when filament hasn't been dried in a while (configurable per material or manual threshold)
* Fix: occasional crashes during first-time setup and while navigating the settings menus
* Fix: crash on invalid Spoolman IP
* More ideas welcome – feel free to open an issue or join the Discord!

---

## Spoolman Setup

SpoolmanScale uses Spoolman's **extra fields** to store NFC tag UIDs and drying dates.
The following extra fields need to be defined in your Spoolman settings. SpoolmanScale checks for these fields during the first-time setup and creates them automatically if they don't exist yet:

| Field | Type | Used for |
| --- | --- | --- |
| `tag` | Text | NFC tag UID (Bambu UUID or NTAG UID) |
| `last_dried` | DateTime | Last drying date |

**Recommended add-on: [OpenSpoolMan](https://github.com/drndos/openspoolman)**
OpenSpoolMan connects to your Bambu printer via MQTT and reads which filament is loaded in which AMS tray. It uses the same `extra.tag` field to identify spools – so if your Bambu spools are already linked in SpoolmanScale, OpenSpoolMan will recognize them instantly without any additional setup. Both tools run alongside each other and complement each other well.

---

## Inspiration

* [PandaBalance 2](https://makerworld.com) by the Makerworld community
* [SpoolEase](https://github.com/yanshay/SpoolEase) by yanshay

---

💬 **Community & Support:** [Join Discord](https://discord.gg/GzQzGa5pBG)

*Not affiliated with Spoolman. Uses the Spoolman REST API.*

*Full wiring diagrams, BOM, and build guide will be published very shortly.*

💛 **If you find this project useful: You can buy me a coffee** [ko-fi.com/formfollowsfunction](https://ko-fi.com/formfollowsfunction)
