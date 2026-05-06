# SpoolmanScale – Build Guide

This guide covers everything you need to physically build a SpoolmanScale: parts, wiring, assembly, and calibration.

For the project overview, features, and flashing instructions, see the [README](README.md).

> ⚠️ This is a beta build guide. If something is unclear or doesn't fit your hardware batch, please report it on [MakerWorld](https://makerworld.com/@FormFollowsF) or in the [Discord](https://discord.gg/GzQzGa5pBG).

---

## Parts List

### Electronics

| Component | Model | Link |
|---|---|---|
| MCU + Display | WT32-SC01 Plus (ESP32-S3, 480×320, ST7796) | [AliExpress](https://a.aliexpress.com/_Ey1VKfI) |
| Debug Board (recommended) | ZXACC-ESPDB | [AliExpress](https://a.aliexpress.com/_Eu5Y0Ug) |
| NFC Reader | PN532 | [AliExpress](https://a.aliexpress.com/_ExScN8M) |
| Scale ADC | NAU7802 (Adafruit) | [AliExpress](https://a.aliexpress.com/_EvlFNj2) |
| Load Cell | YZC-133 2 kg beam cell (5 kg works too) | [AliExpress](https://a.aliexpress.com/_EuhhVF2) |
| Connector Cables | STEMMA QT / JST cables | [AliExpress](https://a.aliexpress.com/_Ezjg6fQ) |
| Connector Cables (recommended) | Micro JST 1.0 SH 5-pin – easier assembly | [Amazon](https://amzn.eu/d/0aKJ4Va9) |
| USB-C Panel Mount 90° | 30 cm, full USB-C PD + data support | [AliExpress](https://a.aliexpress.com/_EjQ6sma) |

### Additional Materials

- Thin stranded wire in 5 different colors (black, red, yellow, white, green – ~30–40 cm each)
- 2× M5×25 socket head screws
- 2× M4×15 socket head screws
- 9× M2.5×5 self-tapping screws
- 2–4× M2×4.4 self-tapping screws ([example](https://a.aliexpress.com/_EyCD3rS))

Self-tapping screws are recommended, but standard machine screws (M2.5×5, M2×4) will likely work as well.

---

## 3D Files

The printable enclosure is available on MakerWorld:
👉 [makerworld.com/@FormFollowsF](https://makerworld.com/de/models/2713675-spoolmanscale#profileId-3005075)

All parts fit on 3 print plates (currently distributed across 4). If you can print TPU, use it for the feet – they grip better. Otherwise, self-adhesive silicone feet work just as well.

> If the enclosure is too tight or too loose for your display, please report it – display dimensions can vary slightly between batches.

---

## Assembly Steps

### Step 1 – Flash the board first

Before assembling anything, flash the firmware to the bare board via the [Web Flasher](https://niko11111.github.io/SpoolmanScale). This confirms the board is working before you start wiring.

### Step 2 – Wire components one at a time

Connect components one at a time – NFC reader first, then the scale ADC and load cell – and verify each one works before moving on. Much easier to debug at this stage than inside a fully assembled enclosure.

See the wiring tables below for all connections.

### Step 3 – Assemble & close up

Wire everything up, do a final check that all components are working, then press the display into the enclosure. It should sit snugly without screws. If you want extra security, it can be fastened from the back.

### Step 4 – Calibrate the scale

Go to **Settings → Scale → Calibration**.

1. Tare the scale with nothing on it
2. Place an object with a known weight – ideally ~1000 g (a full filament spool verified on a kitchen scale works well)
3. Enter the exact weight in grams and save

The more precise your reference weight, the more accurate your results.

---

## Wiring

All components connect to the **I/O connector** on the WT32-SC01 Plus using the included 7-pin cable. The I/O socket has 8 pins — plug the 7-pin cable in flush to the left.

The PN532 and NAU7802 share the same I2C bus (SDA/SCL) and are wired in parallel. **Do not daisy-chain them via the NAU7802's STEMMA QT passthrough** – that port only supplies 3.3 V and the PN532 requires 5 V.

### WT32-SC01 Plus I/O Connector

| Pin | Color | Signal | Connect to |
|---|---|---|---|
| 1 | Red | 5 V | PN532 VCC + NAU7802 VIN |
| 2 | Black | GND | PN532 GND + NAU7802 GND |
| 3 | Yellow | GPIO10 (SDA) | PN532 SDA + NAU7802 SDA |
| 4 | Green | GPIO11 (SCL) | PN532 SCL + NAU7802 SCL |
| 5 | Blue | — | unused |
| 6 | White | — | unused |
| 7 | Brown | GPIO12 (RST) | PN532 RST |

### PN532 – Soldering & Assembly

The PN532 has no connector — wires must be soldered directly. **Always solder from the back of the PCB** — there is not enough clearance on the front once it's mounted.

**Recommended assembly order:**

1. Solder all other components first (NAU7802, load cell, WT32 breakout cable) with the enclosure open
2. Leave the PN532 wires loose and long enough to work with
3. Feed the loose wires up through the PN532 mount opening from below
4. Solder the wires to the back of the PN532 PCB
5. Slide the PN532 into its mount and pull the excess cable back down into the enclosure
6. Route and secure cables so they don't press against the weighing platform

If you use a 5-pin JST SH 1.0mm connector on the PN532 pigtail, the mount opening is just large enough to pass the connector through — meaning you can do all soldering outside the enclosure and simply plug it in during final assembly.

### PN532 – Cable Pinout (JST SH 1.0mm 5-pin, 3rd party colors)

| Pin | Color (3rd party) | Signal | WT32 Cable |
|---|---|---|---|
| 1 | Black | GND | Pin 2 (Black) |
| 2 | Red | 5 V | Pin 1 (Red) |
| 3 | Yellow | SDA | Pin 3 (Yellow) |
| 4 | White | SCL | Pin 4 (Green) |
| 5 | Orange | RST | Pin 7 (Brown) |

### NAU7802 – STEMMA QT Connector (JST SH 1.0mm 4-pin)

Soldering directly to the labeled pads (VIN, GND, SDA, SCL) on the NAU7802 is the safest option. If you prefer the STEMMA QT connector, note that the pin order of 3rd-party JST SH 1.0mm cables does **not** match the WT32 cable — you will need to re-pin or swap wires:

| STEMMA QT Pin | Color (3rd party) | Signal | WT32 Cable |
|---|---|---|---|
| 1 | Black | GND | Pin 2 (Black) |
| 2 | Red | 5 V | Pin 1 (Red) |
| 3 | Yellow | SDA | Pin 3 (Yellow) |
| 4 | White | SCL | Pin 4 (Green) |

### Load Cell → NAU7802

| Load Cell wire | NAU7802 terminal |
|---|---|
| Red | E+ (excitation +) |
| Black | E− (excitation −) |
| White | A+ (signal +) |
| Green | A− (signal −) |

> If the scale shows negative values, swap A+ and A−.

### USB-C Panel Mount

The USB-C panel mount extension needs to be trimmed before installation. Using a utility knife, carefully shorten the connector housing little by little until it no longer protrudes beyond the display edge. Take your time – small cuts at a time. Once flush, it will fit cleanly into the enclosure.

---

## Assembly Photos

[![](images/spoolmanscale_assembly_1.jpeg)](images/spoolmanscale_assembly_1.jpeg) [![](images/spoolmanscale_assembly_2.jpeg)](images/spoolmanscale_assembly_2.jpeg)
[![](images/spoolmanscale_assembly_3.jpeg)](images/spoolmanscale_assembly_3.jpeg) [![](images/spoolmanscale_assembly_4.jpeg)](images/spoolmanscale_assembly_4.jpeg)
[![](images/spoolmanscale_assembly_5.jpeg)](images/spoolmanscale_assembly_5.jpeg) [![](images/spoolmanscale_assembly_6.jpeg)](images/spoolmanscale_assembly_6.jpeg)
[![](images/spoolmanscale_assembly_7.jpeg)](images/spoolmanscale_assembly_7.jpeg) [![](images/spoolmanscale_assembly_8.jpeg)](images/spoolmanscale_assembly_8.jpeg)
[![](images/spoolmanscale_assembly_9.jpeg)](images/spoolmanscale_assembly_9.jpeg)
