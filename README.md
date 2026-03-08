# OpenSpoolScale
⚠️ Work in Progress – This project is in early development. Updates are coming.

OpenSpoolScale is an open-source ESP32-based device that combines a filament scale and NFC reader into a single unit, integrating directly with Spoolman. 
Place a spool on the scale, it reads the NFC tag, pulls the spool data from Spoolman, and lets you update the remaining weight or log a drying date – all from a 3.5" touchscreen, 
no phone needed.

Planned Features:

🏷️ Automatic NFC tag reading (PN532) on both sides for Bambu Lab NFC Tags
⚖️ Live weight measurement (HX711 + load cell)
📡 Direct Spoolman REST API integration
📱 On-device touchscreen UI (LVGL on WT32-SC01 Plus)
⚙️ On-screen configuration (Wi-Fi, server URL, scale calibration)

More details, hardware list, and firmware coming soon.

In its first Version it is primarely focused on Bambu Lab Spools, but V2 is planed to write on universal NFC Tags. 

It is inspierd by "PandaBalance 2" from Makerworld and the awsome project "SpoolEase" from yanshay here on Github.
