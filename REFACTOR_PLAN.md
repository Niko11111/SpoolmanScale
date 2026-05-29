# Refactor Plan

## Purpose

`src/main.cpp` has grown into a single file that owns hardware setup, UI construction, state management, Spoolman API calls, OTA, SD logging, Bambu tag parsing, preferences, and multiple user flows. The goal of this refactor is to split responsibilities without changing firmware behavior.

This document is the working checklist for the refactor branch.

## Guardrails

- Keep behavior unchanged unless a separate bug fix is explicitly called out.
- Prefer small, buildable commits over a large rewrite.
- After each scoped extraction, pause for user-run build/upload verification.
- Only mark refactor checklist items complete after user-run device verification; use notes for code that is extracted but not yet hardware-tested.
- Do not refactor LVGL screen lifetimes and callbacks until lower-risk service code is isolated.
- Preserve the current deferred-callback pattern for LVGL navigation until it can be replaced deliberately.
- Keep public constants, NVS keys, API paths, and tag parsing behavior compatible.

## Target Shape

```text
src/
  main.cpp                 setup(), loop(), top-level orchestration
  app/
    app_state.*
  bambu/
    bambu_kdf.*
    bambu_tag.*
    material_match.*
  hardware/
    display.*
    nfc.*
    scale.*
    sd_logger.*
  services/
    spoolman_api.*
    wifi_manager.*
    ota_update.*
    prefs_store.*
  ui/
    ui_common.*
    main_screen.*
    settings_screen.*
    wifi_screen.*
    copy_flow.*
    link_flow.*
    ota_screens.*
```

The exact folder names can change if PlatformIO include behavior or Arduino build conventions make a simpler layout better.

## Phases

### Phase 1: Low-Risk Pure/Service Extractions

- [x] Move SD logger code into `hardware/sd_logger.*`.
- [x] Move Bambu KDF helpers into `bambu/bambu_kdf.*`.
- [x] Move Bambu tag parsing helpers into `bambu/bambu_tag.*`.
- [x] Move material/color matching helpers into `bambu/material_match.*`.
- [ ] Add focused tests or small host-build checks where practical for pure helpers. Deferred until pure modules stabilize and host-build setup is worthwhile.

### Phase 2: API and Persistence Boundaries

- [x] Introduce `services/spoolman_api.*` for HTTP calls and response parsing.
- [x] Introduce `services/spoolman_actions.*` for Spoolman operations that still update app state/UI while delegating HTTP to `spoolman_api.*`.
- [x] Introduce `services/prefs_store.*` for `Preferences` load/save logic.
- [x] Introduce `services/wifi_manager.*` for WiFi connect/scan/status behavior.
- [x] Introduce `services/ota_web_server.*` for browser OTA upload and web settings routes.
- [x] Keep existing UI callbacks calling these services through narrow functions.

### Phase 3: Hardware Boundaries

- [x] Move display/touch initialization into `hardware/display.*`.
- [ ] Move NAU7802 scale setup/read/tare helpers into `hardware/scale.*`. Started with NAU7802 ownership, setup, calibration, and raw reads.
- [x] Move PN532 setup/read helpers into `hardware/nfc.*`.
- [x] Keep pin definitions centralized or grouped by hardware module.

### Phase 4: UI Structure

- [x] Extract shared UI helpers for buttons, labels, overlays, headers, and safe screen cleanup.
- [ ] Split standalone screens first: WiFi info, OTA browser, OTA GitHub, display settings. Display settings verified in `ui/display_screen.*`; OTA menu verified in `ui/ota_menu.*`; Browser OTA screen verified in `ui/ota_browser.*`; GitHub OTA screen/check/pre-release toggle verified in `ui/ota_github.*`; Info/support screen verified in `ui/info_screen.*`; Language screen verified in `ui/language_screen.*`; System screen verified in `ui/system_screen.*`; WiFi info screen moved to `ui/wifi_info.*` but not wired to an active UI path; GitHub flash path not tested because current version matches latest release.
- [ ] Split complex flows later: link flow, copy flow, Spoolman settings, main screen. Settings main screen verified in `ui/settings_screen.*`; Connection screen verified in `ui/connection_screen.*`; Scale submenu verified in `ui/scale_menu.*`; Last Used mode screen verified in `ui/last_used_screen.*`; Bag Weight screen verified in `ui/bag_screen.*`; Calibration screen verified in `ui/factor_screen.*`; Drying Reminder screen verified in `ui/drying_reminder_screen.*`; Calibration Reminder screen verified in `ui/cal_reminder_screen.*`; WiFi setup flow verified in `ui/wifi_setup_screen.*`; Spoolman IP screen moved to `ui/spoolman_screen.*` pending validation.

### Verified Fixes During Refactor

- [x] Avoid noisy `Preferences::getFloat()` missing-key logs for unset float preferences by checking key existence before reading.
- [ ] Avoid changing LVGL object ownership semantics during initial extraction.

### Phase 5: State Cleanup

- [ ] Group globals into state structs where ownership is clear.
- [ ] Replace reused fields and temporary storage with explicit types.
- [ ] Reduce cross-module mutable globals by passing state references where practical.
- [ ] Revisit deferred flags and event handling once screens are modular.

## Known Risk Areas

- LVGL callbacks that delete or hide their own parent screens.
- Global `lv_obj_t*` pointers reused across screens.
- HTTP calls inside or near UI event flow.
- PSRAM/internal RAM pressure during JSON parsing.
- Copy/link flows reusing `UnlinkedSpool` fields for unrelated data.
- OTA and SD logging interactions while UI is active.

## Verification Checklist

- [ ] User-run clean build: `pio run -e wt32-sc01-plus`.
- [ ] User-run upload to device.
- [ ] Boot without SD card.
- [ ] Boot with SD card and verify log file creation.
- [ ] WiFi setup and reconnect.
- [ ] Spoolman IP save/test.
- [ ] Bambu RFID scan and Spoolman lookup.
- [ ] NTAG scan and lookup.
- [ ] Link spool flow.
- [ ] Copy spool flow, active and archived.
- [ ] Weight update and dried-today actions.
- [ ] Browser OTA page starts and stops.
- [ ] GitHub OTA check path still renders.

## Running Notes

- Branch: `refactor/main-split`
- Initial strategy: extract low-risk modules first, then UI.
- Build policy: Codex does not automatically run PlatformIO builds; user builds/tests each phase and reports issues.
