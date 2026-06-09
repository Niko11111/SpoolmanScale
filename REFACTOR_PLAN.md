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
- [x] Move Bambu NFC scan/read helpers into `bambu/bambu_scan.*`.
- [x] Move material/color matching helpers into `bambu/material_match.*`.
- [ ] Add focused tests or small host-build checks where practical for pure helpers. Deferred until pure modules stabilize and host-build setup is worthwhile.

### Phase 2: API and Persistence Boundaries

- [x] Introduce `services/spoolman_api.*` for HTTP calls and response parsing.
- [x] Introduce `services/spoolman_actions.*` for Spoolman operations that still update app state/UI while delegating HTTP to `spoolman_api.*`.
- [x] Introduce `services/prefs_store.*` for `Preferences` load/save logic.
- [x] Introduce `services/app_settings.*` for app-specific settings load/save wrappers.
- [x] Introduce `services/drying_config.*` for drying reminder thresholds and material defaults.
- [x] Introduce `services/list_limits.*` for Spoolman/location list limits.
- [x] Introduce `services/auto_weight_state.*` for auto-weight toggles and timing state.
- [x] Introduce `services/user_options.*` for display precision and Last Used mode.
- [x] Introduce `services/ota_state.*` for update availability and GitHub pre-release state.
- [ ] Introduce `services/location_state.*` for location popup debounce/shared state. Pending validation.
- [x] Introduce `services/wifi_manager.*` for WiFi connect/scan/status behavior.
- [x] Introduce `services/time_service.*` for NTP sync and date helpers.
- [x] Introduce `services/ota_web_server.*` for browser OTA upload and web settings routes.
- [x] Keep existing UI callbacks calling these services through narrow functions.

### Phase 3: Hardware Boundaries

- [x] Move display/touch initialization into `hardware/display.*`.
- [x] Move display activity/dim/sleep handling into `hardware/display_power.*`.
- [x] Move NAU7802 scale setup/read/tare helpers into `hardware/scale.*`. NAU7802 hardware path verified on device.
- [x] Move scale calibration/bag/tare persistence and filter reset helpers into `hardware/scale_state.*`.
- [x] Move PN532 setup/read helpers into `hardware/nfc.*`.
- [x] Keep pin definitions centralized or grouped by hardware module.

### Phase 4: UI Structure

Verified extractions:

- [x] Shared UI helpers for buttons, labels, overlays, headers, and safe screen cleanup.
- [x] Display settings screen in `ui/display_screen.*`.
- [x] OTA menu in `ui/ota_menu.*`.
- [x] Browser OTA screen in `ui/ota_browser.*`.
- [x] GitHub OTA screen, update check, and pre-release toggle in `ui/ota_github.*`.
- [x] Info/support screen in `ui/info_screen.*`.
- [x] Language screen in `ui/language_screen.*`.
- [x] System screen in `ui/system_screen.*`.
- [x] Settings main screen in `ui/settings_screen.*`.
- [x] Connection screen in `ui/connection_screen.*`.
- [x] Scale submenu in `ui/scale_menu.*`.
- [x] Last Used mode screen in `ui/last_used_screen.*`.
- [x] Bag Weight screen in `ui/bag_screen.*`.
- [x] Calibration screen in `ui/factor_screen.*`.
- [x] Drying Reminder screen in `ui/drying_reminder_screen.*`.
- [x] Calibration Reminder screen in `ui/cal_reminder_screen.*`.
- [x] WiFi setup flow in `ui/wifi_setup_screen.*`.
- [x] WiFi password placeholder localized through `lang.*`.
- [x] Spoolman IP screen in `ui/spoolman_screen.*`.
- [x] Welcome/first-boot setup screens in `ui/setup_welcome_screen.*`, verified with factory-reset welcome and Skip Setup path.
- [x] Extra Fields screen in `ui/extra_fields_screen.*`, verified for setup check/all-present path.
- [x] More Info/location picker in `ui/more_info_screen.*`.
- [x] Confirm/weight popup in `ui/confirm_popup.*`.
- [x] Main button visibility helper in `ui/main_screen_helpers.*`.
- [x] Update badges in `ui/update_badges.*`.
- [x] Clear tag display in `ui/tag_display.*`.
- [x] Header status in `ui/header_status.*`.
- [x] Date/drying label display helpers in `ui/date_display.*`.
- [x] Dried Today action in `ui/dried_action.*`.
- [x] Main screen construction and tag display refresh in `ui/main_screen.*`.
- [x] Link and copy spool flows in `ui/spool_flow.*`.
- [x] Spoolman lookup and main-screen result display in `ui/spoolman_lookup.*`.
- [x] Runtime loop orchestration in `app/app_loop.*`.
- [x] Boot/setup and WiFi connect orchestration in `app/app_boot.*`.
- [x] Main/settings navigation helpers in `ui/navigation.*`.

Pending validation:

- [ ] Deferred UI navigation flags in `app/deferred_actions.*`.
- [ ] Spoolman failure screen in `ui/spoolman_screen.*`.
- [ ] Reboot popup in `ui/reboot_popup.*`.
- [ ] Weight display formatter in `ui/weight_format.*`.

Deferred or not actively wired:

- [ ] WiFi info screen moved to `ui/wifi_info.*`, but not wired to an active UI path.
- [ ] GitHub flash/install path not tested because the current firmware version matches the latest release.
- [ ] Split `ui/spool_flow.*` into separate link and copy flow modules after current behavior is stable.

### Verified Fixes During Refactor

- [x] Avoid noisy `Preferences::getFloat()` missing-key logs for unset float preferences by checking key existence before reading.
- [ ] Avoid changing LVGL object ownership semantics during initial extraction.

### Phase 5: State Cleanup

- [x] Move global app state definitions from `main.cpp` into `app/app_state.*`.
- [ ] Split `app/app_state.*` into domain state modules where ownership is clear.
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
