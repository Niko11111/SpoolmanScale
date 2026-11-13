#pragma once

#include <stdint.h>

extern bool skip_setup_pending;
extern bool finish_setup_pending;
// The setup's scale step: the calibration, led through.
extern bool cal_reminder_pending;
// The setup's closing screen, once the calibration is done or put off.
extern bool setup_done_pending;
// Back from the calibration's first step in the setup: the calibration is
// freed first, then the step before it opens. From the loop, because the
// back button sits on the screen that goes.
extern bool cal_setup_back_pending;
extern bool show_bag_pending;
extern bool show_factor_pending;
// The calibration reset was confirmed. Deferred like every other write reached
// from an LVGL callback, and because it rebuilds the screen the button sits on.
extern bool cal_reset_pending;
// A row of the scale menu changed a setting and the screen has to show it.
// Deferred rather than rebuilt on the spot: the rebuild deletes the screen the
// button that set it sits on, which the house rules rule out.
extern bool scale_sub_rebuild_pending;
// A setting changed that is only read while the interface is built, so it
// takes a restart to show. Its own flag rather than a call from the callback:
// the same tap also schedules a screen rebuild, and that one runs
// hideAllOverlays() - a popup opened first would be taken down by it. Drained
// after the rebuild, so the order is fixed rather than hoped for.
extern bool show_reboot_pending;
// The bag weight crossed 0 g: the main screen's weight zone swaps between
// its layout with and without the bag lines.
extern bool live_zone_rebuild_pending;
extern bool show_lastused_pending;
extern bool show_backend_pending;
extern bool show_online_pending;

// Set by the web route, consumed in appLoop(). Not applied in the handler
// itself: that runs in the loop task, already deep in the WebServer stack, and
// backendApplyMode() rebuilds screens and makes requests of its own. The loop
// task has 16 kB, and that nesting is what overflowed it before.
extern bool backend_mode_change_pending;
extern uint8_t pending_backend_mode;
// Which online service was asked for (services/backend_profiles.h). From the
// web only the switch; from the device's page the browser follows in one pass.
extern bool backend_profile_change_pending;
extern bool online_pick_pending;
extern uint8_t pending_backend_profile;
// The same for exchanging the active server set for the parked one
// (backendApplySetSwap()), from the web page and later from the device.
extern bool server_set_swap_pending;
// The same for new access to the same address (backendApplyAuth()): a screen
// to clear, and caches that belong to the account left behind.
extern bool server_access_change_pending;
extern bool show_filaman_options_pending;
extern bool show_ams_assign_pending;
// The AMS view. A flag rather than a direct call because building it ends in
// an HTTP request, and that must not run inside the LVGL callback that asked
// for it. Set from wherever a way into the view is offered - the row is two
// lines, so the place it sits can move without touching anything else.
extern bool show_ams_view_pending;
// The same page opened from Settings > Scale, which is where it goes back to.
extern bool show_ams_view_scale_pending;
// The AMS button on a device without a load cell, pressed while a spool is
// shown: assign that spool. FilaMan reports its stored weight to open the
// window, BamBuddy opens the bay picker - both make requests, so the button
// only raises this and appLoop() does the rest.
extern bool ams_main_assign_pending;
// The tag view, from the NFC chip in the header. A flag like the AMS view's,
// so the card is built on the loop and never inside the chip's callback.
extern bool show_tag_view_pending;
extern bool show_filaman_fields_pending;
extern bool show_bambuddy_options_pending;
extern bool show_bambuddy_dried_pending;
// The companion field picker, opened from the Spoolman options and rebuilt by
// its own rows after a pick - same shape as show_bambuddy_dried_pending.
extern bool show_tag_comp_pending;
// The tag write screen: opened from the scale menu, and re-rendered by its own
// rows after a pick - same shape as show_bambuddy_dried_pending above.
extern bool show_tagwrite_pending;
extern bool show_timezone_pending;
extern bool show_language_pending;

// The NFC reset probe touches the I2C bus, so it cannot run from the LVGL
// callback that asks for it - the bus belongs to the loop task.
extern bool nfc_reset_probe_pending;
extern bool show_welcome_pending;
extern bool show_spoolman_options_pending;
// Turning the card_uids switch on needs the field to exist on the server, so
// the assistant is opened right away rather than left for the user to find.
extern bool show_extra_fields_pending;
// The picker behind it, for which extra field holds the tag UID.
extern bool show_tag_field_pending;
// Create the selected tag field on the server. Its own flag rather than a
// detour through the extra fields assistant, because the row that sets it says
// "create the field" and has to do exactly that.
extern bool create_tag_field_pending;
extern bool show_spoolman_pending;
// Back to the Connection screen, rebuilt: from the Spoolman screen, and from
// the WiFi menu and the Bluetooth screen, whose tiles it has to redraw.
extern bool show_connection_from_spoolman_pending;
extern bool show_system_pending;
extern bool show_ota_pending;
extern bool show_info_pending;
extern bool show_drying_reminder_pending;
// The numpads of the drying thresholds and of the AMS window. Opened from the
// loop, which deletes the screen they replace in the same pass: built in the
// row's callback, a pad stood in the pool next to its screen and pushed LVGL
// into PSRAM (27.10.2026: 61 KB internal plus 11 KB PSRAM).
extern int8_t dry_pad_pending;          // -1 none, 0 yellow, 1 red
extern bool   ams_window_pad_pending;

// The OTA screen asked for a check while the background task held the TLS
// connection. Retried from appLoop() once it is free, and given up on after
// GH_CHECK_WAIT_MS so a task that never finishes cannot leave the screen
// waiting forever.
// The reactivate button was pressed on an archived spool. Deferred like every
// other network call reached from an LVGL callback, and it carries the weight
// the button named rather than re-measuring in the loop.
extern bool  reactivate_pending;
extern float reactivate_weight_g;

extern bool gh_check_pending;
// The user confirmed a downgrade on the OTA screen. The download blocks for
// about a minute and ends in a restart, so it does not run from the popup's
// own callback.
extern bool gh_downgrade_pending;
// The update button on the OTA screen. Same minute, same restart as the
// downgrade above, and it used to run inline in the button's callback.
extern bool gh_flash_pending;
extern unsigned long gh_check_wait_since;
#define GH_CHECK_WAIT_MS 10000

// Asked before a weight is written that BamBuddy's own inventory would clamp:
// it stores consumption, so anything above the label weight is lost. Carries
// the two numbers the question needs.
extern bool  show_bb_cap_pending;
extern float bb_cap_measured_g;
extern float bb_cap_label_g;

// The diagnosis banner offered a way out and the user took it. Both run from
// the loop rather than the popup's own callback: one opens a screen, the other
// touches the I2C bus, and neither is safe from inside an LVGL event.
//
// A re-probe after the user has been told to check a plug. Without it the only
// way to confirm a repair is a restart, which is a poor answer to "I just
// pushed the connector back in".
extern bool i2c_rescan_pending;

// The WiFi menu behind the Connection tile, and the way back into it from
// the WiFi setup and status screens: built on the loop, never from inside
// the callback of the screen it replaces.
extern bool show_wifi_menu_pending;
// The Bluetooth screen behind its Connection tile.
extern bool show_bluetooth_pending;
// The Bluetooth switch was flipped or a scan finished: the screen is rebuilt
// to show it, which deletes the row the tap landed on - so not from there.
extern bool bluetooth_rebuild_pending;
// A device scan. It starts the BLE stack and blocks for seconds: loop only.
extern bool ble_scan_pending;
// The device list behind the Bluetooth screen's row.
extern bool show_ble_devices_pending;
// A device row was tapped: the index of the card to build, -1 for none. The
// card is a popup over the list and is built on the loop like every popup.
extern int  ble_card_pending;
// The card's Close button: the card goes on the next pass, not from inside
// the callback of the button that sits on it.
extern bool ble_card_close_pending;
// The card's action: make this device the label printer (index), or drop
// the printer. Both write NVS and rebuild the list, so from the loop.
extern int  ble_card_set_printer_pending;
extern bool ble_card_forget_printer_pending;
// The printer screen behind the Bluetooth screen's row, and its rows: each
// change is saved and the screen rebuilt, the test print blocks for seconds.
extern bool show_printer_pending;
extern bool printer_test_pending;
extern bool printer_calib_pending;   // the calibration page, browser or device
// Formnext 2026 only, removed with 0.8.5: Tare held, the business card.
extern bool print_fair_card_pending;
extern bool show_printer_offset_pending;
extern bool printer_forget_pending;
extern bool printer_toggle_ask_pending;   // the "show before printing" row
// The print sheet (ui/print_sheet.h): open it, rebuild it after a change on
// it, close it, print from it, and leave it for the printer screen.
extern bool show_print_sheet_pending;
extern bool print_sheet_refresh_pending;
extern bool print_sheet_close_pending;
extern bool print_sheet_print_pending;
extern bool print_sheet_printer_pending;
// The label of the spool on the pad, from the More info header. Rendered
// and printed from the loop: the print starts the BLE stack and blocks.
extern bool print_spool_label_pending;
// The same header without a Bluetooth printer, on FilaMan: the card that
// sends the label to the PC (ui/pc_print_popup.h).
extern bool show_pc_print_pending;
// The label editor in the browser: print the last spool scanned with the
// saved template, and fetch that spool's dates for the preview (HTTP).
extern bool print_last_label_pending;
// The same for the filament's label of that spool.
extern bool print_last_filament_label_pending;
extern bool label_dates_pending;
// The print card's answer to a label the server would not draw: print the
// same spool with the scale's own layout.
extern bool print_own_layout_pending;
// A weight did not arrive; holds its WeightWriteProblem until the loop can tell
// the user. Set where the answer comes in, which is no place to build a popup.
extern uint8_t weight_write_problem_pending;
