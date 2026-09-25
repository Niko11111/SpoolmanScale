#pragma once

#include <stdint.h>

extern bool skip_setup_pending;
extern bool finish_setup_pending;
extern bool cal_reminder_pending;
extern bool show_bag_pending;
extern bool show_factor_pending;
// The calibration reset was confirmed. Deferred like every other write reached
// from an LVGL callback, and because it rebuilds the screen the button sits on.
extern bool cal_reset_pending;
// A row of the scale menu changed a setting and the screen has to show it.
// Deferred rather than rebuilt on the spot: the rebuild deletes the screen the
// button that set it sits on, which is what CLAUDE.md rules out.
extern bool scale_sub_rebuild_pending;
// A setting changed that is only read while the interface is built, so it
// takes a restart to show. Its own flag rather than a call from the callback:
// the same tap also schedules a screen rebuild, and that one runs
// hideAllOverlays() - a popup opened first would be taken down by it. Drained
// after the rebuild, so the order is fixed rather than hoped for.
extern bool show_reboot_pending;
extern bool show_lastused_pending;
extern bool show_backend_pending;

// Set by the web route, consumed in appLoop(). Not applied in the handler
// itself: that runs in the loop task, already deep in the WebServer stack, and
// backendApplyMode() rebuilds screens and makes requests of its own. The loop
// task has 16 kB, and that nesting is what overflowed it before.
extern bool backend_mode_change_pending;
extern uint8_t pending_backend_mode;
extern bool show_filaman_options_pending;
extern bool show_ams_assign_pending;
// The AMS view. A flag rather than a direct call because building it ends in
// an HTTP request, and that must not run inside the LVGL callback that asked
// for it. Set from wherever a way into the view is offered - the row is two
// lines, so the place it sits can move without touching anything else.
extern bool show_ams_view_pending;
// The same page opened from Settings > Scale, which is where it goes back to.
extern bool show_ams_view_scale_pending;
// The tag view, from the NFC chip in the header. A flag like the AMS view's,
// so the card is built on the loop and never inside the chip's callback.
extern bool show_tag_view_pending;
extern bool show_filaman_fields_pending;
extern bool show_bambuddy_options_pending;
extern bool show_bambuddy_dried_pending;
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
// "Calibrate now" on the reminder at the end of the setup. It has two steps in
// a fixed order - leave the setup, then open the calibration - so it cannot be
// expressed with show_factor_pending alone.
extern bool cal_now_pending;

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
extern bool printer_cycle_model_pending;
extern bool printer_cycle_media_pending;
extern bool printer_test_pending;
extern bool printer_forget_pending;
// The label of the spool on the pad, from the More info header. Rendered
// and printed from the loop: the print starts the BLE stack and blocks.
extern bool print_spool_label_pending;
