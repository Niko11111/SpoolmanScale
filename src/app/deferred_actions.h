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
extern bool show_filaman_fields_pending;
extern bool show_bambuddy_options_pending;
extern bool show_bambuddy_dried_pending;
// The tag write screen: opened from the scale menu, and re-rendered by its own
// rows after a pick - same shape as show_bambuddy_dried_pending above.
extern bool show_tagwrite_pending;
extern bool show_timezone_pending;
extern bool show_language_pending;
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
