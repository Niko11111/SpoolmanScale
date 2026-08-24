#pragma once

extern bool skip_setup_pending;
extern bool finish_setup_pending;
extern bool cal_reminder_pending;
extern bool show_bag_pending;
extern bool show_factor_pending;
extern bool show_lastused_pending;
extern bool show_backend_pending;
extern bool show_filaman_options_pending;
extern bool show_ams_assign_pending;
extern bool show_filaman_fields_pending;
extern bool show_bambuddy_options_pending;
extern bool show_bambuddy_dried_pending;
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
extern bool lang_selected_no_reboot;

// The OTA screen asked for a check while the background task held the TLS
// connection. Retried from appLoop() once it is free, and given up on after
// GH_CHECK_WAIT_MS so a task that never finishes cannot leave the screen
// waiting forever.
extern bool gh_check_pending;
extern unsigned long gh_check_wait_since;
#define GH_CHECK_WAIT_MS 10000

// Asked before a weight is written that BamBuddy's own inventory would clamp:
// it stores consumption, so anything above the label weight is lost. Carries
// the two numbers the question needs.
extern bool  show_bb_cap_pending;
extern float bb_cap_measured_g;
extern float bb_cap_label_g;
