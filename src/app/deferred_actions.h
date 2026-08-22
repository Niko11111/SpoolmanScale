#pragma once

extern bool skip_setup_pending;
extern bool finish_setup_pending;
extern bool cal_reminder_pending;
extern bool show_bag_pending;
extern bool show_factor_pending;
extern bool show_lastused_pending;
extern bool show_backend_pending;
extern bool show_filaman_options_pending;
extern bool show_bambuddy_options_pending;
extern bool show_bambuddy_dried_pending;
extern bool show_spoolman_pending;
extern bool show_connection_from_spoolman_pending;
extern bool show_system_pending;
extern bool show_ota_pending;
extern bool show_info_pending;
extern bool show_drying_reminder_pending;
extern bool lang_selected_no_reboot;

// Asked before a weight is written that BamBuddy's own inventory would clamp:
// it stores consumption, so anything above the label weight is lost. Carries
// the two numbers the question needs.
extern bool  show_bb_cap_pending;
extern float bb_cap_measured_g;
extern float bb_cap_label_g;
