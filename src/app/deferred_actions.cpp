#include <stdint.h>

#include "deferred_actions.h"

bool skip_setup_pending = false;
bool finish_setup_pending = false;
bool cal_reminder_pending = false;
bool show_bag_pending = false;
bool show_factor_pending = false;
bool cal_reset_pending = false;
bool scale_sub_rebuild_pending = false;
bool show_lastused_pending = false;
bool show_backend_pending = false;
bool backend_mode_change_pending = false;
uint8_t pending_backend_mode = 0;
bool show_filaman_options_pending = false;
bool show_ams_assign_pending = false;
bool show_filaman_fields_pending = false;
bool show_bambuddy_options_pending = false;
bool show_bambuddy_dried_pending = false;
bool show_timezone_pending = false;
bool show_language_pending = false;
bool show_welcome_pending = false;
bool show_spoolman_options_pending = false;
bool show_extra_fields_pending = false;
bool show_tag_field_pending = false;
bool create_tag_field_pending = false;
bool show_spoolman_pending = false;
bool show_connection_from_spoolman_pending = false;
bool show_system_pending = false;
bool show_ota_pending = false;
bool show_info_pending = false;
bool show_drying_reminder_pending = false;
bool  reactivate_pending   = false;
float reactivate_weight_g  = 0.0f;
bool gh_check_pending = false;
bool gh_downgrade_pending = false;
unsigned long gh_check_wait_since = 0;

bool  show_bb_cap_pending = false;
float bb_cap_measured_g   = 0.0f;
float bb_cap_label_g      = 0.0f;
