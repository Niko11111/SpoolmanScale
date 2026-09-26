#include "user_options.h"

#include "services/tag_field.h"
#include "services/tag_write.h"

bool g_scale_fitted = true;
uint8_t last_used_mode = 0;
bool g_whole_gram = true;
uint8_t g_ip_bar_mode = IP_BAR_OFF;
bool g_flm_autolink = false;
bool g_flm_tagless = true;
bool g_flm_remote_write = false;
bool g_wake_on_load = true;
bool g_snapmaker_tags = false;
uint8_t g_bb_dried_target = BB_DRIED_NOTE;
uint8_t g_tag_field = TAG_FIELD_TAG;
bool g_tag_field_chosen = false;
bool g_card_uids_write = false;
bool g_hw_uid_write = false;
bool g_osm_tag = false;
bool g_ams_pick_ask = false;
bool g_tag2_ask = false;
bool g_flm_bambu_tags = false;
bool g_flm_ext_id = true;
uint8_t g_tagwrite_mode = TAGWRITE_OFF;
bool g_tagmismatch_ask = false;
uint8_t g_tagwrite_fmt = TAG_FMT_OPENSPOOL;
bool g_ble_enabled = false;
