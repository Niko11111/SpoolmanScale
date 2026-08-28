#include "user_options.h"

#include "services/tag_field.h"
#include "services/tag_write.h"

uint8_t last_used_mode = 0;
bool g_whole_gram = false;
uint8_t g_ip_bar_mode = IP_BAR_OFF;
bool g_flm_autolink = false;
bool g_flm_tagless = true;
bool g_flm_remote_write = false;
bool g_wake_on_load = true;
uint8_t g_bb_dried_target = BB_DRIED_NOTE;
uint8_t g_tag_field = TAG_FIELD_TAG;
bool g_tag_field_chosen = false;
bool g_card_uids_write = false;
bool g_flm_bambu_tags = false;
bool g_flm_ext_id = true;
uint8_t g_tagwrite_mode = TAGWRITE_OFF;
bool g_tagmismatch_ask = false;
uint8_t g_tagwrite_fmt = TAG_FMT_OPENSPOOL;
