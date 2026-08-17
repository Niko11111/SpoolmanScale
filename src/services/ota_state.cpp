#include "ota_state.h"

bool update_available = false;
bool gh_prerelease = false;

char gh_latest_version[32] = "";

volatile bool gh_flash_active = false;

bool g_upd_autocheck = true;
uint32_t g_upd_last_epoch = 0;
