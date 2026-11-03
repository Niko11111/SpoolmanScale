#include "services/server_sets.h"

#include <Arduino.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/ams_source.h"
#include "services/app_settings.h"
#include "services/backend.h"
#include "services/backend_profiles.h"
#include "services/prefs_store.h"
#include "services/text_util.h"

// One value of a set: the key its owner reads it from, and the key it is
// parked under. The active keys belong to app_settings.cpp (spoolman_ip),
// backend.cpp and ams_source.cpp; NVS keys are never renamed, since a device
// in the field already carries them. Parked keys stay within NVS's 15
// characters.
struct SetSlot {
  const char* active;
  const char* parked;
  bool        is_uchar;   // sm_auth is a number, everything else text
};

static const SetSlot SLOTS[] = {
  { "spoolman_ip",  "alt_sm_ip",     false },
  { "filaman_host", "alt_fm_host",   false },
  { "filaman_key",  "alt_fm_key",    false },
  { "filaman_dev",  "alt_fm_dev",    false },
  { "bb_host",      "alt_bb_host",   false },
  { "bb_key",       "alt_bb_key",    false },
  { "sm_auth",      "alt_sm_auth",   true  },
  { "sm_user",      "alt_sm_user",   false },
  { "sm_secret",    "alt_sm_secret", false },
  { "sm_bind",      "alt_sm_bind",   false },
  { "ams_src_host", "alt_ams_host",  false },
  { "ams_src_key",  "alt_ams_key",   false },
  { "set_name",     "alt_set_name",  false },
  { "backend_prof", "alt_bk_prof",   true  },
  { "bp1_ip",       "alt_bp1_ip",    false },
  { "bp1_auth",     "alt_bp1_auth",  true  },
  { "bp1_user",     "alt_bp1_user",  false },
  { "bp1_secret",   "alt_bp1_secret", false },
  { "bp1_bind",     "alt_bp1_bind",  false },
  { "bp1_name",     "alt_bp1_name",  false },
  { "bp1_for",      "alt_bp1_for",   false },
  { "bp2_auth",     "alt_bp2_auth",  true  },
  { "bp2_user",     "alt_bp2_user",  false },
  { "bp2_secret",   "alt_bp2_secret", false },
  { "bp2_bind",     "alt_bp2_bind",  false },
};
static constexpr size_t SLOT_COUNT = sizeof(SLOTS) / sizeof(SLOTS[0]);

enum SlotIndex : uint8_t {
  SLOT_SPOOLMAN, SLOT_FM_HOST, SLOT_FM_KEY, SLOT_FM_DEV, SLOT_BB_HOST, SLOT_BB_KEY,
  SLOT_SM_AUTH, SLOT_SM_USER, SLOT_SM_SECRET, SLOT_SM_BIND, SLOT_AMS_HOST,
  SLOT_AMS_KEY, SLOT_NAME,
  SLOT_PROFILE, SLOT_OTHER_IP, SLOT_OTHER_AUTH, SLOT_OTHER_USER, SLOT_OTHER_SECRET,
  SLOT_OTHER_BIND, SLOT_OTHER_NAME, SLOT_OTHER_FOR,
  SLOT_SPOOLY_AUTH, SLOT_SPOOLY_USER, SLOT_SPOOLY_SECRET, SLOT_SPOOLY_BIND
};
static_assert(SLOT_SPOOLY_BIND + 1 == SLOT_COUNT, "SlotIndex and SLOTS are out of step");

static const char* keyOf(SlotIndex i, bool parked) {
  return parked ? SLOTS[i].parked : SLOTS[i].active;
}

static String readText(SlotIndex i, bool parked) {
  // The Spoolman address has a built-in default that loadPrefs() falls back
  // to while nothing is stored; the active set shows the same.
  // With an online service active the RAM copy holds that service's address,
  // which must never land in the local server's key.
  const char* fallback = (!parked && i == SLOT_SPOOLMAN && !backendProfileIsOnline())
                             ? cfg_spoolman_ip : "";
  return prefsGetString(keyOf(i, parked), fallback);
}

static void copyText(char* out, size_t n, const String& s) {
  snprintf(out, n, "%s", s.c_str());
}

void serverSetRead(bool parked, ServerSetView* out) {
  if (!out) return;
  *out = ServerSetView{};
  copyText(out->name,       sizeof(out->name),       readText(SLOT_NAME, parked));
  copyText(out->spoolman,   sizeof(out->spoolman),   readText(SLOT_SPOOLMAN, parked));
  copyText(out->filaman,    sizeof(out->filaman),    readText(SLOT_FM_HOST, parked));
  copyText(out->bambuddy,   sizeof(out->bambuddy),   readText(SLOT_BB_HOST, parked));
  copyText(out->ams_source, sizeof(out->ams_source), readText(SLOT_AMS_HOST, parked));
  out->filaman_key     = readText(SLOT_FM_KEY, parked).length() > 0;
  out->filaman_device  = readText(SLOT_FM_DEV, parked).length() > 0;
  out->bambuddy_key    = readText(SLOT_BB_KEY, parked).length() > 0;
  out->spoolman_access = prefsGetUChar(keyOf(SLOT_SM_AUTH, parked), SM_AUTH_NONE) != SM_AUTH_NONE &&
                         readText(SLOT_SM_SECRET, parked).length() > 0;
  out->ams_source_key  = readText(SLOT_AMS_KEY, parked).length() > 0;
  // What the set has chosen, else what it holds. Spooly's address is in the
  // firmware, so without the choice its key is what says it is in use.
  const uint8_t chosen = prefsGetUChar(keyOf(SLOT_PROFILE, parked), BP_SPOOLMAN);
  const String other = readText(SLOT_OTHER_IP, parked);
  const bool spooly_key = readText(SLOT_SPOOLY_SECRET, parked).length() > 0;
  const bool spooly = chosen == BP_SPOOLY || (chosen != BP_OTHER && !other.length() && spooly_key);
  copyText(out->online, sizeof(out->online), spooly ? String(backendProfileNameOf(BP_SPOOLY)) : other);
  out->online_access = spooly ? spooly_key : readText(SLOT_OTHER_SECRET, parked).length() > 0;
}

bool serverSetParkedEmpty() {
  ServerSetView v;
  serverSetRead(true, &v);
  return !v.spoolman[0] && !v.filaman[0] && !v.bambuddy[0] && !v.ams_source[0] && !v.online[0];
}

void serverSetParkedLabel(char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  ServerSetView v;
  serverSetRead(true, &v);
  const char* own = backendIsFilaMan()  ? v.filaman
                  : backendIsBamBuddy() ? v.bambuddy
                                        : v.spoolman;
  const char* pick = v.name[0] ? v.name
                   : own[0]    ? own
                   : v.spoolman[0] ? v.spoolman
                   : v.filaman[0]  ? v.filaman
                   : v.bambuddy[0] ? v.bambuddy
                   : v.online[0]   ? v.online
                                   : v.ams_source;
  snprintf(out, out_size, "%s", pick);
}

bool serverSetRename(bool parked, const char* name) {
  if (!name) name = "";
  while (*name == ' ') name++;   // leading blanks would use up the length
  // Below a space and DEL are dropped: the name ends up in a page and a log
  // line. Then cut on a character boundary and trimmed.
  char clean[64];
  size_t j = 0;
  for (size_t i = 0; name[i] && j + 1 < sizeof(clean); i++) {
    const unsigned char c = (unsigned char)name[i];
    if (c >= 0x20 && c != 0x7f) clean[j++] = (char)c;
  }
  clean[j] = '\0';
  char cut[SERVER_SET_NAME_MAX + 1];
  utf8Cut(clean, SERVER_SET_NAME_MAX, cut, sizeof(cut));
  String s(cut);
  s.trim();
  const bool ok = prefsPutString(keyOf(SLOT_NAME, parked), s.c_str());
  logSDf("Server set: %s set named \"%s\"%s", parked ? "parked" : "active", s.c_str(),
         ok ? "" : " - not stored");
  return ok;
}

bool serverSetClearParked() {
  bool ok = true;
  for (size_t i = 0; i < SLOT_COUNT; i++) {
    const SetSlot& s = SLOTS[i];
    const bool done = s.is_uchar ? prefsPutUChar(s.parked, 0) : prefsPutString(s.parked, "");
    if (!done) logSDf("Server set: NVS refused to clear %s", s.parked);
    ok = ok && done;
  }
  logSDf("Server set: parked set removed%s", ok ? "" : " - incomplete");
  return ok;
}

static bool swapSlot(SlotIndex i) {
  const SetSlot& s = SLOTS[i];
  if (s.is_uchar) {
    const uint8_t a = prefsGetUChar(s.active, 0);
    const uint8_t p = prefsGetUChar(s.parked, 0);
    return prefsPutUChar(s.active, p) && prefsPutUChar(s.parked, a);
  }
  const String a = readText(i, false);
  const String p = readText(i, true);
  return prefsPutString(s.active, p.c_str()) && prefsPutString(s.parked, a.c_str());
}

// The owners read their values again, each through its own load path.
static void reloadOwners() {
  saveSpoolmanIP(readText(SLOT_SPOOLMAN, false).c_str());
  backendLoadSettings();
  const String host = readText(SLOT_AMS_HOST, false);
  const String key  = readText(SLOT_AMS_KEY, false);
  if (!amsSourceSet(host.c_str(), key.c_str())) {
    logSDf("Server set: AMS source %s does not fit, switched off", host.c_str());
    amsSourceSet("", "");
  }
}

bool serverSetsSwap() {
  const unsigned long t0 = millis();
  bool ok = true;
  for (size_t i = 0; i < SLOT_COUNT && ok; i++) {
    ok = swapSlot((SlotIndex)i);
    if (!ok) logSDf("Server set: swap stopped, NVS refused %s", SLOTS[i].active);
  }
  reloadOwners();
  ServerSetView now;
  serverSetRead(false, &now);
  logSDf("Server set: now \"%s\" (%s), %lu ms%s", now.name, backendHost(),
         millis() - t0, ok ? "" : " - incomplete");
  return ok;
}
