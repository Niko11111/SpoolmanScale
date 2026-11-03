#include "services/backend_profiles.h"

#include <Arduino.h>
#include <string.h>
#include <strings.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/prefs_store.h"
#include "services/server_name_rules.h"

#define NVS_BACKEND_PROFILE "backend_prof"
#define NVS_OTHER_NAME      "bp1_name"
#define NVS_OTHER_NAME_FOR  "bp1_for"

// Not live yet at spooly.eu (404 on 03.11.2026): this branch tests against dev,
// the merge changes it to https://spooly.eu/api/spoolman.
#define SPOOLY_URL         "https://dev.spooly.eu/api/spoolman"
#define SPOOLY_ACCOUNT_URL "https://spooly.eu"

static const BackendProfile PROFILES[BP_COUNT] = {
  { BP_SPOOLMAN, "spoolman", "Spoolman", "SPM",   "",         SM_AUTH_NONE, "",                 0 },
  { BP_OTHER,    "other",    nullptr,    nullptr, "",         SM_AUTH_KEY,  "",                 STR_ONLINE_OTHER_SUB },
  { BP_SPOOLY,   "spooly",   "Spooly",   "SPY",   SPOOLY_URL, SM_AUTH_KEY,  SPOOLY_ACCOUNT_URL, STR_ONLINE_SPOOLY_SUB },
};

static const BackendProfileKeys KEYS[BP_COUNT] = {
  { "spoolman_ip", "sm_auth",  "sm_user",  "sm_secret",  "sm_bind"  },
  { "bp1_ip",      "bp1_auth", "bp1_user", "bp1_secret", "bp1_bind" },
  { "",            "bp2_auth", "bp2_user", "bp2_secret", "bp2_bind" },
};

const uint8_t BACKEND_ONLINE_ORDER[] = { BP_SPOOLY, BP_OTHER };
const size_t  BACKEND_ONLINE_COUNT   = sizeof(BACKEND_ONLINE_ORDER) / sizeof(BACKEND_ONLINE_ORDER[0]);

static uint8_t s_profile = BP_SPOOLMAN;
static char    s_other_name[SERVER_NAME_MAX + 1] = "";
static char    s_other_badge[SERVER_BADGE_LEN + 1] = SERVER_BADGE_DEFAULT;

static void useOtherName(const char* name) {
  snprintf(s_other_name, sizeof(s_other_name), "%s", name);
  serverNameBadge(s_other_name, s_other_badge);
}

static void shortHostOfStoredOther(char* out, size_t n) {
  const String addr = prefsGetString(KEYS[BP_OTHER].ip, "");
  backendProfileShortHost(addr.c_str(), out, n);
}

void backendProfileReloadName() {
  // A name read back from NVS is held to the same rules as a new one, and it
  // only counts for the address it was announced by: another address may be
  // another service.
  char clean[SERVER_NAME_MAX + 1];
  char host[64];
  shortHostOfStoredOther(host, sizeof(host));
  const String name = prefsGetString(NVS_OTHER_NAME, "");
  const bool ok = prefsGetString(NVS_OTHER_NAME_FOR, "") == host &&
                  serverNameClean(name.c_str(), clean, sizeof(clean));
  useOtherName(ok ? clean : "");
}

const BackendProfile& backendProfile(uint8_t id) {
  return PROFILES[id < BP_COUNT ? id : BP_SPOOLMAN];
}

const BackendProfileKeys& backendProfileKeys(uint8_t id) {
  return KEYS[id < BP_COUNT ? id : BP_SPOOLMAN];
}

uint8_t backendProfileId()       { return s_profile; }
bool    backendProfileIsOnline() { return s_profile != BP_SPOOLMAN; }

const char* backendProfileNameOf(uint8_t id) {
  const BackendProfile& p = backendProfile(id);
  if (p.name) return p.name;
  return s_other_name[0] ? s_other_name : T(STR_ONLINE_OTHER);
}

const char* backendProfileName() { return backendProfileNameOf(s_profile); }

const char* backendProfileBadge() {
  const BackendProfile& p = backendProfile(s_profile);
  return p.badge ? p.badge : s_other_badge;
}

const char* backendProfileHeaderName() {
  const BackendProfile& p = backendProfile(s_profile);
  if (!p.fixed_url[0] || !p.name) return nullptr;
  char host[64];
  backendProfileShortHost(p.fixed_url, host, sizeof(host));
  static char name[24];
  snprintf(name, sizeof(name), "%s%s", p.name, strncasecmp(host, "dev.", 4) == 0 ? " Dev" : "");
  return name;
}

void backendProfileLoad(bool mode_has_profiles) {
  const uint8_t raw = prefsGetUChar(NVS_BACKEND_PROFILE, BP_SPOOLMAN);
  // Anything unknown is the plain server: a value written by a newer firmware
  // cannot leave the scale on a profile this build has no row for.
  s_profile = (mode_has_profiles && raw < BP_COUNT) ? raw : (uint8_t)BP_SPOOLMAN;
  backendProfileReloadName();
}

void backendProfileStore(uint8_t id) {
  s_profile = id < BP_COUNT ? id : (uint8_t)BP_SPOOLMAN;
  prefsPutUChar(NVS_BACKEND_PROFILE, s_profile);
}

void backendProfileShortHost(const char* url, char* out, size_t n) {
  if (!out || n == 0) return;
  out[0] = '\0';
  if (!url) return;
  if (strncasecmp(url, "https://", 8) == 0)     url += 8;
  else if (strncasecmp(url, "http://", 7) == 0) url += 7;
  size_t j = 0;
  for (; *url && *url != '/' && j + 1 < n; url++) out[j++] = *url;
  out[j] = '\0';
}

bool backendProfileWantsServerName() {
  return s_profile == BP_OTHER && !s_other_name[0];
}

void backendProfileNoteServer(const char* base_url, const char* announced) {
  if (s_profile != BP_OTHER) return;
  char clean[SERVER_NAME_MAX + 1];
  if (!serverNameClean(announced, clean, sizeof(clean))) {
    if (announced && announced[0]) logSD("Backend: the name the server announced is not usable");
    return;
  }
  char host[64];
  backendProfileShortHost(base_url, host, sizeof(host));
  char stored[64];
  shortHostOfStoredOther(stored, sizeof(stored));
  if (strcasecmp(host, stored) != 0) return;   // an answer from before the address changed
  if (!strcmp(clean, s_other_name)) return;
  prefsPutString(NVS_OTHER_NAME, clean);
  prefsPutString(NVS_OTHER_NAME_FOR, host);
  useOtherName(clean);
  logSDf("Backend: the server at %s calls itself %s", host, clean);
}

bool backendProfileHasSecret(uint8_t id) {
  return prefsGetString(backendProfileKeys(id).secret, "").length() > 0;
}

void backendProfileReadAddress(uint8_t id, char* out, size_t n) {
  if (!out || n == 0) return;
  const BackendProfile& p = backendProfile(id);
  if (p.fixed_url[0]) { snprintf(out, n, "%s", p.fixed_url); return; }
  const String addr = prefsGetString(backendProfileKeys(id).ip, "");
  snprintf(out, n, "%s", addr.c_str());
}

uint8_t backendProfileReadKind(uint8_t id) {
  const uint8_t kind = prefsGetUChar(backendProfileKeys(id).auth, SM_AUTH_NONE);
  return (kind == SM_AUTH_NONE || kind > SM_AUTH_BASIC) ? backendProfile(id).auth_default : kind;
}

void backendProfileReadUser(uint8_t id, char* out, size_t n) {
  if (!out || n == 0) return;
  const String user = prefsGetString(backendProfileKeys(id).user, "");
  snprintf(out, n, "%s", user.c_str());
}

void backendProfileReadBoundHost(uint8_t id, char* out, size_t n) {
  if (!out || n == 0) return;
  const String bound = prefsGetString(backendProfileKeys(id).bind, "");
  snprintf(out, n, "%s", bound.c_str());
}
