#include "backend.h"
#include "services/backend_http.h"

#include <Arduino.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/app_settings.h"
#include "services/bambuddy_api.h"
#include "services/prefs_store.h"

// NVS keys. Kept short, NVS limits key length to 15 characters.
#define NVS_BACKEND_MODE    "backend_mode"
#define NVS_FILAMAN_KEY     "filaman_key"
#define NVS_FILAMAN_DEVICE  "filaman_dev"
#define NVS_FILAMAN_HOST    "filaman_host"
#define NVS_BAMBUDDY_KEY    "bb_key"
#define NVS_BAMBUDDY_HOST   "bb_host"
#define NVS_SM_AUTH         "sm_auth"
#define NVS_SM_USER         "sm_user"
#define NVS_SM_SECRET       "sm_secret"
#define NVS_SM_BIND         "sm_bind"

static BackendMode s_mode = BACKEND_SPOOLMAN;
static char s_api_key[80]      = "";
static char s_device_token[80] = "";
static char s_filaman_host[64] = "";
static char s_filaman_base[80] = "";
// BamBuddy keys look like "bb_" plus 43 base64url characters, 46 in total.
static char s_bambuddy_key[80]  = "";
static char s_bambuddy_host[64] = "";
static char s_bambuddy_base[80] = "";
static uint8_t s_sm_auth        = SM_AUTH_NONE;
static char    s_sm_user[64]    = "";
static char    s_sm_secret[SM_SECRET_MAX_LEN + 1] = "";
static char    s_sm_bind[64]    = "";   // the address the secret was entered for

// The one place an address becomes a base URL. A stored address carries its
// scheme only when it is https; a bare one is http, as every address was
// before https existed, so nothing already stored changes meaning.
void backendComposeBase(char* out, size_t n, const char* host) {
  if (!out || n == 0) return;
  if (!host || !host[0])                     out[0] = '\0';
  else if (strncasecmp(host, "https://", 8) == 0) snprintf(out, n, "%s", host);
  else                                       snprintf(out, n, "http://%s", host);
}

static void rebuildFilamanBase() {
  backendComposeBase(s_filaman_base, sizeof(s_filaman_base), s_filaman_host);
}

static void rebuildBamBuddyBase() {
  backendComposeBase(s_bambuddy_base, sizeof(s_bambuddy_base), s_bambuddy_host);
}

// A credential goes into an HTTP header as it is, so a CR or LF inside it
// would end the header line and start one the sender chose. The web form
// trims the ends only; everything below a space and DEL is dropped here,
// for every key and token on its way in, from the form and from NVS.
static void copyCredential(char* dst, size_t n, const char* src) {
  size_t j = 0;
  for (size_t i = 0; src[i] && j + 1 < n; i++) {
    const unsigned char c = (unsigned char)src[i];
    if (c < 0x20 || c == 0x7f) continue;
    dst[j++] = (char)c;
  }
  dst[j] = '\0';
}

// How long a credential is once copyCredential() has dropped what it drops.
static size_t credentialLen(const char* src) {
  size_t n = 0;
  for (size_t i = 0; src[i]; i++) {
    const unsigned char c = (unsigned char)src[i];
    if (c >= 0x20 && c != 0x7f) n++;
  }
  return n;
}

// "https://Spoolman.lan:7912/x" -> "spoolman.lan:7912": what the Spoolman
// secret is bound to, from a stored address or from a request's URL alike.
static void smBindKey(const char* addr, char* out, size_t n) {
  if (!out || n == 0) return;
  out[0] = '\0';
  if (!addr) return;
  if (strncasecmp(addr, "https://", 8) == 0)     addr += 8;
  else if (strncasecmp(addr, "http://", 7) == 0) addr += 7;
  size_t j = 0;
  for (; *addr && *addr != '/' && *addr != '?' && *addr != '#' && j + 1 < n; addr++) {
    out[j++] = (char)tolower((unsigned char)*addr);
  }
  out[j] = '\0';
}

// An empty binding matches nothing: a secret entered while no address was
// set goes nowhere until it is entered again.
static bool smBoundTo(const char* addr) {
  if (!spoolmanAuthStored() || !s_sm_bind[0]) return false;
  char key[sizeof(s_sm_bind)];
  smBindKey(addr, key, sizeof(key));
  return strcmp(key, s_sm_bind) == 0;
}

void backendLoadSettings() {
  backendTlsLoad();
  uint8_t raw = prefsGetUChar(NVS_BACKEND_MODE, BACKEND_SPOOLMAN);
  // Anything unknown falls back to Spoolman, so a value written by a newer
  // firmware cannot leave the device in a mode this build has no code for.
  s_mode = (raw == BACKEND_FILAMAN)  ? BACKEND_FILAMAN
         : (raw == BACKEND_BAMBUDDY) ? BACKEND_BAMBUDDY
                                     : BACKEND_SPOOLMAN;

  String key = prefsGetString(NVS_FILAMAN_KEY, "");
  copyCredential(s_api_key, sizeof(s_api_key), key.c_str());

  String dev = prefsGetString(NVS_FILAMAN_DEVICE, "");
  copyCredential(s_device_token, sizeof(s_device_token), dev.c_str());

  String host = prefsGetString(NVS_FILAMAN_HOST, "");
  strncpy(s_filaman_host, host.c_str(), sizeof(s_filaman_host) - 1);
  s_filaman_host[sizeof(s_filaman_host) - 1] = '\0';
  rebuildFilamanBase();

  String bb_key = prefsGetString(NVS_BAMBUDDY_KEY, "");
  copyCredential(s_bambuddy_key, sizeof(s_bambuddy_key), bb_key.c_str());

  const uint8_t sm_auth = prefsGetUChar(NVS_SM_AUTH, SM_AUTH_NONE);
  s_sm_auth = (sm_auth <= SM_AUTH_BASIC) ? sm_auth : SM_AUTH_NONE;
  String sm_user = prefsGetString(NVS_SM_USER, "");
  copyCredential(s_sm_user, sizeof(s_sm_user), sm_user.c_str());
  String sm_secret = prefsGetString(NVS_SM_SECRET, "");
  copyCredential(s_sm_secret, sizeof(s_sm_secret), sm_secret.c_str());
  String sm_bind = prefsGetString(NVS_SM_BIND, "");
  snprintf(s_sm_bind, sizeof(s_sm_bind), "%s", sm_bind.c_str());
  // A secret stored before it was bound to an address belongs to the one it
  // has been going to all along. loadPrefs() has read that address already.
  if (s_sm_secret[0] && !prefsHasKey(NVS_SM_BIND)) {
    smBindKey(cfg_spoolman_ip, s_sm_bind, sizeof(s_sm_bind));
    prefsPutString(NVS_SM_BIND, s_sm_bind);
    logSDf("Backend: Spoolman access bound to %s", s_sm_bind[0] ? s_sm_bind : "-");
  }

  String bb_host = prefsGetString(NVS_BAMBUDDY_HOST, "");
  strncpy(s_bambuddy_host, bb_host.c_str(), sizeof(s_bambuddy_host) - 1);
  s_bambuddy_host[sizeof(s_bambuddy_host) - 1] = '\0';
  rebuildBamBuddyBase();

  // Both channels, so the active backend is visible in a serial monitor as
  // well and not only on the card. writeBootBlock() repeats the same line
  // inside the daily log file, which is the one a user actually sends in.
  char line[160];
  backendStatusLine(line, sizeof(line));
  logSDf("Backend: %s", line);
  Serial.printf("Backend: %s\n", line);
}

BackendMode backendMode() { return s_mode; }
bool backendIsFilaMan()   { return s_mode == BACKEND_FILAMAN; }
bool backendIsBamBuddy()  { return s_mode == BACKEND_BAMBUDDY; }

void backendSetMode(BackendMode mode) {
  s_mode = (mode == BACKEND_FILAMAN)  ? BACKEND_FILAMAN
         : (mode == BACKEND_BAMBUDDY) ? BACKEND_BAMBUDDY
                                      : BACKEND_SPOOLMAN;
  prefsPutUChar(NVS_BACKEND_MODE, (uint8_t)s_mode);
  logSDf("Backend: mode -> %s", backendName());
}

const char* backendBaseUrl() {
  switch (s_mode) {
    case BACKEND_FILAMAN:  return s_filaman_base;
    case BACKEND_BAMBUDDY: return s_bambuddy_base;
    default:               return cfg_spoolman_base;
  }
}

const char* backendHost() {
  switch (s_mode) {
    case BACKEND_FILAMAN:  return s_filaman_host;
    case BACKEND_BAMBUDDY: return s_bambuddy_host;
    default:               return cfg_spoolman_ip;
  }
}

// Cleans an address before it is stored. Until now this took whatever it was
// handed, which was harmless while the only way in was the device's twelve
// key numeric pad - it cannot produce a slash or a space. The web interface
// has a real keyboard, so "http://spoolman.local/" is now a thing a user can
// type, and rebuildFilamanBase() would have turned it into
// "http://http://spoolman.local/".
//
// "https://" is kept, in lower case, and becomes the scheme of the base URL
// (backendComposeBase); "http://" is dropped, because a bare address already
// means http.
size_t backendCleanHost(const char* in, char* out, size_t out_size) {
  if (!in || !out || out_size == 0) return 0;
  while (*in == ' ' || *in == '\t') in++;
  if (strncasecmp(in, "http://", 7) == 0) in += 7;
  size_t lead = 0;
  if (strncasecmp(in, "https://", 8) == 0 && out_size > 9) {
    memcpy(out, "https://", 8);
    lead = 8;
    in += 8;
  }

  // Only what an address is made of: letters, digits, dot, colon, hyphen,
  // underscore, slash. A quote or a bracket has no place in one, and the
  // value goes into a page attribute later - escaped there as well, but a
  // host that cannot carry one is the cheaper of the two locks.
  size_t n = lead;
  for (; *in && n + 1 < out_size; in++) {
    const char c = *in;
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == ':' ||
                    c == '-' || c == '_' || c == '/';
    if (ok) out[n++] = c;
  }
  while (n > lead && (out[n-1] == ' ' || out[n-1] == '\t' || out[n-1] == '/')) n--;
  if (n == lead) n = 0;   // a scheme with nothing behind it is no address
  out[n] = '\0';
  return n;
}

void backendSetHost(const char* host) {
  if (!host) return;
  char clean[64];
  backendCleanHost(host, clean, sizeof(clean));
  host = clean;
  switch (s_mode) {
    case BACKEND_FILAMAN:
      strncpy(s_filaman_host, host, sizeof(s_filaman_host) - 1);
      s_filaman_host[sizeof(s_filaman_host) - 1] = '\0';
      rebuildFilamanBase();
      prefsPutString(NVS_FILAMAN_HOST, s_filaman_host);
      logSDf("Backend: FilaMan host -> %s", s_filaman_host);
      return;
    case BACKEND_BAMBUDDY:
      strncpy(s_bambuddy_host, host, sizeof(s_bambuddy_host) - 1);
      s_bambuddy_host[sizeof(s_bambuddy_host) - 1] = '\0';
      rebuildBamBuddyBase();
      prefsPutString(NVS_BAMBUDDY_HOST, s_bambuddy_host);
      logSDf("Backend: BamBuddy host -> %s", s_bambuddy_host);
      return;
    default:
      saveSpoolmanIP(host);   // unchanged path, same NVS key as before
      return;
  }
}

const char* filamanApiKey()      { return s_api_key; }
const char* filamanDeviceToken() { return s_device_token; }

void filamanSetApiKey(const char* key) {
  if (!key) return;
  copyCredential(s_api_key, sizeof(s_api_key), key);
  prefsPutString(NVS_FILAMAN_KEY, s_api_key);
  logSDf("Backend: FilaMan API key %s", s_api_key[0] ? "stored" : "cleared");
}

void filamanSetDeviceToken(const char* token) {
  if (!token) return;
  copyCredential(s_device_token, sizeof(s_device_token), token);
  prefsPutString(NVS_FILAMAN_DEVICE, s_device_token);
  logSDf("Backend: FilaMan device token %s", s_device_token[0] ? "stored" : "cleared");
}

const char* bambuddyApiKey() { return s_bambuddy_key; }

void bambuddySetApiKey(const char* key) {
  if (!key) return;
  copyCredential(s_bambuddy_key, sizeof(s_bambuddy_key), key);
  prefsPutString(NVS_BAMBUDDY_KEY, s_bambuddy_key);
  logSDf("Backend: BamBuddy API key %s", s_bambuddy_key[0] ? "stored" : "cleared");
}

uint8_t     spoolmanAuthMode()   { return s_sm_auth; }
const char* spoolmanAuthUser()   { return s_sm_user; }
const char* spoolmanAuthSecret() { return s_sm_secret; }
const char* spoolmanAuthBoundHost() { return s_sm_bind; }
bool spoolmanAuthStored() { return s_sm_auth != SM_AUTH_NONE && s_sm_secret[0]; }
bool spoolmanAuthActive() { return smBoundTo(cfg_spoolman_ip); }
bool spoolmanAuthSendsTo(const char* url) { return smBoundTo(url); }

bool spoolmanSetAuth(uint8_t mode, const char* user, const char* secret) {
  if (secret && credentialLen(secret) > SM_SECRET_MAX_LEN) {
    logSDf("Backend: Spoolman secret refused, %u characters, at most %u",
           (unsigned)credentialLen(secret), (unsigned)SM_SECRET_MAX_LEN);
    return false;
  }
  s_sm_auth = (mode <= SM_AUTH_BASIC) ? mode : SM_AUTH_NONE;
  copyCredential(s_sm_user, sizeof(s_sm_user), user ? user : "");
  if (secret) {
    copyCredential(s_sm_secret, sizeof(s_sm_secret), secret);
    smBindKey(cfg_spoolman_ip, s_sm_bind, sizeof(s_sm_bind));
  }
  // No access chosen means none stored either, so nothing lingers in NVS.
  if (s_sm_auth == SM_AUTH_NONE) { s_sm_user[0] = '\0'; s_sm_secret[0] = '\0'; }
  // No secret, nothing to bind.
  if (!s_sm_secret[0]) s_sm_bind[0] = '\0';
  prefsPutUChar(NVS_SM_AUTH, s_sm_auth);
  prefsPutString(NVS_SM_USER, s_sm_user);
  prefsPutString(NVS_SM_SECRET, s_sm_secret);
  prefsPutString(NVS_SM_BIND, s_sm_bind);
  // A connection kept open was made with the old credentials.
  backendConnClose();
  logSDf("Backend: Spoolman access %s",
         spoolmanAuthActive() ? "stored" : spoolmanAuthStored() ? "stored, for another address"
                                                                : "cleared");
  return true;
}

const char* backendModeName(BackendMode mode) {
  switch (mode) {
    case BACKEND_FILAMAN:  return "FilaMan";
    case BACKEND_BAMBUDDY: return "BamBuddy";
    default:               return "Spoolman";
  }
}

const char* backendName() { return backendModeName(s_mode); }

const char* backendBadge() {
  switch (s_mode) {
    case BACKEND_FILAMAN:  return "FLM";
    // Which database is behind BamBuddy decides where every read and write
    // lands, and it can change while the scale runs - worth the one letter.
    case BACKEND_BAMBUDDY: return (bbInventoryMode() == BB_INV_SPOOLMAN) ? "BBS" : "BBY";
    default:               return "SPM";
  }
}

void backendCaption(char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  snprintf(out, out_size, "%s", backendName());
}

bool backendSpoolPageUrl(int spool_id, char* out, size_t out_size) {
  if (!out || out_size == 0) return false;
  out[0] = '\0';
  const char* base = backendBaseUrl();
  if (spool_id <= 0 || !base || !base[0]) return false;
  switch (s_mode) {
    case BACKEND_SPOOLMAN:
      snprintf(out, out_size, "%s/spool/show/%d", base, spool_id);
      return true;
    case BACKEND_FILAMAN:
      snprintf(out, out_size, "%s/spools/%d", base, spool_id);
      return true;
    default:
      return false;
  }
}

void backendStatusLine(char* out, size_t out_size) {
  if (!out || out_size == 0) return;

  // backendHost() picks the host of the active mode, so a leftover FilaMan
  // address never shows up while Spoolman is selected, and the other way round.
  const char* host = backendHost();

  if (backendIsFilaMan()) {
    snprintf(out, out_size, "%s | host=%s | key=%s | device=%s | configured=%s",
      backendName(),
      host[0] ? host : "-",
      s_api_key[0] ? "set" : "empty",
      s_device_token[0] ? "set" : "empty",
      backendIsConfigured() ? "yes" : "no");
  } else if (backendIsBamBuddy()) {
    // The key is reported but never gates "configured" - an instance with
    // authentication disabled works without one.
    snprintf(out, out_size, "%s | host=%s | key=%s | configured=%s",
      backendName(),
      host[0] ? host : "-",
      s_bambuddy_key[0] ? "set" : "empty",
      backendIsConfigured() ? "yes" : "no");
  } else {
    static const char* const AUTH[] = { "none", "key", "bearer", "basic" };
    snprintf(out, out_size, "%s | host=%s | auth=%s | configured=%s",
      backendName(),
      host[0] ? host : "-",
      spoolmanAuthActive() ? AUTH[s_sm_auth] : spoolmanAuthStored() ? "other-address" : "none",
      backendIsConfigured() ? "yes" : "no");
  }
}

void backendText(const char* src, char* out, size_t out_size) {
  if (!out || out_size == 0) return;
  out[0] = '\0';
  if (!src) return;

  // In Spoolman mode nothing changes, so take the cheap path.
  if (s_mode == BACKEND_SPOOLMAN) {
    strncpy(out, src, out_size - 1);
    out[out_size - 1] = '\0';
    return;
  }

  static const char  kNeedle[] = "Spoolman";
  static const size_t kNeedleLen = sizeof(kNeedle) - 1;
  const char* name = backendName();
  const size_t name_len = strlen(name);

  size_t o = 0;
  for (const char* p = src; *p && o < out_size - 1; ) {
    if (strncmp(p, kNeedle, kNeedleLen) == 0 &&
        strncmp(p + kNeedleLen, "Scale", 5) != 0) {   // never touch SpoolmanScale
      size_t room = out_size - 1 - o;
      size_t n = (name_len < room) ? name_len : room;
      memcpy(out + o, name, n);
      o += n;
      p += kNeedleLen;
      continue;
    }
    out[o++] = *p++;
  }
  out[o] = '\0';
}

bool backendIsConfigured() {
  if (strlen(backendBaseUrl()) <= 7) return false;   // longer than "http://"
  if (!backendIsFilaMan()) return true;              // Spoolman and BamBuddy need no credentials
  return s_api_key[0] != '\0' && s_device_token[0] != '\0';
}
