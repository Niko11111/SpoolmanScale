#pragma once

#include <stddef.h>
#include <stdint.h>

// ============================================================
//  BACKEND PROFILES
//
//  A server that speaks Spoolman's API runs in BACKEND_SPOOLMAN: some forty
//  places unlock what such a server can do on that mode, and a fourth mode
//  would miss them all. What sets it apart is a profile on top of the mode:
//  its name, its badge, its own address and its own access.
//
//  Profile 0 is Spoolman as it always was, under the NVS keys it always had. A
//  scale that never chose anything else reads the same values as before, and a
//  firmware that knows no profiles still finds the local server untouched.
//
//  Only BACKEND_SPOOLMAN has profiles: the two other modes always run on 0.
//  A further partner is one row in the table, one in the key table and its
//  slots in server_sets.cpp.
// ============================================================

// NVS content: append, never renumber.
enum BackendProfileId : uint8_t {
  BP_SPOOLMAN = 0,
  BP_OTHER    = 1,
  BP_SPOOLY   = 2,
  BP_COUNT
};

struct BackendProfile {
  uint8_t     id;
  const char* key;           // for logs
  const char* name;          // nullptr: BP_OTHER takes what the server announces
  const char* badge;         // three characters, nullptr: derived from the name
  const char* fixed_url;     // "" when the user enters the address
  uint8_t     auth_default;  // SpoolmanAuth a new key is stored as
  const char* account_url;   // where an account is made, "" when there is no such page
  int         sub_str;       // the second line on the online page, a StringID
};

// Where a profile keeps what it does not share. Its address is empty for a
// profile with a fixed one, which is read from the table so that a service
// moving house is dealt with by an update.
struct BackendProfileKeys {
  const char* ip;
  const char* auth;
  const char* user;
  const char* secret;
  const char* bind;
};

// The online services in the order the page lists them: partners first, the
// free entry last.
extern const uint8_t BACKEND_ONLINE_ORDER[];
extern const size_t  BACKEND_ONLINE_COUNT;

const BackendProfile&     backendProfile(uint8_t id);       // unknown id: profile 0
const BackendProfileKeys& backendProfileKeys(uint8_t id);

// The active profile. Set through backendSetSelection() in backend.h.
uint8_t backendProfileId();
bool    backendProfileIsOnline();
const char* backendProfileName();    // for BP_OTHER the announced name, else the generic wording
const char* backendProfileBadge();
// What the status bar calls the server in place of its address: a service with
// a fixed address goes by its name, its test system with " Dev" after it, so
// the two are told apart. nullptr for an address the user entered.
const char* backendProfileHeaderName();
// The display name of a profile that may not be the active one.
const char* backendProfileNameOf(uint8_t id);

// Reads the stored profile, for a mode that has profiles or not.
void backendProfileLoad(bool mode_has_profiles);
// Persists. Unknown ids count as 0.
void backendProfileStore(uint8_t id);

// What a server calls itself, kept for BP_OTHER as long as its address stays.
// Anything else is ignored. Stored only when it changed. Called on the loop.
void backendProfileNoteServer(const char* base_url, const char* announced);
// After BP_OTHER's stored address changed: the old name no longer counts.
void backendProfileReloadName();
// BP_OTHER is active and has no name for its address yet.
bool backendProfileWantsServerName();

// Host of a URL for showing: "https://spooly.eu/api/spoolman" to "spooly.eu".
void backendProfileShortHost(const char* url, char* out, size_t n);

// What the web form shows of a profile that may not be the active one. Only
// whether a secret is there leaves this module, never the secret.
bool backendProfileHasSecret(uint8_t id);
void backendProfileReadAddress(uint8_t id, char* out, size_t n);
// How it gets in: the kind, its default while nothing is stored, and the user.
uint8_t backendProfileReadKind(uint8_t id);
void    backendProfileReadUser(uint8_t id, char* out, size_t n);
// The address a stored secret belongs to, "host[:port]", empty without one.
void    backendProfileReadBoundHost(uint8_t id, char* out, size_t n);
