#pragma once

#include <stddef.h>

// ============================================================
//  SERVER SETS
//
//  The scale keeps a second, parked copy of everything that ties it to one
//  group of servers: the address of each backend, the FilaMan key and device
//  token, the BamBuddy key, the Spoolman access, and the AMS source. Swapping
//  the two moves the scale from one installation to the other - a home
//  server and a test Pi, say - without typing anything again, and FilaMan
//  registers only once per server.
//
//  The swap happens in NVS. The owners of the values then read them back
//  through their own load paths, so every check those apply on the way in
//  applies here too. The backend mode is not part of a set: which of the
//  three is active stays where it is. The online services are: their address
//  and access, and which of them is chosen (services/backend_profiles.h).
//
//  An absent parked key reads as empty, so a scale that never used this has
//  an empty parked set and nothing changes for it.
// ============================================================

// A name as typed into the web page, "Home" or "Test Pi".
#define SERVER_SET_NAME_MAX  24

// What the web page shows of one set. The secrets themselves never leave
// this module, only whether they are there.
struct ServerSetView {
  char name[SERVER_SET_NAME_MAX + 1];
  char spoolman[64];
  char filaman[64];
  char bambuddy[64];
  char ams_source[96];
  char online[64];        // the service name, or the other service's address
  bool filaman_key;
  bool filaman_device;
  bool bambuddy_key;
  bool spoolman_access;
  bool ams_source_key;
  bool online_access;
};

void serverSetRead(bool parked, ServerSetView* out);

// No backend and no AMS source has an address in it.
bool serverSetParkedEmpty();

// What a button that switches to the parked set calls it: its name, else the
// address it holds for the active backend, else the first address it holds.
void serverSetParkedLabel(char* out, size_t out_size);

// Stores a set's name, cleaned of anything below a space. False when NVS
// refused it.
bool serverSetRename(bool parked, const char* name);

// Empties every parked value, its name included: the second server is gone
// and the page shows the one-line offer again. The active set is untouched.
// False when NVS refused a write.
bool serverSetClearParked();

// Exchanges the active and the parked set and has the owners load the new
// active values. Call through backendApplySetSwap() (app/backend_switch.h),
// which lets go of everything that belonged to the old servers. False when
// NVS refused a write; the log names the value.
bool serverSetsSwap();
