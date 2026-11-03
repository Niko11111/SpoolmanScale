#include "services/server_refusal.h"

#include <Arduino.h>

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"

// Written by whichever core ran the request, read by the loop. One word each,
// and being a pass late with either changes nothing.
static volatile bool     s_paused         = false;
static volatile uint32_t s_pause_until_ms = 0;
static volatile int      s_seen_code      = 0;
static volatile uint32_t s_refusal_count  = 0;

static ServerRefusal s_popup_pending      = REFUSAL_NONE;
static bool          s_placement_popup_used = false;

void serverRefusalRecord(int code, const char* retry_after) {
  const ServerRefusal refusal = serverRefusalOf(code);
  if (refusal == REFUSAL_NONE) return;
  s_seen_code = code;
  s_refusal_count = s_refusal_count + 1;
  if (refusal != REFUSAL_TOO_MANY) return;
  const uint32_t seconds = retryAfterSeconds(retry_after);
  s_pause_until_ms = millis() + seconds * 1000UL;
  s_paused = true;
  logSDf("Server: rate limited (HTTP 429), background requests wait %lus", (unsigned long)seconds);
}

bool serverPauseActive() {
  if (!s_paused) return false;
  // Signed difference, so this survives the millis() rollover. The longest
  // wait, a day, is far inside what that can tell apart.
  if ((int32_t)(millis() - s_pause_until_ms) < 0) return true;
  s_paused = false;
  logSD("Server: rate limit wait is over");
  return false;
}

uint32_t serverRefusalCount() { return s_refusal_count; }

void serverRefusalClearSeen() { s_seen_code = 0; }
int  serverRefusalSeen()      { return s_seen_code; }

void serverRefusalForget() {
  s_paused = false;
  s_seen_code = 0;
  s_popup_pending = REFUSAL_NONE;
  s_placement_popup_used = false;
}

void serverRefusalNote(int code, bool user_action) {
  if (code >= 200 && code < 300) {
    s_placement_popup_used = false;
    return;
  }
  const ServerRefusal refusal = serverRefusalOf(code);
  if (refusal == REFUSAL_NONE) return;
  if (!user_action) {
    if (s_placement_popup_used) return;
    s_placement_popup_used = true;
  }
  s_popup_pending = refusal;
}

ServerRefusal serverRefusalPopupTake() {
  const ServerRefusal refusal = s_popup_pending;
  s_popup_pending = REFUSAL_NONE;
  return refusal;
}

int serverRefusalTitleId(ServerRefusal refusal) {
  switch (refusal) {
    case REFUSAL_ACCOUNT:  return STR_REFUSED_ACCOUNT;
    case REFUSAL_TOO_MANY: return STR_REFUSED_BUSY;
    default:
      // Only Spoolman can run without any access set up. The other two always
      // carry a key once they are configured, so there it was turned down.
      return backendMode() == BACKEND_SPOOLMAN && !spoolmanAuthActive()
               ? STR_SM_AUTH_MISSING : STR_SM_AUTH_REJECTED;
  }
}

int serverRefusalTextId(ServerRefusal refusal) {
  switch (refusal) {
    case REFUSAL_ACCOUNT:  return STR_REFUSED_ACCOUNT_TEXT;
    case REFUSAL_TOO_MANY: return STR_REFUSED_BUSY_TEXT;
    default:               return STR_REFUSED_ACCESS_TEXT;
  }
}
