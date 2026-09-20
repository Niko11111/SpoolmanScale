#include "services/server_reach.h"

#include <Arduino.h>
#include <HTTPClient.h>   // the HTTPC_ERROR_ codes, nothing is requested here

#include "app/app_state.h"
#include "hardware/sd_logger.h"

static bool s_popup_pending        = false;
// The placement lookup's one popup per outage has been used up.
static bool s_placement_popup_used = false;

bool serverReachIsNetworkFailure(int code) {
  switch (code) {
    case HTTPC_ERROR_CONNECTION_REFUSED:
    case HTTPC_ERROR_SEND_PAYLOAD_FAILED:
    case HTTPC_ERROR_NOT_CONNECTED:
    case HTTPC_ERROR_CONNECTION_LOST:
    case HTTPC_ERROR_NO_HTTP_SERVER:
    case HTTPC_ERROR_READ_TIMEOUT:
      return true;
    default:
      return false;
  }
}

int serverReachNote(int code, bool user_action) {
  if (!serverReachIsNetworkFailure(code)) return code;

  if (sm_reachable) {
    // Said once per outage, not per request: a flow that tries three times
    // would otherwise log three lines for one fact.
    logSDf("Server: unreachable (HTTP %d), marked down until it answers", code);
    sm_reachable = false;
  }
  if (!user_action) {
    if (s_placement_popup_used) return code;
    s_placement_popup_used = true;
  }
  s_popup_pending = true;
  return code;
}

void serverReachRestored() {
  s_placement_popup_used = false;
}

bool serverReachPopupTake() {
  if (!s_popup_pending) return false;
  s_popup_pending = false;
  return true;
}
