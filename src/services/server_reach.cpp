#include "services/server_reach.h"

#include <Arduino.h>
#include <HTTPClient.h>   // the HTTPC_ERROR_ codes, nothing is requested here
#include <WiFi.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "hardware/sound.h"
#include "services/backend_api.h"
#include "services/server_refusal.h"

static bool s_popup_pending        = false;
// The placement lookup's one popup per outage has been used up.
static bool s_placement_popup_used = false;

// The backend went from answering to silent. Heard only when nobody is
// waiting at the display for that request, which shows its own popup, and
// only while the WiFi is up: a WiFi loss has played the tone already.
static void announceLost(bool user_action) {
  if (user_action || WiFi.status() != WL_CONNECTED) return;
  soundPlay(SND_LINK_LOST);
}

void serverReachLost() { announceLost(false); }

bool serverReachIsNetworkFailure(int code) {
  switch (code) {
    case HTTPC_ERROR_CONNECTION_REFUSED:
    case HTTPC_ERROR_SEND_PAYLOAD_FAILED:
    case HTTPC_ERROR_NOT_CONNECTED:
    case HTTPC_ERROR_CONNECTION_LOST:
    case HTTPC_ERROR_NO_HTTP_SERVER:
    case HTTPC_ERROR_READ_TIMEOUT:
    // A reverse proxy in front of the backend answers for it when the server
    // behind is gone: Caddy says 502 for a stopped FilaMan. Nothing reached
    // the backend either way, and "API error" sent the user nowhere.
    case HTTP_CODE_BAD_GATEWAY:
    case HTTP_CODE_SERVICE_UNAVAILABLE:
    case HTTP_CODE_GATEWAY_TIMEOUT:
      return true;
    default:
      return false;
  }
}

int serverReachNote(int code, bool user_action) {
  serverRefusalNote(code, user_action);
  if (!serverReachIsNetworkFailure(code)) return code;

  if (sm_reachable) {
    // Said once per outage, not per request: a flow that tries three times
    // would otherwise log three lines for one fact.
    logSDf("Server: unreachable (HTTP %d), marked down until it answers", code);
    sm_reachable = false;
    announceLost(user_action);
  }
  if (!user_action) {
    if (s_placement_popup_used) return code;
    s_placement_popup_used = true;
  }
  s_popup_pending = true;
  return code;
}

int amsReachNote(int code, bool user_action) {
  if (!backendAmsIsSeparateServer()) return serverReachNote(code, user_action);
  if (code != 200) logSDf("AMS source: HTTP %d, not counted against the backend", code);
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
