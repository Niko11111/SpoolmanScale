#include "services/improv_serial.h"

#include <Arduino.h>
#include <WiFi.h>
#include <cstring>

#include "app/app_state.h"
#include "app_config.h"
#include "hardware/sd_logger.h"
#include "services/app_settings.h"
#include "services/device_name.h"
#include "services/prefs_store.h"
#include "services/setup_portal.h"
#include "services/time_service.h"
#include "services/wifi_manager.h"
#include "web/web_access.h"

// Frame: "IMPROV", version, type, data length, data, checksum. The checksum is
// the sum of every byte before it, truncated to eight bits. Specification at
// https://www.improv-wifi.com/serial/
#define IMPROV_HEADER             "IMPROV"
#define IMPROV_HEADER_LEN         6
#define IMPROV_VERSION            0x01
#define IMPROV_PREFIX_LEN         9      // header, version, type, length
#define IMPROV_DATA_MAX           255    // the length is one byte
#define IMPROV_RX_MAX             (IMPROV_PREFIX_LEN + IMPROV_DATA_MAX + 1)
// A newline on either side of the frame, see sendFrame().
#define IMPROV_TX_MAX             (1 + IMPROV_RX_MAX + 1)

#define IMPROV_TYPE_STATE         0x01
#define IMPROV_TYPE_ERROR         0x02
#define IMPROV_TYPE_RPC           0x03
#define IMPROV_TYPE_RESULT        0x04

#define IMPROV_STATE_READY        0x02
#define IMPROV_STATE_PROVISIONING 0x03
#define IMPROV_STATE_PROVISIONED  0x04

#define IMPROV_ERR_INVALID_RPC    0x01
#define IMPROV_ERR_UNKNOWN_RPC    0x02
#define IMPROV_ERR_UNABLE_CONNECT 0x03

#define IMPROV_CMD_WIFI_SETTINGS  0x01
#define IMPROV_CMD_GET_STATE      0x02
#define IMPROV_CMD_GET_INFO       0x03
#define IMPROV_CMD_GET_NETWORKS   0x04

// A frame arrives in one piece. A pause this long in the middle of one means
// it was cut off, and whatever follows starts over.
#define IMPROV_BYTE_GAP_MS        500
// Bytes read per loop pass. Enough for several whole frames; the cap only
// keeps a stream of noise from holding the loop.
#define IMPROV_RX_BUDGET          512
// The browser waits 30 s for the answer, the setup screen gives up after 10.
#define IMPROV_CONNECT_TIMEOUT_MS 15000
// Networks offered to the browser.
#define IMPROV_SCAN_MAX           20

static uint8_t       s_rx[IMPROV_RX_MAX];
static size_t        s_rx_len     = 0;
static unsigned long s_rx_last_ms = 0;

static bool          s_connecting        = false;
static unsigned long s_connect_start_ms  = 0;
static bool          s_provisioned_event = false;
static char          s_ssid[sizeof(cfg_wifi_ssid)]     = "";
static char          s_pass[sizeof(cfg_wifi_password)] = "";

// One Serial.write() per frame, so the log lines the other tasks print cannot
// land inside it. The newline in front ends any half line a log left behind:
// the browser discards everything up to a newline before it looks for the
// header. The one behind is what ESPHome and the browser send as well.
static void sendFrame(uint8_t type, const uint8_t *data, size_t len) {
  if (len > IMPROV_DATA_MAX) return;
  uint8_t out[IMPROV_TX_MAX];
  size_t n = 0;
  out[n++] = '\n';
  memcpy(out + n, IMPROV_HEADER, IMPROV_HEADER_LEN);
  n += IMPROV_HEADER_LEN;
  out[n++] = IMPROV_VERSION;
  out[n++] = type;
  out[n++] = (uint8_t)len;
  if (len > 0) memcpy(out + n, data, len);
  n += len;
  uint8_t sum = 0;
  for (size_t i = 1; i < n; i++) sum += out[i];
  out[n++] = sum;
  out[n++] = '\n';
  Serial.write(out, n);
}

static void sendState(uint8_t state) { sendFrame(IMPROV_TYPE_STATE, &state, 1); }
static void sendError(uint8_t error) { sendFrame(IMPROV_TYPE_ERROR, &error, 1); }

// An RPC result: the command it answers, the length of what follows, then
// strings, each with a length byte in front.
struct ImprovResult {
  uint8_t buf[IMPROV_DATA_MAX];
  size_t  len;
};

static void resultBegin(ImprovResult &r, uint8_t command) {
  r.buf[0] = command;
  r.buf[1] = 0;
  r.len    = 2;
}

// A string that no longer fits is left out rather than cut. Nothing sent here
// comes near the limit: an SSID is 32 bytes at most.
static void resultAdd(ImprovResult &r, const char *s) {
  const size_t l = strlen(s);
  if (r.len + 1 + l > sizeof(r.buf)) return;
  r.buf[r.len++] = (uint8_t)l;
  memcpy(r.buf + r.len, s, l);
  r.len += l;
  r.buf[1] = (uint8_t)(r.len - 2);
}

static void resultSend(const ImprovResult &r) {
  sendFrame(IMPROV_TYPE_RESULT, r.buf, r.len);
}

// Where the browser can go next. Only while the web interface is switched on:
// a link to a page that refuses to load is worse than none. The address rather
// than a name, because the name may not resolve on the computer doing the
// flashing.
static void sendUrls(uint8_t command) {
  ImprovResult r;
  resultBegin(r, command);
  if (webMasterEnabled() && wifiManagerIsConnected()) {
    char url[32];
    snprintf(url, sizeof(url), "http://%s", wifiManagerLocalIP().toString().c_str());
    resultAdd(r, url);
  }
  resultSend(r);
}

static void sendCurrentState() {
  if (s_connecting) {
    sendState(IMPROV_STATE_PROVISIONING);
  } else if (wifiManagerIsConnected()) {
    sendState(IMPROV_STATE_PROVISIONED);
    sendUrls(IMPROV_CMD_GET_STATE);
  } else {
    sendState(IMPROV_STATE_READY);
  }
}

static void sendDeviceInfo() {
  ImprovResult r;
  resultBegin(r, IMPROV_CMD_GET_INFO);
  resultAdd(r, "SpoolmanScale");
  resultAdd(r, FW_VERSION);
  resultAdd(r, "ESP32-S3");
  resultAdd(r, deviceLabel());
  resultSend(r);
}

// Lets the browser offer a list instead of a text field. Strongest first,
// each SSID once, the way the setup screen shows them. Not while the setup
// portal is up: a scan needs station mode, which would end its access point.
static void sendNetworks() {
  if (!s_connecting && !setupPortalActive()) {
    // A scan while connected works as it is. After a failed begin() it returns
    // nothing unless the radio is reset first, see doWifiScan().
    if (!wifiManagerIsConnected()) wifiManagerPrepareScan();
    static WifiScanEntry nets[IMPROV_SCAN_MAX];
    const int n = wifiManagerScanSorted(nets, IMPROV_SCAN_MAX);
    if (n < 0) logSDf("Improv: WiFi scan failed (rc=%d)", n);
    for (int i = 0; i < n; i++) {
      char rssi[8];
      snprintf(rssi, sizeof(rssi), "%d", nets[i].rssi);
      ImprovResult r;
      resultBegin(r, IMPROV_CMD_GET_NETWORKS);
      resultAdd(r, nets[i].ssid);
      resultAdd(r, rssi);
      resultAdd(r, nets[i].open ? "NO" : "YES");
      resultSend(r);
    }
  }
  // An empty result ends the list.
  ImprovResult end;
  resultBegin(end, IMPROV_CMD_GET_NETWORKS);
  resultSend(end);
}

// Payload: SSID length, SSID, password length, password.
static void startProvisioning(const uint8_t *p, size_t len) {
  if (len < 2) { sendError(IMPROV_ERR_INVALID_RPC); return; }
  const size_t ssid_len = p[0];
  if (1 + ssid_len + 1 > len) { sendError(IMPROV_ERR_INVALID_RPC); return; }
  const size_t pass_len = p[1 + ssid_len];
  if (1 + ssid_len + 1 + pass_len > len ||
      ssid_len == 0 || ssid_len >= sizeof(s_ssid) || pass_len >= sizeof(s_pass)) {
    sendError(IMPROV_ERR_INVALID_RPC);
    return;
  }
  memcpy(s_ssid, p + 1, ssid_len);
  s_ssid[ssid_len] = '\0';
  memcpy(s_pass, p + 1 + ssid_len + 1, pass_len);
  s_pass[pass_len] = '\0';

  logSDf("Improv: WiFi settings received for %s", s_ssid);
  sendState(IMPROV_STATE_PROVISIONING);
  // The browser wins over a setup portal that is still open: station mode
  // would end its access point anyway, and the portal screen notices.
  setupPortalStop();
  // The same reset the setup screen does before it connects.
  wifiManagerPrepareScan();
  wifiManagerBegin(s_ssid, s_pass);
  s_connecting       = true;
  s_connect_start_ms = millis();
}

static void handleRpc(const uint8_t *data, size_t len) {
  if (len < 2 || (size_t)data[1] + 2 > len) {
    sendError(IMPROV_ERR_INVALID_RPC);
    return;
  }
  const uint8_t *payload     = data + 2;
  const size_t   payload_len = data[1];
  switch (data[0]) {
    case IMPROV_CMD_WIFI_SETTINGS: startProvisioning(payload, payload_len); break;
    case IMPROV_CMD_GET_STATE:     sendCurrentState();                      break;
    case IMPROV_CMD_GET_INFO:      sendDeviceInfo();                        break;
    case IMPROV_CMD_GET_NETWORKS:  sendNetworks();                          break;
    default:                       sendError(IMPROV_ERR_UNKNOWN_RPC);       break;
  }
}

// Everything that is not a frame - a monitor typing, stray bytes - falls out
// at the header check and costs nothing.
static void rxByte(uint8_t b) {
  const unsigned long now = millis();
  if (s_rx_len > 0 && now - s_rx_last_ms > IMPROV_BYTE_GAP_MS) s_rx_len = 0;
  s_rx_last_ms = now;

  if (s_rx_len < IMPROV_HEADER_LEN) {
    if (b == (uint8_t)IMPROV_HEADER[s_rx_len]) {
      s_rx[s_rx_len++] = b;
    } else {
      // Not the next header byte, but possibly the first one of a new header.
      s_rx_len = 0;
      if (b == (uint8_t)IMPROV_HEADER[0]) s_rx[s_rx_len++] = b;
    }
    return;
  }

  s_rx[s_rx_len++] = b;
  if (s_rx_len == IMPROV_HEADER_LEN + 1 && b != IMPROV_VERSION) {
    s_rx_len = 0;
    return;
  }
  if (s_rx_len < IMPROV_PREFIX_LEN) return;
  const size_t frame_len = IMPROV_PREFIX_LEN + s_rx[IMPROV_PREFIX_LEN - 1] + 1;
  if (s_rx_len < frame_len) return;

  s_rx_len = 0;
  uint8_t sum = 0;
  for (size_t i = 0; i < frame_len - 1; i++) sum += s_rx[i];
  if (sum != s_rx[frame_len - 1]) {
    sendError(IMPROV_ERR_INVALID_RPC);
    return;
  }
  if (s_rx[IMPROV_HEADER_LEN + 1] != IMPROV_TYPE_RPC) return;
  handleRpc(s_rx + IMPROV_PREFIX_LEN, frame_len - IMPROV_PREFIX_LEN - 1);
}

static void pollConnect() {
  if (wifiManagerIsConnected()) {
    s_connecting = false;
    saveWifiCredentials(s_ssid, s_pass);
    memset(s_pass, 0, sizeof(s_pass));
    wifi_ok = true;
    // Language, then a restart, then the rest of the setup: without this the
    // restart would find an SSID and boot straight past the setup.
    if (setup_active && !cfg_setup_resume) {
      cfg_setup_resume = true;
      prefsPutBool("setup_resume", true);
    }
    logSDf("Improv: connected to %s, IP %s",
           cfg_wifi_ssid, wifiManagerLocalIP().toString().c_str());
    sendState(IMPROV_STATE_PROVISIONED);
    sendUrls(IMPROV_CMD_WIFI_SETTINGS);
    s_provisioned_event = true;
    // After the answer, so the browser is not kept waiting on the clock.
    syncNTP();
    return;
  }
  if (millis() - s_connect_start_ms < IMPROV_CONNECT_TIMEOUT_MS) return;

  s_connecting = false;
  memset(s_pass, 0, sizeof(s_pass));
  logSDf("Improv: could not connect to %s", s_ssid);
  // Stops the attempt, so a slow access point cannot bring up a link whose
  // credentials were never stored. The stored network is untouched and the
  // reconnect watchdog takes it back up.
  wifiManagerPrepareScan();
  sendError(IMPROV_ERR_UNABLE_CONNECT);
  sendState(IMPROV_STATE_READY);
}

void improvSerialTick() {
  for (int budget = IMPROV_RX_BUDGET; budget > 0 && Serial.available() > 0; budget--) {
    const int b = Serial.read();
    if (b < 0) break;
    rxByte((uint8_t)b);
  }
  if (s_connecting) pollConnect();
}

bool improvSerialBusy() {
  return s_connecting;
}

bool improvSerialTakeProvisioned() {
  const bool event = s_provisioned_event;
  s_provisioned_event = false;
  return event;
}
