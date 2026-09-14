#include "services/setup_portal.h"

#include <Arduino.h>
#include <DNSServer.h>
#include <esp_system.h>
#include <cstring>

#include "hardware/sd_logger.h"
#include "services/wifi_manager.h"

// A network of its own. The access point default, 192.168.4.1, is a common
// home subnet as well, which makes an address on the screen ambiguous.
#define SETUP_PORTAL_IP_A        10
#define SETUP_PORTAL_IP_B        42
#define SETUP_PORTAL_IP_C        0
#define SETUP_PORTAL_IP_D        1
#define SETUP_PORTAL_NETMASK_C   0     // 255.255.255.0

#define SETUP_PORTAL_DNS_PORT    53
#define SETUP_PORTAL_SSID_PREFIX "SpoolmanScale-"
#define SETUP_PORTAL_PASS_LEN    8
// Time for the answer page to reach the phone before its network goes away.
#define SETUP_PORTAL_HANDOFF_MS  1500

// Lower case and digits without the ones that read alike on a small screen
// (l, 1, i, o, 0), so the password can be typed off the display as well.
static const char PASS_CHARS[] = "abcdefghjkmnpqrstuvwxyz23456789";

static DNSServer     s_dns;
static bool          s_active = false;
static char          s_ap_ssid[sizeof(SETUP_PORTAL_SSID_PREFIX) + 4] = "";
static char          s_ap_pass[SETUP_PORTAL_PASS_LEN + 1]             = "";
static WifiScanEntry s_nets[SETUP_PORTAL_SCAN_MAX];
static int           s_net_count = 0;

static bool          s_submitted     = false;
static unsigned long s_submit_ms     = 0;
static bool          s_handoff_ready = false;
static char          s_sub_ssid[sizeof(s_nets[0].ssid)] = "";
static char          s_sub_pass[65]                     = "";

IPAddress setupPortalIP() {
  return IPAddress(SETUP_PORTAL_IP_A, SETUP_PORTAL_IP_B, SETUP_PORTAL_IP_C, SETUP_PORTAL_IP_D);
}

void setupPortalUrl(char* out, size_t len) {
  snprintf(out, len, "http://%u.%u.%u.%u/",
           SETUP_PORTAL_IP_A, SETUP_PORTAL_IP_B, SETUP_PORTAL_IP_C, SETUP_PORTAL_IP_D);
}

bool setupPortalStart() {
  if (s_active) return true;

  // The list for the form. The radio is reset first, the same way the setup
  // screen does it: after a failed begin() a scan returns nothing.
  wifiManagerPrepareScan();
  const int n = wifiManagerScanSorted(s_nets, SETUP_PORTAL_SCAN_MAX);
  if (n < 0) logSDf("Portal: WiFi scan failed (rc=%d)", n);
  s_net_count = n > 0 ? n : 0;

  // The last two bytes of the device id, so two scales side by side can be
  // told apart in a phone's network list.
  const uint64_t mac = ESP.getEfuseMac();
  snprintf(s_ap_ssid, sizeof(s_ap_ssid), SETUP_PORTAL_SSID_PREFIX "%02X%02X",
           (unsigned)((mac >> 32) & 0xFF), (unsigned)((mac >> 40) & 0xFF));
  // A new password every time, so one that was seen once is no key later.
  for (int i = 0; i < SETUP_PORTAL_PASS_LEN; i++) {
    s_ap_pass[i] = PASS_CHARS[esp_random() % (sizeof(PASS_CHARS) - 1)];
  }
  s_ap_pass[SETUP_PORTAL_PASS_LEN] = '\0';

  const IPAddress ip = setupPortalIP();
  if (!wifiManagerStartAp(s_ap_ssid, s_ap_pass, ip,
                          IPAddress(255, 255, 255, SETUP_PORTAL_NETMASK_C))) {
    logSD("Portal: access point did not start");
    wifiManagerStopAp();
    return false;
  }

  // Every name resolves to the scale. That is what makes a phone's probe for
  // captive.apple.com or connectivitycheck.gstatic.com land on the form.
  s_dns.setErrorReplyCode(DNSReplyCode::NoError);
  if (!s_dns.start(SETUP_PORTAL_DNS_PORT, "*", ip)) {
    // Still usable: the second QR code carries the address.
    logSD("Portal: DNS did not start, the page has to be opened by address");
  }

  s_submitted     = false;
  s_handoff_ready = false;
  s_active        = true;
  logSDf("Portal: access point %s up at %s, %d networks listed",
         s_ap_ssid, ip.toString().c_str(), s_net_count);
  return true;
}

void setupPortalStop() {
  if (!s_active) return;
  s_dns.stop();
  wifiManagerStopAp();
  s_active    = false;
  s_submitted = false;
  logSD("Portal: access point down");
}

bool setupPortalActive() {
  return s_active;
}

void setupPortalTick() {
  if (!s_active) return;
  s_dns.processNextRequest();
  if (s_submitted && millis() - s_submit_ms >= SETUP_PORTAL_HANDOFF_MS) {
    setupPortalStop();
    s_handoff_ready = true;
  }
}

const char* setupPortalSsid()     { return s_ap_ssid; }
const char* setupPortalPassword() { return s_ap_pass; }
int         setupPortalNetworkCount() { return s_net_count; }

const char* setupPortalNetwork(int index) {
  return (index >= 0 && index < s_net_count) ? s_nets[index].ssid : "";
}

void setupPortalSubmit(const char* ssid, const char* password) {
  snprintf(s_sub_ssid, sizeof(s_sub_ssid), "%s", ssid);
  snprintf(s_sub_pass, sizeof(s_sub_pass), "%s", password);
  s_submitted = true;
  s_submit_ms = millis();
  logSDf("Portal: WiFi settings received for %s", s_sub_ssid);
}

bool setupPortalSubmitted() {
  return s_submitted;
}

bool setupPortalTakeCredentials(char* ssid, size_t ssid_len, char* password, size_t password_len) {
  if (!s_handoff_ready) return false;
  s_handoff_ready = false;
  snprintf(ssid, ssid_len, "%s", s_sub_ssid);
  snprintf(password, password_len, "%s", s_sub_pass);
  memset(s_sub_pass, 0, sizeof(s_sub_pass));
  return true;
}
