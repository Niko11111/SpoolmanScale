#include "services/device_name.h"

#include <Arduino.h>
#include <WiFi.h>
#include <ctype.h>
#include <lwip/dns.h>
#include <lwip/ip_addr.h>
#include <string.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/mdns_service.h"
#include "services/prefs_store.h"
#include "services/wifi_manager.h"

// Default is the product name, spelled the way the docs spell it. Two scales
// out of the box therefore claim the same name; that is the price of a name
// worth typing, and the fix is to rename one of them in the browser.
#define DEVICE_LABEL_DEFAULT "spoolmanscale"

// Long enough that a name typed into the settings page is checked while the
// user is still looking at it, rare enough that a wrong name does not turn
// into a query every second for the life of the device.
#define DNS_RECHECK_MS 300000UL
// Longer than any lwIP resolver timeout, so this only ever catches an answer
// that was lost rather than one still on its way.
#define DNS_GIVE_UP_MS 30000UL

static char s_label[DEVICE_LABEL_MAX + 1]   = DEVICE_LABEL_DEFAULT;
static char s_domain[DEVICE_DOMAIN_MAX + 1] = "";
static char s_fqdn[DEVICE_FQDN_MAX + 1]     = DEVICE_LABEL_DEFAULT;
static bool s_mdns_on = true;

// Written by the lwIP callback, read by the loop task. Only these three cross
// the thread boundary, and each is a single word.
static volatile uint8_t  s_dns_state = DEV_DNS_UNKNOWN;
static volatile uint32_t s_dns_ip    = 0;
// A rename while a lookup is in flight would otherwise let the old answer
// land on the new name.
static volatile uint32_t s_dns_gen   = 0;

static unsigned long s_dns_last_ms  = 0;
static uint32_t      s_dns_last_ip  = 0;  // our own address at the last check
static unsigned long s_dns_start_ms = 0;

const char* deviceLabel()  { return s_label; }
const char* deviceDomain() { return s_domain; }
const char* deviceFqdn()   { return s_fqdn; }
bool deviceMdnsEnabled()   { return s_mdns_on; }
uint8_t   deviceDnsState() { return s_dns_state; }
IPAddress deviceDnsIP()    { return IPAddress(s_dns_ip); }

// RFC 1123 host label: letters, digits and hyphens, not starting or ending
// with one. Case is folded because DNS and mDNS both compare case
// insensitively and the responder lowercases the name anyway - accepting
// "Waage" and then answering to "waage" would just look like the setting had
// not been saved.
static bool normaliseLabel(const char* in, size_t in_len, char* out, size_t out_size) {
  if (!in || in_len == 0) return false;
  if (in_len + 1 > out_size) return false;
  for (size_t i = 0; i < in_len; i++) {
    // Whitespace is refused rather than stripped. Silently turning "my scale"
    // into "myscale" and reporting success would leave the user looking at a
    // name they did not choose.
    char c = (char)tolower((unsigned char)in[i]);
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    if (!ok) return false;
    out[i] = c;
  }
  out[in_len] = '\0';
  if (out[0] == '-' || out[in_len - 1] == '-') return false;
  return true;
}

// Every label of a suffix, checked one at a time. Rejects an empty label, so
// "scale..lan" and a leading dot cannot get through.
static bool normaliseDomain(const char* in, char* out, size_t out_size) {
  if (!in || !*in) { out[0] = '\0'; return true; }
  size_t n = strlen(in);
  if (n + 1 > out_size) return false;

  size_t start = 0;
  for (size_t i = 0; i <= n; i++) {
    if (i != n && in[i] != '.') continue;
    const size_t len = i - start;
    // A DNS label may be 63 characters even where our own is capped shorter:
    // this half is never shown in the status bar.
    if (len == 0 || len > 63) return false;
    char lbl[64];
    if (!normaliseLabel(in + start, len, lbl, sizeof(lbl))) return false;
    memcpy(out + start, lbl, len);
    if (i != n) out[i] = '.';
    start = i + 1;
  }
  out[n] = '\0';
  return true;
}

// The name the rest of the firmware prints. A configured domain wins: the
// user asked for it by hand. Otherwise the mDNS name, while it is actually
// answering - claiming ".local" when the responder failed to start would send
// someone to an address that does not exist.
static void rebuildFqdn() {
  if (s_domain[0]) {
    snprintf(s_fqdn, sizeof(s_fqdn), "%s.%s", s_label, s_domain);
  } else if (mdnsRunning()) {
    snprintf(s_fqdn, sizeof(s_fqdn), "%s.local", s_label);
  } else {
    strncpy(s_fqdn, s_label, sizeof(s_fqdn) - 1);
    s_fqdn[sizeof(s_fqdn) - 1] = '\0';
  }
}

void deviceNameLoad() {
  String stored = prefsGetString("mdns_host", DEVICE_LABEL_DEFAULT);
  char buf[DEVICE_LABEL_MAX + 1];
  // A stored name that no longer validates falls back rather than leaving the
  // device unreachable by name - the only way to get one in is through the
  // validator, so this covers a shortened limit rather than bad input.
  if (normaliseLabel(stored.c_str(), stored.length(), buf, sizeof(buf))) {
    strncpy(s_label, buf, sizeof(s_label) - 1);
    s_label[sizeof(s_label) - 1] = '\0';
  } else {
    strncpy(s_label, DEVICE_LABEL_DEFAULT, sizeof(s_label) - 1);
    s_label[sizeof(s_label) - 1] = '\0';
  }

  String dom = prefsGetString("net_domain", "");
  char dbuf[DEVICE_DOMAIN_MAX + 1];
  if (normaliseDomain(dom.c_str(), dbuf, sizeof(dbuf))) {
    strncpy(s_domain, dbuf, sizeof(s_domain) - 1);
    s_domain[sizeof(s_domain) - 1] = '\0';
  } else {
    s_domain[0] = '\0';
  }

  s_mdns_on = prefsGetBool("mdns_on", true);
  rebuildFqdn();
}

bool deviceSetName(const char* in) {
  if (!in) return false;

  // People paste what is in their address bar. Strip the scheme and the
  // trailing slash rather than rejecting it - same courtesy the backend
  // address field extends in backendCleanHost().
  String s(in);
  s.trim();
  s.toLowerCase();
  if (s.startsWith("http://"))  s = s.substring(7);
  if (s.startsWith("https://")) s = s.substring(8);
  int slash = s.indexOf('/');
  if (slash >= 0) s = s.substring(0, slash);
  while (s.endsWith(".")) s = s.substring(0, s.length() - 1);
  s.trim();
  if (s.length() == 0) return false;

  const int dot = s.indexOf('.');
  String label_in = (dot < 0) ? s : s.substring(0, dot);
  String dom_in   = (dot < 0) ? String("") : s.substring(dot + 1);

  // Someone typing "scale.local" means the mDNS name, not a DNS domain
  // called "local". Taking them literally would produce "scale.local.local".
  if (dom_in == "local") dom_in = "";

  char lbuf[DEVICE_LABEL_MAX + 1];
  if (!normaliseLabel(label_in.c_str(), label_in.length(), lbuf, sizeof(lbuf))) return false;
  char dbuf[DEVICE_DOMAIN_MAX + 1];
  if (!normaliseDomain(dom_in.c_str(), dbuf, sizeof(dbuf))) return false;

  const bool label_changed = (strcmp(lbuf, s_label) != 0);
  const bool dom_changed   = (strcmp(dbuf, s_domain) != 0);
  if (!label_changed && !dom_changed) return true;

  strncpy(s_label, lbuf, sizeof(s_label) - 1);
  s_label[sizeof(s_label) - 1] = '\0';
  strncpy(s_domain, dbuf, sizeof(s_domain) - 1);
  s_domain[sizeof(s_domain) - 1] = '\0';

  if (label_changed) prefsPutString("mdns_host", s_label);
  if (dom_changed)   prefsPutString("net_domain", s_domain);

  rebuildFqdn();
  logSDf("Device name: %s", s_fqdn);

  // The answer that stood belonged to the old name. Bump the generation so a
  // lookup still in flight cannot write into the new one, and leave the state
  // at UNKNOWN: the next tick is what starts the lookup, and setting CHECKING
  // here would only make the tick wait for an answer nobody asked for.
  s_dns_gen++;
  s_dns_state   = DEV_DNS_UNKNOWN;
  s_dns_ip      = 0;
  s_dns_last_ms = 0;
  s_dns_last_ip = 0;
  return true;
}

void deviceSetMdnsEnabled(bool on) {
  if (on == s_mdns_on) return;
  s_mdns_on = on;
  prefsPutBool("mdns_on", on);
  logSDf("Device name: mDNS %s", on ? "on" : "off");
  // mdnsSyncState() picks the switch up on its own pass; rebuildFqdn() runs
  // in the tick right after, once the responder has actually stopped.
}

// Runs in the tcpip task. Does the least that can be done there: compare the
// generation, store a word, let the loop task do the rest.
static void dnsFound(const char* name, const ip_addr_t* ipaddr, void* arg) {
  (void)name;
  if ((uint32_t)(uintptr_t)arg != s_dns_gen) return;
  if (!ipaddr) {
    s_dns_state = DEV_DNS_FAIL;
    return;
  }
  s_dns_ip    = ip4_addr_get_u32(ip_2_ip4(ipaddr));
  s_dns_state = DEV_DNS_UNKNOWN;   // resolved; the loop task judges whose it is
}

static void startLookup() {
  ip_addr_t addr;
  s_dns_state    = DEV_DNS_CHECKING;
  s_dns_start_ms = millis();
  // Called straight from the loop task, the way the Arduino core's own
  // hostByName() does. Unlike hostByName() it does not wait: a blocking
  // resolve would freeze LVGL for the length of the DNS timeout.
  const err_t e = dns_gethostbyname(s_fqdn, &addr, dnsFound,
                                    (void*)(uintptr_t)s_dns_gen);
  if (e == ERR_OK) {
    // Already in the cache, answered inline - the callback did not run.
    s_dns_ip    = ip4_addr_get_u32(ip_2_ip4(&addr));
    s_dns_state = DEV_DNS_UNKNOWN;
  } else if (e != ERR_INPROGRESS) {
    s_dns_state = DEV_DNS_FAIL;
  }
}

void deviceNameTick() {
  rebuildFqdn();

  const bool link_up = wifi_ok && (WiFi.status() == WL_CONNECTED);
  if (!link_up || !s_domain[0]) {
    // Nothing to check and nothing to claim. The settings page shows no
    // verdict at all rather than a stale one.
    if (s_dns_state != DEV_DNS_CHECKING) s_dns_state = DEV_DNS_UNKNOWN;
    s_dns_last_ms = 0;
    return;
  }

  const uint32_t own = (uint32_t)wifiManagerLocalIP();

  // A resolved address the callback left behind, judged here so the verdict
  // is formed in the loop task and the comparison sees a settled IP.
  if (s_dns_state == DEV_DNS_UNKNOWN && s_dns_ip != 0) {
    s_dns_state = (s_dns_ip == own) ? DEV_DNS_MATCH : DEV_DNS_OTHER;
  }

  if (s_dns_state == DEV_DNS_CHECKING) {
    // lwIP answers a lookup one way or the other, but a verdict that never
    // arrives would leave the settings page saying "checking" for good.
    if (millis() - s_dns_start_ms >= DNS_GIVE_UP_MS) s_dns_state = DEV_DNS_FAIL;
    return;
  }

  // An address change makes the old verdict meaningless in both directions:
  // the name may now point at someone else, or it may have caught up with us.
  const bool moved = (own != s_dns_last_ip);
  const bool due   = (s_dns_last_ms == 0) ||
                     (millis() - s_dns_last_ms >= DNS_RECHECK_MS);
  if (!moved && !due) return;

  s_dns_last_ms = millis();
  s_dns_last_ip = own;
  s_dns_ip      = 0;
  s_dns_gen++;
  startLookup();
}

void deviceBrowserUrl(char* out, size_t len) {
  if (!out || len == 0) return;
  // The fqdn is a bare label when neither a domain nor a running responder
  // backs it, and a bare label is not an address anyone can type.
  const bool named = s_domain[0] || mdnsRunning();
  if (named) {
    snprintf(out, len, "http://%s", s_fqdn);
  } else {
    snprintf(out, len, "http://%s", wifiManagerLocalIP().toString().c_str());
  }
}

void deviceMdnsName(char* out, size_t len) {
  if (!out || len == 0) return;
  snprintf(out, len, "%s.local", s_label);
}

void deviceAltAddress(char* out, size_t len) {
  if (!out || len == 0) return;
  out[0] = '\0';
  // Only worth a second line when the first one carries a name. Name large,
  // address small underneath - not either or, because some Android versions
  // still will not resolve a .local name and a DNS name only works where the
  // network actually serves it.
  if (!(s_domain[0] || mdnsRunning())) return;
  strncpy(out, wifiManagerLocalIP().toString().c_str(), len - 1);
  out[len - 1] = '\0';
}
