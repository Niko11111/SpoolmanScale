#pragma once

#include <Arduino.h>
#include <stdbool.h>
#include <stdint.h>

// The name this scale answers to, and the one place that decides how an
// address is written down.
//
// A device name is two things that used to be one. The label is a DNS label:
// it goes out as DHCP option 12, so the router lists the scale by name, and
// it is what the mDNS responder answers to as "<label>.local". The domain is
// the suffix the surrounding network knows the scale under - "home.arpa",
// "lan", "iot.example.com" - and it exists purely so the interface stops
// claiming that ".local" is the only way in.
//
// The scale cannot make a DNS name true; only the network can. What it can do
// is resolve the name and check whether it points back here, which is what
// deviceDnsState() reports and what the settings page shows underneath the
// field. That is also the honest answer to "read DHCP option 15": the option
// is not reachable from the Arduino framework (esp_netif does not carry id 15,
// lwIP neither requests nor stores it, and lwIP ships precompiled), and a
// suffix from a lease would not have proven a record exists behind it anyway.
//
// Every "http://" and every ".local" the firmware writes down is composed
// here. The responder in mdns_service.cpp is the one caller that names its
// own suffix, and it asks for it below.

// The status bar has about 94 pixels for the label and the point of the name
// is that someone can type it. A DNS label may be 63.
#define DEVICE_LABEL_MAX  20
#define DEVICE_DOMAIN_MAX 48
#define DEVICE_FQDN_MAX   (DEVICE_LABEL_MAX + 1 + DEVICE_DOMAIN_MAX)

// Result of resolving deviceFqdn() and comparing it against our own address.
enum {
  DEV_DNS_UNKNOWN = 0,  // no domain set, or offline - nothing to say
  DEV_DNS_CHECKING,
  DEV_DNS_MATCH,        // the name points at this scale
  DEV_DNS_OTHER,        // it resolves, but somewhere else - see deviceDnsIP()
  DEV_DNS_FAIL          // the network does not resolve it at all
};

// Reads label, domain and the mDNS switch. Called from loadPrefs() before
// WiFi comes up, because the label is handed to the DHCP client and that has
// to happen before WiFi.begin().
void deviceNameLoad();

const char* deviceLabel();   // "scale"        never empty
const char* deviceDomain();  // "home.arpa"    empty when none is set
const char* deviceFqdn();    // best name available: label.domain, else
                             // label.local while mDNS answers, else the label

// Takes a whole name - "scale" or "scale.home.arpa" - and splits it at the
// first dot. Strips a pasted scheme and trailing dots or slashes. Returns
// false and changes nothing when either half is not a legal DNS label.
bool deviceSetName(const char* in);

bool deviceMdnsEnabled();
void deviceSetMdnsEnabled(bool on);

uint8_t   deviceDnsState();
IPAddress deviceDnsIP();     // meaningful only for DEV_DNS_OTHER

// Idempotent, called once a second next to mdnsSyncState(). Drives the DNS
// check: right after a rename, on an address change, and every five minutes.
void deviceNameTick();

// The address someone types, "http://" included. Falls back to the bare IP
// when no name resolves, and never returns an empty string while WiFi is up.
void deviceBrowserUrl(char* out, size_t len);

// The second line under it: the bare IP. Empty when the first line already
// carries the IP itself, so the two never say the same thing twice.
void deviceAltAddress(char* out, size_t len);

// "<label>.local", whether or not the responder is up. The name the scale
// answers to without any DNS server involved, listed as an alternative
// wherever a DNS name has taken the main line.
void deviceMdnsName(char* out, size_t len);
