#pragma once

#include <Arduino.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <memory>

// ============================================================
//  ONE HTTP CLIENT FOR EVERY BACKEND ADDRESS
//
//  An HTTPClient that decides at begin() how to reach the address: an
//  "http://" address goes exactly the way it always went, HTTPClient's own
//  begin(url), and nothing else is created; an "https://" address gets a TLS
//  client of its own, checked against the certificate bundle the GitHub
//  check already uses - or not checked at all, where the user has said so
//  for a server with a self-signed certificate.
//
//  Declared where HTTPClient was, `BackendHttp http;`, and used the same way.
//  The TLS client sits in a base class listed before HTTPClient: base
//  classes are torn down in reverse order, so HTTPClient's destructor, which
//  may still call stop() on the client after end(), runs while that client
//  is alive.
// ============================================================

struct BackendTlsHolder {
  std::unique_ptr<WiFiClientSecure> tls;
};

class BackendHttp : private BackendTlsHolder, public HTTPClient {
 public:
  bool begin(const String& url);
  bool begin(const char* url) { return begin(String(url)); }
};

// True for an address that starts with "https://", any case.
bool backendUrlIsHttps(const char* url);

// Whether the backend's certificate is checked. Off only on request, for a
// server whose certificate no public authority vouches for. NVS "tls_insec".
bool backendTlsInsecure();
void backendSetTlsInsecure(bool on);
void backendTlsLoad();
