#include "backend_http.h"

#include <strings.h>

#include "hardware/sd_logger.h"
#include "services/github_release.h"
#include "services/prefs_store.h"

static bool s_insecure = false;

bool backendUrlIsHttps(const char* url) {
  return url && strncasecmp(url, "https://", 8) == 0;
}

bool backendTlsInsecure() { return s_insecure; }

void backendSetTlsInsecure(bool on) {
  s_insecure = on;
  prefsPutBool("tls_insec", on);
}

void backendTlsLoad() {
  s_insecure = prefsGetBool("tls_insec", false);
}

bool BackendHttp::begin(const String& url) {
  if (!backendUrlIsHttps(url.c_str())) return HTTPClient::begin(url);
  // One per object, kept for its lifetime: a caller that pages through a list
  // begins again on the same object, and HTTPClient may still point at it.
  if (!tls) {
    tls.reset(new WiFiClientSecure());
    if (!tls) return false;
    if (s_insecure) tls->setInsecure();
    else            githubTrust(*tls);
  }
  return HTTPClient::begin(*tls, url);
}
