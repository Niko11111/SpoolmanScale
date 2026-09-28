#include "backend_http.h"

#include <strings.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/github_release.h"
#include "services/prefs_store.h"

// Opening the connection ahead of time is a task of its own: the handshake
// would otherwise stand the loop still for 0.6 s. The stack is the update
// check's, for the same TLS handshake; it comes from the heap only while the
// task runs, and only when the heap can spare it.
#define WARM_STACK_BYTES     14336
#define WARM_PRIORITY        1
#define WARM_CORE            0
#define WARM_MIN_HEAP        60000
// A request that finds the connection being opened waits this long for it:
// longer than a handshake, shorter than doing a second one beside it.
#define WARM_WAIT_MS         3000
// What counts as a spool arriving on the pad, and as the pad being cleared.
#define WARM_WEIGHT_G        50.0f
#define WARM_CLEAR_G         20.0f
#define KEEP_MINUTES_DEFAULT 5

static bool s_insecure = false;
static uint8_t s_keep_min = KEEP_MINUTES_DEFAULT;

// The kept connection. Only touched while holding s_mux.
static BackendTls*       s_pool          = nullptr;
static bool              s_pool_insecure = false;   // the trust it was set up with
static String            s_pool_host;
static uint16_t          s_pool_port     = 0;
static SemaphoreHandle_t s_mux           = nullptr;
static volatile bool     s_warming       = false;
static volatile unsigned long s_last_used = 0;

bool backendUrlIsHttps(const char* url) {
  return url && strncasecmp(url, "https://", 8) == 0;
}

bool backendTlsInsecure() { return s_insecure; }

void backendSetTlsInsecure(bool on) {
  s_insecure = on;
  prefsPutBool("tls_insec", on);
  backendConnClose();   // set up with the old trust
}

uint8_t backendKeepMinutes() { return s_keep_min; }

void backendSetKeepMinutes(uint8_t minutes) {
  if (minutes != 1 && minutes != 5 && minutes != 30) minutes = KEEP_MINUTES_DEFAULT;
  s_keep_min = minutes;
  prefsPutUChar("tls_keep", minutes);
}

void backendTlsLoad() {
  s_insecure = prefsGetBool("tls_insec", false);
  const uint8_t k = prefsGetUChar("tls_keep", KEEP_MINUTES_DEFAULT);
  s_keep_min = (k == 1 || k == 5 || k == 30) ? k : KEEP_MINUTES_DEFAULT;
}

// "https://host:8443/path" -> host, port; 443 without a port.
static bool splitHost(const char* url, String& host, uint16_t& port) {
  if (!backendUrlIsHttps(url)) return false;
  const char* p = url + 8;
  const char* end = p;
  while (*end && *end != '/' && *end != ':') end++;
  if (end == p) return false;
  host = String(p).substring(0, end - p);
  port = 443;
  if (*end == ':') port = (uint16_t)atoi(end + 1);
  return port != 0;
}

static bool ensureMux() {
  if (!s_mux) s_mux = xSemaphoreCreateMutex();
  return s_mux != nullptr;
}

// Holding s_mux: the kept client, set up for this host and the current trust.
static bool poolFor(const String& host, uint16_t port) {
  if (s_pool && s_pool_insecure != s_insecure) {
    s_pool->stop();
    delete s_pool;
    s_pool = nullptr;
  }
  if (!s_pool) {
    s_pool = new BackendTls();
    if (!s_pool) return false;
    s_pool_insecure = s_insecure;
    if (s_insecure) s_pool->setInsecure();
    else            githubTrust(*s_pool);
  }
  if (host != s_pool_host || port != s_pool_port) {
    s_pool->stop();   // a socket open to another server must not be reused
    s_pool_host = host;
    s_pool_port = port;
  }
  return true;
}

// ---- chunked transfer ------------------------------------------

int ChunkedStream::nextByte() {
  char c;
  return (in_ && in_->readBytes(&c, 1) == 1) ? (uint8_t)c : -1;
}

bool ChunkedStream::nextChunk() {
  // The CRLF that ends the chunk before, then "<hex size>[;ext]\r\n".
  long size = 0;
  int digits = 0;
  bool ext = false;
  for (int guard = 0; guard < 80; guard++) {
    const int c = nextByte();
    if (c < 0) return false;
    if (c == '\n') {
      if (digits == 0) continue;            // the CRLF after the previous chunk
      break;
    }
    if (c == '\r' || ext) continue;
    if (c == ';') { ext = true; continue; }
    int v = -1;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    if (v < 0) return false;
    size = size * 16 + v;
    digits++;
  }
  if (digits == 0) return false;
  left_ = size;
  if (size == 0) {
    // The last chunk; its trailer ends with an empty line. Read if it is
    // already there, so a kept connection starts clean.
    for (int guard = 0; guard < 4 && in_->available() > 0; guard++) nextByte();
    done_ = true;
    return false;
  }
  return true;
}

int ChunkedStream::read() {
  if (peeked_ >= 0) { const int c = peeked_; peeked_ = -1; return c; }
  if (done_) return -1;
  if (left_ <= 0 && !nextChunk()) { done_ = true; return -1; }
  const int c = nextByte();
  if (c < 0) { done_ = true; return -1; }
  left_--;
  return c;
}

int ChunkedStream::peek() {
  if (peeked_ < 0) peeked_ = read();
  return peeked_;
}

int ChunkedStream::available() {
  if (peeked_ >= 0) return 1;
  if (done_ || !in_) return 0;
  const int raw = in_->available();
  if (left_ > 0) return raw < left_ ? raw : (int)left_;
  return raw > 0 ? 1 : 0;   // a size line is waiting; read() will tell
}

Stream& BackendHttp::getStream() {
  if (_transferEncoding == HTTPC_TE_CHUNKED) {
    chunked_.reset(&Http::getStream());
    chunked_.setTimeout(_tcpTimeout);
    return chunked_;
  }
  return Http::getStream();
}

bool BackendHttp::begin(const String& url) {
  if (!backendUrlIsHttps(url.c_str())) return Http::begin(url);

  String host;
  uint16_t port = 0;
  // Begun again on the same object - a list read page by page - while it
  // still holds the kept connection: taking the mutex a second time would
  // fail and open a second connection beside the first.
  if (pooled_ && splitHost(url.c_str(), host, port) && poolFor(host, port)) {
    _host = host;
    return Http::begin(*s_pool, url);
  }
  if (s_keep_min && splitHost(url.c_str(), host, port) && ensureMux()) {
    const TickType_t wait = s_warming ? pdMS_TO_TICKS(WARM_WAIT_MS) : 0;
    if (xSemaphoreTake(s_mux, wait) == pdTRUE) {
      if (poolFor(host, port)) {
        pooled_ = true;
        setReuse(true);
        // HTTPClient drops an open connection when the host it last used
        // differs from the new one - and a fresh object has used none, so
        // every request closed the kept connection (beta.15, reuse 600 ms
        // instead of 16). It is the same server: say so before begin().
        _host = host;
        return Http::begin(*s_pool, url);
      }
      xSemaphoreGive(s_mux);
    }
  }

  // One per object, kept for its lifetime: a caller that pages through a list
  // begins again on the same object, and HTTPClient may still point at it.
  if (!tls) {
    tls.reset(new BackendTls());
    if (!tls) return false;
    if (s_insecure) tls->setInsecure();
    else            githubTrust(*tls);
  }
  return Http::begin(*tls, url);
}

BackendHttp::~BackendHttp() {
  if (!pooled_) return;
  // An answer not read to its end would be read as the start of the next
  // one; closed instead, so the next request opens afresh.
  if (s_pool && s_pool->available() > 0) s_pool->stop();
  // HTTPClient's destructor stops whatever _client points at. The kept
  // connection is not this object's to stop.
  _client = nullptr;
  s_last_used = millis();
  xSemaphoreGive(s_mux);
}

void backendConnClose() {
  if (!s_mux) return;
  if (xSemaphoreTake(s_mux, pdMS_TO_TICKS(WARM_WAIT_MS)) != pdTRUE) return;
  if (s_pool) s_pool->stop();
  s_pool_host = "";
  s_pool_port = 0;
  xSemaphoreGive(s_mux);
}

static void warmTask(void*) {
  if (xSemaphoreTake(s_mux, pdMS_TO_TICKS(10000)) == pdTRUE) {
    String host;
    uint16_t port = 0;
    if (splitHost(backendBaseUrl(), host, port) && poolFor(host, port) && !s_pool->connected()) {
      const unsigned long t0 = millis();
      const int ok = s_pool->connect(host.c_str(), port);
      logSDf("Backend https: connection opened ahead of time, %s, %lu ms",
             ok ? "ok" : "failed", (unsigned long)(millis() - t0));
    }
    s_last_used = millis();
    xSemaphoreGive(s_mux);
  }
  s_warming = false;
  vTaskDelete(NULL);
}

static void warmStart() {
  if (s_warming || !ensureMux()) return;
  if (ESP.getFreeHeap() < WARM_MIN_HEAP) return;
  s_warming = true;
  if (xTaskCreatePinnedToCore(warmTask, "tlswarm", WARM_STACK_BYTES, nullptr,
                              WARM_PRIORITY, nullptr, WARM_CORE) != pdPASS) {
    s_warming = false;
  }
}

void backendConnTick() {
  // Idle: closed once the chosen time has passed since the last request.
  if (s_pool && s_mux && !s_warming &&
      millis() - s_last_used > (unsigned long)s_keep_min * 60000UL &&
      xSemaphoreTake(s_mux, 0) == pdTRUE) {
    if (s_pool->connected()) {
      s_pool->stop();
      logSDf("Backend https: connection closed after %u min idle", (unsigned)s_keep_min);
    }
    xSemaphoreGive(s_mux);
  }

  if (!s_keep_min || !wifi_ok || !backendUrlIsHttps(backendBaseUrl())) return;

  // A spool arriving on the pad, or a tag being read: a request is coming.
  static bool loaded = false;
  static char last_uid[sizeof(g_tag.uid_str)] = "";
  bool coming = false;
  if (scale_weight_g > WARM_WEIGHT_G) {
    if (!loaded) { loaded = true; coming = true; }
  } else if (scale_weight_g < WARM_CLEAR_G) {
    loaded = false;
  }
  if (g_tag.uid_str[0] && strcmp(last_uid, g_tag.uid_str) != 0) {
    snprintf(last_uid, sizeof(last_uid), "%s", g_tag.uid_str);
    coming = true;
  } else if (!g_tag.uid_str[0]) {
    last_uid[0] = '\0';
  }
  if (coming) warmStart();
}
