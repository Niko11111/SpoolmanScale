#include "backend_http.h"

#include <Network.h>
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
// The connect timeout of the ahead-of-time open: the 5 s HTTPClient gives
// every backend request, so a server that is gone holds the kept connection
// - and every request waiting for it - no longer than a request of its own
// would. The TLS client's own default is 30 s. The handshake is bounded
// by BackendTls itself, as for every request.
#define WARM_CONNECT_MS      HTTPCLIENT_DEFAULT_TCP_TIMEOUT
// What is left of an answer nobody read is read and dropped before the kept
// connection serves the next request: up to this much, waiting this long for
// it. A write's answer is the spool written or an error; a Spoolman spool
// runs to 550 - 1050 bytes in the simulator's fixtures, so 1 kB would have
// closed the connection after some of them. A rest that is larger or slower
// closes it instead.
#define DRAIN_MAX_BYTES      2048
#define DRAIN_WAIT_MS        100
#define DRAIN_POLL_MS        2

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

// Looked up with the very call the client makes in its connect(), so a name
// that resolves there - mDNS ".local" included, lwIP asks for it itself -
// resolves here as well, and the second lookup comes out of lwIP's cache.
// Network.hostByName() answers 1 on success and an lwIP error code otherwise,
// and core 3's connect() tests it with "!", so a failure went on to 0.0.0.0.
static bool hostResolves(const String& host) {
  // An IPv6 literal in brackets is the client's to parse; an IPv4 literal
  // comes back from hostByName() without a lookup.
  if (host.length() == 0 || host[0] == '[') return true;
  IPAddress ip;
  const int r = Network.hostByName(host.c_str(), ip);
  if (r == 1) return true;
  logSDf("Backend: %s does not resolve (DNS error %d), request not sent", host.c_str(), r);
  return false;
}

// The host of an http or https address: no scheme, user, port or path.
static bool urlResolves(const String& url) {
  int p = url.indexOf("://");
  p = (p < 0) ? 0 : p + 3;
  int end = p;
  while (end < (int)url.length() && url[end] != '/' && url[end] != '?' && url[end] != '#') end++;
  String host = url.substring(p, end);
  const int at = host.lastIndexOf('@');
  if (at >= 0) host = host.substring(at + 1);
  if (host.length() && host[0] != '[') {
    const int colon = host.indexOf(':');
    if (colon >= 0) host = host.substring(0, colon);
  }
  return hostResolves(host);
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
    // The last chunk; its trailer ends with an empty line. Read as far as it
    // is already there, so a kept connection starts clean; finish() waits
    // for the rest.
    last_ = true;
    for (int guard = 0; guard < 4 && !clean_ && in_->available() > 0; guard++) {
      trailerByte(nextByte());
    }
    done_ = true;
    return false;
  }
  return true;
}

void ChunkedStream::trailerByte(int c) {
  if (c < 0 || c == '\r') return;
  if (c == '\n') {
    if (line_ == 0) clean_ = true;   // the empty line: the answer is over
    line_ = 0;
    return;
  }
  if (line_ < 255) line_++;
}

bool ChunkedStream::finish(size_t max_bytes, uint32_t wait_ms) {
  if (!in_) return false;
  // Every byte read here waits no longer than the whole drain may take.
  const unsigned long keep = in_->getTimeout();
  in_->setTimeout(wait_ms);
  const unsigned long t0 = millis();
  for (size_t n = 0; !clean_ && n < max_bytes && millis() - t0 < wait_ms; n++) {
    if (!last_) {
      if (done_) break;              // ended on data that made no sense
      read();
    } else {
      const int c = nextByte();
      if (c < 0) break;
      trailerByte(c);
    }
  }
  in_->setTimeout(keep);
  return clean_;
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
  streamed_ = true;
  if (_transferEncoding == HTTPC_TE_CHUNKED) {
    chunked_.reset(&Http::getStream());
    chunked_.setTimeout(_tcpTimeout);
    return chunked_;
  }
  if (pooled_) {
    counted_.reset(&Http::getStream());
    counted_.setTimeout(_tcpTimeout);
    return counted_;
  }
  return Http::getStream();
}

String BackendHttp::getString() {
  String s = Http::getString();
  // HTTPClient read the body itself - all of it when the text is as long as
  // the answer said. After the last chunk it leaves the trailer behind.
  if (pooled_ && _size >= 0 && s.length() == (size_t)_size) {
    if (_transferEncoding == HTTPC_TE_CHUNKED) {
      chunked_.resetAtTrailer(&Http::getStream());
      streamed_ = true;
    } else {
      counted_.count = _size;
    }
  }
  return s;
}

void BackendHttp::newAnswer() {
  settled_  = false;
  streamed_ = false;
  counted_.reset(nullptr);
  counted_.count = 0;
  chunked_.reset(nullptr);
}

// Whether the answer on the kept connection has been read to its end, reading
// what is left of it where that is small and arrives quickly.
bool BackendHttp::answerRead() {
  // No answer, or one that has no body by definition.
  if (_returnCode <= 0) return true;
  if (_returnCode < 200 || _returnCode == 204 || _returnCode == 304) return true;
  if (_transferEncoding == HTTPC_TE_CHUNKED) {
    if (!streamed_) chunked_.reset(&Http::getStream());
    return chunked_.finish(DRAIN_MAX_BYTES, DRAIN_WAIT_MS);
  }
  if (_size < 0) return false;   // the body ends where the server closes
  long left = (long)_size - counted_.count;
  if (left <= 0) return true;
  if (left > DRAIN_MAX_BYTES) return false;
  uint8_t buf[64];
  const unsigned long t0 = millis();
  while (left > 0) {
    const int r = s_pool->read(buf, left < (long)sizeof(buf) ? (size_t)left : sizeof(buf));
    if (r < 0) return false;   // closed
    if (r == 0) {
      if (millis() - t0 >= DRAIN_WAIT_MS) return false;
      delay(DRAIN_POLL_MS);
      continue;
    }
    left -= r;
  }
  return true;
}

// Holding s_mux, before HTTPClient forgets the answer's length: whether the
// kept connection can serve the next request, or is closed.
void BackendHttp::settle() {
  if (!pooled_ || settled_) return;
  settled_ = true;
  // Begun again on another host, the object fell back to a client of its
  // own: this answer is not on the kept connection.
  if (!s_pool || _client != s_pool || !s_pool->connected()) return;
  if (_returnCode > 0 && (!_canReuse || !answerRead())) {
    s_pool->stop();
    return;
  }
  // Anything beyond the end of the answer belongs to no request.
  if (s_pool->available() > 0) s_pool->stop();
}

void BackendHttp::end() {
  settle();
  Http::end();
}

bool BackendHttp::begin(const String& url) {
  // Begun again on the same object: the answer before is done with.
  settle();
  newAnswer();
  const bool first = !begun_;
  begun_ = true;

  if (!backendUrlIsHttps(url.c_str())) {
    if (first && !urlResolves(url)) return false;
    return Http::begin(url);
  }

  String host;
  uint16_t port = 0;
  // Begun again on the same object - a list read page by page - while it
  // still holds the kept connection: taking the mutex a second time would
  // fail and open a second connection beside the first.
  if (pooled_ && splitHost(url.c_str(), host, port) && poolFor(host, port)) {
    _host = host;
    return Http::begin(*s_pool, url);
  }
  if (!no_pool_ && s_keep_min && splitHost(url.c_str(), host, port) && ensureMux()) {
    const TickType_t wait = s_warming ? pdMS_TO_TICKS(WARM_WAIT_MS) : 0;
    if (xSemaphoreTake(s_mux, wait) == pdTRUE) {
      if (poolFor(host, port)) {
        // An open connection needs no lookup; a new one does.
        if (!s_pool->connected() && !hostResolves(host)) {
          xSemaphoreGive(s_mux);
          return false;
        }
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

  if (first && !urlResolves(url)) return false;
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
  // one: read to its end here, or closed so the next request opens afresh.
  settle();
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
    if (splitHost(backendBaseUrl(), host, port) && poolFor(host, port) && !s_pool->connected() &&
        hostResolves(host)) {
      const unsigned long t0 = millis();
      const int ok = s_pool->connect(host.c_str(), port, WARM_CONNECT_MS);
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
