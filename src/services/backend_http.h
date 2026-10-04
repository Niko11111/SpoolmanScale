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

// NetworkClientSecure answers read() with -1 whenever no decrypted byte is
// waiting yet, and NetworkClient::readBytes() takes -1 for an error and stops.
// So anything read with readBytes over TLS - which is how ArduinoJson reads a
// stream - ended at the first pause in the data: "IncompleteInput" from the
// Bambu catalog and from a spool list behind Caddy (28.09.2026). While the
// connection stands, nothing yet is 0 here, and readBytes waits for it.
//
// The single byte read() has to be answered here as well: the base class
// builds it on read(buf, 1) and hands back its uninitialised byte, 0xFF,
// when that returns 0 - an endless stream of 0xFF that hung the header
// parser on the device (beta.13).
//
// _connected, not connected(): connected() itself calls read(&dummy, 0), so
// asking it from here recursed until the stack ran out (beta.14).
//
// The base is named through an alias: scripts/check_conventions.py counts any
// function whose body names the client class as one that talks HTTP, and
// every read() in the firmware - the load cell's among them - would inherit
// that from these two.
//
// The handshake is bounded: the client's own default is 120 s, so a server
// that took the connection and then said nothing held a request - and the
// screen waiting on it - for two minutes. One takes about 0.6 s here.
#define BACKEND_TLS_HANDSHAKE_S  10

class BackendTls : public WiFiClientSecure {
  using Base = WiFiClientSecure;
 public:
  BackendTls() { setHandshakeTimeout(BACKEND_TLS_HANDSHAKE_S); }
  int read(uint8_t* buf, size_t size) override {
    const int r = Base::read(buf, size);
    return (r < 0 && _connected) ? 0 : r;
  }
  int read() override {
    uint8_t b;
    return Base::read(&b, 1) == 1 ? b : -1;
  }
};

struct BackendTlsHolder {
  std::unique_ptr<BackendTls> tls;
};

// The body of an answer sent "Transfer-Encoding: chunked", with the chunk
// sizes taken out. A reverse proxy answers that way where the backend itself
// did not - Caddy in front of Spoolman does, over HTTP/1.1 - and every parser
// here reads the raw stream, so the first size line broke the JSON.
class ChunkedStream : public Stream {
 public:
  void reset(Stream* in) {
    in_ = in; left_ = 0; done_ = false; last_ = false; clean_ = false; line_ = 0; peeked_ = -1;
  }
  // HTTPClient's getString() has read every chunk itself; only the trailer
  // after the last one is left on the connection.
  void resetAtTrailer(Stream* in) { reset(in); done_ = true; last_ = true; }
  // Reads what is left of the answer and drops it, at most max_bytes and for
  // about wait_ms. True once the empty line that ends the answer is read: the
  // connection then starts clean for the next request.
  bool finish(size_t max_bytes, uint32_t wait_ms);
  int    available() override;
  int    read() override;
  int    peek() override;
  size_t write(uint8_t) override { return 0; }
  void   flush() override {}
  // Nothing more will come: the last chunk was read, or the stream broke off.
  // For a reader that cannot wait for the socket to close - a kept-alive one
  // stays open after the body.
  bool   done() const { return done_ && peeked_ < 0; }
 private:
  int  nextByte();      // one byte of the raw stream, waiting up to the timeout
  bool nextChunk();     // reads a size line; false at the end or on garbage
  void trailerByte(int c);
  Stream* in_ = nullptr;
  long left_ = 0;       // bytes still to come in the current chunk
  bool done_ = false;   // no more body: the last chunk, or data that made no sense
  bool last_ = false;   // the last chunk, size 0, has been read
  bool clean_ = false;  // ... and the empty line after its trailer as well
  uint8_t line_ = 0;    // characters on the current trailer line
  int  peeked_ = -1;
};

// The body of an answer with a Content-Length, counted on its way through, so
// that it is known at the end whether all of it was read. Used only on the
// kept connection; every other one is closed after its answer anyway.
class CountedStream : public Stream {
 public:
  void reset(Stream* in) { in_ = in; }
  long count = 0;       // body bytes read so far
  using Stream::readBytes;
  int available() override { return in_ ? in_->available() : 0; }
  int read() override {
    const int c = in_ ? in_->read() : -1;
    if (c >= 0) count++;
    return c;
  }
  int peek() override { return in_ ? in_->peek() : -1; }
  // Handed on whole, so the raw client's own waiting - see BackendTls - and
  // its speed stay what they were.
  size_t readBytes(char* buf, size_t len) override {
    const size_t n = in_ ? in_->readBytes(buf, len) : 0;
    count += (long)n;
    return n;
  }
  size_t write(uint8_t) override { return 0; }
  void   flush() override {}
 private:
  Stream* in_ = nullptr;
};

// An https request may borrow the one kept-alive connection instead (see
// KEEP-ALIVE below): it then holds that connection until it is destroyed,
// and hands it back open rather than letting HTTPClient close it.
//
// A borrowed connection is handed back only when the answer on it was read to
// its end: a Content-Length's worth, or the chunked body up to the empty line
// after its last chunk. A request that did not read it all - a write whose
// answer nobody looks at - leaves a small rest, which is read and dropped
// here within a short wait; a larger one, or one that does not arrive, closes
// the connection. A byte of the old answer read as the start of the next one
// would turn a good answer into garbage.
//
// Before the first connect the address is looked up once more: core 3's
// clients take a name that does not resolve for 0.0.0.0 and spend the whole
// connect timeout on it, where core 2 gave up at once. begin() then returns
// false and the request fails straight away.
class BackendHttp : private BackendTlsHolder, public HTTPClient {
  using Http = HTTPClient;   // see BackendTls: keeps begin() and getStream() off the HTTP list
 public:
  ~BackendHttp();
  bool begin(const String& url);
  bool begin(const char* url) { return begin(String(url)); }
  // The body, chunking undone where the server chunked it. Hides
  // HTTPClient's own, which hands out the raw socket either way.
  Stream& getStream();
  Stream* getStreamPtr() { return &getStream(); }
  // Hide HTTPClient's own: a borrowed connection has to know how much of the
  // answer was read before HTTPClient forgets its length.
  String getString();
  void end();
  // Never borrow the kept connection: for a diagnostic that measures what a
  // connection of its own costs, and must not move the kept one elsewhere.
  void noPool() { no_pool_ = true; }
 private:
  void newAnswer();
  void settle();
  bool answerRead();
  bool pooled_   = false;
  bool no_pool_  = false;
  bool begun_    = false;   // looked the address up already
  bool settled_  = false;   // the kept connection's fate for this answer is decided
  bool streamed_ = false;   // the caller read the body through getStream()
  ChunkedStream chunked_;
  CountedStream counted_;
};

// True for an address that starts with "https://", any case.
bool backendUrlIsHttps(const char* url);

// Whether the backend's certificate is checked. Off only on request, for a
// server whose certificate no public authority vouches for. NVS "tls_insec".
bool backendTlsInsecure();
void backendSetTlsInsecure(bool on);
void backendTlsLoad();

// ============================================================
//  KEEP-ALIVE
//
//  A TLS handshake costs the ESP32 about 0.6 s of arithmetic, measured on
//  the device against spooly.eu, spoolio.net, GitHub and a self-signed server
//  in the LAN alike; a request on an open connection about 30 ms. So one
//  https connection to the backend is kept open between requests, for as long
//  as the user has chosen (1, 5 or 30 min, NVS "tls_keep", 5 by default), and
//  opened ahead of time when a spool is put on the pad or a tag is read -
//  the NFC read of a Bambu tag alone takes three seconds, time enough for the
//  handshake to be done before the lookup asks.
//
//  One request uses it at a time. Another one in the meantime - the loop and
//  the backend worker can both ask - opens a connection of its own, as every
//  request did before, except while the connection is being opened: then it
//  waits for it, which is quicker than a second handshake. A connection the
//  server has closed is opened again by the next request; the server's own
//  idle limit (nginx 75 s, Caddy 5 min) may therefore be shorter than the
//  one chosen here, which costs a handshake and nothing else.
// ============================================================

// Minutes the connection stays open after the last request: 1, 5 or 30.
uint8_t backendKeepMinutes();
void    backendSetKeepMinutes(uint8_t minutes);

// From appLoop(): closes an idle connection, and opens one ahead of time when
// a spool arrives on the pad or a tag is read.
void backendConnTick();

// Closes the kept connection, e.g. when the address or the certificate
// setting changes.
void backendConnClose();
