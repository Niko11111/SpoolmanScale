#pragma once

#include <Stream.h>
#include <stddef.h>
#include <stdint.h>

// ============================================================
//  PROGRESS FOR A LONG RESPONSE
//
//  Loading a whole inventory is one blocking call. Without a hook inside it
//  there is no moment at which the UI could say anything, and a wait that
//  says nothing reads as a hang.
//
//  This lives here rather than in one backend's API layer because all three
//  backends answer the same request and all three take just as long. The
//  hook is global and set only while something on screen wants to show
//  progress; while it is null nothing is wrapped and nothing costs anything.
//
//  The hook must be cheap and must not process input - it runs inside a
//  parse, on the loop task.
// ============================================================

typedef void (*HttpProgressFn)(size_t bytes_read);

// ============================================================
//  TIME THE LOOP SPENT NOT LOOPING
//
//  A whole inventory is one blocking call: appLoop() does not come round
//  again until it returns, which on a large FilaMan library is eight seconds
//  and more. Anything counting down in the meantime counts down unattended -
//  the AMS question opened with ten seconds on the clock, the fetch ate all
//  ten, and the log records the answer as "counted down to no" without the
//  user ever having been offered a button.
//
//  So the blocking time is measured and anything with a clock subtracts it.
//  Measured here because this file already sees every long transfer, and one
//  counter serves every caller.
// ============================================================

// Brackets a call that will hold up the loop. Nesting is counted, so an inner
// bracket cannot end the outer one's measurement early.
//
// Do not call these by hand - use HttpStall below. The first version of this
// did call them by hand, and the retry loop in querySpoolman() has a `return`
// in the middle: one trip through it left the bracket open, the depth stuck
// at 1, and httpStallTotalMs() growing at wall-clock rate for the rest of the
// boot. That made the AMS countdown subtract exactly as much as had elapsed,
// so it stood at ten seconds forever, and the location prompt that hangs off
// its timeout was never asked again.
void httpStallBegin();
void httpStallEnd();

// Total milliseconds spent inside those brackets since boot. A clock takes it
// when it opens and subtracts the difference from its elapsed time; while a
// fetch runs the clock therefore stands still instead of running out.
uint32_t httpStallTotalMs();

void           httpSetProgressHook(HttpProgressFn fn);

// The bracket as a scope, so no return path can leave it open. It also clears
// the progress hook on the way out: the two are set together at every call
// site and forgetting the hook leaves it painting into a label that the next
// request knows nothing about.
//
//     { HttpStall stall(searchProgress);
//       ... blocking fetch, returns allowed ... }
//
// Passing no hook brackets the time only.
class HttpStall {
public:
  explicit HttpStall(HttpProgressFn hook = nullptr) {
    httpStallBegin();
    if (hook) httpSetProgressHook(hook);
  }
  ~HttpStall() {
    httpSetProgressHook(nullptr);
    httpStallEnd();
  }
  HttpStall(const HttpStall&) = delete;
  HttpStall& operator=(const HttpStall&) = delete;
};

HttpProgressFn httpProgressHook();

// True while a hook is registered. Call sites use it to skip the wrapper
// entirely rather than paying for a virtual call per byte.
bool httpProgressActive();

// Passes a response through untouched and counts what went by.
//
// `already` is what makes a paged fetch add up: FilaMan answers a large
// inventory over several requests, and a counter that restarted on each of
// them would run to 90 kB three times instead of once to 270.
class HttpProgressStream : public Stream {
public:
  explicit HttpProgressStream(Stream& inner, size_t already = 0)
    : in_(inner), total_(already), last_(already) {}

  size_t total() const { return total_; }

  int    available() override { return in_.available(); }
  int    peek() override      { return in_.peek(); }
  void   flush() override     { in_.flush(); }
  size_t write(uint8_t b) override { return in_.write(b); }
  int    read() override {
    int c = in_.read();
    if (c >= 0) count(1);
    return c;
  }
  size_t readBytes(char* buf, size_t len) override {
    size_t r = in_.readBytes(buf, len);
    count(r);
    return r;
  }

private:
  void count(size_t n);

  Stream& in_;
  size_t  total_;
  size_t  last_;
};
