#pragma once

#include <Stream.h>
#include <stddef.h>

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

void           httpSetProgressHook(HttpProgressFn fn);
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
