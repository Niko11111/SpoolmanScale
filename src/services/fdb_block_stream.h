#pragma once

#include <Arduino.h>
#include <string.h>

#include "filament_db.h"

// ============================================================
//  READING A FILAMENT DATABASE ANSWER IN BLOCKS
//
//  ArduinoJson asks for one byte at a time, and one socket read per byte
//  made SpoolmanDB's 3 MB a matter of minutes. The backends' database
//  loaders (spoolman_filament_db.cpp, filaman_filament_db.cpp) put this in
//  between the socket and the parser.
// ============================================================

#define FDB_READ_BUF  1024

// Hands the body on in blocks, never asking the socket for more than it
// already has: on a kept connection a read past the end of the answer would
// wait out the timeout. Counts what it read for the waiting card.
class FdbBlockStream : public Stream {
 public:
  explicit FdbBlockStream(Stream& in) : in_(in) {}
  int available() override { return (int)(len_ - pos_) + in_.available(); }
  int read() override { return fill() ? buf_[pos_++] : -1; }
  int peek() override { return fill() ? buf_[pos_] : -1; }
  size_t readBytes(char* out, size_t n) override {
    size_t got = 0;
    while (got < n && fill()) {
      size_t k = len_ - pos_;
      if (k > n - got) k = n - got;
      memcpy(out + got, buf_ + pos_, k);
      pos_ += k;
      got += k;
    }
    return got;
  }
  size_t write(uint8_t) override { return 0; }
  void   flush() override {}
 private:
  bool fill() {
    if (pos_ < len_) return true;
    const int ready = in_.available();
    const size_t want = ready > 0 ? (ready < FDB_READ_BUF ? (size_t)ready : FDB_READ_BUF) : 1;
    len_ = in_.readBytes((char*)buf_, want);
    pos_ = 0;
    *fdbBytesCounter() += len_;
    return len_ > 0;
  }
  Stream& in_;
  uint8_t buf_[FDB_READ_BUF];
  size_t  len_ = 0;
  size_t  pos_ = 0;
};
