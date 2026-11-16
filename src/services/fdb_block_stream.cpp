#include "fdb_block_stream.h"

#include <Arduino.h>

#include "../hardware/sd_logger.h"

// How long the reader parses before it lets the idle task of its core run.
// The database task sits above idle on core 0; a server on the same network
// sends SpoolmanDB's 3.6 MB faster than it parses, so the read never waits
// and IDLE0 starved past the 5 s task watchdog (beta.62, 16.11.2026). One
// tick every 100 ms costs about 1 % of the load time.
#define FDB_YIELD_EVERY_MS  100

static int skipBlanks(Stream& s) {
  int c;
  do { c = s.read(); } while (c == ' ' || c == '\n' || c == '\r' || c == '\t');
  return c;
}

bool fdbEachElement(Stream& raw, uint32_t timeout_ms, JsonDocument& filter,
                    FdbElementFn fn, void* ctx) {
  FdbBlockStream s(raw);
  s.setTimeout(timeout_ms);
  if (skipBlanks(s) != '[') return false;
  JsonDocument doc;
  uint32_t yielded_ms = millis();
  for (;;) {
    while (s.peek() == ' ' || s.peek() == '\n' || s.peek() == '\r' || s.peek() == '\t') s.read();
    if (s.peek() == ']') return true;
    const DeserializationError err = deserializeJson(doc, s, DeserializationOption::Filter(filter));
    if (err) { logSDf("Filament DB: element did not parse: %s", err.c_str()); return false; }
    fn(doc.as<JsonObjectConst>(), ctx);
    if (millis() - yielded_ms >= FDB_YIELD_EVERY_MS) {
      vTaskDelay(1);
      yielded_ms = millis();
    }
    const int c = skipBlanks(s);
    if (c == ']') return true;
    if (c != ',') return false;
  }
}
