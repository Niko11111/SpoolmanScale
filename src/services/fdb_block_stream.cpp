#include "fdb_block_stream.h"

#include "../hardware/sd_logger.h"

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
  for (;;) {
    while (s.peek() == ' ' || s.peek() == '\n' || s.peek() == '\r' || s.peek() == '\t') s.read();
    if (s.peek() == ']') return true;
    const DeserializationError err = deserializeJson(doc, s, DeserializationOption::Filter(filter));
    if (err) { logSDf("Filament DB: element did not parse: %s", err.c_str()); return false; }
    fn(doc.as<JsonObjectConst>(), ctx);
    const int c = skipBlanks(s);
    if (c == ']') return true;
    if (c != ',') return false;
  }
}
