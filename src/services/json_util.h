#pragma once
// ============================================================
//  json_util.h - small questions to an ArduinoJson document
// ============================================================

#include <ArduinoJson.h>
#include <string.h>

// Whether an object carries the key at all, a null value included. This is
// what containsKey() answered; obj[key].isNull() also says "absent" for a key
// that is present and null, and where a server's version is told by which
// fields it sends, the key's presence is the whole question.
inline bool jsonHasKey(JsonObjectConst obj, const char* key) {
  for (JsonPairConst kv : obj)
    if (strcmp(kv.key().c_str(), key) == 0) return true;
  return false;
}
