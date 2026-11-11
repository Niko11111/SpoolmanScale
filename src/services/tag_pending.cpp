#include "tag_pending.h"

#include <Arduino.h>

#include "hardware/sd_logger.h"
#include "services/prefs_store.h"
#include "services/tag_write.h"

namespace {

// NVS keys are 15 characters at most.
const char* const PENDING_KEY = "tw_unfinished";

TagPendingMark s_mark{};          // what NVS holds, uid_len 0 for nothing
bool           s_loaded = false;

bool    s_armed = false;
bool    s_begun = false;          // the armed job has stored its marker
int     s_arm_spool = 0;
uint8_t s_arm_fmt = 0;

// A format a spool write can produce. A marker read back from flash is not
// trusted: an erase in it would wipe the tag on "finish writing".
bool writableFormat(uint8_t fmt) {
  return fmt == TAG_FMT_ACE || fmt == TAG_FMT_OPENSPOOL || fmt == TAG_FMT_FILAMAN ||
         fmt == TAG_FMT_CREALITY;
}

// Once per boot, on first use: every later question is answered from RAM.
void load() {
  if (s_loaded) return;
  s_loaded = true;
  const String v = prefsGetString(PENDING_KEY, "");
  if (v.length() == 0) return;
  if (!tagPendingDecode(v.c_str(), &s_mark) || !writableFormat(s_mark.fmt)) {
    logSDf("TagPending: stored marker '%s' unreadable, dropped", v.c_str());
    s_mark = TagPendingMark{};
    prefsRemoveKey(PENDING_KEY);
    return;
  }
  logSDf("TagPending: a write to spool %d was left unfinished", s_mark.spool_id);
}

void clearStored() {
  s_mark = TagPendingMark{};
  prefsRemoveKey(PENDING_KEY);
}

}  // namespace

void tagPendingArm(int spool_id, uint8_t fmt) {
  s_armed = spool_id > 0;
  s_begun = false;
  s_arm_spool = spool_id;
  s_arm_fmt = fmt;
}

void tagPendingDisarm() {
  s_armed = false;
  s_begun = false;
}

void tagPendingBegin(const uint8_t* uid, uint8_t uid_len) {
  if (!s_armed || s_begun || !uid || !tagPendingUidLenOk(uid_len)) return;
  s_begun = true;
  load();
  TagPendingMark m{};
  memcpy(m.uid, uid, uid_len);
  m.uid_len = uid_len;
  m.spool_id = s_arm_spool;
  m.fmt = s_arm_fmt;
  // The same tag for the same spool again, a retry: already stored.
  if (tagPendingMatches(s_mark, uid, uid_len) && s_mark.spool_id == m.spool_id &&
      s_mark.fmt == m.fmt) return;
  char text[TAG_PENDING_TEXT_MAX];
  if (!tagPendingEncode(m, text, sizeof(text))) return;
  // RAM first: a full NVS still lets this boot know the tag again.
  s_mark = m;
  prefsPutString(PENDING_KEY, text);
}

void tagPendingDone(const uint8_t* uid, uint8_t uid_len) {
  load();
  if (!tagPendingMatches(s_mark, uid, uid_len)) return;
  clearStored();
}

bool tagPendingFor(const uint8_t* uid, uint8_t uid_len, TagPendingMark* out) {
  load();
  if (!tagPendingMatches(s_mark, uid, uid_len)) return false;
  if (out) *out = s_mark;
  return true;
}

bool tagPendingResumes(const uint8_t* uid, uint8_t uid_len) {
  load();
  return s_armed && tagPendingMatches(s_mark, uid, uid_len) &&
         s_mark.spool_id == s_arm_spool && s_mark.fmt == s_arm_fmt;
}

void tagPendingDrop(const uint8_t* uid, uint8_t uid_len) {
  load();
  if (!tagPendingMatches(s_mark, uid, uid_len)) return;
  logSDf("TagPending: unfinished write to spool %d dropped by the owner", s_mark.spool_id);
  clearStored();
}

void tagPendingForget() {
  load();
  if (!s_mark.uid_len) return;
  logSDf("TagPending: unfinished write to spool %d forgotten, the server changed",
         s_mark.spool_id);
  clearStored();
}
