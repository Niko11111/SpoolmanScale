#include "services/spool_mine.h"

#include <Arduino.h>

#include "hardware/sd_logger.h"
#include "services/prefs_store.h"

static const char* const MINE_KEY = "spool_mine";

int spoolMineLoad(SpoolChoice out[SPOOL_MINE_MAX]) {
  return spoolMineDecode(prefsGetString(MINE_KEY).c_str(), out);
}

bool spoolMineSave(const SpoolChoice* list, int n) {
  if (n <= 0) return prefsRemoveKey(MINE_KEY) || !prefsHasKey(MINE_KEY);
  static char text[SPOOL_MINE_TEXT_MAX];
  if (!spoolMineEncode(list, n, text, sizeof(text))) {
    logSD("SpoolMine: the list does not fit its text, not saved");
    return false;
  }
  return prefsPutString(MINE_KEY, text);
}
