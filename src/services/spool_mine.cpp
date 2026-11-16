#include "services/spool_mine.h"

#include <Arduino.h>
#include <stdlib.h>

#include "hardware/psram_new.h"
#include "hardware/sd_logger.h"
#include "services/prefs_store.h"

static const char* const MINE_KEY = "spool_mine";

int spoolMineLoad(SpoolChoice out[SPOOL_MINE_MAX]) {
  return spoolMineDecode(prefsGetString(MINE_KEY).c_str(), out);
}

bool spoolMineSave(const SpoolChoice* list, int n) {
  if (n <= 0) return prefsRemoveKey(MINE_KEY) || !prefsHasKey(MINE_KEY);
  // 0.8 kB for one save from the web page: too much for its task's stack,
  // and no reason to hold it in internal RAM between saves.
  char* text = static_cast<char*>(psramMalloc(SPOOL_MINE_TEXT_MAX));
  if (!text) {
    logSD("SpoolMine: no memory for the list's text, not saved");
    return false;
  }
  bool saved = false;
  if (spoolMineEncode(list, n, text, SPOOL_MINE_TEXT_MAX)) {
    saved = prefsPutString(MINE_KEY, text);
  } else {
    logSD("SpoolMine: the list does not fit its text, not saved");
  }
  free(text);
  return saved;
}
