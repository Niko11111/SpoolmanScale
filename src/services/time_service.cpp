#include "time_service.h"

#include <time.h>

#include "services/prefs_store.h"

// A short list rather than every zone there is: these cover where the device
// actually gets used. The value is the POSIX string the C library wants,
// rules included, so daylight saving is handled rather than assumed.
const TimeZoneEntry TZ_LIST[] = {
  { "UTC",                 "UTC0",                          "UTC+0"       },
  { "Europe (CET/CEST)",   "CET-1CEST,M3.5.0,M10.5.0/3",    "UTC+1 / +2"  },
  { "Europe (UK)",         "GMT0BST,M3.5.0/1,M10.5.0",      "UTC+0 / +1"  },
  { "Europe (EET/EEST)",   "EET-2EEST,M3.5.0/3,M10.5.0/4",  "UTC+2 / +3"  },
  { "US Eastern",          "EST5EDT,M3.2.0,M11.1.0",        "UTC-5 / -4"  },
  { "US Central",          "CST6CDT,M3.2.0,M11.1.0",        "UTC-6 / -5"  },
  { "US Mountain",         "MST7MDT,M3.2.0,M11.1.0",        "UTC-7 / -6"  },
  { "US Pacific",          "PST8PDT,M3.2.0,M11.1.0",        "UTC-8 / -7"  },
  { "Australia Eastern",   "AEST-10AEDT,M10.1.0,M4.1.0/3",  "UTC+10 / +11"},
  { "Japan",               "JST-9",                         "UTC+9"       },
  { "India",               "IST-5:30",                      "UTC+5:30"    },
  { "Brazil (Sao Paulo)",  "<-03>3",                        "UTC-3"       },
};
const size_t TZ_COUNT = sizeof(TZ_LIST) / sizeof(TZ_LIST[0]);

#define TZ_INDEX_CET  1
#define TZ_INDEX_UTC  0

// Read straight from preferences rather than through lang.h. The language
// screen writes this key, and going through the header would drag the T()
// macro into a file that has no use for it.
#define PREF_KEY_LANG  "lang"
#define PREF_KEY_TZ    "tz"
#define LANG_VALUE_DE  0
// Same default loadPrefs() uses, so a device that has never been asked lands
// on the same language here as it does everywhere else.
#define LANG_DEFAULT   1

int timeZoneDefaultIndexForLang(uint8_t lang) {
  return (lang == LANG_VALUE_DE) ? TZ_INDEX_CET : TZ_INDEX_UTC;
}

String timeZoneGet() {
  const String stored = prefsGetString(PREF_KEY_TZ, "");
  if (stored.length()) return stored;
  const uint8_t lang = prefsGetUChar(PREF_KEY_LANG, LANG_DEFAULT);
  return String(TZ_LIST[timeZoneDefaultIndexForLang(lang)].tz);
}

void timeZoneApply() {
  const String tz = timeZoneGet();
  setenv("TZ", tz.c_str(), 1);
  tzset();
}

void timeZoneSet(const char *tz) {
  prefsPutString(PREF_KEY_TZ, tz ? tz : "");
  timeZoneApply();
}

int timeZoneIndex() {
  const String tz = timeZoneGet();
  for (size_t i = 0; i < TZ_COUNT; i++) {
    if (tz == TZ_LIST[i].tz) return (int)i;
  }
  return -1;
}

const char* timeZoneName() {
  const int i = timeZoneIndex();
  if (i >= 0) return TZ_LIST[i].name;
  // Not one of ours. Showing the raw string beats showing nothing, and it is
  // the only way a hand-set zone stays readable.
  static String raw;
  raw = timeZoneGet();
  return raw.c_str();
}

void syncNTP() {
  // configTime() takes an offset in seconds and a daylight offset, and builds
  // a TZ string with no switching rules from them - "UTC-1DST" for the
  // +1/+1 this used to pass. Without rules the C library falls back to its
  // own default, which is the US calendar, so a central European device
  // changed over three weeks early in spring and a week late in autumn.
  //
  // configTzTime() takes the POSIX string as it is, rules included.
  const String tz = timeZoneGet();
  configTzTime(tz.c_str(), "pool.ntp.org", "time.nist.gov");
  Serial.printf("NTP sync (TZ=%s)...", tz.c_str());
  struct tm ti;
  for (int i = 0; i < 20; i++) {
    delay(500);
    if (getLocalTime(&ti)) {
      Serial.printf("OK! %02d.%02d.%04d %02d:%02d\n", ti.tm_mday, ti.tm_mon + 1,
        ti.tm_year + 1900, ti.tm_hour, ti.tm_min);
      return;
    }
    Serial.print(".");
  }
  Serial.println("NTP ERROR");
}
