#include "services/settings_registry.h"

#include <Arduino.h>
#include <cstring>

// bambuddy_api.h pulls in ArduinoJson, which must be parsed before lang.h
// defines T() - ArduinoJson uses T as a template parameter and the macro turns
// its headers into nonsense. Same ordering rule as everywhere else that needs
// both.
#include "services/bambuddy_api.h"

#include "services/ams_assign.h"
#include "services/backend.h"
#include "services/prefs_store.h"
#include "services/tag_field.h"
#include "services/user_options.h"

// Only for the LV_SYMBOL_* strings, which are plain UTF-8 literals. Two other
// services already include it for the same kind of reason.
#include <lvgl.h>

// Last on purpose, see the note above bambuddy_api.h.
#include "lang.h"

// ---------------------------------------------------------------------------
//  Hooks the table points at
// ---------------------------------------------------------------------------

// card_uids only means anything on a field with a list format, which is
// card_uids alone. With any other field selected there is no setting there to
// explain, so the row is absent rather than disabled.
static bool appliesCardUids() { return tagFieldIsList(); }

// The two fields the scale needs, named rather than described: the field names
// are what the user sees on the Spoolman side and are not translated. The tag
// field is whichever one is selected, so the row says which without being
// opened.
static const char* subExtraFields() {
  static char buf[48];
  snprintf(buf, sizeof(buf), "%s, " LAST_DRIED_FIELD, tagFieldKeyName());
  return buf;
}

// BamBuddy has no field for a drying date at all, so the scale needs somewhere
// to put one. The Spoolman route only exists while BamBuddy is actually
// proxying to a Spoolman server - past BamBuddy, into the same database.
static bool bbDriedOptOk(uint8_t value) {
  if (value != BB_DRIED_SPOOLMAN) return true;
  return (bbInventoryMode() == BB_INV_SPOOLMAN) && bbSpoolmanUrl()[0];
}

static const uint16_t OPT_BB_DRIED[] = {
  STR_BB_DRIED_OFF, STR_BB_DRIED_SPOOLMAN, STR_BB_DRIED_NOTE
};

static const uint16_t OPT_AMS_MODE[] = {
  STR_AMS_MODE_OFF, STR_AMS_MODE_ASK, STR_AMS_MODE_ALWAYS
};

// ---------------------------------------------------------------------------
//  The table
//
//  Order is the order both interfaces show. Fields in declaration order:
//    id / kind / scope / store
//    str_name / str_sub / str_info / icon
//    def / opt_count / opt_str
//    applies / sub_fn / on_change / opens / opt_ok / active_if_set
// ---------------------------------------------------------------------------
const SettingDesc SETTINGS[] = {

  // ---- Spoolman ----------------------------------------------------------

  // Extra fields. No help circle: it had none, and the subtitle already names
  // the two fields, which is the whole content the popup would have had.
  { "sp_fields", SET_SUBMENU, SC_SPOOLMAN, nullptr,
    STR_EXTRA_FIELDS_TITLE, 0, 0, LV_SYMBOL_LIST,
    0, 0, nullptr,
    nullptr, subExtraFields, nullptr, OPEN_SP_EXTRA_FIELDS, nullptr, false },

  // Linking more than one tag to a spool. Below the extra fields because it
  // depends on one of them being selected, and because it is the rarer setting.
  { "cu_write", SET_BOOL, SC_SPOOLMAN, &g_card_uids_write,
    STR_CU_WRITE, STR_CU_WRITE_SUB, STR_CU_WRITE_INFO, LV_SYMBOL_PLUS,
    0, 0, nullptr,
    appliesCardUids, nullptr, nullptr, OPEN_NONE, nullptr, false },

  // ---- FilaMan -----------------------------------------------------------

  // Link without asking. The subtitle carries the condition, because the
  // setting only ever acts when the spool was already on the scale.
  { "flm_autolink", SET_BOOL, SC_FILAMAN, &g_flm_autolink,
    STR_FLM_AUTOLINK, STR_FLM_AUTOLINK_SUB, STR_FLM_AUTOLINK_INFO, LV_SYMBOL_CHARGE,
    0, 0, nullptr,
    nullptr, nullptr, nullptr, OPEN_NONE, nullptr, false },

  // Weigh without a tag. Under auto link because both decide what happens when
  // a remote link arrives; this one covers the case where no tag exists.
  { "flm_tagless", SET_BOOL, SC_FILAMAN, &g_flm_tagless,
    STR_FLM_TAGLESS, STR_FLM_TAGLESS_SUB, STR_FLM_TAGLESS_INFO, LV_SYMBOL_DRIVE,
    1, 0, nullptr,
    nullptr, nullptr, nullptr, OPEN_NONE, nullptr, false },

  // Write the tag on a remote trigger. Third in the row because all three
  // answer the same question: what happens when a link arrives from the web.
  { "flm_write", SET_BOOL, SC_FILAMAN, &g_flm_remote_write,
    STR_FLM_REMOTE_WRITE, STR_FLM_REMOTE_WRITE_SUB, STR_FLM_REMOTE_WRITE_INFO,
    LV_SYMBOL_EDIT,
    1, 0, nullptr,
    nullptr, nullptr, nullptr, OPEN_NONE, nullptr, false },

  // Which fields the scale writes and what it leaves to the Bambu Lab plugin.
  // Its own screen because the two switches in it need room for what they cost.
  { "flm_fields", SET_SUBMENU, SC_FILAMAN, nullptr,
    STR_FLM_FIELDS, STR_FLM_FIELDS_SUB, STR_FLM_FIELDS_INFO, LV_SYMBOL_GPS,
    0, 0, nullptr,
    nullptr, nullptr, nullptr, OPEN_FLM_FIELDS, nullptr, false },

  // Auto AMS assignment. A mode, not a switch, and its screen also carries the
  // window length and the timeout behaviour - so the row leads there rather
  // than cycling the value. It still reads as active while a mode is set,
  // which is what active_if_set is for.
  //
  // The mode name goes in the subtitle, never in the arrow: a whole word there
  // runs through the help circle - "Nachfragen" is 85 px and the gap is 42.
  // Listing opt_str is what lets settingSubtitle() build "Auto assign - Ask"
  // without a function that reaches into the screens for the name.
  { "ams_mode", SET_SUBMENU, SC_FILAMAN, &g_ams_mode,
    STR_AMS_TITLE, STR_AMS_SUB, STR_AMS_INFO, LV_SYMBOL_LOOP,
    AMS_OFF, AMS_MODE_COUNT, OPT_AMS_MODE,
    nullptr, nullptr, nullptr, OPEN_AMS_ASSIGN, nullptr, true },

  // ---- BamBuddy ----------------------------------------------------------

  // Where the drying date goes. A real three way choice, so the web can render
  // it as one - the device keeps its own screen, which shows why the Spoolman
  // route is unavailable rather than just hiding it.
  { "bb_dried", SET_ENUM, SC_BAMBUDDY, &g_bb_dried_target,
    STR_BB_DRIED_TITLE, 0, STR_BB_DRIED_INFO, LV_SYMBOL_TINT,
    BB_DRIED_NOTE, BB_DRIED_COUNT, OPT_BB_DRIED,
    nullptr, nullptr, nullptr, OPEN_BB_DRIED, bbDriedOptOk, false },
};

const size_t SETTINGS_COUNT = sizeof(SETTINGS) / sizeof(SETTINGS[0]);

// ---------------------------------------------------------------------------
//  Access
// ---------------------------------------------------------------------------

uint8_t settingGet(const SettingDesc &s) {
  if (!s.store) return 0;
  if (s.kind == SET_BOOL) return *(bool *)s.store ? 1 : 0;
  return *(uint8_t *)s.store;
}

void settingSet(const SettingDesc &s, uint8_t v) {
  if (!s.store) return;

  if (s.kind == SET_BOOL) {
    const bool b = (v != 0);
    *(bool *)s.store = b;
    prefsPutBool(s.id, b);
  } else {
    // The value arrives off the network now, so the range is checked here
    // rather than trusted. A stored value past the end of opt_str would read
    // past the table on the next render.
    if (s.opt_count && v >= s.opt_count) return;
    *(uint8_t *)s.store = v;
    prefsPutUChar(s.id, v);
  }

  if (s.on_change) s.on_change();
}

const SettingDesc* settingById(const char *id) {
  if (!id || !id[0]) return nullptr;
  for (size_t i = 0; i < SETTINGS_COUNT; i++) {
    if (!strcmp(SETTINGS[i].id, id)) return &SETTINGS[i];
  }
  return nullptr;
}

bool settingVisible(const SettingDesc &s) {
  uint8_t here = backendIsFilaMan()  ? SC_FILAMAN
               : backendIsBamBuddy() ? SC_BAMBUDDY
                                     : SC_SPOOLMAN;
  if (!(s.scope & here)) return false;
  if (s.applies && !s.applies()) return false;
  return true;
}

void settingSubtitle(const SettingDesc &s, char *out, size_t out_size) {
  if (!out || out_size == 0) return;
  out[0] = '\0';

  if (s.sub_fn) {
    strncpy(out, s.sub_fn(), out_size - 1);
    out[out_size - 1] = '\0';
    return;
  }

  // The name of the value currently held, when the row has a list of them.
  const char *opt = nullptr;
  if (s.opt_str && s.opt_count) {
    const uint8_t v = settingGet(s);
    if (v < s.opt_count) opt = T((StringID)s.opt_str[v]);
  }

  const char *sub = s.str_sub ? T((StringID)s.str_sub) : nullptr;

  if (sub && opt)      snprintf(out, out_size, "%s - %s", sub, opt);
  else if (sub)        strncpy(out, sub, out_size - 1);
  else if (opt)        strncpy(out, opt, out_size - 1);
  out[out_size - 1] = '\0';
}

void settingsLoadAll() {
  for (size_t i = 0; i < SETTINGS_COUNT; i++) {
    const SettingDesc &s = SETTINGS[i];
    if (!s.store) continue;
    if (s.kind == SET_BOOL) {
      *(bool *)s.store = prefsGetBool(s.id, s.def != 0);
    } else {
      uint8_t v = prefsGetUChar(s.id, s.def);
      // A value past the end of the list would read past opt_str on the first
      // render. NVS survives a downgrade, so this is not hypothetical.
      if (s.opt_count && v >= s.opt_count) v = s.def;
      *(uint8_t *)s.store = v;
    }
  }
}
