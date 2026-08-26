#pragma once

#include <stddef.h>
#include <stdint.h>

// Every backend option, declared once, rendered by both interfaces.
//
// A single on/off row used to be ~27 lines of LVGL for six pieces of actual
// information, and the nine-line block that turns the row's arrow into ON/OFF
// stood word for word in six files. None of it existed in the web interface at
// all, so adding an option meant building it twice - and the two would drift,
// exactly the way the two tab tables did before WebPage replaced them.
//
// The shape follows TagFieldSpec in services/tag_field.h, which had already
// solved the hard part: StringIDs are kept as plain numbers so this header
// stays clear of lang.h. Its T() macro collides with ArduinoJson's template
// parameter, and this header is included from both the LVGL screens and the
// web pages, which use ArduinoJson.
//
// The scope is deliberately narrow: the flat backend options, not every
// setting the device has. The existing web cards are less regular than they
// look - one answers with a whole card state and polls itself, another with
// the result of a real health check, a third is an action with a network
// round trip. Pressing those into a table would need a "custom body" escape
// hatch on the first day and would have gained nothing.

// Where a row leads when it does not change its value in place.
enum SettingScreen : uint8_t {
  OPEN_NONE = 0,
  OPEN_SP_EXTRA_FIELDS,
  OPEN_FLM_FIELDS,
  OPEN_AMS_ASSIGN,
  OPEN_BB_DRIED,
};

enum SettingKind : uint8_t {
  SET_BOOL,      // on or off
  SET_ENUM,      // one of opt_count values, labelled by opt_str
  SET_SUBMENU,   // no value of its own; opens a screen that has its own logic
};

// Which backend an option belongs to. A bitmask because an option may well
// apply to more than one, even though none does today.
enum SettingScope : uint8_t {
  SC_SPOOLMAN = 1,
  SC_FILAMAN  = 2,
  SC_BAMBUDDY = 4,
  SC_ALL      = 7,
};

struct SettingDesc {
  // The NVS key, and the identity the web uses. Deliberately the same string:
  // these keys are in the NVS of every device in the field, so renaming one
  // would silently reset that setting to its default. A separate web id would
  // be a second name for the same thing and could disagree with it.
  const char*  id;
  SettingKind  kind;
  uint8_t      scope;

  // SET_BOOL reads and writes a bool, SET_ENUM a uint8_t. SET_SUBMENU may
  // carry one too - the AMS row has a mode behind it even though the mode is
  // edited on its own screen - or null when it has no value at all.
  void*        store;

  uint16_t     str_name;
  uint16_t     str_sub;    // 0 = none, or when sub_fn is set
  uint16_t     str_info;   // 0 = no help circle on the row
  const char*  icon;       // LVGL symbol; the web ignores it

  uint8_t      def;        // what loadPrefs() falls back to
  uint8_t      opt_count;  // SET_ENUM
  const uint16_t* opt_str; // SET_ENUM: opt_count StringIDs, in value order

  // Null means "always". Otherwise the row is left out of both interfaces -
  // card_uids only means something while a list field is selected, and with
  // any other field there is no setting there to explain.
  bool (*applies)();

  // A subtitle that has to be built at run time and cannot come out of the
  // string table at all - the extra fields row names the field it points at.
  // Null means the subtitle is composed from str_sub and opt_str, see below.
  const char* (*sub_fn)();

  // Run after the value changed and was written. Choosing a tag field that is
  // not a list has to clear the card_uids switch, or a stale "on" from before
  // the change leaks into the next write.
  void (*on_change)();

  // Which screen the row leads to, if any. A symbol rather than a function
  // pointer on purpose: this header belongs to the service layer, and a
  // pointer into the screens would turn it around. The UI switches on it, the
  // web only needs to know that a target exists.
  SettingScreen opens;

  // Whether one value of a SET_ENUM can be picked at all right now. Null means
  // all of them can. BamBuddy's drying date can only go to Spoolman while
  // BamBuddy is actually proxying to one.
  bool (*opt_ok)(uint8_t value);

  // Rows without a value of their own are drawn plain. The AMS row is the
  // exception: it is not a switch, but it should read as active while a mode
  // is set. SET_BOOL ignores this - its own value decides.
  bool active_if_set;
};

// The subtitle a row shows, already resolved. In order: sub_fn when set, then
// str_sub joined with the current option name when the row has both, then
// whichever of the two it has, then empty.
//
// That join is what reproduces the two composed subtitles the screens used to
// build by hand - "Auto assign - Ask" and the drying target on its own - out
// of the table alone, so neither needs a function that reaches into the UI for
// the name of a value the table already lists.
void settingSubtitle(const SettingDesc &s, char *out, size_t out_size);

extern const SettingDesc SETTINGS[];
extern const size_t      SETTINGS_COUNT;

// The current value: 0/1 for SET_BOOL, the raw value otherwise. A descriptor
// without a store answers 0.
uint8_t settingGet(const SettingDesc &s);

// The only thing that writes an option. Variable, NVS and on_change in one, so
// a web route cannot forget what a device callback does. Out of range values
// for a SET_ENUM are refused rather than stored - the value comes off the
// network now.
void settingSet(const SettingDesc &s, uint8_t v);

// Null when nothing carries that id.
const SettingDesc* settingById(const char *id);

// Whether the option belongs on screen right now: this backend, and applies().
bool settingVisible(const SettingDesc &s);

// Reads every option from NVS into its variable. Replaces the hand written
// run of prefsGetX(key, default) that loadPrefs() used to carry, where the
// key, the type and the default were three things that had to agree by hand -
// and once did not, which is the bug page_config.cpp:360 still describes.
void settingsLoadAll();
