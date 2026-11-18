#pragma once

#include <stdint.h>
#include <string.h>

#include "services/spool_color.h"

// ============================================================
//  AMS SLOT MODEL
//
//  One shape for the AMS of a Bambu printer, filled from either
//  backend and read by the view. Deliberately the smallest header
//  in the project: no HTTP, no ArduinoJson, no LVGL, no lang.h.
//  That is what lets the view live next to the UI and the parsers
//  next to their own clients without either knowing the other.
//
//  The two backends describe the same hardware differently:
//
//    BamBuddy   ams[] of units, each with tray[], plus vt_tray[]
//               for the external holder. Humidity and temperature
//               sit on the unit.
//    FilaMan    a flat slots[], grouped by a slot_index of the
//               form "<ams_id>-<tray_id>", with the unit data in
//               a separate ams_units[].
//
//  Both collapse into the grouped form below, because that is how
//  Bambu addresses a slot everywhere else: as the pair
//  (ams_id, tray_id). A flat 1..16 numbering breaks the moment an
//  AMS HT with a single bay is attached.
// ============================================================

// AMS and AMS HT units a printer may carry, external holder not counted.
// Bambu's largest set is on the H2D, H2S and H2C: four AMS 2 Pro and eight
// AMS HT, twelve units and 24 bays. The P2S takes four and four, the X1 and
// P1 four in all. The view shares the places between AMS and AMS HT, so
// twelve covers every set Bambu sells.
#define AMS_MAX_UNITS        12

// An AMS HT holds one bay, a regular AMS four, the H3C's AMS 3H nine. Never
// assume four, always read tray_count.
#define AMS_MAX_TRAYS        9

// Bays in the external holder: one on most printers, two on a dual nozzle
// H2D (Ext-L and Ext-R). They are bays of a single unit, not units of their
// own - FilaMan reports them exactly that way, as one entry of kind
// "external" carrying slots 254 and 255. An H3C has one per hotend, nine.
#define AMS_MAX_EXT          9

// The external holder is that one extra unit.
#define AMS_UNITS_TOTAL      (AMS_MAX_UNITS + 1)

// "PLA Matte" and "AMS HT 1" both fit, with room to spare.
#define AMS_NAME_MAX         20
// "Charcoal", "Bambu Green", "Cyan" - the manufacturer's own colour name.
#define AMS_COLOR_NAME_MAX   16
#define AMS_PRINTER_NAME_MAX 24
// "printing", "idle", "paused". Short on purpose: this is a state word, not
// the name of the job.
#define AMS_STATE_MAX        16

// How many printers the picker offers. Beyond this the list is cut with a
// log line rather than silently.
#define AMS_MAX_PRINTERS     8

// Sentinels for values the printer did not report. Bambu sends -1 for an
// unknown fill level itself, so that one is passed through unchanged.
#define AMS_REMAIN_NA        (-1)
#define AMS_HUMIDITY_NA      (-1)
#define AMS_TEMP_NA          INT16_MIN
#define AMS_JOB_NA           (-1)
// Slot labels are "A1".."D4", "HT1", "Ext1" - four characters and a
// terminator is enough for every one FilaMan generates.
#define AMS_LABEL_MAX        6
// The printer's own word for the material in a bay. "PLA-AERO" is the longest
// a Bambu printer sends, and a longer one may be cut: only the part before
// the dash is ever compared.
#define AMS_TYPE_MAX         10

// The external holder. Its bay numbering is not stable across servers:
// FilaMan 1.3.1 reported ams_id 255 with bays 254 (Ext-L) and 255 (Ext-R),
// Bambu's own numbering, while 1.3.3 collapses those onto 0 and 1 so a dual
// nozzle machine shows two bays instead of four ghosts. Real bay ids are
// therefore always stored as they arrive and never assumed - this default is
// only for a backend that names the holder without numbering its bay.
#define AMS_EXT_AMS_ID       255
#define AMS_EXT_TRAY_ID      0

// Which hardware a unit is. BamBuddy names it by the module the printer
// reports ("n3f" for an AMS 2 Pro); FilaMan's display API names it in words
// ("ams_2_pro"), from a version that carries the field on. An older FilaMan
// says nothing finer than ams, ams_ht or external, so UNKNOWN is a normal
// value there, not an error, and nothing may treat it as "the first
// generation".
enum AmsModel : uint8_t {
  AMS_MODEL_UNKNOWN = 0,   // the backend does not say, or a code not listed here
  AMS_MODEL_AMS,           // "ams", the first generation
  AMS_MODEL_AMS_2_PRO,     // "n3f" / "ams_2_pro", four bays and a heater
  AMS_MODEL_AMS_HT,        // "n3s" / "ams_ht", one bay and a heater
  AMS_MODEL_AMS_LITE,      // "ams_lite", the A1's four open bays
  AMS_MODEL_AMS_3H,        // "n10a", the H3C's unit 32 with nine bays
};

// Which hotend a bay is loaded in, on a dual-nozzle printer (H2D, H2C).
// Zero is "none" so a bay that was cleared with {} is right without a word;
// single-nozzle printers and the H3C, whose every bay is a hotend of its own,
// never set anything else.
enum AmsHotend : uint8_t {
  AMS_HOTEND_NONE = 0,
  AMS_HOTEND_RIGHT,        // Bambu's extruder 0, the main one
  AMS_HOTEND_LEFT,         // Bambu's extruder 1
};

// A single bay.
struct AmsSlotTray {
  // Alpha included: a clear spool is 00000000 and is drawn as glass, not as
  // an empty bay. Invalid means unknown, not black.
  SpoolColor color;
  int      spool_id;               // 0 when no spool is known for this bay
  char     name[AMS_NAME_MAX];     // sub brand or trade name, else material
  char     color_name[AMS_COLOR_NAME_MAX];  // manufacturer's name, may be empty
  int16_t  remain_g;               // grams left, or AMS_REMAIN_NA
  // The nozzle range the server keeps for this bay's filament, or
  // AMS_REMAIN_NA. Carried per bay rather than fetched with the spool
  // because the display answer already has it and a second request would
  // buy nothing. Only FilaMan reports it; BamBuddy never reads it back.
  int16_t  nozzle_min;
  int16_t  nozzle_max;
  uint8_t  tray_id;                // bay id as the server numbered it
  int8_t   remain;                 // percent, or AMS_REMAIN_NA
  // The bay that stands in for this one when it runs out, empty when none.
  // A label like "B2", not a number: FilaMan names the partner rather than
  // numbering it, and the partner can sit in a different unit.
  char     backup_of[AMS_LABEL_MAX];
  // The bare material as the printer itself reports it ("PETG"), empty when
  // the backend does not hand that over on its own. BamBuddy passes the
  // printer's tray_type through and fills this. FilaMan's display answer
  // merges the material from the spool it has assigned before the printer's,
  // so what arrives there proves nothing about the bay and is not stored
  // here. The detail card holds this against the spool the database names
  // for the bay, see sdMaterialContradicts().
  char     type[AMS_TYPE_MAX];
  bool     exists;                 // a spool is physically in the bay
  // The bay the printer currently feeds from. Worth its own byte: it is the
  // one thing on the screen that says "this is what is printing right now",
  // and both backends report it.
  bool     active;
  // On a printer with two hotends, the one this bay is loaded in. Sits in
  // the padding after the bools, so the bay does not grow.
  AmsHotend hotend;
};

// One AMS unit, or one external holder with a single bay.
struct AmsSlotUnit {
  AmsSlotTray tray[AMS_MAX_TRAYS];
  // A name the user gave this unit on the server, empty when there is none.
  // Deliberately not filled with a generated "AMS 1": that is a label the
  // view builds through T(), and a service writing display text would put an
  // untranslated string on the screen. Empty here means "call it by number".
  char        label[AMS_NAME_MAX];
  int16_t     temp_c10;             // tenths of a degree, or AMS_TEMP_NA
  uint8_t     ams_id;
  int8_t      humidity;             // AMS_HUMIDITY_NA when unknown
  uint8_t     tray_count;           // real length of tray[], 1 on an AMS HT
  // Drying, and only while a cycle really runs. FilaMan 1.3.3 stopped
  // reporting the field as present-but-idle, so this is now a yes or no
  // rather than "the unit can dry".
  int16_t     dry_minutes;          // remaining, or AMS_REMAIN_NA
  int8_t      dry_target_c;         // target, or AMS_REMAIN_NA
  bool        drying;
  bool        is_ext;               // external holder rather than an AMS
  bool        is_ht;                // AMS HT, one bay and its own numbering
  // Bambu reports humidity either as a raw percentage or as its own 1 to 5
  // step, and which one arrives depends on the printer. The view has to say
  // "33%" or "step 2", so the parser records which it stored instead of
  // leaving the view to guess from the range.
  bool        humidity_is_level;
  // Stored in the padding the bools above leave, so the unit does not grow.
  AmsModel    model;
  // The heated chamber of an AMS 3H: which bays sit in it (bit per tray id,
  // 0 when the unit has none) and its own readings, apart from the unit's.
  uint16_t    dryer_mask;
  int16_t     dryer_temp_c10;       // AMS_TEMP_NA when unknown
  int8_t      dryer_humidity;       // AMS_HUMIDITY_NA when unknown
};

// The model, from either spelling: Bambu's module name as BamBuddy passes it
// on, or the word FilaMan's display API uses. Anything else stays UNKNOWN
// rather than being guessed at.
static inline AmsModel amsModelFromModuleType(const char* s) {
  if (!s || !s[0])                  return AMS_MODEL_UNKNOWN;
  if (strcmp(s, "ams") == 0)        return AMS_MODEL_AMS;
  if (strcmp(s, "n3f") == 0 ||
      strcmp(s, "ams_2_pro") == 0)  return AMS_MODEL_AMS_2_PRO;
  if (strcmp(s, "n3s") == 0 ||
      strcmp(s, "ams_ht") == 0)     return AMS_MODEL_AMS_HT;
  if (strcmp(s, "ams_lite") == 0)   return AMS_MODEL_AMS_LITE;
  if (strcmp(s, "n10a") == 0)       return AMS_MODEL_AMS_3H;
  return AMS_MODEL_UNKNOWN;
}

// The H3C's AMS 3H. BamBuddy reports it as unit 32 and names it in
// module_type; ams_type 6 (Bambu's ZMULTI_A) or the unit id alone is what
// BamBuddy itself falls back on when the name is missing (utils/tray_ids.py).
#define AMS_3H_UNIT_ID        32
#define AMS_TYPE_ZMULTI_A     6
#define AMS_3H_BAYS           9
#define AMS_REGULAR_BAYS      4
// Bambu Studio's global bay numbers, the ones tray_now reports: a regular
// AMS counts ams_id * 4 + bay, an AMS 3H 28 + bay, an AMS HT its unit id.
#define AMS_3H_GLOBAL_BASE    28

static inline AmsModel amsModelFromBambu(const char* module_type, int ams_type,
                                         int ams_id) {
  const AmsModel m = amsModelFromModuleType(module_type);
  if (m != AMS_MODEL_UNKNOWN) return m;
  if (ams_type == AMS_TYPE_ZMULTI_A || ams_id == AMS_3H_UNIT_ID) return AMS_MODEL_AMS_3H;
  return AMS_MODEL_UNKNOWN;
}

static inline int amsGlobalTrayId(const AmsSlotUnit& u, int tray_id) {
  if (u.is_ht) return u.ams_id;
  if (u.model == AMS_MODEL_AMS_3H) return AMS_3H_GLOBAL_BASE + tray_id;
  return u.ams_id * AMS_REGULAR_BAYS + tray_id;
}

// Whether BamBuddy accepts a bay in an assignment: four bays a unit, nine on
// the AMS 3H and on the external inputs, which an H3C has one per hotend
// (schemas/spoolman.py).
static inline bool amsBayAssignable(int ams_id, int tray_id) {
  if (ams_id < 0 || ams_id > AMS_EXT_AMS_ID || tray_id < 0) return false;
  const bool nine = (ams_id == AMS_3H_UNIT_ID || ams_id == AMS_EXT_AMS_ID);
  return tray_id < (nine ? AMS_3H_BAYS : AMS_REGULAR_BAYS);
}

// A fill level the printer reports, as the bay shows it. Bambu measures only
// a spool with an RFID chip; for one entered by hand in Bambu Studio it sends
// 0 on the external holder and -1 in an AMS, and both mean "unknown", not
// "empty". So 0 counts only when a chip stands behind it. A chip id of zeros
// is no chip: that is what Bambu sends for a spool without one.
static inline bool amsChipIdReal(const char* id) {
  if (!id || !id[0]) return false;
  for (const char* c = id; *c; c++) {
    if (*c != '0') return true;
  }
  return false;
}

static inline int8_t amsPrinterRemain(int remain, bool has_chip) {
  if (remain < 0 || remain > 100) return AMS_REMAIN_NA;
  if (remain == 0 && !has_chip) return AMS_REMAIN_NA;
  return (int8_t)remain;
}

// Whether a bay's card may offer to record a drying for the whole unit. Only
// an AMS 2 Pro dries four spools at once; an AMS HT holds one, and on the
// first generation the spools in one unit have nothing in common.
static inline bool amsUnitOffersDriedAll(const AmsSlotUnit& u) {
  return !u.is_ext && u.model == AMS_MODEL_AMS_2_PRO;
}

// One bay and the spool a backend has on file for it. Used where a whole
// printer is resolved at once rather than bay by bay.
struct AmsSlotSpool {
  int     spool_id;
  uint8_t ams_id;
  uint8_t tray_id;
  // Grams left on that spool where the same answer already said so, else
  // AMS_REMAIN_NA. BamBuddy's own inventory embeds the whole spool in every
  // assignment; behind Spoolman it names the id alone and the weight is a
  // second request.
  int16_t grams;
};

// Everything the view needs for one printer.
struct AmsSlotState {
  AmsSlotUnit unit[AMS_UNITS_TOTAL];
  char        printer[AMS_PRINTER_NAME_MAX];
  // What the printer is doing, so the header says more than a name and the
  // green border on a bay has a reason the user can see.
  char        state[AMS_STATE_MAX];
  int8_t      job_percent;          // AMS_JOB_NA when nothing is printing
  int         printer_id;
  uint8_t     unit_count;           // units plus external holders
  bool        valid;                // a fetch filled this, do not draw before
  bool        connected;            // the backend can currently reach the printer
  // FilaMan answers null while no driver has ever reported, which is not the
  // same as "the printer is off". Without this the screen would call a
  // backend that simply does not know yet an offline printer.
  bool        conn_known;           // the backend actually stated the above
  bool        ams_exists;           // the printer reports an AMS at all
};

// 9.5 kB with twelve units, measured; the budget leaves a little room.
#define AMS_SLOT_STATE_BUDGET_BYTES 10000

// Never on the stack: the loop task has 16 kB. The view and the presence
// check each keep one in PSRAM (psramNew), so the bound is a tripwire against
// sprawl, not a hardware limit. Asserted rather than commented so it cannot
// drift unnoticed when a field is added. Raised from 4200 when the view went
// from four units to twelve.
static_assert(sizeof(AmsSlotState) <= AMS_SLOT_STATE_BUDGET_BYTES,
              "AmsSlotState outgrew its budget, check where it is stored");

// Whether a unit a backend reports still gets a place. AMS and AMS HT units
// share the AMS_MAX_UNITS places; the external holder has the one place after
// them to itself. An H2D takes four AMS and up to eight AMS HT, so a printer
// can report more units than the screen keeps, and the external holder must
// never be the one that falls off: FilaMan sends it last.
inline bool amsUnitHasRoom(const AmsSlotState& s, bool is_ext) {
  if (s.unit_count >= AMS_UNITS_TOTAL) return false;
  uint8_t ams_units = 0;
  bool    ext_taken = false;
  for (int u = 0; u < s.unit_count; u++) {
    if (s.unit[u].is_ext) ext_taken = true;
    else                  ams_units++;
  }
  return is_ext ? !ext_taken : ams_units < AMS_MAX_UNITS;
}

struct AmsPrinter {
  int  id;
  char name[AMS_PRINTER_NAME_MAX];
  bool active;
  bool online;
};

struct AmsPrinterList {
  AmsPrinter p[AMS_MAX_PRINTERS];
  uint8_t    count;
};
