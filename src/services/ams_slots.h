#pragma once

#include <stdint.h>

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

// Bambu allows four AMS units per printer. The reading endpoints of both
// backends would permit more, so going higher is a matter of raising this
// and paying the RAM, not of changing code.
#define AMS_MAX_UNITS        4

// An AMS HT holds one bay, a regular AMS four. Never assume four, always
// read tray_count.
#define AMS_MAX_TRAYS        4

// Bays in the external holder: one on most printers, two on a dual nozzle
// H2D (Ext-L and Ext-R). They are bays of a single unit, not units of their
// own - FilaMan reports them exactly that way, as one entry of kind
// "external" carrying slots 254 and 255.
#define AMS_MAX_EXT          2

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

// The external holder. Its bay numbering is not stable across servers:
// FilaMan 1.3.1 reported ams_id 255 with bays 254 (Ext-L) and 255 (Ext-R),
// Bambu's own numbering, while 1.3.3 collapses those onto 0 and 1 so a dual
// nozzle machine shows two bays instead of four ghosts. Real bay ids are
// therefore always stored as they arrive and never assumed - this default is
// only for a backend that names the holder without numbering its bay.
#define AMS_EXT_AMS_ID       255
#define AMS_EXT_TRAY_ID      0

// A single bay.
struct AmsSlotTray {
  uint32_t color;                  // 0xRRGGBB, alpha dropped
  int      spool_id;               // 0 when no spool is known for this bay
  char     name[AMS_NAME_MAX];     // sub brand or trade name, else material
  char     color_name[AMS_COLOR_NAME_MAX];  // manufacturer's name, may be empty
  int16_t  remain_g;               // grams left, or AMS_REMAIN_NA
  uint8_t  tray_id;                // bay id as the server numbered it
  int8_t   remain;                 // percent, or AMS_REMAIN_NA
  // The bay that stands in for this one when it runs out, empty when none.
  // A label like "B2", not a number: FilaMan names the partner rather than
  // numbering it, and the partner can sit in a different unit.
  char     backup_of[AMS_LABEL_MAX];
  bool     exists;                 // a spool is physically in the bay
  bool     has_color;              // false means unknown, not black
  // The bay the printer currently feeds from. Worth its own byte: it is the
  // one thing on the screen that says "this is what is printing right now",
  // and both backends report it.
  bool     active;
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

// Kept in BSS, never on the stack: the loop task has 16 kB and already warns
// about its high water mark. The bound is asserted rather than commented so
// it cannot drift unnoticed when a field is added.
// The bound is asserted rather than commented so it cannot drift unnoticed
// when a field is added. Raised from 1200 when the colour name, the drying
// figures and the printer state came in: the struct lives in BSS, not on the
// loop task's 16 kB stack, and the device has well over 100 kB of internal
// RAM free - so this is a tripwire against sprawl, not a hardware limit.
static_assert(sizeof(AmsSlotState) <= 1800,
              "AmsSlotState outgrew its budget, check where it is stored");

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
