#pragma once

// ============================================================
//  THE LINK FLOW AND THE COPY FLOW, WHAT THEY SHARE
//
//  ui/copy_flow.cpp came out of spool_flow.cpp (v0.8.0-beta.47). The two
//  flows share the spool list in PSRAM and a handful of flags: an NTAG copy
//  runs through the link flow's vendor and material picker, the link flow's
//  ID input doubles as the copy's, and the spool created from the tag is
//  finished the way a copy is. What they share is declared here; the rest
//  stays static in its own file.
//
//  Included by those two files only, and in front of lang.h: it pulls in
//  ArduinoJson, whose templates do not survive the T() macro.
// ============================================================

#include <ArduinoJson.h>
#include <lvgl.h>
#include <time.h>

#include "lang.h"
#include "services/spool_color.h"
#include "services/tag_field.h"
#include "services/tag_uid.h"

// One row of the link and copy lists, in PSRAM.
struct UnlinkedSpool {
  int   id;
  char  name[48];      // filament.name
  char  vendor[32];    // filament.vendor.name
  char  material[16];  // filament.material (PLA, PETG, ABS...)
  char  color_hex[SPOOL_COLOR_HEX_MAX];  // filament.color_hex, #RRGGBB or #RRGGBBAA
  // The row was handed out by services/spool_cache and nobody has read the
  // spool from the server since. Its tag_values are then EMPTY whatever the
  // spool holds, because the cache keeps no tag values - and empty is what a
  // write takes for "unbound". So a row with this set must never reach
  // patchSpoolTag(): linkRefreshRow() reads the spool and clears it.
  //
  // In the row and not beside it, because qsort() moves whole rows. In the two
  // bytes of padding that were here anyway, the row stays at 896. Every place
  // that fills a row has to set it: the block comes from heap_caps_malloc(),
  // which does not zero.
  bool  from_cache;
  float remaining;     // remaining_weight
  float total;         // filament.weight
  // What the spool holds in each tag field, indexed by TagFieldId, quote
  // stripped, empty where the field holds nothing. Three jobs: it says whether
  // the spool is bound at all, it is what the overwrite warning offers to
  // replace, and patchSpoolTag() reads it to decide between appending to a
  // list and migrating a UID out of the field it currently sits in.
  //
  // One size for all three rather than a tight fit per field: it keeps the row
  // indexable by TagFieldId instead of needing a switch at every use site, and
  // the list lives in PSRAM where the difference does not matter. Overlong
  // values are stored as empty rather than shortened, see the fetch below -
  // a truncated list would send the write somewhere it does not belong.
  char  tag_values[TAG_FIELD_COUNT][CARD_UIDS_MAX];
  int   filament_id;   // filament.id (for copy flow)
  float spool_weight;  // spool_weight (for copy flow)
};

// ---- in spool_flow.cpp -------------------------------------------------------

// Under a spool list that is kept in the cache: when it was loaded, and a
// button that loads it again. A list the cache does not hold keeps its full
// height.
#define LINK_LIST_H        264
#define LINK_STRIP_H        36
void listReloadStrip(lv_obj_t* scr, time_t at, uint32_t age_ms, lv_event_cb_t on_reload);

extern UnlinkedSpool* link_spools;
extern int            link_spool_count;
extern int            link_spools_capacity;
void linkSpoolsFree();

extern char link_id_input[8];

// The copy confirmation, raised from a row of the copy list or of the link
// flow's picker in copy mode, opened by the link flow's deferred handler.
extern bool  copy_confirm_pending;
extern int   copy_confirm_fid;
extern int   copy_confirm_spool_id;
extern float copy_confirm_remaining, copy_confirm_initial, copy_confirm_spool_w;
extern char  copy_confirm_name[80];

// What the copy confirmation shows of its template besides the numbers.
struct CopyLook {
  char material[16];
  char name[48];
  char vendor[32];
  char color_hex[SPOOL_COLOR_HEX_MAX];   // #RRGGBB, empty when unknown
};
extern CopyLook copy_confirm_look;
void copyLookFromRow(CopyLook& look, const UnlinkedSpool& s);

bool nameStartsWithMaterial(const char* name, const char* material);
void addListMoreInfo(lv_obj_t* list, StringID str_id);
void linkPickerReset();
void linkPickerForCopy(bool archived);
void linkPickerClose();
// Shows the picker's spool list again if it is there, hidden behind a question.
void linkPickerShowList();
// The link write and everything after it, see doLinkPatch(). True when the
// tag was written.
bool doLinkPatchUid(int spool_id, bool is_bambu, const char* link_uuid);
// The X of a screen without a header: top right, "out to the main screen".
void flowCloseButton(lv_obj_t* parent, lv_event_cb_t cb);
// "New from tag" on the copy entry opens the popup of spool_flow.cpp.
extern bool newtag_open_pending;

// ---- in copy_flow.cpp and copy_confirm_popup.cpp --------------------------------------------------------

extern lv_obj_t *scr_copy_entry;     // entry screen (ID / active / archived)
extern lv_obj_t *scr_copy_list;      // spool list
extern lv_obj_t *scr_copy_confirm;   // confirm popup
extern bool      copy_flow_archived; // true = showing archived spools

void closeCopyListPopup();
void closeCopyConfirmPopup();
// Patch newly created spool with tag UID and query it on main screen
// True when the tag was bound; the spool exists either way.
bool finishCopyFlow(int new_spool_id, const char* tray_uuid_override = nullptr);
// From handleSpoolFlowDeferredActions(): the list the entry asked for, the
// spool the confirmation asked for.
void copyFlowDeferredActions();
// The confirmation's yes: create the spool from this template, from the loop.
void copyCreateRequest(int template_spool_id, int template_filament_id,
                       float template_initial, float template_spool_w);
