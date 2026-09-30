#include "main_screen_helpers.h"
#include "app/app_state.h"

#include <lvgl.h>
#include <stdio.h>
#include <string.h>
#include "services/ams_presence.h"
#include "services/backend.h"
#include "services/user_options.h"
#include "app_config.h"
#include "services/backend_api.h"
#include "services/tag_spool_match.h"
#include "ui/spool_flow.h"
#include "ui/spoolman_lookup.h"
#include "ui/theme.h"
#include "ui/ui_common.h"
#include "services/spool_color.h"
#include "hardware/sd_logger.h"
// After backend_api.h and the ArduinoJson it brings: the T() macro would
// otherwise expand inside ArduinoJson's own templates.
#include "lang.h"

// Long enough to read a line of red twice, short enough that the resting text
// is back before anyone wonders why it says nothing about the spool.
#define STATUS_MESSAGE_HOLD_MS  8000UL
// The resting text for an archived spool, grey like the weight line beside it.
#define STATUS_COL_ARCHIVED     UI_COL_ARCHIVED
// How far past its own box the status line answers a tap, so the whole bar
// is the target when it switches between tag and spool.
#define STATUS_TAP_EXT_PX       5

static unsigned long s_msg_ms = 0;                       // 0: nothing held
static char          s_msg_uid[sizeof(g_tag.uid_str)] = "";

void statusMessageShow(const char* text, uint32_t color) {
  if (!lbl_status || !text) return;
  lv_label_set_text(lbl_status, text);
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(color), 0);
  snprintf(s_msg_uid, sizeof(s_msg_uid), "%s", g_tag.uid_str);
  s_msg_ms = millis() ? millis() : 1;
}

void applyTagSpoolView() {
  if (!lbl_material || !lbl_vendor || !lbl_color_swatch) return;
  if (tagSpoolLookupShowsSpool()) {
    const char* m = tagSpoolLookupMaterial();
    const char* v = tagSpoolLookupVendor();
    lv_label_set_text(lbl_material, m[0] ? m : "-");
    lv_label_set_text(lbl_vendor,   v[0] ? v : "-");
    SpoolColor c;
    if (spoolColorParse(tagSpoolLookupColor(), &c)) swatchPaint(lbl_color_swatch, c);
    return;
  }
  // The tag's side, painted exactly as updateDisplay() and applyServerColor()
  // paint it after a scan.
  lv_label_set_text(lbl_material, g_tag.material[0] ? g_tag.material : T(STR_UNKNOWN));
  lv_label_set_text(lbl_vendor,   g_tag.vendor[0]   ? g_tag.vendor   : BAMBU_VENDOR_NAME);
  SpoolColor server;
  spoolColorParse(sm_color_global, &server);
  const SpoolColor shown = spoolColorResolve(g_tag.color, server);
  if (shown.valid) swatchPaint(lbl_color_swatch, shown);
}

void tagSpoolViewAttach(lv_obj_t* status_label) {
  if (!status_label) return;
  lv_obj_add_flag(status_label, LV_OBJ_FLAG_CLICKABLE);
  // The line is 14 px type in a 26 px bar; this makes the whole bar height
  // a target without reaching into the header above.
  lv_obj_set_ext_click_area(status_label, STATUS_TAP_EXT_PX);
  lv_obj_add_event_cb(status_label, [](lv_event_t* e) {
    if (!sm_found || !tagSpoolLookupDiffers()) return;
    tagSpoolLookupToggleView();
    logSDf("UI: status line -> showing the %s of spool %d",
           tagSpoolLookupShowsSpool() ? "spool" : "tag", sm_id);
    applyTagSpoolView();
    paintTagStatus();
  }, LV_EVENT_CLICKED, NULL);
}

static bool statusMessageHeld() {
  if (s_msg_ms == 0) return false;
  if (millis() - s_msg_ms < STATUS_MESSAGE_HOLD_MS &&
      strcmp(s_msg_uid, g_tag.uid_str) == 0) return true;
  s_msg_ms = 0;
  return false;
}

void paintTagStatus() {
  if (!lbl_status || statusMessageHeld()) return;
  // Neither found nor unknown yet: the inventory is still coming in.
  if (lookupPending()) { lookupPaintSearching(); return; }
  // A lookup that never reached the server says nothing about the spool, so
  // the line names the connection rather than the backend the spool is
  // supposedly not in. backendText() puts the backend's own name in.
  if (!sm_found && lookupLostConnection()) {
    char nb[48];
    backendText(T(STR_NO_CONNECTION_TO), nb, sizeof(nb));
    lv_label_set_text(lbl_status, nb);
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_BAD_TEXT), 0);
    return;
  }
  // Archived is its own answer: saying "tag detected" in green while the
  // line below reads "Archived" tells the user two different things.
  // Found, but the Bambu tag describes another filament than the spool it is
  // linked to: said in amber, because half the screen is the tag's and half
  // the spool's and neither half says so.
  const bool differs = sm_found && !sm_archived && tagSpoolLookupDiffers();
  char sb[48];
  backendText(sm_archived ? T(STR_ARCHIVED)
              : differs   ? T(STR_TAG_MISMATCH_STATUS)
              : sm_found  ? T(sm_dup_count > 1 ? STR_TAG_FOUND_DUP : STR_TAG_FOUND)
                          : T(STR_NOT_IN_SPOOLMAN), sb, sizeof(sb));
  // The arrow says the line can be tapped, and which side it would show.
  if (differs) {
    char view[40];
    if (tagSpoolLookupShowsSpool()) snprintf(view, sizeof(view), T(STR_TAG_VIEW_SPOOL), sm_id);
    else                            copyT(view, sizeof(view), STR_TAG_MISMATCH_STATUS);
    snprintf(sb, sizeof(sb), "%s  " LV_SYMBOL_RIGHT, view);
  }
  lv_label_set_text(lbl_status, sb);
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(
      sm_archived ? STATUS_COL_ARCHIVED : differs ? UI_COL_WARN
      : sm_found ? UI_COL_ACCENT : UI_COL_WARN), 0);
}

void updateLinkButton() {
  // Whichever button buildUI() put in the left slot. With a load cell that is
  // "update weight"; without one there is no weight to send and the slot holds
  // the location instead. Only ever one of the two exists, so this asks for the
  // one that does rather than testing both.
  lv_obj_t *slot1 = g_scale_fitted ? btn_weight_main : btn_location;

  if (!btn_dried || !btn_link || !slot1 || !btn_copy) return;

  // Two slots, four buttons: weight and link share the left one, dried and
  // copy the right. An archived spool is the third combination of the same
  // four, not a fifth button - there is no room for one anyway.
  //
  //   unknown tag   link   + copy
  //   archived      weight + copy    <- here
  //   found         weight + dried
  //
  // Drying a spool that has been used up says nothing, while copying it is
  // exactly the restock case: the reason it is archived is that it ran out.
  if (sm_archived && sm_found) {
    // The location picker refuses an archived spool, so on a device without a
    // scale the left slot has nothing to offer and stays empty. A button that
    // does nothing when pressed is worse than a gap.
    if (g_scale_fitted) lv_obj_clear_flag(slot1, LV_OBJ_FLAG_HIDDEN);
    else                lv_obj_add_flag(slot1,   LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_dried,         LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_link,          LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_copy,        LV_OBJ_FLAG_HIDDEN);
    return;
  }

  // While the inventory comes in the tag is neither known nor unknown, and
  // "Link" would load the same inventory a second time next to it.
  if (tag_present && lookupPending()) {
    lv_obj_add_flag(slot1,             LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_dried,         LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_link,          LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_copy,          LV_OBJ_FLAG_HIDDEN);
    return;
  }

  if (tag_present && !sm_found) {
    lv_obj_add_flag(slot1,             LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_dried,         LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_link,        LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_copy,        LV_OBJ_FLAG_HIDDEN);
  } else {
    lv_obj_clear_flag(slot1,           LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_dried,       LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_link,          LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_copy,          LV_OBJ_FLAG_HIDDEN);
  }
}


void updateAmsAffordance() {
  // Two questions, and both have to be yes. backendHasAmsView() is the cheap
  // one - a backendMode() switch and two string checks, no network - and it
  // only says the backend could talk about a printer at all. Whether that
  // printer actually has an AMS costs a blocking round trip, so it is asked
  // on a slow timer and cached in ams_presence. Without the second half the
  // chip appears on every FilaMan and BamBuddy setup, including printers
  // with no AMS on them, and leads to an empty page.
  const bool has_ams = backendHasAmsView() && amsPresenceHasAms();

  // The header chip first, and in both modes - it is the only way in on a
  // device that has a load cell. Before layoutHeaderChips() runs, which is
  // what lets the row close up when it goes.
  if (btn_hdr_ams) {
    if (has_ams) lv_obj_clear_flag(btn_hdr_ams, LV_OBJ_FLAG_HIDDEN);
    else         lv_obj_add_flag(btn_hdr_ams,   LV_OBJ_FLAG_HIDDEN);
  }

  // The rest is zone 4's right half, which exists only without a load cell.
  if (!lbl_no_scale) return;

  const bool show_ams = btn_ams_main && has_ams;

  if (btn_ams_main) {
    if (show_ams) lv_obj_clear_flag(btn_ams_main, LV_OBJ_FLAG_HIDDEN);
    else          lv_obj_add_flag(btn_ams_main,   LV_OBJ_FLAG_HIDDEN);
  }

  // With a button under it the note is a caption and sits on the zone's
  // caption row, level with "Spoolman:" opposite. Alone it is the only thing
  // in the half and goes in the middle.
  if (show_ams) {
    lv_obj_set_pos(lbl_no_scale, MAIN_NOSCALE_X, MAIN_ZONE4_Y);
    return;
  }

  // Centred from the height it really has, not from a number worked out for
  // German: a longer translation wraps to two lines, and a fixed y would hang
  // it out of the zone. The label only knows its height after a layout pass.
  lv_obj_set_pos(lbl_no_scale, MAIN_NOSCALE_X, MAIN_ZONE4_Y);
  lv_obj_update_layout(lbl_no_scale);
  const lv_coord_t h = lv_obj_get_height(lbl_no_scale);
  lv_obj_set_pos(lbl_no_scale, MAIN_NOSCALE_X,
                 MAIN_ZONE4_Y + (MAIN_ZONE4_H - h) / 2);
}
