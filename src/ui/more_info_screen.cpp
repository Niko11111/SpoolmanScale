#include "more_info_screen.h"
#include "navigation.h"
#include "app/app_state.h"
#include "services/tag_field.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <lvgl.h>
#include <cstring>

#include "bambu/bambu_tag.h"
#include "hardware/sd_logger.h"
#include "services/list_limits.h"
#include "services/location_state.h"
#include "services/spoolman_actions.h"
#include "services/tag_uid.h"
#include "services/user_options.h"
#include "services/backend.h"
#include "services/breadcrumb.h"
#include "services/backend_api.h"
#include "services/server_reach.h"
#include "services/filaman_api.h"
#include "services/wifi_manager.h"
#include "lang.h"
#include "confirm_popup.h"
#include "status_picker.h"
#include "tag_display.h"
#include "ui/main_screen_helpers.h"
#include "ui/tag_write_popup.h"
#include "ui/theme.h"
#include "ui_common.h"


void showLocationPicker();
void buildMoreInfoScreen();
void fetchAndFillLocationList();
static void applyPickedStatus(int status_id);
static void openStatusPicker();

static bool show_location_picker_pending = false;
static bool show_more_info_pending = false;
static bool fetch_locations_pending = false;
static bool g_loc_picker_from_popup = false;

static lv_obj_t *scr_location_picker = nullptr;

// Status picker. The chosen id is parked here rather than acted on in the row
// callback, so the overlay is gone before anything blocks on the network.
static bool show_status_picker_pending = false;
static bool status_apply_pending      = false;
static bool status_archive_pending    = false;
static int  status_pick_id            = 0;   // 1..6, or 0 for "cancelled"

// Shared by both confirm buttons of the unlink popup. user_data is 1 for
// "release the whole binding" and 0 for "only the tag on the scale" - the
// distinction two UIDs create and a single one does not have.
// Parked by the unlink confirmation and the location picker for
// handleMoreInfoDeferredActions(). Both reach the backend, and both used to
// run inside the callback of the button that asked - with the popup gone and
// the touch panel dead for the length of the request.
static bool unlink_pending  = false;
static bool unlink_all      = false;
static int  unlink_spool_id = 0;
static bool loc_patch_pending  = false;
static char loc_patch_name[48] = "";      // empty: clear the location
static bool loc_cancel_pending = false;   // the picker's X
static void closeLocationPicker();
// The unlink confirmation. A local of the button's callback until now, so no
// navigation could take it down.
static lv_obj_t *s_unlink_popup = nullptr;

void closeMoreInfoPopups() { releaseScreen(&s_unlink_popup); }

static void unlinkConfirmCb(lv_event_t *e) {
  lv_obj_t *btn = lv_event_get_target(e);
  unlink_all      = (bool)(intptr_t)lv_obj_get_user_data(btn);
  unlink_spool_id = sm_id;
  // Read out of the button before the popup goes. The popup is this button's
  // grandparent, so it is released asynchronously; the unlink itself runs from
  // the loop a pass later.
  releaseScreen(&s_unlink_popup);
  unlink_pending = true;
}

static void runUnlink() {
  const bool all      = unlink_all;
  const int  spool_id = unlink_spool_id;
  if (spool_id <= 0) return;

  if (backendMode() == BACKEND_SPOOLMAN) {
    // Only Spoolman has more than one place a binding can sit, so only there
    // does the unlink have to look. unlinkCardUid() clears whichever fields
    // hold something and leaves the rest alone - writing a field that is
    // already empty costs a request and, on a server that does not know the
    // field, an HTTP 400.
    //
    // g_tag.tray_uuid is the identifier the spool was found under: app_loop
    // puts the plain UID there for NTAGs and for cards with no Bambu data, so
    // it is the entry to take out of a list.
    unlinkCardUid(spool_id, g_tag.tray_uuid, all);
  } else {
    // FilaMan and BamBuddy keep one tag each in a place of their own, and
    // patchSpoolTag() with an empty uuid is how both of them unlink.
    patchSpoolTag(spool_id, "");
    // FilaMan has more places a binding can hide. The Bambu plugin's fields
    // would otherwise find the spool on the very next scan and the migration
    // would write rfid_uid back, so an unlink that looked done did not hold.
    // Only what this scale itself writes is taken back, see the function.
    // Not after a request that found no server: this one would only wait out
    // the same timeout again.
    if (backendIsFilaMan() && !tagBindingFailedOnNetwork()) {
      char chip[24];
      tagUidNormalize(g_tag.uid_str, chip, sizeof(chip));
      filamanUnlinkBambuFields(backendBaseUrl(), filamanApiKey(), spool_id, chip);
    }
    logSDf("Unlink spool ID=%d", spool_id);
  }
  Serial.printf("Unlink spool ID=%d all=%d\n", spool_id, all ? 1 : 0);

  // An unlink that never reached the server leaves the spool bound, so the
  // screen keeps it and says so. Reported as done, it cleared the display and
  // offered to erase the tag while the server still held the binding - and the
  // next scan found the spool again, which read as the unlink not working.
  if (tagBindingFailedOnNetwork()) {
    logSDf("UNLINK ABORT: spool %d not reached, binding kept", spool_id);
    if (scr_more_info) { lv_obj_del(scr_more_info); scr_more_info = nullptr; }
    showMainScreen();
    statusMessageShow(T(STR_UNLINK_NO_CONNECTION), UI_COL_BAD_TEXT);
    return;
  }

  // The binding is gone, but the tag on the reader still carries the spool
  // data - the next reader to see it would still name a spool this one no
  // longer knows. Asked rather than done: the tag may be somebody else's, and
  // the question only appears when one is actually lying there with something
  // on it.
  requestTagEraseAsk();

  // Close More Info and reset display - NFC will re-scan and find no match
  if (scr_more_info) { lv_obj_del(scr_more_info); scr_more_info = nullptr; }
  clearTagDisplay();
  showMainScreen();
}
static lv_obj_t *loc_list_obj = nullptr;
static lv_obj_t *loc_status_obj = nullptr;

void requestLocationPicker(bool from_popup) {
  g_loc_picker_from_popup = from_popup;
  show_location_picker_pending = true;
}

void handleMoreInfoDeferredActions() {
  if (unlink_pending) {
    unlink_pending = false;
    runUnlink();
  }
  if (loc_cancel_pending) {
    loc_cancel_pending = false;
    closeLocationPicker();
    if (g_loc_picker_from_popup) showMainScreen();
    else                         showMoreInfoScreen();
  }
  if (loc_patch_pending) {
    loc_patch_pending = false;
    closeLocationPicker();
    if (sm_id > 0) {
      const bool clear = (loc_patch_name[0] == '\0');
      const int code = serverReachNote(backendPatchSpoolLocation(cfg_spoolman_base, sm_id,
                                                 clear ? nullptr : loc_patch_name, 8000), true);
      if (code == 200) {
        if (clear) {
          sm_location_id = 0;
          sm_location_name[0] = '\0';
        } else {
          strncpy(sm_location_name, loc_patch_name, sizeof(sm_location_name) - 1);
          sm_location_name[sizeof(sm_location_name) - 1] = '\0';
          sm_location_id = 0;
          // Mark the popup as shown so it does not re-trigger on the next
          // removal.
          g_loc_popup_shown_for_id = sm_id;
          logSDf("[verbose] LOC: location saved '%s' id=%d from_popup=%d",
                 loc_patch_name, sm_id, (int)g_loc_picker_from_popup);
        }
      }
    }
    if (g_loc_picker_from_popup) showMainScreen();
    else                         showMoreInfoScreen();
  }
  if (show_location_picker_pending) {
    show_location_picker_pending = false;
    logSDf("[verbose] LOC: show_location_picker_pending fired from_popup=%d id=%d", (int)g_loc_picker_from_popup, sm_id);
    showLocationPicker();
  }
  if (fetch_locations_pending) {
    fetch_locations_pending = false;
    fetchAndFillLocationList();
  }
  if (show_more_info_pending) {
    show_more_info_pending = false;
    // showMoreInfoScreen(), not buildMoreInfoScreen(): the latter overwrites
    // scr_more_info with a fresh object and leaks the previous instance.
    showMoreInfoScreen();
  }

  if (show_status_picker_pending) {
    show_status_picker_pending = false;
    openStatusPicker();
  }
  // Both are set by onStatusPicked(), which status_picker.cpp calls a pass
  // after its overlay is really gone - so the blocking write below never runs
  // with the picker still on screen.
  if (status_apply_pending) {
    status_apply_pending = false;
    applyPickedStatus(status_pick_id);
  }
  if (status_archive_pending) {
    status_archive_pending = false;
    showConfirmPopup(T(STR_ARCHIVE_CONFIRM), 3);
  }
}

// Both pickers, from the one list hideAllOverlays() already is. Neither used
// to be in it, so navigating away from the location picker left it standing.
void hideMoreInfoOverlays() {
  releaseScreen(&scr_location_picker);
  closeStatusPicker();
  loc_status_obj = nullptr;
  loc_list_obj   = nullptr;
}

// The picker and the two labels inside it, always together. The three buttons
// that close it used to delete the screen and leave loc_status_obj and
// loc_list_obj pointing into it - and fetchAndFillLocationList() pumps LVGL
// for 100 ms before it writes to exactly those two, so a tap during the pump
// left it writing to freed memory. LV_USE_ASSERT_OBJ is 0, so nothing catches
// that on the way through.
static void closeLocationPicker() {
  if (scr_location_picker) { lv_obj_del(scr_location_picker); scr_location_picker = nullptr; }
  loc_status_obj = nullptr;
  loc_list_obj   = nullptr;
}

// ============================================================
//  MORE INFO FILAMENT SCREEN
//  Overlay with teal border (8px margin), shows UID, UUID,
//  article nr, production date, spool weight (empty), free slot.
//  Always rebuilt on open. Only one close button (X).
//
//  Same grid as the main screen: 10 px inner margin inside the box,
//  captions font 12 in 0x4a6fa0, 18 px from a caption's baseline to its
//  value's baseline, two columns at 10 and 236. Values are font 18 in the
//  grid and font 16 elsewhere, so the y offsets differ (14 and 16) to land
//  on the same 18 px baseline distance.
// ============================================================
void showMoreInfoScreen() {
  logSD("SHOW: MoreInfoScreen");
  logSD("UI: Screen -> MoreInfo");
  // Delete old instance if exists
  if (scr_more_info) { lv_obj_del(scr_more_info); scr_more_info = nullptr; }
  buildMoreInfoScreen();
}

// ── Location Picker ─────────────────────────────────────────
void showLocationPicker() {
  // Through the same helper as the three close buttons, and for the same
  // reason: the early return below leaves the function without building
  // anything, and the two label pointers would otherwise still name the
  // screen that was just deleted here.
  closeLocationPicker();
  // A storage location on an archived spool describes a shelf nobody will look
  // on. Bringing it back first is the step that makes the question meaningful.
  //
  // Logged, because this used to be the one path in the whole chain that
  // produced no trace at all: by the time this runs, one loop pass after the
  // prompt was scheduled, the next spool's lookup may already have moved
  // sm_id - and then the question simply never appeared, with nothing on the
  // card to say why.
  if (!sm_found || sm_archived || sm_id <= 0) {
    logSDf("LOC: picker not shown, sm_found=%d archived=%d sm_id=%d",
           (int)sm_found, (int)sm_archived, sm_id);
    return;
  }

  // Backdrop
  scr_location_picker = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_location_picker, 480, 320);
  lv_obj_set_pos(scr_location_picker, 0, 0);
  lv_obj_set_style_bg_color(scr_location_picker, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_location_picker, LV_OPA_70, 0);
  lv_obj_set_style_border_width(scr_location_picker, 0, 0);
  lv_obj_set_style_radius(scr_location_picker, 0, 0);
  lv_obj_set_style_pad_all(scr_location_picker, 0, 0);
  lv_obj_clear_flag(scr_location_picker, LV_OBJ_FLAG_SCROLLABLE);

  // Inner box
  lv_obj_t *box = lv_obj_create(scr_location_picker);
  lv_obj_set_size(box, 400, 280);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0b1525), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, 10, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Header
  lv_obj_t *hdr = lv_obj_create(box);
  lv_obj_set_size(hdr, 400, 44);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(hdr);
  char title_buf[48];
  copyT(title_buf, sizeof(title_buf), STR_LOCATION_TITLE);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *btn_x = lv_btn_create(hdr);
  lv_obj_set_size(btn_x, 40, 40);
  lv_obj_align(btn_x, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_x, 1, 0);
  lv_obj_set_style_border_color(btn_x, lv_color_hex(0x601010), 0);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e) {
    // Parked: this button sits on the picker it would delete, and the fetch
    // that fills the list pumps LVGL - a tap here used to rebuild More Info
    // from inside that fetch.
    loc_cancel_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);

  // Status label (loading / error)
  lv_obj_t *lbl_loc_status = lv_label_create(box);
  char status_buf[48];
  copyT(status_buf, sizeof(status_buf), STR_LOCATION_LOADING);
  lv_label_set_text(lbl_loc_status, status_buf);
  lv_obj_set_style_text_color(lbl_loc_status, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_loc_status, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_loc_status, LV_ALIGN_CENTER, 0, 10);

  // Scrollable list container
  lv_obj_t *list = lv_obj_create(box);
  lv_obj_set_size(list, 380, 220);
  lv_obj_set_pos(list, 10, 50);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0b1525), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_style_pad_all(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_add_flag(list, LV_OBJ_FLAG_HIDDEN);

  // Store refs for async fetch
  loc_status_obj = lbl_loc_status;
  loc_list_obj   = list;

  // Trigger async HTTP fetch via loop()
  if (!wifiManagerIsConnected()) {
    char buf[32]; copyT(buf, sizeof(buf), STR_LOCATION_NO_WIFI);
    lv_label_set_text(lbl_status, buf);
    return;
  }
  fetch_locations_pending = true;
}

void fetchAndFillLocationList() {
  crumbSet("loc fetch");
  logSD("LOC: fetchAndFillLocationList called");
  if (!loc_list_obj || !loc_status_obj) { logSD("LOC: null refs, abort"); return; }
  if (!scr_location_picker) { logSD("LOC: picker gone, abort"); return; }

  // Mehrere LVGL-Ticks geben damit das Overlay vollständig gerendert ist
  for (int i = 0; i < 5; i++) {
    lv_task_handler();
    delay(20);
  }
  // lv_task_handler() dispatches touch, so those 100 ms are live: the X button
  // and every row of the picker can close it from inside this loop. Asked
  // again rather than trusting the check above - everything below writes into
  // the two labels, and a closed picker has none.
  if (!scr_location_picker || !loc_list_obj || !loc_status_obj) {
    logSD("LOC: picker closed while it was being drawn, abort");
    return;
  }

  // The address the request actually goes to, not the Spoolman one: with
  // FilaMan or BamBuddy selected this line named a host that was never asked,
  // and the path differs between the backends as well.
  logSDf("LOC: GET locations from %s", backendBaseUrl());
  JsonDocument doc;
  DeserializationError err = DeserializationError::Ok;
  int code = serverReachNote(backendGetLocationsJson(cfg_spoolman_base, doc, 8000, &err), true);
  logSDf("LOC: HTTP code=%d", code);
  if (code != 200) {
    char buf[48];
    snprintf(buf, sizeof(buf), "HTTP %d", code);
    lv_label_set_text(loc_status_obj, buf);
    return;
  }
  logSDf("LOC: parse err=%s isArray=%d", err.c_str(), (int)doc.is<JsonArray>());
  if (err || !doc.is<JsonArray>()) {
    char buf[48];
    snprintf(buf, sizeof(buf), "Parse: %s", err.c_str());
    lv_label_set_text(loc_status_obj, buf);
    return;
  }

  JsonArray locs = doc.as<JsonArray>();
  logSDf("LOC: locs.size()=%d", (int)locs.size());
  if (locs.size() == 0) {
    char buf[48]; backendText(T(STR_LOCATION_NO_LOCATIONS), buf, sizeof(buf));
    lv_label_set_text(loc_status_obj, buf);
    return;
  }

  // Hide status, show list
  lv_obj_add_flag(loc_status_obj, LV_OBJ_FLAG_HIDDEN);
  lv_obj_clear_flag(loc_list_obj, LV_OBJ_FLAG_HIDDEN);
  lv_obj_t *list = loc_list_obj;

  // "Kein Lagerort" Row
  lv_obj_t *btn_none = lv_btn_create(list);
  // An exhausted LVGL pool comes back as NULL here, and LVGL 8.3 asserts
  // nothing on the way - the next style call would write through it and take
  // the device down with a panic. See the same guard in spool_flow.cpp.
  if (!btn_none) { logSD("LOC: LVGL pool exhausted, no rows built"); return; }
  lv_obj_set_size(btn_none, 370, 44);
  lv_obj_set_style_bg_color(btn_none, lv_color_hex(0x0d2040), 0);
  lv_obj_set_style_bg_color(btn_none, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_border_color(btn_none, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(btn_none, 1, 0);
  lv_obj_set_style_radius(btn_none, 6, 0);
  lv_obj_set_style_shadow_width(btn_none, 0, 0);
  lv_obj_set_style_pad_bottom(btn_none, 4, 0);
  lv_obj_t *lbl_none = lv_label_create(btn_none);
  char none_buf[48]; copyT(none_buf, sizeof(none_buf), STR_LOCATION_NONE);
  lv_label_set_text(lbl_none, none_buf);
  lv_obj_set_style_text_color(lbl_none, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_none, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_none);
  lv_obj_add_event_cb(btn_none, [](lv_event_t *e) {
    if (!wifiManagerIsConnected() || sm_id <= 0) return;
    loc_patch_name[0] = '\0';      // clear
    loc_patch_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  logLvMem("loclist/pre", 0);
  // Location rows - API gibt Array von Strings zurück
  int loc_shown = 0;
  bool loc_limit_hit = false;
  for (JsonVariant v : locs) {
    if (loc_shown >= location_list_limit) { loc_limit_hit = true; break; }
    char loc_name[48];
    strncpy(loc_name, v.as<const char*>() ? v.as<const char*>() : "-", sizeof(loc_name)-1);
    loc_name[sizeof(loc_name)-1] = '\0';

    // Same reserve as the spool lists, same reason - see lvPoolHasRoomForRow().
    if (!lvPoolHasRoomForRow()) {
      logSDf("LOC: LVGL pool low, list cut at %d rows", loc_shown);
      break;
    }
    lv_obj_t *row = lv_btn_create(list);
    if (!row) { logSDf("LOC: no room for a row, list cut at %d", loc_shown); break; }
    lv_obj_set_size(row, 370, 44);
    bool is_current = (strlen(sm_location_name) > 0 && strcmp(loc_name, sm_location_name) == 0);
    lv_obj_set_style_bg_color(row, is_current ? lv_color_hex(0x0d3020) : lv_color_hex(0x0d2040), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(row, is_current ? lv_color_hex(0x28d49a) : lv_color_hex(0x0f1e30), 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_pad_bottom(row, 4, 0);

    lv_obj_t *lbl_row = lv_label_create(row);
    lv_label_set_text(lbl_row, loc_name);
    lv_obj_set_style_text_color(lbl_row, is_current ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0f0f0), 0);
    lv_obj_set_style_text_font(lbl_row, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_row);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      lv_obj_t *lbl = lv_obj_get_child(lv_event_get_target(e), 0);
      if (!lbl || !wifiManagerIsConnected() || sm_id <= 0) return;
      // Copied out of the label now: the picker is gone by the time the
      // PATCH runs from the loop.
      const char* sel_name = lv_label_get_text(lbl);
      strncpy(loc_patch_name, sel_name ? sel_name : "", sizeof(loc_patch_name) - 1);
      loc_patch_name[sizeof(loc_patch_name) - 1] = '\0';
      loc_patch_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    loc_shown++;
  }
  logLvMem("loclist/post", loc_shown);
  // Hinweis: Limit erreicht
  if (loc_limit_hit) {
    lv_obj_t *limit_row = lv_obj_create(loc_list_obj);
    lv_obj_set_size(limit_row, 360, 40);
    lv_obj_set_style_bg_color(limit_row, lv_color_hex(0x1a0808), 0);
    lv_obj_set_style_radius(limit_row, 6, 0);
    lv_obj_set_style_border_width(limit_row, 1, 0);
    lv_obj_set_style_border_color(limit_row, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_pad_all(limit_row, 0, 0);
    lv_obj_clear_flag(limit_row, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *limit_lbl = lv_label_create(limit_row);
    char limit_buf[64]; copyT(limit_buf, sizeof(limit_buf), STR_LOCATION_LIMIT_HIT);
    lv_label_set_text(limit_lbl, limit_buf);
    lv_obj_set_style_text_color(limit_lbl, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(limit_lbl, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(limit_lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(limit_lbl, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(limit_lbl, 350);
    lv_obj_center(limit_lbl);
  }
  // Hint that empty locations are hidden. Only true for Spoolman, which
  // derives its location list from the spools themselves, so a location
  // without spools does not exist there. FilaMan keeps locations as their
  // own objects and returns them all, empty or not.
  if (backendIsFilaMan()) return;

  lv_obj_t *hint_row = lv_obj_create(loc_list_obj);
  lv_obj_set_size(hint_row, 360, 40);
  lv_obj_set_style_bg_color(hint_row, lv_color_hex(0x1a1a08), 0);
  lv_obj_set_style_radius(hint_row, 6, 0);
  lv_obj_set_style_border_width(hint_row, 1, 0);
  lv_obj_set_style_border_color(hint_row, lv_color_hex(0x3a3010), 0);
  lv_obj_set_style_pad_all(hint_row, 0, 0);
  lv_obj_clear_flag(hint_row, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
  lv_obj_t *hint_lbl = lv_label_create(hint_row);
  char hint_buf[64]; copyT(hint_buf, sizeof(hint_buf), STR_LOCATION_HINT_EMPTY);
  lv_label_set_text(hint_lbl, hint_buf);
  lv_obj_set_style_text_color(hint_lbl, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(hint_lbl, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(hint_lbl, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(hint_lbl, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint_lbl, 350);
  lv_obj_center(hint_lbl);
}

// ── Status Picker (FilaMan only) ────────────────────────────
// FilaMan's six statuses. Fixed on the server, so the list needs no fetch
// stage the way the location picker does. The caption and the colour behind
// each one live in ui_common: the AMS detail card shows the same status, and
// a second copy of the switch would drift the first time FilaMan adds one.

// Runs from handleMoreInfoDeferredActions(), never from a row callback: it
// blocks for as long as the server takes.
static void applyPickedStatus(int status_id) {
  const char* key = filamanStatusKey(status_id);
  if (!key || sm_id <= 0) return;
  if (!wifiManagerIsConnected()) return;

  int code = serverReachNote(backendSetSpoolStatus(cfg_spoolman_base, sm_id, key, 5000), true);
  logSDf("status: spool %d -> %s HTTP %d", sm_id, key, code);
  if (code == 200) sm_status_id = status_id;
  // Rebuilt either way. On failure the chip goes back to showing the truth.
  show_more_info_pending = true;
}

// The picker moved to status_picker.cpp when the AMS detail card needed the
// same one. What stays here is which spool is meant and what the answer does -
// the archive branch in particular, which tears this screen down first.
static void onStatusPicked(int status_id) {
  if (status_id == FILAMAN_STATUS_ARCHIVED) {
    // Archiving empties the spool and unlinks it, so the detail view behind
    // the picker is about to be wrong either way. patchArchiveSpool() writes
    // its result onto the main screen.
    releaseScreen(&scr_more_info);
    status_archive_pending = true;
  } else if (status_id > 0 && status_id != sm_status_id) {
    status_pick_id = status_id;
    status_apply_pending = true;
  }
}

static void openStatusPicker() {
  if (!backendIsFilaMan() || !sm_found || sm_id <= 0) return;
  showStatusPicker(sm_status_id, onStatusPicked);
}

void buildMoreInfoScreen() {
  logSD("BUILD: MoreInfoScreen");
  // Full-screen dimmed backdrop
  scr_more_info = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_more_info, 480, 320);
  lv_obj_set_pos(scr_more_info, 0, 0);
  lv_obj_set_style_bg_color(scr_more_info, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_more_info, LV_OPA_50, 0);
  lv_obj_set_style_border_width(scr_more_info, 0, 0);
  lv_obj_set_style_radius(scr_more_info, 0, 0);
  lv_obj_set_style_pad_all(scr_more_info, 0, 0);
  lv_obj_clear_flag(scr_more_info, LV_OBJ_FLAG_SCROLLABLE);

  // Inner box: 464x300, teal border, 8px margins
  lv_obj_t *box = lv_obj_create(scr_more_info);
  lv_obj_set_size(box, 464, 300);
  lv_obj_set_pos(box, 8, 10);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0b1525), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, 10, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // ── Header 52px (larger for 44px X button) ──────────────
  lv_obj_t *hdr = lv_obj_create(box);
  lv_obj_set_size(hdr, 464, 52);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  // Title - Fix 12: always "More info filament" in both languages
  lv_obj_t *lbl_title = lv_label_create(hdr);
  lv_label_set_text(lbl_title, "Filament");
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);

  // Status chip - left half of the header, which holds nothing else. The box
  // below is full to the pixel, this costs no vertical space at all.
  // FilaMan only: it is the one backend with a status worth showing and worth
  // changing. Spoolman has just archived:bool and BamBuddy just an archive
  // route, and for those the weight popup's reactivate button is the way back,
  // so a chip here would be a second control for a single boolean.
  if (backendIsFilaMan() && sm_found && sm_id > 0) {
    buildStatusChip(hdr, 10, 4, sm_status_id, [](lv_event_t *e) {
      if (!wifiManagerIsConnected()) return;
      show_status_picker_pending = true;
    });
  }

  // Close X button - Fix 10: 44x44px proper size
  lv_obj_t *btn_x = lv_btn_create(hdr);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_RIGHT_MID, -10, 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_x, 1, 0);
  lv_obj_set_style_border_color(btn_x, lv_color_hex(0x601010), 0);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e) {
    if (scr_more_info) { lv_obj_del(scr_more_info); scr_more_info = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);

  // Header separator (below header, Fix 10: at y=52)
  lv_obj_t *hdiv = lv_obj_create(box);
  lv_obj_set_size(hdiv, 464, 1);
  lv_obj_set_pos(hdiv, 0, 52);
  lv_obj_set_style_bg_color(hdiv, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(hdiv, 0, 0);
  lv_obj_set_style_radius(hdiv, 0, 0);
  lv_obj_set_style_pad_all(hdiv, 0, 0);

  // ── Swatch row: caps y=60, values on baseline 91 ─────────
  // Cap: ID. These three used to be 0x2a4060, which the design guide asks
  // for and which is 1.7:1 on this background - a shape colour used as text.
  lv_obj_t *mi_id_cap = lv_label_create(box);
  lv_label_set_text(mi_id_cap, "ID");
  lv_obj_set_style_text_color(mi_id_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(mi_id_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(mi_id_cap, 60, 60);

  // Centred on the text line beside it (60..95), rather than hanging below it
  lv_obj_t *swatch = lv_obj_create(box);
  lv_obj_set_size(swatch, 42, 42);
  lv_obj_set_pos(swatch, 10, 56);
  lv_obj_set_style_radius(swatch, 6, 0);
  lv_obj_set_style_border_color(swatch, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_border_width(swatch, 1, 0);
  lv_obj_set_style_pad_all(swatch, 0, 0);
  lv_obj_clear_flag(swatch, LV_OBJ_FLAG_SCROLLABLE);
  // The same colour the home screen shows: the tag's where it names one, the
  // server's where it does not. An NTAG has no tag colour here, so the server
  // decides alone.
  SpoolColor server_color;
  spoolColorParse(sm_color_global, &server_color);
  swatchPaint(swatch, spoolColorResolve(g_tag.color, server_color));

  // SM-ID value
  lv_obj_t *lbl_id = lv_label_create(box);
  char id_buf[12];
  if (sm_found && sm_id > 0) snprintf(id_buf, sizeof(id_buf), "%d", sm_id);
  else strncpy(id_buf, "?", sizeof(id_buf)-1);
  lv_label_set_text(lbl_id, id_buf);
  lv_obj_set_style_text_color(lbl_id,
    (sm_found && sm_id > 0) ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_id, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_id, 60, 76);
  // Every value label on this card gets a real height, one line of its font:
  // with LV_SIZE_CONTENT a text wider than the label wraps to a second line
  // and LV_LABEL_LONG_DOT never engages, because there is no height to be
  // too tall for. The second line then ran through the divider below, or
  // over the caption of the next row. Same fix as on the AMS detail card.
  lv_obj_set_size(lbl_id, 46, lv_font_get_line_height(&lv_font_montserrat_ext_16));
  lv_label_set_long_mode(lbl_id, LV_LABEL_LONG_DOT);

  // Cap: Material
  lv_obj_t *mi_mat_cap = lv_label_create(box);
  lv_label_set_text(mi_mat_cap, T(STR_LBL_MATERIAL));
  lv_obj_set_style_text_color(mi_mat_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(mi_mat_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(mi_mat_cap, 114, 60);

  // Material value - for NTAG spools use sm_material (from Spoolman), for Bambu use g_tag.material
  lv_obj_t *lbl_mat = lv_label_create(box);
  const char* mat_val = (strlen(sm_material_global) > 0) ? sm_material_global :
                        (strlen(g_tag.material) > 0 ? g_tag.material : "-");
  lv_label_set_text(lbl_mat, mat_val);
  lv_obj_set_style_text_color(lbl_mat, lv_color_hex(0xf0f0f0), 0);
  lv_obj_set_style_text_font(lbl_mat, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_pos(lbl_mat, 114, 74);
  lv_obj_set_size(lbl_mat, 114, lv_font_get_line_height(&lv_font_montserrat_ext_18));
  lv_label_set_long_mode(lbl_mat, LV_LABEL_LONG_DOT);

  // Cap: Filament
  lv_obj_t *mi_fn_cap = lv_label_create(box);
  lv_label_set_text(mi_fn_cap, "Filament");
  lv_obj_set_style_text_color(mi_fn_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(mi_fn_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(mi_fn_cap, 236, 60);

  // Filament name value
  lv_obj_t *lbl_fn = lv_label_create(box);
  lv_label_set_text(lbl_fn, strlen(sm_filament_name) > 0 ? sm_filament_name : "-");
  lv_obj_set_style_text_color(lbl_fn, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_fn, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_fn, 236, 76);
  lv_obj_set_size(lbl_fn, 218, lv_font_get_line_height(&lv_font_montserrat_ext_16));
  lv_label_set_long_mode(lbl_fn, LV_LABEL_LONG_DOT);

  // Separator after swatch row
  lv_obj_t *div1 = lv_obj_create(box);
  lv_obj_set_size(div1, 444, 1);
  lv_obj_set_pos(div1, 10, 104);
  lv_obj_set_style_bg_color(div1, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(div1, 0, 0);
  lv_obj_set_style_radius(div1, 0, 0);
  lv_obj_set_style_pad_all(div1, 0, 0);

  // ── 2x2 grid, then UID and UUID ─────────────────────────
  // Col A: x=10, Col B: x=236, both 218 wide
  // Row 1 caps y=110, values y=124   (baselines 123 / 141)
  // Row 2 caps y=154, values y=168   (baselines 167 / 185)
  // separator y=196
  // Row 3 caps y=202: UID (A) | location button (B)
  // Row 4 caps y=256: Spoolman UUID (A) | unlink button (B)
  const int CA = 10, CB = 236;
  const int CW = 218;  // reserved width of a column
  const int VF = 14;   // cap y to value y, for a font 18 value on a font 12 cap
  const int R1 = 110, R2 = 154, R3 = 202, R4 = 256;
  const int VF16 = 16;  // same 18 px baseline distance, for a font 16 value

  // Row 1 Left: hex colour
  char hex_cap[24]; copyT(hex_cap, sizeof(hex_cap), STR_LBL_HEX_COLOR);
  lv_obj_t *c1 = lv_label_create(box);
  lv_label_set_text(c1, hex_cap);
  lv_obj_set_style_text_color(c1, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c1, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(c1, CA, R1);
  lv_obj_t *v1 = lv_label_create(box);
  // What the tag holds, alpha included - "#00000000" is how Bambu writes a
  // clear filament, and showing it explains the swatch. The server's value
  // where there is no tag colour.
  char color_display[SPOOL_COLOR_HEX_MAX];
  spoolColorFormat(g_tag.color.valid ? g_tag.color : server_color,
                   color_display, sizeof(color_display));
  lv_label_set_text(v1, color_display[0] ? color_display : "-");
  lv_obj_set_style_text_color(v1, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(v1, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_pos(v1, CA, R1 + VF);
  lv_obj_set_size(v1, CW, lv_font_get_line_height(&lv_font_montserrat_ext_18));
  lv_label_set_long_mode(v1, LV_LABEL_LONG_DOT);

  // Row 1 Right: production date
  char prod_cap[24]; copyT(prod_cap, sizeof(prod_cap), STR_LBL_PRODUCTION_DATE);
  lv_obj_t *c2 = lv_label_create(box);
  lv_label_set_text(c2, prod_cap);
  lv_obj_set_style_text_color(c2, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c2, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(c2, CB, R1);
  lv_obj_t *v2 = lv_label_create(box);
  lv_label_set_text(v2, strlen(g_tag.production_date) > 4 ? g_tag.production_date : "-");
  lv_obj_set_style_text_color(v2, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(v2, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_pos(v2, CB, R1 + VF);
  lv_obj_set_size(v2, CW, lv_font_get_line_height(&lv_font_montserrat_ext_18));
  lv_label_set_long_mode(v2, LV_LABEL_LONG_DOT);

  // Row 2 Left: Article no.
  char art_cap[24]; copyT(art_cap, sizeof(art_cap), STR_LBL_ARTICLE_NO_SHORT);
  lv_obj_t *c3 = lv_label_create(box);
  lv_label_set_text(c3, art_cap);
  lv_obj_set_style_text_color(c3, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c3, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(c3, CA, R2);
  lv_obj_t *v3 = lv_label_create(box);
  lv_label_set_text(v3, strlen(sm_article_nr) > 0 ? sm_article_nr : "-");
  lv_obj_set_style_text_color(v3, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(v3, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_pos(v3, CA, R2 + VF);
  lv_obj_set_size(v3, CW, lv_font_get_line_height(&lv_font_montserrat_ext_18));
  lv_label_set_long_mode(v3, LV_LABEL_LONG_DOT);

  // Row 2 Right: Spool weight (empty)
  char sw_cap[24]; copyT(sw_cap, sizeof(sw_cap), STR_LBL_SPOOL_WEIGHT_EMPTY);
  lv_obj_t *c4 = lv_label_create(box);
  lv_label_set_text(c4, sw_cap);
  lv_obj_set_style_text_color(c4, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c4, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(c4, CB, R2);
  lv_obj_t *v4 = lv_label_create(box);
  // An inherited tare is marked, so a number that came from the brand default
  // is not mistaken for one measured off this spool.
  char sw_buf[32];
  if (sm_spool_weight > 0) {
    const char *from = (sm_tare_source == TARE_FILAMENT) ? T(STR_TARE_FROM_FILAMENT)
                     : (sm_tare_source == TARE_VENDOR)   ? T(STR_TARE_FROM_BRAND)
                     : "";
    snprintf(sw_buf, sizeof(sw_buf), "%.0f g%s", sm_spool_weight, from);
  } else {
    strncpy(sw_buf, "-", sizeof(sw_buf)-1);
  }
  lv_label_set_text(v4, sw_buf);
  lv_obj_set_style_text_color(v4, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(v4, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_pos(v4, CB, R2 + VF);
  lv_obj_set_size(v4, CW, lv_font_get_line_height(&lv_font_montserrat_ext_18));
  lv_label_set_long_mode(v4, LV_LABEL_LONG_DOT);

  // Separator before UID+UUID
  lv_obj_t *div2 = lv_obj_create(box);
  lv_obj_set_size(div2, 444, 1);
  lv_obj_set_pos(div2, 10, 196);
  lv_obj_set_style_bg_color(div2, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(div2, 0, 0);
  lv_obj_set_style_radius(div2, 0, 0);
  lv_obj_set_style_pad_all(div2, 0, 0);

  // UID left, location button right - both starting on y=202
  lv_obj_t *c_uid = lv_label_create(box);
  lv_label_set_text(c_uid, "UID");
  lv_obj_set_style_text_color(c_uid, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c_uid, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(c_uid, CA, R3);
  lv_obj_t *v_uid = lv_label_create(box);
  lv_label_set_text(v_uid, strlen(g_tag.uid_str) > 0 ? g_tag.uid_str : "-");
  lv_obj_set_style_text_color(v_uid, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(v_uid, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(v_uid, CA, R3 + VF16);
  lv_obj_set_size(v_uid, CW, lv_font_get_line_height(&lv_font_montserrat_ext_16));
  lv_label_set_long_mode(v_uid, LV_LABEL_LONG_DOT);

  // Location button - column B of row 3, top edge flush with the UID caption
  lv_obj_t *btn_loc = lv_btn_create(box);
  lv_obj_set_size(btn_loc, CW, 46);
  lv_obj_set_pos(btn_loc, CB, R3);
  lv_obj_set_style_bg_color(btn_loc, lv_color_hex(0x0d2040), 0);
  lv_obj_set_style_bg_color(btn_loc, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_border_color(btn_loc, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(btn_loc, 1, 0);
  lv_obj_set_style_radius(btn_loc, 8, 0);
  lv_obj_set_style_shadow_width(btn_loc, 0, 0);
  lv_obj_set_style_pad_all(btn_loc, 0, 0);
  // Cap label - centered, shifted 2px up from center
  lv_obj_t *btn_loc_cap = lv_label_create(btn_loc);
  char loc_cap_buf[32];
  copyT(loc_cap_buf, sizeof(loc_cap_buf), STR_BTN_LOCATION);
  lv_label_set_text(btn_loc_cap, loc_cap_buf);
  lv_obj_set_style_text_color(btn_loc_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(btn_loc_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(btn_loc_cap, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(btn_loc_cap, LV_ALIGN_CENTER, 0, -11);
  // Value label - centered
  lv_obj_t *btn_loc_val = lv_label_create(btn_loc);
  char loc_val_buf[48];
  strncpy(loc_val_buf, sm_location_name[0] ? sm_location_name : "-", sizeof(loc_val_buf)-1);
  loc_val_buf[sizeof(loc_val_buf)-1] = '\0';
  lv_label_set_text(btn_loc_val, loc_val_buf);
  lv_obj_set_style_text_color(btn_loc_val, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(btn_loc_val, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(btn_loc_val, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_size(btn_loc_val, CW - 14, lv_font_get_line_height(&lv_font_montserrat_ext_16));
  lv_label_set_long_mode(btn_loc_val, LV_LABEL_LONG_DOT);
  lv_obj_align(btn_loc_val, LV_ALIGN_CENTER, 0, 7);
  lv_obj_add_event_cb(btn_loc, [](lv_event_t *e) {
    if (!wifiManagerIsConnected()) {
      return;
    }
    requestLocationPicker(false);
  }, LV_EVENT_CLICKED, NULL);

  // Spoolman UUID left, unlink right - both ending on y=290
  lv_obj_t *c_uuid = lv_label_create(box);
  { char ub[32]; snprintf(ub, sizeof(ub), T(STR_BACKEND_UUID), backendName()); lv_label_set_text(c_uuid, ub); }
  lv_obj_set_style_text_color(c_uuid, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c_uuid, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(c_uuid, CA, R4);
  lv_obj_t *v_uuid = lv_label_create(box);
  lv_label_set_text(v_uuid,
    strlen(g_tag.tray_uuid) == 32 ? g_tag.tray_uuid : "-");
  lv_obj_set_style_text_color(v_uuid, lv_color_hex(0x4a7080), 0);
  lv_obj_set_style_text_font(v_uuid, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(v_uuid, CA, R4 + VF16);
  lv_obj_set_size(v_uuid, 330, lv_font_get_line_height(&lv_font_montserrat_ext_16));  // shortened to make room for Unlink button
  lv_label_set_long_mode(v_uuid, LV_LABEL_LONG_DOT);

  // Unlink button - bottom right, only visible when spool is linked (sm_found && sm_id > 0)
  if (sm_found && sm_id > 0) {
    lv_obj_t *btn_unlink = lv_btn_create(box);
    lv_obj_set_size(btn_unlink, 104, 34);
    lv_obj_set_pos(btn_unlink, 350, R4);
    lv_obj_set_style_bg_color(btn_unlink, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_unlink, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_unlink, 8, 0);
    lv_obj_set_style_shadow_width(btn_unlink, 0, 0);
    lv_obj_set_style_border_width(btn_unlink, 1, 0);
    lv_obj_set_style_border_color(btn_unlink, lv_color_hex(0x601010), 0);
    lv_obj_add_event_cb(btn_unlink, [](lv_event_t *e) {
      // Build confirmation popup on lv_scr_act() so it sits above more_info
      releaseScreen(&s_unlink_popup);
      lv_obj_t *pop = lv_obj_create(lv_scr_act());
      s_unlink_popup = pop;
      lv_obj_set_size(pop, 480, 320);
      lv_obj_set_pos(pop, 0, 0);
      lv_obj_set_style_bg_color(pop, lv_color_hex(0x000000), 0);
      lv_obj_set_style_bg_opa(pop, LV_OPA_80, 0);
      lv_obj_set_style_border_width(pop, 0, 0);
      lv_obj_set_style_radius(pop, 0, 0);
      lv_obj_set_style_pad_all(pop, 0, 0);
      lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

      // Two UIDs make "unlink" ambiguous: the tag on the scale, or the whole
      // binding including the one on the other flange, which the user cannot
      // see. One UID or a plain tag field has no such question, and there the
      // popup stays exactly what it always was.
      const int cu_count = smBoundUidCount();
      const bool cu_multi = (cu_count >= 2);
      // What is about to be cleared, by name. The old message said "clears the
      // tag field entry" and named neither which field nor that Spoolman's own
      // relation goes too - so an unlink that touched two places looked like it
      // touched one.
      char cu_src[96] = "";
      { size_t used = 0;
        for (uint8_t i = 0; i < TAG_FIELD_COUNT; i++) {
          if (!sm_tag_values[i][0]) continue;
          char nm[32];
          copyT(nm, sizeof(nm), tagFieldSpec(i).str_name);
          const size_t need = strlen(nm) + (used ? 2 : 0);
          if (used + need >= sizeof(cu_src)) break;
          if (used) { cu_src[used++] = ','; cu_src[used++] = ' '; }
          strcpy(cu_src + used, nm);
          used += strlen(nm);
        }
      }

      lv_obj_t *box2 = lv_obj_create(pop);
      lv_obj_set_size(box2, 420, cu_multi ? 262 : 210);
      lv_obj_align(box2, LV_ALIGN_CENTER, 0, 0);
      lv_obj_set_style_bg_color(box2, lv_color_hex(0x1a0808), 0);
      lv_obj_set_style_border_color(box2, lv_color_hex(0x602020), 0);
      lv_obj_set_style_border_width(box2, 2, 0);
      lv_obj_set_style_radius(box2, 12, 0);
      lv_obj_set_style_pad_all(box2, 0, 0);
      lv_obj_clear_flag(box2, LV_OBJ_FLAG_SCROLLABLE);

      lv_obj_t *lbl_t = lv_label_create(box2);
      char buf_t[48]; copyT(buf_t, sizeof(buf_t), STR_UNLINK_TITLE);
      lv_label_set_text(lbl_t, buf_t);
      lv_obj_set_style_text_color(lbl_t, lv_color_hex(0xff8080), 0);
      lv_obj_set_style_text_font(lbl_t, &lv_font_montserrat_ext_18, 0);
      lv_obj_align(lbl_t, LV_ALIGN_TOP_MID, 0, 16);

      lv_obj_t *lbl_m = lv_label_create(box2);
      char buf_m[288];
      if (cu_multi) copyT(buf_m, sizeof(buf_m), STR_UNLINK_MULTI_MSG);
      else          backendText(T(STR_UNLINK_MSG), buf_m, sizeof(buf_m));
      buf_m[sizeof(buf_m) - 1] = '\0';
      if (cu_src[0]) {
        const size_t used = strlen(buf_m);
        char line[128];
        snprintf(line, sizeof(line), T(STR_UNLINK_SOURCES), cu_src);
        snprintf(buf_m + used, sizeof(buf_m) - used, "\n%s", line);
      }
      lv_label_set_text(lbl_m, buf_m);
      lv_obj_set_style_text_color(lbl_m, lv_color_hex(0xc8d8f0), 0);
      lv_obj_set_style_text_font(lbl_m, &lv_font_montserrat_ext_14, 0);
      lv_obj_set_style_text_align(lbl_m, LV_TEXT_ALIGN_CENTER, 0);
      lv_label_set_long_mode(lbl_m, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(lbl_m, 380);
      lv_obj_align(lbl_m, LV_ALIGN_TOP_MID, 0, 48);

      // Cancel (links)
      lv_obj_t *btn_no = lv_btn_create(box2);
      lv_obj_set_size(btn_no, cu_multi ? 396 : 170, 44);
      lv_obj_set_pos(btn_no, 12, cu_multi ? 204 : 154);
      lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x0a1828), 0);
      lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x1a2840), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn_no, 8, 0);
      lv_obj_set_style_shadow_width(btn_no, 0, 0);
      lv_obj_set_style_border_width(btn_no, 1, 0);
      lv_obj_set_style_border_color(btn_no, lv_color_hex(0x1a2840), 0);
      lv_obj_add_event_cb(btn_no, [](lv_event_t *e) {
        releaseScreen(&s_unlink_popup);
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_no = lv_label_create(btn_no);
      char buf_no[32]; copyT(buf_no, sizeof(buf_no), STR_CANCEL);
      lv_label_set_text(lbl_no, buf_no);
      lv_obj_set_style_text_color(lbl_no, lv_color_hex(0x4a6fa0), 0);
      lv_obj_set_style_text_font(lbl_no, &lv_font_montserrat_ext_14, 0);
      lv_obj_align(lbl_no, LV_ALIGN_CENTER, 0, 0);

      // Confirm unlink (rechts, rot)
      lv_obj_t *btn_yes = lv_btn_create(box2);
      lv_obj_set_size(btn_yes, cu_multi ? 196 : 220, 44);
      lv_obj_set_pos(btn_yes, cu_multi ? 12 : 190, cu_multi ? 150 : 154);
      lv_obj_set_style_bg_color(btn_yes, lv_color_hex(0x3a1010), 0);
      lv_obj_set_style_bg_color(btn_yes, lv_color_hex(0x602020), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn_yes, 8, 0);
      lv_obj_set_style_shadow_width(btn_yes, 0, 0);
      lv_obj_set_style_border_width(btn_yes, 1, 0);
      lv_obj_set_style_border_color(btn_yes, lv_color_hex(0x602020), 0);
      // user_data carries whether this button means "all" or "only this one",
      // so both share the handler below.
      lv_obj_set_user_data(btn_yes, (void *)(intptr_t)(cu_multi ? 0 : 1));
      lv_obj_add_event_cb(btn_yes, unlinkConfirmCb, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_yes = lv_label_create(btn_yes);
      char buf_yes[48];
      copyT(buf_yes, sizeof(buf_yes), cu_multi ? STR_BTN_UNLINK_ONE : STR_UNLINK_CONFIRM);
      lv_label_set_text(lbl_yes, buf_yes);
      lv_obj_set_style_text_color(lbl_yes, lv_color_hex(0xff8080), 0);
      lv_obj_set_style_text_font(lbl_yes, &lv_font_montserrat_ext_14, 0);
      lv_obj_align(lbl_yes, LV_ALIGN_CENTER, 0, 0);

      if (cu_multi) {
        lv_obj_t *btn_all = lv_btn_create(box2);
        lv_obj_set_size(btn_all, 196, 44);
        lv_obj_set_pos(btn_all, 212, 150);
        lv_obj_set_style_bg_color(btn_all, lv_color_hex(0x3a1010), 0);
        lv_obj_set_style_bg_color(btn_all, lv_color_hex(0x602020), LV_STATE_PRESSED);
        lv_obj_set_style_radius(btn_all, 8, 0);
        lv_obj_set_style_shadow_width(btn_all, 0, 0);
        lv_obj_set_style_border_width(btn_all, 1, 0);
        lv_obj_set_style_border_color(btn_all, lv_color_hex(0x602020), 0);
        lv_obj_set_user_data(btn_all, (void *)(intptr_t)1);
        lv_obj_add_event_cb(btn_all, unlinkConfirmCb, LV_EVENT_CLICKED, NULL);
        lv_obj_t *lbl_all = lv_label_create(btn_all);
        char buf_all[48];
        copyT(buf_all, sizeof(buf_all), STR_BTN_UNLINK_ALL);
        lv_label_set_text(lbl_all, buf_all);
        lv_obj_set_style_text_color(lbl_all, lv_color_hex(0xff8080), 0);
        lv_obj_set_style_text_font(lbl_all, &lv_font_montserrat_ext_14, 0);
        lv_obj_align(lbl_all, LV_ALIGN_CENTER, 0, 0);
      }
    }, LV_EVENT_CLICKED, NULL);

    lv_obj_t *lbl_unlink = lv_label_create(btn_unlink);
    char buf_ul[16]; copyT(buf_ul, sizeof(buf_ul), STR_UNLINK_BTN);
    lv_label_set_text(lbl_unlink, buf_ul);
    lv_obj_set_style_text_color(lbl_unlink, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_unlink, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(lbl_unlink, LV_ALIGN_CENTER, 0, 0);
  }
}
