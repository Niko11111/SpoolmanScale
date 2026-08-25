#include "more_info_screen.h"
#include "navigation.h"
#include "app/app_state.h"

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
#include "services/backend_api.h"
#include "services/filaman_api.h"
#include "services/wifi_manager.h"
#include "lang.h"
#include "confirm_popup.h"
#include "tag_display.h"
#include "ui/tag_write_popup.h"
#include "ui_common.h"


void showLocationPicker();
void buildMoreInfoScreen();
void fetchAndFillLocationList();
static void showStatusPicker();
static void applyPickedStatus(int status_id);

static bool show_location_picker_pending = false;
static bool show_more_info_pending = false;
static bool fetch_locations_pending = false;
static bool g_loc_picker_from_popup = false;

static lv_obj_t *scr_location_picker = nullptr;

// Status picker. The chosen id is parked here rather than acted on in the row
// callback, so the overlay is gone before anything blocks on the network.
static lv_obj_t *scr_status_picker = nullptr;
static bool show_status_picker_pending = false;
static bool status_close_pending      = false;
static bool status_apply_pending      = false;
static bool status_archive_pending    = false;
static int  status_pick_id            = 0;   // 1..6, or 0 for "cancelled"

// Shared by both confirm buttons of the unlink popup. user_data is 1 for
// "release the whole binding" and 0 for "only the tag on the scale" - the
// distinction two UIDs create and a single one does not have.
static void unlinkConfirmCb(lv_event_t *e) {
  lv_obj_t *btn = lv_event_get_target(e);
  const bool all = (bool)(intptr_t)lv_obj_get_user_data(btn);
  const int spool_id = sm_id;

  // Read out of the button before the popup goes, then close it: the calls
  // below reach the network and a dialog still on screen would look frozen.
  lv_obj_del(lv_obj_get_parent(lv_obj_get_parent(btn)));

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
    if (backendIsFilaMan()) {
      char chip[24];
      tagUidNormalize(g_tag.uid_str, chip, sizeof(chip));
      filamanUnlinkBambuFields(backendBaseUrl(), filamanApiKey(), spool_id, chip);
    }
    logSDf("Unlink spool ID=%d", spool_id);
  }
  Serial.printf("Unlink spool ID=%d all=%d\n", spool_id, all ? 1 : 0);

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
    showStatusPicker();
  }
  if (status_apply_pending) {
    status_apply_pending = false;
    applyPickedStatus(status_pick_id);
  }
  if (status_archive_pending) {
    status_archive_pending = false;
    showConfirmPopup(T(STR_ARCHIVE_CONFIRM), 3);
  }
  // Deliberately last. releaseScreen() frees asynchronously, and appLoop()
  // runs lv_timer_handler() before it gets here, so a flag set below is only
  // read on the next pass - by which time the overlay is really gone and the
  // blocking POST cannot freeze the screen with the picker still on it.
  if (status_close_pending) {
    status_close_pending = false;
    releaseScreen(&scr_status_picker);
    if (status_pick_id == FILAMAN_STATUS_ARCHIVED) {
      // Archiving empties the spool and unlinks it, so the detail view behind
      // the picker is about to be wrong either way. patchArchiveSpool() writes
      // its result onto the main screen.
      releaseScreen(&scr_more_info);
      status_archive_pending = true;
    } else if (status_pick_id > 0 && status_pick_id != sm_status_id) {
      status_apply_pending = true;
    }
  }
}

// Both pickers, from the one list hideAllOverlays() already is. Neither used
// to be in it, so navigating away from the location picker left it standing.
void hideMoreInfoOverlays() {
  releaseScreen(&scr_location_picker);
  releaseScreen(&scr_status_picker);
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
  if (scr_location_picker) { lv_obj_del(scr_location_picker); scr_location_picker = nullptr; }
  if (!sm_found || sm_id <= 0) return;

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
  strncpy(title_buf, T(STR_LOCATION_TITLE), sizeof(title_buf)-1);
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
    if (scr_location_picker) { lv_obj_del(scr_location_picker); scr_location_picker = nullptr; }
    if (g_loc_picker_from_popup) { showMainScreen(); }
    else { showMoreInfoScreen(); }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);

  // Status label (loading / error)
  lv_obj_t *lbl_status = lv_label_create(box);
  char status_buf[48];
  strncpy(status_buf, T(STR_LOCATION_LOADING), sizeof(status_buf)-1);
  lv_label_set_text(lbl_status, status_buf);
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_status, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_status, LV_ALIGN_CENTER, 0, 10);

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
  loc_status_obj = lbl_status;
  loc_list_obj   = list;

  // Trigger async HTTP fetch via loop()
  if (!wifiManagerIsConnected()) {
    char buf[32]; strncpy(buf, T(STR_LOCATION_NO_WIFI), sizeof(buf)-1);
    lv_label_set_text(lbl_status, buf);
    return;
  }
  fetch_locations_pending = true;
}

void fetchAndFillLocationList() {
  logSD("LOC: fetchAndFillLocationList called");
  if (!loc_list_obj || !loc_status_obj) { logSD("LOC: null refs, abort"); return; }
  if (!scr_location_picker) { logSD("LOC: picker gone, abort"); return; }

  // Mehrere LVGL-Ticks geben damit das Overlay vollständig gerendert ist
  for (int i = 0; i < 5; i++) {
    lv_task_handler();
    delay(20);
  }

  logSDf("LOC: GET %s/api/v1/location", cfg_spoolman_base);
  JsonDocument doc;
  DeserializationError err = DeserializationError::Ok;
  int code = backendGetLocationsJson(cfg_spoolman_base, doc, 8000, &err);
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
  lv_obj_set_size(btn_none, 370, 44);
  lv_obj_set_style_bg_color(btn_none, lv_color_hex(0x0d2040), 0);
  lv_obj_set_style_bg_color(btn_none, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_border_color(btn_none, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(btn_none, 1, 0);
  lv_obj_set_style_radius(btn_none, 6, 0);
  lv_obj_set_style_shadow_width(btn_none, 0, 0);
  lv_obj_set_style_pad_bottom(btn_none, 4, 0);
  lv_obj_t *lbl_none = lv_label_create(btn_none);
  char none_buf[48]; strncpy(none_buf, T(STR_LOCATION_NONE), sizeof(none_buf)-1);
  lv_label_set_text(lbl_none, none_buf);
  lv_obj_set_style_text_color(lbl_none, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_none, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_none);
  lv_obj_add_event_cb(btn_none, [](lv_event_t *e) {
    if (!wifiManagerIsConnected() || sm_id <= 0) return;
    int code = backendPatchSpoolLocation(cfg_spoolman_base, sm_id, nullptr, 8000);
    if (code == 200) {
      sm_location_id = 0;
      sm_location_name[0] = '\0';
    }
    if (scr_location_picker) { lv_obj_del(scr_location_picker); scr_location_picker = nullptr; }
    if (g_loc_picker_from_popup) { showMainScreen(); }
    else { showMoreInfoScreen(); }
  }, LV_EVENT_CLICKED, NULL);

  logLvMem("loclist/pre", 0);
  // Location rows — API gibt Array von Strings zurück
  int loc_shown = 0;
  bool loc_limit_hit = false;
  for (JsonVariant v : locs) {
    if (loc_shown >= location_list_limit) { loc_limit_hit = true; break; }
    char loc_name[48];
    strncpy(loc_name, v.as<const char*>() ? v.as<const char*>() : "-", sizeof(loc_name)-1);
    loc_name[sizeof(loc_name)-1] = '\0';

    lv_obj_t *row = lv_btn_create(list);
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
      const char* sel_name = lv_label_get_text(lbl);
      int code = backendPatchSpoolLocation(cfg_spoolman_base, sm_id, sel_name, 8000);
      if (code == 200) {
        strncpy(sm_location_name, sel_name, sizeof(sm_location_name)-1);
        sm_location_name[sizeof(sm_location_name)-1] = '\0';
        sm_location_id = 0;
        // Mark popup as shown so it doesn't re-trigger on next tag-remove
        g_loc_popup_shown_for_id = sm_id;
        logSDf("[verbose] LOC: location saved '%s' id=%d from_popup=%d", sel_name, sm_id, (int)g_loc_picker_from_popup);
      }
      if (scr_location_picker) { lv_obj_del(scr_location_picker); scr_location_picker = nullptr; }
      if (g_loc_picker_from_popup) { showMainScreen(); }
      else { showMoreInfoScreen(); }
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
    char limit_buf[64]; strncpy(limit_buf, T(STR_LOCATION_LIMIT_HIT), sizeof(limit_buf)-1);
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
  char hint_buf[64]; strncpy(hint_buf, T(STR_LOCATION_HINT_EMPTY), sizeof(hint_buf)-1);
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
// stage the way the location picker does.
static StringID statusStrId(int status_id) {
  switch (status_id) {
    case FILAMAN_STATUS_NEW:      return STR_STATUS_NEW;
    case FILAMAN_STATUS_OPENED:   return STR_STATUS_OPENED;
    case FILAMAN_STATUS_DRYING:   return STR_STATUS_DRYING;
    case FILAMAN_STATUS_ACTIVE:   return STR_STATUS_ACTIVE;
    case FILAMAN_STATUS_EMPTY:    return STR_STATUS_EMPTY;
    case FILAMAN_STATUS_ARCHIVED: return STR_ARCHIVED;
    default:                      return STR_STATUS_UNKNOWN;
  }
}

static uint32_t statusColor(int status_id) {
  switch (status_id) {
    case FILAMAN_STATUS_NEW:      return 0x8ab0d8;
    case FILAMAN_STATUS_OPENED:   return 0x28d49a;
    case FILAMAN_STATUS_DRYING:   return 0xf0b838;
    case FILAMAN_STATUS_ACTIVE:   return 0x28d49a;
    case FILAMAN_STATUS_EMPTY:    return 0xe04040;
    case FILAMAN_STATUS_ARCHIVED: return 0x808080;
    default:                      return 0x4a6fa0;
  }
}

// Runs from handleMoreInfoDeferredActions(), never from a row callback: it
// blocks for as long as the server takes.
static void applyPickedStatus(int status_id) {
  const char* key = filamanStatusKey(status_id);
  if (!key || sm_id <= 0) return;
  if (!wifiManagerIsConnected()) return;

  int code = backendSetSpoolStatus(cfg_spoolman_base, sm_id, key, 5000);
  logSDf("status: spool %d -> %s HTTP %d", sm_id, key, code);
  if (code == 200) sm_status_id = status_id;
  // Rebuilt either way. On failure the chip goes back to showing the truth.
  show_more_info_pending = true;
}

static void statusRowCb(lv_event_t *e) {
  status_pick_id = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
  status_close_pending = true;
}

static void showStatusPicker() {
  releaseScreen(&scr_status_picker);
  if (!backendIsFilaMan() || !sm_found || sm_id <= 0) return;

  // Backdrop
  scr_status_picker = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_status_picker, 480, 320);
  lv_obj_set_pos(scr_status_picker, 0, 0);
  lv_obj_set_style_bg_color(scr_status_picker, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_status_picker, LV_OPA_70, 0);
  lv_obj_set_style_border_width(scr_status_picker, 0, 0);
  lv_obj_set_style_radius(scr_status_picker, 0, 0);
  lv_obj_set_style_pad_all(scr_status_picker, 0, 0);
  lv_obj_clear_flag(scr_status_picker, LV_OBJ_FLAG_SCROLLABLE);

  // Inner box - same dimensions as the location picker so both read alike
  lv_obj_t *box = lv_obj_create(scr_status_picker);
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
  strncpy(title_buf, T(STR_STATUS_TITLE), sizeof(title_buf)-1);
  title_buf[sizeof(title_buf)-1] = '\0';
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
    status_pick_id = 0;
    status_close_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);

  // 2x3 grid. Six fixed values do not earn a scroll list, and a grid saves
  // the mis-tap a narrow row invites on a touchscreen.
  const int CELL_W = 186;
  const int CELL_H = 66;
  const int COL_X[2] = { 10, 204 };
  const int ROW_Y[3] = { 54, 128, 202 };

  for (int id = FILAMAN_STATUS_NEW; id <= FILAMAN_STATUS_COUNT; id++) {
    const int idx = id - 1;
    const bool is_current = (id == sm_status_id);
    const bool is_archive = (id == FILAMAN_STATUS_ARCHIVED);

    lv_obj_t *cell = lv_btn_create(box);
    lv_obj_set_size(cell, CELL_W, CELL_H);
    lv_obj_set_pos(cell, COL_X[idx % 2], ROW_Y[idx / 2]);
    lv_obj_set_style_radius(cell, 8, 0);
    lv_obj_set_style_shadow_width(cell, 0, 0);
    lv_obj_set_style_border_width(cell, 1, 0);
    lv_obj_set_style_pad_all(cell, 0, 0);

    uint32_t txt_col;
    if (is_current) {
      // Same "this is the one you have" language as the location rows.
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x0d3020), 0);
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(cell, lv_color_hex(0x28d49a), 0);
      txt_col = 0x28d49a;
    } else if (is_archive) {
      // The archive vocabulary from the weight popup, so the one cell that
      // asks a question before it acts announces itself.
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x3a1a00), 0);
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x6a3000), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(cell, lv_color_hex(0x6a3000), 0);
      txt_col = 0xffb060;
    } else {
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x0d2040), 0);
      lv_obj_set_style_bg_color(cell, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(cell, lv_color_hex(0x0f1e30), 0);
      txt_col = 0xf0f0f0;
    }

    lv_obj_set_user_data(cell, (void*)(intptr_t)id);
    lv_obj_add_event_cb(cell, statusRowCb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *lbl = lv_label_create(cell);
    char cell_buf[32];
    strncpy(cell_buf, T(statusStrId(id)), sizeof(cell_buf)-1);
    cell_buf[sizeof(cell_buf)-1] = '\0';
    lv_label_set_text(lbl, cell_buf);
    lv_obj_set_style_text_color(lbl, lv_color_hex(txt_col), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(lbl, CELL_W - 12);
    lv_label_set_long_mode(lbl, LV_LABEL_LONG_DOT);
    lv_obj_center(lbl);
  }
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

  // Title — Fix 12: always "More info filament" in both languages
  lv_obj_t *lbl_title = lv_label_create(hdr);
  lv_label_set_text(lbl_title, "Filament");
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);

  // Status chip — left half of the header, which holds nothing else. The box
  // below is full to the pixel, this costs no vertical space at all.
  // FilaMan only: Spoolman has just archived:bool and BamBuddy just an
  // archive route, and an archived spool leaves sm_found false anyway, so the
  // chip would never appear there.
  if (backendIsFilaMan() && sm_found && sm_id > 0) {
    const uint32_t st_col = statusColor(sm_status_id);
    lv_obj_t *chip = lv_btn_create(hdr);
    lv_obj_set_size(chip, 150, 44);
    lv_obj_set_pos(chip, 10, 4);
    lv_obj_set_style_bg_color(chip, lv_color_hex(0x0d2040), 0);
    lv_obj_set_style_bg_color(chip, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(chip, lv_color_hex(st_col), 0);
    lv_obj_set_style_border_width(chip, 1, 0);
    lv_obj_set_style_radius(chip, 8, 0);
    lv_obj_set_style_shadow_width(chip, 0, 0);
    lv_obj_set_style_pad_all(chip, 0, 0);
    lv_obj_add_event_cb(chip, [](lv_event_t *e) {
      if (!wifiManagerIsConnected()) return;
      show_status_picker_pending = true;
    }, LV_EVENT_CLICKED, NULL);

    // Cap is identical in both languages, like "Filament" and "Material".
    lv_obj_t *chip_cap = lv_label_create(chip);
    lv_label_set_text(chip_cap, "Status");
    lv_obj_set_style_text_color(chip_cap, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(chip_cap, &lv_font_montserrat_ext_12, 0);
    lv_obj_align(chip_cap, LV_ALIGN_CENTER, 0, -10);

    lv_obj_t *chip_val = lv_label_create(chip);
    char st_buf[24];
    strncpy(st_buf, T(statusStrId(sm_status_id)), sizeof(st_buf)-1);
    st_buf[sizeof(st_buf)-1] = '\0';
    lv_label_set_text(chip_val, st_buf);
    lv_obj_set_style_text_color(chip_val, lv_color_hex(st_col), 0);
    lv_obj_set_style_text_font(chip_val, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(chip_val, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(chip_val, 134);
    lv_label_set_long_mode(chip_val, LV_LABEL_LONG_DOT);
    lv_obj_align(chip_val, LV_ALIGN_CENTER, 0, 8);
  }

  // Close X button — Fix 10: 44x44px proper size
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
  // Swatch color: prefer tag color (Bambu), fall back to Spoolman color (NTAG)
  const char* swatch_hex = (strlen(g_tag.color_hex) == 7) ? g_tag.color_hex :
                           (strlen(sm_color_global) >= 6 ? sm_color_global : nullptr);
  // swatchColorFromHex() handles the nullptr and malformed cases itself
  lv_obj_set_style_bg_color(swatch, swatchColorFromHex(swatch_hex), 0);

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
  lv_label_set_long_mode(lbl_id, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_id, 46);

  // Cap: Material
  lv_obj_t *mi_mat_cap = lv_label_create(box);
  lv_label_set_text(mi_mat_cap, "Material");
  lv_obj_set_style_text_color(mi_mat_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(mi_mat_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(mi_mat_cap, 114, 60);

  // Material value — for NTAG spools use sm_material (from Spoolman), for Bambu use g_tag.material
  lv_obj_t *lbl_mat = lv_label_create(box);
  const char* mat_val = (strlen(sm_material_global) > 0) ? sm_material_global :
                        (strlen(g_tag.material) > 0 ? g_tag.material : "-");
  lv_label_set_text(lbl_mat, mat_val);
  lv_obj_set_style_text_color(lbl_mat, lv_color_hex(0xf0f0f0), 0);
  lv_obj_set_style_text_font(lbl_mat, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_pos(lbl_mat, 114, 74);
  lv_label_set_long_mode(lbl_mat, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_mat, 114);

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
  lv_label_set_long_mode(lbl_fn, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_fn, 218);

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
  char hex_cap[24]; strncpy(hex_cap, T(STR_LBL_HEX_COLOR), sizeof(hex_cap)-1);
  hex_cap[sizeof(hex_cap)-1] = '\0';
  lv_obj_t *c1 = lv_label_create(box);
  lv_label_set_text(c1, hex_cap);
  lv_obj_set_style_text_color(c1, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c1, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(c1, CA, R1);
  lv_obj_t *v1 = lv_label_create(box);
  const char* color_display = (strlen(g_tag.color_hex) > 1) ? g_tag.color_hex :
                              (strlen(sm_color_global) > 1 ? sm_color_global : "-");
  lv_label_set_text(v1, color_display);
  lv_obj_set_style_text_color(v1, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(v1, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_pos(v1, CA, R1 + VF);
  lv_label_set_long_mode(v1, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v1, CW);

  // Row 1 Right: production date
  char prod_cap[24]; strncpy(prod_cap, T(STR_LBL_PRODUCTION_DATE), sizeof(prod_cap)-1);
  prod_cap[sizeof(prod_cap)-1] = '\0';
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
  lv_label_set_long_mode(v2, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v2, CW);

  // Row 2 Left: Article no.
  char art_cap[24]; strncpy(art_cap, T(STR_LBL_ARTICLE_NO_SHORT), sizeof(art_cap)-1);
  art_cap[sizeof(art_cap)-1] = '\0';
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
  lv_label_set_long_mode(v3, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v3, CW);

  // Row 2 Right: Spool weight (empty)
  char sw_cap[24]; strncpy(sw_cap, T(STR_LBL_SPOOL_WEIGHT_EMPTY), sizeof(sw_cap)-1);
  sw_cap[sizeof(sw_cap)-1] = '\0';
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
  lv_label_set_long_mode(v4, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v4, CW);

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
  lv_label_set_long_mode(v_uid, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v_uid, CW);

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
  // Cap label — centered, shifted 2px up from center
  lv_obj_t *btn_loc_cap = lv_label_create(btn_loc);
  char loc_cap_buf[32];
  strncpy(loc_cap_buf, T(STR_BTN_LOCATION), sizeof(loc_cap_buf)-1);
  lv_label_set_text(btn_loc_cap, loc_cap_buf);
  lv_obj_set_style_text_color(btn_loc_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(btn_loc_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(btn_loc_cap, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(btn_loc_cap, LV_ALIGN_CENTER, 0, -11);
  // Value label — centered
  lv_obj_t *btn_loc_val = lv_label_create(btn_loc);
  char loc_val_buf[48];
  strncpy(loc_val_buf, sm_location_name[0] ? sm_location_name : "-", sizeof(loc_val_buf)-1);
  loc_val_buf[sizeof(loc_val_buf)-1] = '\0';
  lv_label_set_text(btn_loc_val, loc_val_buf);
  lv_obj_set_style_text_color(btn_loc_val, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(btn_loc_val, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(btn_loc_val, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(btn_loc_val, CW - 14);
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
  { char ub[32]; snprintf(ub, sizeof(ub), "%s UUID", backendName()); lv_label_set_text(c_uuid, ub); }
  lv_obj_set_style_text_color(c_uuid, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c_uuid, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(c_uuid, CA, R4);
  lv_obj_t *v_uuid = lv_label_create(box);
  lv_label_set_text(v_uuid,
    strlen(g_tag.tray_uuid) == 32 ? g_tag.tray_uuid : "-");
  lv_obj_set_style_text_color(v_uuid, lv_color_hex(0x4a7080), 0);
  lv_obj_set_style_text_font(v_uuid, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(v_uuid, CA, R4 + VF16);
  lv_label_set_long_mode(v_uuid, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v_uuid, 330);  // shortened to make room for Unlink button

  // Unlink button — bottom right, only visible when spool is linked (sm_found && sm_id > 0)
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
      lv_obj_t *pop = lv_obj_create(lv_scr_act());
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
      char buf_t[48]; strncpy(buf_t, T(STR_UNLINK_TITLE), sizeof(buf_t)-1);
      lv_label_set_text(lbl_t, buf_t);
      lv_obj_set_style_text_color(lbl_t, lv_color_hex(0xff8080), 0);
      lv_obj_set_style_text_font(lbl_t, &lv_font_montserrat_ext_18, 0);
      lv_obj_align(lbl_t, LV_ALIGN_TOP_MID, 0, 16);

      lv_obj_t *lbl_m = lv_label_create(box2);
      char buf_m[192];
      if (cu_multi) snprintf(buf_m, sizeof(buf_m), T(STR_UNLINK_MULTI_MSG), cu_count);
      else          backendText(T(STR_UNLINK_MSG), buf_m, sizeof(buf_m));
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
        lv_obj_del(lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e))));
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_no = lv_label_create(btn_no);
      char buf_no[32]; strncpy(buf_no, T(STR_CANCEL), sizeof(buf_no)-1);
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
      strncpy(buf_yes, T(cu_multi ? STR_BTN_UNLINK_ONE : STR_UNLINK_CONFIRM), sizeof(buf_yes)-1);
      buf_yes[sizeof(buf_yes)-1] = '\0';
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
        strncpy(buf_all, T(STR_BTN_UNLINK_ALL), sizeof(buf_all)-1);
        buf_all[sizeof(buf_all)-1] = '\0';
        lv_label_set_text(lbl_all, buf_all);
        lv_obj_set_style_text_color(lbl_all, lv_color_hex(0xff8080), 0);
        lv_obj_set_style_text_font(lbl_all, &lv_font_montserrat_ext_14, 0);
        lv_obj_align(lbl_all, LV_ALIGN_CENTER, 0, 0);
      }
    }, LV_EVENT_CLICKED, NULL);

    lv_obj_t *lbl_unlink = lv_label_create(btn_unlink);
    char buf_ul[16]; strncpy(buf_ul, T(STR_UNLINK_BTN), sizeof(buf_ul)-1);
    lv_label_set_text(lbl_unlink, buf_ul);
    lv_obj_set_style_text_color(lbl_unlink, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_unlink, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(lbl_unlink, LV_ALIGN_CENTER, 0, 0);
  }
}
