#include "ui/spool_flow_internal.h"
#include "spool_flow.h"
#include "ui_common.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <lvgl.h>
#include <cstring>

#include "app_config.h"
#include "app/backend_switch.h"
#include "bambu/bambu_tag.h"
#include "bambu/material_match.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/backend_job.h"
#include "services/breadcrumb.h"
#include "services/list_limits.h"
#include "services/server_reach.h"
#include "services/spool_cache.h"
#include "services/spoolman_actions.h"
#include "services/tag_field.h"
#include "ui/info_popup.h"
#include "ui/link_wait_card.h"
#include "ui/loading_overlay.h"
#include "ui/main_screen_helpers.h"
#include "ui/navigation.h"
#include "ui/spoolman_lookup.h"
#include "ui/theme.h"

// From ui/spool_flow.cpp, see the same line in spoolman_lookup.cpp: what counts
// as bound, for the spool cache a download here fills.
bool spoolHasAnyTag(JsonObjectConst spool);

// ============================================================
//  THE COPY FLOW
//
//  Moved out of spool_flow.cpp word for word (v0.8.0-beta.47). What it shares
//  with the link flow is declared in spool_flow_internal.h. New in the same
//  step: the list of a Bambu copy loads on the backend worker behind the
//  waiting card, like the link list, instead of holding the loop.
// ============================================================

namespace {

// The inventory out of the cache goes into PSRAM like every list of it.
struct SpiRamAllocator : ArduinoJson::Allocator {
  void* allocate(size_t size) override {
    void* ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
    if (!ptr) ptr = malloc(size);
    return ptr;
  }
  void deallocate(void* pointer) override { heap_caps_free(pointer); }
  void* reallocate(void* ptr, size_t new_size) override {
    void* p = heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM);
    if (!p) p = realloc(ptr, new_size);
    return p;
  }
};

}

lv_obj_t *scr_copy_entry   = nullptr;  // entry screen (ID / active / archived)
lv_obj_t *scr_copy_list    = nullptr;  // spool list
bool copy_flow_archived = false;        // true = showing archived spools


static bool  copy_fetch_pending      = false;   // copy entry: active or archived spools
static bool  copy_fetch_archived     = false;
static bool  copy_create_pending     = false;   // copy confirm OK
static int   copy_create_sid = 0, copy_create_fid = 0;
static float copy_create_ini = 0.0f, copy_create_spw = 0.0f;
static int   copy_row_refresh_pending = -1;
static bool  copy_reload_pending      = false;  // "Reload" under the copy list
// The list on screen is the one the cache holds, so it gets the strip.
static bool  s_cf_list_cached         = false;

   // a cached row was tapped: index into link_spools

// ============================================================
//  COPY SPOOL FLOW
//  Creates a new Spoolman spool based on an existing spool template
//  (active or archived). Uses 3 API calls: fetch list, POST spool, PATCH tag.
//  Limit: spool_list_limit rows shown, from NVS "list_limit".
// ============================================================

void closeCopyEntryPopup() {
  releaseScreen(&scr_copy_entry);
}

void closeCopyListPopup() {
  releaseScreen(&scr_copy_list);
}


bool finishCopyFlow(int new_spool_id, const char* tray_uuid_override) {
  // Bambu tags: use tray_uuid (long UUID from NFC block 9) - same logic as doLinkPatch
  // NTAG: use link_tag_uid (short UID used as Spoolman key)
  //
  // The override exists because g_tag is not permanent: the no-tag timer in
  // app_loop.cpp clears it 60 s after the tag was last seen. A caller that
  // took its own copy earlier hands it in here rather than reading a field
  // that may have been wiped while a popup was waiting for an answer.
  const char* tray = (tray_uuid_override && strlen(tray_uuid_override) == 32)
                     ? tray_uuid_override : g_tag.tray_uuid;
  bool is_bambu_tag = (strlen(tray) == 32);
  const char* tag_to_write = is_bambu_tag ? tray : link_tag_uid;
  logSDf("finishCopyFlow: spool=%d bambu=%d tag=%s", new_spool_id, (int)is_bambu_tag, tag_to_write);
  // Through the link itself, not beside it: the write with its conflict and
  // network answers, the uid index, the screen, and the questions a link
  // asks afterwards - writing the tag, the second tag. A copy wrote the tag
  // on its own and asked none of them, on all three backends.
  const bool linked = doLinkPatchUid(new_spool_id, is_bambu_tag, tag_to_write);
  // The picker's screens, when the template came through it.
  linkPickerClose();
  showMainScreen();  // navigate to main after copy flow completes
  return linked;
}

// Creates the new spool from the template, then attaches the tag.
void doCopySpoolCreate(int template_spool_id, int template_filament_id,
                       float template_initial, float template_spool_w) {
  if (!wifi_ok) return;
  float netto = scale_weight_g - template_spool_w;
  if (netto < 0) netto = 0;

  int new_id = 0;
  int code = serverReachNote(backendCreateSpool(cfg_spoolman_base, template_spool_id, template_filament_id,
    template_initial, template_spool_w, netto, &new_id, 8000), true);
  if ((code == 200 || code == 201) && new_id > 0) {
    Serial.printf("Copy spool created: new ID=%d\n", new_id);
    logSDf("Copy spool created: tmpl_spool=%d fid=%d new_spool_id=%d",
           template_spool_id, template_filament_id, new_id);
    // A spool the kept list does not have, and a row for it cannot be made up
    // from here. The stamp would catch it; BamBuddy has none.
    spoolCacheForget("spool created by copy");
    // The spool exists either way; a tag that could not be bound has said so
    // on the status line, and that must stay readable.
    if (finishCopyFlow(new_id)) statusMessageShow(T(STR_COPY_OK), UI_COL_ACCENT);
    return;
  }
  Serial.printf("Copy spool POST failed: HTTP %d\n", code);
  // Nothing was created: the picker's hidden screens and its copy mode go.
  linkPickerClose();
  lv_label_set_text(lbl_status, T(STR_COPY_FAIL));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xff8080), 0);
}


// Everything after the list is in: the filter, the rows in PSRAM. Fetch
// spools for copy list (active or archived, material-filtered). Max
// spool_list_limit entries shown.
static bool copyListBuild(JsonDocument& doc, bool archived, const char* material_filter,
                          bool is_bambu_tag, bool from_cache) {
  JsonArray arr = doc.as<JsonArray>();
  // Count matching entries first (for allocation)
  int count = 0;
  for (JsonObject spool : arr) {
    bool is_archived = spool["archived"] | false;
    if (is_archived != archived) continue;
    // Bambu tag: only show Bambu Lab spools
    if (is_bambu_tag) {
      const char* vname = spool["filament"]["vendor"]["name"] | "";
      if (strncasecmp(vname, "Bambu", 5) != 0) continue;
    }
    const char* mat = spool["filament"]["material"] | "";
    if (material_filter && strlen(material_filter) > 0) {
      if (isSupportMaterial(material_filter)) {
        if (!isSupportSpoolmanMat(mat)) continue;
        // No color filter for support filaments
      } else {
        int flen = strlen(material_filter) < 3 ? (int)strlen(material_filter) : 3;
        if (strncasecmp(mat, material_filter, flen) != 0) continue;
        if (isSupportSpoolmanMat(mat)) continue;
        char subkw[16];
        if (extractBambuSubtype(material_filter, subkw, sizeof(subkw))) {
          const char* fname = spool["filament"]["name"] | "";
          const char* fname_sub = spool["filament"]["material_subgroup"] | "";
          if (!bambuSubtypeMatches(mat, subkw) && !bambuSubtypeMatches(fname, subkw) &&
              !bambuSubtypeMatches(fname_sub, subkw)) continue;
        }
        if (g_tag.color_hex[0] == '#') {
          const char* col = spool["filament"]["color_hex"] | "";
          char col_buf[8]; snprintf(col_buf, sizeof(col_buf), "#%s", col);
          if (colorDistance(g_tag.color_hex, col_buf) > 120) continue;
        }
      }
    }
    count++;
    if (count >= spool_list_limit + 1) break;
  }

  { char buf[48];
    snprintf(buf, sizeof(buf), T(STR_LOADING_FILTER), count);
    loadingOverlaySetText(buf); }

  bool limit_hit = (count > spool_list_limit);
  int alloc_count = limit_hit ? spool_list_limit : count;

  link_spools = (UnlinkedSpool*)heap_caps_malloc(alloc_count * sizeof(UnlinkedSpool), MALLOC_CAP_SPIRAM);
  if (!link_spools) link_spools = (UnlinkedSpool*)malloc(alloc_count * sizeof(UnlinkedSpool));
  if (!link_spools) { link_spool_count = 0; loadingOverlayHide(); return true; }
  link_spools_capacity = alloc_count;

  int idx = 0;
  for (JsonObject spool : arr) {
    if (idx >= alloc_count) break;
    bool is_archived = spool["archived"] | false;
    if (is_archived != archived) continue;
    // Bambu tag: only show Bambu Lab spools
    if (is_bambu_tag) {
      const char* vname = spool["filament"]["vendor"]["name"] | "";
      if (strncasecmp(vname, "Bambu", 5) != 0) continue;
    }
    const char* mat = spool["filament"]["material"] | "";
    if (material_filter && strlen(material_filter) > 0) {
      if (isSupportMaterial(material_filter)) {
        if (!isSupportSpoolmanMat(mat)) continue;
        // No color filter for support filaments
      } else {
        int flen = strlen(material_filter) < 3 ? (int)strlen(material_filter) : 3;
        if (strncasecmp(mat, material_filter, flen) != 0) continue;
        if (isSupportSpoolmanMat(mat)) continue;
        char subkw[16];
        if (extractBambuSubtype(material_filter, subkw, sizeof(subkw))) {
          const char* fname2 = spool["filament"]["name"] | "";
          const char* fname2_sub = spool["filament"]["material_subgroup"] | "";
          if (!bambuSubtypeMatches(mat, subkw) && !bambuSubtypeMatches(fname2, subkw) &&
              !bambuSubtypeMatches(fname2_sub, subkw)) continue;
        }
        if (g_tag.color_hex[0] == '#') {
          const char* col2 = spool["filament"]["color_hex"] | "";
          char col_buf2[8]; snprintf(col_buf2, sizeof(col_buf2), "#%s", col2);
          if (colorDistance(g_tag.color_hex, col_buf2) > 120) continue;
        }
      }
    }
    UnlinkedSpool& s = link_spools[idx];
    s.id = spool["id"] | 0;
    // Out of the cache the template is read fresh when its row is tapped,
    // see copyRowRefresh(): a new spool is never built on the cache.
    s.from_cache = from_cache;
    // Not a tag here, and deliberately emptied rather than left alone:
    // link_spools[] lives in PSRAM and is not zeroed, and the shared list
    // builders skip every row that is already bound, see linkSpoolBound().
    for (uint8_t f = 0; f < TAG_FIELD_EXTRA_COUNT; f++) s.tag_values[f][0] = '\0';
    strncpy(s.name,     spool["filament"]["name"]           | "", sizeof(s.name)-1);
    s.name[sizeof(s.name)-1] = '\0';
    strncpy(s.vendor,   spool["filament"]["vendor"]["name"] | "", sizeof(s.vendor)-1);
    s.vendor[sizeof(s.vendor)-1] = '\0';
    strncpy(s.material, mat,                                      sizeof(s.material)-1);
    s.material[sizeof(s.material)-1] = '\0';
    const char* col = spool["filament"]["color_hex"] | "333333";
    snprintf(s.color_hex, sizeof(s.color_hex), "#%s", col);
    s.total     = spool["filament"]["weight"]  | 1000.0f;
    s.remaining = spool["remaining_weight"]    | 0.0f;
    float spw = spool["spool_weight"] | 0.0f;
    s.filament_id  = spool["filament"]["id"] | 0;
    s.spool_weight = spw;
    idx++;
  }
  link_spool_count = idx;
  loadingOverlayHide();

  if (limit_hit) {
    Serial.printf("fetchSpoolsForCopy: limit hit (%d), showing %d\n", count, spool_list_limit);
  }
  if (link_spool_count > 0) logSDf("[verbose] fetchSpoolsForCopy[0]: spool_id=%d fid=%d spw=%.0f",
    link_spools[0].id, link_spools[0].filament_id, link_spools[0].spool_weight);
  Serial.printf("fetchSpoolsForCopy: %d spools loaded (archived=%d mat=%s)\n",
    link_spool_count, (int)archived, material_filter ? material_filter : "");
  return true;
}

// The copy confirmation for the row at idx, raised as a flag: the list row
// callback that asks for it must not build new LVGL objects.
static void copyConfirmFromRow(int idx) {
  UnlinkedSpool &sel = link_spools[idx];
  int fid = sel.filament_id;
  float spw = sel.spool_weight;
  char tmpl_name[80];
  if (nameStartsWithMaterial(sel.name, sel.material))
    snprintf(tmpl_name, sizeof(tmpl_name), "%s (%s)", sel.name, sel.vendor);
  else
    snprintf(tmpl_name, sizeof(tmpl_name), "%s %s (%s)", sel.material, sel.name, sel.vendor);
  logSDf("BTN: CopyList row -> spool id=%d fid=%d", sel.id, fid);
  // Flag pattern: do not build new LVGL objects inside a list row callback
  copy_confirm_pending = true;
  copy_confirm_fid = fid;
  copy_confirm_spool_id = sel.id;
  copy_confirm_remaining = sel.remaining;
  copy_confirm_initial = sel.total;
  copy_confirm_spool_w = spw;
  strncpy(copy_confirm_name, tmpl_name, sizeof(copy_confirm_name)-1);
  copy_confirm_name[sizeof(copy_confirm_name)-1] = '\0';
  copyLookFromRow(copy_confirm_look, sel);
}

// Spool list for copy flow - identical layout to FilteredSpoolList
void showCopySpoolList() {
  crumbSet("copy list build");
  logSDf("SHOW: CopySpoolList archived=%d count=%d", (int)copy_flow_archived, link_spool_count);
  closeCopyListPopup();

  scr_copy_list = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_copy_list, 480, 320);
  lv_obj_set_pos(scr_copy_list, 0, 0);
  lv_obj_set_style_bg_color(scr_copy_list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr_copy_list, 0, 0);
  lv_obj_set_style_pad_all(scr_copy_list, 0, 0);
  lv_obj_set_style_radius(scr_copy_list, 0, 0);
  lv_obj_clear_flag(scr_copy_list, LV_OBJ_FLAG_SCROLLABLE);

  // Header: 52px, Back left, Cancel/X right, title center
  char title_buf[48];
  char title_str[32]; copyT(title_str, sizeof(title_str), STR_COPY_TITLE);
  snprintf(title_buf, sizeof(title_buf), "%s - %d", title_str, link_spool_count);

  lv_obj_t *hdr = lv_obj_create(scr_copy_list);
  lv_obj_set_size(hdr, 480, 52);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(hdr);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *btn_hdr_back = lv_btn_create(hdr);
  lv_obj_set_size(btn_hdr_back, 44, 44);
  lv_obj_set_pos(btn_hdr_back, 4, 4);
  lv_obj_set_style_bg_color(btn_hdr_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_hdr_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_hdr_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_hdr_back, 0, 0);
  lv_obj_set_style_border_width(btn_hdr_back, 0, 0);
  lv_obj_add_event_cb(btn_hdr_back, [](lv_event_t *e) {
    logSD("BTN: CopyList -> Back");
    closeCopyListPopup();
    if (scr_copy_entry) lv_obj_clear_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_hdr_back);
    lv_label_set_text(l, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(l, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(l); }

  lv_obj_t *btn_hdr_cancel = lv_btn_create(hdr);
  lv_obj_set_size(btn_hdr_cancel, 44, 44);
  lv_obj_align(btn_hdr_cancel, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_hdr_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_hdr_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_hdr_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_hdr_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_hdr_cancel, 0, 0);
  lv_obj_add_event_cb(btn_hdr_cancel, [](lv_event_t *e) {
    logSD("BTN: CopyList -> Cancel");
    closeCopyListPopup();
    closeCopyEntryPopup();
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_hdr_cancel);
    lv_label_set_text(l, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(l); }

  // Separator
  lv_obj_t *div = lv_obj_create(scr_copy_list);
  lv_obj_set_size(div, 480, 1); lv_obj_set_pos(div, 0, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  // The link list's strip: when the list was loaded, and Reload. Also under an
  // empty list, which is where a template made in the backend a moment ago is
  // most likely missing.
  if (s_cf_list_cached) {
    listReloadStrip(scr_copy_list,
                    copy_flow_archived ? spoolCacheArchiveFilledAt() : spoolCacheFilledAt(),
                    copy_flow_archived ? spoolCacheArchiveAgeMs()    : spoolCacheAgeMs(),
                    [](lv_event_t *e) {
                      logSD("BTN: CopyList -> Reload");
                      copy_reload_pending = true;
                    });
  }

  if (link_spool_count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_copy_list);
    char empty_buf[48]; copyT(empty_buf, sizeof(empty_buf), STR_COPY_NO_SPOOLS);
    lv_label_set_text(lbl_empty, empty_buf);
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, 0);
    return;
  }

  lv_obj_t *list = lv_obj_create(scr_copy_list);
  lv_obj_set_size(list, 460, s_cf_list_cached ? LINK_LIST_H - LINK_STRIP_H : LINK_LIST_H);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  logLvMem("copylist/pre", 0);

  int copy_display_count = (link_spool_count > spool_list_limit) ? spool_list_limit : link_spool_count;
  if (link_spool_count > spool_list_limit) {
    logSDf("CopySpoolList: limit %d applied, showing %d of %d", spool_list_limit, copy_display_count, link_spool_count);
  }
  for (int i = 0; i < copy_display_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    // A row is five objects. LVGL 8.3 answers an exhausted pool with NULL and
    // asserts nothing, and every widget constructor writes through that pointer
    // one line later - so running out here is a panic reboot, not the freeze the
    // assert handler suggests. Asked before the row rather than after each of its
    // objects, because the pool ran out between the second and the third.
    if (!lvPoolHasRoomForRow()) {
      logSDf("CopySpoolList: LVGL pool low, list cut at %d rows", i);
      break;
    }
    lv_obj_t *row = lv_btn_create(list);
    if (!row) { logSDf("CopySpoolList: no room for a row, list cut at %d", i); break; }
    lv_obj_set_size(row, 452, 56);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    lv_obj_t *lbl_id = lv_label_create(row);
    char id_buf[10]; snprintf(id_buf, sizeof(id_buf), "%d", s.id);
    lv_label_set_text(lbl_id, id_buf);
    lv_obj_set_style_text_color(lbl_id, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_id, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_id, LV_ALIGN_TOP_LEFT, 6, 5);

    lv_obj_t *lbl_name = lv_label_create(row);
    char full_name[64];
    if (s.material[0]) {
      bool nm = (s.name[0] && strncasecmp(s.name, s.material, strlen(s.material)) == 0);
      if (nm) strncpy(full_name, s.name, sizeof(full_name)-1);
      else snprintf(full_name, sizeof(full_name), "%s %s", s.material, s.name);
    } else {
      strncpy(full_name, s.name, sizeof(full_name)-1);
    }
    full_name[sizeof(full_name)-1] = '\0';
    lv_label_set_text(lbl_name, full_name);
    lv_obj_set_style_text_color(lbl_name, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl_name, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_name, LV_ALIGN_TOP_LEFT, 50, 5);
    lv_label_set_long_mode(lbl_name, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_name, 396);

    lv_obj_t *swatch = lv_obj_create(row);
    lv_obj_set_size(swatch, 14, 14);
    lv_obj_align(swatch, LV_ALIGN_BOTTOM_LEFT, 6, -6);
    lv_obj_set_style_radius(swatch, 3, 0);
    lv_obj_set_style_border_width(swatch, 1, 0);
    lv_obj_set_style_border_color(swatch, lv_color_hex(0x2a4060), 0);
    lv_obj_set_style_pad_all(swatch, 0, 0);
    lv_obj_clear_flag(swatch, LV_OBJ_FLAG_SCROLLABLE);
    swatchPaintHex(swatch, s.color_hex);

    lv_obj_t *lbl_rest = lv_label_create(row);
    char rest_buf[24];
    if (s.remaining <= 0 && s.total > 0) snprintf(rest_buf, sizeof(rest_buf), T(STR_NEW_SPOOL_WEIGHT_FMT), s.total);
    else snprintf(rest_buf, sizeof(rest_buf), "%.0f g", s.remaining);
    lv_label_set_text(lbl_rest, rest_buf);
    lv_obj_set_style_text_color(lbl_rest, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_rest, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(lbl_rest, LV_ALIGN_BOTTOM_LEFT, 26, -5);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      lv_obj_t *btn = lv_event_get_target(e);
      lv_obj_t *par = lv_obj_get_parent(btn);
      int idx = 0;
      uint32_t child_cnt = lv_obj_get_child_cnt(par);
      for (uint32_t c = 0; c < child_cnt; c++) {
        if (lv_obj_get_child(par, c) == btn) { idx = (int)c; break; }
      }
      if (idx >= link_spool_count) return;
      // A row out of the cache is read from the server first, and that is a
      // request: parked for the loop, which opens the question afterwards.
      if (link_spools[idx].from_cache) { copy_row_refresh_pending = idx; return; }
      copyConfirmFromRow(idx);
    }, LV_EVENT_CLICKED, NULL);
  }
  logLvMem("copylist/post", copy_display_count);
  if (link_spool_count > spool_list_limit) {
    addListMoreInfo(list, STR_LIST_MORE_SPOOLS);
  }
}

// Entry popup: choose ID / Active spools / Archived spools
void showCopyEntryPopup() {
  logSD("SHOW: CopyEntryPopup");
  linkPickerReset();  // clear so NTAG always goes via vendor/material picker
  closeCopyEntryPopup();

  scr_copy_entry = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_copy_entry, 480, 320);
  lv_obj_set_pos(scr_copy_entry, 0, 0);
  lv_obj_set_style_bg_color(scr_copy_entry, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr_copy_entry, 0, 0);
  lv_obj_set_style_pad_all(scr_copy_entry, 0, 0);
  lv_obj_set_style_radius(scr_copy_entry, 0, 0);
  lv_obj_clear_flag(scr_copy_entry, LV_OBJ_FLAG_SCROLLABLE);

  // Title
  lv_obj_t *lbl_title = lv_label_create(scr_copy_entry);
  char title_buf[32]; copyT(title_buf, sizeof(title_buf), STR_COPY_TITLE);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 22);

  // The same as Cancel below.
  flowCloseButton(scr_copy_entry, [](lv_event_t *e) {
    logSD("BTN: CopyEntry -> X");
    closeCopyEntryPopup();
  });

  // Separator
  lv_obj_t *div = lv_obj_create(scr_copy_entry);
  lv_obj_set_size(div, 472, 1); lv_obj_set_pos(div, 4, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  // Context: material info if available
  lv_obj_t *lbl_ctx = lv_label_create(scr_copy_entry);
  char ctx_buf[56];
  if (strlen(g_tag.material) > 0) {
    char fmt_c[48]; backendText(T(STR_LINK_CTX_NOT_IN_SM), fmt_c, sizeof(fmt_c));
    snprintf(ctx_buf, sizeof(ctx_buf), fmt_c, g_tag.material);
  } else if (strlen(link_tag_uid) > 0) {
    snprintf(ctx_buf, sizeof(ctx_buf), "UID: %s", link_tag_uid);
  } else {
    snprintf(ctx_buf, sizeof(ctx_buf), "UID: %s", g_tag.uid_str);
  }
  lv_label_set_text(lbl_ctx, ctx_buf);
  lv_obj_set_style_text_color(lbl_ctx, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_ctx, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_ctx, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_ctx, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_ctx, 450);
  lv_obj_align(lbl_ctx, LV_ALIGN_TOP_MID, 0, 60);

  // Creating from the tag needs a backend that can do it and a Bambu tag to
  // read it from - an NTAG carries no material, and material is the one field
  // BamBuddy insists on.
  const bool offer_from_tag = backendCanCreateFromTag() &&
                              strlen(g_tag.tray_uuid) == 32 &&
                              g_tag.material[0] != '\0';

  // Button layout: 3 buttons + cancel, ID= >100 recommended | List= <100
  // recommended. A fifth row only fits if every row gives up a few pixels, so
  // the roomier spacing stays whenever the extra button is not offered.
  const int BTN_W = 380;
  const int BTN_H   = offer_from_tag ? 42 : 48;
  const int BTN_GAP = offer_from_tag ?  5 :  8;
  const int Y1 = offer_from_tag ? 84 : 92;
  const int Y2 = Y1+BTN_H+BTN_GAP, Y3 = Y2+BTN_H+BTN_GAP, Y4 = Y3+BTN_H+BTN_GAP;
  const int Y5 = Y4+BTN_H+BTN_GAP;
  const int Y_CANCEL = offer_from_tag ? Y5 : Y4;

  // Button 1: Enter ID (works for active + archived, >100 spools recommended)
  lv_obj_t *btn1 = lv_btn_create(scr_copy_entry);
  lv_obj_set_size(btn1, BTN_W, BTN_H);
  lv_obj_align(btn1, LV_ALIGN_TOP_MID, 0, Y1);
  lv_obj_set_style_bg_color(btn1, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn1, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn1, 10, 0);
  lv_obj_set_style_shadow_width(btn1, 0, 0);
  lv_obj_set_style_border_width(btn1, 1, 0);
  lv_obj_set_style_border_color(btn1, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn1, [](lv_event_t *e) { link_id_input[0] = '\0'; showIdInputPopup(strlen(g_tag.tray_uuid) == 32, true); }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn1);
    char b[40]; backendText(T(STR_COPY_ID_BTN), b, sizeof(b));
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }

  // Button 2: Active spools (<100 recommended)
  lv_obj_t *btn2 = lv_btn_create(scr_copy_entry);
  lv_obj_set_size(btn2, BTN_W, BTN_H);
  lv_obj_align(btn2, LV_ALIGN_TOP_MID, 0, Y2);
  lv_obj_set_style_bg_color(btn2, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn2, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn2, 10, 0);
  lv_obj_set_style_shadow_width(btn2, 0, 0);
  lv_obj_set_style_border_width(btn2, 1, 0);
  lv_obj_set_style_border_color(btn2, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn2, [](lv_event_t *e) {
    logSD("BTN: CopyEntry -> Active spools");
    copy_fetch_archived = false;
    copy_fetch_pending  = true;
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn2);
    char b[40]; copyT(b, sizeof(b), STR_COPY_ACTIVE_BTN);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }

  // Button 3: Archived spools (<100 recommended)
  lv_obj_t *btn3 = lv_btn_create(scr_copy_entry);
  lv_obj_set_size(btn3, BTN_W, BTN_H);
  lv_obj_align(btn3, LV_ALIGN_TOP_MID, 0, Y3);
  lv_obj_set_style_bg_color(btn3, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn3, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn3, 10, 0);
  lv_obj_set_style_shadow_width(btn3, 0, 0);
  lv_obj_set_style_border_width(btn3, 1, 0);
  lv_obj_set_style_border_color(btn3, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn3, [](lv_event_t *e) {
    logSD("BTN: CopyEntry -> Archived spools");
    copy_fetch_archived = true;
    copy_fetch_pending  = true;
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn3);
    char b[40]; copyT(b, sizeof(b), STR_COPY_ARCHIVED_BTN);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }

  // Button 4: create from the tag, only where that leads anywhere
  if (offer_from_tag) {
    lv_obj_t *btnt = lv_btn_create(scr_copy_entry);
    lv_obj_set_size(btnt, BTN_W, BTN_H);
    lv_obj_align(btnt, LV_ALIGN_TOP_MID, 0, Y4);
    lv_obj_set_style_bg_color(btnt, lv_color_hex(0x0a2818), 0);
    lv_obj_set_style_bg_color(btnt, lv_color_hex(0x1a4a30), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btnt, 10, 0);
    lv_obj_set_style_shadow_width(btnt, 0, 0);
    lv_obj_set_style_border_width(btnt, 1, 0);
    lv_obj_set_style_border_color(btnt, lv_color_hex(0x28d49a), 0);
    lv_obj_add_event_cb(btnt, [](lv_event_t *e) {
      logSD("BTN: CopyEntry -> New from tag");
      newtag_open_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l = lv_label_create(btnt);
    char b[40]; copyT(b, sizeof(b), STR_NEWTAG_BTN);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0x80ffb0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
  }

  // Cancel
  lv_obj_t *btn4 = lv_btn_create(scr_copy_entry);
  lv_obj_set_size(btn4, BTN_W, BTN_H);
  lv_obj_align(btn4, LV_ALIGN_TOP_MID, 0, Y_CANCEL);
  lv_obj_set_style_bg_color(btn4, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn4, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn4, 10, 0);
  lv_obj_set_style_shadow_width(btn4, 0, 0);
  lv_obj_set_style_border_width(btn4, 0, 0);
  lv_obj_add_event_cb(btn4, [](lv_event_t *e) { closeCopyEntryPopup(); }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn4);
    char b[16]; copyT(b, sizeof(b), STR_CANCEL);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }
}

// ============================================================
//  THE LIST OF A BAMBU COPY ON THE BACKEND WORKER
//
//  The whole inventory with the archive and without a field filter, the
//  largest answer of all: about 450 kB and 4 s on a 256 spool FilaMan
//  library, all of it with the loop standing still. Now it comes in on the
//  worker behind the link list's waiting card. Cancel ends the wait; the list
//  is dropped when it arrives, there is no cache for it.
// ============================================================
// The copy list always had ten seconds.
#define COPY_FETCH_TIMEOUT_MS  10000

enum CopyFetchState : uint8_t { CF_IDLE, CF_WAIT_SLOT, CF_LOADING };
static CopyFetchState s_cf_state     = CF_IDLE;
static bool           s_cf_cancelled = false;
static bool           s_cf_archived  = false;
// The stamp taken in front of the download, for the caches it fills.
static bool           s_cf_have_stamp = false;
static InventoryStamp s_cf_stamp      = { -1, 0 };
static char           s_cf_material[24] = "";

// After a reload that ended without a list: the entry it started from is
// hidden under the list that is gone, and would leave an empty screen.
static void copyEntryShowIfAlone() {
  if (!scr_copy_list && scr_copy_entry) lv_obj_clear_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN);
}

static void copyFetchTryStart() {
  if (s_cf_state != CF_WAIT_SLOT) return;
  if (backendListBusy() || backendJobState() != BJS_IDLE) return;
  if (!backendJobStartList(true, nullptr, COPY_FETCH_TIMEOUT_MS, 1, 0)) return;
  s_cf_state = CF_LOADING;
}

static void copyFetchStart(bool archived, const char* material_filter) {
  if (s_cf_state != CF_IDLE) return;   // the card is up, it swallows the second tap
  // Free previous list
  linkSpoolsFree();
  if (!wifi_ok) return;
  s_cf_archived  = archived;
  snprintf(s_cf_material, sizeof(s_cf_material), "%s", material_filter ? material_filter : "");

  // Templates out of the spool cache when its stamp still holds, the same test
  // the link list makes: the active list, or the archive beside it.
  {
    InventoryStamp stamp = { -1, 0 };
    const uint32_t t0 = millis();
    const int sc = backendInventoryStamp(cfg_spoolman_base, &stamp);
    logSDf("copy fetch: stamp code=%d count=%d witness=%d (%lu ms)",
           sc, stamp.count, stamp.witness_id, (unsigned long)(millis() - t0));
    if (serverReachIsNetworkFailure(sc)) {
      serverReachNote(sc, true);
      return;
    }
    s_cf_have_stamp = (sc == 200);
    s_cf_stamp      = stamp;
    const InventoryStamp* st = s_cf_have_stamp ? &s_cf_stamp : nullptr;
    const bool usable = archived ? spoolCacheArchiveUsable(st) : spoolCacheUsable(st);
    if (usable) {
      SpiRamAllocator psram_alloc;
      JsonDocument doc(&psram_alloc);
      const bool got = archived ? spoolCacheArchiveToJson(doc)
                                : spoolCacheToJson(doc, tagFieldSpec(0).key);
      if (got) {
        logSD("copy fetch: list from cache");
        s_cf_list_cached = true;
        copyListBuild(doc, archived, s_cf_material, true, true);
        showCopySpoolList();
        return;
      }
    }
  }

  s_cf_cancelled = false;
  s_cf_state     = CF_WAIT_SLOT;
  linkWaitCardShow();
  copyFetchTryStart();
}

static void copyFetchTick() {
  if (s_cf_state == CF_IDLE) return;

  // Only while the card is this flow's: after a cancel it may already be
  // standing for another list.
  if ((s_cf_state == CF_WAIT_SLOT || !s_cf_cancelled) && linkWaitCardCancelTake()) {
    linkWaitCardHide();
    logSD("copy fetch: cancelled");
    copyEntryShowIfAlone();
    if (s_cf_state == CF_WAIT_SLOT) s_cf_state = CF_IDLE;
    else                            s_cf_cancelled = true;
    return;
  }

  if (!s_cf_cancelled) linkWaitCardBytes(backendJobBytes());
  if (s_cf_state == CF_WAIT_SLOT) { copyFetchTryStart(); return; }
  if (backendJobState() != BJS_DONE) return;

  const BackendListResult r = backendJobResult();
  JsonDocument& doc = backendJobDoc();
  const bool cancelled = s_cf_cancelled;
  s_cf_state     = CF_IDLE;
  s_cf_cancelled = false;
  if (cancelled) { backendJobTake(); return; }

  linkWaitCardHide();
  if (r.gen != backendGeneration()) {
    backendJobTake();
    logSD("copy fetch: the list is from before a backend switch, dropped");
    return;
  }
  if (r.code != 200 || r.err) {
    backendJobTake();
    Serial.printf("fetchSpoolsForCopy JSON error: %s\n", r.err.c_str());
    serverReachNote(r.code, true);
    copyEntryShowIfAlone();
    return;
  }
  // The list holds the active spools and the archive, unfiltered: it fills
  // both caches, so the next copy - of either kind - and the next link come
  // out of them. Not a list FilaMan gave up on halfway.
  s_cf_list_cached = false;
  if (!r.partial) {
    const InventoryStamp* st = s_cf_have_stamp ? &s_cf_stamp : nullptr;
    spoolCacheFill(doc.as<JsonArrayConst>(), spoolHasAnyTag, st);
    spoolCacheArchiveFill(doc.as<JsonArrayConst>(), st);
    // The strip only where the cache took the list: its clock is the strip's.
    s_cf_list_cached = s_cf_archived ? (spoolCacheArchiveRows() > 0) : (spoolCacheRows() > 0);
  }
  copyListBuild(doc, s_cf_archived, s_cf_material, true, false);
  backendJobTake();
  showCopySpoolList();
}

// How long a tapped row may hold the loop while it is read, the link list's
// figure: no card for this one.
#define COPY_ROW_REFRESH_TIMEOUT_MS 3000

// The template a row out of the cache names, read from the server before the
// copy confirmation shows its numbers and a new spool is built on them.
static void copyRowRefresh(int idx) {
  if (!link_spools || idx < 0 || idx >= link_spool_count || !scr_copy_list) return;
  UnlinkedSpool &s = link_spools[idx];

  JsonDocument doc;
  DeserializationError err = DeserializationError::Ok;
  const uint32_t t0 = millis();
  const int code = serverReachNote(
      backendGetSpoolJson(cfg_spoolman_base, s.id, doc, COPY_ROW_REFRESH_TIMEOUT_MS, &err), true);
  const unsigned long took = (unsigned long)(millis() - t0);

  // No answer: serverReachNote() has asked for the popup, the list stays.
  if (serverReachIsNetworkFailure(code)) {
    logSDf("copy row: spool %d not read, no connection (%d, %lu ms)", s.id, code, took);
    return;
  }
  // Gone, or moved in or out of the archive since the list was kept: not on
  // this list any more. The list is fetched again, from the server this time.
  const bool gone = (code == 404) ||
                    (code == 200 && !err && (doc["archived"] | false) != s_cf_archived);
  if (gone) {
    logSDf("copy row: spool %d gone or archived meanwhile (%lu ms), list reloaded", s.id, took);
    spoolCacheForget("a listed template changed");
    char mat[sizeof(s_cf_material)];   // copyFetchStart() writes into s_cf_material
    snprintf(mat, sizeof(mat), "%s", s_cf_material);
    copyFetchStart(s_cf_archived, mat);
    return;
  }
  if (code != 200 || err) {
    logSDf("copy row: spool %d not read, HTTP %d %s (%lu ms)", s.id, code,
           err ? err.c_str() : "", took);
    showInfoPopup(STR_SERVER_DOWN_TITLE, STR_SERVER_DOWN_TEXT, INFO_WARN);
    return;
  }

  s.remaining    = doc["remaining_weight"] | 0.0f;
  s.total        = doc["filament"]["weight"] | 1000.0f;
  s.filament_id  = doc["filament"]["id"] | 0;
  s.spool_weight = doc["spool_weight"] | 0.0f;
  s.from_cache   = false;
  spoolCacheSetRemaining(s.id, s.remaining);
  logSDf("copy row: spool %d read fresh (%lu ms)", s.id, took);
  copyConfirmFromRow(idx);
}

void copyCreateRequest(int template_spool_id, int template_filament_id,
                       float template_initial, float template_spool_w) {
  copy_create_sid = template_spool_id;
  copy_create_fid = template_filament_id;
  copy_create_ini = template_initial;
  copy_create_spw = template_spool_w;
  copy_create_pending = true;
}

void copyFlowDeferredActions() {
  copyFetchTick();
  if (copy_reload_pending) {
    copy_reload_pending = false;
    // From the server this time: the rows index into the array the fetch is
    // about to free, so the list goes first.
    spoolCacheForget("reload asked for");
    closeCopyListPopup();
    char mat[sizeof(s_cf_material)];   // copyFetchStart() writes into s_cf_material
    snprintf(mat, sizeof(mat), "%s", s_cf_material);
    copyFetchStart(s_cf_archived, mat);
  }
  if (copy_row_refresh_pending >= 0) {
    const int idx = copy_row_refresh_pending;
    copy_row_refresh_pending = -1;
    copyRowRefresh(idx);
  }
  if (copy_fetch_pending) {
    copy_fetch_pending = false;
    copy_flow_archived = copy_fetch_archived;
    const bool is_bambu_tag = (strlen(g_tag.tray_uuid) == 32);
    if (is_bambu_tag) {
      // Bambu: use the material filter if available, else show all.
      copyFetchStart(copy_fetch_archived, strlen(g_tag.material) > 0 ? g_tag.material : "");
    } else {
      // NTAG: always through the vendor/material picker.
      linkPickerForCopy(copy_fetch_archived);
    }
  }
  if (copy_create_pending) {
    copy_create_pending = false;
    closeCopyConfirmPopup();
    closeCopyListPopup();
    closeCopyEntryPopup();
    doCopySpoolCreate(copy_create_sid, copy_create_fid, copy_create_ini, copy_create_spw);
  }
}
