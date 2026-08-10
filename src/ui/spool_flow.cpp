#include "spool_flow.h"
#include "navigation.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <lvgl.h>
#include <cstring>

#include "app_config.h"
#include "bambu/bambu_tag.h"
#include "bambu/material_match.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/list_limits.h"
#include "services/spoolman_actions.h"
#include "services/backend_api.h"
#include "ui/main_screen_helpers.h"
#include "ui/spoolman_lookup.h"
#include "ui/ui_common.h"

namespace {

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



// Tag type enum — declared globally so all functions can use it
struct UnlinkedSpool {
  int   id;
  char  name[48];      // filament.name
  char  vendor[32];    // filament.vendor.name
  char  material[16];  // filament.material (PLA, PETG, ABS...)
  char  color_hex[8];  // filament.color_hex (#RRGGBB)
  float remaining;     // remaining_weight
  float total;         // filament.weight
  char  existing_tag[48]; // extra.tag falls gesetzt (fuer Ueberschreib-Check)
  int   filament_id;   // filament.id (for copy flow)
  float spool_weight;  // spool_weight (for copy flow)
};
static UnlinkedSpool* link_spools = nullptr;  // PSRAM-allocated at fetch time, freed after link flow
static int            link_spool_count = 0;
char          link_tag_uid[24] = "";   // UID of the tag to be linked
static lv_obj_t     *scr_link_list = nullptr; // Spool selection overlay (old, kept for compatibility)

// Neuer Link-Flow Overlays
static lv_obj_t *scr_link_entry   = nullptr;  // Entry popup
static lv_obj_t *scr_link_id      = nullptr;  // Numeric keypad
static lv_obj_t *scr_link_warn_a  = nullptr;  // Warning popup A (already linked)
static lv_obj_t *scr_link_warn_b  = nullptr;  // Warning popup B (material mismatch)
static lv_obj_t *scr_link_vendor  = nullptr;  // Vendor-Auswahl (Flow B Pfad 2)
static lv_obj_t *scr_link_mat     = nullptr;  // Material selection (flow B path 2)
static lv_obj_t *scr_link_mat_sub = nullptr;  // Material sub-name selection (Stufe 3)
static lv_obj_t *scr_link_spools  = nullptr;  // Spool list (all path 2)

// State for ID input
static char link_id_input[8] = "";            // Input buffer for numeric keypad
static lv_obj_t *lbl_link_id_display = nullptr; // Label for digit display
static lv_obj_t *lbl_link_id_status  = nullptr; // Error label in numeric keypad

// State for path-2 navigation
static char link_selected_vendor[32]   = "";   // selected vendor
static char link_selected_material[8]  = "";   // 3-char material prefix
static char link_selected_material_full[32] = ""; // full material name (Stufe 3)
static bool link_stage3_shown = false;          // true if stage 3 actually rendered (not auto-skipped)
static bool link_flow_is_bambu = false;         // which flow is active

// Copy spool flow state
static lv_obj_t *scr_copy_entry   = nullptr;  // entry screen (ID / active / archived)
static lv_obj_t *scr_copy_id      = nullptr;  // numeric ID input
static lv_obj_t *scr_copy_list    = nullptr;  // spool list
static lv_obj_t *scr_copy_confirm = nullptr;  // confirm popup
static bool copy_flow_archived = false;        // true = showing archived spools
static bool copy_flow_via_list = false;        // true = copy flow using vendor/material list path
static bool copy_confirm_pending = false;      // deferred showCopyConfirmPopup from list row click
static int  copy_confirm_fid = 0;
static float copy_confirm_remaining = 0, copy_confirm_initial = 0, copy_confirm_spool_w = 0;
static char copy_confirm_name[80] = {};
static char copy_id_input[8] = "";
static lv_obj_t *lbl_copy_id_display = nullptr;
static lv_obj_t *lbl_copy_id_status  = nullptr;
// Template selected for copy
static int   copy_template_filament_id = 0;
static float copy_template_initial     = 0;
static float copy_template_spool_w     = 0;
static char  copy_template_name[64]    = "";
// btn_copy: global for show/hide alongside btn_link
lv_obj_t *btn_copy = nullptr;
// Configurable list limit — loaded from NVS, adjustable via webserver /listlimit

// Popup control: prevents immediate re-display after cancel
static bool id_popup_is_bambu = false;  // shared between numpad lambdas
static bool id_popup_is_copy   = false;  // true = copy flow, false = link flow
static int  copy_id_lookup_pending = 0;  // >0 = deferred copy ID fetch (avoids stack overflow in lambda)
static int  link_id_lookup_pending = 0;  // >0 = deferred linkIdLookupAndPatch (avoids stack overflow in lambda)
static bool link_id_lookup_is_bambu = false;
static bool show_id_input_pending = false;   // deferred re-open of IdInputPopup from Back button
static bool show_id_input_rebuild = false;   // deferred re-open from WarnPopupA retry (rebuild after del)
static bool id_input_open = false;           // true while IdInputPopup is visible — suppresses NFC Spoolman query

bool link_popup_dismissed = false;              // user dismissed the popup
unsigned long link_tag_first_seen_ms = 0;       // time of first detection
#define LINK_POPUP_DELAY_MS  3000               // 3s warten bevor Popup erscheint

// ============================================================
//  SPOOLMAN: LOAD ALL SPOOLS (for new link flow)
//  Loads all active spools including extra.tag status
// ============================================================
void fetchAllSpoolsForLink(bool is_bambu, const char* material_filter, bool archived_only) {
  // Free any previous allocation
  if (link_spools) { free(link_spools); link_spools = nullptr; }
  link_spool_count = 0;
  if (!wifi_ok) return;

  logSDf("link fetch: is_bambu=%d material_filter='%s' archived_only=%d",
    is_bambu, material_filter ? material_filter : "", (int)archived_only);

  StaticJsonDocument<384> filterL;
  JsonArray filterL_arr = filterL.to<JsonArray>();
  JsonObject fL = filterL_arr.createNestedObject();
  fL["id"] = true;
  fL["archived"] = true;
  fL["remaining_weight"] = true;
  fL["extra"]["tag"] = true;
  fL["filament"]["id"] = true;
  fL["filament"]["name"] = true;
  fL["filament"]["material"] = true;
  fL["filament"]["weight"] = true;
  fL["filament"]["color_hex"] = true;
  fL["filament"]["vendor"]["name"] = true;
  fL["spool_weight"] = true;
  SpiRamAllocator psram_alloc;
  JsonDocument doc(&psram_alloc);
  DeserializationError err = DeserializationError::Ok;
  int code = backendGetSpoolListJson(cfg_spoolman_base, archived_only, doc, 8000, &filterL, &err);
  if (code != 200 || err) return;

  JsonArray spools = doc.as<JsonArray>();
  int total_in_api = 0;
  int skipped_tag = 0, skipped_vendor = 0, skipped_material = 0;
  int count_bambu = 0, count_linked = 0;

  // ── Pass 1: count matching spools (pre-filter) ──────────────
  int matched = 0;
  int skipped_archived = 0;
  for (JsonObject spool : spools) {
    total_in_api++;

    // Archived filter: copy-archived flow shows ONLY archived; otherwise skip them
    bool sp_archived = spool["archived"] | false;
    if (archived_only) {
      if (!sp_archived) { skipped_archived++; continue; }
    } else {
      if (sp_archived) { skipped_archived++; continue; }
    }

    // Skip already-linked spools — only in normal link flow.
    // In copy-archived flow, archived spools are templates (typically still tagged) -> don't skip.
    String existing_tag = "";
    if (spool.containsKey("extra") && spool["extra"].containsKey("tag")) {
      existing_tag = spool["extra"]["tag"].as<String>();
      existing_tag.replace("\"",""); existing_tag.trim();
    }
    if (!archived_only && existing_tag.length() > 0) { skipped_tag++; count_linked++; continue; }

    String vname = "";
    if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull())
      vname = spool["filament"]["vendor"]["name"] | String("");
    vname.trim();
    bool bambu_vendor = (strncasecmp(vname.c_str(), "Bambu", 5) == 0);
    if (bambu_vendor) count_bambu++;

    if (is_bambu) {
      if (!bambu_vendor) { skipped_vendor++; continue; }
      if (material_filter && material_filter[0]) {
        String mat = spool["filament"]["material"] | String("");
        mat.trim();
        // Support materials: match Spoolman materials ending in "-S" (e.g. PLA-S, ABS-S)
        if (isSupportMaterial(material_filter)) {
          if (!isSupportSpoolmanMat(mat.c_str())) { skipped_material++; continue; }
          // No color filter for support filaments (always natural/white)
        } else {
          // Standard 3-char material prefix match (e.g. "PLA", "PET", "ABS")
          if (strncasecmp(mat.c_str(), material_filter, 3) != 0) { skipped_material++; continue; }
          // Exclude support materials from non-support filter (e.g. ABS-GF must not show ABS-S)
          if (isSupportSpoolmanMat(mat.c_str())) { skipped_material++; continue; }
          // Subtype filter: only for known technical subtypes (see bambu_blacklist.h)
          char subkw[16];
          if (extractBambuSubtype(material_filter, subkw, sizeof(subkw))) {
            String fname = spool["filament"]["name"] | String("");
            if (!containsIgnoreCase(mat.c_str(), subkw) && !containsIgnoreCase(fname.c_str(), subkw)) {
              logSDf("link fetch: subtype skip mat='%s' name='%.20s' kw='%s'", mat.c_str(), fname.c_str(), subkw);
              skipped_material++; continue;
            }
          }
          // Color filter: if tag has a color, skip spools with very different color
          if (g_tag.color_hex[0] == '#') {
            String col = spool["filament"]["color_hex"] | String("");
            char col_buf[8]; snprintf(col_buf, sizeof(col_buf), "#%s", col.c_str());
            int dist = colorDistance(g_tag.color_hex, col_buf);
            if (dist > 120) { skipped_material++; continue; }
          }
        }
      }
    }
    matched++;
  }

  logSDf("Spoolman inventory: %d total | %d linked | %d unlinked | %d Bambu",
    total_in_api, count_linked, total_in_api - count_linked, count_bambu);
  Serial.printf("Spoolman inventory: %d total | %d linked | %d unlinked | %d Bambu\n",
    total_in_api, count_linked, total_in_api - count_linked, count_bambu);
  logSDf("link fetch: total=%d matched=%d (skip_tag=%d skip_vendor=%d skip_mat=%d)",
    total_in_api, matched, skipped_tag, skipped_vendor, skipped_material);
  Serial.printf("link fetch: total=%d matched=%d (skip_tag=%d skip_vendor=%d skip_mat=%d)\n",
    total_in_api, matched, skipped_tag, skipped_vendor, skipped_material);

  if (matched == 0) return;

  // Store ALL matched spools — the display limit is applied at render time (showFilteredSpoolList)
  // This allows Vendor and Material lists to see the full dataset
  int alloc_count = matched;
  logSDf("link fetch: matched=%d, allocating all for vendor/material dedupe", matched);

  // ── Allocate exactly the needed size in PSRAM ───────────────
  link_spools = (UnlinkedSpool*)heap_caps_malloc(alloc_count * sizeof(UnlinkedSpool), MALLOC_CAP_SPIRAM);
  if (!link_spools) {
    // Fallback: internal RAM
    link_spools = (UnlinkedSpool*)malloc(alloc_count * sizeof(UnlinkedSpool));
    logSD("link fetch: PSRAM alloc failed, using internal RAM");
  }
  if (!link_spools) { logSD("link fetch: alloc failed completely"); return; }

  // ── Pass 2: fill array (same filter) ────────────────────────
  for (JsonObject spool : spools) {
    if (link_spool_count >= alloc_count) break;

    // Archived filter: same logic as pass 1
    bool sp_archived = spool["archived"] | false;
    if (archived_only) {
      if (!sp_archived) continue;
    } else {
      if (sp_archived) continue;
    }

    String existing_tag = "";
    if (spool.containsKey("extra") && spool["extra"].containsKey("tag")) {
      existing_tag = spool["extra"]["tag"].as<String>();
      existing_tag.replace("\"",""); existing_tag.trim();
    }
    if (!archived_only && existing_tag.length() > 0) continue;

    String vname = "";
    if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull())
      vname = spool["filament"]["vendor"]["name"] | String("");
    vname.trim();
    bool bambu_vendor = (strncasecmp(vname.c_str(), "Bambu", 5) == 0);

    if (is_bambu) {
      if (!bambu_vendor) continue;
      if (material_filter && material_filter[0]) {
        String mat = spool["filament"]["material"] | String("");
        mat.trim();
        if (isSupportMaterial(material_filter)) {
          if (!isSupportSpoolmanMat(mat.c_str())) continue;
          // No color filter for support filaments
        } else {
          if (strncasecmp(mat.c_str(), material_filter, 3) != 0) continue;
          if (isSupportSpoolmanMat(mat.c_str())) continue;
          char subkw[16];
          if (extractBambuSubtype(material_filter, subkw, sizeof(subkw))) {
            String fname2 = spool["filament"]["name"] | String("");
            if (!containsIgnoreCase(mat.c_str(), subkw) && !containsIgnoreCase(fname2.c_str(), subkw)) continue;
          }
          if (g_tag.color_hex[0] == '#') {
            String col = spool["filament"]["color_hex"] | String("");
            char col_buf[8]; snprintf(col_buf, sizeof(col_buf), "#%s", col.c_str());
            if (colorDistance(g_tag.color_hex, col_buf) > 120) continue;
          }
        }
      }
    }

    UnlinkedSpool &s = link_spools[link_spool_count];
    s.id = spool["id"] | 0;

    strncpy(s.existing_tag, existing_tag.c_str(), sizeof(s.existing_tag)-1);
    s.existing_tag[sizeof(s.existing_tag)-1] = '\0';

    String fname = spool["filament"]["name"] | String("?");
    fname.trim();
    strncpy(s.name, fname.c_str(), sizeof(s.name)-1);
    s.name[sizeof(s.name)-1] = '\0';

    strncpy(s.vendor, vname.c_str(), sizeof(s.vendor)-1);
    s.vendor[sizeof(s.vendor)-1] = '\0';

    String mat = spool["filament"]["material"] | String("");
    mat.trim();
    strncpy(s.material, mat.c_str(), sizeof(s.material)-1);
    s.material[sizeof(s.material)-1] = '\0';

    String col = spool["filament"]["color_hex"] | String("");
    col.trim();
    if (col.length() > 0 && col[0] != '#') col = "#" + col;
    strncpy(s.color_hex, col.c_str(), sizeof(s.color_hex)-1);
    s.color_hex[sizeof(s.color_hex)-1] = '\0';

    s.remaining = spool["remaining_weight"] | 0.0f;
    s.total = spool["filament"]["weight"] | 1000.0f;
    s.filament_id = spool["filament"]["id"] | 0;
    s.spool_weight = spool["spool_weight"] | 0.0f;

    if (sd_verbose) {
      logSDf("[verbose] link spool %d: vendor='%s' mat='%s' name='%s' fid=%d spw=%.0f",
        s.id, s.vendor, s.material, s.name, s.filament_id, s.spool_weight);
    }

    link_spool_count++;
  }
  Serial.printf("fetchAllSpoolsForLink: %d spools loaded (PSRAM)\n", link_spool_count);
  logSDf("link fetch done: %d spools in list", link_spool_count);
}

// Legacy wrapper for compatibility
void fetchUnlinkedSpools() { fetchAllSpoolsForLink(false, ""); }

// ============================================================
//  SPOOLMAN: SAVE TAG UUID (extra.tag)
// ============================================================
// ============================================================
//  LINK FLOW: COMPLETE LINKING
//  PATCH + update main screen
// ============================================================
void doLinkPatch(int spool_id, bool is_bambu) {
  const char* link_uuid = is_bambu ? g_tag.tray_uuid : link_tag_uid;
  Serial.printf("doLinkPatch: ID=%d uuid=%s\n", spool_id, link_uuid);
  patchSpoolTag(spool_id, link_uuid);

  // Close all link overlays
  if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
  if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id     = nullptr; }
  if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
  if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }
  if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
  if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
  if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
  if (scr_link_list)   { lv_obj_del(scr_link_list);   scr_link_list   = nullptr; }
  // Free PSRAM spool list
  if (link_spools) { free(link_spools); link_spools = nullptr; }
  link_spool_count = 0;

  // Re-query Spoolman — use single-spool endpoint since we know the ID
  link_popup_dismissed = false;
  if (is_bambu) {
    spoolman_queried_uid[0] = '\0';
    querySpoolmanById(spool_id);
  } else {
    strncpy(g_tag.uid_str, link_tag_uid, sizeof(g_tag.uid_str)-1);
    strncpy(g_tag.tray_uuid, link_tag_uid, sizeof(g_tag.tray_uuid)-1);
    spoolman_queried_uid[0] = '\0';
    querySpoolmanById(spool_id);
  }
  Serial.printf("Linking complete! ID=%d\n", spool_id);
}

// ============================================================
//  LINK FLOW: HELPER — create overlay base
// ============================================================
static lv_obj_t* buildLinkOverlay() {
  lv_obj_t *scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr, 480, 320);
  lv_obj_set_pos(scr, 0, 0);
  lv_obj_set_style_bg_color(scr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(scr, 0, 0);
  lv_obj_set_style_radius(scr, 0, 0);
  lv_obj_set_style_pad_all(scr, 0, 0);
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);
  return scr;
}

// ============================================================
//  LINK FLOW: WARNING POPUP A (spool already linked)
// ============================================================
void showWarnPopupA(int spool_id, const char* existing_tag, bool is_bambu, const char* link_uuid) {
  logSDf("SHOW: WarnPopupA spool=%d", spool_id);
  if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }

  scr_link_warn_a = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_link_warn_a, 480, 320);
  lv_obj_set_pos(scr_link_warn_a, 0, 0);
  lv_obj_set_style_bg_color(scr_link_warn_a, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_link_warn_a, LV_OPA_80, 0);
  lv_obj_set_style_border_width(scr_link_warn_a, 0, 0);
  lv_obj_set_style_radius(scr_link_warn_a, 0, 0);
  lv_obj_set_style_pad_all(scr_link_warn_a, 0, 0);
  lv_obj_clear_flag(scr_link_warn_a, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_link_warn_a);
  lv_obj_set_size(box, 440, 262);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Warning icon + title
  lv_obj_t *lbl_title = lv_label_create(box);
  lv_label_set_text(lbl_title, T(STR_WARN_A_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 16);

  // Separator line
  lv_obj_t *line = lv_obj_create(box);
  lv_obj_set_size(line, 420, 1);
  lv_obj_set_pos(line, 10, 42);
  lv_obj_set_style_bg_color(line, lv_color_hex(0x3a2800), 0);
  lv_obj_set_style_border_width(line, 0, 0);
  lv_obj_set_style_radius(line, 0, 0);
  lv_obj_set_style_pad_all(line, 0, 0);

  // ID + shortened tag
  char tag_short[14];
  snprintf(tag_short, sizeof(tag_short), "%.10s...", existing_tag);

  // Get material and name from link_spools
  const char* sm_mat  = "";
  const char* sm_name = "";
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].id == spool_id) {
      sm_mat  = link_spools[i].material;
      sm_name = link_spools[i].name;
      break;
    }
  }
  char info_buf[96];
  if (sm_mat[0] || sm_name[0]) {
    snprintf(info_buf, sizeof(info_buf), T(STR_WARN_A_SPOOL_INFO),
      spool_id, sm_mat, sm_name, tag_short);
  } else {
    snprintf(info_buf, sizeof(info_buf), T(STR_WARN_A_SPOOL_SHORT), spool_id, tag_short);
  }
  lv_obj_t *lbl_info = lv_label_create(box);
  lv_label_set_text(lbl_info, info_buf);
  lv_obj_set_style_text_color(lbl_info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_info, 400);
  lv_obj_align(lbl_info, LV_ALIGN_TOP_MID, 0, 54);

  // Three buttons: link anyway / enter new ID / cancel
  // Button: link anyway
  // We pass spool_id and is_bambu via static captures (lambda workaround: user_data)
  static int  warn_a_spool_id = 0;
  static bool warn_a_is_bambu = false;
  warn_a_spool_id = spool_id;
  warn_a_is_bambu = is_bambu;

  lv_obj_t *btn_force = lv_btn_create(box);
  lv_obj_set_size(btn_force, 420, 44);
  lv_obj_set_pos(btn_force, 10, 114);
  lv_obj_set_style_bg_color(btn_force, lv_color_hex(0x3a2800), 0);
  lv_obj_set_style_bg_color(btn_force, lv_color_hex(0x5a4000), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_force, 8, 0);
  lv_obj_set_style_shadow_width(btn_force, 0, 0);
  lv_obj_set_style_border_width(btn_force, 0, 0);
  lv_obj_add_event_cb(btn_force, [](lv_event_t *e) {
    if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id = nullptr; }
    doLinkPatch(warn_a_spool_id, warn_a_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_force = lv_label_create(btn_force);
  lv_label_set_text(lbl_force, T(STR_BTN_OVERWRITE));
  lv_obj_set_style_text_color(lbl_force, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_force, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_force);

  lv_obj_t *btn_retry = lv_btn_create(box);
  lv_obj_set_size(btn_retry, 420, 44);
  lv_obj_set_pos(btn_retry, 10, 166);  // 114+44+8
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_retry, 8, 0);
  lv_obj_set_style_shadow_width(btn_retry, 0, 0);
  lv_obj_set_style_border_width(btn_retry, 1, 0);
  lv_obj_set_style_border_color(btn_retry, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_retry, [](lv_event_t *e) {
    logSD("BTN: WarnA -> retry IdInput (flag)");
    if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id     = nullptr; }
    link_id_input[0] = '\0';
    link_id_lookup_pending = 0;
    show_id_input_rebuild = true;  // loop rebuilds IdInputPopup safely
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_retry = lv_label_create(btn_retry);
  lv_label_set_text(lbl_retry, T(STR_ENTER_NEW_ID));
  lv_obj_set_style_text_color(lbl_retry, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_retry, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_retry);

  lv_obj_t *btn_cancel = lv_btn_create(box);
  lv_obj_set_size(btn_cancel, 420, 36);
  lv_obj_set_pos(btn_cancel, 10, 218);  // 166+44+8
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_cancel, 0, 0);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e) {
    if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cancel = lv_label_create(btn_cancel);
  lv_label_set_text(lbl_cancel, T(STR_CANCEL));
  lv_obj_set_style_text_color(lbl_cancel, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_cancel, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_cancel);
}

// ============================================================
//  LINK FLOW: WARNING POPUP B (material mismatch)
//  Nur Flow A (Bambu), Pfad 1
// ============================================================
void showWarnPopupB(int spool_id, bool is_bambu) {
  logSDf("SHOW: WarnPopupB spool=%d", spool_id);
  if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }

  static int  warn_b_spool_id = 0;
  static bool warn_b_is_bambu = false;
  warn_b_spool_id = spool_id;
  warn_b_is_bambu = is_bambu;

  scr_link_warn_b = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_link_warn_b, 480, 320);
  lv_obj_set_pos(scr_link_warn_b, 0, 0);
  lv_obj_set_style_bg_color(scr_link_warn_b, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_link_warn_b, LV_OPA_80, 0);
  lv_obj_set_style_border_width(scr_link_warn_b, 0, 0);
  lv_obj_set_style_radius(scr_link_warn_b, 0, 0);
  lv_obj_set_style_pad_all(scr_link_warn_b, 0, 0);
  lv_obj_clear_flag(scr_link_warn_b, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_link_warn_b);
  lv_obj_set_size(box, 440, 260);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(box);
  lv_label_set_text(lbl_title, T(STR_WARN_B_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 16);

  lv_obj_t *line = lv_obj_create(box);
  lv_obj_set_size(line, 420, 1);
  lv_obj_set_pos(line, 10, 42);
  lv_obj_set_style_bg_color(line, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_border_width(line, 0, 0);
  lv_obj_set_style_radius(line, 0, 0);
  lv_obj_set_style_pad_all(line, 0, 0);

  // Material-Vergleich anzeigen
  char mat_buf[80];
  // Spoolman-Material finden
  const char* sm_mat = "-";
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].id == spool_id) { sm_mat = link_spools[i].material; break; }
  }
  snprintf(mat_buf, sizeof(mat_buf), T(STR_WARN_B_DETAILS),
    g_tag.material[0] ? g_tag.material : "?", sm_mat, spool_id);
  lv_obj_t *lbl_info = lv_label_create(box);
  lv_label_set_text(lbl_info, mat_buf);
  lv_obj_set_style_text_color(lbl_info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_info, 400);
  lv_obj_align(lbl_info, LV_ALIGN_TOP_MID, 0, 52);

  lv_obj_t *btn_force = lv_btn_create(box);
  lv_obj_set_size(btn_force, 420, 48);
  lv_obj_align(btn_force, LV_ALIGN_TOP_MID, 0, 142);
  lv_obj_set_style_bg_color(btn_force, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_force, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_force, 8, 0);
  lv_obj_set_style_shadow_width(btn_force, 0, 0);
  lv_obj_set_style_border_width(btn_force, 0, 0);
  lv_obj_add_event_cb(btn_force, [](lv_event_t *e) {
    if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id = nullptr; }
    doLinkPatch(warn_b_spool_id, warn_b_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_force = lv_label_create(btn_force);
  lv_label_set_text(lbl_force, T(STR_BTN_OVERWRITE));
  lv_obj_set_style_text_color(lbl_force, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_force, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_force);

  lv_obj_t *btn_retry = lv_btn_create(box);
  lv_obj_set_size(btn_retry, 420, 44);
  lv_obj_align(btn_retry, LV_ALIGN_TOP_MID, 0, 198);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_retry, 8, 0);
  lv_obj_set_style_shadow_width(btn_retry, 0, 0);
  lv_obj_set_style_border_width(btn_retry, 1, 0);
  lv_obj_set_style_border_color(btn_retry, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_retry, [](lv_event_t *e) {
    if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }
    link_id_input[0] = '\0';
    showIdInputPopup(warn_b_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_retry = lv_label_create(btn_retry);
  lv_label_set_text(lbl_retry, T(STR_ENTER_NEW_ID));
  lv_obj_set_style_text_color(lbl_retry, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_retry, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_retry);

  lv_obj_t *btn_cancel = lv_btn_create(box);
  lv_obj_set_size(btn_cancel, 420, 36);
  lv_obj_align(btn_cancel, LV_ALIGN_BOTTOM_MID, 0, -8);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_cancel, 0, 0);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e) {
    if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cancel = lv_label_create(btn_cancel);
  lv_label_set_text(lbl_cancel, T(STR_CANCEL));
  lv_obj_set_style_text_color(lbl_cancel, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_cancel, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_cancel);
}

// ============================================================
//  LINK-FLOW: HTTP-LOOKUP + VERKNUEPFUNG (ausgelagert vom Lambda)
// ============================================================
void linkIdLookupAndPatch(int entered_id, bool is_bambu) {
  if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_CHECKING));
  lv_timer_handler();
  if (!wifi_ok) { if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_NO_WIFI)); return; }

  DynamicJsonDocument doc(8192);
  DeserializationError err = DeserializationError::Ok;
  int code = backendGetSpoolJson(cfg_spoolman_base, entered_id, doc, 5000, &err);
  if (code == 404 || code < 0) {
    if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_ID_NOT_FOUND));
    return;
  }
  if (code == -2) {
    if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_JSON_ERR));
    return;
  }
  if (code != 200) {
    char err[32]; snprintf(err, sizeof(err), T(STR_LINK_HTTP_ERR), code);
    if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, err);
    return;
  }

  String existing = "";
  if (doc.containsKey("extra") && doc["extra"].containsKey("tag")) {
    existing = doc["extra"]["tag"].as<String>();
    existing.replace("\"",""); existing.trim();
  }

  // Ensure link_spools has room for this spool (may be nullptr if no list was loaded)
  if (link_spools == nullptr) {
    link_spools = (UnlinkedSpool*)heap_caps_malloc(sizeof(UnlinkedSpool), MALLOC_CAP_SPIRAM);
    if (!link_spools) link_spools = (UnlinkedSpool*)malloc(sizeof(UnlinkedSpool));
    link_spool_count = 0;
  }
  bool found_in_list = false;
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].id == entered_id) { found_in_list = true; break; }
  }
  if (!found_in_list && link_spools != nullptr) {
    // Allocate one extra slot if needed (link_spools may be nullptr if no list was loaded)
    UnlinkedSpool &s = link_spools[link_spool_count];
    s.id = entered_id;
    strncpy(s.existing_tag, existing.c_str(), sizeof(s.existing_tag)-1);
    String mat = doc["filament"]["material"] | String("");
    mat.trim(); strncpy(s.material, mat.c_str(), sizeof(s.material)-1);
    String fname = doc["filament"]["name"] | String("?");
    fname.trim(); strncpy(s.name, fname.c_str(), sizeof(s.name)-1);
    String vnd = doc["filament"]["vendor"]["name"] | String("");
    vnd.trim(); strncpy(s.vendor, vnd.c_str(), sizeof(s.vendor)-1);
    String col = doc["filament"]["color_hex"] | String("");
    col.trim();
    if (col.length() > 0 && col[0] != '#') col = "#" + col;
    strncpy(s.color_hex, col.c_str(), sizeof(s.color_hex)-1);
    link_spool_count++;
  }

  if (existing.length() > 0) {
    showWarnPopupA(entered_id, existing.c_str(), is_bambu, "");
    return;
  }
  if (is_bambu && g_tag.material[0]) {
    String sm_mat = doc["filament"]["material"] | String("");
    sm_mat.trim();
    if (sm_mat.length() >= 3 && strlen(g_tag.material) >= 3) {
      if (strncasecmp(g_tag.material, sm_mat.c_str(), 3) != 0) {
        showWarnPopupB(entered_id, is_bambu);
        return;
      }
    }
  }
  doLinkPatch(entered_id, is_bambu);
}

// ============================================================
//  LINK-FLOW: ZIFFERNBLOCK (Pfad 1 — ID eingeben)
// ============================================================
void showIdInputPopup(bool is_bambu, bool is_copy) {
  logSDf("SHOW: IdInputPopup bambu=%d copy=%d", (int)is_bambu, (int)is_copy);
  id_input_open = true;  // suppress NFC Spoolman query while numpad open
  if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
  lbl_link_id_display = nullptr;
  lbl_link_id_status  = nullptr;

  scr_link_id = buildLinkOverlay();

  // ── Header like settings menu ───────────────────────────
  // Title zentriert
  lv_obj_t *lbl_title = lv_label_create(scr_link_id);
  lv_label_set_text(lbl_title, T(STR_LINK_ID_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

  // Zurueck-Button (←) oben links
  lv_obj_t *btn_back = lv_btn_create(scr_link_id);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e) {
    logSD("BTN: IdInput -> Back (flag)");
    show_id_input_pending = false;  // cancel any pending re-open
    // Use flag pattern — cannot delete own parent screen in callback
    if (id_popup_is_copy) {
      // Close and show copy entry — deferred via loop
      if (scr_link_id) { lv_obj_add_flag(scr_link_id, LV_OBJ_FLAG_HIDDEN); }
      if (scr_copy_entry) lv_obj_clear_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN);
      // Delete scr_link_id safely after callback via pending flag
      show_id_input_pending = true;  // reuse flag to signal cleanup
    } else {
      if (scr_link_id) { lv_obj_add_flag(scr_link_id, LV_OBJ_FLAG_HIDDEN); }
      if (scr_link_entry) lv_obj_clear_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN);
      show_id_input_pending = true;
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_bk);

  // X-Button oben rechts → komplett schliessen
  lv_obj_t *btn_x = lv_btn_create(scr_link_id);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_set_style_border_width(btn_x, 0, 0);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e) {
    logSD("BTN: IdInput -> X Close");
    // Flag pattern: cannot delete own parent screen from callback
    id_input_open = false;
    link_id_lookup_pending = 0;
    copy_id_lookup_pending = 0;
    show_id_input_pending = true;  // loop will delete scr_link_id safely
    // Also mark entry popup for deletion
    if (id_popup_is_copy) {
      if (scr_copy_entry) lv_obj_add_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN);
    } else {
      if (scr_link_entry) lv_obj_add_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN);
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);

  // Separator line
  lv_obj_t *div = lv_obj_create(scr_link_id);
  lv_obj_set_size(div, 472, 1); lv_obj_set_pos(div, 4, 48);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  // Kontext-Info
  lv_obj_t *lbl_ctx = lv_label_create(scr_link_id);
  char ctx_buf[48];
  if (is_bambu) {
    snprintf(ctx_buf, sizeof(ctx_buf), "Bambu  %s", g_tag.material[0] ? g_tag.material : "Tag");
  } else {
    snprintf(ctx_buf, sizeof(ctx_buf), "UID: %.14s", link_tag_uid);
  }
  lv_label_set_text(lbl_ctx, ctx_buf);
  lv_obj_set_style_text_color(lbl_ctx, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_ctx, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_ctx, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_ctx, LV_ALIGN_TOP_MID, 0, 56);

  // Input field — kompakter, y=76
  lv_obj_t *input_box = lv_obj_create(scr_link_id);
  lv_obj_set_size(input_box, 260, 44);
  lv_obj_align(input_box, LV_ALIGN_TOP_MID, 0, 76);
  lv_obj_set_style_bg_color(input_box, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_border_color(input_box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(input_box, 1, 0);
  lv_obj_set_style_radius(input_box, 6, 0);
  lv_obj_set_style_pad_all(input_box, 0, 0);
  lv_obj_clear_flag(input_box, LV_OBJ_FLAG_SCROLLABLE);

  lbl_link_id_display = lv_label_create(input_box);
  lv_label_set_text(lbl_link_id_display, link_id_input[0] ? link_id_input : "_");
  lv_obj_set_style_text_color(lbl_link_id_display, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_link_id_display, &lv_font_montserrat_ext_24, 0);
  lv_obj_set_style_text_align(lbl_link_id_display, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(lbl_link_id_display);

  // Status label inside input box (replaces digit display when error occurs)
  lbl_link_id_status = lv_label_create(input_box);
  lv_label_set_text(lbl_link_id_status, "");
  lv_obj_set_style_text_color(lbl_link_id_status, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_link_id_status, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_link_id_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_link_id_status, LV_ALIGN_BOTTOM_MID, 0, -2);

  // ── Numeric keypad: 4x3, START_Y=132 ─────────────────────
  // BTN 80x38, GAP 5 → 4 rows: 4*38+3*5=167px → ends at 132+167=299 ✓
  // No separate cancel button needed (X top right)
  const int BTN_W = 80, BTN_H = 38, GAP = 5;
  const int PAD_X = (480 - 3*BTN_W - 2*GAP) / 2;
  const int START_Y = 132;

  // 12 buttons: 1-9, then 0 / ⌫ / ✓
  const char* digits12[] = {"1","2","3","4","5","6","7","8","9","0",LV_SYMBOL_BACKSPACE,LV_SYMBOL_OK};
  int pos_x12[] = {0,1,2, 0,1,2, 0,1,2, 0,1,2};
  int pos_y12[] = {0,0,0, 1,1,1, 2,2,2, 3,3,3};

  id_popup_is_bambu = is_bambu;
  id_popup_is_copy  = is_copy;

  for (int d = 0; d < 12; d++) {
    lv_obj_t *btn = lv_btn_create(scr_link_id);
    int bx = PAD_X + pos_x12[d] * (BTN_W + GAP);
    int by = START_Y + pos_y12[d] * (BTN_H + GAP);
    lv_obj_set_size(btn, BTN_W, BTN_H);
    lv_obj_set_pos(btn, bx, by);

    bool is_ok        = (d == 11);
    bool is_backspace = (d == 10);
    uint32_t bg_col = is_ok ? 0x1a3020 : 0x0a1e30;
    uint32_t bg_pr  = is_ok ? 0x2a5030 : 0x1a3060;
    uint32_t bd_col = is_ok ? 0x2a5030 : 0x1a3060;
    uint32_t tx_col = is_ok ? 0x40c080 : (is_backspace ? 0xf0b838 : 0xe8f0ff);

    lv_obj_set_style_bg_color(btn, lv_color_hex(bg_col), 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(bg_pr), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn, 8, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_set_style_border_width(btn, 1, 0);
    lv_obj_set_style_border_color(btn, lv_color_hex(bd_col), 0);

    lv_obj_t *lbl = lv_label_create(btn);
    lv_label_set_text(lbl, digits12[d]);
    lv_obj_set_style_text_color(lbl, lv_color_hex(tx_col), 0);
    lv_obj_set_style_text_font(lbl, is_ok ? &lv_font_montserrat_ext_20 : &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl);

    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      const char* digit_str = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
      bool is_bs     = (strcmp(digit_str, LV_SYMBOL_BACKSPACE) == 0);
      bool is_ok_btn = (strcmp(digit_str, LV_SYMBOL_OK) == 0);

      if (is_ok_btn) {
        if (strlen(link_id_input) == 0) {
          if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_ID_TITLE));
          return;
        }
        int entered_id = atoi(link_id_input);
        if (entered_id <= 0) {
          if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_ID_NOT_FOUND));
          return;
        }
        if (id_popup_is_copy) {
          // Defer to loop — HTTP + JSON in lambda causes stack overflow
          if (!wifi_ok) { if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_NO_WIFI)); return; }
          copy_id_lookup_pending = entered_id;
          if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_CHECKING));
        } else {
          // Defer to loop — direct call causes stack overflow in LVGL lambda
          link_id_lookup_pending = entered_id;
          link_id_lookup_is_bambu = id_popup_is_bambu;
          if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_CHECKING));
        }
      } else if (is_bs) {
        int len = strlen(link_id_input);
        if (len > 0) link_id_input[len-1] = '\0';
        if (lbl_link_id_display)
          lv_label_set_text(lbl_link_id_display, link_id_input[0] ? link_id_input : "_");
        if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, "");
      } else {
        int len = strlen(link_id_input);
        if (len < 6) { link_id_input[len] = digit_str[0]; link_id_input[len+1] = '\0'; }
        if (lbl_link_id_display)
          lv_label_set_text(lbl_link_id_display, link_id_input[0] ? link_id_input : "_");
        if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, "");
      }
    }, LV_EVENT_CLICKED, NULL);
  }
}

void closeIdInputPopup() {
  id_input_open = false;
  link_id_lookup_pending = 0;  // cancel any pending lookup when popup closes
  copy_id_lookup_pending = 0;
  if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
  lbl_link_id_display = nullptr;
  lbl_link_id_status  = nullptr;
}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — SPULEN-LISTE (Stufe 3)
// ============================================================
// Helper: adds a non-clickable info row at the bottom of a list when limit was hit
static void addListMoreInfo(lv_obj_t* list, StringID str_id) {
  char buf[96];
  strncpy(buf, T(str_id), sizeof(buf)-1);
  buf[sizeof(buf)-1] = '\0';

  lv_obj_t *row = lv_obj_create(list);
  lv_obj_set_size(row, 452, 48);
  lv_obj_set_style_bg_color(row, lv_color_hex(0x1a1a08), 0);
  lv_obj_set_style_radius(row, 6, 0);
  lv_obj_set_style_border_width(row, 1, 0);
  lv_obj_set_style_border_color(row, lv_color_hex(0x3a3010), 0);
  lv_obj_set_style_pad_all(row, 0, 0);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *lbl = lv_label_create(row);
  lv_label_set_text(lbl, buf);
  lv_obj_set_style_text_color(lbl, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl, 440);
  lv_obj_center(lbl);
}

void showFilteredSpoolList(const char* vendor_name, const char* material_prefix, const char* material_full) {
  logSDf("SHOW: FilteredSpoolList vendor=%s mat=%s matf=%s", vendor_name, material_prefix, material_full ? material_full : "");
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }

  scr_link_spools = buildLinkOverlay();

  // Count matching spools for title
  int display_count = 0;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &sc = link_spools[i];
    if (sc.existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;
    bool bv = (strncasecmp(sc.vendor, "Bambu", 5) == 0);
    if (link_flow_is_bambu) {
      if (!bv) continue;
      if (g_tag.material[0] && sc.material[0]) {
        if (isSupportMaterial(g_tag.material)) {
          if (!isSupportSpoolmanMat(sc.material)) continue;
        } else {
          if (material_prefix[0] && strncasecmp(sc.material, material_prefix, strlen(material_prefix)) != 0) continue;
          if (isSupportSpoolmanMat(sc.material)) continue;
        }
      }
    } else {
      if (bv) continue;
      if (vendor_name[0] && strncasecmp(sc.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
      if (material_prefix[0] && strncasecmp(sc.material, material_prefix, strlen(material_prefix)) != 0) continue;
      // Stage 3: full material name match (exact, case-insensitive)
      if (material_full && material_full[0] && strcasecmp(sc.material, material_full) != 0) continue;
    }
    display_count++;
  }

  char title_buf[48];
  if (link_flow_is_bambu) {
    snprintf(title_buf, sizeof(title_buf), "Bambu %s - %d",
      g_tag.material[0] ? g_tag.material : "", display_count);
  } else if (material_full && material_full[0]) {
    snprintf(title_buf, sizeof(title_buf), "%.8s %.10s - %d", vendor_name, material_full, display_count);
  } else if (material_prefix[0]) {
    snprintf(title_buf, sizeof(title_buf), "%.8s %.4s - %d", vendor_name, material_prefix, display_count);
  } else {
    snprintf(title_buf, sizeof(title_buf), "%s - %d", T(STR_SPOOLS_ALL), display_count);
  }

  // Header: 52px, Back left, Cancel/X right, title center
  lv_obj_t *hdr = lv_obj_create(scr_link_spools);
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

  // Back button top-left
  lv_obj_t *btn_hdr_back = lv_btn_create(hdr);
  lv_obj_set_size(btn_hdr_back, 44, 44);
  lv_obj_set_pos(btn_hdr_back, 4, 4);
  lv_obj_set_style_bg_color(btn_hdr_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_hdr_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_hdr_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_hdr_back, 0, 0);
  lv_obj_set_style_border_width(btn_hdr_back, 0, 0);
  lv_obj_add_event_cb(btn_hdr_back, [](lv_event_t *e) {
    logSD("BTN: SpoolList -> Back");
    if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
    if (link_flow_is_bambu) {
      if (scr_link_entry) lv_obj_clear_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN);
    } else {
      // NTAG: if stage 3 was actually shown (not auto-skipped), back goes there
      // otherwise back goes to stage 2 (material prefix list)
      if (link_stage3_shown) {
        showMaterialSubList(link_selected_vendor, link_selected_material);
      } else {
        showMaterialList(link_selected_vendor);
      }
    }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_hdr_back);
    lv_label_set_text(l, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(l, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(l); }

  // Cancel/X button top-right
  lv_obj_t *btn_hdr_cancel = lv_btn_create(hdr);
  lv_obj_set_size(btn_hdr_cancel, 44, 44);
  lv_obj_align(btn_hdr_cancel, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_hdr_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_hdr_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_hdr_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_hdr_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_hdr_cancel, 0, 0);
  lv_obj_add_event_cb(btn_hdr_cancel, [](lv_event_t *e) {
    logSD("BTN: SpoolList -> Cancel");
    if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
    if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_hdr_cancel);
    lv_label_set_text(l, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(l); }

  // Separator
  lv_obj_t *div = lv_obj_create(scr_link_spools);
  lv_obj_set_size(div, 480, 1); lv_obj_set_pos(div, 0, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  // Scrollable list — full height below header
  lv_obj_t *list = lv_obj_create(scr_link_spools);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  int count = 0;
  for (int i = 0; i < link_spool_count; i++) {
    if (count >= spool_list_limit) break;  // render limit — full data is still in link_spools[]
    UnlinkedSpool &s = link_spools[i];

    // Filter: kein Tag, passender Vendor, passender Material-Prefix
    if (s.existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;  // bereits verknuepft
    bool bambu_vendor = (strncasecmp(s.vendor, "Bambu", 5) == 0);
    if (link_flow_is_bambu) {
      // Bambu-Flow: vendor muss Bambu enthalten, Material muss passen
      if (!bambu_vendor) continue;
      if (g_tag.material[0] && s.material[0]) {
        if (isSupportMaterial(g_tag.material)) {
          // Support tags: match Spoolman materials ending in "-S"
          if (!isSupportSpoolmanMat(s.material)) continue;
        } else {
          if (strncasecmp(s.material, g_tag.material, 3) != 0) continue;
          // Exclude support materials from non-support display
          if (isSupportSpoolmanMat(s.material)) continue;
        }
      }
    } else {
      // Flow B: vendor und material prefix filtern
      if (vendor_name[0] && strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
      if (material_prefix[0] && strncasecmp(s.material, material_prefix, strlen(material_prefix)) != 0) continue;
      // Stage 3: full material name match (exact, case-insensitive)
      if (material_full && material_full[0] && strcasecmp(s.material, material_full) != 0) continue;
    }

    count++;
    lv_obj_t *row = lv_btn_create(list);
    lv_obj_set_size(row, 452, 56);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    // ── Zeile 1: #ID + Material+Name ──────────────────────
    lv_obj_t *lbl_id = lv_label_create(row);
    char id_buf[10]; snprintf(id_buf, sizeof(id_buf), "%d", s.id);
    lv_label_set_text(lbl_id, id_buf);
    lv_obj_set_style_text_color(lbl_id, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_id, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_id, LV_ALIGN_TOP_LEFT, 6, 5);

    // Material + Name zusammen, abgeschnitten wenn zu lang
    // Avoid duplication when the filament name already starts with the material
    // (Spoolman often stores names like "PLA+ White" while material is "PLA+")
    lv_obj_t *lbl_name = lv_label_create(row);
    char full_name[64];
    if (s.material[0]) {
      bool name_has_mat = (s.name[0] && strncasecmp(s.name, s.material, strlen(s.material)) == 0);
      if (name_has_mat)
        strncpy(full_name, s.name, sizeof(full_name)-1);
      else
        snprintf(full_name, sizeof(full_name), "%s %s", s.material, s.name);
    } else {
      strncpy(full_name, s.name, sizeof(full_name)-1);
    }
    full_name[sizeof(full_name)-1] = '\0';
    lv_label_set_text(lbl_name, full_name);
    lv_obj_set_style_text_color(lbl_name, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl_name, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_name, LV_ALIGN_TOP_LEFT, 50, 5);
    lv_label_set_long_mode(lbl_name, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_name, 396);  // volle Breite — kein Hersteller in Zeile 1

    // ── Zeile 2: Farbkachel + Gewicht + Hersteller rechts ─
    // Color tile (14x14px)
    lv_obj_t *swatch = lv_obj_create(row);
    lv_obj_set_size(swatch, 14, 14);
    lv_obj_align(swatch, LV_ALIGN_BOTTOM_LEFT, 6, -6);
    lv_obj_set_style_radius(swatch, 3, 0);
    lv_obj_set_style_border_width(swatch, 1, 0);
    lv_obj_set_style_border_color(swatch, lv_color_hex(0x2a4060), 0);
    lv_obj_set_style_pad_all(swatch, 0, 0);
    lv_obj_clear_flag(swatch, LV_OBJ_FLAG_SCROLLABLE);
    // Farbe setzen
    uint32_t swatch_col = 0x333333;  // Fallback grau
    if (s.color_hex[0] == '#' && strlen(s.color_hex) >= 7) {
      unsigned int r, g, b;
      sscanf(s.color_hex + 1, "%02X%02X%02X", &r, &g, &b);
      swatch_col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
    }
    lv_obj_set_style_bg_color(swatch, lv_color_hex(swatch_col), 0);

    // Gewicht neben Kachel
    lv_obj_t *lbl_rest = lv_label_create(row);
    char rest_buf[24];
    if (s.remaining <= 0 && s.total > 0)
      snprintf(rest_buf, sizeof(rest_buf), "%.0fg neu", s.total);
    else
      snprintf(rest_buf, sizeof(rest_buf), "%.0fg", s.remaining);
    lv_label_set_text(lbl_rest, rest_buf);
    lv_obj_set_style_text_color(lbl_rest, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_rest, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(lbl_rest, LV_ALIGN_BOTTOM_LEFT, 26, -5);

    // Click → Sicherheits-Popup
    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      int idx = (intptr_t)lv_event_get_user_data(e);
      if (idx < 0 || idx >= link_spool_count) return;
      UnlinkedSpool &s = link_spools[idx];

      // Sicherheits-Popup (halbtransparentes Overlay)
      lv_obj_t *popup = lv_obj_create(lv_scr_act());
      lv_obj_set_size(popup, 480, 320);
      lv_obj_set_pos(popup, 0, 0);
      lv_obj_set_style_bg_color(popup, lv_color_hex(0x000000), 0);
      lv_obj_set_style_bg_opa(popup, LV_OPA_70, 0);
      lv_obj_set_style_border_width(popup, 0, 0);
      lv_obj_set_style_radius(popup, 0, 0);
      lv_obj_set_style_pad_all(popup, 0, 0);
      lv_obj_clear_flag(popup, LV_OBJ_FLAG_SCROLLABLE);

      lv_obj_t *box = lv_obj_create(popup);
      lv_obj_set_size(box, 440, 220);
      lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
      lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
      lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
      lv_obj_set_style_border_width(box, 2, 0);
      lv_obj_set_style_radius(box, 12, 0);
      lv_obj_set_style_pad_all(box, 0, 0);
      lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

      lv_obj_t *lbl_q = lv_label_create(box);
      lv_label_set_text(lbl_q, copy_flow_via_list ? T(STR_COPY_CONFIRM_TITLE) : T(STR_CONFIRM_LINK));
      lv_obj_set_style_text_color(lbl_q, lv_color_hex(0x28d49a), 0);
      lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_ext_18, 0);
      lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);
      lv_obj_align(lbl_q, LV_ALIGN_TOP_MID, 0, 16);

      // Spulen-Info
      char info[80];
      bool name_has_mat = (s.material[0] && s.name[0] &&
                           strncasecmp(s.name, s.material, strlen(s.material)) == 0);
      if (name_has_mat) {
        snprintf(info, sizeof(info), "#%d  %s\n%.0fg / %.0fg",
          s.id, s.name, s.remaining, s.total);
      } else {
        snprintf(info, sizeof(info), "#%d  %s %s\n%.0fg / %.0fg",
          s.id, s.material, s.name, s.remaining, s.total);
      }
      lv_obj_t *lbl_info = lv_label_create(box);
      lv_label_set_text(lbl_info, info);
      lv_obj_set_style_text_color(lbl_info, lv_color_hex(0xc8d8f0), 0);
      lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_ext_16, 0);
      lv_obj_set_style_text_align(lbl_info, LV_TEXT_ALIGN_CENTER, 0);
      lv_label_set_long_mode(lbl_info, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(lbl_info, 400);
      lv_obj_align(lbl_info, LV_ALIGN_TOP_MID, 0, 48);

      // Link button — y=110, h=46
      lv_obj_t *btn_yes = lv_btn_create(box);
      lv_obj_set_size(btn_yes, 420, 46);
      lv_obj_set_pos(btn_yes, 10, 110);
      lv_obj_set_style_bg_color(btn_yes, lv_color_hex(0x1a3020), 0);
      lv_obj_set_style_bg_color(btn_yes, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn_yes, 8, 0);
      lv_obj_set_style_shadow_width(btn_yes, 0, 0);
      lv_obj_set_style_border_width(btn_yes, 0, 0);
      lv_obj_set_user_data(btn_yes, (void*)(intptr_t)idx);
      lv_obj_add_event_cb(btn_yes, [](lv_event_t *e) {
        int cidx = (intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
        lv_obj_t *pop = lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e)));
        lv_obj_del(pop);
        if (copy_flow_via_list) {
          // Copy flow via vendor/material picker — flag pattern
          copy_flow_via_list = false;
          UnlinkedSpool &cs = link_spools[cidx];
          logSDf("CopyConfirm via list: spool_id=%d fid=%d spw=%.0f", cs.id, cs.filament_id, cs.spool_weight);
          copy_confirm_fid = cs.filament_id;
          copy_confirm_remaining = cs.remaining;
          copy_confirm_initial = cs.total;
          copy_confirm_spool_w = cs.spool_weight;
          {
            bool nm = (cs.material[0] && cs.name[0] &&
                       strncasecmp(cs.name, cs.material, strlen(cs.material)) == 0);
            if (nm)
              snprintf(copy_confirm_name, sizeof(copy_confirm_name), "%s (%s)", cs.name, cs.vendor);
            else
              snprintf(copy_confirm_name, sizeof(copy_confirm_name), "%s %s (%s)", cs.material, cs.name, cs.vendor);
          }
          copy_confirm_pending = true;
        } else {
          doLinkPatch(link_spools[cidx].id, link_flow_is_bambu);
        }
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_yes = lv_label_create(btn_yes);
      lv_label_set_text(lbl_yes, copy_flow_via_list ? T(STR_BTN_CONFIRMED) : T(STR_LINK_OK));
      lv_obj_set_style_text_color(lbl_yes, lv_color_hex(0x40c080), 0);
      lv_obj_set_style_text_font(lbl_yes, &lv_font_montserrat_ext_18, 0);
      lv_obj_center(lbl_yes);

      // Cancel button — y=164 (gap=8 after btn_yes ends at 156)
      lv_obj_t *btn_no = lv_btn_create(box);
      lv_obj_set_size(btn_no, 420, 40);
      lv_obj_set_pos(btn_no, 10, 164);
      lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x3a1010), 0);
      lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x602020), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn_no, 8, 0);
      lv_obj_set_style_shadow_width(btn_no, 0, 0);
      lv_obj_set_style_border_width(btn_no, 0, 0);
      lv_obj_add_event_cb(btn_no, [](lv_event_t *e) {
        lv_obj_del(lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e))));
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_no = lv_label_create(btn_no);
      lv_label_set_text(lbl_no, T(STR_CANCEL));
      lv_obj_set_style_text_color(lbl_no, lv_color_hex(0xff8080), 0);
      lv_obj_set_style_text_font(lbl_no, &lv_font_montserrat_ext_14, 0);
      lv_obj_center(lbl_no);

    }, LV_EVENT_CLICKED, (void*)(intptr_t)i);
  }

  if (count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_spools);
    lv_label_set_text(lbl_empty, T(STR_NO_SPOOLS));
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  } else if (count >= spool_list_limit) {
    addListMoreInfo(list, STR_LIST_MORE_SPOOLS);
  }
}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — MATERIAL-AUSWAHL (Stufe 2)
// ============================================================
void showMaterialList(const char* vendor_name) {
  logSDf("SHOW: MaterialList vendor=%s", vendor_name);
  if (scr_link_mat) { lv_obj_del(scr_link_mat); scr_link_mat = nullptr; }
  strncpy(link_selected_vendor, vendor_name, sizeof(link_selected_vendor)-1);
  link_selected_material_full[0] = 0;  // reset on entry — set fresh in stage 3
  link_stage3_shown = false;

  scr_link_mat = buildLinkOverlay();

  char title_buf[48];
  snprintf(title_buf, sizeof(title_buf), "%s | %.16s", T(STR_MAT_TITLE), vendor_name);

  // Header with Back + Cancel
  lv_obj_t *hdr_mat = lv_obj_create(scr_link_mat);
  lv_obj_set_size(hdr_mat, 480, 52); lv_obj_set_pos(hdr_mat, 0, 0);
  lv_obj_set_style_bg_color(hdr_mat, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr_mat, 0, 0);
  lv_obj_set_style_pad_all(hdr_mat, 0, 0);
  lv_obj_set_style_radius(hdr_mat, 0, 0);
  lv_obj_clear_flag(hdr_mat, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t *lbl_title = lv_label_create(hdr_mat);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);
  lv_obj_t *btn_mat_back = lv_btn_create(hdr_mat);
  lv_obj_set_size(btn_mat_back, 44, 44); lv_obj_set_pos(btn_mat_back, 4, 4);
  lv_obj_set_style_bg_color(btn_mat_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_mat_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_mat_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_mat_back, 0, 0);
  lv_obj_set_style_border_width(btn_mat_back, 0, 0);
  lv_obj_add_event_cb(btn_mat_back, [](lv_event_t *e) {
    logSD("BTN: MatList -> Back");
    if (scr_link_mat) { lv_obj_del(scr_link_mat); scr_link_mat = nullptr; }
    showVendorList();
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_mat_back); lv_label_set_text(l, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(l, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }
  lv_obj_t *btn_mat_cancel = lv_btn_create(hdr_mat);
  lv_obj_set_size(btn_mat_cancel, 44, 44);
  lv_obj_align(btn_mat_cancel, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_mat_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_mat_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_mat_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_mat_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_mat_cancel, 0, 0);
  lv_obj_add_event_cb(btn_mat_cancel, [](lv_event_t *e) {
    logSD("BTN: MatList -> Cancel");
    copy_flow_via_list = false;
    if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
    if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_copy_entry)  { lv_obj_del(scr_copy_entry);  scr_copy_entry  = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_mat_cancel); lv_label_set_text(l, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }
  lv_obj_t *div = lv_obj_create(scr_link_mat);
  lv_obj_set_size(div, 480, 1); lv_obj_set_pos(div, 0, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  lv_obj_t *list = lv_obj_create(scr_link_mat);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  // Deduplicate material prefixes (3 chars) for the selected vendor
  static char seen_mats[20][4] = {};
  static int  mat_counts[20]   = {};
  static int  seen_count       = 0;
  seen_count = 0;
  memset(seen_mats, 0, sizeof(seen_mats));
  memset(mat_counts, 0, sizeof(mat_counts));

  bool mat_limit_hit = false;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (s.existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;
    if (strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
    if (!s.material[0]) continue;
    char prefix[4]; strncpy(prefix, s.material, 3); prefix[3] = '\0';
    bool found = false;
    for (int j = 0; j < seen_count; j++) {
      if (strncasecmp(seen_mats[j], prefix, 3) == 0) { mat_counts[j]++; found = true; break; }
    }
    if (!found) {
      if (seen_count >= spool_list_limit) { mat_limit_hit = true; continue; }
      strncpy(seen_mats[seen_count], prefix, 3);
      mat_counts[seen_count] = 1;
      seen_count++;
    }
  }

  for (int m = 0; m < seen_count; m++) {
    lv_obj_t *row = lv_btn_create(list);
    lv_obj_set_size(row, 452, 50);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    lv_obj_t *lbl_mat = lv_label_create(row);
    lv_label_set_text(lbl_mat, seen_mats[m]);
    lv_obj_set_style_text_color(lbl_mat, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_mat, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_mat, LV_ALIGN_LEFT_MID, 16, 0);

    lv_obj_t *lbl_cnt = lv_label_create(row);
    char cnt_buf[12]; snprintf(cnt_buf, sizeof(cnt_buf), "%d x", mat_counts[m]);
    lv_label_set_text(lbl_cnt, cnt_buf);
    lv_obj_set_style_text_color(lbl_cnt, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_cnt, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_cnt, LV_ALIGN_RIGHT_MID, -16, 0);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      int idx = (intptr_t)lv_event_get_user_data(e);
      strncpy(link_selected_material, seen_mats[idx], sizeof(link_selected_material)-1);
      link_selected_material_full[0] = 0;  // reset for new branch
      if (scr_link_mat) { lv_obj_del(scr_link_mat); scr_link_mat = nullptr; }
      showMaterialSubList(link_selected_vendor, link_selected_material);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)m);
  }

  if (seen_count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_mat);
    lv_label_set_text(lbl_empty, T(STR_NO_MATERIALS));
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  } else if (mat_limit_hit) {
    addListMoreInfo(list, STR_LIST_MORE_MATS);
  }

}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — MATERIAL-VOLLNAME-AUSWAHL (Stufe 3)
//  Dedupliziert s.material exakt fuer Vendor + Material-Prefix.
//  Bei nur einem Eintrag: direkt zu Stufe 4 (auto-skip).
// ============================================================
void showMaterialSubList(const char* vendor_name, const char* material_prefix) {
  logSDf("SHOW: MaterialSubList vendor=%s mat=%s", vendor_name, material_prefix);

  // First pass: collect unique full material names + counts
  static char seen_full[20][32] = {};
  static int  full_counts[20]   = {};
  static int  full_seen_count   = 0;
  full_seen_count = 0;
  memset(seen_full, 0, sizeof(seen_full));
  memset(full_counts, 0, sizeof(full_counts));

  bool full_limit_hit = false;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (s.existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;
    if (strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
    if (!s.material[0]) continue;
    if (strncasecmp(s.material, material_prefix, strlen(material_prefix)) != 0) continue;

    bool found = false;
    for (int j = 0; j < full_seen_count; j++) {
      if (strcasecmp(seen_full[j], s.material) == 0) { full_counts[j]++; found = true; break; }
    }
    if (!found) {
      if (full_seen_count >= spool_list_limit) { full_limit_hit = true; continue; }
      strncpy(seen_full[full_seen_count], s.material, sizeof(seen_full[0])-1);
      full_counts[full_seen_count] = 1;
      full_seen_count++;
    }
  }

  // Auto-skip stage 3 when only one full name found — go directly to stage 4
  if (full_seen_count == 1 && !full_limit_hit) {
    logSDf("MaterialSubList auto-skip: only %s", seen_full[0]);
    strncpy(link_selected_material_full, seen_full[0], sizeof(link_selected_material_full)-1);
    link_stage3_shown = false;  // not actually rendered — back from stage 4 must skip stage 3
    showFilteredSpoolList(vendor_name, material_prefix, link_selected_material_full);
    return;
  }

  link_stage3_shown = true;  // actually rendered
  if (scr_link_mat_sub) { lv_obj_del(scr_link_mat_sub); scr_link_mat_sub = nullptr; }
  scr_link_mat_sub = buildLinkOverlay();

  char title_buf[48];
  snprintf(title_buf, sizeof(title_buf), "%.16s | %.4s", vendor_name, material_prefix);

  // Header with Back + Cancel
  lv_obj_t *hdr_ms = lv_obj_create(scr_link_mat_sub);
  lv_obj_set_size(hdr_ms, 480, 52); lv_obj_set_pos(hdr_ms, 0, 0);
  lv_obj_set_style_bg_color(hdr_ms, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr_ms, 0, 0);
  lv_obj_set_style_pad_all(hdr_ms, 0, 0);
  lv_obj_set_style_radius(hdr_ms, 0, 0);
  lv_obj_clear_flag(hdr_ms, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t *lbl_title = lv_label_create(hdr_ms);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *btn_ms_back = lv_btn_create(hdr_ms);
  lv_obj_set_size(btn_ms_back, 44, 44); lv_obj_set_pos(btn_ms_back, 4, 4);
  lv_obj_set_style_bg_color(btn_ms_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_ms_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ms_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_ms_back, 0, 0);
  lv_obj_set_style_border_width(btn_ms_back, 0, 0);
  lv_obj_add_event_cb(btn_ms_back, [](lv_event_t *e) {
    logSD("BTN: MatSubList -> Back");
    if (scr_link_mat_sub) { lv_obj_del(scr_link_mat_sub); scr_link_mat_sub = nullptr; }
    showMaterialList(link_selected_vendor);
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_ms_back); lv_label_set_text(l, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(l, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }

  lv_obj_t *btn_ms_cancel = lv_btn_create(hdr_ms);
  lv_obj_set_size(btn_ms_cancel, 44, 44);
  lv_obj_align(btn_ms_cancel, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_ms_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_ms_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ms_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_ms_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_ms_cancel, 0, 0);
  lv_obj_add_event_cb(btn_ms_cancel, [](lv_event_t *e) {
    logSD("BTN: MatSubList -> Cancel");
    copy_flow_via_list = false;
    if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
    if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_copy_entry)  { lv_obj_del(scr_copy_entry);  scr_copy_entry  = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_ms_cancel); lv_label_set_text(l, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }

  lv_obj_t *div = lv_obj_create(scr_link_mat_sub);
  lv_obj_set_size(div, 480, 1); lv_obj_set_pos(div, 0, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  lv_obj_t *list = lv_obj_create(scr_link_mat_sub);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  for (int m = 0; m < full_seen_count; m++) {
    lv_obj_t *row = lv_btn_create(list);
    lv_obj_set_size(row, 452, 50);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    lv_obj_t *lbl_full = lv_label_create(row);
    lv_label_set_text(lbl_full, seen_full[m]);
    lv_obj_set_style_text_color(lbl_full, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_full, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_full, LV_ALIGN_LEFT_MID, 16, 0);
    lv_label_set_long_mode(lbl_full, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_full, 340);

    lv_obj_t *lbl_cnt = lv_label_create(row);
    char cnt_buf[12]; snprintf(cnt_buf, sizeof(cnt_buf), "%d x", full_counts[m]);
    lv_label_set_text(lbl_cnt, cnt_buf);
    lv_obj_set_style_text_color(lbl_cnt, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_cnt, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_cnt, LV_ALIGN_RIGHT_MID, -16, 0);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      int idx = (intptr_t)lv_event_get_user_data(e);
      strncpy(link_selected_material_full, seen_full[idx], sizeof(link_selected_material_full)-1);
      if (scr_link_mat_sub) { lv_obj_del(scr_link_mat_sub); scr_link_mat_sub = nullptr; }
      showFilteredSpoolList(link_selected_vendor, link_selected_material, link_selected_material_full);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)m);
  }

  if (full_seen_count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_mat_sub);
    lv_label_set_text(lbl_empty, T(STR_NO_MATERIALS));
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  } else if (full_limit_hit) {
    addListMoreInfo(list, STR_LIST_MORE_MATS);
  }
}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — HERSTELLER-AUSWAHL (Stufe 1)
// ============================================================
void showVendorList() {
  logSD("SHOW: VendorList");
  if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }

  scr_link_vendor = buildLinkOverlay();

  // Zaehle Spulen gesamt (ohne bereits verknuepft)
  int total_unlinked = 0;
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;
    total_unlinked++;
  }

  char title_buf[40];
  snprintf(title_buf, sizeof(title_buf), T(STR_VENDOR_TITLE), total_unlinked);

  lv_obj_t *hdr_vnd = lv_obj_create(scr_link_vendor);
  lv_obj_set_size(hdr_vnd, 480, 52); lv_obj_set_pos(hdr_vnd, 0, 0);
  lv_obj_set_style_bg_color(hdr_vnd, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr_vnd, 0, 0);
  lv_obj_set_style_pad_all(hdr_vnd, 0, 0);
  lv_obj_set_style_radius(hdr_vnd, 0, 0);
  lv_obj_clear_flag(hdr_vnd, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t *lbl_title = lv_label_create(hdr_vnd);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);
  // Back: go back to entry popup
  lv_obj_t *btn_vnd_back = lv_btn_create(hdr_vnd);
  lv_obj_set_size(btn_vnd_back, 44, 44); lv_obj_set_pos(btn_vnd_back, 4, 4);
  lv_obj_set_style_bg_color(btn_vnd_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_vnd_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_vnd_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_vnd_back, 0, 0);
  lv_obj_set_style_border_width(btn_vnd_back, 0, 0);
  lv_obj_add_event_cb(btn_vnd_back, [](lv_event_t *e) {
    logSD("BTN: VendorList -> Back");
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  lv_obj_clear_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN);
    if (scr_copy_entry)  lv_obj_clear_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_vnd_back); lv_label_set_text(l, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(l, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }
  lv_obj_t *btn_vnd_x = lv_btn_create(hdr_vnd);
  lv_obj_set_size(btn_vnd_x, 44, 44);
  lv_obj_align(btn_vnd_x, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_vnd_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_vnd_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_vnd_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_vnd_x, 0, 0);
  lv_obj_set_style_border_width(btn_vnd_x, 0, 0);
  lv_obj_add_event_cb(btn_vnd_x, [](lv_event_t *e) {
    logSD("BTN: VendorList -> Cancel");
    copy_flow_via_list = false;
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_copy_entry)  { lv_obj_del(scr_copy_entry);  scr_copy_entry  = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_vnd_x); lv_label_set_text(l, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }
  lv_obj_t *div = lv_obj_create(scr_link_vendor);
  lv_obj_set_size(div, 480, 1); lv_obj_set_pos(div, 0, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  lv_obj_t *list = lv_obj_create(scr_link_vendor);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  // Dedupliziere Vendors
  static char seen_vendors[20][32] = {};
  static int  vendor_counts[20]    = {};
  static int  seen_v               = 0;
  seen_v = 0;
  memset(seen_vendors, 0, sizeof(seen_vendors));
  memset(vendor_counts, 0, sizeof(vendor_counts));

  bool vendor_limit_hit = false;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (s.existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;
    const char* vn = s.vendor[0] ? s.vendor : "Unbekannt";
    bool found = false;
    for (int j = 0; j < seen_v; j++) {
      if (strcasecmp(seen_vendors[j], vn) == 0) { vendor_counts[j]++; found = true; break; }
    }
    if (!found) {
      if (seen_v >= spool_list_limit) { vendor_limit_hit = true; continue; }
      strncpy(seen_vendors[seen_v], vn, 31);
      vendor_counts[seen_v] = 1;
      seen_v++;
    }
  }

  for (int v = 0; v < seen_v; v++) {
    lv_obj_t *row = lv_btn_create(list);
    lv_obj_set_size(row, 452, 50);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    lv_obj_t *lbl_vnd = lv_label_create(row);
    lv_label_set_text(lbl_vnd, seen_vendors[v]);
    lv_obj_set_style_text_color(lbl_vnd, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl_vnd, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_vnd, LV_ALIGN_LEFT_MID, 16, 0);
    lv_label_set_long_mode(lbl_vnd, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_vnd, 320);

    lv_obj_t *lbl_cnt = lv_label_create(row);
    char cnt_buf[12]; snprintf(cnt_buf, sizeof(cnt_buf), "%d x", vendor_counts[v]);
    lv_label_set_text(lbl_cnt, cnt_buf);
    lv_obj_set_style_text_color(lbl_cnt, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_cnt, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_cnt, LV_ALIGN_RIGHT_MID, -16, 0);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      int idx = (intptr_t)lv_event_get_user_data(e);
      if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
      showMaterialList(seen_vendors[idx]);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)v);
  }

  if (seen_v == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_vendor);
    lv_label_set_text(lbl_empty, T(STR_NO_VENDORS));
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  } else if (vendor_limit_hit) {
    addListMoreInfo(list, STR_LIST_MORE_VENDORS);
  }

}

// ============================================================
//  LINK-FLOW: EINSTIEGS-POPUP (Flow A + B)
// ============================================================
void closeLinkEntryPopup() {
  if (scr_link_entry) { lv_obj_del(scr_link_entry); scr_link_entry = nullptr; }
}

void showLinkEntryPopup(bool is_bambu) {
  logSDf("SHOW: LinkEntryPopup bambu=%d", (int)is_bambu);
  link_selected_material[0] = 0;  // reset material selection for each new flow
  link_selected_material_full[0] = 0;
  link_stage3_shown = false;
  closeLinkEntryPopup();
  link_flow_is_bambu = is_bambu;
  link_id_input[0]   = '\0';

  scr_link_entry = buildLinkOverlay();

  // Header-Titel
  lv_obj_t *lbl_title = lv_label_create(scr_link_entry);
  lv_label_set_text(lbl_title, is_bambu ? T(STR_LINK_BAMBU_TITLE) : T(STR_LINK_NTAG_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 22);

  // Separator line
  lv_obj_t *div = lv_obj_create(scr_link_entry);
  lv_obj_set_size(div, 472, 1); lv_obj_set_pos(div, 4, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  // Kontext-Info (Material/UID)
  lv_obj_t *lbl_ctx = lv_label_create(scr_link_entry);
  char ctx_buf[56];
  if (is_bambu) {
    snprintf(ctx_buf, sizeof(ctx_buf), T(STR_LINK_CTX_NOT_IN_SM),
      g_tag.material[0] ? g_tag.material : "Bambu Tag");
  } else {
    snprintf(ctx_buf, sizeof(ctx_buf), "UID: %s", link_tag_uid);
  }
  lv_label_set_text(lbl_ctx, ctx_buf);
  lv_obj_set_style_text_color(lbl_ctx, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_ctx, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_ctx, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_ctx, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_ctx, 450);
  lv_obj_align(lbl_ctx, LV_ALIGN_TOP_MID, 0, 62);

  // Button-Layout: 3 Buttons zentriert, je 380x60
  const int BTN_W = 380, BTN_H = 60, BTN_GAP = 10;
  const int Y1 = 100, Y2 = Y1 + BTN_H + BTN_GAP, Y3 = Y2 + BTN_H + BTN_GAP;

  // Button 1: Spool-ID eingeben
  lv_obj_t *btn1 = lv_btn_create(scr_link_entry);
  lv_obj_set_size(btn1, BTN_W, BTN_H);
  lv_obj_align(btn1, LV_ALIGN_TOP_MID, 0, Y1);
  lv_obj_set_style_bg_color(btn1, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn1, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn1, 10, 0);
  lv_obj_set_style_shadow_width(btn1, 0, 0);
  lv_obj_set_style_border_width(btn1, 1, 0);
  lv_obj_set_style_border_color(btn1, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn1, [](lv_event_t *e) {
    link_id_input[0] = '\0';
    showIdInputPopup(link_flow_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *l1 = lv_label_create(btn1);
  lv_label_set_text(l1, T(STR_BTN_ENTER_ID));
  lv_obj_set_style_text_color(l1, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(l1, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(l1);

  // Button 2: Aus Liste waehlen
  lv_obj_t *btn2 = lv_btn_create(scr_link_entry);
  lv_obj_set_size(btn2, BTN_W, BTN_H);
  lv_obj_align(btn2, LV_ALIGN_TOP_MID, 0, Y2);
  lv_obj_set_style_bg_color(btn2, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn2, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn2, 10, 0);
  lv_obj_set_style_shadow_width(btn2, 0, 0);
  lv_obj_set_style_border_width(btn2, 1, 0);
  lv_obj_set_style_border_color(btn2, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn2, [](lv_event_t *e) {
    // Load and pre-filter spools, then start appropriate flow
    fetchAllSpoolsForLink(link_flow_is_bambu, link_flow_is_bambu ? g_tag.material : "");
    if (link_flow_is_bambu) {
      showFilteredSpoolList("", "", "");  // Flow A: direct list (already material-filtered)
    } else {
      showVendorList();               // Flow B: 3-step
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *l2 = lv_label_create(btn2);
  lv_label_set_text(l2, T(STR_BTN_FROM_LIST));
  lv_obj_set_style_text_color(l2, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(l2, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(l2);

  // Button 3: Abbrechen
  lv_obj_t *btn3 = lv_btn_create(scr_link_entry);
  lv_obj_set_size(btn3, BTN_W, BTN_H - 14);  // etwas kleiner
  lv_obj_align(btn3, LV_ALIGN_TOP_MID, 0, Y3);
  lv_obj_set_style_bg_color(btn3, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn3, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn3, 10, 0);
  lv_obj_set_style_shadow_width(btn3, 0, 0);
  lv_obj_set_style_border_width(btn3, 0, 0);
  lv_obj_add_event_cb(btn3, [](lv_event_t *e) {
    link_popup_dismissed = true;
    closeLinkEntryPopup();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *l3 = lv_label_create(btn3);
  lv_label_set_text(l3, T(STR_CANCEL));
  lv_obj_set_style_text_color(l3, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(l3, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(l3);
}

// ============================================================
//  LEGACY: closeLinkList / showLinkList (nicht mehr aktiv genutzt)
// ============================================================
void closeLinkList() {
  if (scr_link_list)   { lv_obj_del(scr_link_list);   scr_link_list   = nullptr; }
  if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
  if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id     = nullptr; }
  if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
  if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
  if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
}

void showLinkList() {
  logSD("SHOW: LinkList (legacy)");
  // Wird nicht mehr direkt aufgerufen — Entry-Popup uebernimmt
  showLinkEntryPopup(false);
}

// ============================================================
//  UI BAUEN  — Redesign Beta_0.4.100
// Main screen construction lives in ui/main_screen.cpp.

// ============================================================
//  COPY SPOOL FLOW
//  Creates a new Spoolman spool based on an existing spool template
//  (active or archived). Uses 3 API calls: fetch list, POST spool, PATCH tag.
//  Limit: COPY_SPOOL_LIMIT spools shown (recommend <100 for stability).
// ============================================================

void closeCopyEntryPopup() {
  if (scr_copy_entry) { lv_obj_del(scr_copy_entry); scr_copy_entry = nullptr; }
}

void closeCopyIdInputPopup() {
  if (scr_copy_id) { lv_obj_del(scr_copy_id); scr_copy_id = nullptr; }
}

void closeCopyListPopup() {
  if (scr_copy_list) { lv_obj_del(scr_copy_list); scr_copy_list = nullptr; }
}

void closeCopyConfirmPopup() {
  if (scr_copy_confirm) { lv_obj_del(scr_copy_confirm); scr_copy_confirm = nullptr; }
}

// Patch newly created spool with tag UID and query it on main screen
void finishCopyFlow(int new_spool_id) {
  // Bambu tags: use tray_uuid (long UUID from NFC block 9) — same logic as doLinkPatch
  // NTAG: use link_tag_uid (short UID used as Spoolman key)
  bool is_bambu_tag = (strlen(g_tag.tray_uuid) == 32);
  const char* tag_to_write = is_bambu_tag ? g_tag.tray_uuid : link_tag_uid;
  logSDf("finishCopyFlow: spool=%d bambu=%d tag=%s", new_spool_id, (int)is_bambu_tag, tag_to_write);
  patchSpoolTag(new_spool_id, tag_to_write);
  sm_id = new_spool_id;
  sm_found = true;
  spoolman_queried_uid[0] = '\0';
  if (is_bambu_tag) {
    querySpoolman(g_tag.tray_uuid);
  } else {
    querySpoolmanById(new_spool_id);
  }
  updateLinkButton();
  showMainScreen();  // navigate to main after copy flow completes
}

// POST /api/v1/spool with template data, then PATCH tag
void doCopySpoolCreate(int template_filament_id, float template_initial, float template_spool_w) {
  if (!wifi_ok) return;
  float netto = scale_weight_g - template_spool_w;
  if (netto < 0) netto = 0;

  int new_id = 0;
  int code = backendCreateSpool(cfg_spoolman_base, template_filament_id, template_initial,
    template_spool_w, netto, &new_id, 8000);
  if ((code == 200 || code == 201) && new_id > 0) {
    Serial.printf("Copy spool created: new ID=%d\n", new_id);
    logSDf("Copy spool created: filament_id=%d new_spool_id=%d", template_filament_id, new_id);
    finishCopyFlow(new_id);
    lv_label_set_text(lbl_status, T(STR_COPY_OK));
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
    return;
  }
  Serial.printf("Copy spool POST failed: HTTP %d\n", code);
  lv_label_set_text(lbl_status, T(STR_COPY_FAIL));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xff8080), 0);
}

// Confirm popup: shows template name + current scale weight, then creates
void showCopyConfirmPopup(int template_filament_id, const char* template_name,
                           float template_remaining, float template_initial, float template_spool_w) {
  closeCopyConfirmPopup();
  copy_template_filament_id = template_filament_id;
  copy_template_initial      = template_initial;
  copy_template_spool_w      = template_spool_w;
  strncpy(copy_template_name, template_name, sizeof(copy_template_name)-1);

  scr_copy_confirm = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_copy_confirm, 480, 320);
  lv_obj_set_pos(scr_copy_confirm, 0, 0);
  lv_obj_set_style_bg_color(scr_copy_confirm, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_copy_confirm, LV_OPA_70, 0);
  lv_obj_set_style_border_width(scr_copy_confirm, 0, 0);
  lv_obj_set_style_pad_all(scr_copy_confirm, 0, 0);
  lv_obj_clear_flag(scr_copy_confirm, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_copy_confirm);
  lv_obj_set_size(box, 420, 260);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, 10, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Title
  lv_obj_t *lbl_title = lv_label_create(box);
  char title_buf[32]; strncpy(title_buf, T(STR_COPY_CONFIRM_TITLE), sizeof(title_buf)-1);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 14);

  // Info text
  lv_obj_t *lbl_info = lv_label_create(box);
  char info_buf[192];
  float display_netto = scale_weight_g - template_spool_w;
  if (display_netto < 0) display_netto = 0;
  snprintf(info_buf, sizeof(info_buf), T(STR_COPY_CONFIRM_MSG), template_name, template_remaining, display_netto);
  lv_label_set_text(lbl_info, info_buf);
  lv_obj_set_style_text_color(lbl_info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_info, 380);
  lv_obj_align(lbl_info, LV_ALIGN_TOP_MID, 0, 48);

  // Confirm button
  lv_obj_t *btn_ok = lv_btn_create(box);
  lv_obj_set_size(btn_ok, 180, 52);
  lv_obj_set_pos(btn_ok, 16, 192);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x1a4020), 0);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x2a7030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok, 8, 0);
  lv_obj_set_style_shadow_width(btn_ok, 0, 0);
  lv_obj_add_event_cb(btn_ok, [](lv_event_t *e) {
    int fid   = copy_template_filament_id;
    float ini = copy_template_initial;
    float spw = copy_template_spool_w;
    closeCopyConfirmPopup();
    closeCopyListPopup();
    closeCopyIdInputPopup();
    closeCopyEntryPopup();
    doCopySpoolCreate(fid, ini, spw);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok = lv_label_create(btn_ok);
  char ok_buf[32]; strncpy(ok_buf, T(STR_BTN_CONFIRMED), sizeof(ok_buf)-1);
  lv_label_set_text(lbl_ok, ok_buf);
  lv_obj_set_style_text_color(lbl_ok, lv_color_hex(0x80ffb0), 0);
  lv_obj_set_style_text_font(lbl_ok, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_ok, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_ok, LV_ALIGN_CENTER, 0, 0);

  // Cancel button
  lv_obj_t *btn_no = lv_btn_create(box);
  lv_obj_set_size(btn_no, 180, 52);
  lv_obj_set_pos(btn_no, 224, 192);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_no, 8, 0);
  lv_obj_set_style_shadow_width(btn_no, 0, 0);
  lv_obj_add_event_cb(btn_no, [](lv_event_t *e) {
    logSD("BTN: CopyConfirm -> Cancel (back to list)");
    closeCopyConfirmPopup();
    if (scr_copy_list) lv_obj_clear_flag(scr_copy_list, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_no = lv_label_create(btn_no);
  char no_buf[32]; strncpy(no_buf, T(STR_CANCEL), sizeof(no_buf)-1);
  lv_label_set_text(lbl_no, no_buf);
  lv_obj_set_style_text_color(lbl_no, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_no, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_no, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_no, LV_ALIGN_CENTER, 0, 0);
}

// Fetch spools for copy list (active or archived, material-filtered)
// Uses PSRAM allocator. Max COPY_SPOOL_LIMIT entries shown.
void fetchSpoolsForCopy(bool archived, const char* material_filter, bool is_bambu_tag) {
  // Free previous list
  if (link_spools) { free(link_spools); link_spools = nullptr; link_spool_count = 0; }

  if (!wifi_ok) return;

  SpiRamAllocator alloc;
  JsonDocument doc(&alloc);
  DeserializationError err = DeserializationError::Ok;
  int code = backendGetSpoolListJson(cfg_spoolman_base, true, doc, 10000, nullptr, &err);
  if (code != 200 || err) { Serial.printf("fetchSpoolsForCopy JSON error: %s\n", err.c_str()); return; }

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
          if (!containsIgnoreCase(mat, subkw) && !containsIgnoreCase(fname, subkw)) continue;
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

  bool limit_hit = (count > spool_list_limit);
  int alloc_count = limit_hit ? spool_list_limit : count;

  link_spools = (UnlinkedSpool*)heap_caps_malloc(alloc_count * sizeof(UnlinkedSpool), MALLOC_CAP_SPIRAM);
  if (!link_spools) link_spools = (UnlinkedSpool*)malloc(alloc_count * sizeof(UnlinkedSpool));
  if (!link_spools) { link_spool_count = 0; return; }

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
          if (!containsIgnoreCase(mat, subkw) && !containsIgnoreCase(fname2, subkw)) continue;
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
    // Store filament_id in existing_tag field (reuse struct field)
    snprintf(s.existing_tag, sizeof(s.existing_tag), "%d", (int)(spool["filament"]["id"] | 0));
    strncpy(s.name,     spool["filament"]["name"]           | "", sizeof(s.name)-1);
    strncpy(s.vendor,   spool["filament"]["vendor"]["name"] | "", sizeof(s.vendor)-1);
    strncpy(s.material, mat,                                      sizeof(s.material)-1);
    const char* col = spool["filament"]["color_hex"] | "333333";
    snprintf(s.color_hex, sizeof(s.color_hex), "#%s", col);
    s.total     = spool["filament"]["weight"]  | 1000.0f;
    s.remaining = spool["remaining_weight"]    | 0.0f;
    // Store spool_weight in remaining temporarily (we need it for the copy POST)
    // Use a global for spool_weight — stored in existing_tag we repurpose below
    // Actually store as: existing_tag = "filament_id:spool_weight_int"
    float spw = spool["spool_weight"] | 0.0f;
    snprintf(s.existing_tag, sizeof(s.existing_tag), "%d:%.0f", (int)(spool["filament"]["id"] | 0), spw);
    s.filament_id  = spool["filament"]["id"] | 0;
    s.spool_weight = spw;
    idx++;
  }
  link_spool_count = idx;

  if (limit_hit) {
    Serial.printf("fetchSpoolsForCopy: limit hit (%d), showing %d\n", count, spool_list_limit);
  }
  if (link_spool_count > 0) logSDf("[verbose] fetchSpoolsForCopy[0]: spool_id=%d fid=%d spw=%.0f",
    link_spools[0].id, link_spools[0].filament_id, link_spools[0].spool_weight);
  Serial.printf("fetchSpoolsForCopy: %d spools loaded (archived=%d mat=%s)\n",
    link_spool_count, (int)archived, material_filter ? material_filter : "");
}

// Spool list for copy flow — identical layout to FilteredSpoolList
void showCopySpoolList() {
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
  char title_str[32]; strncpy(title_str, T(STR_COPY_TITLE), sizeof(title_str)-1);
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

  if (link_spool_count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_copy_list);
    char empty_buf[48]; strncpy(empty_buf, T(STR_COPY_NO_SPOOLS), sizeof(empty_buf)-1);
    lv_label_set_text(lbl_empty, empty_buf);
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, 0);
    return;
  }

  lv_obj_t *list = lv_obj_create(scr_copy_list);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  int copy_display_count = (link_spool_count > spool_list_limit) ? spool_list_limit : link_spool_count;
  if (link_spool_count > spool_list_limit) {
    logSDf("CopySpoolList: limit %d applied, showing %d of %d", spool_list_limit, copy_display_count, link_spool_count);
  }
  for (int i = 0; i < copy_display_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    lv_obj_t *row = lv_btn_create(list);
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
    uint32_t swatch_col = 0x333333;
    if (s.color_hex[0] == '#' && strlen(s.color_hex) >= 7) {
      unsigned int r, g, b;
      sscanf(s.color_hex + 1, "%02X%02X%02X", &r, &g, &b);
      swatch_col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
    }
    lv_obj_set_style_bg_color(swatch, lv_color_hex(swatch_col), 0);

    lv_obj_t *lbl_rest = lv_label_create(row);
    char rest_buf[24];
    if (s.remaining <= 0 && s.total > 0) snprintf(rest_buf, sizeof(rest_buf), "%.0fg neu", s.total);
    else snprintf(rest_buf, sizeof(rest_buf), "%.0fg", s.remaining);
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
      UnlinkedSpool &sel = link_spools[idx];
      int fid = sel.filament_id;
      float spw = sel.spool_weight;
      char tmpl_name[80];
      snprintf(tmpl_name, sizeof(tmpl_name), "%s %s (%s)", sel.material, sel.name, sel.vendor);
      logSDf("BTN: CopyList row -> spool id=%d fid=%d", sel.id, fid);
      // Flag pattern: do not build new LVGL objects inside a list row callback
      copy_confirm_pending = true;
      copy_confirm_fid = fid;
      copy_confirm_remaining = sel.remaining;
      copy_confirm_initial = sel.total;
      copy_confirm_spool_w = spw;
      strncpy(copy_confirm_name, tmpl_name, sizeof(copy_confirm_name)-1);
    }, LV_EVENT_CLICKED, NULL);
  }
  if (link_spool_count > spool_list_limit) {
    addListMoreInfo(list, STR_LIST_MORE_SPOOLS);
  }
}

// ID input popup for copy flow — reuses same numpad style as link ID input
void showCopyIdInputPopup() {
  logSD("SHOW: CopyIdInputPopup");
  closeCopyIdInputPopup();
  copy_id_input[0] = '\0';

  scr_copy_id = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_copy_id, 480, 320);
  lv_obj_set_pos(scr_copy_id, 0, 0);
  lv_obj_set_style_bg_color(scr_copy_id, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr_copy_id, 0, 0);
  lv_obj_set_style_pad_all(scr_copy_id, 0, 0);
  lv_obj_set_style_radius(scr_copy_id, 0, 0);
  lv_obj_clear_flag(scr_copy_id, LV_OBJ_FLAG_SCROLLABLE);

  addBackButton(scr_copy_id, [](lv_event_t *e) { closeCopyIdInputPopup(); });

  lv_obj_t *lbl_title = lv_label_create(scr_copy_id);
  char title_buf[32]; strncpy(title_buf, T(STR_COPY_ID_BTN), sizeof(title_buf)-1);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 8);

  // Digit display
  lbl_copy_id_display = lv_label_create(scr_copy_id);
  lv_label_set_text(lbl_copy_id_display, "_");
  lv_obj_set_style_text_color(lbl_copy_id_display, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_copy_id_display, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_copy_id_display, LV_ALIGN_TOP_MID, 0, 36);

  // Status label
  lbl_copy_id_status = lv_label_create(scr_copy_id);
  lv_label_set_text(lbl_copy_id_status, "");
  lv_obj_set_style_text_color(lbl_copy_id_status, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_copy_id_status, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_copy_id_status, LV_ALIGN_TOP_MID, 0, 66);

  // Numpad: same style as link ID input (104x30, gap 4)
  const int NP_W = 104, NP_H = 30, NP_GAP = 4;
  const int NP_X0 = (480 - 3*(NP_W+NP_GAP)+NP_GAP) / 2;
  const int NP_Y0 = 84;
  const char* keys[] = {"1","2","3","4","5","6","7","8","9","<","0","OK"};
  for (int k = 0; k < 12; k++) {
    int row = k / 3, col = k % 3;
    lv_obj_t *btn = lv_btn_create(scr_copy_id);
    lv_obj_set_size(btn, NP_W, NP_H);
    lv_obj_set_pos(btn, NP_X0 + col*(NP_W+NP_GAP), NP_Y0 + row*(NP_H+NP_GAP));
    bool is_ok  = (k == 11);
    bool is_del = (k == 9);
    lv_obj_set_style_bg_color(btn, is_ok ? lv_color_hex(0x1a3020) : (is_del ? lv_color_hex(0x1a2030) : lv_color_hex(0x0a1828)), 0);
    lv_obj_set_style_radius(btn, 6, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_set_style_border_width(btn, 0, 0);
    lv_obj_t *lbl = lv_label_create(btn);
    lv_label_set_text(lbl, keys[k]);
    lv_obj_set_style_text_color(lbl, is_ok ? lv_color_hex(0x40c080) : lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 0);
    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      lv_obj_t *b = lv_event_get_target(e);
      lv_obj_t *l = lv_obj_get_child(b, 0);
      const char *txt = lv_label_get_text(l);
      if (strcmp(txt, "<") == 0) {
        int len = strlen(copy_id_input);
        if (len > 0) copy_id_input[len-1] = '\0';
      } else if (strcmp(txt, "OK") == 0) {
        if (strlen(copy_id_input) == 0) return;
        int entered_id = atoi(copy_id_input);
        if (entered_id <= 0) { lv_label_set_text(lbl_copy_id_status, "Invalid ID"); return; }
        // Fetch spool data from Spoolman (allow archived)
        if (!wifi_ok) { lv_label_set_text(lbl_copy_id_status, T(STR_LINK_NO_WIFI)); return; }
        StaticJsonDocument<512> doc;
        DeserializationError derr = DeserializationError::Ok;
        int code = backendGetSpoolJson(cfg_spoolman_base, entered_id, doc, 8000, &derr);
        if (code != 200) {
          char err_buf[32]; snprintf(err_buf, sizeof(err_buf), T(STR_LINK_ID_NOT_FOUND), entered_id);
          lv_label_set_text(lbl_copy_id_status, err_buf);
          return;
        }
        int fid      = doc["filament"]["id"] | 0;
        float ini    = doc["filament"]["weight"] | 1000.0f;
        float spw    = doc["spool_weight"] | 0.0f;
        const char *fname = doc["filament"]["name"] | "?";
        const char *fmat  = doc["filament"]["material"] | "";
        const char *fvnd  = doc["filament"]["vendor"]["name"] | "";
        char tmpl[80];
        float rem2 = doc["remaining_weight"] | 0.0f;
        snprintf(tmpl, sizeof(tmpl), "%s %s (%s)", fmat, fname, fvnd);
        showCopyConfirmPopup(fid, tmpl, rem2, ini, spw);
      } else {
        if (strlen(copy_id_input) < 6) {
          strncat(copy_id_input, txt, 1);
        }
      }
      // Update display
      char disp[10];
      snprintf(disp, sizeof(disp), "%s_", strlen(copy_id_input)?copy_id_input:"");
      lv_label_set_text(lbl_copy_id_display, disp);
    }, LV_EVENT_CLICKED, NULL);
  }
}

// Entry popup: choose ID / Active spools / Archived spools
void showCopyEntryPopup() {
  logSD("SHOW: CopyEntryPopup");
  link_selected_material[0] = 0;  // clear so NTAG always goes via vendor/material picker
  link_selected_material_full[0] = 0;
  link_stage3_shown = false;
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
  char title_buf[32]; strncpy(title_buf, T(STR_COPY_TITLE), sizeof(title_buf)-1);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 22);

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
    snprintf(ctx_buf, sizeof(ctx_buf), T(STR_LINK_CTX_NOT_IN_SM), g_tag.material);
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

  // Button layout: 3 buttons + cancel, ID= >100 recommended | List= <100 recommended
  const int BTN_W = 380, BTN_H = 48, BTN_GAP = 8;
  const int Y1 = 92, Y2 = Y1+BTN_H+BTN_GAP, Y3 = Y2+BTN_H+BTN_GAP, Y4 = Y3+BTN_H+BTN_GAP;

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
    char b[40]; strncpy(b, T(STR_COPY_ID_BTN), sizeof(b)-1);
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
    copy_flow_archived = false;
    bool is_bambu_tag = (strlen(g_tag.tray_uuid) == 32);
    if (is_bambu_tag) {
      // Bambu: use material filter if available, else show all
      fetchSpoolsForCopy(false, strlen(g_tag.material) > 0 ? g_tag.material : "", true);
      showCopySpoolList();
    } else {
      // NTAG: always go via 4-stage vendor/material picker
      copy_flow_via_list = true;
      link_flow_is_bambu = false;
      link_selected_material[0] = 0;
      link_selected_material_full[0] = 0;
      link_stage3_shown = false;
      fetchAllSpoolsForLink(false, "", false);  // active spools only
      showVendorList();
    }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn2);
    char b[40]; strncpy(b, T(STR_COPY_ACTIVE_BTN), sizeof(b)-1);
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
    copy_flow_archived = true;
    bool is_bambu_tag = (strlen(g_tag.tray_uuid) == 32);
    if (is_bambu_tag) {
      fetchSpoolsForCopy(true, strlen(g_tag.material) > 0 ? g_tag.material : "", true);
      showCopySpoolList();
    } else {
      // NTAG: always go via 4-stage vendor/material picker (archived only)
      copy_flow_via_list = true;
      link_flow_is_bambu = false;
      link_selected_material[0] = 0;
      link_selected_material_full[0] = 0;
      link_stage3_shown = false;
      fetchAllSpoolsForLink(false, "", true);  // archived only
      showVendorList();
    }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn3);
    char b[40]; strncpy(b, T(STR_COPY_ARCHIVED_BTN), sizeof(b)-1);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }

  // Button 4: Cancel
  lv_obj_t *btn4 = lv_btn_create(scr_copy_entry);
  lv_obj_set_size(btn4, BTN_W, BTN_H);
  lv_obj_align(btn4, LV_ALIGN_TOP_MID, 0, Y4);
  lv_obj_set_style_bg_color(btn4, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn4, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn4, 10, 0);
  lv_obj_set_style_shadow_width(btn4, 0, 0);
  lv_obj_set_style_border_width(btn4, 0, 0);
  lv_obj_add_event_cb(btn4, [](lv_event_t *e) { closeCopyEntryPopup(); }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn4);
    char b[16]; strncpy(b, T(STR_CANCEL), sizeof(b)-1);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }
}

void hideSpoolFlowOverlays() {
  if (link_spools) { free(link_spools); link_spools = nullptr; link_spool_count = 0; }
}

void deleteSpoolFlowOverlays() {
  if (scr_copy_entry)   { lv_obj_del(scr_copy_entry);   scr_copy_entry   = nullptr; }
  if (scr_copy_id)      { lv_obj_del(scr_copy_id);      scr_copy_id      = nullptr; }
  if (scr_copy_list)    { lv_obj_del(scr_copy_list);    scr_copy_list    = nullptr; }
  if (scr_copy_confirm) { lv_obj_del(scr_copy_confirm); scr_copy_confirm = nullptr; }
}

void handleSpoolFlowDeferredActions() {
  if (show_id_input_pending) {
    show_id_input_pending = false;
    id_input_open = false;
    link_id_lookup_pending = 0;
    copy_id_lookup_pending = 0;
    if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
    lbl_link_id_display = nullptr;
    lbl_link_id_status  = nullptr;
    // Clean up entry popups if they were hidden by X button
    if (scr_copy_entry && (lv_obj_has_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN))) {
      lv_obj_del(scr_copy_entry); scr_copy_entry = nullptr;
    }
    if (scr_link_entry && (lv_obj_has_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN))) {
      lv_obj_del(scr_link_entry); scr_link_entry = nullptr;
    }
  }
  if (show_id_input_rebuild) {
    show_id_input_rebuild = false;
    link_id_lookup_pending = 0;
    copy_id_lookup_pending = 0;
    link_id_input[0] = '\0';
    lbl_link_id_display = nullptr;
    lbl_link_id_status  = nullptr;
    // Delete old numpad BEFORE showIdInputPopup; prevents residual touch events
    // from firing the confirm callback during lv_obj_del inside showIdInputPopup.
    if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
    // Free the single-slot link_spools buffer allocated during the failed lookup
    // so the next lookup starts with a clean slate and no out-of-bounds risk.
    if (link_spools != nullptr) {
      free(link_spools);
      link_spools = nullptr;
    }
    link_spool_count = 0;
    // Pump LVGL twice to flush all residual events from the deleted screen.
    lv_timer_handler();
    lv_timer_handler();
    // Clear all pending flags AFTER pump; residual confirm callbacks may have re-set them.
    link_id_lookup_pending = 0;
    copy_id_lookup_pending = 0;
    showIdInputPopup(link_flow_is_bambu);
  }
  if (copy_confirm_pending) {
    copy_confirm_pending = false;
    // Hide copy list (keep it for cancel-back navigation), delete others.
    if (scr_copy_list) lv_obj_add_flag(scr_copy_list, LV_OBJ_FLAG_HIDDEN);
    if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
    if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
    if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_copy_entry)  { lv_obj_del(scr_copy_entry);  scr_copy_entry  = nullptr; }
    showCopyConfirmPopup(copy_confirm_fid, copy_confirm_name,
                        copy_confirm_remaining, copy_confirm_initial, copy_confirm_spool_w);
  }
  // link_id_lookup_pending removed — direct call in callback (was causing PANIC)
  if (link_id_lookup_pending > 0 && scr_link_warn_a == nullptr && scr_link_warn_b == nullptr) {
    int pid = link_id_lookup_pending;
    bool pbambu = link_id_lookup_is_bambu;
    link_id_lookup_pending = 0;
    // Close numpad before HTTP call
    if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
    lbl_link_id_display = nullptr; lbl_link_id_status = nullptr;
    id_input_open = false;
    linkIdLookupAndPatch(pid, pbambu);
  }
  if (copy_id_lookup_pending > 0) {
    int cid = copy_id_lookup_pending;
    copy_id_lookup_pending = 0;
    // Fetch spool data for copy confirm — done in loop to avoid stack overflow in lambda.
    DynamicJsonDocument cdoc(1024);
    DeserializationError derr2 = DeserializationError::Ok;
    int hcode = backendGetSpoolJson(cfg_spoolman_base, cid, cdoc, 5000, &derr2);
    if (hcode != 200) {
      if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_ID_NOT_FOUND));
    } else {
      if (!derr2) {
        int cfid   = cdoc["filament"]["id"] | 0;
        float cini = cdoc["filament"]["weight"] | 1000.0f;
        float cspw = cdoc["spool_weight"] | 0.0f;
        float crem = cdoc["remaining_weight"] | 0.0f;
        const char *cfname = cdoc["filament"]["name"] | "?";
        const char *cfmat  = cdoc["filament"]["material"] | "";
        const char *cfvnd  = cdoc["filament"]["vendor"]["name"] | "";
        char ctmpl[80];
        snprintf(ctmpl, sizeof(ctmpl), "%s %s (%s)", cfmat, cfname, cfvnd);
        lbl_link_id_display = nullptr;
        lbl_link_id_status  = nullptr;
        if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
        showCopyConfirmPopup(cfid, ctmpl, crem, cini, cspw);
      } else {
        if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_JSON_ERR));
      }
    }
  }
}

void setSpoolFlowIdInputOpen(bool open) {
  id_input_open = open;
}

bool isSpoolFlowIdInputOpen() {
  return id_input_open;
}

bool isSpoolFlowLinkEntryOpen() {
  return scr_link_entry != nullptr;
}
