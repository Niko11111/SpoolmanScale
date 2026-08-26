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
#include "services/http_progress.h"
#include "services/spoolman_api.h"
#include "services/tag_field.h"
#include "services/tag_uid.h"
#include "services/user_options.h"
#include "services/backend_api.h"
#include "services/tag_write.h"
#include "ui/loading_overlay.h"
#include "ui/main_screen_helpers.h"
#include "ui/spoolman_lookup.h"
#include "ui/tag_write_popup.h"
#include "ui/ui_common.h"
#include "services/backend.h"
#include "services/breadcrumb.h"

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
// Upper bound of the deduplicated group lists below, and the only bound they
// have. They are fixed size arrays, so a loop guarded by spool_list_limit
// alone wrote past the end as soon as a library had more than 20 vendors or
// materials - which is what this constant was introduced for.
//
// spool_list_limit is deliberately NOT checked here as well. It is the page
// size of the spool list, and a vendor picker cut down to it made a library
// with 13 vendors show 5 of them because someone had set the spool list to 5.
// These rows are cheap anyway: 716 bytes each measured on hardware, so all 20
// cost 14 kB against the 56 kB free when the picker opens.
#define LINK_GROUP_MAX 20

// True when the filament name already opens with the material. Spoolman's own
// naming does this, and BamBuddy's mapping always does ("PETG HF Orange"), so
// prefixing the material a second time would read "PETG PETG HF Orange".
static bool nameStartsWithMaterial(const char* name, const char* material) {
  if (!name || !name[0]) return false;
  if (!material || !material[0]) return true;   // nothing left to prefix with
  return strncasecmp(name, material, strlen(material)) == 0;
}

// Sort order of the link and copy lists: vendor, material, name, id, all
// case insensitive except the id. Spools without a vendor go last rather
// than first, because they are shown as "unknown" and belong at the end of
// a list, not at the top of it.
static int compareLinkSpools(const void* a, const void* b) {
  const UnlinkedSpool* x = (const UnlinkedSpool*)a;
  const UnlinkedSpool* y = (const UnlinkedSpool*)b;

  const bool xv = (x->vendor[0] != '\0');
  const bool yv = (y->vendor[0] != '\0');
  if (xv != yv) return xv ? -1 : 1;

  int c = strcasecmp(x->vendor, y->vendor);
  if (c != 0) return c;
  c = strcasecmp(x->material, y->material);
  if (c != 0) return c;
  c = strcasecmp(x->name, y->name);
  if (c != 0) return c;
  return (x->id > y->id) - (x->id < y->id);
}

// Whether a second UID can be appended at all right now: the selected tag
// field has a list format, the switch is on, and the server actually has that
// field. Probed where the list is loaded,
// never in a button callback - backendHasCardUidsField() can reach the network
// on the first call, and it is the same answer patchSpoolTag() decides on.
static bool link_cu_ok = false;

static UnlinkedSpool* link_spools = nullptr;  // PSRAM-allocated at fetch time, freed after link flow
static int            link_spool_count = 0;
// Slots actually allocated in link_spools. The fetch functions allocate an
// exact fit for what they load, so anything appending afterwards has to grow
// the block first instead of writing at link_spool_count.
static int            link_spools_capacity = 0;

// Release the spool list and reset both counters together. Splitting these up
// is how the capacity drifted out of sync with the allocation in the first place.
static void linkSpoolsFree() {
  if (link_spools) { free(link_spools); link_spools = nullptr; }
  link_spool_count    = 0;
  link_spools_capacity = 0;
}

// Grow link_spools to hold at least `needed` entries. PSRAM first, internal
// RAM as fallback, same order the fetch functions use. Returns false if the
// list could not be grown, in which case the caller must not append.
static bool linkSpoolsEnsureCapacity(int needed) {
  if (link_spools && link_spools_capacity >= needed) return true;

  size_t bytes = (size_t)needed * sizeof(UnlinkedSpool);
  UnlinkedSpool* grown = (UnlinkedSpool*)heap_caps_realloc(link_spools, bytes, MALLOC_CAP_SPIRAM);
  if (!grown) grown = (UnlinkedSpool*)realloc(link_spools, bytes);
  if (!grown) {
    logSDf("link spools: grow to %d entries failed", needed);
    return false;
  }
  link_spools          = grown;
  link_spools_capacity = needed;
  return true;
}

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
static lv_obj_t *scr_copy_list    = nullptr;  // spool list
static lv_obj_t *scr_copy_confirm = nullptr;  // confirm popup
static bool copy_flow_archived = false;        // true = showing archived spools
static bool copy_flow_via_list = false;        // true = copy flow using vendor/material list path
static bool copy_confirm_pending = false;      // deferred showCopyConfirmPopup from list row click
static int  copy_confirm_fid = 0;
// The template's own spool id. Carried alongside the filament id because the
// two backends anchor a copy differently: Spoolman points the new spool at the
// template's filament, BamBuddy has no filament as an object and reads the
// template spool back instead. In BamBuddy the filament id is always 0.
static int  copy_confirm_spool_id = 0;
static float copy_confirm_remaining = 0, copy_confirm_initial = 0, copy_confirm_spool_w = 0;
static char copy_confirm_name[80] = {};
// Template selected for copy
static int   copy_template_filament_id = 0;
static int   copy_template_spool_id    = 0;

// Creating a spool from the tag itself. Kept separate from the copy state:
// there is no template here, the tag is the only source.
static lv_obj_t *scr_newtag        = nullptr;
static lv_obj_t *lbl_newtag_info   = nullptr;
static lv_obj_t *btn_newtag_w[NEWTAG_LABEL_COUNT] = { nullptr };
static int  newtag_label_weight    = 0;
static char newtag_material[16]    = "";   // base material, "PETG"
static char newtag_subtype[24]     = "";   // what follows it, "HF"
static char newtag_rgba[10]        = "";   // RRGGBBAA
// Snapshot too, and for a sharper reason than the others: the no-tag timer in
// app_loop.cpp wipes g_tag 60 s after the tag was last seen. Reading the brand
// live at confirm time meant a slow decision produced a spool with no vendor
// at all - and on a Spoolman server that is worse than it sounds, because
// find_or_create_filament() then builds a filament with no vendor and a name
// cut down to the bare material.
static char newtag_brand[32]       = "";
static char newtag_tray[36]        = "";   // same reason as newtag_brand
static char newtag_color_name[32]  = "";   // resolved from the colour value
// Opening the popup costs an HTTP round trip for the colour name, so the
// button only raises a flag and loop() does the work - same reason as
// copy_confirm_pending above.
static bool newtag_open_pending    = false;
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
// Link overlays that hideSpoolFlowOverlays() has hidden and emptied, waiting to
// be deleted on the loop task. They must not be deleted where they are hidden:
// that call arrives from LVGL callbacks too.
static bool link_overlays_close_pending = false;
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
// Is this spool already bound to a tag?
//
// Any of the tag fields can hold one, and which one depends on what wrote it:
// this firmware writes the selected field, SpoolLink writes card_uids, FilaMan
// and SpoolSense write nfc_id. Asking only about the selected one would offer
// a spool bound elsewhere as free and let it collect a second, redundant
// binding.
static bool spoolHasAnyTag(JsonObjectConst spool) {
  JsonObjectConst extra = spool["extra"];
  if (extra.isNull()) return false;

  for (uint8_t f = 0; f < TAG_FIELD_EXTRA_COUNT; f++) {
    const char* key = tagFieldSpec(f).key;
    if (!extra.containsKey(key)) continue;
    // Spoolman stores extra values JSON encoded, so an unset field arrives as
    // a pair of literal quotes rather than as an empty string.
    String v = extra[key].as<String>();
    v.replace("\"", "");
    v.trim();
    if (v.length() > 0) return true;
  }
  return false;
}

// True when any tag field of this spool holds something, whichever one it is.
static bool linkSpoolBound(const UnlinkedSpool& s) {
  for (uint8_t f = 0; f < TAG_FIELD_EXTRA_COUNT; f++)
    if (s.tag_values[f][0]) return true;
  return false;
}

// Whether a row should be left out of a rendered list.
//
// Has to agree with the fetch filter in fetchAllSpoolsForLink(): the fetch
// keeps bound spools whenever a second UID can be appended, and a render pass
// that dropped them anyway would put them in the array and then hide them -
// which is exactly what happened when this was an open coded
// "is extra.tag set" check in six places. Bound spools simply stopped
// appearing, with nothing in the log to say why.
//
// The copy-from-archived flow is the exception it always was: there a tagged
// spool is a template, not a conflict.
static bool linkSpoolSkip(const UnlinkedSpool& s) {
  if (copy_flow_via_list && copy_flow_archived) return false;
  if (link_cu_ok) return false;
  return linkSpoolBound(s);
}

// The target spool's fields as patchSpoolTag() wants them: one pointer per
// TagFieldId, null where the field is empty. Both fetch paths fill the entry,
// so this is the single place the write decision reads from.
//
// The pointer array is static because it has to outlive the call and there is
// only ever one link in flight; the strings it points at live in the spool
// list, which is not freed until the flow closes.
static const char* s_target_values[TAG_FIELD_COUNT];

static const char* const* linkTargetValues(int spool_id) {
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].id != spool_id) continue;
    for (uint8_t f = 0; f < TAG_FIELD_EXTRA_COUNT; f++)
      s_target_values[f] = link_spools[i].tag_values[f][0]
                         ? link_spools[i].tag_values[f] : nullptr;
    return s_target_values;
  }
  return nullptr;
}

// What the next UID would be added to, for the popup to describe: the selected
// field if the spool is already bound there, otherwise whichever field does
// bind it, because that UID becomes the first entry once it is migrated.
// nullptr for an unbound spool. The popup counts what is in here and
// patchSpoolTag() writes onto it, so the number shown and the value written
// cannot drift apart.
static const char* linkTargetBase(int spool_id) {
  const char* const* v = linkTargetValues(spool_id);
  if (!v) return nullptr;
  const uint8_t eff = tagFieldEffective();
  if (v[eff]) return v[eff];
  for (uint8_t f = 0; f < TAG_FIELD_EXTRA_COUNT; f++) if (v[f]) return v[f];
  return nullptr;
}

void fetchAllSpoolsForLink(bool is_bambu, const char* material_filter, bool archived_only) {
  crumbSet("link fetch");
  // Free any previous allocation
  linkSpoolsFree();
  if (!wifi_ok) return;

  // Settled here, once, for every decision the flow makes afterwards. Offering
  // an already bound spool the scale then could not append to would put the
  // second UID straight on top of the first, which is what this guards.
  //
  // All three inputs go into the log: when a bound spool does not turn up in
  // the list, this line is what says which of them said no.
  { const bool is_list = tagFieldIsList();
    const bool present = is_list && backendHasExtraField(tagFieldKey());
    link_cu_ok = is_list && g_card_uids_write && present;
    logSDf("link fetch: append=%d (field=%s list=%d write=%d present=%d)",
           link_cu_ok ? 1 : 0, tagFieldKeyName(), is_list ? 1 : 0,
           g_card_uids_write ? 1 : 0, present ? 1 : 0); }

  // Up before the blocking work, and painted before this returns. The reader
  // below moves it along, so the wait stops looking like a hang.
  loadingOverlayShow(T(STR_LOADING_SPOOLS));
  httpSetProgressHook(loadingOverlayProgress);

  logSDf("link fetch: is_bambu=%d material_filter='%s' archived_only=%d",
    is_bambu, material_filter ? material_filter : "", (int)archived_only);

  StaticJsonDocument<512> filterL;
  JsonArray filterL_arr = filterL.to<JsonArray>();
  JsonObject fL = filterL_arr.createNestedObject();
  fL["id"] = true;
  fL["archived"] = true;
  fL["remaining_weight"] = true;
  // Every tag field: a spool can be bound through any of them, and the link
  // flow has to see that whichever one the user has selected right now.
  for (uint8_t f = 0; f < TAG_FIELD_EXTRA_COUNT; f++)
    fL["extra"][tagFieldSpec(f).key] = true;
  fL["filament"]["id"] = true;
  fL["filament"]["name"] = true;
  fL["filament"]["material"] = true;
  fL["filament"]["weight"] = true;
  fL["filament"]["color_hex"] = true;
  fL["filament"]["vendor"]["name"] = true;
  fL["spool_weight"] = true;
  if (filterL.overflowed())
    logSD("link fetch: filter overflowed, fields will be missing");
  SpiRamAllocator psram_alloc;
  JsonDocument doc(&psram_alloc);
  DeserializationError err = DeserializationError::Ok;
  int code = backendGetSpoolListJson(cfg_spoolman_base, archived_only, doc, 8000, &filterL, &err);
  httpSetProgressHook(nullptr);
  if (code != 200 || err) { loadingOverlayHide(); return; }

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

    // Skip already-linked spools - only in normal link flow.
    // In copy-archived flow, archived spools are templates (typically still tagged) -> don't skip.
    // While a second UID can be appended, an already bound spool stays in the
    // list whichever field binds it: that is the only way to add the tag on the
    // other flange from the scale, and WarnPopupA catches the selection before
    // anything is written. This used to ask for card_uids specifically, which
    // left out every spool bound through any other field.
    if (!archived_only && !link_cu_ok && spoolHasAnyTag(spool)) {
      skipped_tag++; count_linked++; continue;
    }

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

  { char buf[48];
    snprintf(buf, sizeof(buf), T(STR_LOADING_FILTER), total_in_api);
    loadingOverlaySetText(buf); }

  logSDf("Spoolman inventory: %d total | %d linked | %d unlinked | %d Bambu",
    total_in_api, count_linked, total_in_api - count_linked, count_bambu);
  Serial.printf("Spoolman inventory: %d total | %d linked | %d unlinked | %d Bambu\n",
    total_in_api, count_linked, total_in_api - count_linked, count_bambu);
  logSDf("link fetch: total=%d matched=%d (skip_tag=%d skip_vendor=%d skip_mat=%d)",
    total_in_api, matched, skipped_tag, skipped_vendor, skipped_material);
  Serial.printf("link fetch: total=%d matched=%d (skip_tag=%d skip_vendor=%d skip_mat=%d)\n",
    total_in_api, matched, skipped_tag, skipped_vendor, skipped_material);

  if (matched == 0) { loadingOverlayHide(); return; }

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
  if (!link_spools) { logSD("link fetch: alloc failed completely"); loadingOverlayHide(); return; }
  link_spools_capacity = alloc_count;

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

    if (!archived_only && !link_cu_ok && spoolHasAnyTag(spool)) continue;

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

    // Which field binds this spool decides everything the flow does next:
    // whether it is offered at all, whether the warning says "overwrite" or
    // "add", and whether the write appends to a list or migrates a UID out of
    // one field into another.
    //
    // Never keep a shortened value: appending to a truncated list would drop
    // the entries that fell off the end. Empty means "unknown", and the write
    // then treats the spool as unbound rather than acting on half a list.
    for (uint8_t f = 0; f < TAG_FIELD_EXTRA_COUNT; f++) {
      s.tag_values[f][0] = '\0';
      const char* key = tagFieldSpec(f).key;
      if (!spool.containsKey("extra") || !spool["extra"].containsKey(key)) continue;
      String v = spool["extra"][key].as<String>();
      v.replace("\"",""); v.trim();
      if (v.length() == 0) continue;
      if (v.length() < CARD_UIDS_MAX) {
        strncpy(s.tag_values[f], v.c_str(), CARD_UIDS_MAX - 1);
        s.tag_values[f][CARD_UIDS_MAX - 1] = '\0';
      } else {
        logSDf("link fetch: %s of spool %d too long (%d), ignored",
               key, s.id, (int)v.length());
      }
    }

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
  // One sort puts all three levels of the link flow in order. The vendor and
  // material lists are built from the order of first appearance in this
  // array, so they inherit whatever order it has, and that used to be
  // whatever the server happened to return. Spoolman answers in database
  // order, FilaMan in its own, and neither is meaningful to a user.
  //
  // vendor, then material, then name, then id. Where the name is already
  // fixed, which is the case in the final list, that leaves plain ascending
  // ids.
  qsort(link_spools, link_spool_count, sizeof(UnlinkedSpool), compareLinkSpools);

  loadingOverlayHide();
  Serial.printf("fetchAllSpoolsForLink: %d spools loaded (PSRAM, sorted)\n", link_spool_count);
  logSDf("link fetch done: %d spools in list", link_spool_count);
}

// Legacy wrapper for compatibility
void fetchUnlinkedSpools() { fetchAllSpoolsForLink(false, ""); }

// ============================================================
//  SPOOLMAN: SAVE TAG UUID (extra.tag)
// ============================================================
// Tears down every screen of the link flow and frees the PSRAM spool list.
// Both the successful and the aborted path need exactly this.
static void closeLinkOverlays() {
  if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
  if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id     = nullptr; }
  if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
  if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }
  if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
  if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
  if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
  if (scr_link_list)   { lv_obj_del(scr_link_list);   scr_link_list   = nullptr; }
  linkSpoolsFree();
}

// ============================================================
//  LINK FLOW: COMPLETE LINKING
//  PATCH + update main screen
// ============================================================
// Set at the end of a link, picked up on the next pass. Not built there and
// then: doLinkPatch() is reached from LVGL callbacks as well as from this
// handler, and an overlay must never be built out of the callback of the one
// it covers.
static int tagwrite_ask_spool_id = 0;

void doLinkPatch(int spool_id, bool is_bambu) {
  crumbSet("link patch");
  const char* link_uuid = is_bambu ? g_tag.tray_uuid : link_tag_uid;
  Serial.printf("doLinkPatch: ID=%d uuid='%s'\n", spool_id, link_uuid ? link_uuid : "");

  // Linking without a UID must never reach patchSpoolTag. An empty value is
  // the unlink signal there: FilaMan is sent rfid_uid null, Spoolman an empty
  // extra.tag, and both answer 200. The screen afterwards reloads the spool
  // by id, so it looks linked while the tag field is in fact empty.
  //
  // The UID comes from a buffer that is cleared whenever the tag display is
  // reset, so it can legitimately be gone by the time the user finishes
  // picking a spool. That is a failed link, not an unlink.
  if (!link_uuid || !link_uuid[0]) {
    logSDf("LINK ABORT: no tag UID for spool %d (bambu=%d)", spool_id, is_bambu ? 1 : 0);
    Serial.println("doLinkPatch: aborted, no tag UID");
    if (lbl_status) {
      char buf[48];
      strncpy(buf, T(STR_LINK_NO_TAG), sizeof(buf) - 1);
      buf[sizeof(buf) - 1] = '\0';
      lv_label_set_text(lbl_status, buf);
      lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xff8080), 0);
    }
    closeLinkOverlays();
    return;
  }

  // Both stores go along: the list is appended to when there is one, and the
  // tag field's UID becomes the list's first entry when there is not. Null for
  // an unbound spool, and for every spool at all while the switch is off.
  if (!patchSpoolTag(spool_id, link_uuid, linkTargetValues(spool_id))) {
    // Nothing was written - the list was full, or the request failed. Saying
    // nothing here would look like a successful link right up to the next scan.
    logSDf("LINK ABORT: tag field of spool %d not written", spool_id);
    if (lbl_status) {
      char buf[48];
      // Spoolman refuses a UID that another spool holds and says which one.
      // Naming it is the difference between "that did not work" and something
      // the user can act on.
      if (sm_tag_conflict_spool > 0) {
        snprintf(buf, sizeof(buf), T(STR_TAG_ON_OTHER_SPOOL), sm_tag_conflict_spool);
        sm_tag_conflict_spool = 0;
      } else {
        strncpy(buf, T(STR_CU_NOT_WRITTEN), sizeof(buf) - 1);
      }
      buf[sizeof(buf) - 1] = '\0';
      lv_label_set_text(lbl_status, buf);
      lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xff8080), 0);
    }
    closeLinkOverlays();
    return;
  }

  closeLinkOverlays();

  // Re-query Spoolman — use single-spool endpoint since we know the ID
  link_popup_dismissed = false;
  if (is_bambu) {
    tagLookupForget();
    querySpoolmanById(spool_id);
  } else {
    strncpy(g_tag.uid_str, link_tag_uid, sizeof(g_tag.uid_str)-1);
    g_tag.uid_str[sizeof(g_tag.uid_str)-1] = '\0';
    strncpy(g_tag.tray_uuid, link_tag_uid, sizeof(g_tag.tray_uuid)-1);
    g_tag.tray_uuid[sizeof(g_tag.tray_uuid)-1] = '\0';
    tagLookupForget();
    querySpoolmanById(spool_id);
  }

  // The spool is known and an NTAG is lying on the reader, so its data can go
  // onto the tag as well - the one moment where that costs the user nothing but
  // one answer. Bambu tags are read-only and MIFARE is not ours to write, so
  // both are left out by the same test the tag page uses.
  if (!is_bambu && tagIsWritableNtag()) tagwrite_ask_spool_id = spool_id;

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
void showWarnPopupA(int spool_id, const char* existing_tag, bool is_bambu,
                    const char* link_uuid, bool add_mode) {
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
  lv_label_set_text(lbl_title, T(add_mode ? STR_WARN_A_ADD_TITLE : STR_WARN_A_TITLE));
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
  if (add_mode) {
    // The UID list is too long to show and too dull to read. The count is what
    // the user needs in order to recognise the spool as one that is already
    // bound, and nothing is being replaced here anyway.
    const int n = cardUidsCount(existing_tag);
    if (sm_mat[0] || sm_name[0]) {
      snprintf(info_buf, sizeof(info_buf), T(STR_WARN_A_ADD_INFO),
        spool_id, sm_mat, sm_name, n);
    } else {
      snprintf(info_buf, sizeof(info_buf), T(STR_WARN_A_ADD_SHORT), spool_id, n);
    }
  } else if (sm_mat[0] || sm_name[0]) {
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
  // Adding is not the destructive act overwriting is, so it gets the calm
  // green of a normal confirmation rather than the warning amber.
  lv_obj_set_style_bg_color(btn_force, lv_color_hex(add_mode ? 0x1a3020 : 0x3a2800), 0);
  lv_obj_set_style_bg_color(btn_force, lv_color_hex(add_mode ? 0x2a5030 : 0x5a4000), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_force, 8, 0);
  lv_obj_set_style_shadow_width(btn_force, 0, 0);
  lv_obj_set_style_border_width(btn_force, 0, 0);
  lv_obj_add_event_cb(btn_force, [](lv_event_t *e) {
    if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id = nullptr; }
    doLinkPatch(warn_a_spool_id, warn_a_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_force = lv_label_create(btn_force);
  lv_label_set_text(lbl_force, T(add_mode ? STR_BTN_ADD_UID : STR_BTN_OVERWRITE));
  lv_obj_set_style_text_color(lbl_force, lv_color_hex(add_mode ? 0x40c080 : 0xf0b838), 0);
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
  char fmt_b[160]; backendText(T(STR_WARN_B_DETAILS), fmt_b, sizeof(fmt_b));
  snprintf(mat_buf, sizeof(mat_buf), fmt_b,
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

  // The ID path skips the list fetch, so it has to settle this for itself.
  link_cu_ok = tagFieldIsList() && g_card_uids_write &&
               backendHasExtraField(tagFieldKey());

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
  // A spool managed by SpoolLink has an empty tag field but is bound all the
  // same. Kept apart from the tag field, because which of the two is set
  // decides whether the warning offers to overwrite or to add.
  String existing_cu = "";
  if (doc.containsKey("extra") && doc["extra"].containsKey(CARD_UIDS_FIELD)) {
    existing_cu = doc["extra"][CARD_UIDS_FIELD].as<String>();
    existing_cu.replace("\"",""); existing_cu.trim();
  }

  bool found_in_list = false;
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].id == entered_id) { found_in_list = true; break; }
  }
  // A hand entered ID is appended to the list so the rest of the flow can look
  // it up like any other spool. The list is either absent (no list loaded) or
  // allocated to an exact fit by the fetch functions, so it has to be grown
  // first - writing at link_spool_count without that was a heap overflow of one
  // UnlinkedSpool past the end of the block.
  if (!found_in_list && linkSpoolsEnsureCapacity(link_spool_count + 1)) {
    UnlinkedSpool &s = link_spools[link_spool_count];
    s.id = entered_id;
    // Same rule as the list fetch: too long is stored as empty, never cut.
    for (uint8_t f = 0; f < TAG_FIELD_EXTRA_COUNT; f++) {
      s.tag_values[f][0] = '\0';
      const char* key = tagFieldSpec(f).key;
      if (!doc.containsKey("extra") || !doc["extra"].containsKey(key)) continue;
      String v = doc["extra"][key].as<String>();
      v.replace("\"",""); v.trim();
      if (v.length() > 0 && v.length() < CARD_UIDS_MAX) {
        strncpy(s.tag_values[f], v.c_str(), CARD_UIDS_MAX - 1);
        s.tag_values[f][CARD_UIDS_MAX - 1] = '\0';
      }
    }
    String mat = doc["filament"]["material"] | String("");
    mat.trim(); strncpy(s.material, mat.c_str(), sizeof(s.material)-1);
    s.material[sizeof(s.material)-1] = '\0';
    String fname = doc["filament"]["name"] | String("?");
    fname.trim(); strncpy(s.name, fname.c_str(), sizeof(s.name)-1);
    s.name[sizeof(s.name)-1] = '\0';
    String vnd = doc["filament"]["vendor"]["name"] | String("");
    vnd.trim(); strncpy(s.vendor, vnd.c_str(), sizeof(s.vendor)-1);
    s.vendor[sizeof(s.vendor)-1] = '\0';
    String col = doc["filament"]["color_hex"] | String("");
    col.trim();
    if (col.length() > 0 && col[0] != '#') col = "#" + col;
    strncpy(s.color_hex, col.c_str(), sizeof(s.color_hex)-1);
    s.color_hex[sizeof(s.color_hex)-1] = '\0';
    // The four numbers the list fetch fills and this path used to leave alone.
    // link_spools[] comes from heap_caps_malloc, which does not zero, so a row
    // rendered afterwards showed whatever the block held before, and the copy
    // flow would have carried that straight into a new spool as its filament
    // id. Read from the same document as everything above.
    s.remaining    = doc["remaining_weight"] | 0.0f;
    s.total        = doc["filament"]["weight"] | 0.0f;
    s.filament_id  = doc["filament"]["id"] | 0;
    s.spool_weight = doc["spool_weight"] | 0.0f;
    link_spool_count++;
  }

  // While appending is possible neither store is being replaced, so both get
  // the friendlier "add one" variant - the tag field's UID moves into the list
  // and the new one joins it there. The list wins when both are set, because
  // that is the one being written.
  //
  // Without it the tag field wins instead: overwriting it is the destructive
  // case and has to be asked about first.
  if (link_cu_ok && (existing_cu.length() > 0 || existing.length() > 0)) {
    showWarnPopupA(entered_id,
                   existing_cu.length() > 0 ? existing_cu.c_str() : existing.c_str(),
                   is_bambu, "", true);
    return;
  }
  if (existing.length() > 0) {
    showWarnPopupA(entered_id, existing.c_str(), is_bambu, "");
    return;
  }
  if (existing_cu.length() > 0) {
    showWarnPopupA(entered_id, existing_cu.c_str(), is_bambu, "", false);
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
  { char tb[40]; backendText(T(STR_LINK_ID_TITLE), tb, sizeof(tb)); lv_label_set_text(lbl_title, tb); }
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
          if (lbl_link_id_status) { char tb[40]; backendText(T(STR_LINK_ID_TITLE), tb, sizeof(tb)); lv_label_set_text(lbl_link_id_status, tb); }
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

// Whether a spool belongs in the filtered list. One function, because the
// count above the list and the rows in it used to decide separately and did
// not agree: the count skipped Bambu vendors in the non-Bambu flow while the
// rows kept them, so picking "Bambu Lab" from the vendor list produced a
// heading that said 0 over two rows. In the Bambu flow the count matched on
// material_prefix and the rows on g_tag.material, which drifted the same way.
static bool linkRowMatches(const UnlinkedSpool &s, const char* vendor_name,
                           const char* material_prefix, const char* material_full) {
  if (linkSpoolSkip(s)) return false;

  if (link_flow_is_bambu) {
    // The tag names its own vendor, so only Bambu spools can answer to it.
    if (strncasecmp(s.vendor, "Bambu", 5) != 0) return false;
    if (g_tag.material[0] && s.material[0]) {
      if (isSupportMaterial(g_tag.material)) {
        // Support tags: match Spoolman materials ending in "-S"
        if (!isSupportSpoolmanMat(s.material)) return false;
      } else {
        if (strncasecmp(s.material, g_tag.material, 3) != 0) return false;
        // Exclude support materials from non-support display
        if (isSupportSpoolmanMat(s.material)) return false;
      }
    }
    return true;
  }

  // Flow B: whatever the user picked in the vendor and material lists. Bambu
  // is a vendor like any other here - the tag is an NTAG and says nothing
  // about who made the filament.
  if (vendor_name[0] &&
      strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) return false;
  if (material_prefix[0] &&
      strncasecmp(s.material, material_prefix, strlen(material_prefix)) != 0) return false;
  // Stage 3: full material name match (exact, case-insensitive)
  if (material_full && material_full[0] &&
      strcasecmp(s.material, material_full) != 0) return false;
  return true;
}

void showFilteredSpoolList(const char* vendor_name, const char* material_prefix, const char* material_full) {
  crumbSet("spool list build");
  logSDf("SHOW: FilteredSpoolList vendor=%s mat=%s matf=%s", vendor_name, material_prefix, material_full ? material_full : "");
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }

  scr_link_spools = buildLinkOverlay();

  // Count matching spools for title
  int display_count = 0;
  for (int i = 0; i < link_spool_count; i++) {
    if (!linkRowMatches(link_spools[i], vendor_name, material_prefix, material_full)) continue;
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
  logLvMem("spoollist/pre", 0);

  int count = 0;
  for (int i = 0; i < link_spool_count; i++) {
    if (count >= spool_list_limit) break;  // render limit — full data is still in link_spools[]
    UnlinkedSpool &s = link_spools[i];

    // The same question the count above asked, asked once.
    if (!linkRowMatches(s, vendor_name, material_prefix, material_full)) continue;

    count++;
    // A row is five objects. LVGL 8.3 answers an exhausted pool with NULL and
    // asserts nothing, and every widget constructor writes through that pointer
    // one line later - so running out here is a panic reboot, not the freeze the
    // assert handler suggests. Asked before the row rather than after each of its
    // objects, because the pool ran out between the second and the third.
    if (!lvPoolHasRoomForRow()) {
      logSDf("FilteredSpoolList: LVGL pool low, list cut at %d rows", count);
      break;
    }
    lv_obj_t *row = lv_btn_create(list);
    if (!row) { logSDf("FilteredSpoolList: no room for a row, list cut at %d", count); break; }
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
    lv_obj_set_style_bg_color(swatch, swatchColorFromHex(s.color_hex), 0);

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
        // The same test the row callback does before it opens this popup. It is
        // needed twice because the array can be freed between the two taps:
        // anything that reaches hideAllOverlays() does that, a backend switch
        // from the browser among them, and the popup outlives it.
        if (!link_spools || cidx < 0 || cidx >= link_spool_count) {
          logSDf("Link confirm: spool list gone, ignoring idx=%d", cidx);
          return;
        }
        if (copy_flow_via_list) {
          // Copy flow via vendor/material picker — flag pattern
          copy_flow_via_list = false;
          UnlinkedSpool &cs = link_spools[cidx];
          logSDf("CopyConfirm via list: spool_id=%d fid=%d spw=%.0f", cs.id, cs.filament_id, cs.spool_weight);
          copy_confirm_fid = cs.filament_id;
          copy_confirm_spool_id = cs.id;
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
        } else if (link_cu_ok && linkTargetBase(link_spools[cidx].id)) {
          // Only bound spools get a second dialog, and only because they are
          // the ones the list would have hidden before the switch existed.
          // The confirmation behind us says which spool, this one says that it
          // is already bound and that nothing will be replaced.
          showWarnPopupA(link_spools[cidx].id, linkTargetBase(link_spools[cidx].id),
                         link_flow_is_bambu, "", true);
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

  logLvMem("spoollist/post", count);
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
  link_selected_vendor[sizeof(link_selected_vendor)-1] = '\0';
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
  logLvMem("matlist/pre", 0);

  // Deduplicate material prefixes (3 chars) for the selected vendor
  static char seen_mats[LINK_GROUP_MAX][4] = {};
  static int  mat_counts[LINK_GROUP_MAX]   = {};
  static int  seen_count       = 0;
  seen_count = 0;
  memset(seen_mats, 0, sizeof(seen_mats));
  memset(mat_counts, 0, sizeof(mat_counts));

  bool mat_limit_hit = false;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (linkSpoolSkip(s)) continue;
    if (strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
    if (!s.material[0]) continue;
    char prefix[4]; strncpy(prefix, s.material, 3); prefix[3] = '\0';
    bool found = false;
    for (int j = 0; j < seen_count; j++) {
      if (strncasecmp(seen_mats[j], prefix, 3) == 0) { mat_counts[j]++; found = true; break; }
    }
    if (!found) {
      if (seen_count >= LINK_GROUP_MAX) { mat_limit_hit = true; continue; }
      strncpy(seen_mats[seen_count], prefix, 3);
      mat_counts[seen_count] = 1;
      seen_count++;
    }
  }

  for (int m = 0; m < seen_count; m++) {
    // A row is five objects. LVGL 8.3 answers an exhausted pool with NULL and
    // asserts nothing, and every widget constructor writes through that pointer
    // one line later - so running out here is a panic reboot, not the freeze the
    // assert handler suggests. Asked before the row rather than after each of its
    // objects, because the pool ran out between the second and the third.
    if (!lvPoolHasRoomForRow()) {
      logSDf("MaterialList: LVGL pool low, list cut at %d rows", m);
      break;
    }
    lv_obj_t *row = lv_btn_create(list);
    if (!row) { logSDf("MaterialList: no room for a row, list cut at %d", m); break; }
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
      link_selected_material[sizeof(link_selected_material)-1] = '\0';
      link_selected_material_full[0] = 0;  // reset for new branch
      if (scr_link_mat) { lv_obj_del(scr_link_mat); scr_link_mat = nullptr; }
      showMaterialSubList(link_selected_vendor, link_selected_material);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)m);
  }

  logLvMem("matlist/post", seen_count);
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
  static char seen_full[LINK_GROUP_MAX][32] = {};
  static int  full_counts[LINK_GROUP_MAX]   = {};
  static int  full_seen_count   = 0;
  full_seen_count = 0;
  memset(seen_full, 0, sizeof(seen_full));
  memset(full_counts, 0, sizeof(full_counts));

  bool full_limit_hit = false;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (linkSpoolSkip(s)) continue;
    if (strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
    if (!s.material[0]) continue;
    if (strncasecmp(s.material, material_prefix, strlen(material_prefix)) != 0) continue;

    bool found = false;
    for (int j = 0; j < full_seen_count; j++) {
      if (strcasecmp(seen_full[j], s.material) == 0) { full_counts[j]++; found = true; break; }
    }
    if (!found) {
      if (full_seen_count >= LINK_GROUP_MAX) { full_limit_hit = true; continue; }
      strncpy(seen_full[full_seen_count], s.material, sizeof(seen_full[0])-1);
      full_counts[full_seen_count] = 1;
      full_seen_count++;
    }
  }

  // Auto-skip stage 3 when only one full name found — go directly to stage 4
  if (full_seen_count == 1 && !full_limit_hit) {
    logSDf("MaterialSubList auto-skip: only %s", seen_full[0]);
    strncpy(link_selected_material_full, seen_full[0], sizeof(link_selected_material_full)-1);
    link_selected_material_full[sizeof(link_selected_material_full)-1] = '\0';
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
  logLvMem("matsublist/pre", 0);

  for (int m = 0; m < full_seen_count; m++) {
    // A row is five objects. LVGL 8.3 answers an exhausted pool with NULL and
    // asserts nothing, and every widget constructor writes through that pointer
    // one line later - so running out here is a panic reboot, not the freeze the
    // assert handler suggests. Asked before the row rather than after each of its
    // objects, because the pool ran out between the second and the third.
    if (!lvPoolHasRoomForRow()) {
      logSDf("MaterialSubList: LVGL pool low, list cut at %d rows", m);
      break;
    }
    lv_obj_t *row = lv_btn_create(list);
    if (!row) { logSDf("MaterialSubList: no room for a row, list cut at %d", m); break; }
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
      link_selected_material_full[sizeof(link_selected_material_full)-1] = '\0';
      if (scr_link_mat_sub) { lv_obj_del(scr_link_mat_sub); scr_link_mat_sub = nullptr; }
      showFilteredSpoolList(link_selected_vendor, link_selected_material, link_selected_material_full);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)m);
  }

  logLvMem("matsublist/post", full_seen_count);
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
  crumbSet("vendor list build");
  logSD("SHOW: VendorList");
  if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }

  scr_link_vendor = buildLinkOverlay();

  // Zaehle Spulen gesamt (ohne bereits verknuepft)
  int total_unlinked = 0;
  for (int i = 0; i < link_spool_count; i++) {
    if (linkSpoolSkip(link_spools[i])) continue;
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
  logLvMem("vendorlist/pre", 0);

  // Dedupliziere Vendors
  static char seen_vendors[LINK_GROUP_MAX][32] = {};
  static int  vendor_counts[LINK_GROUP_MAX]    = {};
  static int  seen_v               = 0;
  seen_v = 0;
  memset(seen_vendors, 0, sizeof(seen_vendors));
  memset(vendor_counts, 0, sizeof(vendor_counts));

  bool vendor_limit_hit = false;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (linkSpoolSkip(s)) continue;
    const char* vn = s.vendor[0] ? s.vendor : "Unbekannt";
    bool found = false;
    for (int j = 0; j < seen_v; j++) {
      if (strcasecmp(seen_vendors[j], vn) == 0) { vendor_counts[j]++; found = true; break; }
    }
    if (!found) {
      if (seen_v >= LINK_GROUP_MAX) { vendor_limit_hit = true; continue; }
      strncpy(seen_vendors[seen_v], vn, 31);
      vendor_counts[seen_v] = 1;
      seen_v++;
    }
  }

  for (int v = 0; v < seen_v; v++) {
    // A row is five objects. LVGL 8.3 answers an exhausted pool with NULL and
    // asserts nothing, and every widget constructor writes through that pointer
    // one line later - so running out here is a panic reboot, not the freeze the
    // assert handler suggests. Asked before the row rather than after each of its
    // objects, because the pool ran out between the second and the third.
    if (!lvPoolHasRoomForRow()) {
      logSDf("VendorList: LVGL pool low, list cut at %d rows", v);
      break;
    }
    lv_obj_t *row = lv_btn_create(list);
    if (!row) { logSDf("VendorList: no room for a row, list cut at %d", v); break; }
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

  logLvMem("vendorlist/post", seen_v);
  if (seen_v == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_vendor);
    { char eb[80]; backendText(T(STR_NO_VENDORS), eb, sizeof(eb)); lv_label_set_text(lbl_empty, eb); }
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
    char fmt_c[48]; backendText(T(STR_LINK_CTX_NOT_IN_SM), fmt_c, sizeof(fmt_c));
    snprintf(ctx_buf, sizeof(ctx_buf), fmt_c,
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
//  Limit: spool_list_limit rows shown, from NVS "list_limit".
// ============================================================

void closeCopyEntryPopup() {
  if (scr_copy_entry) { lv_obj_del(scr_copy_entry); scr_copy_entry = nullptr; }
}

void closeCopyListPopup() {
  if (scr_copy_list) { lv_obj_del(scr_copy_list); scr_copy_list = nullptr; }
}

void closeCopyConfirmPopup() {
  if (scr_copy_confirm) { lv_obj_del(scr_copy_confirm); scr_copy_confirm = nullptr; }
}

// Patch newly created spool with tag UID and query it on main screen
void finishCopyFlow(int new_spool_id, const char* tray_uuid_override = nullptr) {
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
  patchSpoolTag(new_spool_id, tag_to_write);
  sm_id = new_spool_id;
  sm_found = true;
  tagLookupForget();
  if (is_bambu_tag) {
    querySpoolman(tray);
  } else {
    querySpoolmanById(new_spool_id);
  }
  updateLinkButton();
  showMainScreen();  // navigate to main after copy flow completes
}

// Creates the new spool from the template, then attaches the tag.
void doCopySpoolCreate(int template_spool_id, int template_filament_id,
                       float template_initial, float template_spool_w) {
  if (!wifi_ok) return;
  float netto = scale_weight_g - template_spool_w;
  if (netto < 0) netto = 0;

  int new_id = 0;
  int code = backendCreateSpool(cfg_spoolman_base, template_spool_id, template_filament_id,
    template_initial, template_spool_w, netto, &new_id, 8000);
  if ((code == 200 || code == 201) && new_id > 0) {
    Serial.printf("Copy spool created: new ID=%d\n", new_id);
    logSDf("Copy spool created: tmpl_spool=%d fid=%d new_spool_id=%d",
           template_spool_id, template_filament_id, new_id);
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
void showCopyConfirmPopup(int template_spool_id, int template_filament_id,
                           const char* template_name,
                           float template_remaining, float template_initial, float template_spool_w) {
  closeCopyConfirmPopup();
  copy_template_spool_id    = template_spool_id;
  copy_template_filament_id = template_filament_id;
  copy_template_initial      = template_initial;
  copy_template_spool_w      = template_spool_w;
  strncpy(copy_template_name, template_name, sizeof(copy_template_name)-1);
  copy_template_name[sizeof(copy_template_name)-1] = '\0';

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
    int sid   = copy_template_spool_id;
    int fid   = copy_template_filament_id;
    float ini = copy_template_initial;
    float spw = copy_template_spool_w;
    closeCopyConfirmPopup();
    closeCopyListPopup();
    closeCopyEntryPopup();
    doCopySpoolCreate(sid, fid, ini, spw);
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
// Uses PSRAM allocator. Max spool_list_limit entries shown.
void fetchSpoolsForCopy(bool archived, const char* material_filter, bool is_bambu_tag) {
  // Free previous list
  linkSpoolsFree();

  if (!wifi_ok) return;

  loadingOverlayShow(T(STR_LOADING_SPOOLS));
  httpSetProgressHook(loadingOverlayProgress);

  SpiRamAllocator alloc;
  JsonDocument doc(&alloc);
  DeserializationError err = DeserializationError::Ok;
  int code = backendGetSpoolListJson(cfg_spoolman_base, true, doc, 10000, nullptr, &err);
  httpSetProgressHook(nullptr);
  if (code != 200 || err) {
    loadingOverlayHide();
    Serial.printf("fetchSpoolsForCopy JSON error: %s\n", err.c_str());
    return;
  }

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

  { char buf[48];
    snprintf(buf, sizeof(buf), T(STR_LOADING_FILTER), count);
    loadingOverlaySetText(buf); }

  bool limit_hit = (count > spool_list_limit);
  int alloc_count = limit_hit ? spool_list_limit : count;

  link_spools = (UnlinkedSpool*)heap_caps_malloc(alloc_count * sizeof(UnlinkedSpool), MALLOC_CAP_SPIRAM);
  if (!link_spools) link_spools = (UnlinkedSpool*)malloc(alloc_count * sizeof(UnlinkedSpool));
  if (!link_spools) { link_spool_count = 0; loadingOverlayHide(); return; }
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
}

// Spool list for copy flow — identical layout to FilteredSpoolList
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
    lv_obj_set_style_bg_color(swatch, swatchColorFromHex(s.color_hex), 0);

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
    }, LV_EVENT_CLICKED, NULL);
  }
  logLvMem("copylist/post", copy_display_count);
  if (link_spool_count > spool_list_limit) {
    addListMoreInfo(list, STR_LIST_MORE_SPOOLS);
  }
}

// ============================================================
//  CREATE A SPOOL FROM THE TAG
//
//  The way out when no template fits: a brand new Bambu spool whose type is
//  not in the inventory yet. Everything the server needs is already on the
//  tag except the weights - the tag carries no gram value at all - so the
//  core is assumed to be a Bambu one and the nominal weight is picked from
//  the scale and left editable.
//
//  BamBuddy only. Spoolman and FilaMan want a filament_id for a new spool,
//  and a tag cannot supply one.
// ============================================================

void closeNewTagPopup() {
  if (scr_newtag) { lv_obj_del(scr_newtag); scr_newtag = nullptr; }
  lbl_newtag_info = nullptr;
  for (int i = 0; i < NEWTAG_LABEL_COUNT; i++) btn_newtag_w[i] = nullptr;
}

// Net filament on the pad, measured against the assumed Bambu core.
static float newTagNetto() {
  float netto = scale_weight_g - (float)BAMBU_CORE_WEIGHT_G;
  return netto < 0 ? 0 : netto;
}

// Repaints the four choices so the active one is obvious, and refreshes the
// text underneath it.
static void newTagRefresh() {
  static const int choices[NEWTAG_LABEL_COUNT] = NEWTAG_LABEL_CHOICES;
  for (int i = 0; i < NEWTAG_LABEL_COUNT; i++) {
    if (!btn_newtag_w[i]) continue;
    bool on = (choices[i] == newtag_label_weight);
    lv_obj_set_style_bg_color(btn_newtag_w[i], lv_color_hex(on ? 0x1a4020 : 0x0a1e30), 0);
    lv_obj_set_style_border_width(btn_newtag_w[i], 1, 0);
    lv_obj_set_style_border_color(btn_newtag_w[i], lv_color_hex(on ? 0x28d49a : 0x1a3060), 0);
  }
  if (lbl_newtag_info) {
    char msg[192];
    snprintf(msg, sizeof(msg), T(STR_NEWTAG_MSG),
             newtag_brand, g_tag.material,
             newtag_color_name[0] ? newtag_color_name : g_tag.color_hex,
             newTagNetto());
    lv_label_set_text(lbl_newtag_info, msg);
  }
}

// Creates the spool and hands it to the main screen, exactly as a copy would.
void doCreateSpoolFromTag() {
  if (!wifi_ok) return;

  int new_id = 0;
  int code = backendCreateSpoolFromTag(newtag_material, newtag_subtype, newtag_brand,
                                       newtag_rgba, newtag_color_name, newtag_label_weight,
                                       BAMBU_CORE_WEIGHT_G, newTagNetto(),
                                       g_tag.temp_min, g_tag.temp_max, &new_id, 8000);
  if ((code == 200 || code == 201) && new_id > 0) {
    Serial.printf("New spool from tag: new ID=%d\n", new_id);
    logSDf("New spool from tag: mat=%s sub=%s brand=%s col=%s label=%d new_spool_id=%d",
           newtag_material, newtag_subtype, newtag_brand, newtag_color_name,
           newtag_label_weight, new_id);
    finishCopyFlow(new_id, newtag_tray);
    char ok_buf[40]; strncpy(ok_buf, T(STR_NEWTAG_OK), sizeof(ok_buf)-1);
    ok_buf[sizeof(ok_buf)-1] = '\0';
    lv_label_set_text(lbl_status, ok_buf);
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
    return;
  }
  logSDf("New spool from tag failed: HTTP %d", code);
  char fail_buf[40]; strncpy(fail_buf, T(STR_NEWTAG_FAIL), sizeof(fail_buf)-1);
  fail_buf[sizeof(fail_buf)-1] = '\0';
  lv_label_set_text(lbl_status, fail_buf);
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xff8080), 0);
}

void showNewFromTagPopup() {
  logSD("SHOW: NewFromTagPopup");
  closeNewTagPopup();

  // Split "PETG HF" into the material BamBuddy stores and the subtype beside
  // it. extractBambuSubtype() hands back the tail; its return value answers a
  // different question (the PLA blacklist) and is not used here.
  newtag_subtype[0] = '\0';
  extractBambuSubtype(g_tag.material, newtag_subtype, sizeof(newtag_subtype));
  size_t head = 0;
  while (g_tag.material[head] && g_tag.material[head] != ' ' && g_tag.material[head] != '-') head++;
  if (head >= sizeof(newtag_material)) head = sizeof(newtag_material) - 1;
  memcpy(newtag_material, g_tag.material, head);
  newtag_material[head] = '\0';

  strncpy(newtag_brand, g_tag.vendor[0] ? g_tag.vendor : BAMBU_VENDOR_NAME,
          sizeof(newtag_brand)-1);
  newtag_brand[sizeof(newtag_brand)-1] = '\0';
  strncpy(newtag_tray, g_tag.tray_uuid, sizeof(newtag_tray)-1);
  newtag_tray[sizeof(newtag_tray)-1] = '\0';

  // #RRGGBB on the tag, RRGGBBAA on the server. Fully opaque. Left empty when
  // the colour block did not read - "FF" alone would be a malformed colour,
  // and an absent field is the honest answer.
  const char* hex = g_tag.color_hex[0] == '#' ? g_tag.color_hex + 1 : g_tag.color_hex;
  if (strlen(hex) >= 6) snprintf(newtag_rgba, sizeof(newtag_rgba), "%.6sFF", hex);
  else                  newtag_rgba[0] = '\0';

  // The tag has the colour as a value only. Ask the backend for its name, so
  // the new spool reads "PETG HF Orange" rather than a bare hex nobody can
  // shop for. An unknown colour simply leaves the field empty.
  newtag_color_name[0] = '\0';
  if (newtag_rgba[0]) {
    backendLookupColorName(newtag_rgba, g_tag.material,
                           newtag_color_name, sizeof(newtag_color_name));
  }

  // Nearest nominal weight to what is actually on the pad.
  static const int choices[NEWTAG_LABEL_COUNT] = NEWTAG_LABEL_CHOICES;
  float netto = newTagNetto();
  newtag_label_weight = choices[NEWTAG_LABEL_COUNT - 1];
  int best = -1;
  for (int i = 0; i < NEWTAG_LABEL_COUNT; i++) {
    int diff = (int)(netto > choices[i] ? netto - choices[i] : choices[i] - netto);
    if (best < 0 || diff < best) { best = diff; newtag_label_weight = choices[i]; }
  }

  scr_newtag = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_newtag, 480, 320);
  lv_obj_set_pos(scr_newtag, 0, 0);
  lv_obj_set_style_bg_color(scr_newtag, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_newtag, LV_OPA_70, 0);
  lv_obj_set_style_border_width(scr_newtag, 0, 0);
  lv_obj_set_style_pad_all(scr_newtag, 0, 0);
  lv_obj_clear_flag(scr_newtag, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_newtag);
  lv_obj_set_size(box, 440, 284);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, 10, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(box);
  char title_buf[40]; strncpy(title_buf, T(STR_NEWTAG_TITLE), sizeof(title_buf)-1);
  title_buf[sizeof(title_buf)-1] = '\0';
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 10);

  lbl_newtag_info = lv_label_create(box);
  lv_obj_set_style_text_color(lbl_newtag_info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_newtag_info, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_newtag_info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_newtag_info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_newtag_info, 410);
  lv_obj_align(lbl_newtag_info, LV_ALIGN_TOP_MID, 0, 38);

  lv_obj_t *lbl_lw = lv_label_create(box);
  char lw_buf[24]; strncpy(lw_buf, T(STR_NEWTAG_LABEL_W), sizeof(lw_buf)-1);
  lw_buf[sizeof(lw_buf)-1] = '\0';
  lv_label_set_text(lbl_lw, lw_buf);
  lv_obj_set_style_text_color(lbl_lw, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_lw, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_lw, LV_ALIGN_TOP_MID, 0, 108);

  // Four nominal weights side by side. The index is stored on the button so
  // one shared callback serves all of them.
  const int W_BTN = 100, W_GAP = 6, W_Y = 128;
  const int w_x0 = (440 - (NEWTAG_LABEL_COUNT * W_BTN + (NEWTAG_LABEL_COUNT - 1) * W_GAP)) / 2;
  for (int i = 0; i < NEWTAG_LABEL_COUNT; i++) {
    lv_obj_t *b = lv_btn_create(box);
    lv_obj_set_size(b, W_BTN, 46);
    lv_obj_set_pos(b, w_x0 + i * (W_BTN + W_GAP), W_Y);
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_user_data(b, (void*)(intptr_t)i);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      static const int ch[NEWTAG_LABEL_COUNT] = NEWTAG_LABEL_CHOICES;
      int idx = (int)(intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
      if (idx < 0 || idx >= NEWTAG_LABEL_COUNT) return;
      newtag_label_weight = ch[idx];
      newTagRefresh();
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l = lv_label_create(b);
    char wb[12]; snprintf(wb, sizeof(wb), "%d g", choices[i]);
    lv_label_set_text(l, wb);
    lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0);
    btn_newtag_w[i] = b;
  }

  lv_obj_t *btn_ok = lv_btn_create(box);
  lv_obj_set_size(btn_ok, 200, 52);
  lv_obj_set_pos(btn_ok, 12, 194);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x1a4020), 0);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x2a7030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok, 8, 0);
  lv_obj_set_style_shadow_width(btn_ok, 0, 0);
  lv_obj_add_event_cb(btn_ok, [](lv_event_t *e) {
    logSD("BTN: NewFromTag -> Confirm");
    closeNewTagPopup();
    closeCopyListPopup();
    closeCopyEntryPopup();
    doCreateSpoolFromTag();
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_ok);
    char b[32]; strncpy(b, T(STR_BTN_CONFIRMED), sizeof(b)-1); b[sizeof(b)-1] = '\0';
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0x80ffb0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }

  lv_obj_t *btn_no = lv_btn_create(box);
  lv_obj_set_size(btn_no, 200, 52);
  lv_obj_set_pos(btn_no, 228, 194);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_no, 8, 0);
  lv_obj_set_style_shadow_width(btn_no, 0, 0);
  lv_obj_add_event_cb(btn_no, [](lv_event_t *e) {
    logSD("BTN: NewFromTag -> Cancel");
    closeNewTagPopup();
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_no);
    char b[32]; strncpy(b, T(STR_CANCEL), sizeof(b)-1); b[sizeof(b)-1] = '\0';
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }

  newTagRefresh();
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
    char b[40]; strncpy(b, T(STR_NEWTAG_BTN), sizeof(b)-1); b[sizeof(b)-1] = '\0';
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
    char b[16]; strncpy(b, T(STR_CANCEL), sizeof(b)-1);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }
}

void hideSpoolFlowOverlays() {
  // The spool array is what every link overlay reads from, so freeing it while
  // one of them is still on screen leaves a list that renders from nothing and
  // a confirm button that dereferences a null pointer - a panic reboot, and
  // for a while the only explanation for three of them in one test session.
  //
  // Hidden first, because a hidden object takes no input: from this line on
  // the overlays cannot reach the freed array no matter what the user taps.
  // Deleting them here is not allowed - hideAllOverlays() is reached from
  // LVGL callbacks as well, so the delete is parked for the next loop pass.
  lv_obj_t *const link_scr[] = {
    scr_link_entry, scr_link_id, scr_link_warn_a, scr_link_warn_b,
    scr_link_vendor, scr_link_mat, scr_link_mat_sub, scr_link_spools,
    scr_link_list
  };
  for (unsigned i = 0; i < sizeof(link_scr) / sizeof(link_scr[0]); i++)
    if (link_scr[i]) {
      lv_obj_add_flag(link_scr[i], LV_OBJ_FLAG_HIDDEN);
      link_overlays_close_pending = true;
    }

  linkSpoolsFree();
}

void deleteSpoolFlowOverlays() {
  closeNewTagPopup();
  if (scr_copy_entry)   { lv_obj_del(scr_copy_entry);   scr_copy_entry   = nullptr; }
  if (scr_copy_list)    { lv_obj_del(scr_copy_list);    scr_copy_list    = nullptr; }
  if (scr_copy_confirm) { lv_obj_del(scr_copy_confirm); scr_copy_confirm = nullptr; }
}

void handleSpoolFlowDeferredActions() {
  // First, so nothing below builds on top of an overlay that is already dead.
  // closeLinkOverlays() deletes exactly the nine screens hidden there and frees
  // the array again, which is a no-op the second time around.
  if (link_overlays_close_pending) {
    link_overlays_close_pending = false;
    logSD("Link flow: overlays closed after the spool list was freed");
    closeLinkOverlays();
  }
  if (tagwrite_ask_spool_id > 0) {
    const int id = tagwrite_ask_spool_id;
    tagwrite_ask_spool_id = 0;
    showTagWriteAskPopup(id);
  }
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
    // Free the link_spools buffer grown during the failed lookup so the next
    // lookup starts with a clean slate and no out-of-bounds risk.
    linkSpoolsFree();
    // Pump LVGL twice to flush all residual events from the deleted screen.
    lv_timer_handler();
    lv_timer_handler();
    // Clear all pending flags AFTER pump; residual confirm callbacks may have re-set them.
    link_id_lookup_pending = 0;
    copy_id_lookup_pending = 0;
    showIdInputPopup(link_flow_is_bambu);
  }
  if (newtag_open_pending) {
    newtag_open_pending = false;
    showNewFromTagPopup();
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
    showCopyConfirmPopup(copy_confirm_spool_id, copy_confirm_fid, copy_confirm_name,
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
        if (nameStartsWithMaterial(cfname, cfmat))
          snprintf(ctmpl, sizeof(ctmpl), "%s (%s)", cfname, cfvnd);
        else
          snprintf(ctmpl, sizeof(ctmpl), "%s %s (%s)", cfmat, cfname, cfvnd);
        lbl_link_id_display = nullptr;
        lbl_link_id_status  = nullptr;
        if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
        showCopyConfirmPopup(cid, cfid, ctmpl, crem, cini, cspw);
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
