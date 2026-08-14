#include "spoolman_lookup.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <lvgl.h>
#include <cstring>

#include "bambu/bambu_tag.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/location_state.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "ui/date_display.h"
#include "ui/main_screen_helpers.h"

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



// ============================================================
//  SPOOLMAN QUERY BY ID
//  Used after link-flow — fetches only one spool by ID.
//  Fills same globals and labels as querySpoolman().
// ============================================================
void querySpoolmanById(int spool_id) {
  if (!wifi_ok) return;
  Serial.printf("querySpoolmanById: ID=%d\n", spool_id);
  logSDf("Spoolman: query by ID=%d", spool_id);
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (before byID GET)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  DynamicJsonDocument doc(8192);
  DeserializationError err = DeserializationError::Ok;
  int code = backendGetSpoolJson(cfg_spoolman_base, spool_id, doc, 8000, &err);
  if (code != 200) {
    Serial.printf("querySpoolmanById HTTP error: %d\n", code);
    logSDf("Spoolman byID: HTTP error %d", code);
    if (code == -2) {
      Serial.println("querySpoolmanById: JSON error");
      logSD("Spoolman byID: JSON error");
    }
    return;
  }
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (after byID parse)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  JsonObject spool = doc.as<JsonObject>();
  bool is_bambu_tag = (strlen(g_tag.material) > 0);

  sm_found        = true;
  sm_id           = spool["id"] | 0;
  sm_filament_id  = spool["filament"]["id"] | 0;
  sm_vendor_id    = spool["filament"]["vendor"]["id"] | 0;
  sm_remaining    = spool["remaining_weight"] | 0.0f;
  sm_total        = spool["filament"]["weight"] | 1000.0f;
  sm_spool_weight = spool["spool_weight"] | 0.0f;
  logSDf("Spoolman: byID OK ID=%d remaining=%.1fg", sm_id, sm_remaining);

  String art_nr = spool["filament"]["article_number"] | "";
  art_nr.trim();
  strncpy(sm_article_nr, art_nr.c_str(), sizeof(sm_article_nr)-1);

  String fil_name = spool["filament"]["name"] | String("");
  fil_name.trim();
  strncpy(sm_filament_name, fil_name.c_str(), sizeof(sm_filament_name)-1);

  // Location — Spoolman gibt location als einfachen String zurück
  sm_location_id = 0;
  sm_location_name[0] = '\0';
  if (!spool["location"].isNull() && spool["location"].is<const char*>()) {
    String loc_name = spool["location"] | String("");
    loc_name.trim();
    strncpy(sm_location_name, loc_name.c_str(), sizeof(sm_location_name)-1);
  }

  // last_dried
  sm_last_dried[0] = '\0';
  if (spool.containsKey("extra") && spool["extra"].containsKey("last_dried")) {
    String dried = spool["extra"]["last_dried"].as<String>();
    dried.replace("\"", "");
    String iso = dried.substring(0, 10);
    char de_date[12];
    isoToDe(iso.c_str(), de_date, sizeof(de_date));
    strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
  } else {
    strncpy(sm_last_dried, "-", sizeof(sm_last_dried)-1);
  }

  // Material, vendor, color — only for NTAG (Bambu has it from tag itself)
  String sm_material = spool["filament"]["material"] | String("");
  sm_material.trim();
  String sm_vendor_name = "";
  if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull()) {
    sm_vendor_name = spool["filament"]["vendor"]["name"] | String("");
    sm_vendor_name.trim();
  }
  String sm_color = spool["filament"]["color_hex"] | String("");
  sm_color.trim();

  bool is_ntag = !is_bambu_tag;
  if (is_ntag) {
    lv_label_set_text(lbl_material, sm_material.length() > 0 ? sm_material.c_str() : "-");
    lv_label_set_text(lbl_vendor,   sm_vendor_name.length() > 0 ? sm_vendor_name.c_str() : "-");
    strncpy(sm_material_global, sm_material.c_str(), sizeof(sm_material_global)-1);
    sm_material_global[sizeof(sm_material_global)-1] = '\0';
    strncpy(sm_color_global, sm_color.c_str(), sizeof(sm_color_global)-1);
    sm_color_global[sizeof(sm_color_global)-1] = '\0';
  } else {
    // Bambu-Tag: Material aus g_tag.material in sm_material_global schreiben
    // damit dryingAlertLevel() das Material korrekt auflösen kann
    if (g_tag.material[0]) {
      strncpy(sm_material_global, g_tag.material, sizeof(sm_material_global)-1);
      sm_material_global[sizeof(sm_material_global)-1] = '\0';
    }
  }
  if (is_ntag && sm_color.length() >= 6) {
    String hex = sm_color;
    if (hex.startsWith("#")) hex = hex.substring(1);
    unsigned int r, g, b;
    sscanf(hex.c_str(), "%02X%02X%02X", &r, &g, &b);
    uint32_t col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
    lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(col), 0);
  }

  // Update display labels
  char weight_str[32];
  snprintf(weight_str, sizeof(weight_str), "%.0f g", sm_remaining);
  lv_label_set_text(lbl_spoolman_weight, weight_str);
  float pct = (sm_total > 0) ? (sm_remaining / sm_total) * 100.0f : 0;
  uint32_t pct_color;
  if (pct <= 10.0f)      pct_color = 0xe04040;
  else if (pct <= 30.0f) pct_color = 0xf0b838;
  else                   pct_color = 0x28d49a;
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(pct_color), 0);

  char pct_str[16];
  snprintf(pct_str, sizeof(pct_str), "%.1f %%", pct);
  lv_label_set_text(lbl_spoolman_pct, pct_str);
  lv_obj_set_style_text_color(lbl_spoolman_pct, lv_color_hex(pct_color), 0);

  if (lbl_scale_diff) {
    int bar_w = (int)((pct / 100.0f) * 190.0f);
    if (bar_w < 0) bar_w = 0;
    if (bar_w > 190) bar_w = 190;
    lv_obj_set_width(lbl_scale_diff, bar_w);
    lv_obj_set_style_bg_color(lbl_scale_diff, lv_color_hex(pct_color), 0);
  }

  char sm_id_str[16];
  snprintf(sm_id_str, sizeof(sm_id_str), "%d", sm_id);
  lv_label_set_text(lbl_spoolman_id, sm_id_str);
  lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0x28d49a), 0);

  char dried_display[48];
  driedDisplayStr(sm_last_dried, dried_display, sizeof(dried_display));
  applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, sm_last_dried);

  lv_label_set_text(lbl_detail,        strlen(sm_article_nr)    > 0 ? sm_article_nr    : "-");
  lv_label_set_text(lbl_filament_name, strlen(sm_filament_name) > 0 ? sm_filament_name : "-");

  // last_used
  if (spool.containsKey("last_used") && !spool["last_used"].isNull()) {
    String lu = spool["last_used"].as<String>();
    char de_lu[12];
    isoToDe(lu.substring(0, 10).c_str(), de_lu, sizeof(de_lu));
    strncpy(sm_last_used, de_lu, sizeof(sm_last_used)-1);
  } else {
    strncpy(sm_last_used, "-", sizeof(sm_last_used)-1);
  }
  char last_used_display[48];
  driedDisplayStr(sm_last_used, last_used_display, sizeof(last_used_display));
  lv_label_set_text(lbl_last_used, last_used_display);

  Serial.printf("querySpoolmanById OK: ID=%d %.1fg dried=%s\n", sm_id, sm_remaining, sm_last_dried);
  updateLinkButton();
}

// ============================================================
//  SPOOLMAN QUERY
//  Finds spool by tray_uuid in extra.tag field
// ============================================================
void querySpoolman(const char* tray_uuid) {
  if (!wifi_ok) return;
  logSDf("Spoolman: query tray_uuid=%.16s...", tray_uuid ? tray_uuid : "");

  // Reset all Spoolman labels before new query
  lv_label_set_text(lbl_spoolman_weight, T(STR_WAIT));
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_label_set_text(lbl_spoolman_dried_val, "");
  if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
  lv_label_set_text(lbl_detail, "-");
  lv_label_set_text(lbl_filament_name, "-");
  lv_label_set_text(lbl_last_used, "-");
  if (lbl_scale_diff) lv_obj_set_width(lbl_scale_diff, 0);
  if (lbl_spoolman_dried) lv_label_set_text(lbl_spoolman_dried, "");
  if (lbl_keys) lv_label_set_text(lbl_keys, "");
  if (lbl_raw_info) lv_label_set_text(lbl_raw_info, "");
  if (lbl_bag_sm_diff) lv_label_set_text(lbl_bag_sm_diff, "");
  // bei Bambu kommen diese Felder aus dem Tag selbst (updateDisplay) nicht aus Spoolman
  bool is_bambu_tag = (strlen(g_tag.material) > 0);
  if (!is_bambu_tag) {
    lv_label_set_text(lbl_material, "-");
    lv_label_set_text(lbl_vendor, "-");
    lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(0x333333), 0);
  }
  sm_last_dried[0] = '\0';
  sm_article_nr[0] = '\0';
  sm_filament_name[0] = '\0';
  sm_material_global[0] = '\0';
  sm_color_global[0] = '\0';
  sm_last_used[0] = '\0';
  sm_location_name[0] = '\0'; sm_location_id = 0;
  sm_found = false;
  sm_id = 0;
  sm_spool_weight = 0;
  sm_remaining = 0;
  sm_total = 1000;
  lv_timer_handler();

  Serial.printf("DBG free heap: %d bytes  free PSRAM: %d bytes\n", ESP.getFreeHeap(), ESP.getFreePsram());
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (before Spoolman GET)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  // Filter: only parse needed fields — reduces RAM, works with 100+ spools
  // Filter must be Array-wrapped to match the API array response structure
  StaticJsonDocument<512> filter;
  JsonArray filter_arr = filter.to<JsonArray>();
  JsonObject filter_spool = filter_arr.createNestedObject();
  filter_spool["id"] = true;
  filter_spool["archived"] = true;
  filter_spool["remaining_weight"] = true;
  filter_spool["spool_weight"] = true;
  filter_spool["last_used"] = true;
  filter_spool["location"] = true;
  filter_spool["extra"]["tag"] = true;
  filter_spool["extra"]["last_dried"] = true;
  filter_spool["filament"]["id"] = true;
  filter_spool["filament"]["name"] = true;
  filter_spool["filament"]["material"] = true;
  filter_spool["filament"]["weight"] = true;
  filter_spool["filament"]["article_number"] = true;
  filter_spool["filament"]["color_hex"] = true;
  filter_spool["filament"]["vendor"]["id"] = true;
  filter_spool["filament"]["vendor"]["name"] = true;

  // Use PSRAM for this document — frees internal RAM for LVGL
  SpiRamAllocator psram_alloc;
  JsonDocument doc(&psram_alloc);
  DeserializationError err = DeserializationError::Ok;

  // Fast path: FilaMan can filter by tag server side, so one small answer
  // replaces the whole inventory. Spoolman has no such search and returns
  // BACKEND_NOT_SUPPORTED, which falls through to the loop below unchanged.
  //
  // An empty result is not proof of absence: the search only covers
  // rfid_uid, not custom_fields, so spools imported from Spoolman are
  // invisible here until their UID has been migrated. Those are found by
  // the full scan below.
  bool have_result = false;
  {
    int fcode = backendFindSpoolByTag(cfg_spoolman_base, tray_uuid, doc, 8000, &err);
    if (fcode == 200 && !err) {
      // The server side search is a text filter, not an exact tag match. A
      // substring hit on some other spool must not suppress the full scan,
      // otherwise a spool whose UID still lives in custom_fields would be
      // reported as unknown. Only accept the short cut on a real match.
      for (JsonObjectConst s : doc.as<JsonArrayConst>()) {
        String t = s["extra"]["tag"].as<String>();
        t.replace("\"", "");
        t.trim();
        if (t.equalsIgnoreCase(tray_uuid)) { have_result = true; break; }
      }
      if (have_result) {
        logSDf("Backend: tag search hit, %d spool(s) returned",
               (int)doc.as<JsonArrayConst>().size());
      }
    } else if (fcode != BACKEND_NOT_SUPPORTED) {
      // Spoolman answers NOT_SUPPORTED by design, anything else is a real
      // failure and should not disappear silently.
      logSDf("Backend: tag search failed, code=%d err=%s", fcode, err.c_str());
    }
    if (!have_result) {
      doc.clear();
      err = DeserializationError::Ok;
    }
  }

  // Up to 2 attempts: first try, then 1 retry on IncompleteInput / connection issues.
  // 20s timeout is generous for large Spoolman datasets (200+ spools over WiFi).
  for (int attempt = 1; !have_result && attempt <= 2; attempt++) {
    if (attempt > 1) {
      Serial.printf("Spoolman: retry attempt %d after %s\n", attempt, err.c_str());
      logSDf("Spoolman: retry attempt %d (prev err=%s)", attempt, err.c_str());
      delay(300);  // brief pause before retry
      doc.clear();
    }

    int code = backendGetSpoolListJson(cfg_spoolman_base, false, doc, 20000, &filter, &err);
    if (code != 200) {
      Serial.printf("Spoolman HTTP error: %d (attempt %d)\n", code, attempt);
      logSDf("Spoolman: HTTP error %d (attempt %d)", code, attempt);
      if (attempt == 2) {
        lv_label_set_text(lbl_spoolman_weight, code == -2 ? T(STR_LINK_JSON_ERR) : T(STR_API_ERROR));
        return;
      }
      if (code == -2 &&
          err != DeserializationError::IncompleteInput &&
          err != DeserializationError::EmptyInput) {
        break;
      }
      continue;  // retry on HTTP or transient parse error too
    }

    // Stream directly from HTTP — avoids allocating a 40KB+ String in RAM

    if (!err) break;  // success
    // Parse failed -> retry only on transient stream issues
    if (err != DeserializationError::IncompleteInput &&
        err != DeserializationError::EmptyInput) {
      break;  // other errors are not transient -> don't retry
    }
  }

  Serial.printf("DBG free heap after parse: %d bytes  free PSRAM: %d bytes\n", ESP.getFreeHeap(), ESP.getFreePsram());
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (after Spoolman parse)",
    ESP.getFreeHeap(), ESP.getFreePsram());
  if (err) {
    Serial.printf("Spoolman JSON error (final): %s\n", err.c_str());
    logSDf("Spoolman: JSON error final=%s", err.c_str());
    lv_label_set_text(lbl_spoolman_weight, T(STR_LINK_JSON_ERR));
    return;
  }

  JsonArray spools = doc.as<JsonArray>();
  for (JsonObject spool : spools) {
    if (!spool.containsKey("extra")) continue;
    JsonObject extra = spool["extra"];
    if (!extra.containsKey("tag")) continue;

    String tag_val = extra["tag"].as<String>();
    tag_val.replace("\"", "");
    tag_val.trim();

    if (!tag_val.equalsIgnoreCase(tray_uuid)) continue;

    // FOUND
    sm_found    = true;
    sm_id       = spool["id"] | 0;

    // One-off migration for spools imported from Spoolman. Their UID lives in
    // custom_fields, where FilaMan's ?search= cannot see it, so every scan
    // would pull the whole inventory. Writing it to the native rfid_uid once
    // puts the spool on the fast path for good. Silent by design, the user
    // has nothing to decide here.
    //
    // Keyed off the flag the reader set, not off which path found the spool:
    // a failed tag search also lands here, and re-patching an already correct
    // rfid_uid on every scan would be a pointless write and a needless stall.
    if (backendIsFilaMan() && sm_id > 0 && (spool["extra"]["tag_legacy"] | false)) {
      int mc = backendPatchSpoolTag(cfg_spoolman_base, sm_id, tag_val.c_str(), 4000);
      logSDf("FilaMan: migrated tag of spool %d to rfid_uid, HTTP %d", sm_id, mc);
    }

    sm_filament_id = spool["filament"]["id"] | 0;
    sm_vendor_id   = spool["filament"]["vendor"]["id"] | 0;
    sm_remaining = spool["remaining_weight"] | 0.0f;
    sm_total    = spool["filament"]["weight"] | 1000.0f;
    sm_spool_weight = spool["spool_weight"] | 0.0f;
    logSDf("Spoolman: found ID=%d remaining=%.1fg total=%.0fg",
      sm_id, sm_remaining, sm_total);
    logSDf("[verbose] LOC: querySpoolman id=%d shown_for=%d", sm_id, g_loc_popup_shown_for_id);
    String art_nr = spool["filament"]["article_number"] | "";
    art_nr.trim();
    strncpy(sm_article_nr, art_nr.c_str(), sizeof(sm_article_nr)-1);
    String fil_name = spool["filament"]["name"] | String("");
    fil_name.trim();
    strncpy(sm_filament_name, fil_name.c_str(), sizeof(sm_filament_name)-1);

    // Location — einfacher String in Spoolman
    sm_location_name[0] = '\0';
    if (!spool["location"].isNull() && spool["location"].is<const char*>()) {
      String loc = spool["location"] | String("");
      loc.trim();
      strncpy(sm_location_name, loc.c_str(), sizeof(sm_location_name)-1);
    }
    if (extra.containsKey("last_dried")) {
      String dried = extra["last_dried"].as<String>();
      dried.replace("\"", "");
      String iso = dried.substring(0, 10);
      char de_date[12];
      isoToDe(iso.c_str(), de_date, sizeof(de_date));
      strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
    } else {
      strncpy(sm_last_dried, "-", sizeof(sm_last_dried)-1);
    }

    Serial.printf("Spoolman: ID=%d, %.1fg, dried: %s\n",
      sm_id, sm_remaining, sm_last_dried);

    // Read material, vendor, color from Spoolman
    // → shown when no Bambu tag (g_tag.material empty)
    String sm_material = spool["filament"]["material"] | String("");
    sm_material.trim();
    String sm_vendor_name = "";
    if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull()) {
      sm_vendor_name = spool["filament"]["vendor"]["name"] | String("");
      sm_vendor_name.trim();
    }
    String sm_color = spool["filament"]["color_hex"] | String("");
    sm_color.trim();

    // Only fill fields from Spoolman if no Bambu tag present
    bool is_ntag = !is_bambu_tag;
    Serial.printf("is_ntag=%d material='%s' vendor='%s' color='%s'\n",
      is_ntag, sm_material.c_str(), sm_vendor_name.c_str(), sm_color.c_str());
    if (is_ntag) {
      lv_label_set_text(lbl_material, sm_material.length() > 0 ? sm_material.c_str() : "-");
      lv_label_set_text(lbl_vendor, sm_vendor_name.length() > 0 ? sm_vendor_name.c_str() : "-");
      strncpy(sm_material_global, sm_material.c_str(), sizeof(sm_material_global)-1);
      sm_material_global[sizeof(sm_material_global)-1] = '\0';
      strncpy(sm_color_global, sm_color.c_str(), sizeof(sm_color_global)-1);
      sm_color_global[sizeof(sm_color_global)-1] = '\0';
      // Color swatch from Spoolman color_hex (#RRGGBB or RRGGBB)
      if (sm_color.length() >= 6) {
        String hex = sm_color;
        if (hex.startsWith("#")) hex = hex.substring(1);
        unsigned int r, g, b;
        sscanf(hex.c_str(), "%02X%02X%02X", &r, &g, &b);
        uint32_t col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
        lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(col), 0);
        Serial.printf("Color set: #%06X\n", col);
      }
    }

    // Update display — Fix 5: color based on remaining %
    char weight_str[32];
    snprintf(weight_str, sizeof(weight_str), "%.0f g", sm_remaining);
    lv_label_set_text(lbl_spoolman_weight, weight_str);
    float pct = (sm_total > 0) ? (sm_remaining / sm_total) * 100.0f : 0;

    // Choose color: 0-10% red, 11-30% orange, 31-100% green
    uint32_t pct_color;
    if (pct <= 10.0f)       pct_color = 0xe04040;
    else if (pct <= 30.0f)  pct_color = 0xf0b838;
    else                    pct_color = 0x28d49a;

    lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(pct_color), 0);

    char pct_str[16];
    snprintf(pct_str, sizeof(pct_str), "%.1f %%", pct);
    lv_label_set_text(lbl_spoolman_pct, pct_str);
    lv_obj_set_style_text_color(lbl_spoolman_pct, lv_color_hex(pct_color), 0);

    // Update progress bar fill width (max 190px) with same color
    if (lbl_scale_diff) {
      int bar_w = (int)((pct / 100.0f) * 190.0f);
      if (bar_w < 0) bar_w = 0;
      if (bar_w > 190) bar_w = 190;
      lv_obj_set_width(lbl_scale_diff, bar_w);
      lv_obj_set_style_bg_color(lbl_scale_diff, lv_color_hex(pct_color), 0);
    }

    // Show SM-ID in green (linked)
    char sm_id_str[16];
    snprintf(sm_id_str, sizeof(sm_id_str), "%d", sm_id);
    lv_label_set_text(lbl_spoolman_id, sm_id_str);
    lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0x28d49a), 0);

    // Last drying: set value with "N days ago"
    char dried_display[48];
    driedDisplayStr(sm_last_dried, dried_display, sizeof(dried_display));
    applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, sm_last_dried);

    lv_label_set_text(lbl_detail, strlen(sm_article_nr) > 0 ? sm_article_nr : "-");
    lv_label_set_text(lbl_filament_name, strlen(sm_filament_name) > 0 ? sm_filament_name : "-");

    // last_used is directly in the spool object (not in extra!)
    if (spool.containsKey("last_used") && !spool["last_used"].isNull()) {
      String lu = spool["last_used"].as<String>();
      char de_lu[12]; isoToDe(lu.substring(0, 10).c_str(), de_lu, sizeof(de_lu));
      strncpy(sm_last_used, de_lu, sizeof(sm_last_used)-1);
    } else {
      strncpy(sm_last_used, "-", sizeof(sm_last_used)-1);
    }
    char last_used_display[48];
    driedDisplayStr(sm_last_used, last_used_display, sizeof(last_used_display));
    lv_label_set_text(lbl_last_used, last_used_display);

    updateLinkButton();
    return;
  }

  // Not found in active spools — check if archived
  Serial.println("Spoolman: not in active spools, checking archive...");
  doc.clear();  // RAM freigeben vor zweitem Call

  // Second call with allow_archived=true.
  // DynamicJsonDocument is the deprecated v6 shim in ArduinoJson 7: the
  // capacity argument is ignored and it allocates from the internal heap
  // without limit. With a large FilaMan archive that is a way to run the
  // internal RAM dry, so this one uses PSRAM like the active list above.
  JsonDocument doc2(&psram_alloc);
  DeserializationError err2 = DeserializationError::Ok;
  StaticJsonDocument<256> filter2;
  JsonArray filter2_arr = filter2.to<JsonArray>();
  JsonObject f2 = filter2_arr.createNestedObject();
  f2["id"] = true;
  f2["archived"] = true;
  f2["extra"]["tag"] = true;
  int code2 = backendGetSpoolListJson(cfg_spoolman_base, true, doc2, 8000, &filter2, &err2);
  if (code2 == 200) {
    if (!err2) {
      JsonArray spools2 = doc2.as<JsonArray>();
      for (JsonObject spool : spools2) {
        // Only check truly archived spools (explicit bool cast needed for JsonVariant)
        bool is_archived = spool["archived"].as<bool>();
        if (!is_archived) continue;
        if (!spool.containsKey("extra")) continue;
        JsonObject extra = spool["extra"];
        if (!extra.containsKey("tag")) continue;
        String tag_val = extra["tag"].as<String>();
        tag_val.replace("\"", ""); tag_val.trim();
        if (!tag_val.equalsIgnoreCase(tray_uuid)) continue;
        // Archived spool found
        Serial.printf("Spoolman: spool archived (ID=%d)\n", spool["id"] | 0);
        lv_label_set_text(lbl_spoolman_weight, T(STR_ARCHIVED));
        lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x808080), 0);
        lv_label_set_text(lbl_spoolman_pct, "");
        lv_label_set_text(lbl_spoolman_dried_val, "-");
        if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
        lv_label_set_text(lbl_last_used, "-");
        lv_label_set_text(lbl_detail, "-");
        lv_label_set_text(lbl_filament_name, "-");
        // Reset progress bar and diff labels
        if (lbl_scale_diff) lv_obj_set_width(lbl_scale_diff, 0);
        if (lbl_spoolman_dried) lv_label_set_text(lbl_spoolman_dried, "");
        if (lbl_keys) lv_label_set_text(lbl_keys, "");
        sm_found = false;
        updateLinkButton();
        return;
      }
    }
  }

  // Truly not found
  Serial.println("Spoolman: spool not found");
  logSD("Spoolman: spool not found");
  { char nb[40]; backendText(T(STR_NOT_IN_SPOOLMAN), nb, sizeof(nb)); lv_label_set_text(lbl_spoolman_weight, nb); }
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  sm_found = false;
  updateLinkButton();
}
