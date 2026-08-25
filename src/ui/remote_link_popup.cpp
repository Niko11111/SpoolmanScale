#include "remote_link_popup.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <lvgl.h>
#include <cstring>
#include <strings.h>

#include "app_config.h"
#include "bambu/bambu_tag.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/backend.h"
#include "services/user_options.h"
#include "services/backend_api.h"
#include "services/remote_link.h"
#include "services/tag_write.h"
#include "ui/spool_flow.h"
#include "ui/spoolman_lookup.h"
#include "bambu/material_match.h"
#include "ui_common.h"

static lv_obj_t *scr_remote_link = nullptr;
static bool close_remote_link_pending = false;

// Captured when the popup is built, so the button callbacks stay free of any
// lookup. They must not do HTTP themselves, everything they trigger runs from
// appLoop() one pass later.
static int  s_spool_id       = 0;
static bool s_is_bambu       = false;
static bool s_confirm_pending = false;
static bool s_cancel_pending  = false;
static bool s_write_pending   = false;
static char s_link_uuid[40]   = "";

bool isRemoteLinkPopupOpen() { return scr_remote_link != nullptr; }

// Same rule the manual link uses: a Bambu tag is identified by its tray uuid,
// anything else by the plain UID.
//
// link_tag_uid is only filled when the backend lookup came back empty, so a
// tag that is already linked leaves it untouched. Re-linking such a tag is a
// perfectly normal remote link request, and for those the NTAG branch has
// parked the UID in tray_uuid instead. Both buffers are cleared together when
// the tag leaves the scale, so neither can go stale behind the other.
static const char* currentLinkUuid(bool is_bambu) {
  if (is_bambu)          return g_tag.tray_uuid;
  if (link_tag_uid[0])   return link_tag_uid;
  return g_tag.tray_uuid;
}

// What is left of the material once everything the name already says is taken
// out, so the header does not read "PLA Tough+  Tough+ Cyan".
//
// Split on spaces only: Bambu appends PLA variants with a space ("PLA Tough+"),
// but everything else with a hyphen ("TPU-95A", "ABS-GF", "ABS-S"), and there
// the part after the hyphen is the actual information. Keeping hyphenated
// compounds together is what stops this from throwing away the shore hardness
// or the glass fibre content.
//
// containsIgnoreCase() has no word boundaries, so a name like "Plain White"
// counts as containing "PLA" and would swallow that part. The result is a
// missing extra label, never a wrong one, which is worth not growing a second
// comparison next to the shared helper.
static void materialWithoutName(const char* material, const char* name,
                                char* out, size_t out_size) {
  out[0] = '\0';
  if (!material || !material[0] || out_size == 0) return;

  size_t used = 0;
  const char* p = material;
  while (*p) {
    while (*p == ' ') p++;
    const char* start = p;
    while (*p && *p != ' ') p++;
    size_t len = (size_t)(p - start);
    if (len == 0) continue;

    char part[32];
    if (len >= sizeof(part)) len = sizeof(part) - 1;
    memcpy(part, start, len);
    part[len] = '\0';

    if (containsIgnoreCase(name, part)) continue;
    // "Support for ABS" would otherwise leave a dangling "for" once the name
    // already carried "Support". Extend this if more connectives turn up.
    if (used == 0 && strcasecmp(part, "for") == 0) continue;

    int n = snprintf(out + used, out_size - used, used ? " %s" : "%s", part);
    if (n <= 0 || (size_t)n >= out_size - used) break;
    used += (size_t)n;
  }
}

void showRemoteLinkPopup(int spool_id) {
  if (scr_remote_link) return;

  s_write_pending = false;
  s_is_bambu = (strlen(g_tag.tray_uuid) == 32);
  const char* uuid = currentLinkUuid(s_is_bambu);

  // No UID means no link. Patching an empty value is how an unlink is
  // expressed, so this has to abort rather than carry on.
  if (!uuid || !uuid[0]) {
    logSDf("RemoteLink: no tag UID for spool %d", spool_id);
    remoteLinkReport(false, nullptr, "no tag on the scale");
    return;
  }

  s_spool_id = spool_id;
  strncpy(s_link_uuid, uuid, sizeof(s_link_uuid) - 1);
  s_link_uuid[sizeof(s_link_uuid) - 1] = '\0';

  // Whether this tag can carry the spool data at all. A Bambu tag is read-only
  // to us and a 4 byte UID is not an NTAG, so for both the only thing on offer
  // is the link, exactly as before.
  const bool can_write = !s_is_bambu && tagIsWritableNtag();

  // Spool details are only decoration. The link works without them, so a
  // failed lookup downgrades the popup instead of cancelling it. That case is
  // real: reading needs the API key, linking only needs the device token.
  char name[40]     = "";
  char material[24] = "";
  char color_hex[8] = "";
  char vendor[32]   = "";
  float remaining   = -1.0f;      // negative means the server did not say
  bool have_details = false;

  {
    JsonDocument doc;
    DeserializationError err = DeserializationError::Ok;
    int code = backendGetSpoolJson(backendBaseUrl(), spool_id, doc, 6000, &err);
    if (code == 200) {
      have_details = true;
      const char* n = doc["filament"]["name"]      | "";
      const char* m = doc["filament"]["material"]  | "";
      const char* c = doc["filament"]["color_hex"] | "";
      const char* v = doc["filament"]["vendor"]["name"] | "";
      remaining = doc["remaining_weight"] | -1.0f;
      // No explicit terminator needed: the buffers are declared with = "",
      // which zero fills them, so the last byte stays 0 whatever strncpy writes.
      strncpy(name,     n, sizeof(name) - 1);
      strncpy(material, m, sizeof(material) - 1);
      strncpy(vendor,   v, sizeof(vendor) - 1);
      if (c[0]) {
        snprintf(color_hex, sizeof(color_hex), "%s%s", c[0] == '#' ? "" : "#", c);
      }
    } else {
      logSDf("RemoteLink: spool %d lookup failed (HTTP %d)", spool_id, code);
    }
  }

  // Cross-check the tag against the spool. Comparing three characters of the
  // material was not enough: a "PLA Tough+" tag matched a plain "PLA" spool
  // because both start with PLA, and the colour was never looked at, so a blue
  // tag linked to an orange spool without a word.
  //
  // Both extra tests reuse what the manual link flow already applies when it
  // filters its list, so device and web trigger judge a pair the same way.
  bool mismatch_material = false;
  bool mismatch_color    = false;
  if (s_is_bambu && have_details) {
    if (g_tag.material[0] && material[0] &&
        strlen(material) >= 3 && strlen(g_tag.material) >= 3) {
      mismatch_material = (strncasecmp(g_tag.material, material, 3) != 0);

      // Subtype: "PLA Tough+" must not pass as plain "PLA". The keyword has to
      // turn up in either the spool's material or its name, same as the list
      // filter in fetchAllSpoolsForLink().
      char subkw[16];
      if (!mismatch_material && extractBambuSubtype(g_tag.material, subkw, sizeof(subkw))) {
        mismatch_material = !containsIgnoreCase(material, subkw) &&
                            !containsIgnoreCase(name, subkw);
      }
    }
    // Same threshold the manual flow uses to drop far off colours from the list.
    if (g_tag.color_hex[0] == '#' && color_hex[0] == '#') {
      mismatch_color = (colorDistance(g_tag.color_hex, color_hex) > 120);
    }
  }
  const bool mismatch = mismatch_material || mismatch_color;

  // Link without asking, if the user turned that on and the spool was already
  // lying there when they clicked. A mismatch always falls through to the
  // popup: skipping the question is a convenience, skipping the warning would
  // silently commit exactly the wrong link the check exists to catch.
  if (g_flm_autolink && remoteLinkTagWasPresent() && !mismatch) {
    logSDf("RemoteLink: auto-linking spool %d, no prompt (tag was already on)",
           spool_id);
    // Nobody is going to press a button here, so the setting stands in for the
    // one they would have pressed.
    s_write_pending = can_write && g_flm_remote_write;
    // The same two flags the Link button sets. handleRemoteLinkDeferredActions()
    // runs right after this in the same appLoop() pass and does the rest; it
    // null checks the overlay, so building none is fine.
    s_confirm_pending         = true;
    close_remote_link_pending = true;
    return;
  }

  logSDf("SHOW: RemoteLinkPopup spool=%d bambu=%d mismatch=%d autolink=%d",
         spool_id, s_is_bambu ? 1 : 0, mismatch ? 1 : 0,
         g_flm_autolink ? 1 : 0);

  scr_remote_link = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_remote_link, 480, 320);
  lv_obj_set_pos(scr_remote_link, 0, 0);
  lv_obj_set_style_bg_color(scr_remote_link, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_remote_link, LV_OPA_80, 0);
  lv_obj_set_style_border_width(scr_remote_link, 0, 0);
  lv_obj_set_style_radius(scr_remote_link, 0, 0);
  lv_obj_set_style_pad_all(scr_remote_link, 0, 0);
  lv_obj_clear_flag(scr_remote_link, LV_OBJ_FLAG_SCROLLABLE);

  // The comparison block adds two rows plus a header, so the box grows for it
  // rather than pushing the cancel button out through the bottom edge.
  // A mismatch is only ever computed for a Bambu tag, and a Bambu tag is never
  // writable, so the tall comparison box and the third button cannot both be
  // needed at once - which is what keeps either of them on a 320 pixel screen.
  lv_obj_t *box = lv_obj_create(scr_remote_link);
  lv_obj_set_size(box, 440, mismatch ? 300 : (can_write ? 280 : 260));
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box,
    mismatch ? lv_color_hex(0xff8080) : lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(box);
  { char tb[48]; strncpy(tb, T(STR_REMOTE_LINK_TITLE), sizeof(tb) - 1);
    tb[sizeof(tb) - 1] = '\0'; lv_label_set_text(lbl_title, tb); }
  lv_obj_set_style_text_color(lbl_title,
    mismatch ? lv_color_hex(0xff8080) : lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 14);

  lv_obj_t *line = lv_obj_create(box);
  lv_obj_set_size(line, 420, 1);
  lv_obj_set_pos(line, 10, 44);
  lv_obj_set_style_bg_color(line, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(line, 0, 0);
  lv_obj_set_style_radius(line, 0, 0);
  lv_obj_set_style_pad_all(line, 0, 0);

  // Colour swatch, left of the spool description.
  lv_obj_t *swatch = lv_obj_create(box);
  lv_obj_set_size(swatch, 42, 42);
  lv_obj_set_pos(swatch, 16, 56);
  lv_obj_set_style_radius(swatch, 6, 0);
  lv_obj_set_style_border_color(swatch, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(swatch, 1, 0);
  lv_obj_clear_flag(swatch, LV_OBJ_FLAG_SCROLLABLE);
  // Handles the empty and malformed cases itself, including the fallback grey.
  lv_obj_set_style_bg_color(swatch, swatchColorFromHex(color_hex), 0);

  // Header line: id, material and name on top, vendor under it, remaining
  // weight on the right where there was nothing but empty box before.
  // The material sits right after the id, minus whatever the name already
  // says, so "Tough+ Cyan" still gets a leading "PLA" while "PLA Orange"
  // does not get a second one.
  char head[96];
  if (have_details) {
    char mat_extra[32];
    materialWithoutName(material, name, mat_extra, sizeof(mat_extra));
    if (mat_extra[0]) {
      snprintf(head, sizeof(head), "#%d  %s  %s",
               spool_id, mat_extra, name[0] ? name : "-");
    } else {
      snprintf(head, sizeof(head), "#%d  %s", spool_id, name[0] ? name : "-");
    }
  } else {
    char fmt[64]; strncpy(fmt, T(STR_REMOTE_LINK_NO_DETAILS), sizeof(fmt) - 1);
    fmt[sizeof(fmt) - 1] = '\0';
    snprintf(head, sizeof(head), "#%d  %s", spool_id, fmt);
  }
  lv_obj_t *lbl_head = lv_label_create(box);
  lv_label_set_text(lbl_head, head);
  lv_obj_set_style_text_color(lbl_head, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_head, &lv_font_montserrat_ext_16, 0);
  lv_label_set_long_mode(lbl_head, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_head, 250);
  lv_obj_set_pos(lbl_head, 68, 56);

  lv_obj_t *lbl_vendor = lv_label_create(box);
  lv_label_set_text(lbl_vendor, vendor[0] ? vendor : "-");
  lv_obj_set_style_text_color(lbl_vendor, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_vendor, &lv_font_montserrat_ext_14, 0);
  lv_label_set_long_mode(lbl_vendor, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_vendor, 250);
  lv_obj_set_pos(lbl_vendor, 68, 78);

  if (remaining >= 0.0f) {
    char wbuf[24];
    snprintf(wbuf, sizeof(wbuf), "%.0f g", remaining);
    lv_obj_t *lbl_w = lv_label_create(box);
    lv_label_set_text(lbl_w, wbuf);
    lv_obj_set_style_text_color(lbl_w, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_w, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_w, LV_ALIGN_TOP_RIGHT, -16, 62);
  }

  // On a mismatch, put tag and spool side by side. Saying "material differs"
  // without showing which two values differ leaves the user guessing.
  int y_after_head = 108;
  if (mismatch) {
    const int COL_TAG = 150, COL_SPOOL = 300;

    lv_obj_t *h_tag = lv_label_create(box);
    lv_label_set_text(h_tag, T(STR_REMOTE_LINK_COL_TAG));
    lv_obj_set_style_text_color(h_tag, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(h_tag, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_pos(h_tag, COL_TAG, y_after_head);

    lv_obj_t *h_sp = lv_label_create(box);
    lv_label_set_text(h_sp, T(STR_REMOTE_LINK_COL_SPOOL));
    lv_obj_set_style_text_color(h_sp, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(h_sp, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_pos(h_sp, COL_SPOOL, y_after_head);

    // Material row, values in red only where they actually differ.
    lv_obj_t *l_mat = lv_label_create(box);
    lv_label_set_text(l_mat, T(STR_REMOTE_LINK_ROW_MATERIAL));
    lv_obj_set_style_text_color(l_mat, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(l_mat, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_pos(l_mat, 16, y_after_head + 20);

    uint32_t mat_col = mismatch_material ? 0xff8080 : 0xc8d8f0;
    lv_obj_t *v_mt = lv_label_create(box);
    lv_label_set_text(v_mt, g_tag.material[0] ? g_tag.material : "?");
    lv_obj_set_style_text_color(v_mt, lv_color_hex(mat_col), 0);
    lv_obj_set_style_text_font(v_mt, &lv_font_montserrat_ext_14, 0);
    lv_label_set_long_mode(v_mt, LV_LABEL_LONG_DOT);
    lv_obj_set_width(v_mt, 142);
    lv_obj_set_pos(v_mt, COL_TAG, y_after_head + 20);

    lv_obj_t *v_ms = lv_label_create(box);
    lv_label_set_text(v_ms, material[0] ? material : "?");
    lv_obj_set_style_text_color(v_ms, lv_color_hex(mat_col), 0);
    lv_obj_set_style_text_font(v_ms, &lv_font_montserrat_ext_14, 0);
    lv_label_set_long_mode(v_ms, LV_LABEL_LONG_DOT);
    lv_obj_set_width(v_ms, 120);
    lv_obj_set_pos(v_ms, COL_SPOOL, y_after_head + 20);

    // Colour row as two swatches, which says more than two hex strings.
    lv_obj_t *l_col = lv_label_create(box);
    lv_label_set_text(l_col, T(STR_REMOTE_LINK_ROW_COLOR));
    lv_obj_set_style_text_color(l_col, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(l_col, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_pos(l_col, 16, y_after_head + 44);

    uint32_t border = mismatch_color ? 0xff8080 : 0x1a3060;
    for (int i = 0; i < 2; i++) {
      lv_obj_t *sw = lv_obj_create(box);
      lv_obj_set_size(sw, 22, 18);
      lv_obj_set_pos(sw, i == 0 ? COL_TAG : COL_SPOOL, y_after_head + 44);
      lv_obj_set_style_radius(sw, 4, 0);
      lv_obj_set_style_border_color(sw, lv_color_hex(border), 0);
      lv_obj_set_style_border_width(sw, 1, 0);
      lv_obj_set_style_pad_all(sw, 0, 0);
      lv_obj_clear_flag(sw, LV_OBJ_FLAG_SCROLLABLE);
      lv_obj_set_style_bg_color(sw,
        swatchColorFromHex(i == 0 ? g_tag.color_hex : color_hex), 0);
    }
    y_after_head += 70;
  } else if (!can_write) {
    lv_obj_t *lbl_q = lv_label_create(box);
    { char qb[96];
      strncpy(qb, T(STR_REMOTE_LINK_QUESTION), sizeof(qb) - 1);
      qb[sizeof(qb) - 1] = '\0';
      lv_label_set_text(lbl_q, qb); }
    lv_obj_set_style_text_color(lbl_q, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(lbl_q, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(lbl_q, 400);
    lv_obj_align(lbl_q, LV_ALIGN_TOP_MID, 0, y_after_head + 6);
    y_after_head += 34;
  }

  // The write, when there is a tag that can take it. It sits on top and keeps
  // the confirming look, because it is what FilaMan's button asked for - the
  // link below it is the smaller of the two actions, not the safer default.
  if (can_write) {
    lv_obj_t *btn_wr = lv_btn_create(box);
    lv_obj_set_size(btn_wr, 420, 48);
    lv_obj_align(btn_wr, LV_ALIGN_TOP_MID, 0, y_after_head);
    lv_obj_set_style_bg_color(btn_wr, lv_color_hex(0x0d3d2e), 0);
    lv_obj_set_style_bg_color(btn_wr, lv_color_hex(0x18705a), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_wr, 8, 0);
    lv_obj_set_style_shadow_width(btn_wr, 0, 0);
    lv_obj_set_style_border_width(btn_wr, 0, 0);
    lv_obj_add_event_cb(btn_wr, [](lv_event_t *e) {
      // Same rule as every other button here: flags only, the NFC write and
      // the HTTP report happen one loop pass later.
      s_write_pending   = true;
      s_confirm_pending = true;
      close_remote_link_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_wr = lv_label_create(btn_wr);
    { char wb[40]; strncpy(wb, T(STR_REMOTE_LINK_WRITE), sizeof(wb) - 1);
      wb[sizeof(wb) - 1] = '\0'; lv_label_set_text(lbl_wr, wb); }
    lv_obj_set_style_text_color(lbl_wr, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_wr, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_wr);
    y_after_head += 56;
  }

  lv_obj_t *btn_ok = lv_btn_create(box);
  lv_obj_set_size(btn_ok, 420, 48);
  lv_obj_align(btn_ok, LV_ALIGN_TOP_MID, 0, y_after_head);
  lv_obj_set_style_bg_color(btn_ok,
    mismatch ? lv_color_hex(0x3a1010)
             : lv_color_hex(can_write ? 0x0a1828 : 0x0d3d2e), 0);
  lv_obj_set_style_bg_color(btn_ok,
    mismatch ? lv_color_hex(0x602020)
             : lv_color_hex(can_write ? 0x1a3060 : 0x18705a), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok, 8, 0);
  lv_obj_set_style_shadow_width(btn_ok, 0, 0);
  lv_obj_set_style_border_width(btn_ok, can_write ? 1 : 0, 0);
  lv_obj_set_style_border_color(btn_ok, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_ok, [](lv_event_t *e) {
    // No HTTP and no delete in here, both happen one loop pass later.
    s_confirm_pending = true;
    close_remote_link_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok = lv_label_create(btn_ok);
  { char bb[40];
    strncpy(bb, mismatch    ? T(STR_BTN_OVERWRITE)
                : can_write ? T(STR_REMOTE_LINK_ONLY)
                            : T(STR_REMOTE_LINK_CONFIRM),
            sizeof(bb) - 1);
    bb[sizeof(bb) - 1] = '\0'; lv_label_set_text(lbl_ok, bb); }
  lv_obj_set_style_text_color(lbl_ok,
    mismatch    ? lv_color_hex(0xff8080)
    : can_write ? lv_color_hex(0xc8d8f0)
                : lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_ok, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_ok);

  lv_obj_t *btn_cancel = lv_btn_create(box);
  lv_obj_set_size(btn_cancel, 420, 44);
  lv_obj_align(btn_cancel, LV_ALIGN_TOP_MID, 0, y_after_head + 56);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_cancel, 1, 0);
  lv_obj_set_style_border_color(btn_cancel, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e) {
    s_cancel_pending = true;
    close_remote_link_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cancel = lv_label_create(btn_cancel);
  { char cb[32]; strncpy(cb, T(STR_CANCEL), sizeof(cb) - 1);
    cb[sizeof(cb) - 1] = '\0'; lv_label_set_text(lbl_cancel, cb); }
  lv_obj_set_style_text_color(lbl_cancel, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_cancel, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_cancel);
}

void handleRemoteLinkDeferredActions() {
  if (!close_remote_link_pending) return;
  close_remote_link_pending = false;

  if (scr_remote_link) { lv_obj_del(scr_remote_link); scr_remote_link = nullptr; }

  if (s_cancel_pending) {
    s_cancel_pending = false;
    s_write_pending  = false;
    tagRemotePayloadSet("", 0);
    logSDf("RemoteLink: cancelled on device, spool %d", s_spool_id);
    remoteLinkReport(false, s_link_uuid, "cancelled on device");
    return;
  }

  if (s_confirm_pending) {
    s_confirm_pending = false;
    const bool want_write = s_write_pending;
    s_write_pending = false;
    const int spool_id = s_spool_id;

    // Write before reporting, so a tag that could not be written is never
    // reported as linked.
    //
    // want_write can only be set for a tag that was writable when the question
    // was asked, so a Bambu or MIFARE tag never reaches the write at all. It
    // used to: the payload was tried on whatever was lying there, and the
    // failed write then took the link down with it - a link that had worked
    // fine before FilaMan started sending records.
    if (!want_write) {
      tagRemotePayloadSet("", 0);
    } else {
      // What the server sent has the say. Without it the scale builds the same
      // OpenSpool record the tag page writes - FilaMan only sends one with
      // "write extended data" switched on in its admin settings, and that is
      // off by default, so building it here is the ordinary case.
      const bool ok = tagRemotePayloadPending()
                        ? tagWriteRemotePayload()
                        : tagWriteSpoolNow(spool_id, TAG_FMT_OPENSPOOL);
      if (!ok) {
        // The reason, not just the fact. FilaMan shows this string to the user,
        // and "tag write failed" told nobody that the tag was too small.
        const char *why = tagWriteMessage();
        remoteLinkReport(false, s_link_uuid, why[0] ? why : "tag write failed");
        return;
      }
    }

    // FilaMan sets rfid_uid itself when this succeeds, which also clears the
    // UID off any other spool that still carries it. That cleanup is why the
    // remote link reports instead of patching directly.
    remoteLinkReport(true, s_link_uuid, nullptr);

    // Pull the spool back in so the main screen shows the fresh link. The
    // same two steps the manual link does at the end of doLinkPatch().
    if (!s_is_bambu) {
      // g_tag holds the previous scan until overwritten, and a 7 byte UID is
      // exactly 23 characters into a 24 byte field, so the copy fills it to the
      // brim and strncpy writes no terminator. Set it explicitly.
      strncpy(g_tag.uid_str,   s_link_uuid, sizeof(g_tag.uid_str) - 1);
      g_tag.uid_str[sizeof(g_tag.uid_str) - 1] = '\0';
      strncpy(g_tag.tray_uuid, s_link_uuid, sizeof(g_tag.tray_uuid) - 1);
      g_tag.tray_uuid[sizeof(g_tag.tray_uuid) - 1] = '\0';
    }
    link_popup_dismissed = false;
    tagLookupForget();
    querySpoolmanById(spool_id);
    logSDf("RemoteLink: linked spool %d%s", spool_id,
           want_write ? " and wrote the tag" : "");
  }
}
