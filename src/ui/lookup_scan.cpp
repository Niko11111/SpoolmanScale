// ============================================================
//  THE LOOKUP'S VERDICT, AND THE INVENTORY IT IS READ FROM
//
//  querySpoolman() asks the cheap questions first. When none of them knows
//  the tag, the whole inventory has to come in, and that is seconds on a
//  large library: 14 s on FilaMan, 51 s on BamBuddy, measured on 21.09.2026.
//  It used to come in on the loop task, which stood still for that long -
//  no touch, no weight, no NFC, and the AMS or location question on screen
//  could not be answered.
//
//  Now the backend worker (services/backend_job.h) loads it on the other
//  core and lookupScanTick() reads the verdict out of it on a later pass.
//  The verdict itself is the code that used to follow the download inside
//  querySpoolman(), moved here word for word: every edge in it has an
//  incident behind it. What changed around it is only where the document
//  comes from and that the lookup can now be overtaken by events that could
//  not happen while the loop stood still:
//
//  - Another tag is put down, or the display is cleared: the lookup is
//    abandoned, the download runs on and still feeds the spool cache and the
//    uid index. The next lookup waits for it and asks the index first, so
//    most of the time there is no second download.
//  - The backend or its address changes: the result is about a server the
//    scale no longer talks to and is dropped (backendGeneration()).
//  - Things that act on the verdict wait for it: the recheck, the link from
//    the tags page, the Link button. See lookupPending().
// ============================================================

#include "spoolman_lookup.h"
#include "spoolman_lookup_internal.h"
#include "app/app_state.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <lvgl.h>
#include <cstring>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "lang.h"

// From ui/spool_flow.cpp, see the same line in spoolman_lookup.cpp.
bool spoolHasAnyTag(JsonObjectConst spool);

#include "app/backend_switch.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/backend_job.h"
#include "services/breadcrumb.h"
#include "services/filaman_api.h"
#include "services/location_state.h"
#include "services/spool_cache.h"
#include "services/spoolman_actions.h"
#include "services/tag_field.h"
#include "services/tag_uid.h"
#include "services/tag_write.h"
#include "services/time_service.h"
#include "services/uid_index.h"
#include "ui/date_display.h"
#include "ui/main_screen_helpers.h"
#include "ui/spool_flow.h"
#include "ui/theme.h"
#include "ui_common.h"

// The inventory: 20 s for large Spoolman datasets over WiFi (200+ spools),
// and one retry after a pause.
#define SCAN_TIMEOUT_MS          20000
#define SCAN_ATTEMPTS            2
#define SPOOLMAN_RETRY_PAUSE_MS  300
// The archive pass, one attempt as it always had.
#define ARCHIVE_TIMEOUT_MS       8000

// How often the status line is repainted while the inventory comes in. Ten a
// second reads as motion.
#define SEARCH_TICK_MS           100

// How long a lookup waits for the worker when it is busy with somebody
// else's list: the scan of a tag that was taken away, which can be the 51 s
// of a BamBuddy library plus its archive, or the tags page's list.
#define LOOKUP_SLOT_WAIT_MS      120000UL

enum RunStage : uint8_t { RUN_NONE, RUN_ACTIVE, RUN_ARCHIVE };
enum WantStage : uint8_t { WANT_NONE, WANT_ACTIVE, WANT_ARCHIVE };

// What the worker is loading on the lookup's behalf.
static RunStage       s_run = RUN_NONE;
// A lookup waits for that load. False once it was abandoned: the list then
// only feeds the spool cache and the uid index.
static bool           s_run_live = false;
static bool           s_run_have_stamp = false;
static InventoryStamp s_run_stamp = { -1, 0 };

// The lookup waiting for its verdict.
static LookupCtx      s_lk;
static bool           s_pending = false;
// It needs the worker, which was busy when it asked.
static WantStage      s_want = WANT_NONE;
static unsigned long  s_want_since = 0;
// The worker was busy with an abandoned lookup's scan, which fills the uid
// index: ask the index again before loading the same inventory once more.
static bool           s_want_reask = false;

// The two filters, kept for as long as a load may still have to start.
static JsonDocument   s_filter;
static JsonDocument   s_filter2;

bool lookupPending()  { return s_pending; }
bool lookupScanBusy() { return s_run != RUN_NONE || s_want != WANT_NONE; }

void lookupPaintSearching() {
  if (!lbl_status) return;
  char buf[48];
  if (s_run != RUN_NONE && s_run_live && backendJobBytes() > 0) {
    snprintf(buf, sizeof(buf), T(STR_SEARCHING_INVENTORY_KB),
             (unsigned)(backendJobBytes() / 1024));
  } else {
    copyT(buf, sizeof(buf), STR_SEARCHING_INVENTORY);
  }
  lv_label_set_text(lbl_status, buf);
}

// What the caller of querySpoolman() did with the verdict when the lookup
// still ended inside the call. For a lookup that went through the worker the
// tick does it, once the verdict is in.
void lookupFollowUp(LookupOrigin origin, const char* uid) {
  switch (origin) {
    case LOOKUP_FROM_BAMBU:
      if (!sm_found && wifi_ok) {
        link_tag_first_seen_ms = millis();  // Start timer
        link_popup_dismissed = false;
      }
      break;
    case LOOKUP_FROM_UID:
    case LOOKUP_FROM_NTAG:
      if (!sm_found) {
        if (origin == LOOKUP_FROM_NTAG)
          Serial.println("NTAG: not in Spoolman -> waiting for delay");
        strncpy(link_tag_uid, uid, sizeof(link_tag_uid)-1);
        link_tag_uid[sizeof(link_tag_uid)-1] = '\0';
        link_tag_first_seen_ms = millis();
        link_popup_dismissed = false;
      } else {
        if (origin == LOOKUP_FROM_NTAG) {
          lv_label_set_text(lbl_status, T(STR_TAG_FOUND));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(UI_COL_ACCENT), 0);
        }
        // Stays shorter than 32 characters, so everything that tells a
        // Bambu tag apart by that length keeps saying no.
        strncpy(g_tag.tray_uuid, uid, sizeof(g_tag.tray_uuid)-1);
        g_tag.tray_uuid[sizeof(g_tag.tray_uuid)-1] = '\0';
        updateLinkButton();
      }
      break;
    default:
      break;
  }
}

// The verdict is in. A lookup that went through the worker has nobody waiting
// on the other end of querySpoolman() any more, so its follow-up runs here.
static void finishLookup() {
  const bool was_pending = s_pending;
  s_pending = false;
  s_want = WANT_NONE;
  if (!was_pending) return;
  lookupFollowUp(s_lk.origin, s_lk.tray);
  paintTagStatus();
}

void lookupAbandon() {
  if (!s_pending) return;
  s_pending = false;
  s_want = WANT_NONE;
  if (s_run != RUN_NONE) {
    s_run_live = false;
    logSD("Backend: lookup left before its verdict, the inventory still feeds cache and index");
  }
}

static void wantWorker(WantStage stage, bool reask) {
  if (s_want != stage) s_want_since = millis();
  s_want = stage;
  s_want_reask = s_want_reask || reask;
}

static void tryStartActive() {
  if (s_run != RUN_NONE || backendListBusy()) {
    wantWorker(WANT_ACTIVE, s_run != RUN_NONE);
    return;
  }
  if (!backendJobStartList(false, &s_filter, SCAN_TIMEOUT_MS, SCAN_ATTEMPTS,
                           SPOOLMAN_RETRY_PAUSE_MS)) {
    wantWorker(WANT_ACTIVE, false);
    return;
  }
  s_run            = RUN_ACTIVE;
  s_run_live       = true;
  s_run_have_stamp = s_lk.have_stamp;
  s_run_stamp      = s_lk.stamp;
  s_want           = WANT_NONE;
  s_want_reask     = false;
}

static void tryStartArchive() {
  if (s_run != RUN_NONE || backendListBusy()) {
    wantWorker(WANT_ARCHIVE, false);
    return;
  }
  if (!backendJobStartList(true, &s_filter2, ARCHIVE_TIMEOUT_MS, 1, 0)) {
    wantWorker(WANT_ARCHIVE, false);
    return;
  }
  s_run      = RUN_ARCHIVE;
  s_run_live = true;
  s_want     = WANT_NONE;
}

// The filter of the archive pass: only what tells whether a spool answers to
// the tag, and whether it is archived.
static void buildArchiveFilter(JsonDocument& filter2) {
  filter2.clear();
  JsonArray filter2_arr = filter2.to<JsonArray>();
  JsonObject f2 = filter2_arr.add<JsonObject>();
  f2["id"] = true;
  f2["archived"] = true;
  for (uint8_t i = 0; i < TAG_FIELD_EXTRA_COUNT; i++)
    f2["extra"][tagFieldSpec(i).key] = true;
}

void lookupScanBegin(const LookupCtx& c, const JsonDocument& filter) {
  s_lk = c;
  s_pending = true;
  s_filter.set(filter.as<JsonVariantConst>());
  tryStartActive();
}

void lookupArchiveBegin(const LookupCtx& c) {
  s_lk = c;
  // Second call with allow_archived=true, on the worker like the active list
  // and into PSRAM like it.
  buildArchiveFilter(s_filter2);
  // Not after the index has answered: what it holds came out of the archive
  // as much as out of the active list. Then a code of 0 falls through to the
  // tail, which is what sets sm_found and paints "not in Spoolman".
  if (c.index_unknown) {
    lookupResolveArchive(s_lk, nullptr, nullptr);
    finishLookup();
    return;
  }
  s_pending = true;
  tryStartArchive();
}

// An abandoned lookup's list, taken for what it is still good for: the spool
// cache, and the uid index the next unknown tag asks instead of scanning.
// The same tests the verdict makes before it fills them.
static void harvest(RunStage stage, const BackendListResult& r, JsonDocument& doc) {
  const bool whole = (r.code == 200 && !r.err && !r.partial);
  const InventoryStamp* stamp = s_run_have_stamp ? &s_run_stamp : nullptr;
  if (stage == RUN_ACTIVE) {
    if (whole) {
      spoolCacheFill(doc.as<JsonArrayConst>(), spoolHasAnyTag, stamp);
      uidIndexBegin();
      uidIndexAdd(doc.as<JsonArrayConst>(), false);
    }
    backendJobTake();
    logSDf("Backend: inventory of a lookup left behind came in (%s), kept for cache and index",
           whole ? "whole" : "not whole");
    if (!whole) return;
    buildArchiveFilter(s_filter2);
    if (backendJobStartList(true, &s_filter2, ARCHIVE_TIMEOUT_MS, 1, 0)) {
      s_run      = RUN_ARCHIVE;
      s_run_live = false;
    }
    return;
  }
  if (whole) {
    uidIndexAdd(doc.as<JsonArrayConst>(), true);
    uidIndexCommit(stamp);
  }
  backendJobTake();
}

static void collect() {
  const BackendListResult r = backendJobResult();
  JsonDocument& doc = backendJobDoc();
  const RunStage stage = s_run;
  const bool live = s_run_live;
  s_run = RUN_NONE;

  if (r.gen != backendGeneration()) {
    backendJobTake();
    logSD("Backend: an inventory from before the backend switch came in, dropped");
    if (live) {
      // Asked of a server the scale no longer talks to. Forgetting the tag is
      // how the loop is told to look it up again, against the new one.
      s_pending = false;
      s_want = WANT_NONE;
      tagLookupForget();
    }
    return;
  }
  if (!live) { harvest(stage, r, doc); return; }

  if (stage == RUN_ACTIVE) {
    const LookupStep step = lookupResolveActive(s_lk, doc, &r, r.err);
    backendJobTake();
    if (step == LOOKUP_NEEDS_ARCHIVE) lookupArchiveBegin(s_lk);
    else                              finishLookup();
    return;
  }
  lookupResolveArchive(s_lk, &doc, &r);
  backendJobTake();
  finishLookup();
}

void lookupScanTick() {
  if (s_pending) {
    static unsigned long last = 0;
    if (millis() - last >= SEARCH_TICK_MS) {
      last = millis();
      paintTagStatus();
    }
  }

  if (s_run != RUN_NONE) {
    if (backendJobState() != BJS_DONE) return;
    collect();
  }

  if (s_want == WANT_NONE || !s_pending) return;
  if (millis() - s_want_since > LOOKUP_SLOT_WAIT_MS) {
    logSDf("Backend: the worker stayed busy for %lu s, lookup given up",
           LOOKUP_SLOT_WAIT_MS / 1000);
    const WantStage stage = s_want;
    s_want = WANT_NONE;
    if (stage == WANT_ARCHIVE) {
      lookupResolveArchive(s_lk, nullptr, nullptr);
      // The archive was never read: "not found" without it is no verdict.
      s_verdict_unknown = false;
    } else {
      paintLookupFailure(0, STR_API_ERROR);
    }
    finishLookup();
    return;
  }
  if (s_run != RUN_NONE || backendListBusy()) return;

  if (s_want == WANT_ARCHIVE) { tryStartArchive(); return; }

  // The scan the worker was busy with has just filled the index, most of the
  // time. A tag it does not hold needs no second download.
  if (s_want_reask) {
    s_want_reask = false;
    if (s_lk.searches_answered &&
        askUidIndex(s_lk.tray, s_lk.searches_answered,
                    s_lk.have_stamp ? &s_lk.stamp : nullptr)) {
      s_want = WANT_NONE;
      s_lk.index_unknown     = true;
      s_lk.scanned_inventory = false;
      JsonDocument none;
      if (lookupResolveActive(s_lk, none, nullptr, DeserializationError::Ok) ==
          LOOKUP_NEEDS_ARCHIVE)
        lookupArchiveBegin(s_lk);
      else
        finishLookup();
      return;
    }
  }
  tryStartActive();
}

// ============================================================
//  THE VERDICT - moved here from querySpoolman() word for word
// ============================================================

LookupStep lookupResolveActive(const LookupCtx& c, JsonDocument& doc,
                               const BackendListResult* r,
                               DeserializationError err) {
  const char* tray_uuid         = c.tray;
  const bool  is_bambu_tag      = c.is_bambu_tag;
  const bool  scanned_inventory = c.scanned_inventory;
  const bool  have_stamp        = c.have_stamp;
  const InventoryStamp stamp    = c.stamp;
  // The flag of the list this verdict reads, not of whichever list ran last.
  const bool  list_partial      = r ? r->partial : backendLastListPartial();

  // The retry's last attempt ended without an answer.
  if (r && r->gave_up) {
    paintLookupFailure(r->code, r->code == -2 ? STR_LINK_JSON_ERR : STR_API_ERROR);
    return LOOKUP_DONE;
  }

  Serial.printf("DBG free heap after parse: %d bytes  free PSRAM: %d bytes\n", ESP.getFreeHeap(), ESP.getFreePsram());
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (after Spoolman parse)",
    ESP.getFreeHeap(), ESP.getFreePsram());
  if (err) {
    Serial.printf("Backend JSON error (final): %s\n", err.c_str());
    logSDf("Backend: JSON error final=%s", err.c_str());
    paintLookupFailure(0, STR_LINK_JSON_ERR);
    return LOOKUP_DONE;
  }

  JsonArray spools = doc.as<JsonArray>();

  // Here and not further down: the scan below returns from the middle of this
  // function on the first spool it accepts. Only a scan that ran and came in
  // whole - every way out of a failed one has returned above, and a list
  // FilaMan gave up on halfway is not the inventory.
  if (scanned_inventory && !list_partial)
    spoolCacheFill(doc.as<JsonArrayConst>(), spoolHasAnyTag, have_stamp ? &stamp : nullptr);

  // Which rank the best match reaches, and how many spools answer to this tag
  // at all. Both need the whole list, so they are settled before anything is
  // shown: the loop below returns on the first spool it accepts, and taking
  // the first match in list order would hand a Bambu plugin duplicate the win
  // over the record this scale linked itself. FilaMan answers id descending,
  // so the duplicate comes first.
  int best_rank = TAG_RANK_NONE;
  sm_dup_count  = 0;
  for (JsonObjectConst cand : spools) {
    int rank = spoolTagRank(cand, tray_uuid);
    if (rank == TAG_RANK_NONE) continue;
    sm_dup_count++;
    if (best_rank == TAG_RANK_NONE || rank < best_rank) best_rank = rank;
  }
  if (sm_dup_count > 1) {
    logSDf("Backend: tag %s answers %d spools, taking rank %d",
           tray_uuid, sm_dup_count, best_rank);
  }

  // A list that stopped short - FilaMan's timeout or page cap - proves
  // nothing about a tag it does not contain. Read as "not there", the scale
  // offered to link or create the spool, and a library over the cap grew a
  // duplicate per scan. A match in the part that did arrive still counts.
  // Only after a list of this lookup: the flag is the last list call's, and
  // without one it would be some earlier lookup's.
  if (scanned_inventory && best_rank == TAG_RANK_NONE && list_partial) {
    logSDf("Backend: tag %s not in a partial inventory, verdict withheld", tray_uuid);
    paintLookupFailure(0, STR_API_ERROR);
    return LOOKUP_DONE;
  }

  for (JsonObject spool : spools) {
    if (spool["extra"].isNull()) continue;
    JsonObject extra = spool["extra"];

    int rank = spoolTagRank(spool, tray_uuid);
    if (rank == TAG_RANK_NONE || rank != best_rank) continue;

    // Says nothing after a short cut: the index is only asked when a scan is
    // coming, and then this spool came out of that scan.
    uidShadowReport(spool["id"] | 0, rank, spool["archived"] | false);

    // No short cut promises an active spool. FilaMan's scan names an archived
    // one as readily as any other, and the fetch by id that follows brought
    // spool 285 in here on 21.09.2026: shown with its 966 g as if it were on
    // the shelf, sm_archived false, every write open. Asked here rather than
    // in each short cut, so that one added later cannot forget it, and in
    // front of everything below that writes.
    if (spool["archived"] | false) {
      const int archived_id = spool["id"] | 0;
      doc.clear();             // the byId fetch wants the PSRAM back
      showArchivedSpool(archived_id);
      return LOOKUP_DONE;
    }

    // Read after the match, not as part of it: the FilaMan migration below
    // writes this value back and wants the tag field's own notation. A spool
    // matched through card_uids has no tag field, which leaves this empty -
    // harmless, because that migration only runs in FilaMan mode.
    String tag_val;
    if (!extra["tag"].isNull()) {
      tag_val = extra["tag"].as<String>();
      tag_val.replace("\"", "");
      tag_val.trim();
    }

    // FOUND
    sm_found    = true;
    sm_id       = spool["id"] | 0;

    // One-off migration to the plain hex notation. Older firmware wrote an
    // NTAG uid into extra.tag with colons, which is the one notation the
    // server side ilike cannot find once the scale asks in plain hex - the
    // spool is still found, but only by pulling the whole inventory. Writing
    // it back once puts it on the fast path for good.
    //
    // Deliberately narrow:
    //  - only the native Spoolman backend. FilaMan has its own migration two
    //    blocks down, and BamBuddy normalised from the start.
    //  - only a match through the tag field itself. A spool found through the
    //    Bambu plugin's bookkeeping has nothing to correct here.
    //  - never a list field. card_uids holds several entries and writing one
    //    value into it would drop the rest.
    //  - only when the stored value really differs, so a correct entry is not
    //    patched on every scan.
    //
    // A failed write is remembered rather than retried. A key without write
    // permission would otherwise stall and log on every single placement, and
    // the spool is found either way - the migration is a speed-up, not a
    // requirement.
    // Both backends that store a tag in a text field are covered. BamBuddy is
    // not: it normalised from the start and its tag never reaches this loop.
    //
    // The value differs by backend but the question does not. Spoolman keeps
    // it in whichever extra field the user picked, FilaMan in the native
    // rfid_uid, which the mapping presents here as extra.tag.
    const bool notation_backend =
        (backendMode() == BACKEND_SPOOLMAN &&
         !tagFieldIsNative() && !tagFieldIsList() && tagFieldKey()) ||
        // tag_legacy has its own migration below and would double patch.
        (backendIsFilaMan() && !(spool["extra"]["tag_legacy"] | false));
    if (notation_backend && sm_id > 0 && rank == TAG_RANK_FIELD) {
      static int s_migrate_failed_id = 0;    // do not hammer a read-only key
      String stored;
      const char* key = backendIsFilaMan() ? "tag" : tagFieldKey();
      if (!extra[key].isNull()) {
        stored = extra[key].as<String>();
        stored.replace("\"", "");
        stored.trim();
      }
      char want[TAG_UID_CMP_MAX];
      tagUidNormalize(stored.c_str(), want, sizeof(want));
      if (stored.length() && want[0] && stored != want && sm_id != s_migrate_failed_id) {
        int mc = backendPatchSpoolTag(cfg_spoolman_base, sm_id, want, 4000);
        logSDf("%s: rewrote tag of spool %d to plain hex, HTTP %d",
               backendIsFilaMan() ? "FilaMan" : "Spoolman", sm_id, mc);
        s_migrate_failed_id = (mc == 200) ? 0 : sm_id;
      }
    }

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

    // The same idea, one field over: a spool found through the Bambu plugin's
    // own bookkeeping has nothing in rfid_uid, so ?search= cannot see it and
    // every scan would pull the whole inventory again. Writing the tray uuid
    // there once puts it on the fast path for good.
    //
    // Only from rank 2 or 3, which is what "found through the plugin" means.
    // A rank 1 match already has the field, and re-patching it on every scan
    // would be a pointless write and a needless stall.
    if (backendIsFilaMan() && sm_id > 0 && rank > TAG_RANK_FIELD && tag_val.length() == 0) {
      int mc = backendPatchSpoolTag(cfg_spoolman_base, sm_id, tray_uuid, 4000);
      logSDf("FilaMan: spool %d found at rank %d, wrote rfid_uid, HTTP %d",
             sm_id, rank, mc);
      // Free a moment ago, as the link list sees it, and bound from here on.
      // Comfort only: left out, the spool would be offered once more and the
      // read on the tap would turn it down.
      if (mc == 200) spoolCacheSetBound(sm_id, true);
    }

    if (backendIsFilaMan() && sm_id > 0) {
      filamanSyncBambuFields(sm_id, extra, tray_uuid);
    }

    captureBindings(spool);

    // In step with the tag on the reader rather than with the binding. A Bambu
    // spool carries a chip per side and only the one lying on the pad can be
    // reported, so the field would stay half filled if this waited for an
    // explicit link - and a library that is already bound would never reach
    // one at all.
    //
    // What makes it fill itself is a detail of the scan loop: the marker that
    // stops a tag from being looked up twice is keyed on g_tag.uid_str, the
    // chip, while the lookup goes out with the tray uuid (app_loop.cpp:849 and
    // :1510). Turning the spool over is therefore a new tag to that marker and
    // a fresh lookup lands here, where the second chip is appended beside the
    // first. Anything that starts deduplicating on the tray uuid takes that
    // away without touching a line of this.
    syncHwUidField(sm_id, tray_uuid);

    sm_filament_id = spool["filament"]["id"] | 0;
    sm_vendor_id   = spool["filament"]["vendor"]["id"] | 0;
    sm_remaining = spool["remaining_weight"] | 0.0f;
    sm_total    = resolveInitial(spool);
    sm_spool_weight = resolveTare(spool, &sm_tare_source);
    logSDf("Backend: found ID=%d remaining=%.1fg total=%.0fg",
      sm_id, sm_remaining, sm_total);
    logSDf("[verbose] LOC: querySpoolman id=%d shown_for=%d", sm_id, g_loc_popup_shown_for_id);
    String art_nr = spool["filament"]["article_number"] | "";
    art_nr.trim();
    strncpy(sm_article_nr, art_nr.c_str(), sizeof(sm_article_nr)-1);
    sm_article_nr[sizeof(sm_article_nr)-1] = '\0';
    String fil_name = spool["filament"]["name"] | String("");
    fil_name.trim();
    strncpy(sm_filament_name, fil_name.c_str(), sizeof(sm_filament_name)-1);
    sm_filament_name[sizeof(sm_filament_name)-1] = '\0';

    // Location - einfacher String in Spoolman
    sm_location_name[0] = '\0';
    if (!spool["location"].isNull() && spool["location"].is<const char*>()) {
      String loc = spool["location"] | String("");
      loc.trim();
      strncpy(sm_location_name, loc.c_str(), sizeof(sm_location_name)-1);
      sm_location_name[sizeof(sm_location_name)-1] = '\0';
    }

    // Spool status. Only FilaMan maps it, the others leave the key unset.
    sm_status_id = spool["status_id"] | 0;
    if (!extra["last_dried"].isNull()) {
      String dried = extra["last_dried"].as<String>();
      dried.replace("\"", "");
      char day[11];
      isoDayLocal(dried.c_str(), day, sizeof(day));
      char de_date[12];
      isoToDe(day, de_date, sizeof(de_date));
      strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
      sm_last_dried[sizeof(sm_last_dried)-1] = '\0';
    } else {
      strncpy(sm_last_dried, "-", sizeof(sm_last_dried)-1);
    }

    Serial.printf("Backend: ID=%d, %.1fg, dried: %s\n",
      sm_id, sm_remaining, sm_last_dried);

    // Material, vendor and colour from the server. Material and vendor are
    // shown only without a Bambu tag (g_tag.material empty); the colour goes
    // through applyServerColor(), which lets a Bambu tag keep its own.
    String sm_material = spool["filament"]["material"] | String("");
    sm_material.trim();
    String sm_vendor_name = "";
    if (!spool["filament"]["vendor"].isNull()) {
      sm_vendor_name = spool["filament"]["vendor"]["name"] | String("");
      sm_vendor_name.trim();
    snprintf(sm_vendor_g, sizeof(sm_vendor_g), "%s", sm_vendor_name.c_str());
    }
    String sm_color = spool["filament"]["color_hex"] | String("");
    sm_color.trim();

    bool is_ntag = !is_bambu_tag;
    logSDf("Spool %d identified: %s %s, %.0fg of %.0fg", sm_id,
           sm_vendor_name.length() ? sm_vendor_name.c_str() : "?",
           sm_material.length() ? sm_material.c_str() : "?",
           sm_remaining, sm_total);
    Serial.printf("is_ntag=%d material='%s' vendor='%s' color='%s'\n",
      is_ntag, sm_material.c_str(), sm_vendor_name.c_str(), sm_color.c_str());
    if (is_ntag) {
      const TagInfo *ti = tagCachedInfo();
      const bool from_tag = tagCachedHasRecord();
      setFromServerOrTag(lbl_material, sm_material.c_str(), from_tag ? ti->material : "");
      setFromServerOrTag(lbl_vendor, sm_vendor_name.c_str(), from_tag ? ti->brand : "");
      strncpy(sm_material_global, sm_material.c_str(), sizeof(sm_material_global)-1);
      sm_material_global[sizeof(sm_material_global)-1] = '\0';
    }
    applyServerColor(sm_color, is_bambu_tag);

    // Update display - Fix 5: color based on remaining %
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
      int bar_w = (int)((pct / 100.0f) * (float)MAIN_BAR_W);
      if (bar_w < 0) bar_w = 0;
      if (bar_w > MAIN_BAR_W) bar_w = MAIN_BAR_W;
      lv_obj_set_width(lbl_scale_diff, bar_w);
      lv_obj_set_style_bg_color(lbl_scale_diff, lv_color_hex(pct_color), 0);
    }

    // Show SM-ID in green (linked)
    char sm_id_str[16];
    snprintf(sm_id_str, sizeof(sm_id_str), "%d", sm_id);
    lv_label_set_text(lbl_spoolman_id, sm_id_str);
    lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0x28d49a), 0);

    applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, sm_last_dried);

    lv_label_set_text(lbl_detail, strlen(sm_article_nr) > 0 ? sm_article_nr : "-");
    lv_label_set_text(lbl_filament_name, strlen(sm_filament_name) > 0 ? sm_filament_name : "-");

    // last_used is directly in the spool object (not in extra!)
    applyLastUsed(spool["last_used"] | (const char*)nullptr,
                spool["extra"]["last_weighed"] | (const char*)nullptr, sm_id);

    // Bring Spoolman's relation up to what is physically on the reader. Two
    // groups of users end up here: somebody whose spools are bound through an
    // extra field, whose bindings move over on the first placement, and
    // somebody with Bambu spools, which collect one entry per side as each
    // side gets read.
    //
    // A Bambu spool ends up with up to three entries, and each earns its place:
    //   chip uid, one per side  every reader can report these, so they are
    //                           what makes the spool findable by a phone, an
    //                           ESPHome box, or Spoolman's Add tag dialog
    //   tray uuid               only a Bambu-aware reader can produce it, but
    //                           it identifies the spool from either side at
    //                           once, without waiting for both chips
    //
    // What is already linked comes from captureBindings() above, so nothing is
    // sent that Spoolman already holds and a settled spool costs no requests
    // at all.
    //
    // Only while the native source is the selected one. Somebody who picked
    // extra.nfc_id did so because another tool reads that field, and writing
    // into a store they did not choose is not this scale's call.
    //
    // Nothing is cleared here, unlike the explicit link in patchSpoolTag().
    // This runs on its own, without anybody asking for it, and a store that
    // silently empties a field the user never touched is worse than one that
    // leaves a duplicate behind.
    if (tagFieldIsNative() && sm_id > 0 && backendHasNativeTags()) {
      char* have = sm_tag_values[TAG_FIELD_NATIVE];

      struct AutoLink {
        // Whether anything was actually linked, which is what decides if the
        // tag is worth announcing a second time.
        static bool add(int spool_id, const char* uid, const char* format) {
          int conflict = 0;
          int code = backendLinkTag(cfg_spoolman_base, spool_id, uid,
                                    format, &conflict);
          if (code == 409) {
            // Nobody asked for this link, so a tag that belongs to another
            // spool is not an error to put on screen. It is worth a line in
            // the log, because it means two spools claim one identity.
            logSDf("Auto-link: uid=%s belongs to spool %d, left alone",
                   uid, conflict);
            return false;
          } else if (code >= 200 && code < 300) {
            logSDf("Auto-link: uid=%s added to spool %d", uid, spool_id);
            return true;
          }
          logSDf("Auto-link: uid=%s to spool %d failed, HTTP %d",
                 uid, spool_id, code);
          return false;
        }

        // Keeps the captured list in step with what was just linked. It was
        // read before these links existed, and an unlink straight afterwards
        // reads that same list to decide what to drop. Without this it would
        // leave the new entries behind, and a spool the user was told is
        // unlinked would still be found by them.
        static void remember(char* list, const char* uid) {
          char merged[CARD_UIDS_MAX];
          if (cardUidsAppend(list, uid, merged, sizeof(merged)) != CARD_UIDS_ADDED)
            return;
          strncpy(list, merged, CARD_UIDS_MAX - 1);
          list[CARD_UIDS_MAX - 1] = '\0';
        }
      };

      bool linked = false;
      const char* chip = tagNativeUid(tray_uuid);
      if (chip && chip[0] && !cardUidsContain(have, chip)) {
        if (AutoLink::add(sm_id, chip, tagFormatName(tray_uuid))) {
          AutoLink::remember(have, chip);
          linked = true;
        }
      }

      if (tagIsBambu(tray_uuid) && !cardUidsContain(have, tray_uuid)) {
        if (AutoLink::add(sm_id, tray_uuid, "bambu")) {
          AutoLink::remember(have, tray_uuid);
          linked = true;
        }
      }

      // OpenSpoolman reads a spool's tray uuid out of extra.tag and knows
      // nothing about Spoolman's relation yet. A spool that migrates over
       // through this path - found by a chip uid in card_uids, say - would
      // otherwise drop out of its view, and this is the very path a whole
      // library gets adopted through. The explicit link in patchSpoolTag()
      // does the same thing for the same reason.
      //
      // Only into an empty field. Filling a blank is an addition; overwriting
      // a value somebody put there would be an opinion, and this runs without
      // anybody asking for it.
      if (tagIsBambu(tray_uuid) && !sm_tag_values[TAG_FIELD_TAG][0]) {
        const TagFieldSpec& companion = tagFieldSpec(TAG_FIELD_TAG);
        if (backendHasExtraField(companion.key)) {
          char val[40];
          tagFieldFormat(companion, tray_uuid, val, sizeof(val));
          int c = backendPatchExtraField(cfg_spoolman_base, sm_id,
                                         companion.key, val);
          logSDf("Auto-link: kept tray uuid in %s='%s' of spool %d HTTP %d",
                 companion.key, val, sm_id, c);
          if (c >= 200 && c < 300) {
            strncpy(sm_tag_values[TAG_FIELD_TAG], val, CARD_UIDS_MAX - 1);
            sm_tag_values[TAG_FIELD_TAG][CARD_UIDS_MAX - 1] = '\0';
            // Spoolman's own relation does not count as bound in the link
            // list, a value in extra.tag does.
            spoolCacheSetBound(sm_id, true);
          }
        } else {
          logSDf("Auto-link: %s missing on the server, tray uuid not kept",
                 companion.key);
        }
      }

      // The scan that started this lookup went out before the link existed, so
      // any browser paired with this scale was told the tag is unknown. Say it
      // again, now that it resolves.
      if (linked && chip && chip[0])
        scheduleRescan(chip, tagFormatName(tray_uuid));
    }

    updateLinkButton();
    return LOOKUP_DONE;
  }

  // Not found in active spools - check if archived
  Serial.println("Backend: not in active spools, checking archive...");
  // Every identifier this list holds goes into the uid index before the
  // document is given up. Only from a scan that ran and came in whole, the
  // same test the list cache makes above. The index stays open until the
  // archive pass below is in as well; a lookup that leaves before that leaves
  // none behind, see uidIndexTick(). Asked further up, in shadow for now.
  if (scanned_inventory && !list_partial) {
    uidIndexBegin();
    uidIndexAdd(doc.as<JsonArrayConst>(), false);
  }
  doc.clear();  // RAM freigeben vor zweitem Call
  return LOOKUP_NEEDS_ARCHIVE;
}

void lookupResolveArchive(const LookupCtx& c, JsonDocument* doc2p,
                          const BackendListResult* r2) {
  const char* tray_uuid         = c.tray;
  const bool  scanned_inventory = c.scanned_inventory;
  const bool  have_stamp        = c.have_stamp;
  const InventoryStamp stamp    = c.stamp;
  const int   code2 = r2 ? r2->code : 0;
  const DeserializationError err2 = r2 ? r2->err : DeserializationError::Ok;

  bool archive_whole = false;       // the second half of the scan came in, all of it
  if (code2 == 200) {
    JsonDocument& doc2 = *doc2p;
    if (!err2) {
      JsonArray spools2 = doc2.as<JsonArray>();
      archive_whole = !r2->partial;
      // With the archive in, the index has seen what this scan saw. In front
      // of the loop, which returns from its middle and clears the document.
      // Both calls do nothing when the active list did not open an index.
      if (archive_whole) {
        uidIndexAdd(doc2.as<JsonArrayConst>(), true);
        uidIndexCommit(have_stamp ? &stamp : nullptr);
      }
      for (JsonObject spool : spools2) {
        // Only check truly archived spools (explicit bool cast needed for JsonVariant)
        bool is_archived = spool["archived"].as<bool>();
        if (!is_archived) continue;
        const int archived_rank = spoolTagRank(spool, tray_uuid);
        if (archived_rank == TAG_RANK_NONE) continue;
        // Archived, but found. None of what the screen needs is in the lean
        // archive filter, see showArchivedSpool().
        const int archived_id = spool["id"] | 0;
        uidShadowReport(archived_id, archived_rank, true);
        doc2.clear();          // the byId fetch wants the PSRAM back
        showArchivedSpool(archived_id);
        return;
      }
    }
  }

  // Truly not found
  Serial.println("Backend: spool not found");
  logSD("Backend: spool not found");
  // Only a scan that ran to its end is an answer to hold the index against.
  if (scanned_inventory && archive_whole) {
    uidShadowReport(0, TAG_RANK_NONE, false);
  } else if (s_shadow != SHADOW_NOT_ASKED) {
    s_shadow = SHADOW_NOT_ASKED;
    logSD("uid index: the scan did not run to its end, nothing to compare");
  }
  { char nb[40]; backendText(T(STR_NOT_IN_SPOOLMAN), nb, sizeof(nb)); lv_label_set_text(lbl_spoolman_weight, nb); }
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  sm_found = false;
  s_verdict_unknown = true;
  updateLinkButton();
}
