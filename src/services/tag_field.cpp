#include "tag_field.h"

#include <string.h>

// backend_api.h pulls in ArduinoJson, which must be parsed before lang.h
// defines the T() macro - ArduinoJson uses T as a template parameter.
#include "services/backend.h"
#include "services/backend_api.h"

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "services/tag_uid.h"
#include "services/user_options.h"

// Set once the move from extra.tag to the native tags was decided, either way.
#define TAG_NATIVE_MOVE_KEY "tag_mv27"

// The whole feature in one table. Adding a fourth convention is a row here
// plus three strings; nothing else in the firmware asks for a field by name.
//
// card_uids reuses CARD_UIDS_FIELD rather than spelling the key a second time:
// tag_uid.cpp compares against that macro, and two spellings that drift apart
// would break the list handling in a way no compiler would catch.
static const TagFieldSpec SPECS[TAG_FIELD_COUNT] = {
  // key             native is_list plain_hex  name              sub                   info
  { "tag",           false, false,  true,      STR_TF_TAG,       STR_TF_TAG_SUB,       STR_TF_TAG_INFO      },
  { "nfc_id",        false, false,  true,      STR_TF_NFCID,     STR_TF_NFCID_SUB,     STR_TF_NFCID_INFO    },
  { CARD_UIDS_FIELD, false, true,   true,      STR_TF_CARDUIDS,  STR_TF_CARDUIDS_SUB,  STR_TF_CARDUIDS_INFO },
  // No key and not a list: several tags per spool are the normal case here,
  // not a format squeezed into one text field, so the multi tag switch has
  // nothing to switch and stays hidden.
  { nullptr,         true,  false,  true,      STR_TF_NATIVE,    STR_TF_NATIVE_SUB,    STR_TF_NATIVE_INFO   },
};

const TagFieldSpec& tagFieldSpec(uint8_t id) {
  return SPECS[id < TAG_FIELD_COUNT ? id : TAG_FIELD_TAG];
}

uint8_t tagFieldEffective() {
  if (g_tag_field >= TAG_FIELD_COUNT) return TAG_FIELD_TAG;
  if (!SPECS[g_tag_field].is_native) return g_tag_field;
  // The mode, and nothing else. This is read from LVGL callbacks and from
  // early boot, long before the network exists, so it must not reach out:
  // backendHasNativeTags() probes over HTTP the first time it is asked, and
  // lwIP asserts hard on a request made before tcpip_init - "Invalid mbox",
  // a boot loop, no way in but the cable.
  //
  // That makes this a narrower guard than it looks, and deliberately so. It
  // answers "can this backend have a tag relation at all", which is what the
  // NVS setting can get wrong when the backend is switched underneath it.
  if (backendMode() != BACKEND_SPOOLMAN) return TAG_FIELD_TAG;

  // And the second way the setting goes stale: the server was downgraded off
  // the version that has the relation. Nothing about the choice changed, so
  // nothing used to notice - but the selected source has no key, every extra
  // field path skips it, and the native endpoints answer
  // BACKEND_NOT_SUPPORTED. Linking stopped working with no setting looking
  // wrong anywhere.
  //
  // Reading a cache, never probing: an answer that had to be fetched cannot be
  // had from here, see above. Only a server that actually said no counts, so a
  // bad moment on the network does not swing the field back and forth.
  //
  // The stored choice is deliberately left alone. It is still what the user
  // asked for, and putting the server back on a version that has the relation
  // brings it into effect again without anybody having to pick it a second
  // time.
  if (backendNativeTagsAbsent()) return TAG_FIELD_TAG;

  return TAG_FIELD_NATIVE;
}

const TagFieldSpec& tagFieldSelected() { return tagFieldSpec(tagFieldEffective()); }
const char*         tagFieldKey()      { return tagFieldSelected().key; }
bool                tagFieldIsList()   { return tagFieldSelected().is_list; }
bool                tagFieldIsNative() { return tagFieldSelected().is_native; }

const char* tagFieldKeyName() {
  const char* k = tagFieldSelected().key;
  return k ? k : "native";
}

bool tagFieldHoldsSeveral() {
  // FilaMan carries two native columns since 1.3.1 and has no field to choose,
  // so the source below says nothing about it. Whether this particular server
  // is new enough is not decided here - see the comment in the header.
  if (backendIsFilaMan()) return true;
  // BamBuddy holds tag_uid and tray_uuid, which is two identities of one chip
  // rather than two chips. A second flange has nowhere to go.
  if (backendIsBamBuddy()) return false;

  // Spoolman. The list field holds several while the switch that appends
  // rather than replaces is on, and that needs nothing from the server.
  if (!tagFieldIsNative()) return tagFieldIsList() && g_card_uids_write;

  // The relation does need something from the server: it arrived in v0.27, and
  // tagFieldEffective() above answers "native" on every Spoolman because it
  // must not reach the network. On an older server the source therefore reads
  // as selected while the endpoints are not there, and a row offering a second
  // tag would promise something no link can deliver.
  //
  // Read out of the cache, never probed - this runs from the screen build. An
  // unanswered cache (-1) leaves the row visible: before the first lookup
  // nothing is known, and hiding a row that belongs there is the worse guess
  // of the two. A definite "absent" takes it away.
  return backendNativeTagsCached() != 0;
}

void tagFieldAutoSelect() {
  // Asked before the settled-choice return below, because this is the call
  // that fills the cache tagFieldEffective() reads to fall back off a relation
  // the server does not have. Returning early on a settled choice - which is
  // every installation that ever picked one - would leave that cache empty,
  // and the fallback would never arm for the one case it exists for: somebody
  // on the native source whose server was downgraded.
  //
  // But only where the answer is used: while no choice is made yet, or while
  // the native source is the choice. On extra.tag or card_uids the probe
  // decides nothing, and an inconclusive one (a proxy, a timeout) is not
  // cached - so there it would be one blocking request per scan, forever.
  // extra.tag as well, once: see the move to the native tags below.
  const bool move_pending = g_tag_field == TAG_FIELD_TAG && !prefsHasKey(TAG_NATIVE_MOVE_KEY);
  const bool need_probe = !g_tag_field_chosen || g_tag_field == TAG_FIELD_NATIVE || move_pending;
  const bool has_native = need_probe && backendHasNativeTags();

  // A server that answered no while the native source is selected. Said once
  // per probe rather than per scan: tagFieldEffective() is asked constantly
  // and cannot log.
  static bool s_absence_logged = false;
  if (backendNativeTagsAbsent() && g_tag_field == TAG_FIELD_NATIVE) {
    if (!s_absence_logged) {
      logSDf("Tag field: server has no tag relation, falling back to extra.%s",
             tagFieldSpec(TAG_FIELD_TAG).key);
      s_absence_logged = true;
    }
  } else {
    s_absence_logged = false;
  }

  // extra.tag was this firmware's own default for as long as there was no
  // relation, so a scale on it is on it by habit rather than by choice. Once
  // its server has the relation (Spoolman 0.27) it moves over, once: the
  // marker keeps a later choice of extra.tag from being undone on every scan.
  // Nothing is emptied - the spools move one by one as they are placed, see
  // the auto link in lookup_scan.cpp - and extra.tag keeps being written for
  // OpenSpoolman. nfc_id and card_uids were chosen for another tool and stay.
  if (move_pending && has_native) {
    prefsPutBool(TAG_NATIVE_MOVE_KEY, true);
    g_tag_field = TAG_FIELD_NATIVE;
    prefsPutUChar("tag_field", TAG_FIELD_NATIVE);
    g_osm_tag = true;
    prefsPutBool(OSM_TAG_KEY, true);
    logSD("Tag field: server has native tags, moved from extra.tag to them; "
          "extra.tag stays and is still written for OpenSpoolman");
    return;
  }
  // Not marked on a server without the relation: the day it is updated to
  // 0.27 the move still has to happen. The probe caches that server's 404,
  // so waiting costs no request per scan.

  if (!g_tag_field_chosen && has_native) {
    g_tag_field = TAG_FIELD_NATIVE;
    g_tag_field_chosen = true;
    prefsPutUChar("tag_field", TAG_FIELD_NATIVE);
    logSD("Tag field: server has native tags, selected them");
  }

  // Whether OpenSpoolman gets its extra.tag, decided the first time the
  // native tags are in force: on when the field is already there, which means
  // some tool already reads it; off on a server that never had it.
  if (g_tag_field == TAG_FIELD_NATIVE && has_native && !prefsHasKey(OSM_TAG_KEY)) {
    g_osm_tag = backendHasExtraField(tagFieldSpec(TAG_FIELD_TAG).key);
    prefsPutBool(OSM_TAG_KEY, g_osm_tag);
    logSDf("Tag field: extra.tag for OpenSpoolman %s", g_osm_tag ? "on (field exists)" : "off");
  }
}

void tagFieldNoteChoice() {
  prefsPutBool(TAG_NATIVE_MOVE_KEY, true);
}

void tagFieldFormat(const TagFieldSpec& spec, const char* uid,
                    char* out, size_t out_len) {
  if (!out || out_len == 0) return;
  if (spec.plain_hex) {
    tagUidNormalize(uid, out, out_len);
    return;
  }
  // Nothing left that wants the raw form. extra.tag used to keep the colon
  // notation an NTAG is read in, which made it the only one of the four
  // conventions not storing plain hex - and inconsistent with itself, since a
  // Bambu tray uuid went into the same field as bare hex.
  //
  // Switching it does not orphan anything: spoolTagRank() compares normalised
  // on both sides, so an entry still carrying colons is found, and the scan
  // rewrites it once. What it does cost is the fast path for those entries
  // until then, because the server side filter is an ilike on one notation.
  strncpy(out, uid ? uid : "", out_len - 1);
  out[out_len - 1] = '\0';
}

// ============================================================
//  TAG IDENTITY
//  See the block comment in tag_field.h for why a Bambu tag has two.
// ============================================================

bool tagIsBambu(const char* scanned) {
  if (!scanned || !scanned[0]) return false;
  // 32 characters is what a decoded tray uuid has, and nothing else the scale
  // looks a spool up by produces one: a normalised NTAG uid is 14, a card 8.
  char hex[40];
  tagUidNormalize(scanned, hex, sizeof(hex));
  return strlen(hex) == 32;
}

const char* tagNativeUid(const char* scanned) {
  // g_tag.uid_str is only ever written by the Bambu scan path, which is also
  // the only path that produces a 32 character value to be called with. Read
  // under any weaker condition it would hand back whatever Bambu tag came
  // before, and that is how a tag gets linked to the wrong spool.
  return tagIsBambu(scanned) ? g_tag.uid_str : scanned;
}

const char* tagFormatName(const char* scanned) {
  return tagIsBambu(scanned) ? "bambu" : "ntag";
}
