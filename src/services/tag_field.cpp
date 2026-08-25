#include "tag_field.h"

#include <string.h>

// backend_api.h pulls in ArduinoJson, which must be parsed before lang.h
// defines the T() macro - ArduinoJson uses T as a template parameter.
#include "services/backend_api.h"

#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/prefs_store.h"
#include "services/tag_uid.h"
#include "services/user_options.h"

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

const TagFieldSpec& tagFieldSelected() { return tagFieldSpec(g_tag_field); }
const char*         tagFieldKey()      { return tagFieldSelected().key; }
bool                tagFieldIsList()   { return tagFieldSelected().is_list; }
bool                tagFieldIsNative() { return tagFieldSelected().is_native; }

const char* tagFieldKeyName() {
  const char* k = tagFieldSelected().key;
  return k ? k : "native";
}

void tagFieldAutoSelect() {
  if (g_tag_field_chosen) return;          // a decision, even an implicit one
  if (!backendHasNativeTags()) return;

  g_tag_field = TAG_FIELD_NATIVE;
  g_tag_field_chosen = true;
  prefsPutUChar("tag_field", TAG_FIELD_NATIVE);
  logSD("Tag field: server has native tags, selected them");
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
