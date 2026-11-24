// The one way onto an NFC tag: the jobs the device, the web page and FilaMan
// park here, carried out from the loop by tagWriteTick(), and FilaMan's scan
// answered. The pages, the records and what is read back off a tag live in
// the files beside it (services/tag_write_internal.h).
#include "tag_write.h"
#include "hardware/sound.h"

#include <ArduinoJson.h>
#include <lvgl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "hardware/nfc.h"
#include "hardware/sd_logger.h"
#include "app/app_state.h"
#include "creality/creality_scan.h"
#include "creality/creality_write.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/filaman_api.h"
#include "services/mifare_formats.h"
#include "services/mifare_write.h"
#include "services/spoolman_actions.h"
#include "services/tag_link.h"
#include "services/tag_pending.h"
#include "services/tag_uid.h"
#include "services/tag_write_internal.h"

using namespace tagw;

// How long the link is given to settle before its one retry.
#define TAGWRITE_LINK_RETRY_MS  300

static bool      pending = false;
static int       pending_id = 0;
static TagFormat pending_fmt = TAG_FMT_ACE;
static bool      pending_link = false;
static char      pending_uid[26] = "";   // the job's tag, "" for whichever lies there
static char      state[12] = "idle";
static char      message[96] = "";
static uint8_t   result = TW_NONE;
static int       linked_spool = 0;

// Raised by a successful erase, taken once by the UI. A flag rather than a
// call into the screens, because this module belongs to the service layer and
// runs from the loop task - and because the web interface erases through the
// very same tick, so both ways out are covered by one signal instead of the
// popup carrying half of it.
static bool      erased_flag = false;
// The same answer as `message`, in parts, so a translated caller can build its
// own sentence - see TagWriteReport in the header.
static TagWriteReport report;

static bool      scan_pending = false;
static unsigned long scan_since = 0;
#define SCAN_WAIT_MS 30000

void tagScanRequest() { scan_pending = true; scan_since = millis(); }

const TagWriteReport* tagWriteReportData() { return &report; }

const char* tagWriteState()   { return state; }
const char* tagWriteMessage() { return message; }
uint8_t     tagWriteResultCode() { return result; }

int tagWriteTakeLinkedSpool() {
  const int id = linked_spool;
  linked_spool = 0;
  return id;
}

bool tagWriteTakeErased() {
  const bool was = erased_flag;
  erased_flag = false;
  return was;
}

// The tag the main poll is looking at, judged the same way refreshCache()
// judges it: a 7 byte UID prints as 20 characters, a 4 byte one as 11, an 8
// byte ISO 15693 one as 23 and is no NTAG. Reading
// the cached scan rather than selecting the tag again is the point - a select
// here would race the main poll, and the loser gets nothing back.
bool tagIsWritableNtag() {
  return tag_present && strlen(g_tag.uid_str) == TAG_UID_STR_LEN_NTAG;
}

static void finish(const char *st, const char *msg, uint8_t code) {
  // A write that fails and then still links reports "error" twice for the
  // same job; the job sounds once.
  const bool repeated = (strcmp(state, st) == 0);
  snprintf(state, sizeof(state), "%s", st);
  snprintf(message, sizeof(message), "%s", msg);
  result = code;
  report.code = code;
  logSDf("TagWrite: %s - %s", st, msg);
  // Every write and erase ends here, whoever asked for it: the device, the
  // web page or a FilaMan remote trigger.
  if (repeated) return;
  if (strcmp(st, "ok") == 0)         soundPlay(SND_WRITE_OK);
  else if (strcmp(st, "error") == 0) soundPlay(SND_WRITE_FAIL);
}

// Every job starts here, also one that does not wait for tagWriteTick(), so
// finish() tells it from the one before and the web page builds its sentence
// from this job's parts. Without it a FilaMan write after an earlier success
// found "ok" still standing and played no tone, and after a web erase the tag
// page called that write "Tag erased" (22.11.2026).
static void jobStart(int spool_id, TagFormat fmt) {
  memset(&report, 0, sizeof(report));
  report.code     = TW_BUSY;
  report.erase    = (fmt == TAG_FMT_ERASE);
  report.spool_id = spool_id;
  report.fmt      = (uint8_t)fmt;
  result = TW_BUSY;
  snprintf(state, sizeof(state), "pending");
}

bool tagWriteRequest(int spool_id, TagFormat fmt, bool link) {
  if (pending) return false;
  if (fmt != TAG_FMT_ERASE && spool_id <= 0) return false;
  pending_id   = spool_id;
  pending_fmt  = fmt;
  pending_link = link;
  pending_uid[0] = 0;
  pending     = true;
  jobStart(spool_id, fmt);
  if (fmt == TAG_FMT_ERASE)
    snprintf(message, sizeof(message), "Erasing the tag...");
  else
    snprintf(message, sizeof(message), "Writing spool %d...", spool_id);
  return true;
}

bool tagWriteRequestErase(const char* uid_expected) {
  if (!tagWriteRequest(0, TAG_FMT_ERASE, false)) return false;
  snprintf(pending_uid, sizeof(pending_uid), "%s", uid_expected ? uid_expected : "");
  return true;
}

bool tagWriteRequestFor(int spool_id, TagFormat fmt, const char* uid_expected) {
  if (!tagWriteRequest(spool_id, fmt, false)) return false;
  snprintf(pending_uid, sizeof(pending_uid), "%s", uid_expected ? uid_expected : "");
  return true;
}

// "04:A2:..:7F", the spelling g_tag.uid_str and the cache use.
static void uidToStr(const uint8_t *uid, uint8_t uid_len, char *out, size_t n) {
  int u = 0;
  out[0] = 0;
  for (int i = 0; i < uid_len && u < (int)n - 3; i++)
    u += snprintf(out + u, n - u, i ? ":%02X" : "%02X", uid[i]);
}

static char    write_err[80] = "";
static uint8_t write_code = TW_ERR_WRITE;
static char    remote_payload[320] = "";
static char    remote_proto[12] = "";
// What the web page says the remote write was for: the spool FilaMan named and
// the filament in its record, since there is no spool fetch on this path.
static int     remote_spool_id = 0;
static char    remote_name[48] = "";

void tagw::tagWriteFail(uint8_t code, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(write_err, sizeof(write_err), fmt, ap);
  va_end(ap);
  write_code = code;
}

// What the format is called where a person reads it: display, log and the
// web page's write report alike.
const char* tagFormatLabel(uint8_t fmt) {
  switch (fmt) {
    case TAG_FMT_ACE:       return "Anycubic ACE";
    case TAG_FMT_FILAMAN:   return "FilaMan";
    case TAG_FMT_ERASE:     return "erase";
    case TAG_FMT_CREALITY:  return "Creality CFS";
    default:                return "OpenSpool";
  }
}

// What the server sent is kept exactly as it sent it - spool_id included. An
// earlier version swapped that key for sm_id on the way through, on the theory
// that sm_id was the one a reader needs. It is not: sm_id is this firmware's
// own convention, FilaMan looks for spool_id, and a record with only sm_id
// reaches FilaMan as spool 0. The one thing added here is sm_id when it is
// missing, so the same tag also answers to an OpenSpool reader.
void tagRemotePayloadSet(const char *json, int spool_id) {
  remote_payload[0] = 0;
  remote_proto[0] = 0;
  remote_spool_id = spool_id;
  remote_name[0] = 0;
  if (!json || !json[0]) return;

  JsonDocument d;
  if (deserializeJson(d, json)) {
    logSD("RemoteLink: tag payload is not JSON, ignoring it");
    return;
  }
  if (d["sm_id"].isNull() && spool_id > 0) d["sm_id"] = spool_id;

  const size_t n = measureJson(d);
  // Turned away here rather than at write time, because that is what lets the
  // caller fall back to the record the scale builds for itself.
  if (n == 0 || n > NDEF_JSON_MAX || n >= sizeof(remote_payload)) {
    logSDf("RemoteLink: tag payload is %u bytes, too long for a tag",
           (unsigned)n);
    return;
  }
  serializeJson(d, remote_payload, sizeof(remote_payload));

  // Kept for the question on the screen. FilaMan writes the name lowercase;
  // shown to a user it should read the way the two projects spell themselves.
  const char *proto = d["protocol"] | "";
  snprintf(remote_proto, sizeof(remote_proto), "%s",
           strcmp(proto, "filaman") == 0 ? "FilaMan" : "OpenSpool");

  // Both protocols carry OpenSpool's fields; "spool" as the device path says
  // when the spool has no filament name.
  const char *brand = d["brand"] | "";
  const char *type  = d["type"] | "";
  snprintf(remote_name, sizeof(remote_name), "%s%s%s", brand,
           (brand[0] && type[0]) ? " " : "", type);
  if (!remote_name[0]) snprintf(remote_name, sizeof(remote_name), "spool");
}

const char* tagRemotePayloadProtocol() {
  return remote_proto[0] ? remote_proto : "OpenSpool";
}

bool tagRemotePayloadPending() { return remote_payload[0] != 0; }

// Runs from the deferred handler, never from an LVGL callback: this talks to
// the reader and takes as long as a write takes.
//
// Reports through the same state the web page polls. A remote write used to
// leave no trace there at all, so the tag page showed the result of whatever
// had been written before it.
bool tagWriteRemotePayload() {
  if (!remote_payload[0]) return false;
  jobStart(remote_spool_id, strcmp(remote_proto, "FilaMan") == 0 ? TAG_FMT_FILAMAN
                                                                 : TAG_FMT_OPENSPOOL);
  snprintf(report.name, sizeof(report.name), "%s", remote_name);
  write_err[0] = 0;
  write_code = TW_ERR_WRITE;

  uint8_t uid[NFC_UID_MAX], uid_len = 0;
  bool ok = false;
  if (!nfcReadPassiveTarget(uid, &uid_len, 600)) {
    finish("error", "No tag on the reader", TW_ERR_NO_TAG);
  } else if (uid_len != 7) {
    finish("error", "Not a writable NTAG, this tag can only be read",
           TW_ERR_NOT_NTAG);
  } else if (!writeNdefJson(remote_payload)) {
    finish("error", write_err[0] ? write_err
                                 : "Write failed - keep the tag still on the reader",
           write_code);
  } else {
    finish("ok", "Wrote the record the filament manager sent", TW_OK);
    // A whole record, read back: whatever a cut write left on it is gone.
    tagPendingDone(uid, uid_len);
    ok = true;
  }

  remote_payload[0] = 0;
  remote_proto[0] = 0;
  tagCacheMarkDirty();
  return ok;
}

// Bambu puts the finish in the material, "PETG Basic", while FilaMan keeps it
// in material_subgroup and matches on "PETG". Only a known finish word is
// dropped: cutting at the first space would turn "Support For PLA" into
// "Support", and would leave composites like PLA-CF alone only by luck.
static void bareMaterial(char *m) {
  static const char *FINISH[] = {
    "Basic", "Matte", "Silk", "Silk+", "Tough", "Aero", "Galaxy", "Marble",
    "Glow", "Sparkle", "Metal", "Wood", "Translucent", "Impact", "HF", "Plus"
  };
  for (int pass = 0; pass < 2; pass++) {
    char *sp = strrchr(m, ' ');
    if (!sp) return;
    bool hit = false;
    for (unsigned i = 0; i < sizeof(FINISH) / sizeof(FINISH[0]); i++)
      if (!strcasecmp(sp + 1, FINISH[i])) { hit = true; break; }
    if (!hit) return;
    *sp = 0;
  }
}

// FilaMan asks for a scan, the answer is whatever is on the reader. Nothing
// is sent for a blank or unreadable tag: the request expires instead, which
// the web UI reports as a timeout rather than as bad data.
static void scanTick() {
  if (!scan_pending) return;
  if (millis() - scan_since > SCAN_WAIT_MS) {
    scan_pending = false;
    logSD("Tag scan: no readable tag, request expired");
    return;
  }

  char material[17] = "", brand[33] = "", color[8] = "";
  unsigned tlo = 0, thi = 0;
  int sm = 0;

  const TagInfo *ti = tagCachedInfo();
  if (tagCachedHasRecord()) {
    snprintf(material, sizeof(material), "%s", ti->material);
    snprintf(brand, sizeof(brand), "%s", ti->brand);
    snprintf(color, sizeof(color), "%02X%02X%02X", ti->r, ti->g, ti->b);
    tlo = ti->et_lo; thi = ti->et_hi;
    if (ti->sku[0] == 'S' && ti->sku[1] == 'M') sm = atoi(ti->sku + 2);
  } else if (tag_present && g_tag.material[0]) {
    // A Bambu tag. The main flow has already decoded it, and it is the one
    // kind of tag the page itself cannot read.
    snprintf(material, sizeof(material), "%s", g_tag.material);
    bareMaterial(material);
    // Bambu stores no vendor string, but a tag that authenticates with the
    // Bambu keys can only be theirs.
    snprintf(brand, sizeof(brand), "%s",
             g_tag.vendor[0] ? g_tag.vendor : "Bambu Lab");
    // Empty for a clear filament, which names no hue: FilaMan then matches on
    // material and brand alone instead of finding a black filament for it.
    const char *c = g_tag.color_hex;
    if (*c == '#') c++;
    snprintf(color, sizeof(color), "%s", c);
    tlo = (unsigned)g_tag.temp_min; thi = (unsigned)g_tag.temp_max;
    if (sm_found && sm_id > 0) sm = sm_id;
  } else {
    return;
  }

  char json[288];
  snprintf(json, sizeof(json),
    "{\"protocol\":\"openspool\",\"version\":\"1.0\",\"type\":\"%s\","
    "\"color_hex\":\"%s\",\"brand\":\"%s\","
    "\"min_temp\":\"%u\",\"max_temp\":\"%u\"",
    material, color, brand, tlo, thi);
  size_t n = strnlen(json, sizeof(json));
  if (sm > 0) n = appendf(json, sizeof(json), n, ",\"sm_id\":%d", sm);
  appendf(json, sizeof(json), n, "}");

  scan_pending = false;
  filamanSendTagData(backendBaseUrl(), filamanDeviceToken(), json);
}

// Selects the tag and says whether it can be written at all. Both write paths
// start here, so the two refusals read the same wherever they came from.
static bool selectWritableTag(uint8_t *uid, uint8_t *uid_len) {
  *uid_len = 0;
  if (!nfcReadPassiveTarget(uid, uid_len, 600)) {
    finish("error", "No tag on the reader", TW_ERR_NO_TAG);
    return false;
  }
  if (*uid_len != 7) {
    finish("error", "Not a writable NTAG, this tag can only be read",
           TW_ERR_NOT_NTAG);
    return false;
  }
  ntagPagesSelect(uid, *uid_len);
  return true;
}

// Builds the record from the spool and puts it on the already selected tag.
// On failure it reports the reason itself and returns false; on success it
// leaves the filament name in name[] and lets the caller word the message,
// because only the caller knows whether a link is going to be appended to it.
static bool writeSpoolRecord(int spool_id, TagFormat fmt,
                             char *name, size_t name_len) {
  name[0] = 0;
  write_err[0] = 0;
  write_code = TW_ERR_WRITE;

  // Not querySpoolmanById(): that also repaints the main screen and would
  // change which spool the scale believes is loaded.
  JsonDocument doc;
  int code = backendGetSpoolJson(backendBaseUrl(), spool_id, doc);
  if (code != 200 || doc.isNull()) {
    char m[96];
    snprintf(m, sizeof(m), "Spool %d not found on %s (HTTP %d)",
             spool_id, backendName(), code);
    finish("error", m, TW_ERR_BACKEND);
    return false;
  }
  JsonObjectConst sp = doc.as<JsonObjectConst>();

  bool ok;
  {
    AceFields f;
    buildAce(sp, &f);
    tagPendingArm(spool_id, (uint8_t)fmt);
    ok = TAG_FMT_IS_NDEF(fmt) ? writeOpenSpool(&f, spool_id, fmt) : writeAce(&f);
    if (ok) tagPendingDone(ntagPagesUid(), ntagPagesUidLen());
    tagPendingDisarm();
  }

  tagCacheMarkDirty();   // the tag changed under a UID that did not

  if (!ok) {
    finish("error", write_err[0] ? write_err
                                 : "Write failed - keep the tag still on the reader",
           write_code);
    return false;
  }
  const char *n = sp["filament"]["name"] | "spool";
  snprintf(name, name_len, "%s", n[0] ? n : "spool");
  return true;
}

// A MIFARE format (services/mifare_formats.h) onto the 4 byte tag on the
// reader. Its own path: selectWritableTag() turns every 4 byte UID away, and
// none of the NTAG page code applies. Reports through finish() either way.
static bool         s_mf_has_expect = false;
static uint8_t      s_mf_expect[4];
static MifareWaitFn s_mf_wait = nullptr;
static bool         s_mf_overwrite = false;

void tagWriteMifareTarget(const char* uid_str, void (*wait)(int phase, int seconds_left), bool overwrite) {
  unsigned b[4];
  s_mf_has_expect = uid_str && sscanf(uid_str, "%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3]) == 4;
  if (s_mf_has_expect) for (int i = 0; i < 4; i++) s_mf_expect[i] = (uint8_t)b[i];
  s_mf_wait = wait;
  s_mf_overwrite = overwrite;
}

bool tagFormatIsMifare(uint8_t fmt) { return mifareFormatFor(fmt) != nullptr; }

bool tagCrealityCheck(int spool_id, const char* uid_str, bool* own, bool* differs,
                      bool* serial_only) {
  *own = false;
  *differs = false;
  if (serial_only) *serial_only = false;
  unsigned b[4];
  if (!uid_str || sscanf(uid_str, "%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2], &b[3]) != 4) return false;
  const uint8_t uid[4] = {(uint8_t)b[0], (uint8_t)b[1], (uint8_t)b[2], (uint8_t)b[3]};
  char on_tag[41];
  if (!crealityLastRecord(uid, on_tag)) return false;
  JsonDocument doc;
  if (backendGetSpoolJson(backendBaseUrl(), spool_id, doc) != 200 || doc.isNull()) return false;
  JsonObjectConst sp = doc.as<JsonObjectConst>();
  char want[41];
  if (!crealityRecordForSpool(sp, spool_id, want)) return false;
  const char* listed = sp["extra"]["nfc_uid"] | (const char*)nullptr;
  *own = spoolNfcUidListed(listed, uid);
  // Everything but the date: vendor, batch, filament, colour, length and
  // serial. The serial is the spool id on a tag a scale wrote; on an original
  // Creality tag it is Creality's own number, 000001 on every spool seen so
  // far - and CFSync takes the serial for the Spoolman spool id, so it linked
  // spool 5's slot to spool 1 on 14.10.2026. serial_only tells that case
  // apart: the filament agrees, only the id is missing.
  *differs = memcmp(on_tag + 5, want + 5, 29) != 0;
  const bool filament_same = memcmp(on_tag + 5, want + 5, 23) == 0;
  if (serial_only) *serial_only = *differs && filament_same && !*own;
  logSDf("CFS check: %s spool %d, %s tag (nfc_uid '%s'), tag %.29s, Spoolman %.29s%s", uid_str,
         spool_id, *own ? "own" : "foreign", listed ? listed : "<none>",
         on_tag + 5, want + 5, *differs ? " - differs" : "");
  return true;
}

// What mifareWrite() came to, for the web page and the device. True on OK.
static bool mifareResultReported(MifareWriteResult r, uint8_t fmt) {
  char m[96];
  switch (r) {
    case MIFARE_WRITE_OK:
      return true;
    case MIFARE_WRITE_NO_TAG:
      finish("error", "No MIFARE tag on the reader", TW_ERR_NO_TAG);
      return false;
    case MIFARE_WRITE_IS_FORMAT:
      snprintf(m, sizeof(m), "Already a %s tag, left as it is", tagFormatLabel(fmt));
      finish("error", m, TW_ERR_NOT_BLANK);
      return false;
    case MIFARE_WRITE_NOT_BLANK:
      finish("error", "Not a blank tag, left as it is", TW_ERR_NOT_BLANK);
      return false;
    case MIFARE_WRITE_VERIFY_FAILED:
      finish("error", "Written, but it did not read back - try again", TW_ERR_WRITE);
      return false;
    default:
      finish("error", "Write failed - keep the tag still on the reader", TW_ERR_WRITE);
      return false;
  }
}

static bool writeMifareJob(int spool_id, uint8_t fmt, char *name, size_t name_len) {
  name[0] = 0;
  const MifareFormat* mf = mifareFormatFor(fmt);
  JsonDocument doc;
  int code = backendGetSpoolJson(backendBaseUrl(), spool_id, doc);
  if (code != 200 || doc.isNull()) {
    char m[96];
    snprintf(m, sizeof(m), "Spool %d not found on %s (HTTP %d)",
             spool_id, backendName(), code);
    finish("error", m, TW_ERR_BACKEND);
    return false;
  }
  JsonObjectConst sp = doc.as<JsonObjectConst>();
  MifareWriteJob job;
  char text[MIFARE_RECORD_TEXT_BYTES];
  if (!mf || !mf->build(sp, spool_id, &job, text, sizeof(text))) {
    finish("error", "Could not build a record for this spool", TW_ERR_WRITE);
    return false;
  }
  logSDf("%s write: spool %d as %s", job.label, spool_id, text);
  uint8_t uid[4];
  tagPendingArm(spool_id, fmt);
  const MifareWriteResult r = mifareWrite(job, uid, s_mf_has_expect ? s_mf_expect : nullptr,
                                          s_mf_wait, s_mf_overwrite);
  if (r == MIFARE_WRITE_OK) tagPendingDone(uid, 4);
  tagPendingDisarm();
  s_mf_has_expect = false;
  s_mf_wait = nullptr;
  s_mf_overwrite = false;
  tagCacheMarkDirty();
  if (!mifareResultReported(r, fmt)) return false;
  mf->written(uid, text);
  // Ours from now on: either scale may write it again when the spool changes.
  spoolNfcUidAdd(spool_id, sp["extra"]["nfc_uid"] | (const char*)nullptr, uid);
  const char *n = sp["filament"]["name"] | "";
  snprintf(name, name_len, "%s", n[0] ? n : "spool");
  return true;
}

// The whole write for a caller that has no parking slot to go through - the
// device screen and the FilaMan trigger both land here when no record came
// with the request.
bool tagWriteSpoolNow(int spool_id, TagFormat fmt) {
  if (spool_id <= 0) return false;
  jobStart(spool_id, fmt);
  char name[48];
  if (mifareFormatFor(fmt)) {
    if (!writeMifareJob(spool_id, fmt, name, sizeof(name))) return false;
  } else {
    uint8_t uid[NFC_UID_MAX], uid_len = 0;
    if (!selectWritableTag(uid, &uid_len)) return false;
    if (!writeSpoolRecord(spool_id, fmt, name, sizeof(name))) return false;
  }

  char m[128];
  snprintf(m, sizeof(m), "Wrote spool %d (%s) as %s", spool_id, name,
           tagFormatLabel(fmt));
  snprintf(report.name, sizeof(report.name), "%s", name);
  finish("ok", m, TW_OK);
  return true;
}

// An erase asked for a 4 byte tag: sector 1 emptied through mifareErase(),
// keys left as they are. The one MIFARE format the scale writes is CFS, so
// that is the sector and key it empties.
static void eraseMifareTag() {
  const MifareFormat* mf = mifareFormatFor(TAG_FMT_CREALITY);
  MifareWriteJob job;
  uint8_t uid[4];
  MifareWriteResult r = MIFARE_WRITE_FAILED;
  if (mf && mf->erase_job) {
    mf->erase_job(&job);
    tagWriteMifareTarget(pending_uid, s_mf_wait, true);   // this tag and no other
    r = mifareErase(job, uid, s_mf_has_expect ? s_mf_expect : nullptr, s_mf_wait);
  }
  s_mf_has_expect = false;
  s_mf_wait = nullptr;
  s_mf_overwrite = false;
  tagCacheMarkDirty();
  report.erase = true;
  if (r == MIFARE_WRITE_OK) {
    erased_flag = true;
    tagPendingDone(uid, 4);
    finish("ok", "Tag erased", TW_OK);
  } else if (r == MIFARE_WRITE_NO_TAG) {
    finish("error", "No MIFARE tag on the reader - nothing erased", TW_ERR_NO_TAG);
  } else if (r == MIFARE_WRITE_NOT_BLANK) {
    finish("error", "This tag cannot be erased here, left as it is", TW_ERR_NOT_BLANK);
  } else {
    finish("error", "Erase failed - keep the tag still", TW_ERR_WRITE);
  }
}

void tagWriteTick() {
  refreshCache();
  scanTick();
  if (!pending) return;
  pending = false;
  // Again here: a remote or direct write that ran since the request was
  // parked has ended on a state of its own, and this job must not end silent
  // on the same one.
  jobStart(pending_id, pending_fmt);

  if (pending_fmt == TAG_FMT_ERASE && strlen(pending_uid) == TAG_UID_STR_LEN_MIFARE) {
    eraseMifareTag();
    return;
  }

  if (mifareFormatFor(pending_fmt)) {
    // Follows a link that already happened, so there is nothing to link here.
    char cname[48];
    if (writeMifareJob(pending_id, pending_fmt, cname, sizeof(cname))) {
      snprintf(report.name, sizeof(report.name), "%s", cname);
      char m[128];
      snprintf(m, sizeof(m), "Wrote spool %d (%s) as %s", pending_id, cname, tagFormatLabel(pending_fmt));
      finish("ok", m, TW_OK);
    }
    return;
  }

  uint8_t uid[NFC_UID_MAX], uid_len = 0;
  if (!selectWritableTag(uid, &uid_len)) return;

  if (pending_fmt == TAG_FMT_ERASE) {
    char here[26];
    uidToStr(uid, uid_len, here, sizeof(here));
    if (pending_uid[0] && strcmp(pending_uid, here) != 0) {
      logSDf("TagWrite: erase was for %s, %s lies on the reader - not erased", pending_uid, here);
      finish("error", "A different tag is on the reader - nothing erased", TW_ERR_OTHER_TAG);
      return;
    }
    const bool erased = eraseTag();
    tagCacheMarkDirty();
    report.erase = true;
    // The screen is still showing the record that was just wiped, whoever
    // asked for the erase. Only on success: a failed erase left the tag as it
    // was, and what is on screen is then still the truth.
    if (erased) erased_flag = true;
    // Nothing half written is left on it either.
    if (erased) tagPendingDone(uid, uid_len);
    finish(erased ? "ok" : "error",
           erased ? "Tag erased" : "Erase failed - keep the tag still",
           erased ? TW_OK : TW_ERR_WRITE);
    return;
  }

  if (pending_uid[0]) {
    char here[26];
    uidToStr(uid, uid_len, here, sizeof(here));
    if (strcmp(pending_uid, here) != 0) {
      logSDf("TagWrite: write was for %s, %s lies on the reader - not written", pending_uid, here);
      finish("error", "A different tag is on the reader - nothing written", TW_ERR_OTHER_TAG_WRITE);
      return;
    }
  }

  char name[48];
  const bool wrote = writeSpoolRecord(pending_id, pending_fmt, name, sizeof(name));
  snprintf(report.name, sizeof(report.name), "%s", name);
  // writeSpoolRecord() has already reported why, and finish() below would
  // overwrite the code, so keep it.
  const uint8_t code = wrote ? TW_OK : result;

  // A tag too small to write is no reason to leave the spool unbound. But a
  // spool the backend could not hand over is not one to bind a tag to either,
  // so that failure keeps the floor to itself.
  if (!wrote && (!pending_link || code == TW_ERR_BACKEND)) return;

  // Erase returned above, so there is no format to branch on here any more.
  char m[160];
  if (wrote) {
    snprintf(m, sizeof(m), "Wrote spool %d (%s) as %s", pending_id, name,
             tagFormatLabel(pending_fmt));
  } else {
    snprintf(m, sizeof(m), "%s", message);
  }
  size_t n = strnlen(m, sizeof(m));

  if (pending_link) {
    char uid_str[26];
    uidToStr(uid, uid_len, uid_str, sizeof(uid_str));
    char note[48] = "";
    // Spoolman links the way the device's link flow does. The plain field
    // write below has no key for Spoolman's own tag relation, the source every
    // 0.27 server is moved to, so there it failed every time with -1.
    const bool via_link_flow = backendMode() == BACKEND_SPOOLMAN;
    int code2 = via_link_flow
      ? tagLinkAfterWrite(pending_id, uid_str)
      : backendLinkSpoolTag(backendBaseUrl(), pending_id, uid_str, note, sizeof(note));
    // One retry. The failure seen in the field was HTTP -1, a connection error,
    // and it left a written tag on a spool that names no tag - the exact state
    // this step exists to prevent. A second attempt costs 300 ms and only ever
    // runs after something already went wrong. Not after a 409: the tag
    // belongs to another spool, and asking again cannot change that.
    if (!backendWriteOk(code2) && code2 != 409) {
      logSDf("TagWrite: link failed (HTTP %d), retrying once", code2);
      // Paused with the panel kept alive: this runs from appLoop(), and a
      // plain delay() here froze the touch for its length on top of the
      // request that had just failed.
      const unsigned long t0 = millis();
      while (millis() - t0 < TAGWRITE_LINK_RETRY_MS) {
        lv_timer_handler();
        delay(10);
      }
      code2 = via_link_flow
        ? tagLinkAfterWrite(pending_id, uid_str)
        : backendLinkSpoolTag(backendBaseUrl(), pending_id, uid_str, note, sizeof(note));
    }
    // appendf, not m + n: a long filament name makes snprintf report a length
    // it never wrote, and then m + n points past the buffer while
    // sizeof(m) - n underflows. Same reason the rest of this file moved off it.
    report.link_http = code2;
    snprintf(report.link_note, sizeof(report.link_note), "%s", note);
    if (backendWriteOk(code2)) {
      // The tag on the reader now points at this spool, so the screen should
      // say so rather than keep whatever it showed before. Handed over as an
      // id: the lookup repaints the main screen and belongs on the UI side.
      linked_spool = pending_id;
      report.link = TAG_LINK_OK;
      if (note[0]) appendf(m, sizeof(m), n, ", linked (%s)", note);
      else         appendf(m, sizeof(m), n, ", linked to the spool");
    } else {
      report.link = TAG_LINK_FAIL;
      appendf(m, sizeof(m), n, ", but linking failed (HTTP %d)", code2);
    }
  }
  finish(wrote ? "ok" : "error", m, code);
}
