#pragma once

#include <stdint.h>

// Returns the HTTP status, 200 on success. PATCH_WEIGHT_NO_TARGET when it
// never got as far as a request, and PATCH_WEIGHT_ASKING when the cap check
// below deferred to the popup and nothing was written at all. Most callers
// ignore the value; the AMS commit needs it, because it must not claim an
// assignment window is open when the write never happened.
//
// skip_cap_check is set by the popup that asked about the label weight, so
// the second attempt writes instead of asking again.
#define PATCH_WEIGHT_NO_TARGET  (-1)
#define PATCH_WEIGHT_ASKING     (-2)
int patchSpoolmanWeight(float remaining, bool skip_cap_check = false);
// True once the server has the spool archived; the tag question follows only then.
bool patchArchiveSpool();
// Links `uuid` to a spool, or unlinks it when `uuid` is empty.
//
// field_values is what the spool currently holds in each tag field, indexed by
// TagFieldId, or nullptr when the caller does not know. Entries may be null or
// empty. It decides two things: a list field is appended to rather than
// replaced, and a UID found in a field other than the selected one is written
// into the selected one and then cleared where it came from - so the choice of
// field actually takes effect instead of only applying to new spools.
//
// Returns false when nothing was written: the list was full, or the request
// failed. An unlink always reports true.
// Brings the archived spool on the pad back and records `remaining` in the
// same go. Reloads the spool afterwards, so the screen shows what the server
// actually stored rather than what was hoped for.
bool reactivateSpool(float remaining);

//
// `additional` marks a further tag for a spool that is already bound, which is
// the second chip on the other flange. It changes nothing on the sources that
// hold several by nature - the relation takes another row, the list field gets
// another entry - and it is what keeps FilaMan off slot one, where a plain
// write would replace the tag instead of adding to it. A source that can only
// hold one refuses instead of overwriting, and says so in the log.
// Whether the last link had to fall back to the default extra field because
// the selected source does not exist on this server, cleared by the asking.
//
// The scale keeps its tag source in NVS and tagFieldEffective() cannot check
// it against the server without reaching the network, so pointing a scale from
// a v0.27 Spoolman back at an older one leaves "native" selected with no
// endpoints behind it. The link still happens; this is how the screen gets to
// say why it went somewhere else.
bool patchSpoolTagTakeNativeMissing();

// Whether the last patchSpoolTag() or unlinkCardUid() had a request that could
// not reach the server, or found no WiFi at all. The screen names the
// connection then: a link that failed says so instead of a bare "not added",
// and an unlink that never arrived is not reported as done.
bool tagBindingFailedOnNetwork();

// `bambu_chip_uid`: `uuid` is the UID of a Bambu chip rather than its tray
// uuid, for a further chip linked before its tray uuid was read. Spoolman's
// own tag relation then stores it as format "bambu"; every other field takes
// the value as it is.
bool patchSpoolTag(int spool_id, const char* uuid,
                   const char* const* field_values = nullptr,
                   bool additional = false, bool bambu_chip_uid = false);

// Unlink. `all` clears every tag field the spool is bound through; otherwise
// only `uid` is taken out of the list field that holds it, leaving the other
// UIDs of that spool alone.
void unlinkCardUid(int spool_id, const char* uid, bool all);

// Takes the tag on the reader (g_tag) off spool_id, on every backend: Spoolman
// through unlinkCardUid(), FilaMan and BamBuddy through their one tag place.
// Reads the bindings the last lookup captured (sm_tag_values and co.), so
// spool_id has to be the spool the scale shows. Shared by More Info and the
// tag page. tagBindingFailedOnNetwork() says afterwards whether it arrived.
// Loop task only.
void unlinkTagOnReader(int spool_id, bool all);

// nfc_uid: the tags a scale wrote itself. FilaStation's convention, shared:
// a UID in the spool's extra field nfc_uid is a MIFARE tag one of the scales
// wrote, and either may write it again when the spool changes. Original tags
// are not in it and are left alone unless the user explicitly asks.
// Spoolman only; on the other backends these do nothing.
// `value` is the field as the spool record holds it (sp["extra"]["nfc_uid"]).
bool spoolNfcUidListed(const char* value, const uint8_t uid[4]);
// After a verified write. Creates the field when the server lacks it.
void spoolNfcUidAdd(int spool_id, const char* value, const uint8_t uid[4]);
// Part of an unlink: takes `uid` out of the list, or empties it (`all`).
// Fetches the spool: loop task only.
void spoolNfcUidForget(int spool_id, const char* uid, bool all);

// Appends the hardware uid of the tag on the reader to extra.rfid_tag, beside
// whatever binds the spool. `scanned` is the value this lookup was started
// with - the tray uuid for a Bambu tag - never the uid itself: which of the
// two identities goes on the wire is this function's business.
//
// Runs on every lookup that found a spool rather than on an explicit link. A
// Bambu spool is found by its tray uuid from either side, and each side has to
// contribute its own chip uid before a gate reader can resolve both, so the
// field fills itself over two placements instead of asking for anything.
//
// Reads and updates sm_hw_uid_value, which captureBindings() has just filled.
// Silent and free on a spool that already carries the uid, which is the normal
// case. Returns true only when something was written.
bool syncHwUidField(int spool_id, const char* scanned);
void patchInitialWeight(float initial_w);
void patchSpoolWeight(float spool_w);
void patchFilamentSpoolWeight(float spool_w);
void patchVendorSpoolWeight(float spool_w);
