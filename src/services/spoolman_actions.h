#pragma once

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
void patchArchiveSpool();
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
bool patchSpoolTag(int spool_id, const char* uuid,
                   const char* const* field_values = nullptr);

// Unlink. `all` clears every tag field the spool is bound through; otherwise
// only `uid` is taken out of the list field that holds it, leaving the other
// UIDs of that spool alone.
void unlinkCardUid(int spool_id, const char* uid, bool all);
void patchInitialWeight(float initial_w);
void patchSpoolWeight(float spool_w);
void patchFilamentSpoolWeight(float spool_w);
void patchVendorSpoolWeight(float spool_w);
