#pragma once

// skip_cap_check is set by the popup that asked about the label weight, so
// the second attempt writes instead of asking again.
void patchSpoolmanWeight(float remaining, bool skip_cap_check = false);
void patchArchiveSpool();
// current_card_uids is the target spool's list, or nullptr when the caller
// does not know it. Only a non-empty list sends the write to card_uids;
// everything else keeps going to extra.tag exactly as before.
// Returns false only when the write was refused because the list is full.
bool patchSpoolTag(int spool_id, const char* uuid,
                   const char* current_card_uids = nullptr);

// Unlink for a spool whose UIDs live in card_uids. `all` clears the whole
// binding, otherwise only `uid` is taken out of the list.
void unlinkCardUid(int spool_id, const char* uid, bool all);
void patchInitialWeight(float initial_w);
void patchSpoolWeight(float spool_w);
void patchFilamentSpoolWeight(float spool_w);
void patchVendorSpoolWeight(float spool_w);
