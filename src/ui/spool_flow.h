#pragma once

#include <lvgl.h>

void fetchUnlinkedSpools();
void fetchAllSpoolsForLink(bool is_bambu, const char* material_filter, bool archived_only = false);
void closeLinkList();
void showLinkList();
void showLinkEntryPopup(bool is_bambu);
void closeLinkEntryPopup();
void showIdInputPopup(bool is_bambu, bool is_copy = false);
void closeIdInputPopup();
void linkIdLookupAndPatch(int entered_id, bool is_bambu);
// add_mode turns the popup from "already tagged, overwrite?" into "already has
// UIDs, add one?". In that mode existing_tag carries the card_uids list, which
// is shown as a count rather than verbatim.
void showWarnPopupA(int spool_id, const char* existing_tag, bool is_bambu,
                    const char* link_uuid, bool add_mode = false);
void showWarnPopupB(int spool_id, bool is_bambu);
void doLinkPatch(int spool_id, bool is_bambu);

// Binds a further tag to the spool the last link went to - the chip on the
// other flange, answered into the second tag popup.
//
// Runs the very same doLinkPatch() as the first tag, which is the whole point:
// the write, the conflict message, the reload and the tag write question all
// come along instead of being reimplemented beside them. Only two things are
// different, and both are held in this module because that is where they
// belong: the write is marked as an addition, so FilaMan aims at its second
// column instead of overwriting the first, and the second tag question itself
// is suppressed - otherwise answering it would ask it again, forever.
//
// `uid` is what the reader reported. Whether the spool is a Bambu one is read
// off g_tag, not passed in, so there is one source for it rather than two.
void linkAdditionalTag(int spool_id, const char* uid);

// A link made somewhere else resolved the tag on the reader - Spoolman's own
// web page, say. spoolmanRecheckTick() calls this on the hit; once the loop's
// re-read has found the spool, the follow-ups a link from the scale gets (the
// tag write, the second tag) are armed.
void spoolFlowExpectRemoteLink();
// The second tag question alone, for a link the scale's own web page made
// together with a write - the tag is already written, so only that follows.
void spoolFlowAskSecondTag(int spool_id);
// The "move the tag off spool N?" question, for uiModalWaiting().
bool isSpoolFlowTagMoveOpen();
void showVendorList();
void showMaterialList(const char* vendor_name);
void showMaterialSubList(const char* vendor_name, const char* material_prefix);
void showFilteredSpoolList(const char* vendor_name, const char* material_prefix, const char* material_full);

void showCopyEntryPopup();
void closeCopyEntryPopup();
void fetchSpoolsForCopy(bool archived, const char* material_filter, bool is_bambu_tag = false);
void showCopySpoolList();
void showCopyConfirmPopup(int template_spool_id, int template_filament_id, const char* template_name,
                          float template_remaining, float template_initial, float template_spool_w);
void doCopySpoolCreate(int template_spool_id, int template_filament_id,
                       float template_initial, float template_spool_w);

// Creating a spool from the tag itself, for when no template fits. BamBuddy
// only - see backendCanCreateFromTag().
void showNewFromTagPopup();
void closeNewTagPopup();
void doCreateSpoolFromTag();

void hideSpoolFlowOverlays();
void deleteSpoolFlowOverlays();
void handleSpoolFlowDeferredActions();
void setSpoolFlowIdInputOpen(bool open);
bool isSpoolFlowIdInputOpen();
bool isSpoolFlowLinkEntryOpen();

extern char link_tag_uid[24];
extern bool link_popup_dismissed;
extern unsigned long link_tag_first_seen_ms;
extern lv_obj_t *btn_copy;
