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
void showVendorList();
void showMaterialList(const char* vendor_name);
void showMaterialSubList(const char* vendor_name, const char* material_prefix);
void showFilteredSpoolList(const char* vendor_name, const char* material_prefix, const char* material_full);

void showCopyEntryPopup();
void closeCopyEntryPopup();
void showCopyIdInputPopup();
void fetchSpoolsForCopy(bool archived, const char* material_filter, bool is_bambu_tag = false);
void showCopySpoolList();
void showCopyConfirmPopup(int template_id, const char* template_name, float template_remaining, float template_initial, float template_spool_w);
void doCopySpoolCreate(int template_filament_id, float template_initial, float template_spool_w);

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
