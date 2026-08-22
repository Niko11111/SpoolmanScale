#pragma once

// ============================================================
//  AUTO AMS ASSIGNMENT POPUP
//
//  Asked once, right after the spool has been lifted off the pad, while a
//  measurement is parked and waiting to be reported. Answering yes reports
//  it with FilaMan's assignment window open, answering no reports it
//  plainly. Either way the weight is written; the question is only whether
//  a window is opened along with it.
// ============================================================

// Builds the overlay. Pure LVGL, no HTTP, safe to call from appLoop().
// already_saved picks the wording: the value is in FilaMan already, or a
// yes is what puts it there. Passed in rather than read back out of the
// module, so the text cannot depend on when the popup happens to look.
void showAmsAssignPopup(int spool_id, float netto_g, const char* spool_name,
                        bool already_saved);

bool isAmsAssignPopupOpen();

// Ticks the countdown and runs whatever the answer triggered. Called from
// appLoop() like the other deferred UI work, because the answer costs up to
// three HTTP requests and a button callback must never carry those.
void handleAmsAssignDeferredActions();
