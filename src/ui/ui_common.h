#pragma once

#include <lvgl.h>

void addBackButton(lv_obj_t *parent, lv_event_cb_t cb);
void addCloseButton(lv_obj_t *parent);
void buildSubHeader(lv_obj_t *parent, const char *title,
                    lv_event_cb_t back_cb, const char *back_hint = nullptr);
lv_obj_t* buildOverlayScreen();
