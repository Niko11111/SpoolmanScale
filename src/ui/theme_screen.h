#pragma once

#include <lvgl.h>

extern lv_obj_t *scr_theme;

void buildThemeScreen();
void showThemeScreen();

// True while the theme screen is the visible overlay. The web editor uses this
// to decide whether a live palette change should repaint the device now.
bool themeScreenVisible();

// Rebuilds the theme screen in place if it is showing, so a colour dragged in
// the browser is reflected on the panel immediately. Safe to call from the UI
// loop only.
void themeScreenRepaint();
