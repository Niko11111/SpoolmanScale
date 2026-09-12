#pragma once

#include <lvgl.h>

extern lv_obj_t *scr_web;

void buildWebScreen();
void showWebScreen();

// The numpad the web password is typed on. Hidden with every other overlay,
// freed on the way back to the main screen.
void webPinScreenHide();
void webPinScreenClose();
