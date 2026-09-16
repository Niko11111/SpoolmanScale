#pragma once

#include <stddef.h>
#include <lvgl.h>

void isoToLocal(const char* iso, char* out, size_t len);
void isoToDe(const char* iso, char* out, size_t len);
void driedDisplayStr(const char* de_date, char* out, size_t len);
void applyDriedLabel(lv_obj_t* lbl_val, lv_obj_t* lbl_sym, const char* de_date);

// Just the traffic light colour for a drying date, for a caller that wants to
// write the date itself. The material decides the thresholds in material
// mode, so it is passed in rather than taken from the spool on the pad.
uint32_t driedAlertColor(const char* de_date, const char* material);

// The level behind that colour: 0 green, 1 yellow, 2 red, -1 when the
// reminder is off or the date says nothing. For deciding whether to show a
// warning symbol - comparing the colour against a palette entry would only
// work as long as two unrelated tables happen to agree.
int driedAlertLevel(const char* de_date, const char* material);
