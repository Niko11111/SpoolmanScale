#pragma once

#include <stddef.h>
#include <lvgl.h>

void isoToLocal(const char* iso, char* out, size_t len);
void isoToDe(const char* iso, char* out, size_t len);
void driedDisplayStr(const char* de_date, char* out, size_t len);
void applyDriedLabel(lv_obj_t* lbl_val, lv_obj_t* lbl_sym, const char* de_date);
