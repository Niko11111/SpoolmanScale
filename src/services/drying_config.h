#pragma once

#include <stdint.h>

extern uint8_t g_dry_mode;
extern int g_dry_man_yellow;
extern int g_dry_man_red;
extern const char* DRY_MAT_NAMES[];
extern const int DRY_MAT_DEF_YELLOW[];
extern const int DRY_MAT_DEF_RED[];
extern const int DRY_MAT_COUNT;
extern int g_dry_mat_yellow[];
extern int g_dry_mat_red[];
extern bool g_dry_mat_sealed[];
extern float g_dry_mult_sealed;
