#pragma once
#include <lvgl.h>

// Line icons the symbol font lacks, drawn by tools/gen_icons.py. 8 bit alpha:
// an lv_img shows them in its img_recolor colour, see uiIconDisc() in
// ui_common.h.
extern const lv_img_dsc_t ICON_CUP;    // 20 px
extern const lv_img_dsc_t ICON_CODE;   // 20 px
extern const lv_img_dsc_t ICON_CHAT;   // 20 px
extern const lv_img_dsc_t ICON_CUBE;   // 20 px
extern const lv_img_dsc_t ICON_BOOK;   // 20 px
extern const lv_img_dsc_t ICON_QR;     // 36 px
extern const lv_img_dsc_t ICON_FLAME;  // 16 px

