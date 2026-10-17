#include "ui/label_buttons.h"

#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "lang.h"
#include "services/label_fetch.h"
#include "ui/theme.h"

void addLabelPrintButtons(lv_obj_t* hdr, lv_obj_t* title) {
  const bool two = labelServiceConfigured();
  if (two) {
    lv_obj_set_width(title, 120);
    lv_label_set_long_mode(title, LV_LABEL_LONG_DOT);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 14, 0);
  }
  for (int i = 0; i < (two ? 2 : 1); i++) {
    const bool filament = two && i == 1;
    lv_obj_t* btn = lv_btn_create(hdr);
    lv_obj_set_size(btn, two ? 130 : 116, 34);
    // two: 138..268 and 274..404, the X starts at 410
    lv_obj_set_pos(btn, two ? 138 + i * 136 : 282, 9);
    lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW), 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(UI_COL_ROW_PRESS_FILL), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(btn, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_border_width(btn, 1, 0);
    lv_obj_set_style_radius(btn, UI_RADIUS_BTN, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    if (filament) {
      lv_obj_add_event_cb(btn, [](lv_event_t* e) {
        logSD("BTN: MoreInfo -> print filament label");
        print_filament_label_pending = true;
      }, LV_EVENT_CLICKED, NULL);
    } else {
      lv_obj_add_event_cb(btn, [](lv_event_t* e) {
        logSD("BTN: MoreInfo -> print label");
        print_spool_label_pending = true;
      }, LV_EVENT_CLICKED, NULL);
    }
    lv_obj_t* lbl = lv_label_create(btn);
    lv_label_set_text(lbl, T(filament ? STR_PRN_LABEL_FILAMENT
                             : two ? STR_PRN_LABEL_SPOOL : STR_PRN_LABEL_PRINT));
    lv_obj_set_style_text_color(lbl, lv_color_hex(UI_COL_ACCENT), 0);
    lv_obj_set_style_text_font(lbl, UI_FONT_SMALL, 0);
    lv_obj_center(lbl);
  }
}
