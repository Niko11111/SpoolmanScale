#include "display.h"

#include "pins.h"

#include <LovyanGFX.hpp>
#include <Wire.h>
#include <esp_sleep.h>
#include <lvgl.h>

// Set to 1 to enable touch coordinate debug output on Serial.
#define TOUCH_DEBUG 0

static TwoWire i2c_touch = TwoWire(0);
static void (*touch_activity_callback)() = nullptr;

class LGFX : public lgfx::LGFX_Device {
  lgfx::Panel_ST7796  _panel;
  lgfx::Bus_Parallel8 _bus;
  lgfx::Light_PWM     _light;
  lgfx::Touch_FT5x06  _touch;
public:
  LGFX(void) {
    { auto cfg = _bus.config();
      cfg.pin_wr=47; cfg.pin_rd=-1; cfg.pin_rs=0;
      cfg.pin_d0=9;  cfg.pin_d1=46; cfg.pin_d2=3;
      cfg.pin_d3=8;  cfg.pin_d4=18; cfg.pin_d5=17;
      cfg.pin_d6=16; cfg.pin_d7=15;
      _bus.config(cfg); _panel.setBus(&_bus); }
    { auto cfg = _panel.config();
      cfg.pin_cs=-1; cfg.pin_rst=4; cfg.pin_busy=-1;
      cfg.memory_width=320; cfg.memory_height=480;
      cfg.panel_width=320;  cfg.panel_height=480;
      cfg.invert=true; cfg.rgb_order=false;
      _panel.config(cfg); }
    { auto cfg = _light.config();
      cfg.pin_bl=hw_pins::LCD_BACKLIGHT; cfg.invert=false;
      cfg.freq=44100; cfg.pwm_channel=7;
      _light.config(cfg); _panel.setLight(&_light); }
    { auto cfg = _touch.config();
      cfg.x_min=0; cfg.x_max=319; cfg.y_min=0; cfg.y_max=479;
      cfg.pin_int=hw_pins::TOUCH_INT; cfg.bus_shared=false; cfg.offset_rotation=0;
      cfg.i2c_port=0; cfg.i2c_addr=0x38;
      cfg.pin_sda=hw_pins::TOUCH_SDA; cfg.pin_scl=hw_pins::TOUCH_SCL; cfg.freq=400000;
      _touch.config(cfg); _panel.setTouch(&_touch); }
    setPanel(&_panel);
  }
};

static LGFX tft;
static lv_disp_draw_buf_t draw_buf;
static lv_color_t disp_buf[480 * 10];

static void lvgl_flush(lv_disp_drv_t *drv, const lv_area_t *area, lv_color_t *color_p) {
  uint32_t w = area->x2 - area->x1 + 1;
  uint32_t h = area->y2 - area->y1 + 1;
  tft.startWrite();
  tft.setAddrWindow(area->x1, area->y1, w, h);
  tft.writePixels((lgfx::rgb565_t*)color_p, w * h);
  tft.endWrite();
  lv_disp_flush_ready(drv);
}

static void lvgl_touch(lv_indev_drv_t *drv, lv_indev_data_t *data) {
  uint16_t x, y;
  if (tft.getTouch(&x, &y)) {
    data->state = LV_INDEV_STATE_PR;
    data->point.x = x;
    data->point.y = y;
    if (touch_activity_callback) touch_activity_callback();
    #if TOUCH_DEBUG
    static unsigned long last_log = 0;
    if (millis() - last_log > 200) {
      Serial.printf("TOUCH x=%d y=%d\n", x, y);
      last_log = millis();
    }
    #endif
  } else {
    data->state = LV_INDEV_STATE_REL;
  }
}

bool displayHardwareBegin(void (*touch_activity_cb)()) {
  touch_activity_callback = touch_activity_cb;

  i2c_touch.begin(hw_pins::TOUCH_SDA, hw_pins::TOUCH_SCL, 400000);
  tft.init();
  tft.setRotation(1);
  tft.setBrightness(204);
  tft.fillScreen(TFT_BLACK);

  lv_init();
  lv_disp_draw_buf_init(&draw_buf, disp_buf, NULL, 480 * 10);
  static lv_disp_drv_t disp_drv;
  lv_disp_drv_init(&disp_drv);
  disp_drv.hor_res = 480;
  disp_drv.ver_res = 320;
  disp_drv.flush_cb = lvgl_flush;
  disp_drv.draw_buf = &draw_buf;
  lv_disp_drv_register(&disp_drv);

  static lv_indev_drv_t indev_drv;
  lv_indev_drv_init(&indev_drv);
  indev_drv.type = LV_INDEV_TYPE_POINTER;
  indev_drv.read_cb = lvgl_touch;
  lv_indev_drv_register(&indev_drv);

  return true;
}

void displaySetBrightness(uint8_t brightness) {
  tft.setBrightness(brightness);
}

void displayPrepareDeepSleep() {
  displaySetBrightness(0);
  esp_sleep_enable_ext0_wakeup((gpio_num_t)hw_pins::TOUCH_INT, 0);
}
