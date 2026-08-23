#include "display.h"

#include "app_config.h"
#include "pins.h"

#include <LovyanGFX.hpp>
#include <math.h>
#include <esp_sleep.h>
#include <lvgl.h>

// Set to 1 to enable touch coordinate debug output on Serial.
#define TOUCH_DEBUG 0

// No TwoWire object for the touch bus. LovyanGFX owns it: the Touch_FT5x06
// config below carries the port, both pins and the frequency, and bus_shared is
// false. A second TwoWire(0) used to be created and begun here and then never
// read or written, which initialised I2C port 0 twice over the same pins.
static constexpr uint8_t BL_PWM_CHANNEL = 7;

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
      // invert stays false: GPIO45 drives the WT32-SC01 Plus backlight
      // active-high, so duty 255 is full output. Flipping this to true does
      // not brighten a dim panel, it blacks it out -- and it would also turn
      // the backlight fully ON in deep sleep, where displayPrepareDeepSleep()
      // asks for brightness 0.
      cfg.pin_bl=hw_pins::LCD_BACKLIGHT; cfg.invert=false;
      cfg.freq=44100; cfg.pwm_channel=BL_PWM_CHANNEL;
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

// RGB565 gamma lookup. Two small tables (5-bit R/B, 6-bit G) keep the
// per-pixel cost to two array reads and some shifting.
static uint8_t  ui_lut5[32];
static uint8_t  ui_lut6[64];
static uint16_t ui_gain = 100;      // 100 == identity, transform skipped

uint16_t displayGetUiGain() { return ui_gain; }

void displaySetUiGain(uint16_t gamma_x100) {
  if (gamma_x100 < 100) gamma_x100 = 100;
  if (gamma_x100 > 300) gamma_x100 = 300;
  ui_gain = gamma_x100;
  if (ui_gain > 100) {
    const float inv = 100.0f / (float)ui_gain;   // exponent 1/gamma
    for (int i = 0; i < 32; i++)
      ui_lut5[i] = (uint8_t)lroundf(powf((float)i / 31.0f, inv) * 31.0f);
    for (int i = 0; i < 64; i++)
      ui_lut6[i] = (uint8_t)lroundf(powf((float)i / 63.0f, inv) * 63.0f);
  }
  // Only invalidated areas get re-flushed, so force a full repaint. Guarded
  // because this is also called from loadPrefs(), before lv_init() has run.
  if (lv_disp_get_default()) lv_obj_invalidate(lv_scr_act());
}

static void lvgl_flush(lv_disp_drv_t *drv, const lv_area_t *area, lv_color_t *color_p) {
  uint32_t w = area->x2 - area->x1 + 1;
  uint32_t h = area->y2 - area->y1 + 1;
  if (ui_gain > 100) {
    const uint32_t n = w * h;
    for (uint32_t i = 0; i < n; i++) {
      uint16_t c = color_p[i].full;
      color_p[i].full = (uint16_t)((ui_lut5[(c >> 11) & 0x1F] << 11) |
                                   (ui_lut6[(c >>  5) & 0x3F] <<  5) |
                                   (ui_lut5[ c        & 0x1F]));
    }
  }
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

  tft.init();  // brings up the touch I2C bus as configured in LGFX::_touch
  tft.setRotation(1);
  // Full output until displayPowerInit() applies the user's saved level. This
  // used to be a hardcoded 204, which meant every device ran the panel at 80%
  // while the settings slider sat at its 255 default and reported full
  // brightness -- the panel looked dim "at maximum" and dragging the slider to
  // a value it already held fired no LV_EVENT_VALUE_CHANGED to correct it.
  tft.setBrightness(BRIGHT_NORMAL_DEFAULT);
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

// Duty 0 still leaves LEDC driving the pin, and the backlight is an
// unregulated low-side switch. Hold the pin low instead.
void displayBacklightOff() {
  displaySetBrightness(0);
  ledcDetachPin(hw_pins::LCD_BACKLIGHT);
  pinMode(hw_pins::LCD_BACKLIGHT, OUTPUT);
  digitalWrite(hw_pins::LCD_BACKLIGHT, LOW);
}

void displayBacklightOn(uint8_t brightness) {
  ledcAttachPin(hw_pins::LCD_BACKLIGHT, BL_PWM_CHANNEL);
  displaySetBrightness(brightness);
}

void displayPrepareDeepSleep() {
  displaySetBrightness(0);
  esp_sleep_enable_ext0_wakeup((gpio_num_t)hw_pins::TOUCH_INT, 0);
}
