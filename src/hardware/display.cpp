#include "display.h"

#include "app_config.h"
#include "pins.h"

#include <LovyanGFX.hpp>
#include <math.h>
#include <esp_heap_caps.h>
#include <esp_sleep.h>
#include <lvgl.h>

#include "ui/touch_feedback.h"

// Set to 1 to enable touch coordinate debug output on Serial.
#define TOUCH_DEBUG 0

// No TwoWire object for the touch bus. LovyanGFX owns it: the Touch_FT5x06
// config below carries the port, both pins and the frequency, and bus_shared is
// false. A second TwoWire(0) used to be created and begun here and then never
// read or written, which initialised I2C port 0 twice over the same pins.
static constexpr uint8_t BL_PWM_CHANNEL = 7;

// Write clock of the 8 bit panel bus. Left unset, LovyanGFX runs it at 16 MHz,
// which is 19 ms on the bus for one full 480x320 frame before a pixel has been
// rendered. The ST7796S datasheet asks for a write cycle of 66 ns (15 MHz) and
// 15 ns for each half of the pulse, so the default already sat on the limit
// and this is past it. 20 MHz is what nearly every published configuration of
// this board runs. A wrong pixel, a colour fringe or a shifted line, above all
// on a device that has warmed up, means going back down.
static constexpr uint32_t LCD_BUS_WRITE_HZ = 20000000;

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
      cfg.freq_write=LCD_BUS_WRITE_HZ;
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
// Lines LVGL renders and flushes in one go. It walks the object tree once per
// strip, so the stock 10 lines made a full frame 32 walks: measured while
// scrolling, a frame took 78 ms and over 60 of them were rendering, not the
// bus. 20 lines cut the time per drawn line by 30 %.
//
// The buffer lives in PSRAM, which measured within 4 % of internal RAM at this
// size and leaves the internal heap to WiFi and TLS. It is not larger because
// of the data cache: 32 kB, shared with the fonts read from flash. 19 kB fit,
// and an 80 line buffer (77 kB) rendered a quarter slower per line than this.
static constexpr uint32_t DRAW_BUF_LINES          = 20;
// Only for a device whose PSRAM does not answer, taken from the internal heap
// at boot, when there is plenty of it.
static constexpr uint32_t DRAW_BUF_FALLBACK_LINES = 10;
static char draw_buf_info[16] = "";

const char* displayDrawBufInfo() { return draw_buf_info; }

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

// Flush timing since the last displayFlushStatsTake(). Written by lvgl_flush()
// and read by the performance line in the log, both on the loop task.
static DisplayFlushStats flush_stats = {0, 0, 0};

DisplayFlushStats displayFlushStatsTake() {
  const DisplayFlushStats taken = flush_stats;
  flush_stats = {0, 0, 0};
  return taken;
}

static void lvgl_flush(lv_disp_drv_t *drv, const lv_area_t *area, lv_color_t *color_p) {
  // The gamma pass counts: it is part of what a flush costs.
  const uint32_t flush_start_us = micros();
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
  const uint32_t flush_us = micros() - flush_start_us;
  if (flush_us > flush_stats.max_us) flush_stats.max_us = flush_us;
  flush_stats.sum_us += flush_us;
  flush_stats.count++;
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
  uint32_t buf_lines = DRAW_BUF_LINES;
  const char* buf_where = "psram";
  lv_color_t* buf = (lv_color_t*)heap_caps_malloc(
      480 * buf_lines * sizeof(lv_color_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!buf) {
    Serial.println("Display: no PSRAM for the draw buffer, using internal RAM");
    buf_lines = DRAW_BUF_FALLBACK_LINES;
    buf_where = "int";
    buf = (lv_color_t*)heap_caps_malloc(
        480 * buf_lines * sizeof(lv_color_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  }
  if (!buf) {
    Serial.println("Display: no memory for the draw buffer");
    return false;
  }
  const uint32_t buf_px = 480 * buf_lines;
  snprintf(draw_buf_info, sizeof(draw_buf_info), "%s/%u", buf_where, (unsigned)buf_lines);
  lv_disp_draw_buf_init(&draw_buf, buf, NULL, buf_px);
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
  indev_drv.feedback_cb = touchFeedback;
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
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  ledcDetach(hw_pins::LCD_BACKLIGHT);
#else
  ledcDetachPin(hw_pins::LCD_BACKLIGHT);
#endif
  pinMode(hw_pins::LCD_BACKLIGHT, OUTPUT);
  digitalWrite(hw_pins::LCD_BACKLIGHT, LOW);
}

void displayBacklightOn(uint8_t brightness) {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  // Core 3 hands a pin to LEDC through its peripheral manager, and
  // LovyanGFX drives it by pin number. Its own init attaches it again.
  if (tft.light()) tft.light()->init(brightness);
#else
  ledcAttachPin(hw_pins::LCD_BACKLIGHT, BL_PWM_CHANNEL);
  displaySetBrightness(brightness);
#endif
}

void displayPrepareDeepSleep() {
  displaySetBrightness(0);
  esp_sleep_enable_ext0_wakeup((gpio_num_t)hw_pins::TOUCH_INT, 0);
}
