#include "sound.h"

#include <Arduino.h>
#include <driver/i2s_std.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <math.h>

#include "hardware/pins.h"
#include "hardware/sd_logger.h"
#include "services/prefs_store.h"

bool    g_sound_on   = false;
bool    g_snd_nfc    = true;
bool    g_snd_write  = true;
bool    g_snd_weight = true;
uint8_t g_snd_volume = SND_VOL_MED;

void soundLoadPrefs() {
  g_sound_on   = prefsGetBool("snd_on", false);
  g_snd_nfc    = prefsGetBool("snd_nfc", true);
  g_snd_write  = prefsGetBool("snd_write", true);
  g_snd_weight = prefsGetBool("snd_weight", true);
  g_snd_volume = prefsGetUChar("snd_vol", SND_VOL_MED);
  if (g_snd_volume >= SND_VOL_COUNT) g_snd_volume = SND_VOL_MED;
}

// 16 kHz is plenty for beeps of at most 2.5 kHz and keeps the DMA buffers small.
static const uint32_t SAMPLE_RATE = 16000;
static const int      CHUNK       = 240;   // samples per write, 15 ms
// A tone that starts or stops at full amplitude clicks on the speaker.
static const uint16_t FADE_MS     = 3;
static const uint16_t GAP_MS      = 40;    // between two tones queued together
// The DMA still holds the last buffers when the tone is written; this much
// silence lets them play out before the clock stops and cuts the tail off.
static const uint16_t DRAIN_MS    = 60;
static const uint8_t  QUEUE_LEN   = 4;
static const uint32_t TASK_STACK  = 3072;
static const TickType_t WRITE_TIMEOUT = pdMS_TO_TICKS(200);

// Peak amplitude per volume step. Each level is twice the one below it,
// so the four settings split full scale into even 6 dB steps.
static const int16_t AMPLITUDE[SND_VOL_COUNT] = {
  (int16_t)(INT16_MAX / 8),
  (int16_t)(INT16_MAX / 4),
  (int16_t)(INT16_MAX / 2),
  (int16_t)INT16_MAX,
};
// Full scale of a 16-bit sample. A sine that rounds past this is clipped.
static const float SAMPLE_MAX = (float)INT16_MAX;

struct Note { uint16_t hz; uint16_t ms; };   // hz 0 = a pause
struct Tone { const Note *notes; uint8_t count; };

static const Note N_READ[]   = { {2000, 60} };
static const Note N_W_OK[]   = { {1500, 60}, {0, 30}, {2200, 90} };
static const Note N_FAIL[]   = { {500, 120}, {0, 40}, {350, 200} };
// Three equal taps at one pitch: auto weight saved.
static const Note N_WGT_OK[] = { {1800, 50}, {0, 40}, {1800, 50}, {0, 40}, {1800, 50} };
// Three rising notes: the weight button saved.
static const Note N_WGT_MAN[] = { {1300, 50}, {0, 25}, {1700, 50}, {0, 25}, {2200, 80} };
// Short and high, then long and low: the tag is not in the inventory.
static const Note N_UNKNOWN[] = { {2400, 45}, {0, 35}, {320, 220} };
static const Note N_TEST[]   = { {2000, 80} };

static Tone toneFor(SoundEvent e) {
  switch (e) {
    case SND_NFC_READ:      return { N_READ,    1 };
    case SND_TAG_UNKNOWN:   return { N_UNKNOWN, 3 };
    case SND_WRITE_OK:      return { N_W_OK,    3 };
    case SND_WRITE_FAIL:    return { N_FAIL,    3 };
    case SND_WEIGHT_OK:     return { N_WGT_OK,  5 };
    case SND_WEIGHT_MANUAL: return { N_WGT_MAN, 5 };
    case SND_WEIGHT_FAIL:   return { N_FAIL,    3 };
    default:                return { N_TEST,    1 };
  }
}

static QueueHandle_t     s_queue = nullptr;
static i2s_chan_handle_t s_tx    = nullptr;
static bool              s_failed = false;   // I2S would not start; stop trying

static bool i2sStart() {
  if (s_tx) return i2s_channel_enable(s_tx) == ESP_OK;
  i2s_chan_config_t chan = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_AUTO, I2S_ROLE_MASTER);
  chan.dma_desc_num  = 3;
  chan.dma_frame_num = CHUNK;
  chan.auto_clear    = true;   // an underrun plays silence, not the last buffer again
  if (i2s_new_channel(&chan, &s_tx, nullptr) != ESP_OK) { s_tx = nullptr; return false; }

  i2s_std_config_t std = {
    .clk_cfg  = I2S_STD_CLK_DEFAULT_CONFIG(SAMPLE_RATE),
    .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO),
    .gpio_cfg = {
      .mclk = I2S_GPIO_UNUSED,
      .bclk = (gpio_num_t)hw_pins::SPK_BCLK,
      .ws   = (gpio_num_t)hw_pins::SPK_LRCK,
      .dout = (gpio_num_t)hw_pins::SPK_DOUT,
      .din  = I2S_GPIO_UNUSED,
      .invert_flags = { .mclk_inv = false, .bclk_inv = false, .ws_inv = false },
    },
  };
  // The amplifier listens to one slot, which one depends on how its CTRL pin
  // is strapped. Sending the sample on both makes that question go away.
  std.slot_cfg.slot_mask = I2S_STD_SLOT_BOTH;
  if (i2s_channel_init_std_mode(s_tx, &std) != ESP_OK) {
    i2s_del_channel(s_tx);
    s_tx = nullptr;
    return false;
  }
  return i2s_channel_enable(s_tx) == ESP_OK;
}

static int16_t toneSample(float wave, int16_t amp, float env) {
  float s = wave * (float)amp * env;
  if (s > SAMPLE_MAX) s = SAMPLE_MAX;
  if (s < -SAMPLE_MAX) s = -SAMPLE_MAX;
  return (int16_t)s;
}

static void writeNote(const Note &n, int16_t amp) {
  int16_t buf[CHUNK];
  const uint32_t total = (uint32_t)SAMPLE_RATE * n.ms / 1000;
  const uint32_t ramp = SAMPLE_RATE * FADE_MS / 1000;
  const float step = n.hz ? 2.0f * (float)M_PI * n.hz / SAMPLE_RATE : 0.0f;
  float phase = 0.0f;
  for (uint32_t done = 0; done < total; ) {
    const int count = (total - done) < (uint32_t)CHUNK ? (int)(total - done) : CHUNK;
    for (int i = 0; i < count; i++) {
      const uint32_t k = done + i;
      float env = 1.0f;
      if (k < ramp) env = (float)k / ramp;
      else if (total - k < ramp) env = (float)(total - k) / ramp;
      buf[i] = n.hz ? toneSample(sinf(phase), amp, env) : 0;
      phase += step;
      if (phase > 2.0f * (float)M_PI) phase -= 2.0f * (float)M_PI;
    }
    size_t written = 0;
    i2s_channel_write(s_tx, buf, count * sizeof(int16_t), &written, WRITE_TIMEOUT);
    done += count;
  }
}

static void soundTask(void *) {
  uint8_t ev;
  for (;;) {
    if (xQueueReceive(s_queue, &ev, portMAX_DELAY) != pdTRUE) continue;
    if (s_failed) continue;
    if (!i2sStart()) {
      s_failed = true;
      logSD("Sound: I2S could not be started, sound stays silent until reboot");
      continue;
    }
    const int16_t amp = AMPLITUDE[g_snd_volume < SND_VOL_COUNT ? g_snd_volume : SND_VOL_MED];
    // Anything queued while this one plays follows straight on, without
    // stopping the clock in between.
    do {
      const Tone t = toneFor((SoundEvent)ev);
      for (uint8_t i = 0; i < t.count; i++) writeNote(t.notes[i], amp);
      writeNote({0, GAP_MS}, 0);
    } while (xQueueReceive(s_queue, &ev, 0) == pdTRUE);
    writeNote({0, DRAIN_MS}, 0);
    i2s_channel_disable(s_tx);
  }
}

static bool ensureStarted() {
  static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
  static bool starting = false;
  if (s_queue) return true;
  taskENTER_CRITICAL(&mux);
  const bool mine = !starting;
  starting = true;
  taskEXIT_CRITICAL(&mux);
  if (!mine) return false;   // another task is starting it; this tone is dropped

  // Set before the task exists: the task reads s_queue the moment it runs.
  s_queue = xQueueCreate(QUEUE_LEN, sizeof(uint8_t));
  // Low priority: a beep is never more important than the loop or the reader.
  if (!s_queue ||
      xTaskCreatePinnedToCore(soundTask, "sound", TASK_STACK, nullptr, 1, nullptr, 0) != pdPASS) {
    logSD("Sound: no memory for the sound task, the next beep tries again");
    if (s_queue) vQueueDelete(s_queue);
    s_queue = nullptr;
    taskENTER_CRITICAL(&mux);
    starting = false;
    taskEXIT_CRITICAL(&mux);
    return false;
  }
  logSD("Sound: started");
  return true;
}

void soundPlay(SoundEvent e) {
  if (!g_sound_on) return;
  switch (e) {
    case SND_NFC_READ:
    case SND_TAG_UNKNOWN:   if (!g_snd_nfc)    return; break;
    case SND_WRITE_OK:
    case SND_WRITE_FAIL:    if (!g_snd_write)  return; break;
    case SND_WEIGHT_OK:
    case SND_WEIGHT_MANUAL:
    case SND_WEIGHT_FAIL:   if (!g_snd_weight) return; break;
    default: break;
  }
  if (!ensureStarted()) return;
  const uint8_t ev = (uint8_t)e;
  xQueueSend(s_queue, &ev, 0);
}
