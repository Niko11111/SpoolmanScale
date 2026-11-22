#include "sound.h"

#include <Arduino.h>
#include <driver/i2s_std.h>
#include <esp_heap_caps.h>
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
bool    g_snd_ask    = true;
bool    g_snd_print  = true;
bool    g_snd_update = true;
bool    g_snd_link   = true;
uint8_t g_snd_att_db = SND_ATT_DEFAULT_DB;
bool    g_snd_chime  = true;

void soundLoadPrefs() {
  g_sound_on   = prefsGetBool("snd_on", false);
  g_snd_nfc    = prefsGetBool("snd_nfc", true);
  g_snd_write  = prefsGetBool("snd_write", true);
  g_snd_weight = prefsGetBool("snd_weight", true);
  g_snd_ask    = prefsGetBool("snd_ask", true);
  g_snd_print  = prefsGetBool("snd_print", true);
  g_snd_update = prefsGetBool("snd_update", true);
  g_snd_link   = prefsGetBool("snd_link", true);
  g_snd_chime  = prefsGetBool("snd_chime", true);
  g_snd_att_db = prefsGetUChar("snd_att", SND_ATT_DEFAULT_DB);
  if (g_snd_att_db > SND_ATT_MAX_DB) g_snd_att_db = SND_ATT_DEFAULT_DB;
}

static const int8_t CLOCK_PINS[] = {
  hw_pins::SPK_LRCK, hw_pins::SPK_BCLK, hw_pins::SPK_DOUT
};
static const unsigned CLOCK_PIN_COUNT = sizeof(CLOCK_PINS) / sizeof(CLOCK_PINS[0]);

static void driveClockPinsLow() {
  for (unsigned i = 0; i < CLOCK_PIN_COUNT; i++) {
    const gpio_num_t pin = (gpio_num_t)CLOCK_PINS[i];
    gpio_hold_dis(pin);
    gpio_reset_pin(pin);
    gpio_set_direction(pin, GPIO_MODE_OUTPUT);
    gpio_set_level(pin, 0);
  }
}

void soundParkClockPins() {
  driveClockPinsLow();
  logSD("Sound: GPIO35, GPIO36 and GPIO37 driven low until the first tone");
}

static void logInternalHeap(const char *when) {
  multi_heap_info_t info;
  heap_caps_get_info(&info, MALLOC_CAP_INTERNAL);
  logSDf("Sound: internal heap %s, free %u bytes, largest %u",
         when, (unsigned)info.total_free_bytes, (unsigned)info.largest_free_block);
}

// 16 kHz is plenty for beeps of at most 2.5 kHz and keeps the DMA buffers small.
static const uint32_t SAMPLE_RATE = 16000;
static const int      CHUNK       = 240;   // samples per write, 15 ms
// A tone that starts or stops at full amplitude clicks on the speaker.
static const uint16_t FADE_MS     = 3;
// A ringing note falls to e^-3, about 5 % of its start, by its end.
static const float    RING_DECAY  = 3.0f;
static const uint16_t GAP_MS      = 40;    // between two tones queued together
// Long enough that two previewed tones are heard as two, not as one melody.
static const uint16_t PREVIEW_GAP_MS = 400;
// The DMA still holds the last buffers when the tone is written; this much
// silence lets them play out before the clock stops and cuts the tail off.
static const uint16_t DRAIN_MS    = 60;
// The longest preview is three tones and the two pauses between them.
static const uint8_t  QUEUE_LEN   = 8;
static const uint32_t TASK_STACK  = 3072;
static const TickType_t WRITE_TIMEOUT = pdMS_TO_TICKS(200);

// Full scale of a 16-bit sample. A sine that rounds past this is clipped.
static const float SAMPLE_MAX = (float)INT16_MAX;

// Peak amplitude for the attenuation set on the slider.
static int16_t amplitudeFor(uint8_t att_db) {
  if (att_db > SND_ATT_MAX_DB) att_db = SND_ATT_DEFAULT_DB;
  return (int16_t)(SAMPLE_MAX * powf(10.0f, -(float)att_db / 20.0f));
}

struct Note { uint16_t hz; uint16_t ms; };   // hz 0 = a pause
// ring: the note decays like a struck chime instead of holding its level.
struct Tone { const Note *notes; uint8_t count; bool ring; };

// Counts the notes itself, so a table that grows cannot be cut short.
template <size_t N>
static Tone tone(const Note (&notes)[N], bool ring) { return { notes, (uint8_t)N, ring }; }

static const Note N_READ[]   = { {2000, 60} };
static const Note N_W_OK[]   = { {1500, 60}, {0, 30}, {2200, 90} };
static const Note N_FAIL[]   = { {500, 120}, {0, 40}, {350, 200} };
// Three equal taps at one pitch: auto weight saved.
static const Note N_WGT_OK[] = { {1800, 50}, {0, 40}, {1800, 50}, {0, 40}, {1800, 50} };
// Three rising notes: the weight button saved.
static const Note N_WGT_MAN[] = { {1300, 50}, {0, 25}, {1700, 50}, {0, 25}, {2200, 80} };
// Short and high, then long and low: the tag is not in the inventory.
static const Note N_UNKNOWN[] = { {2400, 45}, {0, 35}, {320, 220} };
// Two equal taps, like a knock: something waits for an answer.
static const Note N_ASK[]    = { {2000, 60}, {0, 80}, {2000, 60} };
// Four rising notes, the longest tone: heard once per update.
static const Note N_UPD_OK[] = { {1300, 50}, {0, 25}, {1700, 50}, {0, 25}, {2200, 50}, {0, 25}, {2600, 100} };
static const Note N_LOST[]   = { {1200, 80}, {0, 30}, {700, 160} };
static const Note N_TEST[]   = { {2000, 80} };
static const Note N_PAUSE[]  = { {0, PREVIEW_GAP_MS} };

static Tone beepFor(SoundEvent e) {
  switch (e) {
    case SND_NFC_READ:      return tone(N_READ, false);
    case SND_TAG_UNKNOWN:   return tone(N_UNKNOWN, false);
    case SND_WRITE_OK:
    case SND_PRINT_OK:      return tone(N_W_OK, false);
    case SND_WRITE_FAIL:
    case SND_WEIGHT_FAIL:
    case SND_PRINT_FAIL:
    case SND_UPDATE_FAIL:   return tone(N_FAIL, false);
    case SND_WEIGHT_OK:     return tone(N_WGT_OK, false);
    case SND_WEIGHT_MANUAL: return tone(N_WGT_MAN, false);
    case SND_ASK:           return tone(N_ASK, false);
    case SND_UPDATE_OK:     return tone(N_UPD_OK, false);
    case SND_LINK_LOST:     return tone(N_LOST, false);
    case SND_PAUSE:         return tone(N_PAUSE, false);
    default:                return tone(N_TEST, false);
  }
}

// Feature AA, from the listening samples in the notes: rising for success,
// falling for a tag the inventory does not know, one low note for an error.
// A tag read comes on every placement, so it is a single strike; the rest
// are the AA notes, plus chimes of their own for the events added since.
static const uint16_t CHIME_GAP_MS = 15;
static const Note C_SAVED[]   = { {523, 90}, {0, CHIME_GAP_MS}, {659, 90}, {0, CHIME_GAP_MS}, {784, 160} };
static const Note C_AUTO[]    = { {523, 80}, {0, CHIME_GAP_MS}, {784, 140} };
static const Note C_WRITTEN[] = { {659, 70}, {0, CHIME_GAP_MS}, {1047, 130} };
static const Note C_READ[]    = { {1047, 90} };
static const Note C_UNKNOWN[] = { {1047, 70}, {0, CHIME_GAP_MS}, {784, 110} };
static const Note C_FAIL[]    = { {330, 350} };
// Two equal strikes with room between them, like a doorbell.
static const Note C_ASK[]     = { {1175, 80}, {0, 90}, {1175, 110} };
static const Note C_PRINTED[] = { {880, 70}, {0, CHIME_GAP_MS}, {1175, 130} };
static const Note C_UPDATED[] = { {523, 80}, {0, CHIME_GAP_MS}, {659, 80}, {0, CHIME_GAP_MS},
                                  {784, 80}, {0, CHIME_GAP_MS}, {1047, 220} };
static const Note C_LOST[]    = { {659, 110}, {0, CHIME_GAP_MS}, {440, 220} };
static const Note C_TEST[]    = { {784, 120} };

static Tone chimeFor(SoundEvent e) {
  switch (e) {
    case SND_NFC_READ:      return tone(C_READ, true);
    case SND_TAG_UNKNOWN:   return tone(C_UNKNOWN, true);
    case SND_WRITE_OK:      return tone(C_WRITTEN, true);
    case SND_WEIGHT_OK:     return tone(C_AUTO, true);
    case SND_WEIGHT_MANUAL: return tone(C_SAVED, true);
    case SND_WRITE_FAIL:
    case SND_WEIGHT_FAIL:
    case SND_PRINT_FAIL:
    case SND_UPDATE_FAIL:   return tone(C_FAIL, true);
    case SND_ASK:           return tone(C_ASK, true);
    case SND_PRINT_OK:      return tone(C_PRINTED, true);
    case SND_UPDATE_OK:     return tone(C_UPDATED, true);
    case SND_LINK_LOST:     return tone(C_LOST, true);
    case SND_TEST:          return tone(C_TEST, true);
    default:                return beepFor(e);   // the pause
  }
}

static Tone toneFor(SoundEvent e) { return g_snd_chime ? chimeFor(e) : beepFor(e); }

static QueueHandle_t     s_queue = nullptr;
static i2s_chan_handle_t s_tx    = nullptr;
static bool              s_failed = false;   // I2S would not start; stop trying
static bool              s_asleep = false;   // deep sleep has taken the pins

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

void soundPrepareDeepSleep() {
  s_asleep = true;
  if (s_tx) i2s_channel_disable(s_tx);
  driveClockPinsLow();
  for (unsigned i = 0; i < CLOCK_PIN_COUNT; i++)
    gpio_hold_en((gpio_num_t)CLOCK_PINS[i]);
  logSD("Sound: clock pins held low across deep sleep");
}

static int16_t toneSample(float wave, int16_t amp, float env) {
  float s = wave * (float)amp * env;
  if (s > SAMPLE_MAX) s = SAMPLE_MAX;
  if (s < -SAMPLE_MAX) s = -SAMPLE_MAX;
  return (int16_t)s;
}

static void writeNote(const Note &n, int16_t amp, bool ring = false) {
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
      if (ring) env *= expf(-RING_DECAY * (float)k / total);
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
    if (s_failed || s_asleep) continue;
    if (!i2sStart()) {
      s_failed = true;
      logSD("Sound: I2S could not be started, sound stays silent until reboot");
      continue;
    }
    const int16_t amp = amplitudeFor(g_snd_att_db);
    static bool heap_after = false;
    if (!heap_after) {
      heap_after = true;
      logInternalHeap("after the first tone started I2S");
    }
    // Anything queued while this one plays follows straight on, without
    // stopping the clock in between.
    do {
      const Tone t = toneFor((SoundEvent)ev);
      for (uint8_t i = 0; i < t.count; i++) writeNote(t.notes[i], amp, t.ring);
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

  logInternalHeap("before the first tone");
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

// The switch of the row that e belongs to, or nullptr for a tone that only
// the master switch governs.
static const bool *switchFor(SoundEvent e) {
  switch (e) {
    case SND_NFC_READ:
    case SND_TAG_UNKNOWN:   return &g_snd_nfc;
    case SND_WRITE_OK:
    case SND_WRITE_FAIL:    return &g_snd_write;
    case SND_WEIGHT_OK:
    case SND_WEIGHT_MANUAL:
    case SND_WEIGHT_FAIL:   return &g_snd_weight;
    case SND_ASK:           return &g_snd_ask;
    case SND_PRINT_OK:
    case SND_PRINT_FAIL:    return &g_snd_print;
    case SND_UPDATE_OK:
    case SND_UPDATE_FAIL:   return &g_snd_update;
    case SND_LINK_LOST:     return &g_snd_link;
    default:                return nullptr;
  }
}

// A link that drops and comes back every few minutes would chime each time;
// once in this window is enough to know it is unstable.
static const uint32_t LINK_LOST_QUIET_MS = 10UL * 60UL * 1000UL;

static bool linkLostTooSoon() {
  static uint32_t last_ms = 0;
  static bool played = false;
  const uint32_t now = millis();
  if (played && now - last_ms < LINK_LOST_QUIET_MS) return true;
  played = true;
  last_ms = now;
  return false;
}

void soundPlay(SoundEvent e) {
  if (!g_sound_on) return;
  const bool *sw = switchFor(e);
  if (sw && !*sw) return;
  if (e == SND_LINK_LOST && linkLostTooSoon()) return;
  if (!ensureStarted()) return;
  const uint8_t ev = (uint8_t)e;
  xQueueSend(s_queue, &ev, 0);
}

void soundPreview(const SoundEvent *events, uint8_t count) {
  if (!g_sound_on || !events) return;
  if (!ensureStarted()) return;
  if (count > SND_PREVIEW_MAX) count = SND_PREVIEW_MAX;
  for (uint8_t i = 0; i < count; i++) {
    if (i > 0) {
      const uint8_t pause = (uint8_t)SND_PAUSE;
      xQueueSend(s_queue, &pause, 0);
    }
    const uint8_t ev = (uint8_t)events[i];
    xQueueSend(s_queue, &ev, 0);
  }
}
