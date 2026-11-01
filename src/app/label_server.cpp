#include "app/label_server.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <string.h>

#include "app/backend_switch.h"
#include "hardware/sd_logger.h"
#include "services/worker_heap.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/prefs_store.h"

#define LS_KEY_PRESET         "lbl_fm_preset"
#define LS_LIST_TIMEOUT_MS    8000
// Allow time for the server's configured renderer and network latency.
#define LS_RENDER_TIMEOUT_MS  15000
// The list is asked again after this long, so a preset laid out in FilaMan
// meanwhile shows up; one that did not answer is asked again sooner.
#define LS_LIST_MAX_AGE_MS    60000
#define LS_LIST_RETRY_MS      20000
// A preview older than this is fetched again: the preset may have changed.
#define LS_PREVIEW_MAX_AGE_MS 30000
// The editor's fetches run like the label dates: core 0, below the loop,
// TLS needs the 16 kB of stack.
#define LS_STACK_BYTES        16384
#define LS_PRIORITY           1
#define LS_CORE               0
#define LS_WAIT_STEP_MS       20

// Which label a raster is: spool, preset, print row, roll orientation,
// and the server it came from.
struct LabelKey {
  int      spool_id, preset_id;
  uint16_t dpi, row;
  bool     landscape;
  uint32_t gen;
};

static bool sameKey(const LabelKey& a, const LabelKey& b) {
  return a.spool_id == b.spool_id && a.preset_id == b.preset_id && a.dpi == b.dpi &&
         a.row == b.row && a.landscape == b.landscape && a.gen == b.gen;
}

enum JobKind : uint8_t { JOB_LIST, JOB_PREVIEW };

// The editor's fetch. Everything the task reads is set before it starts and
// everything it writes is read only after s_job_done says so.
struct ServerJob {
  JobKind  kind;
  LabelKey key;
  int      code;
  char     reason[FM_LABEL_REASON_LEN];
  LabelRaster raster;
  FilamanLabelPresetList list;
};
static ServerJob s_job;
static volatile bool s_job_running = false, s_job_done = false;

static int s_preset = -1;   // -1: not read from NVS yet

static FilamanLabelPresetList s_list{};
static LabelServerListState s_list_state = LS_UNKNOWN;
static uint32_t s_list_gen = 0;
static unsigned long s_list_at = 0;
static bool s_want_list = false;

static LabelRaster s_prev{};
static LabelKey s_prev_key{};
static LabelServerPreviewState s_prev_state = LSP_NONE;
static char s_prev_reason[FM_LABEL_REASON_LEN] = "";
static unsigned long s_prev_at = 0;
static uint32_t s_prev_rev = 0;
static bool s_want_prev = false;

static char s_last_reason[FM_LABEL_REASON_LEN] = "";

int labelServerPresetId() {
  if (s_preset < 0) s_preset = prefsGetInt(LS_KEY_PRESET, 0);
  return s_preset;
}

bool labelServerSetPresetId(int id) {
  if (id < 0) id = 0;
  const bool ok = prefsPutInt(LS_KEY_PRESET, id);
  if (ok) s_preset = id;
  logSDf("Label: source %s%d", id ? "FilaMan preset " : "scale layout ", id);
  return ok;
}

// A server known to lack the label API gets the scale's own layout, so a
// preset kept from another server never stands between the user and a label.
bool labelServerInUse() {
  if (backendMode() != BACKEND_FILAMAN || labelServerPresetId() <= 0) return false;
  // A tape printer has its own fixed label (services/label_tape.h); a preset
  // drawn for a label would not fit 12 mm.
  if (labelPrinterIsTape(labelPrinterLoadConfig().model)) return false;
  return !(s_list_state == LS_ABSENT && s_list_gen == backendGeneration());
}

// The key for this spool on this printer; false when there is nothing to
// ask for (no spool, no preset, no printer model).
static bool keyFor(const LabelPrinterConfig& c, int spool_id, LabelKey* k) {
  *k = LabelKey{};
  k->spool_id = spool_id;
  k->preset_id = labelServerPresetId();
  k->dpi = labelPrinterProfile(c.model).dpi;
  k->row = labelPrinterRasterWidth(c.model, c.media_width_mm);
  k->landscape = c.media_width_mm >= c.media_length_mm;
  k->gen = backendGeneration();
  return spool_id > 0 && k->preset_id > 0 && k->dpi > 0 && k->row > 0;
}

static FilamanLabelRequest requestFor(const LabelKey& k) {
  FilamanLabelRequest r{};
  r.spool_id = k.spool_id;
  r.preset_id = k.preset_id;
  r.dpi = k.dpi;
  r.row_width = k.row;
  r.landscape = k.landscape;
  r.timeout_ms = LS_RENDER_TIMEOUT_MS;
  return r;
}

static void jobTask(void*) {
  if (s_job.kind == JOB_LIST)
    s_job.code = backendLabelPresets(&s_job.list, LS_LIST_TIMEOUT_MS);
  else
    s_job.code = backendLabelRender(requestFor(s_job.key), &s_job.raster,
                                    s_job.reason, sizeof(s_job.reason));
  __sync_synchronize();
  s_job_done = true;
  vTaskDelete(NULL);
}

// A refused start is asked for again on every loop pass.
static LogGate s_refusal_gate{};

// False when the task could not start; the caller marks the fetch failed.
static bool startJob(JobKind kind, const LabelKey& key) {
  if (!workerHeapReady("Label: server fetch", workerFloorBackend(), LS_STACK_BYTES,
                       &s_refusal_gate)) {
    return false;
  }
  memset(&s_job, 0, sizeof(s_job));
  s_job.kind = kind;
  s_job.key = key;
  s_job_done = false;
  s_job_running = true;
  if (xTaskCreatePinnedToCore(jobTask, "labelsrv", LS_STACK_BYTES, nullptr,
                              LS_PRIORITY, nullptr, LS_CORE) != pdPASS) {
    s_job_running = false;
    logSD("Label: server fetch task creation failed");
    return false;
  }
  return true;
}

static void dropPreview() {
  labelRasterFree(&s_prev);
  s_prev = LabelRaster{};
  s_prev_state = LSP_NONE;
  s_prev_reason[0] = '\0';
}

// A list only counts for the server it came from.
static void takeList() {
  if (s_job.key.gen != backendGeneration()) return;
  s_list_gen = s_job.key.gen;
  s_list_at = millis();
  if (s_job.code == 200) {
    s_list = s_job.list;
    s_list_state = LS_READY;
  } else {
    const int c = s_job.code;
    s_list_state = (c == 404 || c == 405 || c == 501) ? LS_ABSENT : LS_FAILED;
  }
}

// A preview only counts while it is still the one asked for last.
static void takePreview() {
  if (s_prev_state != LSP_LOADING || !sameKey(s_job.key, s_prev_key)) {
    labelRasterFree(&s_job.raster);
    return;
  }
  s_prev_at = millis();
  s_prev_rev++;
  if (s_job.code == 200) {
    s_prev = s_job.raster;
    s_prev_state = LSP_READY;
  } else {
    snprintf(s_prev_reason, sizeof(s_prev_reason), "%s", s_job.reason);
    s_prev_state = LSP_FAILED;
  }
  s_job.raster = LabelRaster{};
}

static void collectJob() {
  if (!s_job_running || !s_job_done) return;
  __sync_synchronize();
  s_job_running = false;
  if (s_job.kind == JOB_LIST) takeList();
  else takePreview();
}

void labelServerTick() {
  collectJob();
  if (s_job_running) return;
  if (s_want_prev) {
    s_want_prev = false;
    if (!startJob(JOB_PREVIEW, s_prev_key)) s_prev_state = LSP_FAILED;
    return;
  }
  if (s_want_list) {
    s_want_list = false;
    LabelKey k{};
    k.gen = backendGeneration();
    if (!startJob(JOB_LIST, k)) {
      s_list_state = LS_FAILED;
      s_list_at = millis();
    }
  }
}

// Whether the list in hand is due to be asked for again.
static bool listDue() {
  if (s_list_gen != backendGeneration()) return true;
  const unsigned long age = millis() - s_list_at;
  switch (s_list_state) {
    case LS_UNKNOWN: return true;
    case LS_READY:   return age > LS_LIST_MAX_AGE_MS;
    case LS_FAILED:  return age > LS_LIST_RETRY_MS;
    default:         return false;   // loading, or absent on this server
  }
}

LabelServerListState labelServerList(const FilamanLabelPresetList** list) {
  if (list) *list = &s_list;
  if (backendMode() != BACKEND_FILAMAN) return LS_ABSENT;
  if (listDue() && !s_want_list && !(s_job_running && s_job.kind == JOB_LIST)) {
    s_want_list = true;
    // A list in hand stays on show while the new one is fetched.
    if (s_list_state != LS_READY || s_list_gen != backendGeneration()) {
      s_list_state = LS_LOADING;
      s_list.count = 0;
    }
  }
  return s_list_state;
}

LabelServerPreviewState labelServerPreview(const LabelPrinterConfig& config, int spool_id,
                                           const LabelRaster** raster, const char** reason) {
  if (raster) *raster = nullptr;
  if (reason) *reason = "";
  LabelKey k{};
  if (backendMode() != BACKEND_FILAMAN || !keyFor(config, spool_id, &k)) return LSP_FAILED;
  const bool fresh = millis() - s_prev_at < LS_PREVIEW_MAX_AGE_MS;
  if (s_prev_state != LSP_NONE && sameKey(k, s_prev_key) &&
      (s_prev_state == LSP_LOADING || fresh)) {
    if (s_prev_state == LSP_READY && raster) *raster = &s_prev;
    if (s_prev_state == LSP_FAILED && reason) *reason = s_prev_reason;
    return s_prev_state;
  }
  dropPreview();
  s_prev_key = k;
  s_prev_state = LSP_LOADING;
  s_want_prev = true;
  return LSP_LOADING;
}

const LabelRaster* labelServerPreviewInHand(const LabelPrinterConfig& config, int spool_id) {
  LabelKey k{};
  if (!keyFor(config, spool_id, &k)) return nullptr;
  return (s_prev_state == LSP_READY && sameKey(k, s_prev_key)) ? &s_prev : nullptr;
}

uint32_t labelServerPreviewRev() { return s_prev_rev; }

// A copy the print owns; the preview keeps its own.
static bool copyRaster(const LabelRaster& from, LabelRaster* to) {
  *to = from;
  to->pixels = (uint8_t*)heap_caps_malloc(from.length, MALLOC_CAP_SPIRAM);
  if (!to->pixels) {
    *to = LabelRaster{};
    return false;
  }
  memcpy(to->pixels, from.pixels, from.length);
  return true;
}

// The editor's task may hold the server right now; a print waits for it
// rather than opening a second connection just before BLE needs the memory.
static void waitForJob(BleProgressFn tick) {
  const unsigned long started = millis();
  while (s_job_running && !s_job_done && millis() - started < LS_RENDER_TIMEOUT_MS) {
    if (tick) tick();
    delay(LS_WAIT_STEP_MS);
  }
  collectJob();
}

int labelServerPrintRaster(const LabelPrinterConfig& config, int spool_id,
                           LabelRaster* out, BleProgressFn tick) {
  s_last_reason[0] = '\0';
  if (!out) return -1;
  *out = LabelRaster{};
  LabelKey k{};
  if (!keyFor(config, spool_id, &k)) return -1;
  waitForJob(tick);
  int code;
  if (s_prev_state == LSP_READY && sameKey(k, s_prev_key) &&
      millis() - s_prev_at < LS_PREVIEW_MAX_AGE_MS) {
    // What the editor shows is what goes on paper, without asking again.
    code = copyRaster(s_prev, out) ? 200 : FM_LABEL_BAD_RASTER;
  } else {
    code = backendLabelRender(requestFor(k), out, s_last_reason, sizeof(s_last_reason));
  }
  if (code == 200) labelRasterShiftRight(out, labelPrinterContentX(config));
  return code;
}

const char* labelServerLastReason() { return s_last_reason; }

void labelServerForget() {
  s_list = FilamanLabelPresetList{};
  s_list_state = LS_UNKNOWN;
  s_want_list = false;
  s_want_prev = false;
  dropPreview();
  s_prev_key = LabelKey{};
}
