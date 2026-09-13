#include "web_jobs.h"

#include <ArduinoJson.h>
#include <string.h>

#include "app/app_state.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/github_release.h"
#include "web/web_shell.h"

// The same numbers the update check task runs with, for the same reasons: a
// TLS handshake with the certificate bundle wants the stack, the task sits
// below the loop so the display keeps its share, and it lives on the other
// core. The heap floor is checked before the stack is taken from it.
#define WEB_JOB_STACK_BYTES   16384
#define WEB_JOB_PRIORITY      1
#define WEB_JOB_CORE          0
#define WEB_JOB_MIN_HEAP      60000
// A result nobody collects is dropped after this, so the slot is free again
// for the next visitor.
#define WEB_JOB_KEEP_MS       60000UL

// The same allocator the lookup path uses: the inventory goes into PSRAM,
// not into the 320 kB the rest of the firmware shares.
struct SpiRamAllocator : ArduinoJson::Allocator {
  void* allocate(size_t n) override {
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM);
    if (!p) p = malloc(n);
    return p;
  }
  void  deallocate(void* p) override { heap_caps_free(p); }
  void* reallocate(void* p, size_t n) override {
    void* q = heap_caps_realloc(p, n, MALLOC_CAP_SPIRAM);
    if (!q) q = realloc(p, n);
    return q;
  }
};

static volatile WebJobState s_state = WJS_IDLE;
static WebJobResult         s_res;
static char                 s_arg[40] = "";
static bool                 s_flag    = false;
static unsigned long        s_done_ms = 0;

static void runHostTest() {
  s_res.code = backendGetHealthCode(backendBaseUrl(), 4000);
  s_res.ok   = (s_res.code == 200);
}

static void runSpools() {
  // Four fields per spool instead of the whole record. Without the filter a
  // large inventory is parsed in full and none of it is used here.
  JsonDocument filter;
  JsonObject f = filter.to<JsonArray>().add<JsonObject>();
  f["id"] = true;
  JsonObject ff = f["filament"].to<JsonObject>();
  ff["name"] = true;
  ff["material"] = true;
  ff["vendor"]["name"] = true;

  SpiRamAllocator psram_alloc;
  JsonDocument doc(&psram_alloc);
  s_res.code = backendGetSpoolListJson(backendBaseUrl(), false, doc, 8000, &filter);
  if (s_res.code != 200) { s_res.ok = false; return; }

  // Deliberately not clipped to spool_list_limit: that limit exists because
  // an LVGL picker with hundreds of rows runs the device out of memory, and
  // a browser has no such problem.
  String& out = s_res.body;
  out.reserve(4096);
  out = "[";
  bool first = true;
  for (JsonObjectConst sp : doc.as<JsonArrayConst>()) {
    int id = sp["id"] | 0;
    if (!id) continue;
    String label = String(sp["filament"]["vendor"]["name"] | "");
    String name  = String(sp["filament"]["name"] | "");
    String mat   = String(sp["filament"]["material"] | "");
    if (label.length() && name.length()) label += " ";
    label += name;
    if (mat.length()) label += " (" + mat + ")";
    label.replace("\\", "");
    label.replace("\"", "'");
    if (!first) out += ",";
    first = false;
    out += "{\"id\":" + String(id) + ",\"label\":\"" + label + "\"}";
  }
  out += "]";
  s_res.ok = true;
}

static void runGhCheck() {
  s_res.ok = githubLatestTag(s_flag, s_res.tag, sizeof(s_res.tag),
                             s_res.pub, sizeof(s_res.pub),
                             s_res.err, sizeof(s_res.err));
}

static void runGhNotes() {
  GithubRelease rel;
  if (!githubReleaseByTag(s_arg, rel, s_res.err, sizeof(s_res.err))) {
    s_res.ok = false;
    return;
  }
  s_res.body = "{\"ok\":true,\"tag\":\"" + jsonEsc(rel.tag) +
               "\",\"name\":\"" + jsonEsc(rel.name) +
               "\",\"published\":\"" + jsonEsc(rel.published) +
               "\",\"prerelease\":" + (rel.prerelease ? "true" : "false") +
               ",\"notes\":\"" + jsonEsc(rel.notes.c_str()) + "\"}";
  strncpy(s_res.tag, rel.tag, sizeof(s_res.tag) - 1);
  s_res.tag[sizeof(s_res.tag) - 1] = '\0';
  s_res.ok = true;
}

static void webJobTask(void* arg) {
  (void)arg;
  switch (s_res.kind) {
    case WJ_HOST_TEST: runHostTest(); break;
    case WJ_SPOOLS:    runSpools();   break;
    case WJ_GH_CHECK:  runGhCheck();  break;
    case WJ_GH_NOTES:  runGhNotes();  break;
    default: break;
  }
  Serial.printf("[webjob] kind %d done, ok=%d code=%d, stack left %u\n",
                (int)s_res.kind, (int)s_res.ok, s_res.code,
                (unsigned)uxTaskGetStackHighWaterMark(NULL));
  s_done_ms = millis() ? millis() : 1;
  // Everything above is written before the state says so: the handler on
  // the other core reads the state first and the result after.
  __sync_synchronize();
  s_state = WJS_DONE;
  vTaskDelete(NULL);
}

bool webJobStart(WebJobKind kind, const char* arg, bool flag) {
  if (s_state != WJS_IDLE || kind == WJ_NONE) return false;
  // Checked here rather than inside the task: the stack comes out of the
  // heap the moment the task is created, so testing afterwards would be
  // testing the wrong number.
  if (ESP.getFreeHeap() < WEB_JOB_MIN_HEAP) {
    Serial.printf("[webjob] postponed, heap %u\n", (unsigned)ESP.getFreeHeap());
    return false;
  }
  s_res.kind   = kind;
  s_res.ok     = false;
  s_res.code   = 0;
  s_res.err[0] = '\0';
  s_res.tag[0] = '\0';
  s_res.pub[0] = '\0';
  s_res.body   = "";
  s_arg[0] = '\0';
  if (arg) { strncpy(s_arg, arg, sizeof(s_arg) - 1); s_arg[sizeof(s_arg) - 1] = '\0'; }
  s_flag = flag;

  // Set before the task exists: if creation fails it is cleared again below,
  // and if it succeeds the task may finish before this line would run.
  s_state = WJS_RUNNING;
  BaseType_t ok = xTaskCreatePinnedToCore(webJobTask, "webjob", WEB_JOB_STACK_BYTES,
                                          nullptr, WEB_JOB_PRIORITY, nullptr, WEB_JOB_CORE);
  if (ok != pdPASS) {
    s_state = WJS_IDLE;
    Serial.println("[webjob] task creation failed");
    return false;
  }
  return true;
}

WebJobState webJobState() { return s_state; }
WebJobKind  webJobKind()  { return s_res.kind; }

const WebJobResult& webJobResult() { return s_res; }

void webJobTake() {
  if (s_state != WJS_DONE) return;
  s_res.body = "";
  s_res.kind = WJ_NONE;
  s_state = WJS_IDLE;
}

void webJobsTick() {
  if (s_state == WJS_DONE && millis() - s_done_ms > WEB_JOB_KEEP_MS) {
    Serial.printf("[webjob] result of kind %d dropped, nobody asked\n", (int)s_res.kind);
    webJobTake();
  }
}
