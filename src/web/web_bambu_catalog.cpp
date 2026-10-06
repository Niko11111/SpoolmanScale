#include "web_bambu_catalog.h"

#include <time.h>

#include "app/app_state.h"
#include "bambu/bambu_catalog.h"
#include "bambu/bambu_catalog_sync.h"
#include "web/web_access.h"
#include "web/web_jobs.h"
#include "web/web_shell.h"

// Last: T() is a macro, and ArduinoJson uses T as a template parameter.
#include "lang.h"

void bambuCatalogCard(String& h) {
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_BCAT_TITLE);
  h += F("</h2><div class='inrow'>"
         "<button id='bc-btn' disabled></button>"
         "<span class='msg' id='bc-s'></span></div>"
         "<p class='note' style='margin-top:10px'>");
  h += T(STR_W_BCAT_NOTE);
  h += F("</p></div>"
         "<script>(function(){"
         "const M={none:");
  h += jsStr(T(STR_W_BCAT_NONE));
  h += F(",state:");  h += jsStr(T(STR_W_BCAT_STATE));
  h += F(",busy:");   h += jsStr(T(STR_W_BCAT_BUSY));
  h += F(",fail:");   h += jsStr(T(STR_W_BCAT_FAIL));
  h += F(",load:");   h += jsStr(T(STR_W_BCAT_LOAD));
  h += F(",upd:");    h += jsStr(T(STR_W_BCAT_UPDATE));
  h += F(",same:");   h += jsStr(T(STR_W_BCAT_UNCHANGED));
  h += F("};"
         "const s=document.getElementById('bc-s'),b=document.getElementById('bc-btn');"
         "function show(d){"
         "if(d.busy){s.textContent=M.busy;b.disabled=true;setTimeout(poll,1500);return;}"
         "b.disabled=false;b.textContent=d.count?M.upd:M.load;"
         "let t=d.count?M.state.replace('%d',d.count).replace('%s',d.date||'-')"
         ".replace('%s',d.checked||'-'):M.none;"
         "if(d.error)t=M.fail.replace('%s',d.error)+' '+t;"
         "else if(d.note==='unchanged')t=M.same+' '+t;"
         "s.textContent=t;}"
         "function poll(){fetch('/api/bambu/catalog').then(r=>r.json()).then(show).catch(()=>{});}"
         "b.addEventListener('click',()=>{b.disabled=true;s.textContent=M.busy;"
         "fetch('/api/bambu/catalog',{method:'POST'}).then(r=>r.json()).then(show)"
         ".catch(()=>{b.disabled=false;});});"
         "poll();})();</script>");
}

static void dayText(uint32_t epoch, char* out, size_t n) {
  out[0] = '\0';
  if (epoch < 1700000000UL) return;   // a clock that was never set
  const time_t t = (time_t)epoch;
  struct tm tm;
  localtime_r(&t, &tm);
  strftime(out, n, "%d.%m.%Y", &tm);
}

// What the scale holds, when it last compared it with GitHub, and how the
// last load or check ended if it is being collected now.
static void sendStatus(WebServer& srv, const char* error, const char* note = nullptr) {
  char date[16], checked[16];
  dayText(bambuCatalogStamp(), date, sizeof(date));
  dayText(bambuCatalogLastCheck(), checked, sizeof(checked));
  String j = "{\"count\":" + String(bambuCatalogCount()) + ",\"date\":\"" + date +
             "\",\"checked\":\"" + checked + "\"";
  if (error && error[0]) j += ",\"error\":\"" + jsonEsc(error) + "\"";
  if (note && note[0])   j += ",\"note\":\"" + jsonEsc(note) + "\"";
  j += "}";
  srv.send(200, "application/json", j);
}

void bambuCatalogRoutes(WebServer& srv) {
  // Asking is also collecting: the page polls this until the load is done.
  srv.on("/api/bambu/catalog", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;
    if (webJobKind() == WJ_BAMBU_CATALOG) {
      if (webJobState() == WJS_RUNNING) {
        srv.send(200, "application/json", "{\"busy\":true}");
        return;
      }
      if (webJobState() == WJS_DONE) {
        const WebJobResult& r = webJobResult();
        const String err  = r.ok ? String() : String(r.err);
        const String note = String(r.tag);
        webJobTake();
        sendStatus(srv, err.c_str(), note.c_str());
        return;
      }
    }
    sendStatus(srv, nullptr);
  });

  // Loads the table. Writes flash, so the maintenance gate, the one the log
  // and the tag writes sit behind. ?check=1 runs the daily check now instead:
  // with the stored ETag, so an unchanged file downloads nothing - the way
  // to test the schedule without waiting a day.
  srv.on("/api/bambu/catalog", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;
    if (!wifi_ok) { sendStatus(srv, "no WiFi"); return; }
    const bool check = srv.arg("check") == "1";
    const bool started = check ? bambuCatalogSyncNow()
                               : webJobStart(WJ_BAMBU_CATALOG, nullptr, false);
    if (!started) { sendStatus(srv, "busy"); return; }
    srv.send(200, "application/json", "{\"busy\":true}");
  });
}
