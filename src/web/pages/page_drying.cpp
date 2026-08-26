// Drying reminder. A spool that has been open for too long gets an amber or
// a red marker on the main screen, and this is where the two thresholds are
// set - per material, because PLA and PA do not age at the same rate.
//
// Sealed storage multiplies both thresholds. The radio pair says how this
// material is stored here, not what the material is.
#include "web/web_pages.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <WebServer.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/drying_config.h"
#include "services/prefs_store.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

static const char* label() { return T(STR_W_NAV_DRYING); }

static String body() {
  String h;
  h.reserve(7000);

  h += F("<div class='grid'><div class='card wide'><h2>");
  h += T(STR_W_C_DRYING);
  h += F("</h2><div style='overflow-x:auto'><table><thead><tr><th>");
  h += T(STR_W_DRY_MATERIAL);
  h += F("</th><th>");
  h += T(STR_W_DRY_YELLOW);
  h += F("</th><th>");
  h += T(STR_W_DRY_RED);
  h += F("</th><th>");
  h += T(STR_W_DRY_STORAGE);
  h += F("</th></tr></thead><tbody>");

  // Built from the table in drying_config rather than seven copies of the
  // same row. The previous version spelled every material out by hand, so a
  // new one meant editing the page as well as the config.
  for (int i = 0; i < DRY_MAT_COUNT; i++) {
    const String m = DRY_MAT_NAMES[i];
    h += F("<tr><td style='color:var(--ink)'>");
    h += m;
    h += F("</td><td><input type='number' min='1' max='999' name='y_");
    h += m;
    h += F("' value='");
    h += String(g_dry_mat_yellow[i]);
    h += F("'></td><td><input type='number' min='1' max='999' name='r_");
    h += m;
    h += F("' value='");
    h += String(g_dry_mat_red[i]);
    h += F("'></td><td><label style='margin-right:14px;white-space:nowrap'>"
           "<input type='radio' name='s_");
    h += m;
    h += F("' value='open'");
    h += g_dry_mat_sealed[i] ? F("") : F(" checked");
    h += F("> ");
    h += T(STR_W_DRY_OPEN);
    h += F("</label><label style='white-space:nowrap'><input type='radio' name='s_");
    h += m;
    h += F("' value='sealed'");
    h += g_dry_mat_sealed[i] ? F(" checked") : F("");
    h += F("> ");
    h += T(STR_W_DRY_SEALED);
    h += F("</label></td></tr>");
  }

  h += F("</tbody></table></div>"
         "<div class='field' style='margin-top:18px'><label>");
  h += T(STR_W_DRY_MULT);
  h += F("</label><div class='inrow'>"
         "<input id='dm' type='number' min='1' max='10' step='0.1' value='");
  h += String(g_dry_mult_sealed, 1);
  h += F("'><span class='suffix'>&times;</span>"
         "<span class='hint' style='flex:1'>");
  h += T(STR_W_DRY_MULT_HINT);
  h += F("</span></div></div>"
         "<div class='inrow' style='margin-top:18px'><button onclick='saveDry()'>");
  h += T(STR_W_SAVE);
  h += F("</button><button class='danger' onclick='resetDry()'>");
  h += T(STR_W_DEFAULTS);
  h += F("</button><span class='msg' id='dry-s'></span></div></div></div>");

  // The unit is stated once, in the column heads, so it does not repeat
  // fourteen times next to the inputs.
  h += F("<p class='foot' style='text-align:left;margin-top:-6px'>");
  h += T(STR_W_DRY_DAYS);
  h += F("</p>");

  h += F("<script>");
  h += webShellJsStrings();
  h += F("const M={mats:[");
  for (int i = 0; i < DRY_MAT_COUNT; i++) {
    if (i) h += F(",");
    h += jsStr(DRY_MAT_NAMES[i]);
  }
  h += F("]};"
         // The one route that takes a JSON body, so it builds its own fetch
         // rather than going through post() - the shared helper sends plain
         // text, which is what every other setting route speaks.
         "function saveDry(){"
         "const arr=M.mats.map(m=>{"
         "const sr=document.querySelector('[name=s_'+m+'][value=sealed]');"
         "return{name:m,"
         "yellow:parseInt(document.querySelector('[name=y_'+m+']').value)||1,"
         "red:parseInt(document.querySelector('[name=r_'+m+']').value)||1,"
         "sealed:sr?sr.checked:false};});"
         "const mult=parseFloat($('dm').value)||1;"
         "fetch('/api/drying',{method:'POST',"
         "headers:{'Content-Type':'application/json'},"
         "body:JSON.stringify({mult_sealed:mult,materials:arr})})"
         ".then(r=>r.json()).then(d=>flash('dry-s',d.ok?WS.ok:WS.err,!d.ok,4000))"
         ".catch(()=>flash('dry-s',WS.err,true,4000));}"
         "function resetDry(){"
         "postFlash('/api/drying/reset','','dry-s',4000)"
         ".then(r=>{if(r.ok)setTimeout(()=>location.reload(),900);});}"
         "</script>");
  return h;
}

static void routes(WebServer &srv) {
  // ── Drying Reminder: Material-Schwellwerte lesen ──────────
  srv.on("/api/drying", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_DRYING))) return;
    String json = "{";
    json += "\"mode\":" + String(g_dry_mode) + ",";
    json += "\"man_yellow\":" + String(g_dry_man_yellow) + ",";
    json += "\"man_red\":" + String(g_dry_man_red) + ",";
    json += "\"mult_sealed\":" + String(g_dry_mult_sealed, 1) + ",";
    json += "\"materials\":[";
    for (int i = 0; i < DRY_MAT_COUNT; i++) {
      if (i > 0) json += ",";
      json += "{\"name\":\"" + String(DRY_MAT_NAMES[i]) + "\",";
      json += "\"yellow\":" + String(g_dry_mat_yellow[i]) + ",";
      json += "\"red\":" + String(g_dry_mat_red[i]) + ",";
      json += "\"sealed\":" + String(g_dry_mat_sealed[i] ? "true" : "false") + "}";
    }
    json += "]}";
    srv.send(200, "application/json", json);
  });

  // ── Drying Reminder: Material-Schwellwerte speichern ──────
  // Body: JSON {"mult_sealed":3.0,"materials":[{"name":"PLA","yellow":180,"red":365},...]}
  srv.on("/api/drying", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_DRYING))) return;
    if (!srv.hasArg("plain")) {
      srv.send(400, "application/json", "{\"error\":\"no body\"}"); return;
    }
    StaticJsonDocument<1024> doc;
    DeserializationError err = deserializeJson(doc, srv.arg("plain"));
    if (err) {
      srv.send(400, "application/json", "{\"error\":\"json parse\"}"); return;
    }
    if (doc.containsKey("mult_sealed")) {
      g_dry_mult_sealed = doc["mult_sealed"].as<float>();
      if (g_dry_mult_sealed < 1.0f) g_dry_mult_sealed = 1.0f;
      if (g_dry_mult_sealed > 10.0f) g_dry_mult_sealed = 10.0f;
      prefsPutFloat("dry_mult_s", g_dry_mult_sealed);
    }
    if (doc.containsKey("materials")) {
      JsonArray arr = doc["materials"].as<JsonArray>();
      for (JsonObject obj : arr) {
        const char* nm = obj["name"] | "";
        for (int i = 0; i < DRY_MAT_COUNT; i++) {
          if (strcasecmp(nm, DRY_MAT_NAMES[i]) == 0) {
            char key[16];
            if (obj.containsKey("yellow")) {
              g_dry_mat_yellow[i] = max(1, (int)obj["yellow"]);
              snprintf(key, sizeof(key), "dry_y_%s", DRY_MAT_NAMES[i]);
              prefsPutInt(key, g_dry_mat_yellow[i]);
            }
            if (obj.containsKey("red")) {
              g_dry_mat_red[i] = max(1, (int)obj["red"]);
              snprintf(key, sizeof(key), "dry_r_%s", DRY_MAT_NAMES[i]);
              prefsPutInt(key, g_dry_mat_red[i]);
            }
            if (obj["sealed"].is<bool>()) {
              g_dry_mat_sealed[i] = obj["sealed"].as<bool>();
              snprintf(key, sizeof(key), "dry_s_%s", DRY_MAT_NAMES[i]);
              prefsPutBool(key, g_dry_mat_sealed[i]);
            }
            break;
          }
        }
      }
    }
    logSD("Webserver: drying thresholds updated");
    srv.send(200, "application/json", "{\"ok\":true}");
  });

  // ── Drying Reminder: Reset auf Defaults ───────────────────
  srv.on("/api/drying/reset", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_DRYING))) return;
    g_dry_mult_sealed = 2.0f;
    g_dry_man_yellow  = 30;
    g_dry_man_red     = 90;
    prefsPutFloat("dry_mult_s", g_dry_mult_sealed);
    prefsPutInt("dry_man_y",  g_dry_man_yellow);
    prefsPutInt("dry_man_r",  g_dry_man_red);
    char key[16];
    for (int i = 0; i < DRY_MAT_COUNT; i++) {
      g_dry_mat_yellow[i] = DRY_MAT_DEF_YELLOW[i];
      g_dry_mat_red[i]    = DRY_MAT_DEF_RED[i];
      g_dry_mat_sealed[i] = false;
      snprintf(key, sizeof(key), "dry_y_%s", DRY_MAT_NAMES[i]);
      prefsPutInt(key, g_dry_mat_yellow[i]);
      snprintf(key, sizeof(key), "dry_r_%s", DRY_MAT_NAMES[i]);
      prefsPutInt(key, g_dry_mat_red[i]);
      snprintf(key, sizeof(key), "dry_s_%s", DRY_MAT_NAMES[i]);
      prefsPutBool(key, false);
    }
    logSD("Webserver: drying thresholds reset to defaults");
    srv.send(200, "application/json", "{\"ok\":true,\"reset\":true}");
  });
}

extern const WebPage PAGE_DRYING;
const WebPage PAGE_DRYING = {
  "/drying", label, GATE_CONFIG, nullptr,
  body, routes
};
