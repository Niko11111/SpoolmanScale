// Writing NFC tags from the browser. GATE_MAINT rather than GATE_CONFIG:
// a mistake here is written to a physical tag and cannot be taken back from
// the device.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>
#include <ArduinoJson.h>

#include "app/app_state.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_api.h"
#include "services/tag_write.h"
#include "web/web_access.h"

static String body() {
  String html;
  html +=
      "<div class='card'>"
      "<h2>Write a tag</h2>"
      "<p style='font-size:12px;color:#4a6fa0;margin-bottom:14px'>Place a writable NTAG on the reader, pick a spool, and write it. Whatever is already on the tag is replaced. Factory tags are usually MIFARE Classic or locked, and can only be read.</p>"
      "<div id='tg-uid' style='font-size:13px;color:#c8d8f0;margin-bottom:12px'>Checking reader...</div>"
      "<div style='display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px'>"
      "<div id='tg-cur' class='swatch'></div>"
      "<div id='tg-new' class='swatch'></div>"
      "</div>"
      "<div id='tg-note' style='font-size:12px;color:#e0a44a;margin-bottom:12px'></div>"
      "<div style='display:flex;gap:10px;align-items:center;flex-wrap:wrap'>"
      "<label style='font-size:13px;color:#c8d8f0'>Spool ID</label>"
      "<input id='tg-id' type='number' min='1' oninput='loadPreview()' style='width:88px;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;border-radius:8px;padding:8px 10px;font-size:16px'>"
      "<select id='tg-pick' onchange='pickSpool()' style='flex:1;min-width:200px;background:#06080f;color:#e8f0ff;border:1px solid #1a3060;border-radius:8px;padding:8px 10px;font-size:14px'><option value=''>Loading spools...</option></select>"
      "<select id='tg-fmt' onchange='loadPreview()' style='background:#06080f;color:#e8f0ff;border:1px solid #1a3060;border-radius:8px;padding:8px 10px;font-size:14px'>"
      "<option value='0'>Anycubic ACE</option>"
      "<option value='1'>OpenSpool (FilaMan)</option>"
      "</select>"
      "<button id='tg-btn' class='btn-toggle' onclick='writeTag()' disabled>Pick a spool</button>"
      "<button id='tg-erase' class='btn-toggle' onclick='eraseTag()' disabled>Erase tag</button>"
      "</div>"
      "<label style='display:flex;align-items:center;gap:8px;font-size:13px;color:#c8d8f0;margin-top:12px'>"
      "<input id='tg-link' type='checkbox' checked style='width:16px;height:16px'>"
      "Also link this tag to the spool, so presenting it selects that spool"
      "</label>"
      "<div id='tg-s' style='font-size:13px;color:#28d49a;margin-top:12px'></div>"
      "</div>";
  return html;
}

static void routes(WebServer &srv) {
  srv.on("/api/tag/preview", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, "Tag writing")) return;
    int id  = srv.arg("id").toInt();
    int fmt = srv.arg("fmt").toInt();
    char prev[128] = "", linked[40] = "";
    TagInfo ti;
    bool ok = tagPreview(id, fmt == 2 ? TAG_FMT_ERASE : fmt == 1 ? TAG_FMT_OPENSPOOL : TAG_FMT_ACE,
                         prev, sizeof(prev), linked, sizeof(linked), &ti);
    char info[320];
    tagInfoJson(&ti, info, sizeof(info));
    srv.send(200, "application/json",
      String("{\"ok\":") + (ok ? "true" : "false") + ",\"info\":" + info +
      ",\"preview\":\"" + prev + "\",\"linked\":\"" + linked + "\"}");
  });

  srv.on("/api/spools", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, "Tag writing")) return;
    JsonDocument doc;
    int code = backendGetSpoolListJson(backendBaseUrl(), false, doc);
    if (code != 200) {
      srv.send(200, "application/json",
                      String("{\"error\":\"backend HTTP ") + code + "\"}");
      return;
    }
    String out = "[";
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
    srv.send(200, "application/json", out);
  });

  srv.on("/api/tag", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, "Tag writing")) return;
    // Reader state comes from the loop task; touching the reader here would
    // race the main NFC poll.
    char info[320];
    tagInfoJson(tagCachedInfo(), info, sizeof(info));
    String j = String("{\"info\":") + info + ",\"uid\":\"" + tagCachedUid() + "\",\"kind\":\"" + tagCachedKind() +
               "\",\"state\":\"" + tagWriteState() +
               "\",\"message\":\"" + tagWriteMessage() +
               "\",\"content\":\"" + tagCachedContent() + "\"}";
    srv.send(200, "application/json", j);
  });

  srv.on("/api/tag/write", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, "Tag writing")) return;
    if (!srv.hasArg("plain")) { srv.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    String body = srv.arg("plain");
    int c1 = body.indexOf(',');
    int c2 = c1 < 0 ? -1 : body.indexOf(',', c1 + 1);
    int id  = body.substring(0, c1 < 0 ? body.length() : c1).toInt();
    int fmt = c1 < 0 ? 0 : body.substring(c1 + 1, c2 < 0 ? body.length() : c2).toInt();
    bool link = c2 >= 0 && body.substring(c2 + 1).toInt() == 1;
    bool ok = tagWriteRequest(id, fmt == 2 ? TAG_FMT_ERASE : fmt == 1 ? TAG_FMT_OPENSPOOL : TAG_FMT_ACE, link);
    srv.send(200, "application/json",
      ok ? "{\"message\":\"Queued, keep the tag on the reader.\"}"
         : "{\"message\":\"Busy or invalid spool ID.\"}");
  });
}

extern const WebPage PAGE_TAGS;
const WebPage PAGE_TAGS = {
  "/tags", "Tags", nullptr, GATE_MAINT, nullptr,
  body, routes
};
