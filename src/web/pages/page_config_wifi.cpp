#include "web/pages/page_config_wifi.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <WebServer.h>
#include <string.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "services/device_name.h"
#include "services/mdns_service.h"
#include "services/wifi_known.h"
#include "services/wifi_manager.h"
#include "services/wifi_remote.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

// How the page follows a switch: one look this often, each given up after
// WF_GET_TIMEOUT_MS, since the scale may have left for another network and a
// request to its old address would hang for a minute. Past WF_GONE_MS without
// an answer it is taken to be on the new network.
#define WF_POLL_MS        2000
#define WF_GET_TIMEOUT_MS 3000
#define WF_GONE_MS        (WIFI_TRY_GIVE_UP_MS + 15000UL)

static const char* scanWord(WifiRemoteScan s) {
  switch (s) {
    case WRS_WAITING: return "wait";
    case WRS_RUNNING: return "run";
    case WRS_DONE:    return "done";
    case WRS_FAILED:  return "fail";
    default:          return "none";
  }
}

static const char* tryWord(WifiRemoteTry t) {
  switch (t) {
    case WRT_WAITING: return "wait";
    case WRT_TRYING:  return "try";
    case WRT_UP:      return "up";
    case WRT_FAILED:  return "fail";
    default:          return "none";
  }
}

static const char* jsBool(bool b) { return b ? "true" : "false"; }

// Names and states only. The passwords stay on the scale.
static void addKnown(String &j, const char *on) {
  const WifiKnownList &l = wifiKnownList();
  j += ",\"known\":[";
  for (int i = 0; i < l.n; i++) {
    if (i) j += ',';
    j += "{\"s\":\"" + jsonEsc(l.e[i].ssid) + "\"";
    j += ",\"c\":" + String(jsBool(strcmp(l.e[i].ssid, on) == 0));
    j += ",\"p\":" + String(jsBool(strcmp(l.e[i].ssid, wifiPreferredSsid()) == 0)) + "}";
  }
  j += ']';
}

static void addNets(String &j) {
  int n = 0;
  const WifiScanEntry *nets = wifiRemoteScanResults(&n);
  const WifiKnownList &l = wifiKnownList();
  j += ",\"scan\":\"" + String(scanWord(wifiRemoteScanState())) + "\",\"nets\":[";
  for (int i = 0; i < n; i++) {
    if (i) j += ',';
    j += "{\"s\":\"" + jsonEsc(nets[i].ssid) + "\"";
    j += ",\"r\":" + String(nets[i].rssi);
    j += ",\"o\":" + String(jsBool(nets[i].open));
    j += ",\"k\":" + String(jsBool(wifiKnownFind(l, nets[i].ssid) >= 0)) + "}";
  }
  j += ']';
}

static String stateJson() {
  char on[WIFI_KNOWN_SSID_BYTES];
  wifiManagerCurrentSsid(on, sizeof(on));
  String j = "{\"on\":\"" + jsonEsc(on) + "\"";
  if (on[0]) {
    j += ",\"rssi\":" + String(wifiManagerRSSI());
    j += ",\"ip\":\"" + wifiManagerLocalIP().toString() + "\"";
  }
  // The name the scale keeps on any network, where it has one.
  if (deviceDomain()[0] || mdnsRunning()) j += ",\"url\":\"" + jsonEsc(deviceFqdn()) + "\"";
  addKnown(j, on);
  addNets(j);
  j += ",\"try\":\"" + String(tryWord(wifiRemoteTryState())) + "\"";
  j += ",\"trySsid\":\"" + jsonEsc(wifiRemoteTrySsid()) + "\"";
  j += ",\"tryFrom\":\"" + jsonEsc(wifiRemoteTryFrom()) + "\"}";
  return j;
}

static void addWord(String &h, const char *key, int id) {
  h += key;
  h += ':';
  h += jsStr(T(id));
  h += ',';
}

static void addNumber(String &h, const char *key, long v) {
  h += key;
  h += ':';
  h += String(v);
  h += ',';
}

// The page's words and numbers, for the script below.
static String wordsJs() {
  String h = F("const WFT={");
  addWord(h, "pick", STR_W_WIFI_PICK);       addWord(h, "none", STR_WIFI_SAVED_NONE);
  addWord(h, "cp", STR_WIFI_ST_CONN_PREF);    addWord(h, "c", STR_WIFI_STATUS_CONNECTED);
  addWord(h, "p", STR_WIFI_ST_PREFERRED);     addWord(h, "sv", STR_WIFI_ST_SAVED);
  addWord(h, "go", STR_W_WIFI_CONNECT);       addWord(h, "forget", STR_WIFI_FORGET);
  addWord(h, "scanning", STR_WIFI_SCAN);      addWord(h, "scanfail", STR_W_WIFI_SCAN_FAIL);
  addWord(h, "nonets", STR_WIFI_NO_NET);      addWord(h, "saved", STR_WIFI_KNOWN_WORD);
  addWord(h, "open", STR_W_WIFI_OPEN);
  addWord(h, "ask", STR_W_WIFI_ASK);          addWord(h, "askf", STR_W_WIFI_ASK_FORGET);
  addWord(h, "trying", STR_W_WIFI_TRYING);    addWord(h, "awayn", STR_W_WIFI_AWAY_NAME);
  addWord(h, "awaym", STR_W_WIFI_AWAY_MENU);  addWord(h, "up", STR_W_WIFI_UP);
  addWord(h, "fail", STR_W_WIFI_FAIL);        addWord(h, "gonet", STR_W_WIFI_GONE);
  addNumber(h, "b4", SIGNAL_BARS_4_DBM);      addNumber(h, "b3", SIGNAL_BARS_3_DBM);
  addNumber(h, "b2", SIGNAL_BARS_2_DBM);      addNumber(h, "every", WF_POLL_MS);
  addNumber(h, "tmo", WF_GET_TIMEOUT_MS);     addNumber(h, "gone", (long)WF_GONE_MS);
  h += F("};");
  return h;
}

// Everything the card shows is drawn here from the state, rendered into the
// page and fetched after each step: one builder, so the two cannot drift.
// The saved networks are rows (five at most, usually one or two), the ones in
// range a select: a list of every neighbour's network made the card 800 px
// tall. The network the scale is on is left out of the select, it has nothing
// to offer there. The first option says what the list is doing. The select
// keeps its choice by name across the polls, so a scan finishing does not
// take it away.
static const char WF_JS[] PROGMEM =
  "let wfD=null,wfSel='';"
  "function wfE(s){const d=document.createElement('div');d.textContent=s;"
  "return d.innerHTML.replace(/'/g,'&#39;');}"
  "function wfF(t,a){let i=0;return t.replace(/%s/g,()=>a[i++]||'');}"
  "function wfSig(r){const b=r>=WFT.b4?4:r>=WFT.b3?3:r>=WFT.b2?2:1;let s='<span class=sig>';"
  "for(let i=1;i<=4;i++)s+='<i style=background:'+(i<=b?(b>=3?'var(--accent)':'var(--warn)'):"
  "'var(--ink-4)')+'></i>';return s+'</span><em>'+r+' dBm</em>';}"
  "function wfRow(n,sub,btns){return '<div class=orow><div class=ol><span class=on>'+wfE(n)+"
  "'</span><span class=os>'+sub+'</span></div><div class=ov>'+btns+'</div></div>';}"
  "function wfBtn(a,i,t,ic){return '<button class=quiet data-a='+a+' data-i='+i+(ic?' data-ic='+ic:'')+'>'+t+'</button>';}"
  "function wfCur(d){return '<div class=row><span class=k>'+WFT.c+'</span><span class=v>'+"
  "(d.on?wfE(d.on)+wfSig(d.rssi):'-')+'</span></div>';}"
  "function wfState(k){return k.c&&k.p?WFT.cp:k.c?WFT.c:k.p?WFT.p:WFT.sv;}"
  "function wfKnown(d){if(!d.known.length)return '<p class=os>'+WFT.none+'</p>';"
  "return d.known.map((k,i)=>wfRow(k.s,wfState(k),"
  "(k.c?'':wfBtn('c',i,WFT.go))+(k.p?'':wfBtn('f',i,WFT.forget,'rm')))).join('');}"
  "function wfList(d){return d.nets.map((n,i)=>({n:n,i:i})).filter(x=>x.n.s!==d.on);}"
  "function wfHead(d){const s=d.scan;return s==='wait'||s==='run'?WFT.scanning:"
  "s==='fail'?WFT.scanfail:s==='done'&&!wfList(d).length?WFT.nonets:WFT.pick;}"
  "function wfOpt(x){const n=x.n;return '<option value='+x.i+'>'+wfE([n.s,n.r+' dBm',"
  "n.k?WFT.saved:'',n.o?WFT.open:''].filter(Boolean).join(' · '))+'</option>';}"
  "function wfNets(d){const el=$('wf-net'),l=wfList(d);"
  "el.innerHTML='<option value=\"\" disabled>'+wfE(wfHead(d))+'</option>'+l.map(wfOpt).join('');"
  "const k=l.find(x=>x.n.s===wfSel);if(k)el.value=String(k.i);else el.selectedIndex=0;wfShow();}"
  // The chosen network, or null while the first line is showing.
  "function wfNet(){const v=$('wf-net').value;return v===''||!wfD?null:wfD.nets[+v];}"
  "function wfNeedsPw(n){return !!n&&!n.k&&!n.o;}"
  "function wfShow(){const n=wfNet();"
  "$('wf-pwrow').style.display=wfNeedsPw(n)?'flex':'none';$('wf-go').disabled=!n;}"
  "function wfSet(d){if(!d)return;wfD=d;$('wf-cur').innerHTML=wfCur(d);"
  "$('wf-known').innerHTML=wfKnown(d);wfNets(d);"
  "$('wf-scan').disabled=d.scan==='wait'||d.scan==='run';}"
  // Own fetch with a time limit: getJson() would wait for a scale that left.
  "function wfGet(){const c=new AbortController();const t=setTimeout(()=>c.abort(),WFT.tmo);"
  "return fetch('/api/wifi',{cache:'no-store',signal:c.signal}).then(r=>r.ok?r.json():null)"
  ".catch(()=>null).then(j=>{clearTimeout(t);return j;});}"
  "function wfScanPoll(){wfGet().then(d=>{wfSet(d);"
  "if(d&&(d.scan==='wait'||d.scan==='run'))setTimeout(wfScanPoll,1200);});}"
  "function wfAway(t){$('wf-away').textContent=t;}"
  "function wfWatch(s,t0){setTimeout(()=>wfGet().then(d=>{const el=Date.now()-t0;"
  "if(d&&d.trySsid===s&&d.try==='up'){wfSet(d);flash('wf-m',wfF(WFT.up,[s]));wfAway('');return;}"
  "if(d&&d.trySsid===s&&d.try==='fail'){wfSet(d);"
  "flash('wf-m',wfF(WFT.fail,[s,d.tryFrom||d.on]),true);wfAway('');return;}"
  "if(!d&&el>WFT.gone)flash('wf-m',wfF(WFT.gonet,[s]),true);"
  "if(el<WFT.gone*3)wfWatch(s,t0);}),WFT.every);}"
  "function wfTry(s,pw){post('/api/wifi/try',JSON.stringify({ssid:s,pass:pw})).then(r=>{"
  "if(!r.json){flash('wf-m',r.text||WS.err,true);return;}"
  "wfSel='';$('wf-pw').value='';wfSet(r.json);flash('wf-m',wfF(WFT.trying,[s]));"
  "wfAway(wfD.url?wfF(WFT.awayn,[s,'http://'+wfD.url+'/config']):wfF(WFT.awaym,[s]));"
  "wfWatch(s,Date.now());});}"
  "function wfAsk(s,pw){ask(wfF(WFT.ask,[s,s]),WFT.go).then(ok=>{if(ok)wfTry(s,pw);});}"
  "function wfForget(s){ask(wfF(WFT.askf,[s]),WFT.forget,true).then(ok=>{if(!ok)return;"
  "post('/api/wifi/forget',s).then(r=>{if(r.json)wfSet(r.json);"
  "else flash('wf-m',r.text||WS.err,true);});});}"
  // A saved network connects without a password; one in range asks for it
  // only when it is neither saved nor open.
  "function wfGo(){const n=wfNet();if(!n){$('wf-net').focus();return;}"
  "const pw=wfNeedsPw(n)?$('wf-pw').value:'';"
  "if(wfNeedsPw(n)&&!pw){$('wf-pw').focus();return;}wfAsk(n.s,pw);}"
  "$('wf').addEventListener('click',e=>{const b=e.target.closest('button[data-a]');"
  "if(!b||!wfD)return;const k=wfD.known[+b.dataset.i];if(!k)return;"
  "if(b.dataset.a==='f')wfForget(k.s);else wfAsk(k.s,'');});"
  // Only a pick by hand changes what is remembered: a scan empties the list
  // for a moment, and the choice has to outlive that.
  "$('wf-net').addEventListener('change',()=>{$('wf-pw').value='';const n=wfNet();"
  "wfSel=n?n.s:'';wfShow();});"
  "$('wf-go').addEventListener('click',wfGo);"
  "$('wf-pw').addEventListener('keydown',e=>{if(e.key==='Enter')wfGo();});"
  "function wfScan(){post('/api/wifi/scan','').then(r=>{"
  "if(r.json){wfSet(r.json);wfScanPoll();}else flash('wf-m',r.text||WS.err,true);});}"
  "$('wf-scan').addEventListener('click',wfScan);";

String configWifiCard() {
  String h;
  h.reserve(1400 + sizeof(WF_JS));
  h += F("<div class='card wide' id='wf'><h2>");
  h += T(STR_W_R_WIFI);
  // The two lists stand apart from the row above and from each other.
  h += F("</h2><div class='rows' id='wf-cur'></div><div class='field' style='margin-top:24px'><label>");
  h += T(STR_WIFI_SAVED_TITLE);
  h += F("</label><div id='wf-known'></div></div><div class='field' style='margin-top:24px'><label>");
  h += T(STR_W_WIFI_INRANGE);
  // A basis of 220 px: below that the buttons move to a line of their own
  // rather than squeezing the network names to two letters on a phone.
  h += F("</label><div class='inrow'><select id='wf-net' style='flex:1 1 220px'></select>"
         "<button id='wf-go'>");
  h += T(STR_W_WIFI_CONNECT);
  h += F("</button><button class='quiet' id='wf-scan' data-ic='re'>");
  h += T(STR_W_WIFI_SCAN_BTN);
  h += F("</button></div><div class='inrow' id='wf-pwrow' style='margin-top:10px;display:none'>"
         "<input id='wf-pw' type='password' maxlength='64' autocomplete='off' placeholder='");
  h += htmlEsc(T(STR_WIFI_PASS_PLACEHOLDER));
  h += F("'></div><span class='msg' id='wf-m'></span><span class='hint' id='wf-away'></span>"
         "<span class='hint'>");
  char hint[320];
  snprintf(hint, sizeof(hint), T(STR_W_WIFI_HINT), (int)(WIFI_TRY_GIVE_UP_MS / 1000UL));
  h += htmlEsc(hint);
  h += F("</span></div></div><script>");
  h += wordsJs();
  h += F(";");
  h += FPSTR(WF_JS);
  // Drawn before the page is shown, from the same state the routes answer.
  // Nothing searched since the start leaves the select with its first line
  // only, a dead end, so the page searches once by itself.
  h += F(";wfSet(JSON.parse(");
  h += jsStr(stateJson().c_str());
  h += F("));if(wfD.scan==='none')wfScan();</script>");
  return h;
}

static void sendState(WebServer &srv) {
  srv.send(200, "application/json", stateJson());
}

static void handleTry(WebServer &srv) {
  JsonDocument doc;
  if (deserializeJson(doc, srv.arg("plain"))) {
    srv.send(400, "text/plain", "bad request");
    return;
  }
  const char *ssid = doc["ssid"] | "";
  const char *pass = doc["pass"] | "";
  if (!ssid[0] || strlen(ssid) >= WIFI_KNOWN_SSID_BYTES || strlen(pass) >= WIFI_KNOWN_PASS_BYTES) {
    srv.send(400, "text/plain", "bad request");
    return;
  }
  if (!wifiRemoteTryRequest(ssid, pass)) {
    srv.send(409, "text/plain", T(STR_W_WIFI_BUSY));
    return;
  }
  sendState(srv);
}

static void handleForget(WebServer &srv) {
  String ssid = srv.arg("plain");
  // Same rule as on the device: the next boot would still use the preferred one.
  if (ssid == wifiPreferredSsid()) {
    srv.send(400, "text/plain", T(STR_WIFI_PREF_KEEP));
    return;
  }
  wifiKnownForgetSsid(ssid.c_str());
  sendState(srv);
}

void configWifiRoutes(WebServer &srv) {
  srv.on("/api/wifi", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    sendState(srv);
  });
  // Carried out on the loop, see services/wifi_remote.h; the page polls.
  srv.on("/api/wifi/scan", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    wifiRemoteScanRequest();
    sendState(srv);
  });
  srv.on("/api/wifi/try", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    handleTry(srv);
  });
  srv.on("/api/wifi/forget", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_SETTINGS))) return;
    handleForget(srv);
  });
}
