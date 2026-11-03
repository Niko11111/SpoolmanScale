// The second server set on the backend page. Most people have one server, so
// until a second one exists the card is a single line with a button: setting
// it up is what switches the feature on, and removing it switches it off
// again - no separate switch that could disagree with the data. Set up here
// and nowhere else; the device only gets a button to switch (later), because
// the person switching may be standing at the printer rather than a computer.
#include "web/pages/page_backend_sets.h"

#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/server_sets.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro, see page_backend.cpp.
#include "lang.h"

// The rows of the table, one per server a set can point at.
enum SetRow : uint8_t { ROW_SPOOLMAN, ROW_FILAMAN, ROW_BAMBUDDY, ROW_ONLINE, ROW_AMS, ROW_COUNT };

static const char *hostOf(const ServerSetView &v, SetRow r) {
  switch (r) {
    case ROW_SPOOLMAN: return v.spoolman;
    case ROW_FILAMAN:  return v.filaman;
    case ROW_BAMBUDDY: return v.bambuddy;
    case ROW_ONLINE:   return v.online;
    default:           return v.ams_source;
  }
}

static const char *rowLabel(SetRow r) {
  switch (r) {
    case ROW_SPOOLMAN: return backendModeName(BACKEND_SPOOLMAN);
    case ROW_FILAMAN:  return backendModeName(BACKEND_FILAMAN);
    case ROW_BAMBUDDY: return backendModeName(BACKEND_BAMBUDDY);
    case ROW_ONLINE:   return T(STR_BACKEND_INTERNET);
    default:           return T(STR_W_C_AMS_SOURCE);
  }
}

// "API key set" for a credential that belongs to an address, joined by dots.
static void addCredential(String &c, int label, bool set) {
  if (c.length()) c += F(" &middot; ");
  c += T(label);
  c += ' ';
  c += T(set ? STR_W_SET : STR_W_UNSET);
}

// Only whether a secret is there is shown, never the secret.
static String credentials(const ServerSetView &v, SetRow r) {
  String c;
  switch (r) {
    case ROW_SPOOLMAN:
      if (v.spoolman_access) addCredential(c, STR_W_C_CREDS, true);
      break;
    case ROW_FILAMAN:
      addCredential(c, STR_W_APIKEY, v.filaman_key);
      addCredential(c, STR_W_DEVICE_CODE, v.filaman_device);
      break;
    case ROW_BAMBUDDY:
      if (v.bambuddy_key) addCredential(c, STR_W_APIKEY, true);
      break;
    case ROW_ONLINE:
      if (v.online_access) addCredential(c, STR_W_APIKEY, true);
      break;
    default:
      if (v.ams_source_key) addCredential(c, STR_W_APIKEY, true);
      break;
  }
  return c;
}

static void addCell(String &h, const ServerSetView &v, SetRow r) {
  const char *host = hostOf(v, r);
  h += F("<td><span class='h'>");
  h += host[0] ? htmlEsc(host) : String("-");
  h += F("</span>");
  const String c = host[0] ? credentials(v, r) : String();
  if (c.length()) {
    h += F("<small>");
    h += c;
    h += F("</small>");
  }
  h += F("</td>");
}

static void addHead(String &h, int label, const char *name) {
  h += F("<th>");
  h += T(label);
  h += F("<b>");
  h += name[0] ? htmlEsc(name) : String("-");
  h += F("</b></th>");
}

// Active and parked side by side. A row that is empty in both sets is left
// out, so someone with FilaMan alone reads one line, not four.
static String table(const ServerSetView &a, const ServerSetView &p) {
  String h = F("<table class='sets'><tr><th></th>");
  addHead(h, STR_W_SETS_ACTIVE, a.name);
  addHead(h, STR_W_SETS_PARKED, p.name);
  h += F("</tr>");
  for (uint8_t i = 0; i < ROW_COUNT; i++) {
    const SetRow r = (SetRow)i;
    if (!hostOf(a, r)[0] && !hostOf(p, r)[0]) continue;
    h += F("<tr><td>");
    h += htmlEsc(rowLabel(r));
    h += F("</td>");
    addCell(h, a, r);
    addCell(h, p, r);
    h += F("</tr>");
  }
  h += F("</table>");
  return h;
}

static void addNameField(String &h, bool parked, const char *name) {
  h += F("<div class='field'><label>");
  h += T(parked ? STR_W_SETS_PARKED : STR_W_SETS_ACTIVE);
  h += F(" &middot; ");
  h += T(STR_W_R_NAME);
  h += F("</label><input id='sn-");
  h += parked ? 'p' : 'a';
  h += F("' type='text' maxlength='24' spellcheck='false' placeholder='");
  h += htmlEsc(T(STR_W_SETS_NAME_PH));
  h += F("' value='");
  h += htmlEsc(name);
  h += F("'></div>");
}

// Names and removal are needed once, so they fold away under one quiet line.
// One save for both names: they are set up together, and a button per field
// left an empty message line under each.
static String editFold(const ServerSetView &a, const ServerSetView &p) {
  String h = F("<details class='more' style='margin-top:6px'><summary>");
  h += T(STR_W_SETS_EDIT);
  h += F("</summary>");
  addNameField(h, false, a.name);
  addNameField(h, true, p.name);
  h += F("<div class='inrow'><button class='quiet' id='sn-b' type='button'>");
  h += T(STR_W_SAVE);
  h += F("</button><span class='msg' id='sn-s'></span></div>"
         "<div class='inrow'><button class='danger' id='ss-d' type='button'>");
  h += T(STR_W_SETS_DELETE);
  h += F("</button><span class='msg' id='ss-ds'></span></div></details>");
  return h;
}

// Switching asks first, like a change of backend: the scale then talks to a
// different inventory. Setting up says that every address will be empty, and
// removing names what goes. The reload shows the result once it is done.
static String script(bool empty, const char *target) {
  char q[200];
  char del[200] = "";
  if (empty) {
    copyT(q, sizeof(q), STR_W_SETS_CREATE_ASK);
  } else {
    snprintf(q, sizeof(q), T(STR_W_BACKEND_ASK), target);
    snprintf(del, sizeof(del), T(STR_W_SETS_DELETE_ASK), target);
  }
  String h = F("<script>(function(){var SS={ask:");
  h += jsStr(q);
  h += F(",del:");
  h += jsStr(del);
  h += F("},RELOAD_MS=1500;"
         "function bind(id,q,url,msg){var b=$(id);if(!b)return;"
         "b.addEventListener('click',function(){ask(q).then(function(ok){if(!ok)return;"
         "post(url,'1').then(function(r){"
         "if(!r.ok){flash(msg,r.text||WS.err,true);return;}"
         "flash(msg,r.text,false);setTimeout(function(){location.reload();},RELOAD_MS);});});});}"
         "bind('ss-b',SS.ask,'/api/backend/swap','ss-s');"
         "bind('ss-d',SS.del,'/api/backend/setclear','ss-ds');"
         "var nb=$('sn-b');if(nb)nb.addEventListener('click',function(){"
         "post('/api/backend/setname','a\\n'+$('sn-a').value).then(function(r){"
         "if(!r.ok){flash('sn-s',r.text||WS.err,true);return;}"
         "postFlash('/api/backend/setname','p\\n'+$('sn-p').value,'sn-s',4000);});});"
         "})();</script>");
  return h;
}

// The table's look, beyond what the shared table rules give: a name under
// each column head, machine strings in mono, credentials as a quiet line.
static const char SETS_CSS[] PROGMEM =
    "<style>.sets th,.sets td{vertical-align:top}"
    ".sets th b{display:block;margin-top:3px;text-transform:none;letter-spacing:0;"
    "font-size:13.5px;font-weight:600;color:var(--ink)}"
    ".sets td:first-child{color:var(--ink-3);white-space:nowrap;padding-right:16px}"
    ".sets .h{font-family:var(--mono);font-size:12.5px;overflow-wrap:anywhere}"
    ".sets small{display:block;margin-top:2px;font-size:11.5px;color:var(--ink-soft)}</style>";

// Nothing parked yet: one line that says what this is for, and the button
// that sets it up.
static String offerCard() {
  String h = F("<div class='card wide'><h2>");
  h += T(STR_W_C_SERVER_SETS);
  h += F("</h2><div class='inrow' style='justify-content:space-between'>"
         "<p class='hint' style='flex:1;min-width:220px'>");
  h += T(STR_W_SETS_OFF_HINT);
  h += F("</p><button class='quiet' id='ss-b' type='button'>");
  h += T(STR_EF_BTN_CREATE);
  h += F("</button></div><span class='msg' id='ss-s'></span></div>");
  return h;
}

static String setsCard(const char *target) {
  ServerSetView a, p;
  serverSetRead(false, &a);
  serverSetRead(true, &p);
  char button[SERVER_SET_NAME_MAX + 96];
  snprintf(button, sizeof(button), T(STR_SETS_SWITCH_TO), target);

  String h = FPSTR(SETS_CSS);
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_C_SERVER_SETS);
  h += F("</h2><p class='hint'>");
  h += T(STR_W_SETS_HINT);
  h += F("</p><div style='margin-top:12px'>");
  h += table(a, p);
  h += F("</div><div class='inrow' style='margin-top:14px'><button id='ss-b' type='button'>");
  h += htmlEsc(button);
  h += F("</button><span class='msg' id='ss-s'></span></div>");
  h += editFold(a, p);
  h += F("</div>");
  return h;
}

String backendSetsCard() {
  const bool empty = serverSetParkedEmpty();
  char target[SERVER_SET_NAME_MAX + 64];
  serverSetParkedLabel(target, sizeof(target));
  String h = empty ? offerCard() : setsCard(target);
  h += script(empty, target);
  return h;
}

void backendSetsRoutes(WebServer &srv) {
  // Only the intent is recorded, as for a change of backend: appLoop() carries
  // it out with everything that has to be let go of on the way.
  srv.on("/api/backend/swap", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    server_set_swap_pending = true;
    logSDf("Web: server set swap asked for");
    srv.send(200, "text/plain", T(STR_W_SAVED));
  });

  // Touches the parked keys only, nothing the scale is talking to, so it is
  // done right here rather than through the loop.
  srv.on("/api/backend/setclear", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    if (!serverSetClearParked()) {
      srv.send(500, "text/plain", T(STR_W_ERROR));
      return;
    }
    srv.send(200, "text/plain", T(STR_W_SAVED));
  });

  // Body: "a" or "p" for the active or the parked set, then the name on a
  // second line. An empty name clears it.
  srv.on("/api/backend/setname", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    const String body = srv.arg("plain");
    const int nl = body.indexOf('\n');
    if (nl != 1 || (body[0] != 'a' && body[0] != 'p')) {
      srv.send(400, "text/plain", T(STR_W_ERROR));
      return;
    }
    if (!serverSetRename(body[0] == 'p', body.substring(nl + 1).c_str())) {
      srv.send(500, "text/plain", T(STR_W_ERROR));
      return;
    }
    srv.send(200, "text/plain", T(STR_W_SAVED));
  });
}
