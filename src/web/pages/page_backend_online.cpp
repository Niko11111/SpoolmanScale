#include "web/pages/page_backend_online.h"

#include <strings.h>

#include "app/backend_switch.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/backend.h"
#include "services/backend_profiles.h"
#include "web/web_access.h"
#include "web/web_jobs.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro, see page_backend.cpp.
#include "lang.h"

static bool isActive(uint8_t id) { return backendProfileId() == id; }

String backendOnlineTab() {
  String h = F("<button class='btab");
  if (backendProfileIsOnline()) h += F(" on");
  h += F("' id='bt-on' type='button'>");
  h += T(STR_BACKEND_INTERNET);
  h += F(" &rsaquo;</button>");
  return h;
}

String backendOnlineNote() {
  if (!backendProfileIsOnline()) return T(STR_W_BACKEND_NOTE);
  char line[200];
  snprintf(line, sizeof(line), T(STR_W_ONLINE_ACTIVE), backendName());
  return htmlEsc(line);
}

static void addKeyField(String &h, uint8_t id, int hint_str = 0) {
  const bool stored = isActive(id) ? spoolmanAuthActive() : backendProfileHasSecret(id);
  h += F("<div class='field'><label>");
  h += T(STR_W_APIKEY);
  h += F(" &middot; ");
  h += T(stored ? STR_W_SET : STR_W_UNSET);
  h += F("</label><div class='inrow'><input id='ok-");
  h += id;
  h += F("' type='password' autocomplete='new-password' value='");
  h += stored ? F("________________") : F("");
  h += F("'></div>");
  if (hint_str) {
    h += F("<span class='hint'>");
    h += T(hint_str);
    h += F("</span>");
  }
  h += F("</div>");
}

static void addSendRow(String &h, uint8_t id) {
  h += F("<div class='inrow'><button class='on-b' type='button' data-p='");
  h += id;
  h += F("'>");
  h += T(isActive(id) ? STR_W_SAVE : STR_W_ONLINE_CONNECT);
  h += F("</button><span class='msg' id='on-s");
  h += id;
  h += F("'></span></div>");
}

// A service with its address in the table: what it asks for first, then the key.
static void addFixedCard(String &h, const BackendProfile &p) {
  h += F("<p class='hint' style='color:var(--warn)'>");
  h += T(STR_W_ONLINE_PRO);
  h += F("</p>");
  addKeyField(h, p.id, STR_W_ONLINE_KEY_HINT);
  addSendRow(h, p.id);
  if (isActive(p.id)) return;
  h += F("<div class='inrow'><button class='quiet on-a' type='button' data-u='");
  h += htmlEsc(p.account_url);
  h += F("'>");
  h += T(STR_W_ONLINE_ACCOUNT);
  h += F(" &rsaquo;</button></div>");
}

// The free entry: any service that speaks Spoolman's API, in the form it wants.
static void addOtherCard(String &h, const BackendProfile &p) {
  char addr[64];
  backendProfileReadAddress(p.id, addr, sizeof(addr));
  const uint8_t kind = backendProfileReadKind(p.id);
  char user[64];
  backendProfileReadUser(p.id, user, sizeof(user));
  h += F("<p class='hint'>");
  h += T(STR_W_ONLINE_OTHER_HINT);
  h += F("</p><div class='field'><label>");
  h += T(STR_W_ONLINE_ADDR);
  h += F("</label><div class='inrow'><input id='oa-");
  h += p.id;
  h += F("' type='text' maxlength='63' spellcheck='false' "
         "placeholder='https://service.example/api/spoolman' value='");
  h += htmlEsc(addr);
  h += F("'></div><span class='hint' id='oh-");
  h += p.id;
  h += F("' style='display:none;color:var(--warn)'>");
  h += T(STR_W_ONLINE_HTTP);
  h += F("</span></div><div class='field'><label>");
  h += T(STR_W_SM_AUTH_KIND);
  h += F("</label><div class='inrow'><select id='of-");
  h += p.id;
  h += F("' style='min-width:200px'>");
  static const uint8_t KINDS[] = { SM_AUTH_KEY, SM_AUTH_BEARER, SM_AUTH_BASIC };
  static const int     NAMES[] = { STR_W_SM_AUTH_KEY, STR_W_SM_AUTH_BEARER, STR_W_SM_AUTH_BASIC };
  for (size_t i = 0; i < sizeof(KINDS); i++) {
    h += F("<option value='"); h += KINDS[i]; h += F("'");
    if (KINDS[i] == kind) h += F(" selected");
    h += F(">"); h += T(NAMES[i]); h += F("</option>");
  }
  h += F("</select></div></div><div class='field' id='ouf-");
  h += p.id;
  h += F("'");
  if (kind != SM_AUTH_BASIC) h += F(" style='display:none'");
  h += F("><label>");
  h += T(STR_W_SM_USER);
  h += F("</label><div class='inrow'><input id='ou-");
  h += p.id;
  h += F("' type='text' autocomplete='off' spellcheck='false' value='");
  h += htmlEsc(user);
  h += F("'></div></div>");
  addKeyField(h, p.id);
  addSendRow(h, p.id);
}

String backendOnlineCards() {
  String h;
  h.reserve(2400);
  // Hidden until the tab opens them, the rest of the page stays as it was.
  const char *hidden = backendProfileIsOnline() ? "" : " style='display:none'";
  for (size_t i = 0; i < BACKEND_ONLINE_COUNT; i++) {
    const BackendProfile &p = backendProfile(BACKEND_ONLINE_ORDER[i]);
    h += F("<div class='card wide op'");
    h += hidden;
    h += F("><h2>");
    h += p.name ? p.name : T(STR_ONLINE_OTHER);
    h += F("</h2>");
    if (p.fixed_url[0]) addFixedCard(h, p);
    else                addOtherCard(h, p);
    h += F("</div>");
  }
  return h;
}

String backendOnlineScript() {
  String h;
  h.reserve(2400);
  char keeps[200];
  snprintf(keeps, sizeof(keeps), T(STR_W_ONLINE_KEEPS), backendName());
  h += F("const OM={keeps:");
  h += jsStr(keeps);
  h += F(",http:");
  h += jsStr(T(STR_W_ONLINE_HTTP_ASK));
  h += F("};"
         // The tab opens the cards and changes nothing; only a card connects.
         "$('bt-on').addEventListener('click',function(){"
         "document.querySelectorAll('.op').forEach(c=>{c.style.display='';});"
         "if(!this.classList.contains('on')){this.classList.add('open');"
         "$('bm-n').textContent=OM.keeps;}});"
         "document.querySelectorAll('.on-a').forEach(b=>{b.addEventListener('click',()=>{"
         "window.open(b.dataset.u,'_blank','noopener');});});"
         // A key sent without https is the user's call, asked before it goes. A
         // bare address means http, so everything but https counts.
         "function onHttp(a){const v=a?a.value.trim().toLowerCase():'';"
         "return v!==''&&v.indexOf('https://')!==0;}"
         "document.querySelectorAll('[id^=oa-]').forEach(a=>{"
         "const w=$('oh-'+a.id.slice(3));const f=()=>{w.style.display=onHttp(a)?'':'none';};"
         "a.addEventListener('input',f);f();});"
         "document.querySelectorAll('[id^=of-]').forEach(s=>{s.addEventListener('change',()=>{"
         "$('ouf-'+s.id.slice(3)).style.display=s.value==='3'?'':'none';});});"
         "function onSend(id,body){HM='on-s'+id;flash(HM,M.test,false);"
         "post('/api/backend/online',body).then(function(r){"
         "if(!r.ok){flash(HM,r.text||WS.err,true);return;}"
         // After a switch the page is another one. The reload picks the test up.
         "if(r.json&&r.json.sw){setTimeout(function(){location.hash='t'+id;location.reload();},1200);return;}"
         "hostPoll(0);});}"
         "document.querySelectorAll('.on-b').forEach(b=>{b.addEventListener('click',()=>{"
         "const id=b.dataset.p;const k=$('ok-'+id).value;const a=$('oa-'+id);"
         "const f=$('of-'+id);const u=$('ou-'+id);"
         "const body=[id,f?f.value:'',u?u.value:'',a?a.value:'',guard(k)?'1'+k:'0'].join('\\n');"
         "if(onHttp(a)&&k){ask(OM.http).then(ok=>{if(ok)onSend(id,body);});return;}"
         "onSend(id,body);});});"
         "if(location.hash.indexOf('#t')===0){const id=location.hash.slice(2);"
         "history.replaceState(null,'',location.pathname);"
         "if($('on-s'+id)){HM='on-s'+id;flash(HM,M.test,false);"
         "post('/api/backend/test','').then(function(){hostPoll(0);});}}");
  return h;
}

static void startHostTest() {
  if (strlen(backendBaseUrl()) <= 7) return;   // longer than "http://"
  if (webJobState() == WJS_DONE) webJobTake();
  webJobStart(WJ_HOST_TEST, nullptr, false);
}

// The body's next line. pos moves past it.
static String nextLine(const String &body, int &pos) {
  const int nl = body.indexOf('\n', pos);
  String line = nl < 0 ? body.substring(pos) : body.substring(pos, nl);
  pos = nl < 0 ? body.length() : nl + 1;
  line.trim();
  return line;
}

// Body: profile, kind, user, address and the key on five lines. The key's line
// starts with "1" when a new one follows and is "0" to keep the stored one.
static void handleConnect(WebServer &srv) {
  const String body = srv.arg("plain");
  int pos = 0;
  const long id = nextLine(body, pos).toInt();
  const long kind = nextLine(body, pos).toInt();
  const String user = nextLine(body, pos);
  const String addr = nextLine(body, pos);
  const String rest = nextLine(body, pos);
  if (id <= BP_SPOOLMAN || id >= BP_COUNT || rest.length() == 0) {
    srv.send(400, "text/plain", T(STR_W_ERROR));
    return;
  }
  const BackendProfile &p = backendProfile((uint8_t)id);
  char clean[64] = "";
  if (!p.fixed_url[0] && backendCleanHost(addr.c_str(), clean, sizeof(clean)) == 0) {
    srv.send(400, "text/plain", T(STR_W_HOST_EMPTY));
    return;
  }
  // A key belongs to the address it was entered for, and a mistyped address must
  // not receive it. A new address asks for the key again.
  if (rest[0] != '1' && !p.fixed_url[0] && backendProfileHasSecret(p.id)) {
    char host[64];
    char bound[64];
    backendProfileShortHost(clean, host, sizeof(host));
    backendProfileReadBoundHost(p.id, bound, sizeof(bound));
    if (strcasecmp(host, bound) != 0) {
      srv.send(400, "text/plain", T(STR_W_ONLINE_REKEY));
      return;
    }
  }
  const uint8_t form = (kind >= SM_AUTH_KEY && kind <= SM_AUTH_BASIC) ? (uint8_t)kind : p.auth_default;
  const String key = rest.substring(1);
  const char *secret = rest[0] == '1' ? key.c_str() : nullptr;

  bool stored;
  const bool active = backendProfileId() == p.id;
  if (active) {
    if (!p.fixed_url[0] && strcmp(clean, backendHost()) != 0) backendApplyHost(clean);
    stored = backendApplyAuth(form, user.c_str(), secret);
  } else {
    stored = backendProfileStoreOnline(p.id, clean, form, user.c_str(), secret);
  }
  // Refused whole rather than cut: a cut token fails at the server later, with
  // nothing to say why.
  if (!stored) {
    char msg[160];
    snprintf(msg, sizeof(msg), T(STR_W_SM_SECRET_LONG), (unsigned)SM_SECRET_MAX_LEN);
    srv.send(400, "text/plain", msg);
    return;
  }
  logSDf("Web: online service %s saved", p.key);
  if (active) {
    startHostTest();
    srv.send(200, "application/json", "{\"sw\":false}");
    return;
  }
  // The switch itself runs on the loop, as for the backend mode.
  pending_backend_profile = p.id;
  backend_profile_change_pending = true;
  srv.send(200, "application/json", "{\"sw\":true}");
}

void backendOnlineRoutes(WebServer &srv) {
  srv.on("/api/backend/online", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    handleConnect(srv);
  });
  // The same test the address form runs, without a new address. The page asks
  // GET /api/host for the answer.
  srv.on("/api/backend/test", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_BACKEND))) return;
    startHostTest();
    srv.send(200, "text/plain", T(STR_W_SAVED));
  });
}
