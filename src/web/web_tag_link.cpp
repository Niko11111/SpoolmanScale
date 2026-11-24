#include "web/web_tag_link.h"

#include "services/tag_link.h"
#include "services/tag_write.h"
#include "web/web_access.h"
#include "web/web_shell.h"

// Last: T() is a macro, and ArduinoJson uses T as a template parameter.
#include "lang.h"

// The body of /api/tag/move: "id,uid,from,fmt,force".
#define MOVE_BODY_FIELDS 5

// Where a request from this page stands, for the poll. OK covers "already
// bound" and "not linked", which are not failures: the tag ends where it was
// meant to either way. "held" and "mismatch" are questions the page asks.
static const char* tagLinkStateName() {
  switch (tagLinkReportData()->code) {
    case TL_NONE:       return "idle";
    case TL_BUSY:       return "pending";
    case TL_OK:
    case TL_ALREADY:
    case TL_UNLINKED:
    case TL_NOT_LINKED: return "ok";
    case TL_HELD:       return "held";
    case TL_MISMATCH:   return "mismatch";
    default:            return "error";
  }
}

// What is running, said by what was asked for.
static void busyText(const TagLinkReport* r, char* buf, size_t n) {
  switch (r->job) {
    case TLJ_UNLINK: copyT(buf, n, STR_W_TL_UNLINKING); break;
    case TLJ_WRITE:  copyT(buf, n, STR_W_TL_CHECKING); break;
    case TLJ_MOVE:   snprintf(buf, n, T(STR_W_TL_MOVING), r->from_spool, r->spool_id); break;
    default:         snprintf(buf, n, T(STR_W_TL_BUSY), r->spool_id); break;
  }
}

// The answers the queue gained with unlink and move, kept apart from the
// link's own so each switch stays readable.
static bool unlinkText(const TagLinkReport* r, char* buf, size_t n) {
  switch (r->code) {
    case TL_UNLINKED:      snprintf(buf, n, T(STR_W_TL_UNLINKED), r->other_spool); return true;
    case TL_NOT_LINKED:    copyT(buf, n, STR_W_TL_NOT_LINKED); return true;
    case TL_NOT_SHOWN:     snprintf(buf, n, T(STR_W_TL_NOT_SHOWN), r->other_spool); return true;
    case TL_ON_FILAMENT:   snprintf(buf, n, T(STR_W_TL_ON_FILAMENT), r->other_spool); return true;
    case TL_WRITE_REFUSED: copyT(buf, n, STR_W_TW_REFUSED); return true;
    case TL_UNLINK_FAILED: snprintf(buf, n, T(STR_W_TL_UNLINK_FAILED), r->other_spool); return true;
    default:               return false;
  }
}

// tag_link.cpp cannot build a sentence in the user's language, so the
// sentence is put together here from its codes and ids.
static String linkMessageBody() {
  const TagLinkReport* r = tagLinkReportData();
  char buf[192];
  if (unlinkText(r, buf, sizeof(buf))) return String(buf);
  switch (r->code) {
    case TL_NONE:    return String("");
    case TL_BUSY:    busyText(r, buf, sizeof(buf)); break;
    case TL_OK:
      if (r->job == TLJ_MOVE) snprintf(buf, sizeof(buf), T(STR_W_TL_MOVED), r->from_spool, r->spool_id);
      else                    snprintf(buf, sizeof(buf), T(STR_W_TL_OK), r->spool_id);
      break;
    case TL_ALREADY: snprintf(buf, sizeof(buf), T(STR_W_TL_ALREADY), r->spool_id); break;
    case TL_HELD:
      snprintf(buf, sizeof(buf), T(r->write ? STR_W_TL_HELD_WRITE : STR_W_TL_HELD), r->other_spool);
      break;
    case TL_MISMATCH: snprintf(buf, sizeof(buf), T(STR_W_TL_MISMATCH), r->spool_id,
                               r->tag_desc, r->spool_desc); break;
    case TL_CHANGED: copyT(buf, sizeof(buf), STR_W_TL_CHANGED); break;
    case TL_NO_TAG:  copyT(buf, sizeof(buf), STR_TW_ERR_NO_TAG); break;
    case TL_NETWORK: copyT(buf, sizeof(buf), STR_LINK_NO_CONNECTION); break;
    default:         copyT(buf, sizeof(buf), STR_W_TL_FAILED); break;
  }
  return String(buf);
}

// A move that took the tag off its spool and then failed leaves it on none.
// The failure alone would read as if nothing had changed.
static String tagLinkMessageLocal() {
  const TagLinkReport* r = tagLinkReportData();
  String msg = linkMessageBody();
  if (!r->unlinked || r->code == TL_OK || r->code == TL_NONE || r->code == TL_BUSY) return msg;
  char buf[256];
  snprintf(buf, sizeof(buf), T(STR_W_TL_HALF_MOVED), r->from_spool, msg.c_str());
  return String(buf);
}

String tagLinkPollJson() {
  const TagLinkReport* r = tagLinkReportData();
  return String("\"linkspool\":") + r->spool_id +
         ",\"linkstate\":\"" + tagLinkStateName() +
         "\",\"linkmsg\":\"" + jsonEsc(tagLinkMessageLocal().c_str()) +
         "\",\"linkjob\":"   + (int)r->job +
         ",\"linkother\":"   + r->other_spool +
         ",\"linkfrom\":"    + r->from_spool +
         ",\"linkwrite\":"   + (r->write ? "true" : "false") +
         ",\"linkfmt\":"     + (int)r->fmt;
}

String tagLinkScript() {
  String h = F("<script>const TL={mvq:");
  h += jsStr(T(STR_W_TL_MOVE_ASK));
  h += F(",mvqw:");  h += jsStr(T(STR_W_TL_MOVE_ASK_WRITE));
  h += F(",mvbtn:"); h += jsStr(T(STR_TAGMOVE_BTN));
  h += F(",unq:");   h += jsStr(T(STR_W_TL_UNLINK_ASK));
  h += F(",unq0:");  h += jsStr(T(STR_W_TL_UNLINK_ASK_ANY));
  h += F(",unbtn:"); h += jsStr(T(STR_W_TL_UNLINK_BTN));
  h += F("};"
         // Asked once per answer the scale gives, like the mismatch question.
         "let tlAsked='';"
         // The page's offer of a second tag follows a write it asked for. A
         // write the check stopped never ran, so the offer goes with it, and
         // comes back once the answer has the write going after all.
         "function tlNoWrite(d){if(d.linkwrite&&['held','mismatch','error'].includes(d.linkstate))tgWroteId=0;}"
         "function tlWrote(d){if(d.linkwrite){tgWroteId=d.linkspool;tgWroteAt=Date.now();tgT2Off=false;}}"
         // The tag belongs to another spool: move it there, for a link or for
         // a write. Yes sends the same request again as a move.
         "function tlHeld(d){if(!d.linkother||!d.linkspool)return;"
         "const k=[d.linkjob,d.linkspool,d.linkother,tgUid].join(',');if(tlAsked===k)return;tlAsked=k;"
         "const u=tgUid,w=d.linkwrite?d.linkfmt:-1;"
         "const q=(d.linkwrite?TL.mvqw:TL.mvq).replace('%d',d.linkother).replace('%d',d.linkspool);"
         "ask(q,TL.mvbtn,false,'ln').then(ok=>{if(!ok)return;"
         "fetch('/api/tag/move',{method:'POST',body:[d.linkspool,u,d.linkother,w,0].join(',')})"
         ".then(r=>r.json()).then(x=>{if(!x.ok)stat('bad',M.lbusy,'');else tlWrote(d);})"
         ".catch(()=>{});after();});}"
         // The answer to a mismatch that was asked during a move goes back as
         // that move, with the mismatch accepted.
         "function tlForce(d,u){const b=d.linkfrom"
         "?['/api/tag/move',[d.linkspool,u,d.linkfrom,d.linkwrite?d.linkfmt:-1,1].join(',')]"
         ":['/api/tag/link',d.linkspool+','+u+',1'];"
         "fetch(b[0],{method:'POST',body:b[1]})"
         ".then(r=>r.json()).then(x=>{if(!x.ok)stat('bad',M.lbusy,'');else tlWrote(d);})"
         ".catch(()=>{});}"
         // Whichever spool holds the tag. The scale shows it when it knows it.
         "function tlUnlink(){if(!tgUid)return;const u=tgUid,m=tgMatched;"
         "const q=m&&m.found?TL.unq.replace('%d',m.id):TL.unq0;"
         "ask(q,TL.unbtn,true,'unl').then(ok=>{if(!ok)return;"
         "fetch('/api/tag/unlink',{method:'POST',body:u})"
         ".then(r=>r.json()).then(x=>{if(!x.ok)stat('bad',M.lbusy,'');})"
         ".catch(()=>{});after();});}"
         "function tlSync(){const b=document.getElementById('tg-unl');"
         "if(b)b.disabled=!tgUid||tgState==='pending';}"
         "document.addEventListener('DOMContentLoaded',()=>{"
         "const b=document.getElementById('tg-unl');if(b)b.addEventListener('click',tlUnlink);});"
         "</script>");
  return h;
}

// Splits "a,b,c" into at most max parts, trimmed. Returns how many it found.
static int splitBody(const String& body, String parts[], int max) {
  int n = 0, start = 0;
  while (n < max) {
    const int c = body.indexOf(',', start);
    parts[n] = c < 0 ? body.substring(start) : body.substring(start, c);
    parts[n].trim();
    n++;
    if (c < 0) break;
    start = c + 1;
  }
  return n;
}

// The write a move waits for: -1 for none, else one of the formats the page
// offers (/api/tagopts). An erase or an empty field is not a write to link.
static bool moveFormat(const String& field, int* fmt) {
  if (!field.length()) return false;
  *fmt = field.toInt();
  return *fmt == -1 || *fmt == TAG_FMT_ACE || *fmt == TAG_FMT_OPENSPOOL ||
         *fmt == TAG_FMT_FILAMAN;
}

static void sendOk(WebServer& srv, bool ok) {
  srv.send(200, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
}

void tagLinkRoutes(WebServer& srv) {
  // "id,uid" or "id,uid,1": the spool, the tag the page was showing when it
  // was asked, and whether a Bambu tag that does not match the spool was
  // accepted. Parked only; tagLinkTick() makes the request on the loop task
  // and refuses if a different tag lies on the reader by then.
  srv.on("/api/tag/link", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;
    if (!srv.hasArg("plain")) { srv.send(400, "application/json", "{\"error\":\"no body\"}"); return; }
    String body = srv.arg("plain");
    const int c = body.indexOf(',');
    const int id = body.substring(0, c < 0 ? body.length() : c).toInt();
    String uid = c < 0 ? String("") : body.substring(c + 1);
    const int c2 = uid.indexOf(',');
    const bool force = c2 >= 0 && uid.substring(c2 + 1).toInt() == 1;
    if (c2 >= 0) uid = uid.substring(0, c2);
    uid.trim();
    sendOk(srv, tagLinkRequest(id, uid.c_str(), force));
  });

  // "id,uid,from,fmt,force": the answer to "the tag belongs to spool #from".
  // fmt is the write that waits for it, -1 for a link alone.
  srv.on("/api/tag/move", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;
    String p[MOVE_BODY_FIELDS];
    int fmt = -1;
    if (splitBody(srv.arg("plain"), p, MOVE_BODY_FIELDS) < MOVE_BODY_FIELDS ||
        !moveFormat(p[3], &fmt)) {
      srv.send(400, "application/json", "{\"error\":\"id,uid,from,fmt,force\"}");
      return;
    }
    sendOk(srv, tagLinkMoveRequest(p[0].toInt(), p[1].c_str(), p[2].toInt(),
                                   fmt, p[4].toInt() == 1));
  });

  // "uid": the tag the page was showing. Taken off whichever spool holds it.
  srv.on("/api/tag/unlink", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_MAINT, T(STR_W_NAV_TAGS))) return;
    String uid = srv.arg("plain");
    uid.trim();
    sendOk(srv, tagUnlinkRequest(uid.c_str()));
  });
}
