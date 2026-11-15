// How to show this web interface inside the backend's own page.
//
// Both backends frame it the same way, and the scale lets exactly the
// configured backend do so (frame-ancestors, web_server.cpp). So the one
// address that matters is the one stored here: the card shows it and says to
// open the backend with exactly that, because the browser compares it
// literally. FilaMan needs its plugin for the sidebar entry, BamBuddy has a
// setting for it.
#include "web/pages/page_backend_embed.h"

#include <stdio.h>
#include <strings.h>

#include "services/backend.h"
#include "services/device_name.h"
#include "services/wifi_manager.h"
#include "web/web_shell.h"

#include "lang.h"

// Always the newest release, so a new plugin version needs no new firmware.
static const char PLUGIN_RELEASE_URL[] =
    "https://github.com/Niko11111/filaman-spoolmanscale-plugin/releases/latest";

// One address with a button that copies it, and optionally a link to it.
static String addressLine(const char *addr, bool with_open) {
  const String a = htmlEsc(addr);
  String h = F("<div class='addrline'><span class='mono'>");
  h += a;
  h += F("</span><button class='quiet' data-ic='cp' data-copy='");
  h += a;
  h += F("'>");
  h += T(STR_W_COPY);
  h += F("</button>");
  if (with_open) {
    h += F("<a href='");
    h += a;
    h += F("' target='_blank' rel='noopener'>");
    h += T(STR_W_OPEN);
    h += F("</a>");
  }
  h += F("</div>");
  return h;
}

static String stepOpenBackend() {
  char line[160];
  snprintf(line, sizeof(line), T(STR_W_EMBED_OPEN_AS), backendName());
  String h = F("<li><div>");
  h += htmlEsc(line);
  h += addressLine(backendBaseUrl(), true);
  h += F("</div></li>");
  return h;
}

static String stepsFilaman() {
  String h = F("<li><div><a href='");
  h += PLUGIN_RELEASE_URL;
  h += F("' target='_blank' rel='noopener'>");
  h += T(STR_W_EMBED_FM_DOWNLOAD);
  h += F("</a> <span class='hint'>&middot; GitHub</span></div></li><li><div>");
  h += T(STR_W_EMBED_FM_UPLOAD);
  h += F("</div></li>");
  return h;
}

// The scale's own address goes into BamBuddy as a link and stays there, so
// the name comes first where there is one: it survives a new IP from the
// router. The IP follows for the devices that do not resolve the name.
static String stepsBambuddy() {
  // The same two lines the status bar shows: the browser address, and the
  // bare IP under it when the first line carries a name.
  char url[96];
  deviceBrowserUrl(url, sizeof(url));
  char alt[48];
  deviceAltAddress(alt, sizeof(alt));
  String h = F("<li><div>");
  h += T(STR_W_EMBED_BB_STEP1);
  h += F("</div></li><li><div>");
  h += T(STR_W_EMBED_BB_STEP2);
  h += addressLine(url, false);
  if (alt[0]) {
    char alt_url[64];
    snprintf(alt_url, sizeof(alt_url), "http://%s", alt);
    h += addressLine(alt_url, false);
  }
  h += F("<p class='hint'>");
  h += T(alt[0] ? STR_W_EMBED_BB_IP : STR_W_EMBED_BB_FIXIP);
  h += F("</p></div></li>");
  return h;
}

// Folding is remembered per browser, so whoever has set it up once can put
// it away. Copying falls back to execCommand: the scale is plain http, where
// navigator.clipboard does not exist. When that fails too, the button says
// so for a moment instead of staying mute.
static String script() {
  String h = F("<script>(function(){var EM={copy:");
  h += jsStr(T(STR_W_COPY));
  h += F(",copied:");
  h += jsStr(T(STR_W_COPIED));
  h += F(",failed:");
  h += jsStr(T(STR_W_COPY_FAILED));
  h += F("},SHOW_MS=1500,KEY='emb_closed',d=document.getElementById('emb');if(!d)return;"
         "try{if(localStorage.getItem(KEY)==='1')d.open=false;}catch(e){}"
         "d.addEventListener('toggle',function(){try{localStorage.setItem(KEY,d.open?'0':'1');}catch(e){}});"
         "function done(b,ok){b.textContent=ok?EM.copied:EM.failed;"
         "setTimeout(function(){b.textContent=EM.copy;},SHOW_MS);}"
         "function copy(b){var txt=b.getAttribute('data-copy');"
         "if(navigator.clipboard&&window.isSecureContext){"
         "navigator.clipboard.writeText(txt).then(function(){done(b,true);},function(){done(b,false);});return;}"
         "var t=document.createElement('textarea');t.value=txt;t.setAttribute('readonly','');"
         "t.style.position='fixed';t.style.top='-1000px';document.body.appendChild(t);t.select();"
         "var ok=false;try{ok=document.execCommand('copy');}catch(e){ok=false;}"
         "document.body.removeChild(t);done(b,ok);}"
         "d.querySelectorAll('[data-copy]').forEach(function(b){"
         "b.addEventListener('click',function(){copy(b);});});})();</script>");
  return h;
}

String backendEmbedCard() {
  if (!backendIsFilaMan() && !backendIsBamBuddy()) return String();
  const char *base = backendBaseUrl();
  if (!base || !base[0]) return String();

  char title[48];
  snprintf(title, sizeof(title), T(STR_W_C_EMBED), backendName());
  String h = F("<details class='card wide' id='emb' open><summary><h2>");
  h += htmlEsc(title);
  h += F("</h2></summary><p class='hint'>");
  h += T(backendIsFilaMan() ? STR_W_EMBED_FM_INTRO : STR_W_EMBED_BB_INTRO);
  h += F("</p>");
  // An https page may not frame the http scale, so with an https address
  // stored there is no step that would work, only the reason.
  if (strncasecmp(base, "https://", 8) == 0) {
    h += F("<p class='note'>");
    h += T(STR_W_EMBED_HTTPS);
    h += F("</p>");
  } else {
    h += F("<ol class='steps'>");
    h += backendIsFilaMan() ? stepsFilaman() : stepsBambuddy();
    h += stepOpenBackend();
    h += F("</ol><p class='note'>");
    h += T(STR_W_EMBED_NOTE);
    h += F("</p>");
  }
  h += F("</details>");
  h += script();
  return h;
}
