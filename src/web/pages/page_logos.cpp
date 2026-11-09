// The makers' logos for the "Mit Logo" label arrangement: what the scale
// holds, and the way to add more.
//
// The logos are trademarks, the firmware is GPL: none is compiled in. The
// browser fetches a PNG from the filament-profiles repository, cuts it to
// one bit and uploads the bits; the scale stores them by the normalised
// vendor name and a label looks that name up. A brand without a logo prints
// its name, so nothing here is required for a label to print.
//
// The names come from the backend: BamBuddy keeps its brand as free text on
// the spool and has no vendor object, which is why the vendor name itself is
// the key.
#include "web/web_pages.h"

#include <Arduino.h>
#include <WebServer.h>
#include <esp_heap_caps.h>

#include "hardware/sd_logger.h"
#include "services/label_logo.h"
#include "web/web_access.h"
#include "web/web_shell.h"
// Last on purpose: T() is a macro and ArduinoJson uses T as a template
// parameter, so lang.h has to come after anything that pulls it in.
#include "lang.h"

static const char* label() { return T(STR_W_NAV_LOGOS); }

// Where the browser fetches a logo: the label logos of MarksMakerSpace's
// filament profiles, 400 px wide, black on transparent. Read by the browser,
// never by the scale. A name the page does not find there is typed in by
// hand or uploaded as a file.
#define LOGO_REPO_URL "https://raw.githubusercontent.com/MarksMakerSpace/filament-profiles/main/logos/label/"

// The page's own look: the preview as paper, the list's rows as lines.
static void styles(String& h) {
  h += F("<style>"
         ".lg-prev{background:#fff;border:1px solid var(--line);border-radius:8px;"
         "padding:8px;min-height:56px;display:flex;align-items:center;justify-content:center}"
         ".lg-prev canvas{max-width:100%;height:auto;image-rendering:pixelated}"
         "#lg-list .row{gap:12px}"
         "#lg-list .v{flex:1}"
         "#lg-list button{padding:5px 12px;font-size:12.5px}"
         "</style>");
}

// What the store holds, with a way to drop one, and what the store is for.
static void listCard(String& h) {
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_LOGO_STORED);
  h += F("</h2><div class='rows' id='lg-list'></div><div class='hint' id='lg-used'></div>"
         "<div class='hint' style='margin-top:8px'>");
  h += T(STR_W_LOGO_INTRO);
  h += F("</div></div>");
}

// A brand, the repository name to fetch, a file of one's own, and the
// preview that shows what will be stored.
static void addCard(String& h) {
  h += F("<div class='card wide'><h2>");
  h += T(STR_W_LOGO_ADD);
  h += F("</h2><div class='field'><label>");
  h += T(STR_W_LOGO_BRAND);
  h += F("</label><input id='lg-brand' type='text' autocomplete='off'>"
         "<span class='hint'>");
  h += T(STR_W_LOGO_KEY_HINT);
  h += F("</span></div><div class='field'><label>");
  h += T(STR_W_LOGO_SLUG);
  h += F("</label><div class='inrow'><input id='lg-slug' type='text' autocomplete='off'>"
         "<button id='lg-fetch'>");
  h += T(STR_W_LOGO_FETCH);
  h += F("</button></div><span class='hint'>");
  h += T(STR_W_LOGO_SLUG_HINT);
  h += F("</span></div><div class='field'><div class='inrow'><label class='filebtn'>");
  h += T(STR_W_LOGO_OWN);
  h += F("<input id='lg-file' type='file' accept='image/png,image/jpeg,image/webp'></label></div></div>"
         "<div class='field'><label>");
  h += T(STR_W_LOGO_PREVIEW);
  h += F("</label><div class='lg-prev' id='lg-prev'></div></div>"
         "<div class='inrow' style='margin-top:16px'><button id='lg-save' disabled>");
  h += T(STR_W_LOGO_SAVE);
  h += F("</button><span class='msg' id='lg-s'></span></div></div>");
}

// The strings the script writes, and what it holds between two steps.
static void scriptStrings(String& h) {
  h += F("<script>var L={del:");
  h += jsStr(T(STR_W_LOGO_DELETE));
  h += F(",errFetch:");
  h += jsStr(T(STR_W_LOGO_ERR_FETCH));
  h += F(",errBig:");
  h += jsStr(T(STR_W_LOGO_ERR_BIG));
  h += F(",errEmpty:");
  h += jsStr(T(STR_W_LOGO_ERR_EMPTY));
  h += F(",needBrand:");
  h += jsStr(T(STR_W_LOGO_NEED_BRAND));
  h += F("};"
         "var REPO='");
  h += F(LOGO_REPO_URL);
  h += F("';var MAXW=");
  h += String((unsigned long)LABEL_LOGO_MAX_W);
  h += F(",MAXH=");
  h += String((unsigned long)LABEL_LOGO_MAX_H);
  h += F(",MAXB=");
  h += String((unsigned long)LABEL_LOGO_MAX_BITS);
  // The bits waiting for the Save button, and the brand they belong to.
  h += F(";var P=null;");
}

// The image in hand, cut to 1 bit and shown: the logo itself defines where
// its ink starts, so the transparent border a PNG carries does not eat the
// box the label gives it. Dark means ink, so a black mark on white paper
// works as well as black on transparency.
static void scriptBits(String& h) {
  h += F(
         "function ink(d,i){"
         "var a=d[i+3];if(a<128)return false;"
         "return (d[i]*299+d[i+1]*587+d[i+2]*114)/1000<128;}"
         // Drops the preview and what it would save: a failed fetch or a
         // changed brand must not leave an older image under the Save button.
         "function clearPreview(){"
         "P=null;$('lg-save').disabled=true;$('lg-prev').innerHTML='';}"
         "function makeBits(im,vendor){"
         "clearPreview();"
         "if(!im.naturalWidth||!im.naturalHeight){"
         "flash('lg-s',L.errEmpty,true);return;}"
         "var c=document.createElement('canvas');"
         // A photo straight off a camera is far more pixels than a logo needs:
         // cap the source before reading it, or the browser builds an
         // imageData of hundreds of megabytes.
         "var k=Math.min(1,1600/Math.max(im.naturalWidth,im.naturalHeight));"
         "c.width=Math.max(1,Math.round(im.naturalWidth*k));"
         "c.height=Math.max(1,Math.round(im.naturalHeight*k));"
         "var x=c.getContext('2d');x.drawImage(im,0,0,c.width,c.height);"
         "var d=x.getImageData(0,0,c.width,c.height).data;"
         "var x0=c.width,y0=c.height,x1=-1,y1=-1,y,px;"
         "for(y=0;y<c.height;y++){for(px=0;px<c.width;px++){"
         "if(!ink(d,(y*c.width+px)*4))continue;"
         "if(px<x0)x0=px;if(px>x1)x1=px;if(y<y0)y0=y;if(y>y1)y1=y;}}"
         "if(x1<0){flash('lg-s',L.errEmpty,true);return;}"
         // The ink box is what the label gets; a source larger than a logo
         // may be is scaled down instead of turned away. Rows pad to bytes,
         // so the byte budget sets the scale as well as the two sides.
         "var w=x1-x0+1,h=y1-y0+1;"
         "var s=Math.min(1,MAXW/w,MAXH/h,Math.sqrt(MAXB*8/(w*h)));"
         "var tw=Math.max(1,Math.floor(w*s)),th=Math.max(1,Math.floor(h*s));"
         "while((((tw+7)>>3)*th)>MAXB){"
         "tw=Math.max(1,tw-1);th=Math.max(1,Math.floor(h*tw/w));}"
         "if(tw>MAXW||th>MAXH||(((tw+7)>>3)*th)>MAXB){"
         "flash('lg-s',L.errBig,true);return;}"
         "var tc=document.createElement('canvas');tc.width=tw;tc.height=th;"
         "var tx=tc.getContext('2d');"
         "tx.imageSmoothingEnabled=true;tx.imageSmoothingQuality='high';"
         "tx.drawImage(c,x0,y0,w,h,0,0,tw,th);"
         "var td=tx.getImageData(0,0,tw,th).data;"
         "var rb=(tw+7)>>3,bits=new Uint8Array(rb*th);"
         "for(y=0;y<th;y++){for(px=0;px<tw;px++){"
         "if(!ink(td,(y*tw+px)*4))continue;"
         "bits[y*rb+(px>>3)]|=128>>(px&7);}}"
         "var pc=document.createElement('canvas');pc.width=tw;pc.height=th;"
         "var pcx=pc.getContext('2d'),pim=pcx.createImageData(tw,th);"
         "for(y=0;y<th;y++){for(px=0;px<tw;px++){"
         "if(!(bits[y*rb+(px>>3)]&(128>>(px&7))))continue;"
         "var q=(y*tw+px)*4;pim.data[q]=0;pim.data[q+1]=0;pim.data[q+2]=0;pim.data[q+3]=255;}}"
         "pcx.putImageData(pim,0,0);"
         "var host=$('lg-prev');host.innerHTML='';host.appendChild(pc);"
         "P={vendor:vendor,w:tw,h:th,hex:hexOf(bits)};"
         "$('lg-save').disabled=false;}"
         "function hexOf(b){var s='',i;"
         "for(i=0;i<b.length;i++){var h=b[i].toString(16);s+=h.length<2?'0'+h:h;}"
         "return s;}");
}

// Fetching from the repository, and reading a file of one's own: both end in
// the same preview, and the brand is what the logo is stored under.
static void scriptLoad(String& h) {
  h += F(
         "function wantBrand(){"
         "var b=$('lg-brand').value.trim();"
         "if(!b)flash('lg-s',L.needBrand,true);"
         "return b;}"
         "function decode(u,vendor,cb){"
         "var im=new Image();"
         "im.onload=function(){URL.revokeObjectURL(u);makeBits(im,vendor);cb&&cb();};"
         "im.onerror=function(){URL.revokeObjectURL(u);flash('lg-s',L.errFetch,true);};"
         "im.src=u;}"
         // The repository names some makers with a hyphen where the brand has
         // a space, so the built name is tried both ways: "Bambu Lab" finds
         // "bambulab" or "bambu-lab". A name typed in is used as it stands.
         "function slugList(vendor){"
         "var b=vendor.toLowerCase()"
         ".replace(/ä/g,'ae').replace(/ö/g,'oe').replace(/ü/g,'ue').replace(/ß/g,'ss');"
         "var flat=b.replace(/[^a-z0-9]/g,'');"
         "var hy=b.replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'');"
         "return hy&&hy!==flat?[flat,hy]:[flat];}"
         "function trySlug(vendor,slugs,i){"
         "if(i>=slugs.length){flash('lg-s',L.errFetch,true);return;}"
         "fetch(REPO+encodeURIComponent(slugs[i])+'.png',{cache:'no-store'})"
         ".then(function(r){if(!r.ok)throw 0;return r.blob();})"
         ".then(function(b){decode(URL.createObjectURL(b),vendor);})"
         ".catch(function(){trySlug(vendor,slugs,i+1);});}"
         "function fetchLogo(){"
         "var vendor=wantBrand();if(!vendor)return;"
         "var slug=$('lg-slug').value.trim();"
         "clearPreview();flash('lg-s','');"
         "trySlug(vendor,slug?[slug]:slugList(vendor),0);}"
         "function ownFile(f){"
         "var vendor=wantBrand();if(!vendor)return;"
         "clearPreview();decode(URL.createObjectURL(f),vendor);}");
}

// The list as the store has it, and the two writes: save the preview, drop
// one entry. A key is shown as stored, so a brand spelled differently in the
// backend stands out before the label prints without its logo.
static void scriptPage(String& h) {
  h += F(
         "function paint(d){"
         "var host=$('lg-list');host.innerHTML='';"
         "$('lg-used').textContent=Math.round(d.used/1024)+' kB / '+Math.round(d.cap/1024)+' kB';"
         "if(!d.items.length){var p=document.createElement('div');p.className='hint';"
         "p.textContent=");
  h += jsStr(T(STR_W_LOGO_NONE));
  h += F(";host.appendChild(p);return;}"
         "d.items.forEach(function(it){"
         "var row=document.createElement('div');row.className='row';"
         "var k=document.createElement('span');k.className='k';k.textContent=it.key;"
         "var v=document.createElement('span');v.className='v';"
         "v.textContent=it.w+' × '+it.h+' · '+Math.round(it.bytes/1024*10)/10+' kB';"
         "var b=document.createElement('button');b.className='danger';b.textContent=L.del;"
         "b.addEventListener('click',function(){"
         "ask(L.del+'?',L.del,true).then(function(ok){if(!ok)return;"
         "postFlash('/api/label/logos/delete?vendor='+encodeURIComponent(it.key),'','lg-s',4000).then(load);});});"
         "row.appendChild(k);row.appendChild(v);row.appendChild(b);host.appendChild(row);});}"
         "function load(){getJson('/api/label/logos').then(function(d){if(d)paint(d);});}"
         "$('lg-fetch').addEventListener('click',fetchLogo);"
         "$('lg-brand').addEventListener('input',clearPreview);"
         "$('lg-file').addEventListener('change',function(){"
         "var f=this.files&&this.files[0];this.value='';if(f)ownFile(f);});"
         "$('lg-save').addEventListener('click',function(){"
         "if(!P)return;"
         "var u='/api/label/logos?vendor='+encodeURIComponent(P.vendor)+"
         "'&w='+P.w+'&h='+P.h;"
         "postFlash(u,P.hex,'lg-s',6000).then(function(r){if(!r.ok)return;"
         "P=null;$('lg-save').disabled=true;$('lg-prev').innerHTML='';load();});});"
         "load();"
         "</script>");
}

static String body() {
  String h;
  h.reserve(9000);
  styles(h);
  h += F("<div class='grid'>");
  listCard(h);
  addCard(h);
  h += F("</div>");
  scriptStrings(h);
  scriptBits(h);
  scriptLoad(h);
  scriptPage(h);
  return h;
}

// A body of hex digits, one bit per dot as label_logo.h has it.
static int hexDigit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool parseHex(const String& body, uint8_t* out, size_t n) {
  if (body.length() != n * 2) return false;
  for (size_t i = 0; i < n; i++) {
    const int hi = hexDigit(body[i * 2]), lo = hexDigit(body[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)(hi << 4 | lo);
  }
  return true;
}

// The size the page says it sends, or 0 when it is not one a logo can have.
static size_t logoBytesFrom(long w, long h) {
  if (w <= 0 || h <= 0 || w > LABEL_LOGO_MAX_W || h > LABEL_LOGO_MAX_H) return 0;
  const size_t bytes = (size_t)((w + 7) / 8) * h;
  return bytes <= LABEL_LOGO_MAX_BITS ? bytes : 0;
}

static void sendOk(WebServer& srv, bool ok) {
  srv.send(ok ? 200 : 400, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
}

static void routes(WebServer& srv) {
  srv.on("/api/label/logos", HTTP_GET, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LOGOS))) return;
    String j;
    j.reserve(400 + labelLogoCount() * 90);
    j += F("{\"used\":");
    j += String((unsigned long)labelLogoUsedBytes());
    j += F(",\"cap\":");
    j += String((unsigned long)labelLogoCapacityBytes());
    j += F(",\"items\":[");
    for (int i = 0; i < labelLogoCount(); i++) {
      LabelLogoInfo info;
      if (!labelLogoAt(i, &info)) continue;
      if (i) j += ',';
      j += F("{\"key\":\"");
      j += jsonEsc(info.key);
      j += F("\",\"w\":");
      j += String(info.w);
      j += F(",\"h\":");
      j += String(info.h);
      j += F(",\"bytes\":");
      j += String((unsigned long)info.bytes);
      j += '}';
    }
    j += "]}";
    srv.send(200, "application/json", j);
  });

  srv.on("/api/label/logos", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LOGOS))) return;
    const long w = srv.arg("w").toInt(), h = srv.arg("h").toInt();
    const size_t len = logoBytesFrom(w, h);
    const String vendor = srv.arg("vendor");
    if (!len || !vendor.length()) { sendOk(srv, false); return; }
    // The body is all the bits as hex. Check its length before arg("plain")
    // has the library read and buffer it.
    if (srv.clientContentLength() != len * 2) { sendOk(srv, false); return; }
    uint8_t* bits = (uint8_t*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
    if (!bits) bits = (uint8_t*)malloc(len);
    if (!bits) { sendOk(srv, false); return; }
    const bool ok = parseHex(srv.arg("plain"), bits, len) &&
                    labelLogoPut(vendor.c_str(), LabelLogo{ bits, (uint16_t)w, (uint16_t)h });
    heap_caps_free(bits);
    if (!ok) logSDf("Web: logo for %s not stored", vendor.c_str());
    sendOk(srv, ok);
  });

  srv.on("/api/label/logos/delete", HTTP_POST, [&srv]() {
    if (!webRequire(srv, GATE_CONFIG, T(STR_W_NAV_LOGOS))) return;
    sendOk(srv, labelLogoDrop(srv.arg("vendor").c_str()));
  });
}

extern const WebPage PAGE_LOGOS;
const WebPage PAGE_LOGOS = {
  "/logos", label, GATE_CONFIG, nullptr,
  body, routes
};
