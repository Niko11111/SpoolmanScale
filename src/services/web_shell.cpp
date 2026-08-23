#include "web_shell.h"

#include <string.h>

#include "app_config.h"
#include "backend.h"
#include "web_access.h"

// Lifted verbatim from the original firmware-update page so nothing about the
// look changes -- it is now just shared instead of duplicated.

// The project logo, also served decoded from /favicon.jpg so the browser tab
// carries the real mark instead of a generic globe.
static const char LOGO_B64[] =
  "/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCACWAJYDASIAAhEBAxEB/8QAHAAAAQUBAQEAAAAAAAAAAAAAAAECBAYHBQgD/8QAQRAAAQIFAgMFBQQHBwUAAAAAAQIDAAQFBhESIQcxQRMiUWFxFEKBkfAVMqGxCBYjJXLB0VJic4KSsuEzNlN0k//EABsBAAICAwEAAAAAAAAAAAAAAAABBAUCAwYH/8QALBEAAgEEAgEDAgUFAAAAAAAAAAECAwQRIQUSMRNBUSIyFDNxoeFhgbHw8f/aAAwDAQACEQMRAD8A8rwQQRtEJBCwQgGwQ4gQ2EMIII6FAotVr9UZplGp8zPzjxwhlhGpRHUnoEjO6iQB1IgFg58LG10jg5RaXLpevS4dTxwTKUxaQhO/JT6wdX+RIxvuecdOZsDhtPslmVaqMmvGEvJnnl4PjhwFJ+UaJXVKLw2SIWdaazGLMAgMW/iHYk/aLjcx26Z6lvq0szSE6cK6IWOQV4EbHy5RUI3pqSyjQ04vDEghxhMQCGwkOMJAAkEEEABBBBAB9YIXEJDAIIIIACDEEKkalBIzknGAMk+QHU+XWADq2hbVYuuuMUaiS6HZl3Kit1WlpltO63XFe62kbk+gGSQDvlLapdl0pdq2iTMzLgBqdUcRhyZV/eHuoGToZBwBurKiTEek0h3hxZbNBlGwbnrQQ7VVEgmWGAUsZHut5yr+04o9BgSaXINyUvpTqKjlSlHcqVzJPnFHyd+6a6Q8nUcJxMauK1bx7IY1KYcMw8tT7vVxzdX/ABEgggAjlyBxiHrBA2yOZhDggknl6Ryc3KTzJ7O4hTgo4itESpSTNSpsxS5xPaSswkBbeeeDkEeBBAIPMERmtX4T1xxxx22W3qu0k95kJw4jy1bIPxKT6xvtOt+TkZZucroU4+4ApqQB04B5KdI72DzCBgnrgHESpurKKEtK0NyzYwhpACGkDySMAfW8dJxVG7glJyxH4f8AujiecurGcnCEe0vla/6eU67ZF30SX9pqtt1OVYHNwtBaU+pQVY9TgRXuYBGCCMgjrHsiXnSF4cASCcbD6+X0cd462FJS8m5d1CYSwgKH2hLNp7neOO2SBsnc97GxB1dDnoFP5OWaMYMJDuRhIzENhIcYQjeABIIDBAB94SHGEhjEMJCmEgEEad+jzRJeaumZueotJckLdaTNaV7pcmlEiXQR1AUFOH/DT4xmSQVKCQNycCNzoMv9i8GKLS0Dspy4X11F453KFns2fkygnH94xouanp03Ik2dB160YfJ2KOt+p1Kbr80pThmVHSF/eCM8z6kk+pMdo4AJSkAZxv6xApuGJYNpGBgDHlgRKLgyG0nHr6xxFSt6s22ej/hnTiox9gKQpOwKvj5RZrXkmaZIprc42lT61EU9pwZGUnBeI6gHZI6qBPICOdb1NRUKg0ytZbaAU6+5/wCNpIBWv5bDzIibcFR9tnFLabSyykBDTKeTSEjCUAeQ/EnbeLLjLONafqSWl/n+Cj5nk6lCn6EXuX7L+SNOzjsy+pTyypSlFSlKOSSeZJPP65dYoUTu7qAzzwee34/j/FiHSzBm1YSQkJIKlYBA6j128Nue+DiOo1JyzYCS0lZxzcGomOlOOOWha0n9oMgbJA5Y/LHLy9N8SvZ2KlTpumzY7VubZUy4lQ2UFJx/P+sOqTLbWHkpwlRCSANknoR4dfwhtMKfaUEDfWMQCPIr7Dsq+5LPf9Vhamlk9VIJST8wYZHTuzH611nHL7Smsf8A2XHMjcYjTCQ4wQDGHlBCwQAfcw3EOMJDEJCQsITAA13PYOkEpKW1EEdCEkx6IvgNS9202jMgJl6VJtsNJHuhtpCMD5qjzs8Myz3+Er8jG635MlPEWYd1ZDgJB8jpP5ERXcmm6DwXXA9VeRbLFLrSpCNQHLc/CJLakYGoBRHIY84r8rOfs058N4ntzelJcGCEjOPHrHHOOD0dfUX6m/u+01zITh2ou6ABzDLR3/1OH4hMcYp1LAbGrWrGOfX+X9eRjs3An2RErIJUcSkq0yd+aggKUf8AUoxyacNU6lQ3GCojnjw+vIYJ5R2VnR9GhGH9P39zy7krj8RdTqe2dfotIj3jU36JQFmnhBm1ghoqGQD1WR19OpjzXLVWuNXu1PuVKdcqKJlKi6p5RK8qG3PGDywBjyjUuL9yOydzOU0A6W5ZpaR46tX9Pwir8LrbmLiu5FRfaIlZZYW4rG2RyH15RKRAN+m1l2mpUoAKXoVjz5mPlTtDep5ZCUNp1k+GBmCpuAutMJONJ1Hbby+vTxit8S6qaPYNRUhRTMTifZGMHcKc2J+Ccn4RnTh3koik8LJ53r8vOtVGYmpxkpTMvuPJcSdTatayrZQ2971jnRcqdMvEezbLZUO+hQynHoYrNdaZl6q83LthprYpQDsnI5DyibXt1TXZPRGoV+76tbIZhDCHJhD6xEJQEwQQQCJBhphVGEMMYkJ1hTEilyyZypysotam0PvobUpPNKSoAkeeM488QLbwJvCyRikKSUrB0qGD5iNLman9q2/Sa3q1zDLKZeb8e1bSEKJ/iSELHkYux4e2HVpNCafIIZUgYBbeWhw/xEHKj5mIZsaj0aRm5VtE4x2+DrU+pwBQ5HBOM9PSJNTjZ1IuLwRrfloUZqaTyciQnUONJUhQ5ZGI6tLmNc5LtqPdU+hJ9FKAMZrMTE/RXldo1mXQrca0gjzAzHcotyysw2Jlp0K7Ihekc8pOcY+Ecje8bVtpYktHo/HczSu44i9noC5Vl2rTSsbl1f8AuOI5kgtLc2gnACgU/Hb+ePnE6orTMKM02oFLh1pI6hXeH5xy3U946k4HUfXy+HpF8vBwktPDPnc9n0K4ptmbqcs6ZhlOgONOlBUnOdKscxnOPDJ8THSkpem0SRRKSUu3LtJHdbbAyfE784iCafSjHbrxv1Bx8SM/j8RDMal5Vk598nJP19eMZJGJ9ElTzxKyCsnfA29fr/mMh4qXAmtXAmnSyguTpmUBQ5KeP3z/AJRt8VeEWriPc5pUn9mU13NSmU7rG/YIPNR8/AdT47mMyk5ZEu2lShsPugnJUepPj4k9TFlZUXnuyHdVUl1PrLNhhrHvq3PkPCKtcav3w7v7qfyi0lRJyeZioXIv98vDPup/KN97+Wv1NFnup/YiZ84MiPmFecLqirLIfkQQzMEGAJZhIWEMAxOsT7c/7gp3/tN/7hEDrEmkPIl6vKTDqiltt9ClHwAUMmMofcjCe4s2aVmFtKSpDhbeG/dO8d+SuJSkBmpNh5vlqA3EVNsys+yl6WfQtkhOFNEYODnfHygW5MNrRrOtGpWVeXTbpiOi0znMfBYLgsyiXHLqek1oCyOQA5+kZPcNg1SiTJmGELRg7Lb5fXkY0OVmXGlh1hxSDzyDHfkribcQGKkyHEnbWB+ca6lKM1iSyb6VxOk8p4IfBi5hU6Ii3qmsoqcm3pQFbF1ofdUPEgYBHl4GLnMSym1E9c8+cVGftOl1BxM9SXS0+k60LZVpUg+II5GIhuutSqFS32hTp8t90uOpKFn1Kdj8hFZVsGt0/BY07+M39fkuOnCSVDu8iQIqV2Xi1T0OSVKUiYmyMFfNDO3XxPkPnFYrlwVifCm5meS0yeaGe4D6nOTFfLzbezSQSORI2HwjKjY7zMKl4sYgKpB1rmptxTrrqitSlHKlnxMfJaytRUo/LpDFrUtWpSiSesQ6hUJWRa1zLoTnkkbqV6CLBuMF8Ig/VN/LJucxSq+8h6sPqbOpIwnI5ZA3hlWuCanSW2My7J2wk95Xqf6Rzm9kiKy6uFUXWPgsLag4PMvJ9wYeFGPiDDgYhEs+oUCN4IZBDA6KjCGAwQAIYSFPOEEAMfITlQpcx7RTppxhROVJBylXqnkYutDvyVf0sVdoSjp27VO7Z9f7MUjMfNxCVDeJVKtOn9r0RqtvCr9yNnAZebDrK0kKOoLSQQdtoUKKCEae4E51c8knl+PWMdpVTqVHc1SEwUt57zKt21fDp8IvNBvWQnClmfHsMwTjvHLaj5H+RixpXcJ6emV1W1qQ8bRaJideZp025KvraWlpe6T5GKcFnAOTkgRaJ4tClzakAHW0sgjkdoqiT+zT44ESJeTRDGNClXWGOuobQpxxaUITuVKOAI5VWrspJZbQe3eHuJOw9TFTqVRm6g5qmHO6D3UDZKfhEKtdRhpbZNpW0p7ekd2rXMBlqnp1Hl2qht8B/WK0846+6XXlqcWrmVHJhEpPhDwgxW1KsqjzJlhCnGmsRQ1Ij7JhAnrDwkxqbybEJDkwoEOAgSAByggggA6J5wkLCGABQlSj3UlXoMwikqScKBB8xG+/o4WnQKzw/uWrS9pUW8bulJxDcpSqlMhKPZy2glYSdslXaDJ5lGMjEco8OZ/iFxBrEiLao/DBdGpLcxNyTjbi2VHWvLoI0gAjG41JwnnnMY9hmLcoDuY1mq8DqwqrWsxa9xUW5KbczzsvJ1KVKkModbSpSwsEqOAlCzkdUEEA4hLx4Jz9No32rbNz0W7GWqo3Sp1EiFNLlppa0toQrUoggrUlJORjIOCIzVQxwZIRkQx1nIwpPPyja7q4A1ClW/XHJC8KDV67QpL2mq0eUS4HpdJQVbKJOogbjupzjpmLjf3CGmXVeNn0C2GqNbinrSVUZp1MnhDykqbBUoIKSVHX94+cN1EwwzzbTatVKa0tiWfK5daSksubp3HTw+EfCpVepTLYaSBLoxhWg7q+Mbu3+j9TXZGmVVPFe1VUipu+yyk4mXcKX5nUU9k3+0wo5ChzHLlFZlOEUlL3nXrXuq/qDb85SphDTaH2HHVTaVI1hxtIUk6dJGc5wcjpmMvXl16p6MPRjntjZi4ZVD0MknGMmN7Y/R2qyr6rtszNy0iVRSqa1UhOuMuFp1lwqAJGrKMaFZyVRJp/CC37XvmyajXrjo9wWbXXnEInWtTDC3UtqLbSypZOhawkZB6EEDMauyNmDAjLOITlba0jxKSIQIEbPxPpF7MybFIqvCm1qOZ6aaZlZ+k0cNhbhWAlCJhDqk4USB38Eg+uK/elh21a76qXNcQae/WpWablp+VYpcyWpc6gHT2/3V9mCSQACdJA3gygM5xCjB3BB8wcxolz8PqVL2FUbttq7JevyNPW01OJ+zJiTUjtiUtrR2pw4nUMHGMc4unFWwadPcUL3q87UZC1rYpEzKsuTPsa3QXXZdrQ02y1gqJ7yjyAG++Tg7BgwjEGItHEK03bTqsqwmoS1Skp+RZqEhOMIUhMxLu50K0K7yT3SCk7jHnFaxGS2A3EEOxBABMhDCkwkIC+8L0cOOwefuu5bwoNWafzKv0ZhKkhrQnPeCStK9WrkQMYj0PY1/0PiFfF2vSjVSao1Ns72NU082n2uYRrWVukZO+OQODnOeceO4lU+pVCndv9n1Cdk/aGi097PMra7RB91WkjUPI5EYuOQyb1I8YbKsg2JRLKYrVYoVAm5icnZmbbS0/MduhxJShJwNu1KsnSO6ACckxHqnE6wrOtmdp3DpFbqs1V7hYrc2uotCXQwG3UO9inIyclATnBwFEk7AHAhgDAGAOQgg6jPSdwcV+Gskq9bytlVffum8JBMq5JTksES8mrs9GrWNlAbE4Ks422MT6Xxr4eNXRbNwOvVptyTtV+kTTHsBUG3D2JTgg97dC9xkYA5Z38uGEg6gazTb/oEtwRsK03DOfadEuUVKdSJclAYDy15Srko4UNhvGnS3Guw3rlvyYRVK9Ql1mclpiSq8lTQ5MhpuXaQprStKtHeQvmMYXkbx5aEIYfVAepqxxt4dzFzV6usTFa11i1U03snKerLbyFOFIJGxz2m5BI2jNZ68bLrnB/h/Y1VnqtJLpUy8qpvS8h2pbSpt0J0BWzneUkEDoT4RkUJC6oDYJW7rSsKzZ2j2vXKzc8xPT8hOIRMSKpKVlBKzCX9kqJy4sjSSkYxz8/jW6pwxTxATxClanVKimZrbdSft+ZpJSUhbmt5Cnyvs14UVKSBscAZxvGSmEh9RG8cQr/ALdrdjXnb8zf9frr1YLc1TEv0UsMSYae1pl8as5UDgrxpASPQ9ZzjFbr9yXixTLlrVAl66/KT8nV2KX2q5d1thLTjLjKslSSEjCh1/HzhiG4g6gXHi7XVV65mn/1uqV0oYlENJnZ2REqoHUoqQlvokZBBPPJ8Ipu0GIBGSWACCAwQASYMQQQhhiCCCABIMQQQDQYhMQQQCCA8swQQAJBiCCAAxCEQQQAJiDHSCCMhCEQ3rBBCGLzggggEf/Z";

const char* webShellLogoBase64() { return LOGO_B64; }

String webShellHead(const char *subtitle) {
  char ver_buf[20];
  strncpy(ver_buf, FW_VERSION, sizeof(ver_buf)-1);
  ver_buf[sizeof(ver_buf)-1] = '\0';
  String html;
  html += "<!DOCTYPE html><html><head>"
      "<meta charset='utf-8'>"
      "<link rel=\"icon\" type=\"image/jpeg\" href=\"/favicon.jpg\">"
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<title>SpoolmanScale - " + String(subtitle) + "</title>"
      "<style>"
      "*{box-sizing:border-box;margin:0;padding:0}"
      "body{background:#06080f;color:#e8f0ff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
      "min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:32px 16px}"
      ".logo{font-size:32px;font-weight:700;color:#28d49a;letter-spacing:-0.5px;margin-bottom:4px}"
      ".logo span{color:#e8f0ff}"
      ".version{font-size:13px;color:#2a4060;margin-bottom:32px}"
      ".card{background:#0c1828;border:1px solid #1a3060;border-radius:14px;padding:28px;"
      "width:100%;max-width:480px;margin-bottom:20px}"
      ".card h2{color:#28d49a;font-size:16px;font-weight:600;margin-bottom:16px;"
      "display:flex;align-items:center;gap:8px}"
      ".card h2::before{content:'';display:inline-block;width:3px;height:16px;"
      "background:#28d49a;border-radius:2px}"
      ".links{display:grid;grid-template-columns:1fr 1fr;gap:10px;width:100%;max-width:480px}"
      ".link-btn{display:flex;align-items:center;justify-content:center;gap:8px;"
      "padding:12px 16px;border-radius:10px;text-decoration:none;"
      "font-size:14px;font-weight:500;transition:opacity .2s;border:1px solid}"
      ".link-btn:hover{opacity:0.8}"
      ".link-kofi{background:#1a2800;color:#a0d840;border-color:#2a4010}"
      ".link-github{background:#0a1828;color:#28d49a;border-color:#1a3060}"
      ".link-discord{background:#12103a;color:#8090ff;border-color:#2a2860}"
      ".link-maker{background:#1a0a18;color:#c060e0;border-color:#2a1a38}"
      ".footer{margin-top:24px;font-size:11px;color:#1a3060;text-align:center}"
      "</style></head><body>"
      "<img src='data:image/jpeg;base64," + String(LOGO_B64) + "' style='width:120px;height:120px;border-radius:12px;margin-bottom:8px'>"
      "<div class='version'>" + String(ver_buf) + " &nbsp;|&nbsp; " + String(subtitle) + "</div>";
  return html;
}

String webShellPageCss() {
  String html;
  html += "<style>"
      "input[type=file]{width:100%;padding:12px;background:#06080f;border:1px dashed #1a3060;"
      "border-radius:8px;color:#4a6fa0;font-size:14px;margin-bottom:16px;cursor:pointer}"
      "input[type=file]:hover{border-color:#28d49a}"
      ".btn-flash{width:100%;padding:14px;background:#1a3020;color:#40c080;"
      "border:1px solid #2a5030;border-radius:8px;font-size:16px;font-weight:600;"
      "cursor:pointer;transition:background .2s}"
      ".btn-flash:hover{background:#2a5030}"
      ".hint{font-size:12px;color:#2a4060;margin-top:10px;text-align:center}"
      ".log-row{display:flex;align-items:center;justify-content:space-between;"
      "padding:10px 12px;background:#06080f;border:1px solid #1a3060;border-radius:8px;"
      "margin-bottom:8px}"
      ".log-name{color:#c8d8f0;font-size:14px;font-family:monospace}"
      ".log-actions{display:flex;gap:6px}"
      ".log-btn{padding:6px 14px;background:#0a1828;color:#28d49a;border:1px solid #1a3060;"
      "border-radius:6px;font-size:13px;text-decoration:none;cursor:pointer}"
      ".log-btn:hover{background:#1a3060}"
      ".log-btn-del{color:#ff8080;border-color:#3a1010}"
      ".log-btn-del:hover{background:#3a1010}"
      ".sd-info-box{background:#090c0a;border-left:2px solid #1a3020;border-radius:0 4px 4px 0;"
      "padding:5px 10px;margin-bottom:10px;font-size:11px;color:#2a5040;line-height:1.5}"
      ".verbose-row{display:flex;align-items:center;justify-content:space-between;"
      "padding:10px 12px;background:#06080f;border:1px solid #1a3060;border-radius:8px;"
      "margin-bottom:12px}"
      ".verbose-label{color:#c8d8f0;font-size:14px}"
      ".verbose-state{display:inline-block;padding:3px 10px;border-radius:4px;"
      "font-size:12px;font-weight:600;margin-left:8px}"
      ".verbose-on{background:#1a3020;color:#40c080;border:1px solid #2a5030}"
      ".verbose-off{background:#1a1828;color:#4a6fa0;border:1px solid #2a3050}"
      ".swatch{flex:1;min-width:230px;background:#06080f;border:1px solid #1a3060;"
      "border-radius:10px;padding:12px}"
      ".swatch h3{font-size:11px;letter-spacing:.08em;text-transform:uppercase;"
      "color:#4a6fa0;margin:0 0 10px}"
      ".swatch .chip{width:52px;height:52px;border-radius:8px;"
      "border:1px solid #2a4a80;flex:none}"
      ".swatch .name{font-size:15px;color:#e8f0ff;font-weight:600}"
      ".swatch .fmt{font-size:11px;color:#4a6fa0}"
      ".swatch table{width:100%;border-collapse:collapse;margin-top:10px;font-size:12px}"
      ".swatch td{padding:3px 0;color:#c8d8f0}"
      ".swatch td:first-child{color:#4a6fa0;width:42%}"
      ".swatch tr.diff td{color:#e0a44a}"
      ".btn-toggle{padding:6px 14px;background:#0a1828;color:#28d49a;border:1px solid #1a3060;"
      "border-radius:6px;font-size:13px;cursor:pointer;font-family:inherit}"
      ".btn-toggle:hover{background:#1a3060}"
      ".section-divider{height:1px;background:#1a3060;margin:12px 0}"
      ".no-sd{text-align:center;padding:24px 16px}"
      ".no-sd-title{color:#c8d8f0;font-size:15px;font-weight:600;margin-bottom:6px}"
      ".no-sd-hint{color:#4a6fa0;font-size:13px;line-height:1.5}"
      "</style>";
  return html;
}

String webShellLinks() {
  String html;
  html += "<div class='links' style='margin-bottom:20px'>"
      "<a class='link-btn link-kofi' href='https://ko-fi.com/formfollowsfunction' target='_blank'>"
      "&#9749; Ko-fi</a>"
      "<a class='link-btn link-github' href='https://github.com/Niko11111/SpoolmanScale' target='_blank'>"
      "&#9873; GitHub</a>"
      "<a class='link-btn link-discord' href='https://discord.gg/GzQzGa5pBG' target='_blank'>"
      "&#128172; Discord</a>"
      "<a class='link-btn link-maker' href='https://makerworld.com/de/@FormFollowsF/upload' target='_blank'>"
      "&#11088; MakerWorld</a>"
      "</div>";
  return html;
}

String webShellFoot() {
  // Both backends are named regardless of the active mode. This device is
  // called SpoolmanScale, so in FilaMan mode a disclaimer mentioning only
  // FilaMan would leave out the very name that could suggest an affiliation.
  return String("<div class='footer'>Not affiliated with Spoolman, FilaMan or BamBuddy "
                "- Open Source Project</div></body></html>");
}

String webShellNav(const char *active) {
  static const char *PATHS[]  = { "/", "/ota", "/logs", "/drying", "/config", "/filaman", "/tags" };
  static const char *LABELS[] = { "Status", "Firmware", "Logs", "Drying", "Limits", "FilaMan", "Tags" };
  static const WebGate GATES[] = { GATE_OPEN, GATE_MAINT, GATE_MAINT, GATE_CONFIG,
                                   GATE_CONFIG, GATE_CONFIG, GATE_MAINT };

  String n = "<style>.nav{display:flex;flex-wrap:wrap;gap:8px;width:100%;max-width:480px;"
             "margin-bottom:20px}.nav a{padding:8px 14px;background:#0a1828;border:1px solid "
             "#1a3060;border-radius:8px;color:#4a6fa0;text-decoration:none;font-size:13px}"
             ".nav a:hover{border-color:#28d49a;color:#e8f0ff}"
             ".nav a.on{background:#1a3060;color:#e8f0ff;border-color:#28d49a}</style>"
             "<div class='nav'>";
  for (size_t i = 0; i < sizeof(PATHS) / sizeof(PATHS[0]); i++) {
    // Credentials only exist for the two backends that have them, and a tab
    // that only ever says "switched off" is worse than no tab.
    const bool creds = backendIsFilaMan() || backendIsBamBuddy();
    if (!strcmp(PATHS[i], "/filaman") && !creds) continue;
    // Same reasoning applied to the gates: a tab behind a shut one leads
    // only to the "switched off" page.
    if (!webGateOpen(GATES[i])) continue;
    const char *label = (!strcmp(PATHS[i], "/filaman") && backendIsBamBuddy())
                        ? "BamBuddy" : LABELS[i];
    n += String("<a class='") + (strcmp(PATHS[i], active) == 0 ? "on" : "") +
         "' href='" + PATHS[i] + "'>" + label + "</a>";
  }
  n += "</div>";
  return n;
}

String webShellRestartUi() {
  String h;
  h += F("<style>"
         "#rbox{display:none;position:fixed;inset:0;background:rgba(6,8,15,.92);z-index:99;"
         "align-items:center;justify-content:center}"
         "#rbox .rc{background:#0c1828;border:1px solid #1a3060;border-radius:14px;"
         "padding:32px 40px;text-align:center;max-width:360px}"
         ".spin{width:44px;height:44px;margin:0 auto 18px;border:3px solid #1a3060;"
         "border-top-color:#28d49a;border-radius:50%;animation:sp 1s linear infinite}"
         "@keyframes sp{to{transform:rotate(360deg)}}"
         "#rtitle{color:#e8f0ff;font-size:16px;font-weight:600;margin-bottom:8px}"
         "#rsec{color:#4a6fa0;font-size:13px;line-height:1.5}"
         "</style>"
         "<div id='rbox'><div class='rc'><div class='spin'></div>"
         "<div id='rtitle'>Restarting</div>"
         "<div id='rsec'>waiting for the device</div></div></div>"
         "<script>"
         "async function doRestart(){"
         "if(!confirm('Restart the device now?'))return;"
         // How long a boot takes is not a constant: an SD card adds roughly 20
         // seconds, so ask the device what it has before deciding what counts
         // as "too long". Guessing low would report a healthy boot as a failure.
         "let sd=false;"
         "try{sd=(await(await fetch('/status.json',{cache:'no-store'})).json()).sd}catch(e){}"
         "try{await fetch('/api/restart',{method:'POST'})}catch(e){}"
         "const box=document.getElementById('rbox'),m=document.getElementById('rsec');"
         "box.style.display='flex';"
         "const expect=sd?35:10, limit=180;"
         "let t=0;"
         "const iv=setInterval(async()=>{t++;"
         "if(t<2){m.textContent='restarting'}"
         "else if(t<expect){m.textContent='waiting for the device - '+t+'s'"
         "+(sd?' (SD card fitted, boot takes about 20s longer)':'')}"
         "else if(t<limit){m.textContent='still waiting - '+t+'s. It will reload as soon as "
         "the device answers.'}"
         "else{clearInterval(iv);"
         "m.innerHTML=\"device has not answered in \"+limit+\"s.<br>It may be off the network - \"+"
         "\"<a href='' style='color:#28d49a'>reload</a> to check.\";return}"
         // The old server answers for a moment after the request, so give it a
         // beat before the first poll or we reload against the dying instance.
         "if(t<2)return;"
         "try{const r=await fetch('/status.json',{cache:'no-store'});"
         "if(r.ok){clearInterval(iv);location.reload()}}catch(e){}"
         "},1000);}"
         "</script>");
  return h;
}
