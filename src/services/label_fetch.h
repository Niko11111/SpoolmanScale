#pragma once
// ============================================================
//  label_fetch.h - labels rendered by a label service
//  sdfp fork addition (SPOOLMANSCALE-SDFP.md, section 5b)
// ============================================================
//
// A label service renders the label and the scale only prints it. The sdfp
// service (tools/sdfp_service.py, GET /label) serves the label the site
// 3dfilamentprofiles.com renders - brand logo, material bar, colour, four
// info lines, QR to the spool's page - which the canvas renderer cannot draw.
//
// The contract, everything over plain HTTP on the LAN:
//
//   GET <base>/label?spoolman_id=<id>&w=<mm>&h=<mm>&format=raster[&what=filament]
//   200 application/octet-stream
//   X-Label-Width: 320      content width in dots (the stock width, not the head)
//   X-Label-Height: 240
//   X-Label-Row-Bytes: 40   (width + 7) / 8
//   body: height x row_bytes, rows MSB first, 1 = black, padding bits 0
//
// Anything else is a failure: the caller falls back to the built-in label
// where there is one.

#include <stddef.h>

#include "services/label_printer.h"
#include "services/label_raster.h"

// The service's base address, e.g. "http://192.168.1.20:8710". Empty when not
// set, which keeps the scale's own label and its single print button.
const char* labelServiceUrl();
bool labelServiceConfigured();
// Trimmed, trailing slash dropped. "" clears it. False when the value is not
// an http:// address or NVS refused the write.
bool labelServiceSetUrl(const char* url);

// Fetches this spool's label (or its filament's, `filament`) for the loaded
// stock and places it in a full print row at the configured offset, like the
// canvas renderer does. On false, `why` says what went wrong for the log.
// Blocking, from appLoop() only: up to LABEL_FETCH_TIMEOUT_MS.
bool labelFetchRaster(const LabelPrinterConfig& config, int spool_id, bool filament,
                      LabelRaster* out, char* why, size_t why_len);
