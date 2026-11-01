#pragma once

#include <stdint.h>

#include "services/filaman_labels.h"
#include "services/label_printer.h"

// ============================================================
//  A SPOOL LABEL DRAWN BY THE SERVER
//
//  Instead of its own layout the scale can print a label preset
//  the user laid out in FilaMan's label designer: the label
//  editor in the browser picks one, the print fetches the raster
//  and moves it to where the stock runs. Only on FilaMan, and
//  only on a FilaMan that has the label API; everywhere else the
//  choice is not offered and the scale prints its own.
//
//  The editor's list and preview need HTTP, which its handlers
//  must not make: they ask here, a task of its own fetches, and
//  labelServerTick() takes the answer on a later pass of the loop,
//  as the label dates do (app/label_spool.cpp). Everything here
//  apart from that task runs on the loop task.
// ============================================================

// The chosen preset, 0 for the scale's own layout. Kept when the backend
// changes: the server says whether it knows the id.
int  labelServerPresetId();
bool labelServerSetPresetId(int id);
// Whether a spool label comes from the server: FilaMan, and a preset chosen.
// Never for a tape printer: that one prints its own fixed label.
bool labelServerInUse();

enum LabelServerListState : uint8_t {
  LS_UNKNOWN, LS_LOADING, LS_READY,
  LS_ABSENT,    // FilaMan without the label API, or another backend
  LS_FAILED,    // no answer; asked again a little later
};

// The presets as far as known; asks the server when nobody has lately.
// `list` stays valid until the next pass of the loop.
LabelServerListState labelServerList(const FilamanLabelPresetList** list);

enum LabelServerPreviewState : uint8_t { LSP_NONE, LSP_LOADING, LSP_READY, LSP_FAILED };

// The chosen preset drawn for this spool and printer, at the row's left
// edge. Asks for it when it is not the one in hand. READY sets `raster`,
// FAILED sets `reason` (the server's words, may be empty). Both stay valid
// until the next pass of the loop.
LabelServerPreviewState labelServerPreview(const LabelPrinterConfig& config, int spool_id,
                                           const LabelRaster** raster, const char** reason);
// The preview in hand for this spool and printer, whatever its age; nullptr
// when there is none. Asks nothing: for the picture the state route announced.
const LabelRaster* labelServerPreviewInHand(const LabelPrinterConfig& config, int spool_id);
// Counts the previews that arrived, so the browser knows when to load anew.
uint32_t labelServerPreviewRev();

// For a print, from the loop: the label of this spool with the chosen preset,
// placed where the stock runs. Waits for the editor's task first, keeping
// `tick` called. Returns 200 or the failing code; the server's reason is then
// in labelServerLastReason().
int labelServerPrintRaster(const LabelPrinterConfig& config, int spool_id,
                           LabelRaster* out, BleProgressFn tick);
const char* labelServerLastReason();

// The list and the preview belong to the server the scale just left.
void labelServerForget();

// From the loop: takes a finished fetch, starts the next one asked for.
void labelServerTick();
