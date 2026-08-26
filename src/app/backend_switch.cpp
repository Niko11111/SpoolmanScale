#include "app/backend_switch.h"

#include <Arduino.h>
#include <cstring>

// bambuddy_api.h and backend_api.h pull in ArduinoJson, which has to be parsed
// before lang.h defines T() - ArduinoJson uses T as a template parameter.
// Nothing here needs lang.h, so the plain includes are safe.
#include "services/backend_api.h"
#include "services/bambuddy_device.h"
#include "services/filaman_api.h"

#include "app/app_state.h"
#include "app/deferred_actions.h"
#include "hardware/sd_logger.h"
#include "services/ams_assign.h"
#include "services/location_state.h"
#include "services/remote_link.h"
#include "services/tag_field.h"
#include "services/user_options.h"
#include "ui/header_status.h"
#include "ui/tag_display.h"
#include "web/web_server.h"

void backendApplyMode(BackendMode mode) {
  if (mode == backendMode()) return;

  const char *from = backendName();

  // ---- while the old backend is still the current one --------------------

  // An armed AMS window belongs to the server the scale is about to stop
  // talking to. Switching away would leave auto_assign_enabled set on it
  // until the next boot, because amsBootReconcile() runs once per boot behind
  // a function static and nothing else ever turns it off.
  if (backendIsFilaMan() && g_ams_mode != AMS_OFF) {
    amsWriteEnabled(false);
  }
  amsDropPending();

  // An open FilaMan link is a question the scale can no longer answer:
  // remoteLinkReport() bails out on the mode check and only writes a log
  // line, so the web dialog at the other end sits there until its own timeout.
  remoteLinkClear();
  remote_link_reject_pending = false;

  // ---- the switch itself -------------------------------------------------

  backendSetMode(mode);
  logSDf("Backend: %s -> %s (full reset)", from, backendName());

  // ---- caches and sessions that belong to the backend just left ----------

  // Keyed by nothing but a five minute TTL, so it would resolve and write ids
  // belonging to the other instance.
  filamanForgetLocations();

  // The extra field probe is keyed by base URL and invalidates itself, but the
  // text field list is not - it would still name the fields of the old server.
  backendInvalidateExtraFieldCache();

  // Resets the BamBuddy registration and asks the new server whether it keeps
  // its own database or proxies to Spoolman. That answer decides where every
  // read and write goes, and without this it would be up to half a minute
  // stale - during which the badge names the wrong one too. A no-op in the
  // other two modes.
  backendAfterConnect();

  // ---- state on the panel ------------------------------------------------

  sm_reachable = false;          // unknown until the new backend answers

  // The header abbreviation and the caption above the database weight name the
  // backend. Without this they would only catch up on the next reachability
  // change, which can be half a minute away, or on reboot.
  updateHeaderStatus();

  // Everything on screen came from the backend that was just left: spool id,
  // weights, drying date, and for an NTAG even the material and vendor, since
  // those live on the server rather than on the tag. None of it is true for
  // the new one, and the same spool may not exist there at all.
  //
  // This also clears both lookup markers, which is what makes the poll treat
  // the tag on the pad as new: it reads it again and asks the new backend
  // about it, without anyone having to lift the spool off.
  clearTagDisplay();

  // What clearTagDisplay() leaves behind. It is written for a spool being
  // taken off the pad, where these stay true for the 60 seconds the display
  // keeps the last reading - but across a backend change none of them is.
  sm_remaining = 0;
  sm_total = 0;
  sm_dup_count = 0;
  sm_archived = false;
  sm_location_id = 0;            // its name is cleared, the id was not
  sm_tag_conflict_spool = 0;
  sm_vendor_g[0] = '\0';
  sm_tare_source = 0;

  // Spool ids are per backend, so the marker for "the location popup was
  // already shown for this spool" now points at a different spool.
  g_loc_popup_shown_for_id = -1;

  // The card_uids switch only means anything on a list field, and the
  // effective field depends on the backend: the native source applies on
  // Spoolman alone. Same clamp loadPrefs() does at boot.
  if (!tagFieldIsList()) g_card_uids_write = false;

  // Whether port 80 stays open depends on the mode: the FilaMan device
  // protocol holds it up on its own. Ask the one owner of the socket to settle
  // now rather than within the next second.
  webServerSyncState();
}
