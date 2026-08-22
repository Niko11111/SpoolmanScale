#pragma once

// skip_cap_check is set by the popup that asked about the label weight, so
// the second attempt writes instead of asking again.
void patchSpoolmanWeight(float remaining, bool skip_cap_check = false);
void patchArchiveSpool();
void patchSpoolTag(int spool_id, const char* uuid);
void patchInitialWeight(float initial_w);
void patchSpoolWeight(float spool_w);
void patchFilamentSpoolWeight(float spool_w);
void patchVendorSpoolWeight(float spool_w);
