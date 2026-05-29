#pragma once

void patchSpoolmanWeight(float remaining);
void patchArchiveSpool();
void patchSpoolTag(int spool_id, const char* uuid);
void patchInitialWeight(float initial_w);
void patchSpoolWeight(float spool_w);
void patchFilamentSpoolWeight(float spool_w);
void patchVendorSpoolWeight(float spool_w);
