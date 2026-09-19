#include "services/partition_layout.h"

#include <Arduino.h>
#include <esp_partition.h>

#include "app_config.h"
#include "hardware/sd_logger.h"
#include "services/prefs_store.h"

#define KEY_PART_NEVER "part_never"

static PartitionLayout s_layout;
static bool s_read  = false;
static bool s_shown = false;

const PartitionLayout& partitionLayout() {
  if (s_read) return s_layout;
  s_read = true;
  // Both OTA slots are the same size, and getFreeSketchSpace() is the whole
  // size of the one not running - the same call the firmware upload checks
  // against - so it says how large a slot is without naming a partition.
  s_layout.app_slot_bytes = ESP.getFreeSketchSpace();
  s_layout.app_used_bytes = ESP.getSketchSize();
  const esp_partition_t* data = esp_partition_find_first(
      ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, NULL);
  s_layout.data_bytes = data ? data->size : 0;
  s_layout.has_coredump = esp_partition_find_first(
      ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, NULL) != NULL;
  s_layout.current = s_layout.app_slot_bytes >= PARTITION_APP_SLOT_CURRENT_BYTES;
  logSDf("Storage: slots %.1f MB, firmware %.1f MB, data %.1f MB, coredump %s, layout %s",
         s_layout.app_slot_bytes / 1048576.0, s_layout.app_used_bytes / 1048576.0,
         s_layout.data_bytes / 1048576.0, s_layout.has_coredump ? "yes" : "no",
         s_layout.current ? "current" : "old");
  return s_layout;
}

bool partitionHintDue() {
  if (!FLASHER_HAS_CURRENT_LAYOUT) return false;   // nothing to send them to yet
  if (s_shown) return false;
  if (partitionLayout().current) return false;
  return !prefsGetBool(KEY_PART_NEVER, false);
}

void partitionHintShown() { s_shown = true; }

void partitionHintNever() {
  s_shown = true;
  prefsPutBool(KEY_PART_NEVER, true);
}
