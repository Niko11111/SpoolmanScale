// ============================================================
//  SpoolmanScale – Bambu NFC Tag Reader & Decoder
//  Board:   WT32-SC01 Plus (ESP32-S3)
//  Version: v0.5.12-beta
//
//  Reads Bambu Lab MIFARE Classic tags, derives keys via KDF
//  (HKDF/SHA256, master key from Bambu-Research-Group/RFID-Tag-Guide),
//  displays all decoded data on screen and queries
//  Spoolman for weight + last_dried after each scan.
//
//  Wiring:
//    Pin 1 (+5V)  -> PN532 VCC
//    Pin 2 (GND)  -> PN532 GND
//    Pin 3 (IO1)  -> PN532 SDA (GPIO 10)
//    Pin 4 (IO2)  -> PN532 SCL (GPIO 11)
//    Pin 5 (IO3)  -> PN532 RST (GPIO 12)
//
//  PN532 DIP-Switches: SW1=ON, SW2=OFF -> I2C mode
//
//  Libraries:
//    - Adafruit PN532    by Adafruit
//    - Adafruit BusIO    by Adafruit
//    - LovyanGFX         by lovyan03
//    - lvgl              by lvgl (Version 8.3.11!)
//    - ArduinoJson       by Benoit Blanchon (Version 7.x)
//  mbedTLS + WiFi + HTTPClient are included in the ESP32 framework.
// ============================================================

#include <Wire.h>
#include <lvgl.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <ArduinoJson.h>
#include <SD.h>
#include <SPI.h>
#include <esp_system.h>
#include "app_config.h"
#include "bambu/bambu_kdf.h"
#include "bambu/bambu_tag.h"
#include "hardware/display.h"
#include "hardware/nfc.h"
#include "hardware/pins.h"
#include "hardware/scale.h"
#include "hardware/sd_logger.h"
#include "services/prefs_store.h"
#include "services/ota_web_server.h"
#include "services/spoolman_actions.h"
#include "services/spoolman_api.h"
#include "services/wifi_manager.h"
#include "ui/connection_screen.h"
#include "ui/bag_screen.h"
#include "ui/cal_reminder_screen.h"
#include "ui/display_screen.h"
#include "ui/drying_reminder_screen.h"
#include "ui/factor_screen.h"
#include "ui/info_screen.h"
#include "ui/language_screen.h"
#include "ui/last_used_screen.h"
#include "ui/ota_github.h"
#include "ui/ota_browser.h"
#include "ui/ota_menu.h"
#include "ui/scale_menu.h"
#include "ui/settings_screen.h"
#include "ui/spoolman_screen.h"
#include "ui/system_screen.h"
#include "ui/ui_common.h"
#include "ui/wifi_info.h"
#include "ui/wifi_setup_screen.h"

// PSRAM allocator for ArduinoJson — used for large JSON documents (Spoolman spool list)
// Frees internal RAM for LVGL, WiFi stack, and other allocations
struct SpiRamAllocator : ArduinoJson::Allocator {
  void* allocate(size_t size) override {
    void* ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
    if (!ptr) ptr = malloc(size);  // fallback to internal RAM if PSRAM fails
    return ptr;
  }
  void deallocate(void* pointer) override { heap_caps_free(pointer); }
  void* reallocate(void* ptr, size_t new_size) override {
    void* p = heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM);
    if (!p) p = realloc(ptr, new_size);  // fallback
    return p;
  }
};
#include <time.h>
#include <esp_sleep.h>
#include <nvs_flash.h>
// LVGL built-in QR-Code: LV_USE_QRCODE muss in lv_conf.h auf 1 gesetzt sein!
#include "extra/libs/qrcode/lv_qrcode.h"
#include "lang.h"
#include "bambu/material_match.h"

// ============================================================
//  FORWARD DECLARATIONS
// ============================================================
void resetActivityTimer();
void isoToDe(const char* iso, char* out, size_t len);
void driedDisplayStr(const char* de_date, char* out, size_t len);
static int  dryingAlertLevel(const char* last_dried_local);
static void applyDriedLabel(lv_obj_t* lbl_val, lv_obj_t* lbl_sym, const char* de_date);
void querySpoolman(const char* tray_uuid);
void querySpoolmanById(int spool_id);
void closeConfirmPopup();
void patchSpoolWeight(float spool_w);
void patchFilamentSpoolWeight(float spool_w);
void patchVendorSpoolWeight(float spool_w);
void showConfirmPopup(const char* msg, int action);
void closeLinkList();
void showLinkList();
void fetchUnlinkedSpools();
void patchSpoolTag(int spool_id, const char* uuid);
// Neuer Link-Flow
void showLinkEntryPopup(bool is_bambu);
void closeLinkEntryPopup();
void showIdInputPopup(bool is_bambu, bool is_copy = false);
void closeIdInputPopup();
// ID-Eingabe: HTTP-Lookup und Verknuepfung (ausgelagert wegen Stack-Groesse in Lambda)
void linkIdLookupAndPatch(int entered_id, bool is_bambu);
void showWarnPopupA(int spool_id, const char* existing_tag, bool is_bambu, const char* link_uuid);
void showWarnPopupB(int spool_id, bool is_bambu);
void fetchAllSpoolsForLink(bool is_bambu, const char* material_filter, bool archived_only = false);
void doLinkPatch(int spool_id, bool is_bambu);
void showVendorList();
void showMaterialList(const char* vendor_name);
void showMaterialSubList(const char* vendor_name, const char* material_prefix);
void showFilteredSpoolList(const char* vendor_name, const char* material_prefix, const char* material_full);
bool writeSpoolScaleTag(int spool_id, const char* uuid_hex);
bool readSpoolScaleTag(int* out_spool_id, char* out_uuid, size_t uuid_len);
void generateUUID(char* out, size_t len);
void updateHeaderStatus();
void showMoreInfoScreen();
void buildMoreInfoScreen();
void fetchAndFillLocationList();
void updateMoreInfoScreen();
void hideAllOverlays();
void showMainScreen();
void showSettingsScreen();
void buildConnectionScreen();
void buildScaleSubScreen();
void buildDisplayScreen();
void buildSystemScreen();
void showUpdateBadges(bool show);
void buildOtaScreen();
void buildOtaBrowserScreen();
void showOtaScreen();
void showOtaBrowserScreen();
void buildSettingsScreen();
void buildSpoolmanScreen();
void showSpoolmanFailScreen(bool is_setup_flow);
void clearTagDisplay();
void updateLinkButton();
void syncNTP();
void saveSpoolmanIP(const char* ip);
void buildWelcomeScreen();
void buildWifiSetupScreen();
void showWifiSetupScreen();
void showWelcomeScreen();
void saveWifiCredentials(const char* ssid, const char* pass);
void doWifiScan();
void showWifiPassScreen();
void buildWifiPassScreen();
void showWifiConnectingScreen();
void buildWifiConnectingScreen();
void buildBagScreen();
void buildFactorScreen();
void showFactorScreen();
void showRebootPopup();
void showInfoScreen();
void showLanguageScreen();
void showQRPopup(int idx);
void buildFirstBootScreen();
void showFirstBootScreen();
void buildExtraFieldsScreen(bool is_setup_flow);
void showExtraFieldsScreen(bool is_setup_flow);
void buildCalReminderScreen();
void showCalReminderScreen();
void checkAndCreateExtraFields(bool create_missing);
void showCopyEntryPopup();
void closeCopyEntryPopup();
void showCopyIdInputPopup();
void fetchSpoolsForCopy(bool archived, const char* material_filter, bool is_bambu_tag = false);
void showCopySpoolList();
void showCopyConfirmPopup(int template_id, const char* template_name, float template_remaining, float template_initial, float template_spool_w);
void doCopySpoolCreate(int template_filament_id, float template_initial, float template_spool_w);



// ============================================================
//  PINS
// ============================================================
#define BRIGHT_NORMAL_DEFAULT  255   // 100% — Standardwert
#define BRIGHT_DIM_DEFAULT       77   // 30%  — Standardwert
#define DIM_TIMEOUT_DEFAULT   300000  // 5 Min — Standardwert
#define SLEEP_TIMEOUT_DEFAULT 1200000 // 20 Min — Standardwert

// Runtime variables (loaded from NVS, configurable via display menu)
int     bright_normal   = BRIGHT_NORMAL_DEFAULT;
int     dim_timeout_ms  = DIM_TIMEOUT_DEFAULT;
int     sleep_timeout_ms = SLEEP_TIMEOUT_DEFAULT;

// NAU7802 calibration
// CAL_FACTOR: raw value per gram. Determined via calibration and saved in NVS.
// Default 1.0 means: raw values are displayed directly as grams.
#define CAL_FACTOR_DEFAULT  1.0f

// Separate I2C bus for PN532 + NAU7802. Display/touch owns its internal bus.
TwoWire I2C_EXT   = TwoWire(1);

// ============================================================
//  WIFI + SPOOLMAN CONFIGURATION
// ============================================================
// WiFi + Spoolman are loaded from NVS (Preferences)
// Fallback values if NVS is empty:
// Fallback credentials: empty — WiFi is configured via the welcome screen
char cfg_wifi_ssid[33]     = "";
char cfg_wifi_password[65] = "";
char cfg_spoolman_ip[64]   = "";
char cfg_spoolman_base[80] = "";
bool cfg_lang_set          = false;  // true after first language selection
bool cfg_first_boot        = true;   // true = very first boot (greeting screen not yet shown)
static lv_obj_t *lbl_extra_fields_status = nullptr; // status label in extra fields screen
static lv_obj_t *btn_extra_fields_create = nullptr; // create button in extra fields screen
static lv_obj_t *btn_extra_fields_next   = nullptr; // skip/next button (turns green when OK)
static bool extra_fields_setup_flow = false;         // true = called from setup flow
static bool spoolman_fail_is_setup  = false;         // for spoolman fail screen
static bool spoolman_test_pending   = false;         // HTTP test queued for loop
static bool spoolman_test_in_setup  = false;         // context for test result
static bool extra_fields_check_pending = false;      // deferred from event callback to loop
static bool extra_fields_create_pending = false;     // deferred create from event callback
static bool skip_setup_pending = false;  // deferred from skip button callback
static bool cal_reminder_pending = false;            // deferred showCalReminderScreen from callback
bool show_bag_pending    = false;                    // deferred showBagScreen from scale_sub callback
bool show_factor_pending = false;                    // deferred showFactorScreen from scale_sub callback
bool show_lastused_pending = false;                  // deferred buildLastUsedScreen from scale_sub callback
bool show_spoolman_pending = false;                  // deferred buildSpoolmanScreen from connection callback
bool show_connection_from_spoolman_pending = false;  // deferred return-to-connection from spoolman back btn
bool show_system_pending = false;                    // deferred return-to-system from ota/info back btn
bool show_ota_pending    = false;                    // deferred showOtaScreen from system tile callback
bool show_info_pending = false;                      // deferred showInfoScreen from system tile callback
static bool show_location_picker_pending = false;    // deferred showLocationPicker from More Info button
bool show_drying_reminder_pending = false;            // deferred showDryingReminderScreen
static bool show_more_info_pending = false;          // deferred buildMoreInfoScreen after location change
static bool fetch_locations_pending = false;         // deferred HTTP fetch for location picker
static lv_obj_t *loc_list_obj = nullptr;             // location picker list container
static lv_obj_t *loc_status_obj = nullptr;           // location picker status label
static bool lang_selected_no_reboot = false;         // EN selected on welcome screen — go to firstboot without reboot
uint8_t last_used_mode = 0;                          // 0=OpenSpoolMan, 1=Last Weighed
// ============================================================
//  GLOBAL OBJECTS
// ============================================================
bool nfc_ok = false;
bool scl_ok = false;          // NAU7802 scale connected

BambuTagData g_tag;
bool g_tag_ready = false;
bool g_tag_displayed = false;
unsigned long g_tag_shown_ms = 0;
bool wifi_ok = false;
bool sm_reachable = false;  // Fix 10: Spoolman reachability status

// Tare confirmation timeout
static unsigned long tare_msg_ms = 0;
lv_obj_t *lbl_ok_ptr = nullptr;

// No-tag timer: clear display after timeout if no NFC tag detected
static unsigned long last_tag_seen_ms = 0;    // last NFC detection
static bool tag_present = false;               // tag currently on reader?
#define NO_TAG_CLEAR_MS  60000                 // 1 minute without tag -> clear

// Confirmation popup
lv_obj_t *confirm_popup = nullptr;             // current popup object
static int  confirm_action = 0;                // 1=dried, 2=weight

// Settings UI
lv_obj_t *scr_main   = nullptr;
lv_obj_t *scr_settings   = nullptr;
lv_obj_t *scr_wifi       = nullptr;
lv_obj_t *scr_spoolman   = nullptr;
lv_obj_t *scr_spoolman_fail = nullptr; // Spoolman connection failed screen
lv_obj_t *scr_welcome    = nullptr;   // Welcome screen (first boot — language selection)
lv_obj_t *scr_first_boot = nullptr;   // Very first boot greeting screen
lv_obj_t *scr_extra_fields = nullptr; // Spoolman extra fields check screen
lv_obj_t *scr_cal_reminder = nullptr; // Calibration reminder screen (end of first setup)
lv_obj_t *scr_wifi_setup = nullptr;   // WiFi setup: scan + password + connect
lv_obj_t *scr_factor     = nullptr;
lv_obj_t *scr_bag        = nullptr;
lv_obj_t *scr_lastused   = nullptr;  // Last Used Mode screen
// Submenu screens
lv_obj_t *scr_connection = nullptr;  // Connection (WiFi + Spoolman IP)
lv_obj_t *scr_scale_sub  = nullptr;
lv_obj_t *scr_drying_reminder = nullptr;  // Scale (bag weight + calibration)
lv_obj_t *scr_display    = nullptr;  // Display (brightness + timeouts)
lv_obj_t *scr_system     = nullptr;  // System (update + info/donate)
lv_obj_t *scr_ota        = nullptr;  // OTA selection (browser / GitHub)
lv_obj_t *scr_ota_browser = nullptr; // OTA browser upload screen
lv_obj_t *scr_ota_github  = nullptr; // OTA GitHub check screen

lv_obj_t *lbl_ota_status = nullptr;  // Status-Label im Browser-OTA Screen

// GitHub OTA state
bool update_available = false;   // set by silent background check
bool gh_prerelease    = false;   // include pre-releases in update check (NVS: "gh_prerelease")
static bool silent_ota_check_pending = false;  // trigger once after WiFi connect
static lv_obj_t *lbl_burger_badge   = nullptr; // yellow dot on burger button (mainscreen)
lv_obj_t *lbl_system_badge   = nullptr; // yellow dot on System tile (settings)
lv_obj_t *lbl_fw_badge       = nullptr; // yellow dot on Firmware Update button
lv_obj_t *lbl_gh_btn_badge   = nullptr; // yellow dot on GitHub Update button (OTA screen)
lv_obj_t *lbl_wifi_info = nullptr; // WiFi-Info Label
// ta_spoolman_ip, kb_spoolman: replaced by custom numpad — removed
// ta_factor_weight, kb_factor: replaced by custom numpad in buildFactorScreen()
lv_obj_t *ta_factor_weight = nullptr; // (nicht mehr aktiv genutzt)
lv_obj_t *kb_factor     = nullptr;    // (nicht mehr aktiv genutzt)
lv_obj_t *lbl_factor_result = nullptr;
lv_obj_t *lbl_factor_cal_weight = nullptr; // live weight display in calibration screen

// WiFi setup state
lv_obj_t *scr_wifi_pass         = nullptr;  // Passwort-Unterscreen
lv_obj_t *scr_wifi_connecting   = nullptr;  // Connecting screen

// Power management
unsigned long last_activity_ms = 0;  // last activity (NFC or touch)
bool is_dimmed = false;              // Display dimmed?

// Spoolman data kept separate – NOT reset on every scan
int   sm_id = 0;
int   sm_filament_id = 0;   // for PATCH /api/v1/filament/{id}
int   sm_vendor_id = 0;     // for PATCH /api/v1/vendor/{id}
bool  sm_found = false;
float sm_remaining = 0;
float sm_total = 1000;
float sm_spool_weight = 0;   // Empty spool weight (for scale calculation)
static char  sm_last_dried[32] = "";
static char  sm_article_nr[32] = "";
static char  sm_filament_name[32] = "";
static char  sm_material_global[32] = "";
static char  sm_color_global[16] = "";   // Spoolman hex color for NTAG spools
static char  sm_location_name[48] = ""; // Current location name (display)
static int   sm_location_id = 0;        // Current location id

// Scale (NAU7802)
float scale_weight_g = 0.0f;
bool scale_ready = false;
float cal_factor = CAL_FACTOR_DEFAULT;
int32_t zero_offset = 0;
static unsigned long last_scale_ms = 0;

// Moving average for NAU7802 (dampens +/-0.2g noise)
#define SCALE_FILTER_SIZE  8
float scale_filter_buf[SCALE_FILTER_SIZE] = {0};
int   scale_filter_idx = 0;
bool  scale_filter_full = false;

// Display precision: true = whole grams only, false = 0.1g
bool g_whole_gram = false;

// Auto-Weight: Gewicht automatisch speichern bei 3s Stabilität
static bool g_auto_weight = false;               // Toggle-Status (Standard: aus)
bool g_auto_loc_popup = false;                    // Auto location popup on tag removal

// ── Drying Reminder ──────────────────────────────────────────
uint8_t g_dry_mode       = 0;   // 0=Aus, 1=Material, 2=Manuell
int     g_dry_man_yellow = 30;  // Manuell: Gelb-Schwellwert (Tage)
int     g_dry_man_red    = 90;  // Manuell: Rot-Schwellwert (Tage)

// Material-Schwellwerte [7]: PLA, PETG, ABS, ASA, TPU, PA, PC
const char* DRY_MAT_NAMES[]     = { "PLA","PETG","ABS","ASA","TPU","PA","PC" };
extern const int   DRY_MAT_DEF_YELLOW[]= { 180,  90,  90,  90,  30,   7,  30 };
extern const int   DRY_MAT_DEF_RED[]   = { 365, 180, 180, 180,  90,  30,  90 };
extern const int   DRY_MAT_COUNT = 7;
int  g_dry_mat_yellow[7];        // editierbar via Webserver
int  g_dry_mat_red[7];
bool g_dry_mat_sealed[7];        // pro Material: luftdicht gelagert (Multiplikator aktiv)
float g_dry_mult_sealed = 2.0f;  // Multiplikator fuer luftdichte Lagerung, editierbar via Webserver
static int  g_loc_popup_shown_for_id = -1;         // sm_id for which loc popup was last shown
static bool g_loc_picker_from_popup = false;        // true = picker opened from tag-removal popup
static int  loc_popup_pending_id = -1;              // debounced popup: sm_id scheduled, fires after 1500ms
static float auto_weight_last_val = -9999.0f;    // letzter Vergleichswert
static unsigned long auto_weight_stable_ms = 0;  // Zeitpunkt, seit dem stabil
static lv_obj_t *lbl_auto_weight_btn = nullptr;  // Label des Toggle-Buttons im Popup
static lv_obj_t *lbl_weight_main_lbl = nullptr;  // Label des Zone-5 "Gewicht updaten" Buttons
#define AUTO_WEIGHT_STABLE_MS  3000              // 3 Sekunden Wartezeit
#define AUTO_WEIGHT_THRESH_G   0.5f              // max. Abweichung für "stabil"

// Bag weight (configurable in settings)
float bag_weight_g = 50.0f;  // Standard: 50g (Vakuumbeutel + Silikagel)

// Spoolman query: UID of the last queried spool
// Cleared after clearTagDisplay() → forces new query even for same UID
static char spoolman_queried_uid[24] = "";  // max 7-byte UID: "XX:XX:XX:XX:XX:XX:XX" = 23+1
char  sm_last_used[32] = "";

// NFC retry: counter for re-scan attempts when tray_uuid is empty
static int nfc_retry_count = 0;
static int nfc_absent_count = 0;   // consecutive "not found" reads before tag_present = false
#define NFC_MAX_RETRIES  5

// Tag type enum — declared globally so all functions can use it
enum TagType { TAG_BAMBU, TAG_SPOOLSCALE, TAG_BLANK, TAG_UNKNOWN };

struct UnlinkedSpool {
  int   id;
  char  name[48];      // filament.name
  char  vendor[32];    // filament.vendor.name
  char  material[16];  // filament.material (PLA, PETG, ABS...)
  char  color_hex[8];  // filament.color_hex (#RRGGBB)
  float remaining;     // remaining_weight
  float total;         // filament.weight
  char  existing_tag[48]; // extra.tag falls gesetzt (fuer Ueberschreib-Check)
  int   filament_id;   // filament.id (for copy flow)
  float spool_weight;  // spool_weight (for copy flow)
};
static UnlinkedSpool* link_spools = nullptr;  // PSRAM-allocated at fetch time, freed after link flow
static int            link_spool_count = 0;
static char          link_tag_uid[24] = "";   // UID of the tag to be linked
static lv_obj_t     *scr_link_list = nullptr; // Spool selection overlay (old, kept for compatibility)

// Neuer Link-Flow Overlays
static lv_obj_t *scr_link_entry   = nullptr;  // Entry popup
static lv_obj_t *scr_link_id      = nullptr;  // Numeric keypad
static lv_obj_t *scr_link_warn_a  = nullptr;  // Warning popup A (already linked)
static lv_obj_t *scr_link_warn_b  = nullptr;  // Warning popup B (material mismatch)
static lv_obj_t *scr_link_vendor  = nullptr;  // Vendor-Auswahl (Flow B Pfad 2)
static lv_obj_t *scr_link_mat     = nullptr;  // Material selection (flow B path 2)
static lv_obj_t *scr_link_mat_sub = nullptr;  // Material sub-name selection (Stufe 3)
static lv_obj_t *scr_link_spools  = nullptr;  // Spool list (all path 2)

// State for ID input
static char link_id_input[8] = "";            // Input buffer for numeric keypad
static lv_obj_t *lbl_link_id_display = nullptr; // Label for digit display
static lv_obj_t *lbl_link_id_status  = nullptr; // Error label in numeric keypad

// State for path-2 navigation
static char link_selected_vendor[32]   = "";   // selected vendor
static char link_selected_material[8]  = "";   // 3-char material prefix
static char link_selected_material_full[32] = ""; // full material name (Stufe 3)
static bool link_stage3_shown = false;          // true if stage 3 actually rendered (not auto-skipped)
static bool link_flow_is_bambu = false;         // which flow is active

// Copy spool flow state
static lv_obj_t *scr_copy_entry   = nullptr;  // entry screen (ID / active / archived)
static lv_obj_t *scr_copy_id      = nullptr;  // numeric ID input
static lv_obj_t *scr_copy_list    = nullptr;  // spool list
static lv_obj_t *scr_copy_confirm = nullptr;  // confirm popup
static bool copy_flow_archived = false;        // true = showing archived spools
static bool copy_flow_via_list = false;        // true = copy flow using vendor/material list path
static bool copy_confirm_pending = false;      // deferred showCopyConfirmPopup from list row click
static int  copy_confirm_fid = 0;
static float copy_confirm_remaining = 0, copy_confirm_initial = 0, copy_confirm_spool_w = 0;
static char copy_confirm_name[80] = {};
static char copy_id_input[8] = "";
static lv_obj_t *lbl_copy_id_display = nullptr;
static lv_obj_t *lbl_copy_id_status  = nullptr;
// Template selected for copy
static int   copy_template_filament_id = 0;
static float copy_template_initial     = 0;
static float copy_template_spool_w     = 0;
static char  copy_template_name[64]    = "";
// btn_copy: global for show/hide alongside btn_link
static lv_obj_t *btn_copy = nullptr;
// Configurable list limit — loaded from NVS, adjustable via webserver /listlimit
int spool_list_limit   = 16;  // range 5-100, editable via webserver
int location_list_limit = 30;  // range 5-100, editable via webserver

// Popup control: prevents immediate re-display after cancel
static bool id_popup_is_bambu = false;  // shared between numpad lambdas
static bool id_popup_is_copy   = false;  // true = copy flow, false = link flow
static int  copy_id_lookup_pending = 0;  // >0 = deferred copy ID fetch (avoids stack overflow in lambda)
static int  link_id_lookup_pending = 0;  // >0 = deferred linkIdLookupAndPatch (avoids stack overflow in lambda)
static bool link_id_lookup_is_bambu = false;
static bool show_id_input_pending = false;   // deferred re-open of IdInputPopup from Back button
static bool show_id_input_rebuild = false;   // deferred re-open from WarnPopupA retry (rebuild after del)
static bool id_input_open = false;           // true while IdInputPopup is visible — suppresses NFC Spoolman query

static bool link_popup_dismissed = false;       // user dismissed the popup
static unsigned long link_tag_first_seen_ms = 0; // time of first detection
#define LINK_POPUP_DELAY_MS  3000               // 3s warten bevor Popup erscheint

// ============================================================
//  UI Labels
// ============================================================
lv_obj_t *lbl_status;
lv_obj_t *lbl_uid;
lv_obj_t *lbl_tray_uuid;
lv_obj_t *lbl_material;
lv_obj_t *lbl_color;
lv_obj_t *lbl_filament_name;
lv_obj_t *lbl_color_swatch;
lv_obj_t *lbl_vendor;
lv_obj_t *lbl_temp;
lv_obj_t *lbl_detail;
lv_obj_t *lbl_date;
lv_obj_t *lbl_spoolman_id;
lv_obj_t *lbl_scan_count;
lv_obj_t *lbl_keys;
lv_obj_t *lbl_raw_info;
// Spoolman labels
lv_obj_t *lbl_spoolman_weight;
lv_obj_t *lbl_scale_weight;  // Live-Gewicht von NAU7802
lv_obj_t *lbl_scale_diff;   // Differenz (Waage netto) vs. Spoolman remaining
lv_obj_t *lbl_last_used;
lv_obj_t *lbl_lu_cap = nullptr;  // Last used/weighed cap label — updated on mode change
lv_obj_t *lbl_spoolman_pct;
lv_obj_t *lbl_spoolman_dried;
lv_obj_t *lbl_spoolman_dried_val;  // NEU: Wert unter dem Titel
lv_obj_t *lbl_dried_sym = nullptr; // Ampel-Symbol neben last_dried
int  s_dry_numpad_target = 0;
int  s_dry_numpad_value  = 0;
lv_obj_t* s_dry_numpad_scr = nullptr;  // Numpad-Screen fuer Drying Manual
lv_obj_t* s_dry_numpad_lbl = nullptr;  // Wert-Anzeige im Numpad
lv_obj_t *lbl_nfc_dot;            // Status dot before status line (green/yellow)
lv_obj_t *lbl_hdr_wifi;          // Header: WiFi-Symbol (Farbe je RSSI)
lv_obj_t *lbl_hdr_nfc;           // Header: NFC status (green/red)
lv_obj_t *lbl_hdr_scl = nullptr; // Header: Scale/NAU7802 status (green/red)
lv_obj_t *lbl_hdr_scans;         // Header: scan counter (dim)
lv_obj_t *lbl_hdr_sm = nullptr;  // Header: Spoolman reachability status
lv_obj_t *lbl_bag_sm_diff = nullptr; // Zone 4: ohne-Beutel vs SM diff

// Mainscreen buttons (global for show/hide depending on sm_found)
lv_obj_t *btn_dried  = nullptr;  // "Dried today" — visible when sm_found
lv_obj_t *btn_link   = nullptr;  // "Link"             — visible when !sm_found && tag_present
lv_obj_t *btn_weight_main = nullptr;  // "Update Weight" — always visible when sm_found

// More Info screen (overlay, always rebuilt)
static lv_obj_t *scr_more_info = nullptr;

// More Info labels (updated when screen is built)
static lv_obj_t *lbl_mi_smid    = nullptr;
static lv_obj_t *lbl_mi_swatch  = nullptr;
static lv_obj_t *lbl_mi_mat     = nullptr;
static lv_obj_t *lbl_mi_name    = nullptr;
static lv_obj_t *lbl_mi_uid     = nullptr;
static lv_obj_t *lbl_mi_hex     = nullptr;
static lv_obj_t *lbl_mi_article = nullptr;
static lv_obj_t *lbl_mi_prod    = nullptr;
static lv_obj_t *lbl_mi_spool_w = nullptr;
static lv_obj_t *lbl_mi_uuid    = nullptr;

int scan_count = 0;
lv_obj_t *page_main;

// ============================================================
//  MIFARE CLASSIC – authenticate and read sector
//  Key B is used for Bambu-encrypted sectors
// ============================================================
bool readSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16]) {
  return nfcReadMifareSector(sector, key, uid, blocks);
}

// ============================================================
//  FULL TAG SCAN
// ============================================================
void scanTag(uint8_t *uid, uint8_t uid_len) {
  memset(&g_tag, 0, sizeof(g_tag));
  memcpy(g_tag.uid, uid, 4);
  sprintf(g_tag.uid_str, "%02X:%02X:%02X:%02X",
    uid[0], uid[1], uid[2], uid[3]);

  Serial.printf("\n=== Tag gefunden: %s ===\n", g_tag.uid_str);
  logSDf("NFC: Bambu tag found UID=%s", g_tag.uid_str);

  // Derive keys
  Serial.println("Deriving keys...");
  if (!deriveKeys(uid, uid_len, g_tag.keys)) {
    Serial.println("Key derivation failed!");
    return;
  }

  // Print keys (serial monitor)
  for (int i = 0; i < 16; i++) {
    Serial.printf("Key %2d: %02X%02X%02X%02X%02X%02X\n", i,
      g_tag.keys[i][0], g_tag.keys[i][1], g_tag.keys[i][2],
      g_tag.keys[i][3], g_tag.keys[i][4], g_tag.keys[i][5]);
  }
  if (sd_verbose) {
    for (int i = 0; i < 16; i++) {
      logSDf("[verbose] KDF key %2d: %02X%02X%02X%02X%02X%02X", i,
        g_tag.keys[i][0], g_tag.keys[i][1], g_tag.keys[i][2],
        g_tag.keys[i][3], g_tag.keys[i][4], g_tag.keys[i][5]);
    }
  }

  // Read all 16 sectors
  Serial.println("Reading sectors...");
  int success_count = 0;
  // Build a compact verbose summary string: "0:OK 1:OK 2:FAIL ..."
  char sector_summary[160] = "";
  for (int sector = 0; sector < 16; sector++) {
    uint8_t sec_blocks[4][16];
    bool ok = readSector(sector, g_tag.keys[sector], uid, sec_blocks);
    for (int b = 0; b < 3; b++) {
      int block_num = sector * 4 + b;
      if (ok) {
        memcpy(g_tag.blocks[block_num], sec_blocks[b], 16);
        g_tag.block_ok[block_num] = true;
        success_count++;
      }
    }
    Serial.printf("Sector %2d: %s\n", sector, ok ? "OK" : "FAIL");
    if (sd_verbose) {
      char tmp[12];
      snprintf(tmp, sizeof(tmp), "%d:%s ", sector, ok ? "OK" : "FAIL");
      strncat(sector_summary, tmp, sizeof(sector_summary) - strlen(sector_summary) - 1);
    }
  }
  if (sd_verbose) logSDf("[verbose] sectors: %s", sector_summary);

  Serial.printf("%d/48 blocks read\n", success_count);
  logSDf("NFC: %d/48 blocks read", success_count);

  // Sector 0, block 0 is always readable (manufacturer data)
  uint8_t block0[16];
  if (nfcReadMifareBlock(0, block0)) {
    memcpy(g_tag.blocks[0], block0, 16);
    g_tag.block_ok[0] = true;
  }

  // Parse data
  parseTagData(g_tag);

  Serial.printf("tray_uuid: %s\n", g_tag.tray_uuid);
  Serial.printf("MaterialVariantID:   %s\n", g_tag.material_variant_id);
  Serial.printf("MaterialID: %s\n", g_tag.material_id);
  Serial.printf("Material:  %s\n", g_tag.material);
  Serial.printf("Color:     %s\n", g_tag.color_hex);
  Serial.printf("Temp:      %d - %d C\n", g_tag.temp_min, g_tag.temp_max);
  Serial.printf("Vendor:    %s\n", g_tag.vendor);
  Serial.printf("Date:      %s\n", g_tag.production_date);

  g_tag_ready = true;
}

// ============================================================
//  "DRIED TODAY" BUTTON CALLBACK
//  Writes current date as last_dried to Spoolman
// ============================================================
void btn_dried_cb(lv_event_t *e) {
  logSD("UI: Button -> Dried Today");
  if (!wifi_ok) {
    lv_label_set_text(lbl_spoolman_dried_val, "No WiFi!");
    return;
  }
  if (!sm_found || sm_id == 0) {
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_WAIT_SCAN));
    return;
  }

  // Current time as ISO8601 UTC string
  struct tm ti;
  char iso_full_buf[32] = "2026-01-01T00:00:00.000Z";
  if (getLocalTime(&ti)) {
    // Local time (UTC+1) -> convert to UTC
    time_t now = mktime(&ti);
    struct tm *utc = gmtime(&now);
    snprintf(iso_full_buf, sizeof(iso_full_buf), "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
      utc->tm_year+1900, utc->tm_mon+1, utc->tm_mday,
      utc->tm_hour, utc->tm_min, utc->tm_sec);
  }
  String iso_full = String(iso_full_buf);
  String today = iso_full.substring(0, 10);

  Serial.printf("Setting last_dried: %s for spool ID %d\n", iso_full.c_str(), sm_id);

  int code = spoolmanPatchSpoolLastDried(cfg_spoolman_base, sm_id, iso_full.c_str());

  if (code == 200) {
    // Update display
    char de_date[12];
    isoToDe(today.c_str(), de_date, sizeof(de_date));
    strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
    applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, de_date);
    Serial.println("last_dried set!");
  } else {
    Serial.printf("PATCH error: %d\n", code);
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_ERR_SAVE));
  }
}

// ============================================================
//  PREFERENCES (NVS)
// ============================================================

// Helper: format a weight value according to g_whole_gram setting
static inline void fmtG(char* buf, size_t len, float val) {
  if (val > -0.5f && val < 0.5f) val = 0.0f;  // prevent "-0 g"
  if (g_whole_gram) snprintf(buf, len, "%.0f g", val);
  else              snprintf(buf, len, "%.1f g", val);
}

void loadPrefs() {
  String ssid = prefsGetString("wifi_ssid", cfg_wifi_ssid);
  String pass = prefsGetString("wifi_pass", cfg_wifi_password);
  String ip   = prefsGetString("spoolman_ip", cfg_spoolman_ip);
  strncpy(cfg_wifi_ssid,     ssid.c_str(), sizeof(cfg_wifi_ssid)-1);
  strncpy(cfg_wifi_password, pass.c_str(), sizeof(cfg_wifi_password)-1);
  strncpy(cfg_spoolman_ip,   ip.c_str(),   sizeof(cfg_spoolman_ip)-1);
  snprintf(cfg_spoolman_base, sizeof(cfg_spoolman_base), "http://%s", cfg_spoolman_ip);
  // NAU7802: Kalibrierfaktor und Tare-Offset laden
  cal_factor  = prefsGetFloat("cal_factor",   CAL_FACTOR_DEFAULT);
  zero_offset = prefsGetInt("zero_offset", 0);
  bag_weight_g = prefsGetFloat("bag_weight", 50.0f);
  spool_list_limit   = (int)prefsGetUChar("list_limit",  16);
  if (spool_list_limit < 5)   spool_list_limit = 5;
  if (spool_list_limit > 100)  spool_list_limit = 100;
  location_list_limit = (int)prefsGetUChar("loc_limit", 30);
  if (location_list_limit < 5)   location_list_limit = 5;
  if (location_list_limit > 100)  location_list_limit = 100;
  // Display-Einstellungen laden
  bright_normal    = prefsGetUChar("bright",    BRIGHT_NORMAL_DEFAULT);
  int dim_min      = prefsGetUInt("dim_min",    DIM_TIMEOUT_DEFAULT / 60000);
  int sleep_min    = prefsGetUInt("sleep_min",  SLEEP_TIMEOUT_DEFAULT / 60000);
  dim_timeout_ms   = dim_min * 60000;
  sleep_timeout_ms = sleep_min * 60000;
  g_lang     = (Lang)prefsGetUChar("lang",     1);  // Default EN
  g_date_fmt =       prefsGetUChar("date_fmt", 0);
  cfg_lang_set =     prefsGetBool("lang_set",  false);
  cfg_first_boot =   prefsGetBool("first_boot", true);
  last_used_mode =   prefsGetUChar("lu_mode",  0);  // 0=OpenSpoolMan, 1=Last Weighed
  g_whole_gram   =   prefsGetBool("whole_gram", false);
  g_auto_weight  =   prefsGetBool("auto_weight", false);
  g_auto_loc_popup =  prefsGetBool("auto_loc_popup", false);
  gh_prerelease    =  prefsGetBool("gh_prerelease",  false);
  // Drying Reminder
  g_dry_mode       = prefsGetUChar("dry_mode", 0);
  g_dry_man_yellow = (int)prefsGetInt("dry_man_y", 30);
  g_dry_man_red    = (int)prefsGetInt("dry_man_r", 90);
  g_dry_mult_sealed = prefsGetFloat("dry_mult_s", 2.0f);
  { char key[16];
    for (int i = 0; i < DRY_MAT_COUNT; i++) {
      snprintf(key, sizeof(key), "dry_y_%s", DRY_MAT_NAMES[i]);
      g_dry_mat_yellow[i] = (int)prefsGetInt(key, DRY_MAT_DEF_YELLOW[i]);
      snprintf(key, sizeof(key), "dry_r_%s", DRY_MAT_NAMES[i]);
      g_dry_mat_red[i]    = (int)prefsGetInt(key, DRY_MAT_DEF_RED[i]);
      snprintf(key, sizeof(key), "dry_s_%s", DRY_MAT_NAMES[i]);
      g_dry_mat_sealed[i] = prefsGetBool(key, false);
    }
  }
  Serial.printf("Prefs: SSID=%s Spoolman=%s\n", cfg_wifi_ssid, cfg_spoolman_base);
  Serial.printf("Scale: cal_factor=%.4f  zero_offset=%d  bag_weight=%.1fg\n",
    cal_factor, zero_offset, bag_weight_g);
  Serial.printf("Display: bright=%d dim=%dmin sleep=%dmin\n",
    bright_normal, dim_min, sleep_min);
}

void saveCalFactor(float factor) {
  cal_factor = factor;
  prefsPutFloat("cal_factor", factor);
  Serial.printf("cal_factor saved: %.4f\n", factor);
}

void saveBagWeight(float weight) {
  bag_weight_g = weight;
  prefsPutFloat("bag_weight", weight);
  Serial.printf("bag_weight saved: %.1fg\n", weight);
}

void saveTareOffset(int32_t offset) {
  zero_offset = offset;
  prefsPutInt("zero_offset", offset);
  Serial.printf("zero_offset saved: %d\n", offset);
}

void resetScaleFilter() {
  memset(scale_filter_buf, 0, sizeof(scale_filter_buf));
  scale_filter_idx = 0;
  scale_filter_full = false;
}

void clearExtraFieldsUiPointers() {
  lbl_extra_fields_status = nullptr;
  btn_extra_fields_create = nullptr;
  btn_extra_fields_next = nullptr;
}

void saveWifiCredentials(const char* ssid, const char* pass) {
  strncpy(cfg_wifi_ssid,     ssid, sizeof(cfg_wifi_ssid)-1);
  strncpy(cfg_wifi_password, pass, sizeof(cfg_wifi_password)-1);
  prefsPutString("wifi_ssid", ssid);
  prefsPutString("wifi_pass",  pass);
  Serial.printf("WiFi saved: SSID=%s\n", ssid);
}


void saveSpoolmanIP(const char* ip) {
  strncpy(cfg_spoolman_ip, ip, sizeof(cfg_spoolman_ip)-1);
  snprintf(cfg_spoolman_base, sizeof(cfg_spoolman_base), "http://%s", ip);
  prefsPutString("spoolman_ip", ip);
}

// ============================================================
//  HELPER FUNCTIONS: Consistent navigation buttons
//  Back (←): top left, 36x36, goes one level up
//  Close (✕): top right, 36x36, goes directly to main screen
// ============================================================
// ============================================================
//  SETTINGS SCREENS
// ============================================================

// Helper: go back to main screen
void hideAllOverlays() {
  // ── Verbose tracing: count visible overlays + log which one is being deleted ──
  if (sd_verbose) {
    int visible_count = 0;
    if (scr_settings && !lv_obj_has_flag(scr_settings, LV_OBJ_FLAG_HIDDEN)) visible_count++;
    if (scr_connection && !lv_obj_has_flag(scr_connection, LV_OBJ_FLAG_HIDDEN)) visible_count++;
    if (scr_scale_sub && !lv_obj_has_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN)) visible_count++;
    if (scr_display && !lv_obj_has_flag(scr_display, LV_OBJ_FLAG_HIDDEN)) visible_count++;
    if (scr_system && !lv_obj_has_flag(scr_system, LV_OBJ_FLAG_HIDDEN)) visible_count++;
    logSDf("[verbose] hideAllOverlays: %d visible, more_info=%s",
      visible_count, scr_more_info ? "yes(will delete)" : "no");
  }
  // scr_more_info is always rebuilt — safe to delete here
  if (scr_more_info) {
    if (sd_verbose) logSD("[verbose] hideAllOverlays: deleting scr_more_info");
    lv_obj_del(scr_more_info); scr_more_info = nullptr;
    if (sd_verbose) logSD("[verbose] hideAllOverlays: scr_more_info deleted OK");
  }
  // All other screens: hidden only. Deleting here causes PANIC because
  // callbacks call hideAllOverlays() while still running inside the screen's
  // event context. Safe deletion happens in showMainScreen() and showSettingsScreen().
  if (scr_settings)    lv_obj_add_flag(scr_settings,    LV_OBJ_FLAG_HIDDEN);
  if (scr_connection)  lv_obj_add_flag(scr_connection,  LV_OBJ_FLAG_HIDDEN);
  if (scr_scale_sub)   lv_obj_add_flag(scr_scale_sub,   LV_OBJ_FLAG_HIDDEN);
  if (scr_drying_reminder) lv_obj_add_flag(scr_drying_reminder, LV_OBJ_FLAG_HIDDEN);
  if (scr_display)     lv_obj_add_flag(scr_display,     LV_OBJ_FLAG_HIDDEN);
  if (scr_system)      lv_obj_add_flag(scr_system,      LV_OBJ_FLAG_HIDDEN);
  if (scr_ota)         lv_obj_add_flag(scr_ota,         LV_OBJ_FLAG_HIDDEN);
  if (scr_ota_browser) lv_obj_add_flag(scr_ota_browser, LV_OBJ_FLAG_HIDDEN);
  if (scr_ota_github)  lv_obj_add_flag(scr_ota_github,  LV_OBJ_FLAG_HIDDEN);
  if (scr_factor)      lv_obj_add_flag(scr_factor,      LV_OBJ_FLAG_HIDDEN);
  if (scr_bag)         lv_obj_add_flag(scr_bag,         LV_OBJ_FLAG_HIDDEN);
  if (scr_lastused)    lv_obj_add_flag(scr_lastused,    LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman_fail) lv_obj_add_flag(scr_spoolman_fail, LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi)        lv_obj_add_flag(scr_wifi,        LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman)    lv_obj_add_flag(scr_spoolman,    LV_OBJ_FLAG_HIDDEN);
  if (scr_welcome)     lv_obj_add_flag(scr_welcome,     LV_OBJ_FLAG_HIDDEN);
  if (scr_first_boot)  lv_obj_add_flag(scr_first_boot,  LV_OBJ_FLAG_HIDDEN);
  if (scr_extra_fields) lv_obj_add_flag(scr_extra_fields, LV_OBJ_FLAG_HIDDEN);
  if (scr_cal_reminder) lv_obj_add_flag(scr_cal_reminder, LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_setup)  lv_obj_add_flag(scr_wifi_setup,  LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_pass)   lv_obj_add_flag(scr_wifi_pass,   LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_connecting) lv_obj_add_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN);
  // Free PSRAM spool list if link flow was aborted
  if (link_spools) { free(link_spools); link_spools = nullptr; link_spool_count = 0; }
}

void showMainScreen() {
  logSD("SHOW: MainScreen");
  logSD("UI: Screen -> Main");
  id_input_open = false;  // always clear on return to main
  hideAllOverlays();
  // Safe to delete all menu screens here — no screen callbacks are active
  if (scr_settings)    { lv_obj_del(scr_settings);    scr_settings    = nullptr; }
  if (scr_connection)  { lv_obj_del(scr_connection);  scr_connection  = nullptr; }
  if (scr_scale_sub)   { lv_obj_del(scr_scale_sub);   scr_scale_sub   = nullptr; }
  if (scr_drying_reminder) { lv_obj_del(scr_drying_reminder); scr_drying_reminder = nullptr; }
  if (s_dry_numpad_scr)    { lv_obj_del(s_dry_numpad_scr);    s_dry_numpad_scr    = nullptr; }
  // lbl_dried_sym bleibt gueltig (lebt auf Hauptscreen, wird nicht geloescht)
  s_dry_numpad_lbl = nullptr;
  if (scr_display)     { lv_obj_del(scr_display);     scr_display     = nullptr; }
  if (scr_system)      { lv_obj_del(scr_system);      scr_system      = nullptr; }
  if (scr_ota)         { lv_obj_del(scr_ota);         scr_ota         = nullptr; }
  if (scr_ota_browser) { lv_obj_del(scr_ota_browser); scr_ota_browser = nullptr; }
  if (scr_ota_github)  { lv_obj_del(scr_ota_github);  scr_ota_github  = nullptr; }
  if (scr_factor)      { lv_obj_del(scr_factor);      scr_factor      = nullptr; }
  if (scr_bag)         { lv_obj_del(scr_bag);         scr_bag         = nullptr; }
  if (scr_lastused)    { lv_obj_del(scr_lastused);    scr_lastused    = nullptr; }
  if (scr_spoolman_fail){ lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
  if (scr_welcome)     { lv_obj_del(scr_welcome);     scr_welcome     = nullptr; }
  if (scr_first_boot)  { lv_obj_del(scr_first_boot);  scr_first_boot  = nullptr; }
  if (scr_extra_fields){ lv_obj_del(scr_extra_fields); scr_extra_fields = nullptr;
                         lbl_extra_fields_status = nullptr;
                         btn_extra_fields_create = nullptr;
                         btn_extra_fields_next   = nullptr; }
  if (scr_cal_reminder){ lv_obj_del(scr_cal_reminder); scr_cal_reminder = nullptr; }
  // Copy spool flow screens
  if (scr_copy_entry)   { lv_obj_del(scr_copy_entry);   scr_copy_entry   = nullptr; }
  if (scr_copy_id)      { lv_obj_del(scr_copy_id);      scr_copy_id      = nullptr; }
  if (scr_copy_list)    { lv_obj_del(scr_copy_list);    scr_copy_list    = nullptr; }
  if (scr_copy_confirm) { lv_obj_del(scr_copy_confirm); scr_copy_confirm = nullptr; }
  resetActivityTimer();
  updateLinkButton();  // refresh buttons after any flow completes
}

void showSettingsScreen() {
  logSD("SHOW: SettingsScreen");
  logSD("UI: Screen -> Settings");
  // Free setup screens if still in memory
  if (scr_welcome)    { lv_obj_del(scr_welcome);    scr_welcome    = nullptr; }
  if (scr_first_boot) { lv_obj_del(scr_first_boot); scr_first_boot = nullptr; }
  if (scr_wifi_setup) { lv_obj_del(scr_wifi_setup); scr_wifi_setup = nullptr; }
  if (scr_wifi_pass)  { lv_obj_del(scr_wifi_pass);  scr_wifi_pass  = nullptr; }
  hideAllOverlays();
  // Safe to delete sub-screens here — no sub-screen callbacks are active
  if (scr_settings)    { lv_obj_del(scr_settings);    scr_settings    = nullptr; }
  if (scr_connection)  { lv_obj_del(scr_connection);  scr_connection  = nullptr; }
  if (scr_scale_sub)   { lv_obj_del(scr_scale_sub);   scr_scale_sub   = nullptr; }
  if (scr_display)     { lv_obj_del(scr_display);     scr_display     = nullptr; }
  if (scr_system)      { lv_obj_del(scr_system);      scr_system      = nullptr; }
  if (scr_ota)         { lv_obj_del(scr_ota);         scr_ota         = nullptr; }
  if (scr_ota_browser) { lv_obj_del(scr_ota_browser); scr_ota_browser = nullptr; }
  if (scr_ota_github)  { lv_obj_del(scr_ota_github);  scr_ota_github  = nullptr; }
  if (scr_factor)      { lv_obj_del(scr_factor);      scr_factor      = nullptr; }
  if (scr_bag)         { lv_obj_del(scr_bag);         scr_bag         = nullptr; }
  if (scr_lastused)    { lv_obj_del(scr_lastused);    scr_lastused    = nullptr; }
  if (scr_spoolman_fail){ lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
  buildSettingsScreen();
  lv_obj_clear_flag(scr_settings, LV_OBJ_FLAG_HIDDEN);
  resetActivityTimer();
}

// ============================================================
//  WELCOME SCREEN (first boot — SSID empty)
// ============================================================
void showWelcomeScreen() {
  logSD("SHOW: WelcomeScreen");
  logSD("UI: Screen -> Welcome");
  hideAllOverlays();
  if (!scr_welcome) buildWelcomeScreen();
  lv_obj_clear_flag(scr_welcome, LV_OBJ_FLAG_HIDDEN);
}

void buildWelcomeScreen() {
  logSD("BUILD: WelcomeScreen");
  scr_welcome = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_welcome, 480, 320);
  lv_obj_set_pos(scr_welcome, 0, 0);
  lv_obj_add_flag(scr_welcome, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_welcome, 0, 0);
  lv_obj_set_style_border_width(scr_welcome, 0, 0);
  lv_obj_set_style_pad_all(scr_welcome, 0, 0);
  lv_obj_clear_flag(scr_welcome, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_welcome, lv_color_hex(0x0a1020), 0);

  // First boot: language selection
  lv_obj_t *lbl_logo = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_logo, "SpoolmanScale");
  lv_obj_set_style_text_color(lbl_logo, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_logo, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_logo, LV_ALIGN_TOP_MID, 0, 24);

  lv_obj_t *lbl_sub = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_sub, T(STR_WELCOME_LANG_TITLE));
  lv_obj_set_style_text_color(lbl_sub, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sub, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_sub, LV_ALIGN_TOP_MID, 0, 64);

  lv_obj_t *lbl_hint = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_hint, T(STR_WELCOME_LANG_HINT));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, 420);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 96);

  // X button top right (only if lang already set — no infinite loop)
  if (cfg_lang_set) {
    lv_obj_t *btn_x = lv_btn_create(scr_welcome);
    lv_obj_set_size(btn_x, 44, 44);
    lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
    lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_x, 8, 0);
    lv_obj_set_style_shadow_width(btn_x, 0, 0);
    lv_obj_set_style_border_width(btn_x, 0, 0);
    lv_obj_t *lbl_x = lv_label_create(btn_x);
    lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl_x);
    lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
  }

  // X button top right (only if lang already set — no infinite loop)
  // Language buttons side by side
  const int LB_W = 218, LB_H = 60, LB_Y = 136;

  // EN button (links — Standard, hervorgehoben)
  lv_obj_t *btn_en = lv_btn_create(scr_welcome);
  lv_obj_set_size(btn_en, LB_W, LB_H);
  lv_obj_set_pos(btn_en, 8, LB_Y);
  lv_obj_set_style_bg_color(btn_en, lv_color_hex(0x0a2a40), 0);
  lv_obj_set_style_bg_color(btn_en, lv_color_hex(0x1a4060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_en, 10, 0);
  lv_obj_set_style_shadow_width(btn_en, 0, 0);
  lv_obj_set_style_border_width(btn_en, 2, 0);
  lv_obj_set_style_border_color(btn_en, lv_color_hex(0x28d49a), 0);
  lv_obj_t *lbl_en = lv_label_create(btn_en);
  lv_label_set_text(lbl_en, "EN   English");
  lv_obj_set_style_text_color(lbl_en, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_en, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_en);
  lv_obj_add_event_cb(btn_en, [](lv_event_t *e){
    prefsPutUChar("lang", 1);
    prefsPutBool("lang_set", true);
    prefsPutBool("first_boot", true);
    g_lang = LANG_EN;
    cfg_lang_set = true;
    cfg_first_boot = true;
    // EN is default — no reboot needed, defer screen switch to loop
    lang_selected_no_reboot = true;
  }, LV_EVENT_CLICKED, NULL);

  // DE button (rechts)
  lv_obj_t *btn_de = lv_btn_create(scr_welcome);
  lv_obj_set_size(btn_de, LB_W, LB_H);
  lv_obj_set_pos(btn_de, 254, LB_Y);
  lv_obj_set_style_bg_color(btn_de, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_de, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_de, 10, 0);
  lv_obj_set_style_shadow_width(btn_de, 0, 0);
  lv_obj_set_style_border_width(btn_de, 2, 0);
  lv_obj_set_style_border_color(btn_de, lv_color_hex(0x1a3060), 0);
  lv_obj_t *lbl_de = lv_label_create(btn_de);
  lv_label_set_text(lbl_de, "DE   Deutsch");
  lv_obj_set_style_text_color(lbl_de, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_de, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_de);
  lv_obj_add_event_cb(btn_de, [](lv_event_t *e){
    g_lang = LANG_DE;
    prefsPutUChar("lang", 0);
    prefsPutBool("lang_set", true);
    prefsPutBool("first_boot", true);  // show welcome screen after restart
    ESP.restart();
  }, LV_EVENT_CLICKED, NULL);

  // Bottom hint
  lv_obj_t *lbl_skip = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_skip, T(STR_LANG_HINT));
  lv_obj_set_style_text_color(lbl_skip, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_skip, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_skip, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_skip, LV_ALIGN_BOTTOM_MID, 0, -10);
}

// ============================================================
//  FIRST BOOT SCREEN (very first launch — before language selection)
// ============================================================
void showFirstBootScreen() {
  logSD("SHOW: FirstBootScreen");
  logSD("UI: Screen -> FirstBoot");
  hideAllOverlays();
  if (!scr_first_boot) buildFirstBootScreen();
  lv_obj_clear_flag(scr_first_boot, LV_OBJ_FLAG_HIDDEN);
}

void buildFirstBootScreen() {
  logSD("BUILD: FirstBootScreen");
  scr_first_boot = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_first_boot, 480, 320);
  lv_obj_set_pos(scr_first_boot, 0, 0);
  lv_obj_add_flag(scr_first_boot, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_first_boot, 0, 0);
  lv_obj_set_style_border_width(scr_first_boot, 0, 0);
  lv_obj_set_style_pad_all(scr_first_boot, 0, 0);
  lv_obj_clear_flag(scr_first_boot, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_first_boot, lv_color_hex(0x0a1020), 0);

  // Logo
  lv_obj_t *lbl_logo = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_logo, "SpoolmanScale");
  lv_obj_set_style_text_color(lbl_logo, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_logo, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_logo, LV_ALIGN_TOP_MID, 0, 32);

  // Welcome title
  lv_obj_t *lbl_title = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_title, T(STR_FIRSTBOOT_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_20, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 72);

  // Subtitle
  lv_obj_t *lbl_sub = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_sub, T(STR_FIRSTBOOT_SUB));
  lv_obj_set_style_text_color(lbl_sub, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_sub, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_sub, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_sub, LV_ALIGN_TOP_MID, 0, 104);

  // Hint
  lv_obj_t *lbl_hint = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_hint, T(STR_FIRSTBOOT_HINT));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, 420);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 138);

  // X button: only show if WiFi already configured (not absolute first boot)
  if (strlen(cfg_wifi_ssid) > 0) {
    lv_obj_t *btn_cx = lv_btn_create(scr_first_boot);
    lv_obj_set_size(btn_cx, 44, 44);
    lv_obj_align(btn_cx, LV_ALIGN_TOP_RIGHT, -4, 2);
    lv_obj_set_style_bg_color(btn_cx, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_cx, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_cx, 8, 0);
    lv_obj_set_style_shadow_width(btn_cx, 0, 0);
    lv_obj_set_style_border_width(btn_cx, 0, 0);
    lv_obj_add_event_cb(btn_cx, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_cx = lv_label_create(btn_cx);
    lv_label_set_text(lbl_cx, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(lbl_cx, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_cx, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl_cx);
  }

  // Get started button (links) + Skip button (rechts), symmetrisch
  lv_obj_t *btn_start = lv_btn_create(scr_first_boot);
  lv_obj_set_size(btn_start, 226, 48);
  lv_obj_set_pos(btn_start, 12, 252);
  lv_obj_set_style_bg_color(btn_start, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_start, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_start, 10, 0);
  lv_obj_set_style_shadow_width(btn_start, 0, 0);
  lv_obj_set_style_border_width(btn_start, 1, 0);
  lv_obj_set_style_border_color(btn_start, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_start, [](lv_event_t *e) {
    prefsPutBool("first_boot", false);
    cfg_first_boot = false;
    showWifiSetupScreen();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_start = lv_label_create(btn_start);
  lv_label_set_text(lbl_start, T(STR_FIRSTBOOT_BTN));
  lv_obj_set_style_text_color(lbl_start, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_start, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_start, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_start, LV_ALIGN_CENTER, 0, 0);

  // Skip setup button (rechts)
  lv_obj_t *btn_skip = lv_btn_create(scr_first_boot);
  lv_obj_set_size(btn_skip, 226, 48);
  lv_obj_set_pos(btn_skip, 242, 252);
  lv_obj_set_style_bg_color(btn_skip, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_skip, lv_color_hex(0x1a2840), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_skip, 10, 0);
  lv_obj_set_style_shadow_width(btn_skip, 0, 0);
  lv_obj_set_style_border_width(btn_skip, 1, 0);
  lv_obj_set_style_border_color(btn_skip, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_skip, [](lv_event_t *e) {
    skip_setup_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_skip = lv_label_create(btn_skip);
  char skip_buf[32];
  strncpy(skip_buf, T(STR_BTN_SKIP_SETUP), sizeof(skip_buf)-1);
  lv_label_set_text(lbl_skip, skip_buf);
  lv_obj_set_style_text_color(lbl_skip, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_skip, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_skip, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_skip, LV_ALIGN_CENTER, 0, 0);
}

// ============================================================
//  EXTRA FIELDS SCREEN
//  Check/create Spoolman extra fields 'tag' and 'last_dried'
// ============================================================

// Required extra fields — extend this array for future fields
static const char* REQUIRED_EXTRA_FIELDS_BASE[] = { "tag", "last_dried" };
static const int   REQUIRED_EXTRA_FIELDS_BASE_COUNT = 2;

void showExtraFieldsScreen(bool is_setup_flow) {
  logSD("SHOW: ExtraFieldsScreen");
  logSDf("UI: Screen -> ExtraFields (setup=%d)", is_setup_flow ? 1 : 0);
  hideAllOverlays();
  extra_fields_setup_flow = is_setup_flow;
  if (scr_extra_fields) { lv_obj_del(scr_extra_fields); scr_extra_fields = nullptr; }
  lbl_extra_fields_status = nullptr;
  btn_extra_fields_create = nullptr;
  btn_extra_fields_next   = nullptr;
  buildExtraFieldsScreen(is_setup_flow);
  lv_obj_clear_flag(scr_extra_fields, LV_OBJ_FLAG_HIDDEN);
}

void buildExtraFieldsScreen(bool is_setup_flow) {
  logSD("BUILD: ExtraFieldsScreen");
  scr_extra_fields = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_extra_fields, 480, 320);
  lv_obj_set_pos(scr_extra_fields, 0, 0);
  lv_obj_add_flag(scr_extra_fields, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_extra_fields, 0, 0);
  lv_obj_set_style_border_width(scr_extra_fields, 0, 0);
  lv_obj_set_style_pad_all(scr_extra_fields, 0, 0);
  lv_obj_clear_flag(scr_extra_fields, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_extra_fields, lv_color_hex(0x0a1020), 0);

  // Header: back goes to connection screen (if from settings), or back to Spoolman IP (setup flow)
  if (!is_setup_flow) {
    buildSubHeader(scr_extra_fields, T(STR_EXTRA_FIELDS_TITLE),
      [](lv_event_t *e) {
        if (!scr_connection) buildConnectionScreen();
        hideAllOverlays();
        lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
      });
  } else {
    // Setup flow: title only + X (→ main screen), no back button
    lv_obj_t *lbl_title = lv_label_create(scr_extra_fields);
    lv_label_set_text(lbl_title, T(STR_EXTRA_FIELDS_TITLE));
    lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

    // X → main screen (exit setup)
    lv_obj_t *btn_x = lv_btn_create(scr_extra_fields);
    lv_obj_set_size(btn_x, 44, 44);
    lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
    lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_x, 8, 0);
    lv_obj_set_style_shadow_width(btn_x, 0, 0);
    lv_obj_set_style_border_width(btn_x, 0, 0);
    lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ logSD("BTN: Close -> Main"); showMainScreen(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_x = lv_label_create(btn_x);
    lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl_x);
  }

  // Hint text
  lv_obj_t *lbl_hint = lv_label_create(scr_extra_fields);
  lv_label_set_text(lbl_hint, T(STR_EXTRA_FIELDS_HINT));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint, 440);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 54);

  // Check button
  lv_obj_t *btn_check = lv_btn_create(scr_extra_fields);
  lv_obj_set_size(btn_check, 280, 44);
  lv_obj_align(btn_check, LV_ALIGN_TOP_MID, 0, 138);
  lv_obj_set_style_bg_color(btn_check, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_check, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_check, 8, 0);
  lv_obj_set_style_shadow_width(btn_check, 0, 0);
  lv_obj_set_style_border_width(btn_check, 1, 0);
  lv_obj_set_style_border_color(btn_check, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_check, [](lv_event_t *e) {
    extra_fields_check_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_check = lv_label_create(btn_check);
  lv_label_set_text(lbl_check, T(STR_EXTRA_FIELDS_CHECK_BTN));
  lv_obj_set_style_text_color(lbl_check, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_check, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_check);

  // Status label — below check button
  lbl_extra_fields_status = lv_label_create(scr_extra_fields);
  lv_label_set_text(lbl_extra_fields_status, "");
  lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_extra_fields_status, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_extra_fields_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_extra_fields_status, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_extra_fields_status, 440);
  lv_obj_align(lbl_extra_fields_status, LV_ALIGN_TOP_MID, 0, 192);

  // Create missing fields button — full width, above bottom row, initially hidden
  btn_extra_fields_create = lv_btn_create(scr_extra_fields);
  lv_obj_set_size(btn_extra_fields_create, 440, 42);
  lv_obj_align(btn_extra_fields_create, LV_ALIGN_TOP_MID, 0, 228);
  lv_obj_set_style_bg_color(btn_extra_fields_create, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_extra_fields_create, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_extra_fields_create, 8, 0);
  lv_obj_set_style_shadow_width(btn_extra_fields_create, 0, 0);
  lv_obj_set_style_border_width(btn_extra_fields_create, 1, 0);
  lv_obj_set_style_border_color(btn_extra_fields_create, lv_color_hex(0x2a5030), 0);
  lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
  lv_obj_add_event_cb(btn_extra_fields_create, [](lv_event_t *e) {
    // Confirmation popup
    lv_obj_t *pop = lv_obj_create(lv_scr_act());
    lv_obj_set_size(pop, 480, 320);
    lv_obj_set_pos(pop, 0, 0);
    lv_obj_set_style_bg_color(pop, lv_color_hex(0x00000080), 0);  // semi-transparent
    lv_obj_set_style_bg_opa(pop, LV_OPA_70, 0);
    lv_obj_set_style_border_width(pop, 0, 0);
    lv_obj_set_style_radius(pop, 0, 0);
    lv_obj_set_style_pad_all(pop, 0, 0);
    lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *box = lv_obj_create(pop);
    lv_obj_set_size(box, 420, 220);
    lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_bg_color(box, lv_color_hex(0x0d1a2a), 0);
    lv_obj_set_style_border_color(box, lv_color_hex(0x1a3060), 0);
    lv_obj_set_style_border_width(box, 1, 0);
    lv_obj_set_style_radius(box, 10, 0);
    lv_obj_set_style_pad_all(box, 0, 0);
    lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *lbl_ct = lv_label_create(box);
    lv_label_set_text(lbl_ct, T(STR_EXTRA_FIELDS_CONFIRM_TITLE));
    lv_obj_set_style_text_color(lbl_ct, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_ct, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_ct, LV_ALIGN_TOP_MID, 0, 18);

    lv_obj_t *lbl_cm = lv_label_create(box);
    lv_label_set_text(lbl_cm, T(STR_EXTRA_FIELDS_CONFIRM_MSG));
    lv_obj_set_style_text_color(lbl_cm, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(lbl_cm, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl_cm, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(lbl_cm, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(lbl_cm, 380);
    lv_obj_align(lbl_cm, LV_ALIGN_TOP_MID, 0, 52);

    // Confirm button
    lv_obj_t *btn_conf = lv_btn_create(box);
    lv_obj_set_size(btn_conf, 180, 44);
    lv_obj_align(btn_conf, LV_ALIGN_BOTTOM_RIGHT, -12, -12);
    lv_obj_set_style_bg_color(btn_conf, lv_color_hex(0x1a3020), 0);
    lv_obj_set_style_bg_color(btn_conf, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_conf, 8, 0);
    lv_obj_set_style_shadow_width(btn_conf, 0, 0);
    lv_obj_set_style_border_width(btn_conf, 0, 0);
    lv_obj_add_event_cb(btn_conf, [](lv_event_t *e) {
      // Close popup (2 levels up: btn -> box -> pop)
      lv_obj_t *box_obj = lv_obj_get_parent(lv_event_get_target(e));
      lv_obj_t *pop_obj = lv_obj_get_parent(box_obj);
      lv_obj_del(pop_obj);
      // Defer HTTP call to loop — never call HTTP directly from LVGL event callback
      extra_fields_create_pending = true;
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_conf = lv_label_create(btn_conf);
    lv_label_set_text(lbl_conf, T(STR_CONFIRM));
    lv_obj_set_style_text_color(lbl_conf, lv_color_hex(0x40c080), 0);
    lv_obj_set_style_text_font(lbl_conf, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_conf);

    // Cancel button
    lv_obj_t *btn_can = lv_btn_create(box);
    lv_obj_set_size(btn_can, 140, 44);
    lv_obj_align(btn_can, LV_ALIGN_BOTTOM_LEFT, 12, -12);
    lv_obj_set_style_bg_color(btn_can, lv_color_hex(0x1a2030), 0);
    lv_obj_set_style_bg_color(btn_can, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_can, 8, 0);
    lv_obj_set_style_shadow_width(btn_can, 0, 0);
    lv_obj_set_style_border_width(btn_can, 0, 0);
    lv_obj_add_event_cb(btn_can, [](lv_event_t *e) {
      lv_obj_t *box_obj = lv_obj_get_parent(lv_event_get_target(e));
      lv_obj_t *pop_obj = lv_obj_get_parent(box_obj);
      lv_obj_del(pop_obj);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_can = lv_label_create(btn_can);
    lv_label_set_text(lbl_can, T(STR_CANCEL));
    lv_obj_set_style_text_color(lbl_can, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_can, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_can);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_create = lv_label_create(btn_extra_fields_create);
  lv_label_set_text(lbl_create, T(STR_EXTRA_FIELDS_CREATE_BTN));
  lv_obj_set_style_text_color(lbl_create, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_create, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_create);

  // Bottom row (y=276): Test field (left, 210px) | Skip/Next (right, 210px)
  btn_extra_fields_next = lv_btn_create(scr_extra_fields);
  lv_obj_t *btn_skip_bottom = btn_extra_fields_next;
  lv_obj_set_size(btn_skip_bottom, 210, 40);
  lv_obj_set_pos(btn_skip_bottom, 246, 276);
  lv_obj_set_style_bg_color(btn_skip_bottom, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_skip_bottom, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_skip_bottom, 8, 0);
  lv_obj_set_style_shadow_width(btn_skip_bottom, 0, 0);
  lv_obj_set_style_border_width(btn_skip_bottom, 1, 0);
  lv_obj_set_style_border_color(btn_skip_bottom, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_skip_bottom, [](lv_event_t *e) {
    if (extra_fields_setup_flow) {
      // Defer to loop — never call showCalReminderScreen directly from LVGL callback
      cal_reminder_pending = true;
    } else {
      if (!scr_connection) buildConnectionScreen();
      if (!scr_connection) buildConnectionScreen(); hideAllOverlays(); lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_skip_b = lv_label_create(btn_skip_bottom);
  char skip_buf[32];
  snprintf(skip_buf, sizeof(skip_buf), "%s  " LV_SYMBOL_RIGHT, T(STR_EXTRA_FIELDS_SKIP));
  lv_label_set_text(lbl_skip_b, skip_buf);
  lv_obj_set_style_text_color(lbl_skip_b, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_skip_b, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_skip_b);

  // Generate test field button (left, fixed y)
  lv_obj_t *btn_test = lv_btn_create(scr_extra_fields);
  lv_obj_set_size(btn_test, 210, 40);
  lv_obj_set_pos(btn_test, 18, 276);
  lv_obj_set_style_bg_color(btn_test, lv_color_hex(0x1a1a0a), 0);
  lv_obj_set_style_bg_color(btn_test, lv_color_hex(0x2a2a1a), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_test, 8, 0);
  lv_obj_set_style_shadow_width(btn_test, 0, 0);
  lv_obj_set_style_border_width(btn_test, 1, 0);
  lv_obj_set_style_border_color(btn_test, lv_color_hex(0x2a2a1a), 0);
  lv_obj_add_event_cb(btn_test, [](lv_event_t *e) {
    if (!wifi_ok || cfg_spoolman_base[0] == '\0') {
      if (lbl_extra_fields_status) {
        lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_NO_WIFI));
        lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
      }
      return;
    }
    int code = spoolmanCreateSpoolField(cfg_spoolman_base, "spoolscale_test", 1500);
    Serial.printf("Test field create: %d\n", code);
    if (lbl_extra_fields_status) {
      if (code == 200 || code == 201) {
        lv_label_set_text(lbl_extra_fields_status, T(STR_EF_TEST_CREATED));
        lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xf0b838), 0);
      } else if (code == 409) {
        lv_label_set_text(lbl_extra_fields_status, T(STR_EF_TEST_EXISTS));
        lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xf0b838), 0);
      } else {
        lv_label_set_text(lbl_extra_fields_status, T(STR_EF_TEST_FAIL));
        lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
      }
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_test = lv_label_create(btn_test);
  lv_label_set_text(lbl_test, T(STR_EF_TEST_BTN));
  lv_obj_set_style_text_color(lbl_test, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_test, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_test);
}

// Check existing fields, optionally create missing ones
void checkAndCreateExtraFields(bool create_missing) {
  if (!lbl_extra_fields_status) return;

  if (!wifi_ok) {
    lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_NO_WIFI));
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
    return;
  }
  if (cfg_spoolman_base[0] == '\0' || strcmp(cfg_spoolman_base, "http://") == 0) {
    lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_NO_SPOOLMAN));
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
    return;
  }

  lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_CHECKING));
  lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0x4a6fa0), 0);
  if (btn_extra_fields_create) lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
  lv_timer_handler();
  yield();

  // GET /api/v1/field/spool — list all existing extra fields
  DynamicJsonDocument doc(8192);
  DeserializationError err = DeserializationError::Ok;
  int code = spoolmanGetSpoolFieldsJson(cfg_spoolman_base, doc, 4000, &err);
  yield();
  lv_timer_handler();
  yield();
  lv_timer_handler();

  Serial.printf("Extra fields GET: %d\n", code);

  // Spoolman not reachable
  if (code < 0 || (code != 200 && code != 0)) {
    char buf[96];
    strncpy(buf, T(STR_SPOOLMAN_FAIL), sizeof(buf)-1); buf[sizeof(buf)-1]=0;
    lv_label_set_text(lbl_extra_fields_status, buf);
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
    return;
  }

  // Parse existing field names
  int ef_count = REQUIRED_EXTRA_FIELDS_BASE_COUNT;
  bool field_exists[8] = {false};
  if (code == 200 && !err) {
    JsonArray arr = doc.as<JsonArray>();
    for (JsonObject f : arr) {
      const char* fname = f["key"] | "";
      for (int i = 0; i < ef_count; i++) {
        if (strcmp(fname, REQUIRED_EXTRA_FIELDS_BASE[i]) == 0) {
          field_exists[i] = true;
        }
      }
    }
  }

  // Build missing list
  char missing_buf[64] = "";
  int missing_count = 0;
  for (int i = 0; i < ef_count; i++) {
    if (!field_exists[i]) {
      if (missing_count > 0) strncat(missing_buf, ", ", sizeof(missing_buf)-1);
      strncat(missing_buf, REQUIRED_EXTRA_FIELDS_BASE[i], sizeof(missing_buf)-1);
      missing_count++;
    }
  }

  if (missing_count == 0) {
    // All OK
    lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_ALL_OK));
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0x40c080), 0);
    if (btn_extra_fields_create) lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
    // Turn skip/next button green with "Next →" label
    if (btn_extra_fields_next) {
      lv_obj_set_style_bg_color(btn_extra_fields_next, lv_color_hex(0x1a3020), 0);
      lv_obj_set_style_bg_color(btn_extra_fields_next, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(btn_extra_fields_next, lv_color_hex(0x2a5030), 0);
      lv_obj_t *lbl = lv_obj_get_child(btn_extra_fields_next, 0);
      if (lbl) {
        char next_lbl[32];
        snprintf(next_lbl, sizeof(next_lbl), "%s  " LV_SYMBOL_RIGHT, T(STR_CONFIRM));
        lv_label_set_text(lbl, next_lbl);
        lv_obj_set_style_text_color(lbl, lv_color_hex(0x40c080), 0);
      }
    }
    Serial.println("Extra fields: all present");
    return;
  }

  if (!create_missing) {
    char status_buf[128];
    snprintf(status_buf, sizeof(status_buf), T(STR_EXTRA_FIELDS_MISSING), missing_buf);
    lv_label_set_text(lbl_extra_fields_status, status_buf);
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xf0b838), 0);
    if (btn_extra_fields_create) lv_obj_clear_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
    return;
  }

  // Create missing fields
  lv_label_set_text(lbl_extra_fields_status, T(STR_EXTRA_FIELDS_CREATING));
  lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0x4a6fa0), 0);
  lv_timer_handler();
  yield();

  char fail_fields[64] = "";
  int fail_count = 0;
  for (int i = 0; i < ef_count; i++) {
    if (field_exists[i]) continue;
    lv_timer_handler();  // keep LVGL alive between HTTP calls
    yield();             // feed watchdog
    int c2 = spoolmanCreateSpoolField(cfg_spoolman_base, REQUIRED_EXTRA_FIELDS_BASE[i], 3000);
    lv_timer_handler();  // update display after each POST
    yield();
    Serial.printf("Create field '%s': %d\n", REQUIRED_EXTRA_FIELDS_BASE[i], c2);
    if (c2 != 200 && c2 != 201) {
      if (fail_count > 0) strncat(fail_fields, ", ", sizeof(fail_fields)-1);
      strncat(fail_fields, REQUIRED_EXTRA_FIELDS_BASE[i], sizeof(fail_fields)-1);
      fail_count++;
    }
  }

  if (fail_count > 0) {
    char fail_buf[128];
    snprintf(fail_buf, sizeof(fail_buf), T(STR_EXTRA_FIELDS_CREATE_FAIL), fail_fields);
    lv_label_set_text(lbl_extra_fields_status, fail_buf);
    lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xff8080), 0);
  } else {
    if (btn_extra_fields_create) lv_obj_add_flag(btn_extra_fields_create, LV_OBJ_FLAG_HIDDEN);
    yield();
    lv_timer_handler();
    checkAndCreateExtraFields(false);  // verify fields were created
  }
}


// ============================================================
//  SPOOLMAN CONNECTION FAILED SCREEN
// ============================================================
void showSpoolmanFailScreen(bool is_setup_flow) {
  logSD("SHOW: SpoolmanFailScreen");
  logSDf("UI: Screen -> SpoolmanFail (setup=%d)", is_setup_flow ? 1 : 0);
  spoolman_fail_is_setup = is_setup_flow;
  hideAllOverlays();
  if (scr_spoolman_fail) { lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }

  // Copy all strings to RAM buffers — T() returns Flash pointers which LVGL can't read directly
  char buf_title[32], buf_msg[96], buf_retry[48], buf_skip[48];
  strncpy(buf_title, T(STR_SPOOLMAN_TITLE), sizeof(buf_title)-1); buf_title[sizeof(buf_title)-1]=0;
  strncpy(buf_msg,   T(STR_SPOOLMAN_FAIL),  sizeof(buf_msg)-1);   buf_msg[sizeof(buf_msg)-1]=0;
  strncpy(buf_retry, T(STR_SPOOLMAN_RETRY), sizeof(buf_retry)-1); buf_retry[sizeof(buf_retry)-1]=0;
  strncpy(buf_skip,  T(STR_SPOOLMAN_SKIP),  sizeof(buf_skip)-1);  buf_skip[sizeof(buf_skip)-1]=0;

  scr_spoolman_fail = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_spoolman_fail, 480, 320);
  lv_obj_set_pos(scr_spoolman_fail, 0, 0);
  lv_obj_set_style_radius(scr_spoolman_fail, 0, 0);
  lv_obj_set_style_border_width(scr_spoolman_fail, 0, 0);
  lv_obj_set_style_pad_all(scr_spoolman_fail, 0, 0);
  lv_obj_clear_flag(scr_spoolman_fail, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_spoolman_fail, lv_color_hex(0x0a1020), 0);

  // Title
  lv_obj_t *lbl_title = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_title, buf_title);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 20);

  // Back → Spoolman IP
  addBackButton(scr_spoolman_fail, [](lv_event_t *e){
    logSD("BTN: SpoolmanFail -> Back");
    show_spoolman_pending = true;
    // pending handler will delete scr_spoolman_fail via hideAllOverlays + recreate spoolman
  });
  addCloseButton(scr_spoolman_fail);

  // Warning icon
  lv_obj_t *lbl_icon = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_icon, LV_SYMBOL_WARNING);
  lv_obj_set_style_text_color(lbl_icon, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_icon, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_icon, LV_ALIGN_TOP_MID, 0, 60);

  // IP entered
  char ip_buf[80];
  snprintf(ip_buf, sizeof(ip_buf), "http://%s", cfg_spoolman_ip);
  lv_obj_t *lbl_ip = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_ip, ip_buf);
  lv_obj_set_style_text_color(lbl_ip, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_ip, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_ip, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_ip, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_ip, 440);
  lv_obj_align(lbl_ip, LV_ALIGN_TOP_MID, 0, 96);

  // Error message (from RAM buffer)
  lv_obj_t *lbl_msg = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_msg, buf_msg);
  lv_obj_set_style_text_color(lbl_msg, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_msg, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_msg, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_msg, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_msg, 440);
  lv_obj_align(lbl_msg, LV_ALIGN_TOP_MID, 0, 128);

  // Change IP button (left)
  lv_obj_t *btn_retry = lv_btn_create(scr_spoolman_fail);
  lv_obj_set_size(btn_retry, 210, 50);
  lv_obj_set_pos(btn_retry, 16, 248);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_retry, 8, 0);
  lv_obj_set_style_shadow_width(btn_retry, 0, 0);
  lv_obj_set_style_border_width(btn_retry, 0, 0);
  lv_obj_add_event_cb(btn_retry, [](lv_event_t *e){
    logSD("BTN: SpoolmanFail -> Retry");
    show_spoolman_pending = true;
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_r = lv_label_create(btn_retry);
  lv_label_set_text(lbl_r, buf_retry);
  lv_obj_set_style_text_color(lbl_r, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_r, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_r);

  // Continue anyway button (right)
  lv_obj_t *btn_cont = lv_btn_create(scr_spoolman_fail);
  lv_obj_set_size(btn_cont, 210, 50);
  lv_obj_set_pos(btn_cont, 254, 248);
  lv_obj_set_style_bg_color(btn_cont, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_cont, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cont, 8, 0);
  lv_obj_set_style_shadow_width(btn_cont, 0, 0);
  lv_obj_set_style_border_width(btn_cont, 0, 0);
  lv_obj_add_event_cb(btn_cont, [](lv_event_t *e){
    // Delete this screen first to avoid it being accessed during navigation
    if (scr_spoolman_fail) { lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
    if (spoolman_fail_is_setup) {
      showExtraFieldsScreen(true);
    } else {
      if (scr_connection) { lv_obj_del(scr_connection); scr_connection = nullptr; }
      buildConnectionScreen();
      if (!scr_connection) buildConnectionScreen(); hideAllOverlays(); lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_c = lv_label_create(btn_cont);
  lv_label_set_text(lbl_c, buf_skip);
  lv_obj_set_style_text_color(lbl_c, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_c, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_c);
}

// ============================================================
//  OTA — BROWSER UPLOAD
// ============================================================

// ============================================================
//  GITHUB OTA: check latest release via API, download + flash
// ============================================================

// Parse semantic version "Beta_X.Y.Z" → comparable integer X*100000 + Y*1000 + Z

// Show/hide all update badges consistently
void showUpdateBadges(bool show) {
  if (lbl_burger_badge) {
    if (show) lv_obj_clear_flag(lbl_burger_badge, LV_OBJ_FLAG_HIDDEN);
    else      lv_obj_add_flag(lbl_burger_badge,   LV_OBJ_FLAG_HIDDEN);
  }
  if (lbl_system_badge) {
    if (show) lv_obj_clear_flag(lbl_system_badge, LV_OBJ_FLAG_HIDDEN);
    else      lv_obj_add_flag(lbl_system_badge,   LV_OBJ_FLAG_HIDDEN);
  }
  if (lbl_fw_badge) {
    if (show) lv_obj_clear_flag(lbl_fw_badge, LV_OBJ_FLAG_HIDDEN);
    else      lv_obj_add_flag(lbl_fw_badge,   LV_OBJ_FLAG_HIDDEN);
  }
  if (lbl_gh_btn_badge) {
    if (show) lv_obj_clear_flag(lbl_gh_btn_badge, LV_OBJ_FLAG_HIDDEN);
    else      lv_obj_add_flag(lbl_gh_btn_badge,   LV_OBJ_FLAG_HIDDEN);
  }
}

// Silent background update check — no UI changes except badge


// ============================================================
//  REBOOT POPUP (language/date format change)
// ============================================================
void showRebootPopup() {
  logSD("SHOW: RebootPopup");
  logSD("UI: Screen -> RebootPopup");
  lv_obj_t *pop = lv_obj_create(lv_scr_act());
  lv_obj_set_size(pop, 480, 320); lv_obj_set_pos(pop, 0, 0);
  lv_obj_set_style_bg_color(pop, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(pop, LV_OPA_70, 0);
  lv_obj_set_style_border_width(pop, 0, 0);
  lv_obj_set_style_pad_all(pop, 0, 0);
  lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(pop);
  lv_obj_set_size(box, 400, 220);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *t = lv_label_create(box);
  lv_label_set_text(t, T(STR_REBOOT_TITLE));
  lv_obj_set_style_text_color(t, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(t, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(t, LV_ALIGN_TOP_MID, 0, 16);

  lv_obj_t *m = lv_label_create(box);
  lv_label_set_text(m, T(STR_REBOOT_MSG));
  lv_obj_set_style_text_color(m, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(m, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(m, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(m, LV_ALIGN_CENTER, 0, -18);

  // Restart button
  lv_obj_t *btn_rb = lv_btn_create(box);
  lv_obj_set_size(btn_rb, 180, 48);
  lv_obj_align(btn_rb, LV_ALIGN_BOTTOM_LEFT, 10, -12);
  lv_obj_set_style_bg_color(btn_rb, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_rb, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_rb, 8, 0);
  lv_obj_set_style_shadow_width(btn_rb, 0, 0);
  lv_obj_set_style_border_width(btn_rb, 0, 0);
  lv_obj_add_event_cb(btn_rb, [](lv_event_t *e){ logSD("Reboot: user (language/date change)"); ESP.restart(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *rb_lbl = lv_label_create(btn_rb);
  lv_label_set_text(rb_lbl, T(STR_REBOOT_BTN));
  lv_obj_set_style_text_color(rb_lbl, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(rb_lbl, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(rb_lbl);

  // Cancel button
  lv_obj_t *btn_cancel = lv_btn_create(box);
  lv_obj_set_size(btn_cancel, 180, 48);
  lv_obj_align(btn_cancel, LV_ALIGN_BOTTOM_RIGHT, -10, -12);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_cancel, 0, 0);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e){
    // btn_cancel → box → pop: zwei Ebenen nach oben
    lv_obj_t *box_obj = lv_obj_get_parent(lv_event_get_target(e));
    lv_obj_t *pop_obj = lv_obj_get_parent(box_obj);
    lv_obj_del(pop_obj);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *c_lbl = lv_label_create(btn_cancel);
  lv_label_set_text(c_lbl, T(STR_CANCEL));
  lv_obj_set_style_text_color(c_lbl, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(c_lbl, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(c_lbl);
}

// ============================================================
//  LANGUAGE SCREEN (System > Language)
// ============================================================

// ============================================================
//  INFO SCREEN (System > Info & Support)
//  3 QR-Code buttons: Ko-fi / GitHub / Discord
// ============================================================
lv_obj_t *scr_info = nullptr;

// ============================================================
//  CLEAR DISPLAY (no tag detected)
// ============================================================
void clearTagDisplay() {
  lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0xf0b838), 0);  // yellow = kein Tag
  lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
  lv_label_set_text(lbl_uid, "-");
  lv_label_set_text(lbl_tray_uuid, "-");
  lv_label_set_text(lbl_material, "-");
  lv_label_set_text(lbl_date, "-");
  lv_label_set_text(lbl_spoolman_id, "?");
  lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0xf0b838), 0);
  lv_label_set_text(lbl_color, "-");
  lv_label_set_text(lbl_temp, "-");
  lv_label_set_text(lbl_vendor, "-");
  lv_label_set_text(lbl_detail, "-");
  lv_label_set_text(lbl_filament_name, "");
  lv_label_set_text(lbl_last_used, "-");
  lv_label_set_text(lbl_spoolman_weight, "---");
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_label_set_text(lbl_spoolman_dried_val, "-");
  lv_label_set_text(lbl_scale_weight, "---");
  // Reset progress bar fill width to 0
  if (lbl_scale_diff) lv_obj_set_width(lbl_scale_diff, 0);
  if (lbl_spoolman_dried) lv_label_set_text(lbl_spoolman_dried, "");
  if (lbl_keys) lv_label_set_text(lbl_keys, "");
  if (lbl_raw_info) lv_label_set_text(lbl_raw_info, "");
  if (lbl_bag_sm_diff) lv_label_set_text(lbl_bag_sm_diff, "");
  lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(0x333333), 0);
  // Also reset Spoolman data
  sm_found = false; sm_id = 0; sm_filament_id = 0; sm_vendor_id = 0; sm_spool_weight = 0;
  sm_last_dried[0] = '\0'; sm_article_nr[0] = '\0';
  sm_filament_name[0] = '\0'; sm_material_global[0] = '\0'; sm_color_global[0] = '\0'; sm_last_used[0] = '\0';
  sm_location_name[0] = '\0';
  tag_present = false;
  nfc_retry_count = 0; nfc_absent_count = 0;
  g_tag.uid_str[0] = '\0';
  g_tag.tray_uuid[0] = '\0';
  g_tag.material[0] = '\0';   // CRITICAL: otherwise is_ntag=false remains after Bambu scan
  g_tag.color_hex[0] = '\0';
  g_tag.vendor[0] = '\0';
  spoolman_queried_uid[0] = '\0';
  link_tag_uid[0] = '\0';   // Also clear link UID
  link_popup_dismissed = false;
  link_tag_first_seen_ms = 0;
  g_tag_displayed = false;
  updateLinkButton();
  Serial.println("Display cleared (no tag)");
}

// ============================================================
//  READ NTAG (page 4 for magic check)
// ============================================================
bool ntagReadPage(uint8_t page, uint8_t *buf) {
  return nfcReadNtagPage(page, buf);
}

// ============================================================
//  WRITE NTAG (4 bytes per page)
// ============================================================
bool ntagWritePage(uint8_t page, uint8_t *data) {
  return nfcWriteNtagPage(page, data);
}

// ============================================================
//  TAG TYPE DETECTION
//  Reads page 4 of the NTAG and determines the type
// ============================================================
TagType detectNtagType(uint8_t *uid, uint8_t uidLen) {
  if (uidLen == 4) return TAG_BAMBU;
  if (uidLen != 7) return TAG_UNKNOWN;
  // This function is only used internally when page4 has already been read
  // In the NFC loop, page4 is read directly after readPassiveTargetID
  uint8_t page4[4] = {0};
  if (!nfcReadNtagPage(4, page4)) return TAG_UNKNOWN;
  if (memcmp(page4, "SPSC", 4) == 0) return TAG_SPOOLSCALE;
  if (page4[0] == 0x00 && page4[1] == 0x00 && page4[2] == 0x00 && page4[3] == 0x00) return TAG_BLANK;
  if (page4[0] == 0xFF && page4[1] == 0xFF && page4[2] == 0xFF && page4[3] == 0xFF) return TAG_BLANK;
  return TAG_UNKNOWN;
}

// ============================================================
//  READ SPOOLSCALE TAG (SPSC format)
//  Page 9:  "SPSC" magic
//  Page 10: spool_id (uint32 LE)
//  Page 11-14: UUID (16 bytes)
// ============================================================
bool readSpoolScaleTag(int *out_spool_id, char *out_uuid, size_t uuid_len) {
  uint8_t p10[4], p11[4], p12[4], p13[4], p14[4];
  if (!ntagReadPage(10, p10)) return false;
  if (!ntagReadPage(11, p11)) return false;
  if (!ntagReadPage(12, p12)) return false;
  if (!ntagReadPage(13, p13)) return false;
  if (!ntagReadPage(14, p14)) return false;

  *out_spool_id = p10[0] | (p10[1] << 8) | (p10[2] << 16) | (p10[3] << 24);

  snprintf(out_uuid, uuid_len, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
    p11[0], p11[1], p11[2], p11[3],
    p12[0], p12[1], p12[2], p12[3],
    p13[0], p13[1], p13[2], p13[3],
    p14[0], p14[1], p14[2], p14[3]);
  return true;
}

// ============================================================
//  WRITE SPOOLSCALE TAG
//  Page 9:  magic "SPSC" (after NDEF area pages 4-8)
//  Page 10: spool_id uint32 LE
//  Page 11-14: UUID (16 bytes)
// ============================================================
bool writeSpoolScaleTag(int spool_id, const char *uuid_hex) {
  uint8_t magic[4] = {'S','P','S','C'};
  if (!ntagWritePage(9, magic)) return false;

  uint8_t id_bytes[4];
  id_bytes[0] = spool_id & 0xFF;
  id_bytes[1] = (spool_id >> 8) & 0xFF;
  id_bytes[2] = (spool_id >> 16) & 0xFF;
  id_bytes[3] = (spool_id >> 24) & 0xFF;
  if (!ntagWritePage(10, id_bytes)) return false;

  uint8_t uuid_bytes[16];
  for (int i = 0; i < 16; i++) {
    unsigned int b;
    sscanf(uuid_hex + i * 2, "%02x", &b);
    uuid_bytes[i] = (uint8_t)b;
  }
  for (int p = 0; p < 4; p++) {
    if (!ntagWritePage(11 + p, uuid_bytes + p * 4)) return false;
  }
  return true;
}

// ============================================================
//  GENERATE UUID (ESP32 hardware random)
// ============================================================
void generateUUID(char *out, size_t len) {
  uint32_t a = esp_random();
  uint32_t b = esp_random();
  uint32_t c = esp_random();
  uint32_t d = esp_random();
  snprintf(out, len, "%08x%08x%08x%08x", a, b, c, d);
}

// ============================================================
//  SPOOLMAN: LOAD ALL SPOOLS (for new link flow)
//  Loads all active spools including extra.tag status
// ============================================================
void fetchAllSpoolsForLink(bool is_bambu, const char* material_filter, bool archived_only) {
  // Free any previous allocation
  if (link_spools) { free(link_spools); link_spools = nullptr; }
  link_spool_count = 0;
  if (!wifi_ok) return;

  logSDf("link fetch: is_bambu=%d material_filter='%s' archived_only=%d",
    is_bambu, material_filter ? material_filter : "", (int)archived_only);

  StaticJsonDocument<384> filterL;
  JsonArray filterL_arr = filterL.to<JsonArray>();
  JsonObject fL = filterL_arr.createNestedObject();
  fL["id"] = true;
  fL["archived"] = true;
  fL["remaining_weight"] = true;
  fL["extra"]["tag"] = true;
  fL["filament"]["id"] = true;
  fL["filament"]["name"] = true;
  fL["filament"]["material"] = true;
  fL["filament"]["weight"] = true;
  fL["filament"]["color_hex"] = true;
  fL["filament"]["vendor"]["name"] = true;
  fL["spool_weight"] = true;
  SpiRamAllocator psram_alloc;
  JsonDocument doc(&psram_alloc);
  DeserializationError err = DeserializationError::Ok;
  int code = spoolmanGetSpoolListJson(cfg_spoolman_base, archived_only, doc, 8000, &filterL, &err);
  if (code != 200 || err) return;

  JsonArray spools = doc.as<JsonArray>();
  int total_in_api = 0;
  int skipped_tag = 0, skipped_vendor = 0, skipped_material = 0;
  int count_bambu = 0, count_linked = 0;

  // ── Pass 1: count matching spools (pre-filter) ──────────────
  int matched = 0;
  int skipped_archived = 0;
  for (JsonObject spool : spools) {
    total_in_api++;

    // Archived filter: copy-archived flow shows ONLY archived; otherwise skip them
    bool sp_archived = spool["archived"] | false;
    if (archived_only) {
      if (!sp_archived) { skipped_archived++; continue; }
    } else {
      if (sp_archived) { skipped_archived++; continue; }
    }

    // Skip already-linked spools — only in normal link flow.
    // In copy-archived flow, archived spools are templates (typically still tagged) -> don't skip.
    String existing_tag = "";
    if (spool.containsKey("extra") && spool["extra"].containsKey("tag")) {
      existing_tag = spool["extra"]["tag"].as<String>();
      existing_tag.replace("\"",""); existing_tag.trim();
    }
    if (!archived_only && existing_tag.length() > 0) { skipped_tag++; count_linked++; continue; }

    String vname = "";
    if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull())
      vname = spool["filament"]["vendor"]["name"] | String("");
    vname.trim();
    bool bambu_vendor = (strncasecmp(vname.c_str(), "Bambu", 5) == 0);
    if (bambu_vendor) count_bambu++;

    if (is_bambu) {
      if (!bambu_vendor) { skipped_vendor++; continue; }
      if (material_filter && material_filter[0]) {
        String mat = spool["filament"]["material"] | String("");
        mat.trim();
        // Support materials: match Spoolman materials ending in "-S" (e.g. PLA-S, ABS-S)
        if (isSupportMaterial(material_filter)) {
          if (!isSupportSpoolmanMat(mat.c_str())) { skipped_material++; continue; }
          // No color filter for support filaments (always natural/white)
        } else {
          // Standard 3-char material prefix match (e.g. "PLA", "PET", "ABS")
          if (strncasecmp(mat.c_str(), material_filter, 3) != 0) { skipped_material++; continue; }
          // Exclude support materials from non-support filter (e.g. ABS-GF must not show ABS-S)
          if (isSupportSpoolmanMat(mat.c_str())) { skipped_material++; continue; }
          // Subtype filter: only for known technical subtypes (see bambu_blacklist.h)
          char subkw[16];
          if (extractBambuSubtype(material_filter, subkw, sizeof(subkw))) {
            String fname = spool["filament"]["name"] | String("");
            if (!containsIgnoreCase(mat.c_str(), subkw) && !containsIgnoreCase(fname.c_str(), subkw)) {
              logSDf("link fetch: subtype skip mat='%s' name='%.20s' kw='%s'", mat.c_str(), fname.c_str(), subkw);
              skipped_material++; continue;
            }
          }
          // Color filter: if tag has a color, skip spools with very different color
          if (g_tag.color_hex[0] == '#') {
            String col = spool["filament"]["color_hex"] | String("");
            char col_buf[8]; snprintf(col_buf, sizeof(col_buf), "#%s", col.c_str());
            int dist = colorDistance(g_tag.color_hex, col_buf);
            if (dist > 120) { skipped_material++; continue; }
          }
        }
      }
    }
    matched++;
  }

  logSDf("Spoolman inventory: %d total | %d linked | %d unlinked | %d Bambu",
    total_in_api, count_linked, total_in_api - count_linked, count_bambu);
  Serial.printf("Spoolman inventory: %d total | %d linked | %d unlinked | %d Bambu\n",
    total_in_api, count_linked, total_in_api - count_linked, count_bambu);
  logSDf("link fetch: total=%d matched=%d (skip_tag=%d skip_vendor=%d skip_mat=%d)",
    total_in_api, matched, skipped_tag, skipped_vendor, skipped_material);
  Serial.printf("link fetch: total=%d matched=%d (skip_tag=%d skip_vendor=%d skip_mat=%d)\n",
    total_in_api, matched, skipped_tag, skipped_vendor, skipped_material);

  if (matched == 0) return;

  // Store ALL matched spools — the display limit is applied at render time (showFilteredSpoolList)
  // This allows Vendor and Material lists to see the full dataset
  int alloc_count = matched;
  logSDf("link fetch: matched=%d, allocating all for vendor/material dedupe", matched);

  // ── Allocate exactly the needed size in PSRAM ───────────────
  link_spools = (UnlinkedSpool*)heap_caps_malloc(alloc_count * sizeof(UnlinkedSpool), MALLOC_CAP_SPIRAM);
  if (!link_spools) {
    // Fallback: internal RAM
    link_spools = (UnlinkedSpool*)malloc(alloc_count * sizeof(UnlinkedSpool));
    logSD("link fetch: PSRAM alloc failed, using internal RAM");
  }
  if (!link_spools) { logSD("link fetch: alloc failed completely"); return; }

  // ── Pass 2: fill array (same filter) ────────────────────────
  for (JsonObject spool : spools) {
    if (link_spool_count >= alloc_count) break;

    // Archived filter: same logic as pass 1
    bool sp_archived = spool["archived"] | false;
    if (archived_only) {
      if (!sp_archived) continue;
    } else {
      if (sp_archived) continue;
    }

    String existing_tag = "";
    if (spool.containsKey("extra") && spool["extra"].containsKey("tag")) {
      existing_tag = spool["extra"]["tag"].as<String>();
      existing_tag.replace("\"",""); existing_tag.trim();
    }
    if (!archived_only && existing_tag.length() > 0) continue;

    String vname = "";
    if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull())
      vname = spool["filament"]["vendor"]["name"] | String("");
    vname.trim();
    bool bambu_vendor = (strncasecmp(vname.c_str(), "Bambu", 5) == 0);

    if (is_bambu) {
      if (!bambu_vendor) continue;
      if (material_filter && material_filter[0]) {
        String mat = spool["filament"]["material"] | String("");
        mat.trim();
        if (isSupportMaterial(material_filter)) {
          if (!isSupportSpoolmanMat(mat.c_str())) continue;
          // No color filter for support filaments
        } else {
          if (strncasecmp(mat.c_str(), material_filter, 3) != 0) continue;
          if (isSupportSpoolmanMat(mat.c_str())) continue;
          char subkw[16];
          if (extractBambuSubtype(material_filter, subkw, sizeof(subkw))) {
            String fname2 = spool["filament"]["name"] | String("");
            if (!containsIgnoreCase(mat.c_str(), subkw) && !containsIgnoreCase(fname2.c_str(), subkw)) continue;
          }
          if (g_tag.color_hex[0] == '#') {
            String col = spool["filament"]["color_hex"] | String("");
            char col_buf[8]; snprintf(col_buf, sizeof(col_buf), "#%s", col.c_str());
            if (colorDistance(g_tag.color_hex, col_buf) > 120) continue;
          }
        }
      }
    }

    UnlinkedSpool &s = link_spools[link_spool_count];
    s.id = spool["id"] | 0;

    strncpy(s.existing_tag, existing_tag.c_str(), sizeof(s.existing_tag)-1);
    s.existing_tag[sizeof(s.existing_tag)-1] = '\0';

    String fname = spool["filament"]["name"] | String("?");
    fname.trim();
    strncpy(s.name, fname.c_str(), sizeof(s.name)-1);
    s.name[sizeof(s.name)-1] = '\0';

    strncpy(s.vendor, vname.c_str(), sizeof(s.vendor)-1);
    s.vendor[sizeof(s.vendor)-1] = '\0';

    String mat = spool["filament"]["material"] | String("");
    mat.trim();
    strncpy(s.material, mat.c_str(), sizeof(s.material)-1);
    s.material[sizeof(s.material)-1] = '\0';

    String col = spool["filament"]["color_hex"] | String("");
    col.trim();
    if (col.length() > 0 && col[0] != '#') col = "#" + col;
    strncpy(s.color_hex, col.c_str(), sizeof(s.color_hex)-1);
    s.color_hex[sizeof(s.color_hex)-1] = '\0';

    s.remaining = spool["remaining_weight"] | 0.0f;
    s.total = spool["filament"]["weight"] | 1000.0f;
    s.filament_id = spool["filament"]["id"] | 0;
    s.spool_weight = spool["spool_weight"] | 0.0f;

    if (sd_verbose) {
      logSDf("[verbose] link spool %d: vendor='%s' mat='%s' name='%s' fid=%d spw=%.0f",
        s.id, s.vendor, s.material, s.name, s.filament_id, s.spool_weight);
    }

    link_spool_count++;
  }
  Serial.printf("fetchAllSpoolsForLink: %d spools loaded (PSRAM)\n", link_spool_count);
  logSDf("link fetch done: %d spools in list", link_spool_count);
}

// Legacy wrapper for compatibility
void fetchUnlinkedSpools() { fetchAllSpoolsForLink(false, ""); }

// ============================================================
//  SPOOLMAN: SAVE TAG UUID (extra.tag)
// ============================================================
// ============================================================
//  LINK FLOW: COMPLETE LINKING
//  PATCH + update main screen
// ============================================================
void doLinkPatch(int spool_id, bool is_bambu) {
  const char* link_uuid = is_bambu ? g_tag.tray_uuid : link_tag_uid;
  Serial.printf("doLinkPatch: ID=%d uuid=%s\n", spool_id, link_uuid);
  patchSpoolTag(spool_id, link_uuid);

  // Close all link overlays
  if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
  if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id     = nullptr; }
  if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
  if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }
  if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
  if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
  if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
  if (scr_link_list)   { lv_obj_del(scr_link_list);   scr_link_list   = nullptr; }
  // Free PSRAM spool list
  if (link_spools) { free(link_spools); link_spools = nullptr; }
  link_spool_count = 0;

  // Re-query Spoolman — use single-spool endpoint since we know the ID
  link_popup_dismissed = false;
  if (is_bambu) {
    spoolman_queried_uid[0] = '\0';
    querySpoolmanById(spool_id);
  } else {
    strncpy(g_tag.uid_str, link_tag_uid, sizeof(g_tag.uid_str)-1);
    strncpy(g_tag.tray_uuid, link_tag_uid, sizeof(g_tag.tray_uuid)-1);
    spoolman_queried_uid[0] = '\0';
    querySpoolmanById(spool_id);
  }
  Serial.printf("Linking complete! ID=%d\n", spool_id);
}

// ============================================================
//  LINK FLOW: HELPER — create overlay base
// ============================================================
static lv_obj_t* buildLinkOverlay() {
  lv_obj_t *scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr, 480, 320);
  lv_obj_set_pos(scr, 0, 0);
  lv_obj_set_style_bg_color(scr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(scr, 0, 0);
  lv_obj_set_style_radius(scr, 0, 0);
  lv_obj_set_style_pad_all(scr, 0, 0);
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);
  return scr;
}

// ============================================================
//  LINK FLOW: WARNING POPUP A (spool already linked)
// ============================================================
void showWarnPopupA(int spool_id, const char* existing_tag, bool is_bambu, const char* link_uuid) {
  logSDf("SHOW: WarnPopupA spool=%d", spool_id);
  if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }

  scr_link_warn_a = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_link_warn_a, 480, 320);
  lv_obj_set_pos(scr_link_warn_a, 0, 0);
  lv_obj_set_style_bg_color(scr_link_warn_a, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_link_warn_a, LV_OPA_80, 0);
  lv_obj_set_style_border_width(scr_link_warn_a, 0, 0);
  lv_obj_set_style_radius(scr_link_warn_a, 0, 0);
  lv_obj_set_style_pad_all(scr_link_warn_a, 0, 0);
  lv_obj_clear_flag(scr_link_warn_a, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_link_warn_a);
  lv_obj_set_size(box, 440, 262);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Warning icon + title
  lv_obj_t *lbl_title = lv_label_create(box);
  lv_label_set_text(lbl_title, T(STR_WARN_A_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 16);

  // Separator line
  lv_obj_t *line = lv_obj_create(box);
  lv_obj_set_size(line, 420, 1);
  lv_obj_set_pos(line, 10, 42);
  lv_obj_set_style_bg_color(line, lv_color_hex(0x3a2800), 0);
  lv_obj_set_style_border_width(line, 0, 0);
  lv_obj_set_style_radius(line, 0, 0);
  lv_obj_set_style_pad_all(line, 0, 0);

  // ID + shortened tag
  char tag_short[14];
  snprintf(tag_short, sizeof(tag_short), "%.10s...", existing_tag);

  // Get material and name from link_spools
  const char* sm_mat  = "";
  const char* sm_name = "";
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].id == spool_id) {
      sm_mat  = link_spools[i].material;
      sm_name = link_spools[i].name;
      break;
    }
  }
  char info_buf[96];
  if (sm_mat[0] || sm_name[0]) {
    snprintf(info_buf, sizeof(info_buf), T(STR_WARN_A_SPOOL_INFO),
      spool_id, sm_mat, sm_name, tag_short);
  } else {
    snprintf(info_buf, sizeof(info_buf), T(STR_WARN_A_SPOOL_SHORT), spool_id, tag_short);
  }
  lv_obj_t *lbl_info = lv_label_create(box);
  lv_label_set_text(lbl_info, info_buf);
  lv_obj_set_style_text_color(lbl_info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_info, 400);
  lv_obj_align(lbl_info, LV_ALIGN_TOP_MID, 0, 54);

  // Three buttons: link anyway / enter new ID / cancel
  // Button: link anyway
  // We pass spool_id and is_bambu via static captures (lambda workaround: user_data)
  static int  warn_a_spool_id = 0;
  static bool warn_a_is_bambu = false;
  warn_a_spool_id = spool_id;
  warn_a_is_bambu = is_bambu;

  lv_obj_t *btn_force = lv_btn_create(box);
  lv_obj_set_size(btn_force, 420, 44);
  lv_obj_set_pos(btn_force, 10, 114);
  lv_obj_set_style_bg_color(btn_force, lv_color_hex(0x3a2800), 0);
  lv_obj_set_style_bg_color(btn_force, lv_color_hex(0x5a4000), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_force, 8, 0);
  lv_obj_set_style_shadow_width(btn_force, 0, 0);
  lv_obj_set_style_border_width(btn_force, 0, 0);
  lv_obj_add_event_cb(btn_force, [](lv_event_t *e) {
    if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id = nullptr; }
    doLinkPatch(warn_a_spool_id, warn_a_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_force = lv_label_create(btn_force);
  lv_label_set_text(lbl_force, T(STR_BTN_OVERWRITE));
  lv_obj_set_style_text_color(lbl_force, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_force, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_force);

  lv_obj_t *btn_retry = lv_btn_create(box);
  lv_obj_set_size(btn_retry, 420, 44);
  lv_obj_set_pos(btn_retry, 10, 166);  // 114+44+8
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_retry, 8, 0);
  lv_obj_set_style_shadow_width(btn_retry, 0, 0);
  lv_obj_set_style_border_width(btn_retry, 1, 0);
  lv_obj_set_style_border_color(btn_retry, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_retry, [](lv_event_t *e) {
    logSD("BTN: WarnA -> retry IdInput (flag)");
    if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id     = nullptr; }
    link_id_input[0] = '\0';
    link_id_lookup_pending = 0;
    show_id_input_rebuild = true;  // loop rebuilds IdInputPopup safely
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_retry = lv_label_create(btn_retry);
  lv_label_set_text(lbl_retry, T(STR_ENTER_NEW_ID));
  lv_obj_set_style_text_color(lbl_retry, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_retry, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_retry);

  lv_obj_t *btn_cancel = lv_btn_create(box);
  lv_obj_set_size(btn_cancel, 420, 36);
  lv_obj_set_pos(btn_cancel, 10, 218);  // 166+44+8
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_cancel, 0, 0);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e) {
    if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cancel = lv_label_create(btn_cancel);
  lv_label_set_text(lbl_cancel, T(STR_CANCEL));
  lv_obj_set_style_text_color(lbl_cancel, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_cancel, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_cancel);
}

// ============================================================
//  LINK FLOW: WARNING POPUP B (material mismatch)
//  Nur Flow A (Bambu), Pfad 1
// ============================================================
void showWarnPopupB(int spool_id, bool is_bambu) {
  logSDf("SHOW: WarnPopupB spool=%d", spool_id);
  if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }

  static int  warn_b_spool_id = 0;
  static bool warn_b_is_bambu = false;
  warn_b_spool_id = spool_id;
  warn_b_is_bambu = is_bambu;

  scr_link_warn_b = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_link_warn_b, 480, 320);
  lv_obj_set_pos(scr_link_warn_b, 0, 0);
  lv_obj_set_style_bg_color(scr_link_warn_b, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_link_warn_b, LV_OPA_80, 0);
  lv_obj_set_style_border_width(scr_link_warn_b, 0, 0);
  lv_obj_set_style_radius(scr_link_warn_b, 0, 0);
  lv_obj_set_style_pad_all(scr_link_warn_b, 0, 0);
  lv_obj_clear_flag(scr_link_warn_b, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_link_warn_b);
  lv_obj_set_size(box, 440, 260);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(box);
  lv_label_set_text(lbl_title, T(STR_WARN_B_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 16);

  lv_obj_t *line = lv_obj_create(box);
  lv_obj_set_size(line, 420, 1);
  lv_obj_set_pos(line, 10, 42);
  lv_obj_set_style_bg_color(line, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_border_width(line, 0, 0);
  lv_obj_set_style_radius(line, 0, 0);
  lv_obj_set_style_pad_all(line, 0, 0);

  // Material-Vergleich anzeigen
  char mat_buf[80];
  // Spoolman-Material finden
  const char* sm_mat = "-";
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].id == spool_id) { sm_mat = link_spools[i].material; break; }
  }
  snprintf(mat_buf, sizeof(mat_buf), T(STR_WARN_B_DETAILS),
    g_tag.material[0] ? g_tag.material : "?", sm_mat, spool_id);
  lv_obj_t *lbl_info = lv_label_create(box);
  lv_label_set_text(lbl_info, mat_buf);
  lv_obj_set_style_text_color(lbl_info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_info, 400);
  lv_obj_align(lbl_info, LV_ALIGN_TOP_MID, 0, 52);

  lv_obj_t *btn_force = lv_btn_create(box);
  lv_obj_set_size(btn_force, 420, 48);
  lv_obj_align(btn_force, LV_ALIGN_TOP_MID, 0, 142);
  lv_obj_set_style_bg_color(btn_force, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_force, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_force, 8, 0);
  lv_obj_set_style_shadow_width(btn_force, 0, 0);
  lv_obj_set_style_border_width(btn_force, 0, 0);
  lv_obj_add_event_cb(btn_force, [](lv_event_t *e) {
    if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id = nullptr; }
    doLinkPatch(warn_b_spool_id, warn_b_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_force = lv_label_create(btn_force);
  lv_label_set_text(lbl_force, T(STR_BTN_OVERWRITE));
  lv_obj_set_style_text_color(lbl_force, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_force, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_force);

  lv_obj_t *btn_retry = lv_btn_create(box);
  lv_obj_set_size(btn_retry, 420, 44);
  lv_obj_align(btn_retry, LV_ALIGN_TOP_MID, 0, 198);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_retry, 8, 0);
  lv_obj_set_style_shadow_width(btn_retry, 0, 0);
  lv_obj_set_style_border_width(btn_retry, 1, 0);
  lv_obj_set_style_border_color(btn_retry, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_retry, [](lv_event_t *e) {
    if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }
    link_id_input[0] = '\0';
    showIdInputPopup(warn_b_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_retry = lv_label_create(btn_retry);
  lv_label_set_text(lbl_retry, T(STR_ENTER_NEW_ID));
  lv_obj_set_style_text_color(lbl_retry, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_retry, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_retry);

  lv_obj_t *btn_cancel = lv_btn_create(box);
  lv_obj_set_size(btn_cancel, 420, 36);
  lv_obj_align(btn_cancel, LV_ALIGN_BOTTOM_MID, 0, -8);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_cancel, 0, 0);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e) {
    if (scr_link_warn_b) { lv_obj_del(scr_link_warn_b); scr_link_warn_b = nullptr; }
    if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cancel = lv_label_create(btn_cancel);
  lv_label_set_text(lbl_cancel, T(STR_CANCEL));
  lv_obj_set_style_text_color(lbl_cancel, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_cancel, &lv_font_montserrat_ext_14, 0);
  lv_obj_center(lbl_cancel);
}

// ============================================================
//  LINK-FLOW: HTTP-LOOKUP + VERKNUEPFUNG (ausgelagert vom Lambda)
// ============================================================
void linkIdLookupAndPatch(int entered_id, bool is_bambu) {
  if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_CHECKING));
  lv_timer_handler();
  if (!wifi_ok) { if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_NO_WIFI)); return; }

  DynamicJsonDocument doc(8192);
  DeserializationError err = DeserializationError::Ok;
  int code = spoolmanGetSpoolJson(cfg_spoolman_base, entered_id, doc, 5000, &err);
  if (code == 404 || code < 0) {
    if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_ID_NOT_FOUND));
    return;
  }
  if (code == -2) {
    if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_JSON_ERR));
    return;
  }
  if (code != 200) {
    char err[32]; snprintf(err, sizeof(err), T(STR_LINK_HTTP_ERR), code);
    if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, err);
    return;
  }

  String existing = "";
  if (doc.containsKey("extra") && doc["extra"].containsKey("tag")) {
    existing = doc["extra"]["tag"].as<String>();
    existing.replace("\"",""); existing.trim();
  }

  // Ensure link_spools has room for this spool (may be nullptr if no list was loaded)
  if (link_spools == nullptr) {
    link_spools = (UnlinkedSpool*)heap_caps_malloc(sizeof(UnlinkedSpool), MALLOC_CAP_SPIRAM);
    if (!link_spools) link_spools = (UnlinkedSpool*)malloc(sizeof(UnlinkedSpool));
    link_spool_count = 0;
  }
  bool found_in_list = false;
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].id == entered_id) { found_in_list = true; break; }
  }
  if (!found_in_list && link_spools != nullptr) {
    // Allocate one extra slot if needed (link_spools may be nullptr if no list was loaded)
    UnlinkedSpool &s = link_spools[link_spool_count];
    s.id = entered_id;
    strncpy(s.existing_tag, existing.c_str(), sizeof(s.existing_tag)-1);
    String mat = doc["filament"]["material"] | String("");
    mat.trim(); strncpy(s.material, mat.c_str(), sizeof(s.material)-1);
    String fname = doc["filament"]["name"] | String("?");
    fname.trim(); strncpy(s.name, fname.c_str(), sizeof(s.name)-1);
    String vnd = doc["filament"]["vendor"]["name"] | String("");
    vnd.trim(); strncpy(s.vendor, vnd.c_str(), sizeof(s.vendor)-1);
    String col = doc["filament"]["color_hex"] | String("");
    col.trim();
    if (col.length() > 0 && col[0] != '#') col = "#" + col;
    strncpy(s.color_hex, col.c_str(), sizeof(s.color_hex)-1);
    link_spool_count++;
  }

  if (existing.length() > 0) {
    showWarnPopupA(entered_id, existing.c_str(), is_bambu, "");
    return;
  }
  if (is_bambu && g_tag.material[0]) {
    String sm_mat = doc["filament"]["material"] | String("");
    sm_mat.trim();
    if (sm_mat.length() >= 3 && strlen(g_tag.material) >= 3) {
      if (strncasecmp(g_tag.material, sm_mat.c_str(), 3) != 0) {
        showWarnPopupB(entered_id, is_bambu);
        return;
      }
    }
  }
  doLinkPatch(entered_id, is_bambu);
}

// ============================================================
//  LINK-FLOW: ZIFFERNBLOCK (Pfad 1 — ID eingeben)
// ============================================================
void showIdInputPopup(bool is_bambu, bool is_copy) {
  logSDf("SHOW: IdInputPopup bambu=%d copy=%d", (int)is_bambu, (int)is_copy);
  id_input_open = true;  // suppress NFC Spoolman query while numpad open
  if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
  lbl_link_id_display = nullptr;
  lbl_link_id_status  = nullptr;

  scr_link_id = buildLinkOverlay();

  // ── Header like settings menu ───────────────────────────
  // Title zentriert
  lv_obj_t *lbl_title = lv_label_create(scr_link_id);
  lv_label_set_text(lbl_title, T(STR_LINK_ID_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

  // Zurueck-Button (←) oben links
  lv_obj_t *btn_back = lv_btn_create(scr_link_id);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e) {
    logSD("BTN: IdInput -> Back (flag)");
    show_id_input_pending = false;  // cancel any pending re-open
    // Use flag pattern — cannot delete own parent screen in callback
    if (id_popup_is_copy) {
      // Close and show copy entry — deferred via loop
      if (scr_link_id) { lv_obj_add_flag(scr_link_id, LV_OBJ_FLAG_HIDDEN); }
      if (scr_copy_entry) lv_obj_clear_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN);
      // Delete scr_link_id safely after callback via pending flag
      show_id_input_pending = true;  // reuse flag to signal cleanup
    } else {
      if (scr_link_id) { lv_obj_add_flag(scr_link_id, LV_OBJ_FLAG_HIDDEN); }
      if (scr_link_entry) lv_obj_clear_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN);
      show_id_input_pending = true;
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_bk);

  // X-Button oben rechts → komplett schliessen
  lv_obj_t *btn_x = lv_btn_create(scr_link_id);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_set_style_border_width(btn_x, 0, 0);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e) {
    logSD("BTN: IdInput -> X Close");
    // Flag pattern: cannot delete own parent screen from callback
    id_input_open = false;
    link_id_lookup_pending = 0;
    copy_id_lookup_pending = 0;
    show_id_input_pending = true;  // loop will delete scr_link_id safely
    // Also mark entry popup for deletion
    if (id_popup_is_copy) {
      if (scr_copy_entry) lv_obj_add_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN);
    } else {
      if (scr_link_entry) lv_obj_add_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN);
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);

  // Separator line
  lv_obj_t *div = lv_obj_create(scr_link_id);
  lv_obj_set_size(div, 472, 1); lv_obj_set_pos(div, 4, 48);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  // Kontext-Info
  lv_obj_t *lbl_ctx = lv_label_create(scr_link_id);
  char ctx_buf[48];
  if (is_bambu) {
    snprintf(ctx_buf, sizeof(ctx_buf), "Bambu  %s", g_tag.material[0] ? g_tag.material : "Tag");
  } else {
    snprintf(ctx_buf, sizeof(ctx_buf), "UID: %.14s", link_tag_uid);
  }
  lv_label_set_text(lbl_ctx, ctx_buf);
  lv_obj_set_style_text_color(lbl_ctx, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_ctx, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_ctx, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_ctx, LV_ALIGN_TOP_MID, 0, 56);

  // Input field — kompakter, y=76
  lv_obj_t *input_box = lv_obj_create(scr_link_id);
  lv_obj_set_size(input_box, 260, 44);
  lv_obj_align(input_box, LV_ALIGN_TOP_MID, 0, 76);
  lv_obj_set_style_bg_color(input_box, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_border_color(input_box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(input_box, 1, 0);
  lv_obj_set_style_radius(input_box, 6, 0);
  lv_obj_set_style_pad_all(input_box, 0, 0);
  lv_obj_clear_flag(input_box, LV_OBJ_FLAG_SCROLLABLE);

  lbl_link_id_display = lv_label_create(input_box);
  lv_label_set_text(lbl_link_id_display, link_id_input[0] ? link_id_input : "_");
  lv_obj_set_style_text_color(lbl_link_id_display, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_link_id_display, &lv_font_montserrat_ext_24, 0);
  lv_obj_set_style_text_align(lbl_link_id_display, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(lbl_link_id_display);

  // Status label inside input box (replaces digit display when error occurs)
  lbl_link_id_status = lv_label_create(input_box);
  lv_label_set_text(lbl_link_id_status, "");
  lv_obj_set_style_text_color(lbl_link_id_status, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_link_id_status, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl_link_id_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_link_id_status, LV_ALIGN_BOTTOM_MID, 0, -2);

  // ── Numeric keypad: 4x3, START_Y=132 ─────────────────────
  // BTN 80x38, GAP 5 → 4 rows: 4*38+3*5=167px → ends at 132+167=299 ✓
  // No separate cancel button needed (X top right)
  const int BTN_W = 80, BTN_H = 38, GAP = 5;
  const int PAD_X = (480 - 3*BTN_W - 2*GAP) / 2;
  const int START_Y = 132;

  // 12 buttons: 1-9, then 0 / ⌫ / ✓
  const char* digits12[] = {"1","2","3","4","5","6","7","8","9","0",LV_SYMBOL_BACKSPACE,LV_SYMBOL_OK};
  int pos_x12[] = {0,1,2, 0,1,2, 0,1,2, 0,1,2};
  int pos_y12[] = {0,0,0, 1,1,1, 2,2,2, 3,3,3};

  id_popup_is_bambu = is_bambu;
  id_popup_is_copy  = is_copy;

  for (int d = 0; d < 12; d++) {
    lv_obj_t *btn = lv_btn_create(scr_link_id);
    int bx = PAD_X + pos_x12[d] * (BTN_W + GAP);
    int by = START_Y + pos_y12[d] * (BTN_H + GAP);
    lv_obj_set_size(btn, BTN_W, BTN_H);
    lv_obj_set_pos(btn, bx, by);

    bool is_ok        = (d == 11);
    bool is_backspace = (d == 10);
    uint32_t bg_col = is_ok ? 0x1a3020 : 0x0a1e30;
    uint32_t bg_pr  = is_ok ? 0x2a5030 : 0x1a3060;
    uint32_t bd_col = is_ok ? 0x2a5030 : 0x1a3060;
    uint32_t tx_col = is_ok ? 0x40c080 : (is_backspace ? 0xf0b838 : 0xe8f0ff);

    lv_obj_set_style_bg_color(btn, lv_color_hex(bg_col), 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(bg_pr), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn, 8, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_set_style_border_width(btn, 1, 0);
    lv_obj_set_style_border_color(btn, lv_color_hex(bd_col), 0);

    lv_obj_t *lbl = lv_label_create(btn);
    lv_label_set_text(lbl, digits12[d]);
    lv_obj_set_style_text_color(lbl, lv_color_hex(tx_col), 0);
    lv_obj_set_style_text_font(lbl, is_ok ? &lv_font_montserrat_ext_20 : &lv_font_montserrat_ext_18, 0);
    lv_obj_center(lbl);

    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      const char* digit_str = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
      bool is_bs     = (strcmp(digit_str, LV_SYMBOL_BACKSPACE) == 0);
      bool is_ok_btn = (strcmp(digit_str, LV_SYMBOL_OK) == 0);

      if (is_ok_btn) {
        if (strlen(link_id_input) == 0) {
          if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_ID_TITLE));
          return;
        }
        int entered_id = atoi(link_id_input);
        if (entered_id <= 0) {
          if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_ID_NOT_FOUND));
          return;
        }
        if (id_popup_is_copy) {
          // Defer to loop — HTTP + JSON in lambda causes stack overflow
          if (!wifi_ok) { if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_NO_WIFI)); return; }
          copy_id_lookup_pending = entered_id;
          if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_CHECKING));
        } else {
          // Defer to loop — direct call causes stack overflow in LVGL lambda
          link_id_lookup_pending = entered_id;
          link_id_lookup_is_bambu = id_popup_is_bambu;
          if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_CHECKING));
        }
      } else if (is_bs) {
        int len = strlen(link_id_input);
        if (len > 0) link_id_input[len-1] = '\0';
        if (lbl_link_id_display)
          lv_label_set_text(lbl_link_id_display, link_id_input[0] ? link_id_input : "_");
        if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, "");
      } else {
        int len = strlen(link_id_input);
        if (len < 6) { link_id_input[len] = digit_str[0]; link_id_input[len+1] = '\0'; }
        if (lbl_link_id_display)
          lv_label_set_text(lbl_link_id_display, link_id_input[0] ? link_id_input : "_");
        if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, "");
      }
    }, LV_EVENT_CLICKED, NULL);
  }
}

void closeIdInputPopup() {
  id_input_open = false;
  link_id_lookup_pending = 0;  // cancel any pending lookup when popup closes
  copy_id_lookup_pending = 0;
  if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
  lbl_link_id_display = nullptr;
  lbl_link_id_status  = nullptr;
}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — SPULEN-LISTE (Stufe 3)
// ============================================================
// Helper: adds a non-clickable info row at the bottom of a list when limit was hit
static void addListMoreInfo(lv_obj_t* list, StringID str_id) {
  char buf[96];
  strncpy(buf, T(str_id), sizeof(buf)-1);
  buf[sizeof(buf)-1] = '\0';

  lv_obj_t *row = lv_obj_create(list);
  lv_obj_set_size(row, 452, 48);
  lv_obj_set_style_bg_color(row, lv_color_hex(0x1a1a08), 0);
  lv_obj_set_style_radius(row, 6, 0);
  lv_obj_set_style_border_width(row, 1, 0);
  lv_obj_set_style_border_color(row, lv_color_hex(0x3a3010), 0);
  lv_obj_set_style_pad_all(row, 0, 0);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *lbl = lv_label_create(row);
  lv_label_set_text(lbl, buf);
  lv_obj_set_style_text_color(lbl, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl, 440);
  lv_obj_center(lbl);
}

void showFilteredSpoolList(const char* vendor_name, const char* material_prefix, const char* material_full) {
  logSDf("SHOW: FilteredSpoolList vendor=%s mat=%s matf=%s", vendor_name, material_prefix, material_full ? material_full : "");
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }

  scr_link_spools = buildLinkOverlay();

  // Count matching spools for title
  int display_count = 0;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &sc = link_spools[i];
    if (sc.existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;
    bool bv = (strncasecmp(sc.vendor, "Bambu", 5) == 0);
    if (link_flow_is_bambu) {
      if (!bv) continue;
      if (g_tag.material[0] && sc.material[0]) {
        if (isSupportMaterial(g_tag.material)) {
          if (!isSupportSpoolmanMat(sc.material)) continue;
        } else {
          if (material_prefix[0] && strncasecmp(sc.material, material_prefix, strlen(material_prefix)) != 0) continue;
          if (isSupportSpoolmanMat(sc.material)) continue;
        }
      }
    } else {
      if (bv) continue;
      if (vendor_name[0] && strncasecmp(sc.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
      if (material_prefix[0] && strncasecmp(sc.material, material_prefix, strlen(material_prefix)) != 0) continue;
      // Stage 3: full material name match (exact, case-insensitive)
      if (material_full && material_full[0] && strcasecmp(sc.material, material_full) != 0) continue;
    }
    display_count++;
  }

  char title_buf[48];
  if (link_flow_is_bambu) {
    snprintf(title_buf, sizeof(title_buf), "Bambu %s - %d",
      g_tag.material[0] ? g_tag.material : "", display_count);
  } else if (material_full && material_full[0]) {
    snprintf(title_buf, sizeof(title_buf), "%.8s %.10s - %d", vendor_name, material_full, display_count);
  } else if (material_prefix[0]) {
    snprintf(title_buf, sizeof(title_buf), "%.8s %.4s - %d", vendor_name, material_prefix, display_count);
  } else {
    snprintf(title_buf, sizeof(title_buf), "%s - %d", T(STR_SPOOLS_ALL), display_count);
  }

  // Header: 52px, Back left, Cancel/X right, title center
  lv_obj_t *hdr = lv_obj_create(scr_link_spools);
  lv_obj_set_size(hdr, 480, 52);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(hdr);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);

  // Back button top-left
  lv_obj_t *btn_hdr_back = lv_btn_create(hdr);
  lv_obj_set_size(btn_hdr_back, 44, 44);
  lv_obj_set_pos(btn_hdr_back, 4, 4);
  lv_obj_set_style_bg_color(btn_hdr_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_hdr_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_hdr_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_hdr_back, 0, 0);
  lv_obj_set_style_border_width(btn_hdr_back, 0, 0);
  lv_obj_add_event_cb(btn_hdr_back, [](lv_event_t *e) {
    logSD("BTN: SpoolList -> Back");
    if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
    if (link_flow_is_bambu) {
      if (scr_link_entry) lv_obj_clear_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN);
    } else {
      // NTAG: if stage 3 was actually shown (not auto-skipped), back goes there
      // otherwise back goes to stage 2 (material prefix list)
      if (link_stage3_shown) {
        showMaterialSubList(link_selected_vendor, link_selected_material);
      } else {
        showMaterialList(link_selected_vendor);
      }
    }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_hdr_back);
    lv_label_set_text(l, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(l, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(l); }

  // Cancel/X button top-right
  lv_obj_t *btn_hdr_cancel = lv_btn_create(hdr);
  lv_obj_set_size(btn_hdr_cancel, 44, 44);
  lv_obj_align(btn_hdr_cancel, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_hdr_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_hdr_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_hdr_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_hdr_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_hdr_cancel, 0, 0);
  lv_obj_add_event_cb(btn_hdr_cancel, [](lv_event_t *e) {
    logSD("BTN: SpoolList -> Cancel");
    if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
    if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_hdr_cancel);
    lv_label_set_text(l, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(l); }

  // Separator
  lv_obj_t *div = lv_obj_create(scr_link_spools);
  lv_obj_set_size(div, 480, 1); lv_obj_set_pos(div, 0, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  // Scrollable list — full height below header
  lv_obj_t *list = lv_obj_create(scr_link_spools);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  int count = 0;
  for (int i = 0; i < link_spool_count; i++) {
    if (count >= spool_list_limit) break;  // render limit — full data is still in link_spools[]
    UnlinkedSpool &s = link_spools[i];

    // Filter: kein Tag, passender Vendor, passender Material-Prefix
    if (s.existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;  // bereits verknuepft
    bool bambu_vendor = (strncasecmp(s.vendor, "Bambu", 5) == 0);
    if (link_flow_is_bambu) {
      // Bambu-Flow: vendor muss Bambu enthalten, Material muss passen
      if (!bambu_vendor) continue;
      if (g_tag.material[0] && s.material[0]) {
        if (isSupportMaterial(g_tag.material)) {
          // Support tags: match Spoolman materials ending in "-S"
          if (!isSupportSpoolmanMat(s.material)) continue;
        } else {
          if (strncasecmp(s.material, g_tag.material, 3) != 0) continue;
          // Exclude support materials from non-support display
          if (isSupportSpoolmanMat(s.material)) continue;
        }
      }
    } else {
      // Flow B: vendor und material prefix filtern
      if (vendor_name[0] && strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
      if (material_prefix[0] && strncasecmp(s.material, material_prefix, strlen(material_prefix)) != 0) continue;
      // Stage 3: full material name match (exact, case-insensitive)
      if (material_full && material_full[0] && strcasecmp(s.material, material_full) != 0) continue;
    }

    count++;
    lv_obj_t *row = lv_btn_create(list);
    lv_obj_set_size(row, 452, 56);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    // ── Zeile 1: #ID + Material+Name ──────────────────────
    lv_obj_t *lbl_id = lv_label_create(row);
    char id_buf[10]; snprintf(id_buf, sizeof(id_buf), "%d", s.id);
    lv_label_set_text(lbl_id, id_buf);
    lv_obj_set_style_text_color(lbl_id, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_id, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_id, LV_ALIGN_TOP_LEFT, 6, 5);

    // Material + Name zusammen, abgeschnitten wenn zu lang
    // Avoid duplication when the filament name already starts with the material
    // (Spoolman often stores names like "PLA+ White" while material is "PLA+")
    lv_obj_t *lbl_name = lv_label_create(row);
    char full_name[64];
    if (s.material[0]) {
      bool name_has_mat = (s.name[0] && strncasecmp(s.name, s.material, strlen(s.material)) == 0);
      if (name_has_mat)
        strncpy(full_name, s.name, sizeof(full_name)-1);
      else
        snprintf(full_name, sizeof(full_name), "%s %s", s.material, s.name);
    } else {
      strncpy(full_name, s.name, sizeof(full_name)-1);
    }
    full_name[sizeof(full_name)-1] = '\0';
    lv_label_set_text(lbl_name, full_name);
    lv_obj_set_style_text_color(lbl_name, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl_name, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_name, LV_ALIGN_TOP_LEFT, 50, 5);
    lv_label_set_long_mode(lbl_name, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_name, 396);  // volle Breite — kein Hersteller in Zeile 1

    // ── Zeile 2: Farbkachel + Gewicht + Hersteller rechts ─
    // Color tile (14x14px)
    lv_obj_t *swatch = lv_obj_create(row);
    lv_obj_set_size(swatch, 14, 14);
    lv_obj_align(swatch, LV_ALIGN_BOTTOM_LEFT, 6, -6);
    lv_obj_set_style_radius(swatch, 3, 0);
    lv_obj_set_style_border_width(swatch, 1, 0);
    lv_obj_set_style_border_color(swatch, lv_color_hex(0x2a4060), 0);
    lv_obj_set_style_pad_all(swatch, 0, 0);
    lv_obj_clear_flag(swatch, LV_OBJ_FLAG_SCROLLABLE);
    // Farbe setzen
    uint32_t swatch_col = 0x333333;  // Fallback grau
    if (s.color_hex[0] == '#' && strlen(s.color_hex) >= 7) {
      unsigned int r, g, b;
      sscanf(s.color_hex + 1, "%02X%02X%02X", &r, &g, &b);
      swatch_col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
    }
    lv_obj_set_style_bg_color(swatch, lv_color_hex(swatch_col), 0);

    // Gewicht neben Kachel
    lv_obj_t *lbl_rest = lv_label_create(row);
    char rest_buf[24];
    if (s.remaining <= 0 && s.total > 0)
      snprintf(rest_buf, sizeof(rest_buf), "%.0fg neu", s.total);
    else
      snprintf(rest_buf, sizeof(rest_buf), "%.0fg", s.remaining);
    lv_label_set_text(lbl_rest, rest_buf);
    lv_obj_set_style_text_color(lbl_rest, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_rest, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(lbl_rest, LV_ALIGN_BOTTOM_LEFT, 26, -5);

    // Click → Sicherheits-Popup
    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      int idx = (intptr_t)lv_event_get_user_data(e);
      if (idx < 0 || idx >= link_spool_count) return;
      UnlinkedSpool &s = link_spools[idx];

      // Sicherheits-Popup (halbtransparentes Overlay)
      lv_obj_t *popup = lv_obj_create(lv_scr_act());
      lv_obj_set_size(popup, 480, 320);
      lv_obj_set_pos(popup, 0, 0);
      lv_obj_set_style_bg_color(popup, lv_color_hex(0x000000), 0);
      lv_obj_set_style_bg_opa(popup, LV_OPA_70, 0);
      lv_obj_set_style_border_width(popup, 0, 0);
      lv_obj_set_style_radius(popup, 0, 0);
      lv_obj_set_style_pad_all(popup, 0, 0);
      lv_obj_clear_flag(popup, LV_OBJ_FLAG_SCROLLABLE);

      lv_obj_t *box = lv_obj_create(popup);
      lv_obj_set_size(box, 440, 220);
      lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
      lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
      lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
      lv_obj_set_style_border_width(box, 2, 0);
      lv_obj_set_style_radius(box, 12, 0);
      lv_obj_set_style_pad_all(box, 0, 0);
      lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

      lv_obj_t *lbl_q = lv_label_create(box);
      lv_label_set_text(lbl_q, copy_flow_via_list ? T(STR_COPY_CONFIRM_TITLE) : T(STR_CONFIRM_LINK));
      lv_obj_set_style_text_color(lbl_q, lv_color_hex(0x28d49a), 0);
      lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_ext_18, 0);
      lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);
      lv_obj_align(lbl_q, LV_ALIGN_TOP_MID, 0, 16);

      // Spulen-Info
      char info[80];
      bool name_has_mat = (s.material[0] && s.name[0] &&
                           strncasecmp(s.name, s.material, strlen(s.material)) == 0);
      if (name_has_mat) {
        snprintf(info, sizeof(info), "#%d  %s\n%.0fg / %.0fg",
          s.id, s.name, s.remaining, s.total);
      } else {
        snprintf(info, sizeof(info), "#%d  %s %s\n%.0fg / %.0fg",
          s.id, s.material, s.name, s.remaining, s.total);
      }
      lv_obj_t *lbl_info = lv_label_create(box);
      lv_label_set_text(lbl_info, info);
      lv_obj_set_style_text_color(lbl_info, lv_color_hex(0xc8d8f0), 0);
      lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_ext_16, 0);
      lv_obj_set_style_text_align(lbl_info, LV_TEXT_ALIGN_CENTER, 0);
      lv_label_set_long_mode(lbl_info, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(lbl_info, 400);
      lv_obj_align(lbl_info, LV_ALIGN_TOP_MID, 0, 48);

      // Link button — y=110, h=46
      lv_obj_t *btn_yes = lv_btn_create(box);
      lv_obj_set_size(btn_yes, 420, 46);
      lv_obj_set_pos(btn_yes, 10, 110);
      lv_obj_set_style_bg_color(btn_yes, lv_color_hex(0x1a3020), 0);
      lv_obj_set_style_bg_color(btn_yes, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn_yes, 8, 0);
      lv_obj_set_style_shadow_width(btn_yes, 0, 0);
      lv_obj_set_style_border_width(btn_yes, 0, 0);
      lv_obj_set_user_data(btn_yes, (void*)(intptr_t)idx);
      lv_obj_add_event_cb(btn_yes, [](lv_event_t *e) {
        int cidx = (intptr_t)lv_obj_get_user_data(lv_event_get_target(e));
        lv_obj_t *pop = lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e)));
        lv_obj_del(pop);
        if (copy_flow_via_list) {
          // Copy flow via vendor/material picker — flag pattern
          copy_flow_via_list = false;
          UnlinkedSpool &cs = link_spools[cidx];
          logSDf("CopyConfirm via list: spool_id=%d fid=%d spw=%.0f", cs.id, cs.filament_id, cs.spool_weight);
          copy_confirm_fid = cs.filament_id;
          copy_confirm_remaining = cs.remaining;
          copy_confirm_initial = cs.total;
          copy_confirm_spool_w = cs.spool_weight;
          {
            bool nm = (cs.material[0] && cs.name[0] &&
                       strncasecmp(cs.name, cs.material, strlen(cs.material)) == 0);
            if (nm)
              snprintf(copy_confirm_name, sizeof(copy_confirm_name), "%s (%s)", cs.name, cs.vendor);
            else
              snprintf(copy_confirm_name, sizeof(copy_confirm_name), "%s %s (%s)", cs.material, cs.name, cs.vendor);
          }
          copy_confirm_pending = true;
        } else {
          doLinkPatch(link_spools[cidx].id, link_flow_is_bambu);
        }
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_yes = lv_label_create(btn_yes);
      lv_label_set_text(lbl_yes, copy_flow_via_list ? T(STR_BTN_CONFIRMED) : T(STR_LINK_OK));
      lv_obj_set_style_text_color(lbl_yes, lv_color_hex(0x40c080), 0);
      lv_obj_set_style_text_font(lbl_yes, &lv_font_montserrat_ext_18, 0);
      lv_obj_center(lbl_yes);

      // Cancel button — y=164 (gap=8 after btn_yes ends at 156)
      lv_obj_t *btn_no = lv_btn_create(box);
      lv_obj_set_size(btn_no, 420, 40);
      lv_obj_set_pos(btn_no, 10, 164);
      lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x3a1010), 0);
      lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x602020), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn_no, 8, 0);
      lv_obj_set_style_shadow_width(btn_no, 0, 0);
      lv_obj_set_style_border_width(btn_no, 0, 0);
      lv_obj_add_event_cb(btn_no, [](lv_event_t *e) {
        lv_obj_del(lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e))));
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_no = lv_label_create(btn_no);
      lv_label_set_text(lbl_no, T(STR_CANCEL));
      lv_obj_set_style_text_color(lbl_no, lv_color_hex(0xff8080), 0);
      lv_obj_set_style_text_font(lbl_no, &lv_font_montserrat_ext_14, 0);
      lv_obj_center(lbl_no);

    }, LV_EVENT_CLICKED, (void*)(intptr_t)i);
  }

  if (count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_spools);
    lv_label_set_text(lbl_empty, T(STR_NO_SPOOLS));
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  } else if (count >= spool_list_limit) {
    addListMoreInfo(list, STR_LIST_MORE_SPOOLS);
  }
}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — MATERIAL-AUSWAHL (Stufe 2)
// ============================================================
void showMaterialList(const char* vendor_name) {
  logSDf("SHOW: MaterialList vendor=%s", vendor_name);
  if (scr_link_mat) { lv_obj_del(scr_link_mat); scr_link_mat = nullptr; }
  strncpy(link_selected_vendor, vendor_name, sizeof(link_selected_vendor)-1);
  link_selected_material_full[0] = 0;  // reset on entry — set fresh in stage 3
  link_stage3_shown = false;

  scr_link_mat = buildLinkOverlay();

  char title_buf[48];
  snprintf(title_buf, sizeof(title_buf), "%s | %.16s", T(STR_MAT_TITLE), vendor_name);

  // Header with Back + Cancel
  lv_obj_t *hdr_mat = lv_obj_create(scr_link_mat);
  lv_obj_set_size(hdr_mat, 480, 52); lv_obj_set_pos(hdr_mat, 0, 0);
  lv_obj_set_style_bg_color(hdr_mat, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr_mat, 0, 0);
  lv_obj_set_style_pad_all(hdr_mat, 0, 0);
  lv_obj_set_style_radius(hdr_mat, 0, 0);
  lv_obj_clear_flag(hdr_mat, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t *lbl_title = lv_label_create(hdr_mat);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);
  lv_obj_t *btn_mat_back = lv_btn_create(hdr_mat);
  lv_obj_set_size(btn_mat_back, 44, 44); lv_obj_set_pos(btn_mat_back, 4, 4);
  lv_obj_set_style_bg_color(btn_mat_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_mat_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_mat_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_mat_back, 0, 0);
  lv_obj_set_style_border_width(btn_mat_back, 0, 0);
  lv_obj_add_event_cb(btn_mat_back, [](lv_event_t *e) {
    logSD("BTN: MatList -> Back");
    if (scr_link_mat) { lv_obj_del(scr_link_mat); scr_link_mat = nullptr; }
    showVendorList();
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_mat_back); lv_label_set_text(l, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(l, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }
  lv_obj_t *btn_mat_cancel = lv_btn_create(hdr_mat);
  lv_obj_set_size(btn_mat_cancel, 44, 44);
  lv_obj_align(btn_mat_cancel, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_mat_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_mat_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_mat_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_mat_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_mat_cancel, 0, 0);
  lv_obj_add_event_cb(btn_mat_cancel, [](lv_event_t *e) {
    logSD("BTN: MatList -> Cancel");
    copy_flow_via_list = false;
    if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
    if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_copy_entry)  { lv_obj_del(scr_copy_entry);  scr_copy_entry  = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_mat_cancel); lv_label_set_text(l, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }
  lv_obj_t *div = lv_obj_create(scr_link_mat);
  lv_obj_set_size(div, 480, 1); lv_obj_set_pos(div, 0, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  lv_obj_t *list = lv_obj_create(scr_link_mat);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  // Deduplicate material prefixes (3 chars) for the selected vendor
  static char seen_mats[20][4] = {};
  static int  mat_counts[20]   = {};
  static int  seen_count       = 0;
  seen_count = 0;
  memset(seen_mats, 0, sizeof(seen_mats));
  memset(mat_counts, 0, sizeof(mat_counts));

  bool mat_limit_hit = false;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (s.existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;
    if (strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
    if (!s.material[0]) continue;
    char prefix[4]; strncpy(prefix, s.material, 3); prefix[3] = '\0';
    bool found = false;
    for (int j = 0; j < seen_count; j++) {
      if (strncasecmp(seen_mats[j], prefix, 3) == 0) { mat_counts[j]++; found = true; break; }
    }
    if (!found) {
      if (seen_count >= spool_list_limit) { mat_limit_hit = true; continue; }
      strncpy(seen_mats[seen_count], prefix, 3);
      mat_counts[seen_count] = 1;
      seen_count++;
    }
  }

  for (int m = 0; m < seen_count; m++) {
    lv_obj_t *row = lv_btn_create(list);
    lv_obj_set_size(row, 452, 50);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    lv_obj_t *lbl_mat = lv_label_create(row);
    lv_label_set_text(lbl_mat, seen_mats[m]);
    lv_obj_set_style_text_color(lbl_mat, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_mat, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_mat, LV_ALIGN_LEFT_MID, 16, 0);

    lv_obj_t *lbl_cnt = lv_label_create(row);
    char cnt_buf[12]; snprintf(cnt_buf, sizeof(cnt_buf), "%d x", mat_counts[m]);
    lv_label_set_text(lbl_cnt, cnt_buf);
    lv_obj_set_style_text_color(lbl_cnt, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_cnt, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_cnt, LV_ALIGN_RIGHT_MID, -16, 0);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      int idx = (intptr_t)lv_event_get_user_data(e);
      strncpy(link_selected_material, seen_mats[idx], sizeof(link_selected_material)-1);
      link_selected_material_full[0] = 0;  // reset for new branch
      if (scr_link_mat) { lv_obj_del(scr_link_mat); scr_link_mat = nullptr; }
      showMaterialSubList(link_selected_vendor, link_selected_material);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)m);
  }

  if (seen_count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_mat);
    lv_label_set_text(lbl_empty, T(STR_NO_MATERIALS));
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  } else if (mat_limit_hit) {
    addListMoreInfo(list, STR_LIST_MORE_MATS);
  }

}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — MATERIAL-VOLLNAME-AUSWAHL (Stufe 3)
//  Dedupliziert s.material exakt fuer Vendor + Material-Prefix.
//  Bei nur einem Eintrag: direkt zu Stufe 4 (auto-skip).
// ============================================================
void showMaterialSubList(const char* vendor_name, const char* material_prefix) {
  logSDf("SHOW: MaterialSubList vendor=%s mat=%s", vendor_name, material_prefix);

  // First pass: collect unique full material names + counts
  static char seen_full[20][32] = {};
  static int  full_counts[20]   = {};
  static int  full_seen_count   = 0;
  full_seen_count = 0;
  memset(seen_full, 0, sizeof(seen_full));
  memset(full_counts, 0, sizeof(full_counts));

  bool full_limit_hit = false;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (s.existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;
    if (strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
    if (!s.material[0]) continue;
    if (strncasecmp(s.material, material_prefix, strlen(material_prefix)) != 0) continue;

    bool found = false;
    for (int j = 0; j < full_seen_count; j++) {
      if (strcasecmp(seen_full[j], s.material) == 0) { full_counts[j]++; found = true; break; }
    }
    if (!found) {
      if (full_seen_count >= spool_list_limit) { full_limit_hit = true; continue; }
      strncpy(seen_full[full_seen_count], s.material, sizeof(seen_full[0])-1);
      full_counts[full_seen_count] = 1;
      full_seen_count++;
    }
  }

  // Auto-skip stage 3 when only one full name found — go directly to stage 4
  if (full_seen_count == 1 && !full_limit_hit) {
    logSDf("MaterialSubList auto-skip: only %s", seen_full[0]);
    strncpy(link_selected_material_full, seen_full[0], sizeof(link_selected_material_full)-1);
    link_stage3_shown = false;  // not actually rendered — back from stage 4 must skip stage 3
    showFilteredSpoolList(vendor_name, material_prefix, link_selected_material_full);
    return;
  }

  link_stage3_shown = true;  // actually rendered
  if (scr_link_mat_sub) { lv_obj_del(scr_link_mat_sub); scr_link_mat_sub = nullptr; }
  scr_link_mat_sub = buildLinkOverlay();

  char title_buf[48];
  snprintf(title_buf, sizeof(title_buf), "%.16s | %.4s", vendor_name, material_prefix);

  // Header with Back + Cancel
  lv_obj_t *hdr_ms = lv_obj_create(scr_link_mat_sub);
  lv_obj_set_size(hdr_ms, 480, 52); lv_obj_set_pos(hdr_ms, 0, 0);
  lv_obj_set_style_bg_color(hdr_ms, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr_ms, 0, 0);
  lv_obj_set_style_pad_all(hdr_ms, 0, 0);
  lv_obj_set_style_radius(hdr_ms, 0, 0);
  lv_obj_clear_flag(hdr_ms, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t *lbl_title = lv_label_create(hdr_ms);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *btn_ms_back = lv_btn_create(hdr_ms);
  lv_obj_set_size(btn_ms_back, 44, 44); lv_obj_set_pos(btn_ms_back, 4, 4);
  lv_obj_set_style_bg_color(btn_ms_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_ms_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ms_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_ms_back, 0, 0);
  lv_obj_set_style_border_width(btn_ms_back, 0, 0);
  lv_obj_add_event_cb(btn_ms_back, [](lv_event_t *e) {
    logSD("BTN: MatSubList -> Back");
    if (scr_link_mat_sub) { lv_obj_del(scr_link_mat_sub); scr_link_mat_sub = nullptr; }
    showMaterialList(link_selected_vendor);
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_ms_back); lv_label_set_text(l, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(l, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }

  lv_obj_t *btn_ms_cancel = lv_btn_create(hdr_ms);
  lv_obj_set_size(btn_ms_cancel, 44, 44);
  lv_obj_align(btn_ms_cancel, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_ms_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_ms_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ms_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_ms_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_ms_cancel, 0, 0);
  lv_obj_add_event_cb(btn_ms_cancel, [](lv_event_t *e) {
    logSD("BTN: MatSubList -> Cancel");
    copy_flow_via_list = false;
    if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
    if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_copy_entry)  { lv_obj_del(scr_copy_entry);  scr_copy_entry  = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_ms_cancel); lv_label_set_text(l, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }

  lv_obj_t *div = lv_obj_create(scr_link_mat_sub);
  lv_obj_set_size(div, 480, 1); lv_obj_set_pos(div, 0, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  lv_obj_t *list = lv_obj_create(scr_link_mat_sub);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  for (int m = 0; m < full_seen_count; m++) {
    lv_obj_t *row = lv_btn_create(list);
    lv_obj_set_size(row, 452, 50);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    lv_obj_t *lbl_full = lv_label_create(row);
    lv_label_set_text(lbl_full, seen_full[m]);
    lv_obj_set_style_text_color(lbl_full, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_full, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_full, LV_ALIGN_LEFT_MID, 16, 0);
    lv_label_set_long_mode(lbl_full, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_full, 340);

    lv_obj_t *lbl_cnt = lv_label_create(row);
    char cnt_buf[12]; snprintf(cnt_buf, sizeof(cnt_buf), "%d x", full_counts[m]);
    lv_label_set_text(lbl_cnt, cnt_buf);
    lv_obj_set_style_text_color(lbl_cnt, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_cnt, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_cnt, LV_ALIGN_RIGHT_MID, -16, 0);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      int idx = (intptr_t)lv_event_get_user_data(e);
      strncpy(link_selected_material_full, seen_full[idx], sizeof(link_selected_material_full)-1);
      if (scr_link_mat_sub) { lv_obj_del(scr_link_mat_sub); scr_link_mat_sub = nullptr; }
      showFilteredSpoolList(link_selected_vendor, link_selected_material, link_selected_material_full);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)m);
  }

  if (full_seen_count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_mat_sub);
    lv_label_set_text(lbl_empty, T(STR_NO_MATERIALS));
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  } else if (full_limit_hit) {
    addListMoreInfo(list, STR_LIST_MORE_MATS);
  }
}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — HERSTELLER-AUSWAHL (Stufe 1)
// ============================================================
void showVendorList() {
  logSD("SHOW: VendorList");
  if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }

  scr_link_vendor = buildLinkOverlay();

  // Zaehle Spulen gesamt (ohne bereits verknuepft)
  int total_unlinked = 0;
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;
    total_unlinked++;
  }

  char title_buf[40];
  snprintf(title_buf, sizeof(title_buf), T(STR_VENDOR_TITLE), total_unlinked);

  lv_obj_t *hdr_vnd = lv_obj_create(scr_link_vendor);
  lv_obj_set_size(hdr_vnd, 480, 52); lv_obj_set_pos(hdr_vnd, 0, 0);
  lv_obj_set_style_bg_color(hdr_vnd, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr_vnd, 0, 0);
  lv_obj_set_style_pad_all(hdr_vnd, 0, 0);
  lv_obj_set_style_radius(hdr_vnd, 0, 0);
  lv_obj_clear_flag(hdr_vnd, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t *lbl_title = lv_label_create(hdr_vnd);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);
  // Back: go back to entry popup
  lv_obj_t *btn_vnd_back = lv_btn_create(hdr_vnd);
  lv_obj_set_size(btn_vnd_back, 44, 44); lv_obj_set_pos(btn_vnd_back, 4, 4);
  lv_obj_set_style_bg_color(btn_vnd_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_vnd_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_vnd_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_vnd_back, 0, 0);
  lv_obj_set_style_border_width(btn_vnd_back, 0, 0);
  lv_obj_add_event_cb(btn_vnd_back, [](lv_event_t *e) {
    logSD("BTN: VendorList -> Back");
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  lv_obj_clear_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN);
    if (scr_copy_entry)  lv_obj_clear_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_vnd_back); lv_label_set_text(l, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(l, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }
  lv_obj_t *btn_vnd_x = lv_btn_create(hdr_vnd);
  lv_obj_set_size(btn_vnd_x, 44, 44);
  lv_obj_align(btn_vnd_x, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_vnd_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_vnd_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_vnd_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_vnd_x, 0, 0);
  lv_obj_set_style_border_width(btn_vnd_x, 0, 0);
  lv_obj_add_event_cb(btn_vnd_x, [](lv_event_t *e) {
    logSD("BTN: VendorList -> Cancel");
    copy_flow_via_list = false;
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_copy_entry)  { lv_obj_del(scr_copy_entry);  scr_copy_entry  = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_vnd_x); lv_label_set_text(l, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0); lv_obj_center(l); }
  lv_obj_t *div = lv_obj_create(scr_link_vendor);
  lv_obj_set_size(div, 480, 1); lv_obj_set_pos(div, 0, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  lv_obj_t *list = lv_obj_create(scr_link_vendor);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  // Dedupliziere Vendors
  static char seen_vendors[20][32] = {};
  static int  vendor_counts[20]    = {};
  static int  seen_v               = 0;
  seen_v = 0;
  memset(seen_vendors, 0, sizeof(seen_vendors));
  memset(vendor_counts, 0, sizeof(vendor_counts));

  bool vendor_limit_hit = false;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (s.existing_tag[0] != '\0' && !(copy_flow_via_list && copy_flow_archived)) continue;
    const char* vn = s.vendor[0] ? s.vendor : "Unbekannt";
    bool found = false;
    for (int j = 0; j < seen_v; j++) {
      if (strcasecmp(seen_vendors[j], vn) == 0) { vendor_counts[j]++; found = true; break; }
    }
    if (!found) {
      if (seen_v >= spool_list_limit) { vendor_limit_hit = true; continue; }
      strncpy(seen_vendors[seen_v], vn, 31);
      vendor_counts[seen_v] = 1;
      seen_v++;
    }
  }

  for (int v = 0; v < seen_v; v++) {
    lv_obj_t *row = lv_btn_create(list);
    lv_obj_set_size(row, 452, 50);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    lv_obj_t *lbl_vnd = lv_label_create(row);
    lv_label_set_text(lbl_vnd, seen_vendors[v]);
    lv_obj_set_style_text_color(lbl_vnd, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl_vnd, &lv_font_montserrat_ext_18, 0);
    lv_obj_align(lbl_vnd, LV_ALIGN_LEFT_MID, 16, 0);
    lv_label_set_long_mode(lbl_vnd, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_vnd, 320);

    lv_obj_t *lbl_cnt = lv_label_create(row);
    char cnt_buf[12]; snprintf(cnt_buf, sizeof(cnt_buf), "%d x", vendor_counts[v]);
    lv_label_set_text(lbl_cnt, cnt_buf);
    lv_obj_set_style_text_color(lbl_cnt, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_cnt, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_cnt, LV_ALIGN_RIGHT_MID, -16, 0);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      int idx = (intptr_t)lv_event_get_user_data(e);
      if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
      showMaterialList(seen_vendors[idx]);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)v);
  }

  if (seen_v == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_vendor);
    lv_label_set_text(lbl_empty, T(STR_NO_VENDORS));
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  } else if (vendor_limit_hit) {
    addListMoreInfo(list, STR_LIST_MORE_VENDORS);
  }

}

// ============================================================
//  LINK-FLOW: EINSTIEGS-POPUP (Flow A + B)
// ============================================================
void closeLinkEntryPopup() {
  if (scr_link_entry) { lv_obj_del(scr_link_entry); scr_link_entry = nullptr; }
}

void showLinkEntryPopup(bool is_bambu) {
  logSDf("SHOW: LinkEntryPopup bambu=%d", (int)is_bambu);
  link_selected_material[0] = 0;  // reset material selection for each new flow
  link_selected_material_full[0] = 0;
  link_stage3_shown = false;
  closeLinkEntryPopup();
  link_flow_is_bambu = is_bambu;
  link_id_input[0]   = '\0';

  scr_link_entry = buildLinkOverlay();

  // Header-Titel
  lv_obj_t *lbl_title = lv_label_create(scr_link_entry);
  lv_label_set_text(lbl_title, is_bambu ? T(STR_LINK_BAMBU_TITLE) : T(STR_LINK_NTAG_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 22);

  // Separator line
  lv_obj_t *div = lv_obj_create(scr_link_entry);
  lv_obj_set_size(div, 472, 1); lv_obj_set_pos(div, 4, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  // Kontext-Info (Material/UID)
  lv_obj_t *lbl_ctx = lv_label_create(scr_link_entry);
  char ctx_buf[56];
  if (is_bambu) {
    snprintf(ctx_buf, sizeof(ctx_buf), T(STR_LINK_CTX_NOT_IN_SM),
      g_tag.material[0] ? g_tag.material : "Bambu Tag");
  } else {
    snprintf(ctx_buf, sizeof(ctx_buf), "UID: %s", link_tag_uid);
  }
  lv_label_set_text(lbl_ctx, ctx_buf);
  lv_obj_set_style_text_color(lbl_ctx, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_ctx, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_ctx, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_ctx, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_ctx, 450);
  lv_obj_align(lbl_ctx, LV_ALIGN_TOP_MID, 0, 62);

  // Button-Layout: 3 Buttons zentriert, je 380x60
  const int BTN_W = 380, BTN_H = 60, BTN_GAP = 10;
  const int Y1 = 100, Y2 = Y1 + BTN_H + BTN_GAP, Y3 = Y2 + BTN_H + BTN_GAP;

  // Button 1: Spool-ID eingeben
  lv_obj_t *btn1 = lv_btn_create(scr_link_entry);
  lv_obj_set_size(btn1, BTN_W, BTN_H);
  lv_obj_align(btn1, LV_ALIGN_TOP_MID, 0, Y1);
  lv_obj_set_style_bg_color(btn1, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn1, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn1, 10, 0);
  lv_obj_set_style_shadow_width(btn1, 0, 0);
  lv_obj_set_style_border_width(btn1, 1, 0);
  lv_obj_set_style_border_color(btn1, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn1, [](lv_event_t *e) {
    link_id_input[0] = '\0';
    showIdInputPopup(link_flow_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *l1 = lv_label_create(btn1);
  lv_label_set_text(l1, T(STR_BTN_ENTER_ID));
  lv_obj_set_style_text_color(l1, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(l1, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(l1);

  // Button 2: Aus Liste waehlen
  lv_obj_t *btn2 = lv_btn_create(scr_link_entry);
  lv_obj_set_size(btn2, BTN_W, BTN_H);
  lv_obj_align(btn2, LV_ALIGN_TOP_MID, 0, Y2);
  lv_obj_set_style_bg_color(btn2, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn2, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn2, 10, 0);
  lv_obj_set_style_shadow_width(btn2, 0, 0);
  lv_obj_set_style_border_width(btn2, 1, 0);
  lv_obj_set_style_border_color(btn2, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn2, [](lv_event_t *e) {
    // Load and pre-filter spools, then start appropriate flow
    fetchAllSpoolsForLink(link_flow_is_bambu, link_flow_is_bambu ? g_tag.material : "");
    if (link_flow_is_bambu) {
      showFilteredSpoolList("", "", "");  // Flow A: direct list (already material-filtered)
    } else {
      showVendorList();               // Flow B: 3-step
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *l2 = lv_label_create(btn2);
  lv_label_set_text(l2, T(STR_BTN_FROM_LIST));
  lv_obj_set_style_text_color(l2, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(l2, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(l2);

  // Button 3: Abbrechen
  lv_obj_t *btn3 = lv_btn_create(scr_link_entry);
  lv_obj_set_size(btn3, BTN_W, BTN_H - 14);  // etwas kleiner
  lv_obj_align(btn3, LV_ALIGN_TOP_MID, 0, Y3);
  lv_obj_set_style_bg_color(btn3, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn3, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn3, 10, 0);
  lv_obj_set_style_shadow_width(btn3, 0, 0);
  lv_obj_set_style_border_width(btn3, 0, 0);
  lv_obj_add_event_cb(btn3, [](lv_event_t *e) {
    link_popup_dismissed = true;
    closeLinkEntryPopup();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *l3 = lv_label_create(btn3);
  lv_label_set_text(l3, T(STR_CANCEL));
  lv_obj_set_style_text_color(l3, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(l3, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(l3);
}

// ============================================================
//  LEGACY: closeLinkList / showLinkList (nicht mehr aktiv genutzt)
// ============================================================
void closeLinkList() {
  if (scr_link_list)   { lv_obj_del(scr_link_list);   scr_link_list   = nullptr; }
  if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
  if (scr_link_id)     { lv_obj_del(scr_link_id);     scr_link_id     = nullptr; }
  if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
  if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
  if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
}

void showLinkList() {
  logSD("SHOW: LinkList (legacy)");
  // Wird nicht mehr direkt aufgerufen — Entry-Popup uebernimmt
  showLinkEntryPopup(false);
}

void closeConfirmPopup() {
  if (confirm_popup) { lv_obj_del(confirm_popup); confirm_popup = nullptr; }
  confirm_action = 0;
  lbl_auto_weight_btn = nullptr;  // Pointer ungültig nach lv_obj_del
}

void showConfirmPopup(const char* msg, int action) {
  closeConfirmPopup();
  confirm_action = action;

  confirm_popup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(confirm_popup, 480, 320);
  lv_obj_set_pos(confirm_popup, 0, 0);
  lv_obj_set_style_bg_color(confirm_popup, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(confirm_popup, LV_OPA_70, 0);
  lv_obj_set_style_border_width(confirm_popup, 0, 0);
  lv_obj_set_style_radius(confirm_popup, 0, 0);
  lv_obj_set_style_pad_all(confirm_popup, 0, 0);  // KRITISCH: kein Default-Padding!
  lv_obj_clear_flag(confirm_popup, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(confirm_popup);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x2a4080), 0);
  lv_obj_set_style_border_width(box, 2, 0);
  lv_obj_set_style_radius(box, 12, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_q = lv_label_create(box);
  lv_label_set_text(lbl_q, msg);
  lv_obj_set_style_text_color(lbl_q, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_q, LV_LABEL_LONG_WRAP);

  if (action == 2) {
    // Layout: 4 Zeilen — Row1=66, Row2=52, Row3=52, Row4=42
    // BOX_H = 8+28+6+66+6+52+6+52+6+42+8 = 280px (original)
    const int BOX_W  = 460;
    const int H_ROW1 = 66;
    const int H_ROW2 = 52;
    const int H_ROW3 = 52;
    const int H_ROW4 = 42;
    const int PAD    = 6;
    const int EDGE   = 8;
    const int HDR_H  = 28;
    const int BOX_H  = EDGE + HDR_H + PAD + H_ROW1 + PAD + H_ROW2 + PAD + H_ROW3 + PAD + H_ROW4 + EDGE;

    lv_obj_set_size(box, BOX_W, BOX_H);
    lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_pad_all(box, 0, 0);

    lv_obj_set_width(lbl_q, BOX_W - 2*EDGE);
    lv_obj_set_pos(lbl_q, EDGE, 6);
    lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);

    const int Y1 = EDGE + HDR_H + PAD;
    const int Y2 = Y1 + H_ROW1 + PAD;
    const int Y3 = Y2 + H_ROW2 + PAD;
    const int Y4 = Y3 + H_ROW3 + PAD;

    const int BW2 = (BOX_W - 2*EDGE - PAD) / 2;
    const int XL  = EDGE;
    const int XR  = EDGE + BW2 + PAD;

    float netto_plain = scale_weight_g - (float)sm_spool_weight;
    float netto_bag   = netto_plain - bag_weight_g;
    if (netto_plain < 0) netto_plain = 0;
    if (netto_bag   < 0) netto_bag   = 0;

    // ── Zeile 1 Links: Ohne Beutel ──
    lv_obj_t *btn1 = lv_btn_create(box);
    lv_obj_set_size(btn1, BW2, H_ROW1);
    lv_obj_set_pos(btn1, XL, Y1);
    lv_obj_set_style_bg_color(btn1, lv_color_hex(0x1a4020), 0);
    lv_obj_set_style_bg_color(btn1, lv_color_hex(0x2a7030), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn1, 8, 0);
    lv_obj_set_style_shadow_width(btn1, 0, 0);
    lv_obj_add_event_cb(btn1, [](lv_event_t *e) {
      closeConfirmPopup();
      float r = scale_weight_g - (float)sm_spool_weight;
      if (r < 0) r = 0;
      patchSpoolmanWeight(r);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l1 = lv_label_create(btn1);
    char buf1[48];
    snprintf(buf1, sizeof(buf1), T(STR_BTN_NO_BAG_VAL), netto_plain);
    lv_label_set_text(l1, buf1);
    lv_obj_set_style_text_color(l1, lv_color_hex(0x80ffb0), 0);
    lv_obj_set_style_text_font(l1, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l1, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l1);

    // ── Zeile 1 Rechts: Mit Beutel ──
    lv_obj_t *btn2 = lv_btn_create(box);
    lv_obj_set_size(btn2, BW2, H_ROW1);
    lv_obj_set_pos(btn2, XR, Y1);
    lv_obj_set_style_bg_color(btn2, lv_color_hex(0x1a3a20), 0);
    lv_obj_set_style_bg_color(btn2, lv_color_hex(0x2a6030), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn2, 8, 0);
    lv_obj_set_style_shadow_width(btn2, 0, 0);
    lv_obj_add_event_cb(btn2, [](lv_event_t *e) {
      closeConfirmPopup();
      float r = scale_weight_g - (float)sm_spool_weight - bag_weight_g;
      if (r < 0) r = 0;
      patchSpoolmanWeight(r);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l2 = lv_label_create(btn2);
    char buf2[56];
    snprintf(buf2, sizeof(buf2), T(STR_BTN_WITH_BAG_VAL), netto_plain, bag_weight_g);
    lv_label_set_text(l2, buf2);
    lv_obj_set_style_text_color(l2, lv_color_hex(0x80ffb0), 0);
    lv_obj_set_style_text_font(l2, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l2, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l2);

    // ── Zeile 2 Links: Neue Spule ──
    lv_obj_t *btn3 = lv_btn_create(box);
    lv_obj_set_size(btn3, BW2, H_ROW2);
    lv_obj_set_pos(btn3, XL, Y2);
    lv_obj_set_style_bg_color(btn3, lv_color_hex(0x102040), 0);
    lv_obj_set_style_bg_color(btn3, lv_color_hex(0x1a3870), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn3, 8, 0);
    lv_obj_set_style_shadow_width(btn3, 0, 0);
    lv_obj_add_event_cb(btn3, [](lv_event_t *e) {
      closeConfirmPopup();
      float initial = scale_weight_g - (float)sm_spool_weight;
      if (initial < 0) initial = 0;
      patchInitialWeight(initial);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l3 = lv_label_create(btn3);
    char buf3[56];
    snprintf(buf3, sizeof(buf3), T(STR_BTN_NEW_SPOOL_VAL), netto_plain);
    lv_label_set_text(l3, buf3);
    lv_obj_set_style_text_color(l3, lv_color_hex(0x80c8ff), 0);
    lv_obj_set_style_text_font(l3, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(l3, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l3);

    // ── Row 2 right: empty spool + core ──
    lv_obj_t *btn4 = lv_btn_create(box);
    lv_obj_set_size(btn4, BW2, H_ROW2);
    lv_obj_set_pos(btn4, XR, Y2);
    lv_obj_set_style_bg_color(btn4, lv_color_hex(0x1a2a40), 0);
    lv_obj_set_style_bg_color(btn4, lv_color_hex(0x2a4060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn4, 8, 0);
    lv_obj_set_style_shadow_width(btn4, 0, 0);
    lv_obj_add_event_cb(btn4, [](lv_event_t *e) {
      closeConfirmPopup();
      // Sub-popup: where should the spool weight be written?
      float w = scale_weight_g;

      lv_obj_t *popup = lv_obj_create(lv_scr_act());
      lv_obj_set_size(popup, 480, 320);
      lv_obj_set_pos(popup, 0, 0);
      lv_obj_set_style_bg_color(popup, lv_color_hex(0x0a1020), 0);
      lv_obj_set_style_bg_opa(popup, LV_OPA_COVER, 0);
      lv_obj_set_style_border_width(popup, 0, 0);
      lv_obj_set_style_pad_all(popup, 0, 0);
      lv_obj_clear_flag(popup, LV_OBJ_FLAG_SCROLLABLE);

      // Title
      lv_obj_t *title = lv_label_create(popup);
      char title_buf[48];
      snprintf(title_buf, sizeof(title_buf), T(STR_SPOOL_WEIGHT_TITLE), w);
      lv_label_set_text(title, title_buf);
      lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
      lv_obj_set_style_text_font(title, &lv_font_montserrat_ext_14, 0);
      lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

      // Button 1: this spool
      lv_obj_t *b1 = lv_btn_create(popup);
      lv_obj_set_size(b1, 460, 60); lv_obj_set_pos(b1, 10, 36);
      lv_obj_set_style_bg_color(b1, lv_color_hex(0x0a2040), 0);
      lv_obj_set_style_radius(b1, 8, 0); lv_obj_set_style_shadow_width(b1, 0, 0);
      { lv_obj_t *l = lv_label_create(b1);
        lv_label_set_text(l, T(STR_BTN_THIS_SPOOL));
        lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b1, [](lv_event_t *e) {
        patchSpoolWeight(scale_weight_g);
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

      // Button 2: this filament
      lv_obj_t *b2 = lv_btn_create(popup);
      lv_obj_set_size(b2, 460, 60); lv_obj_set_pos(b2, 10, 106);
      lv_obj_set_style_bg_color(b2, lv_color_hex(0x0a2820), 0);
      lv_obj_set_style_radius(b2, 8, 0); lv_obj_set_style_shadow_width(b2, 0, 0);
      { lv_obj_t *l = lv_label_create(b2);
        lv_label_set_text(l, T(STR_BTN_THIS_FILAMENT));
        lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b2, [](lv_event_t *e) {
        patchFilamentSpoolWeight(scale_weight_g);
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

      // Button 3: vendor
      lv_obj_t *b3 = lv_btn_create(popup);
      lv_obj_set_size(b3, 460, 60); lv_obj_set_pos(b3, 10, 176);
      lv_obj_set_style_bg_color(b3, lv_color_hex(0x281a00), 0);
      lv_obj_set_style_radius(b3, 8, 0); lv_obj_set_style_shadow_width(b3, 0, 0);
      { lv_obj_t *l = lv_label_create(b3);
        lv_label_set_text(l, T(STR_BTN_THIS_VENDOR));
        lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b3, [](lv_event_t *e) {
        patchVendorSpoolWeight(scale_weight_g);
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

      // Button 4: cancel
      lv_obj_t *b4 = lv_btn_create(popup);
      lv_obj_set_size(b4, 460, 40); lv_obj_set_pos(b4, 10, 256);
      lv_obj_set_style_bg_color(b4, lv_color_hex(0x3a1010), 0);
      lv_obj_set_style_radius(b4, 8, 0); lv_obj_set_style_shadow_width(b4, 0, 0);
      { lv_obj_t *l = lv_label_create(b4);
        lv_label_set_text(l, T(STR_CANCEL));
        lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_14, 0);
        lv_obj_center(l); }
      lv_obj_add_event_cb(b4, [](lv_event_t *e) {
        lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
      }, LV_EVENT_CLICKED, NULL);

    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l4 = lv_label_create(btn4);
    char buf4[56];
    snprintf(buf4, sizeof(buf4), T(STR_BTN_EMPTY_SPOOL), scale_weight_g);
    lv_label_set_text(l4, buf4);
    lv_obj_set_style_text_color(l4, lv_color_hex(0x80c0ff), 0);
    lv_obj_set_style_text_font(l4, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(l4, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l4);

    // ── Row 3 links: Auto-Speichern Toggle ──
    // AN->AUS: sofort deaktivieren + Popup schliessen
    // AUS->AN: aktivieren + Popup schliessen, Hintergrund laeuft ab jetzt
    lv_obj_t *btn5 = lv_btn_create(box);
    lv_obj_set_size(btn5, BW2, H_ROW3);
    lv_obj_set_pos(btn5, XL, Y3);
    lv_obj_set_style_bg_color(btn5, g_auto_weight ? lv_color_hex(0x1a3020) : lv_color_hex(0x101820), 0);
    lv_obj_set_style_bg_color(btn5, g_auto_weight ? lv_color_hex(0x2a5030) : lv_color_hex(0x1a2a38), LV_STATE_PRESSED);
    lv_obj_set_style_border_width(btn5, 1, 0);
    lv_obj_set_style_border_color(btn5, g_auto_weight ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_radius(btn5, 8, 0);
    lv_obj_set_style_shadow_width(btn5, 0, 0);
    lv_obj_add_event_cb(btn5, [](lv_event_t *e) {
      if (g_auto_weight) {
        // Deaktivieren: sofort, kein zweites Popup
        g_auto_weight = false;
        auto_weight_stable_ms = 0;
        auto_weight_last_val = -9999.0f;
        prefsPutBoolInNamespace("spool", "auto_weight", false);
        logSD("Auto-Weight: deaktiviert");
        if (lbl_weight_main_lbl) {
          char wmbuf[40];
          strncpy(wmbuf, T(STR_BTN_WEIGHT), sizeof(wmbuf)-1); wmbuf[sizeof(wmbuf)-1] = '\0';
          lv_label_set_text(lbl_weight_main_lbl, wmbuf);
          lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x40c080), 0);
        }
        closeConfirmPopup();
      } else {
        // Aktivieren: zweites Bestaetigungs-Popup zeigen
        // Gewichts-Popup verstecken (nicht loeschen — cancel bringt es zurueck)
        if (confirm_popup) lv_obj_add_flag(confirm_popup, LV_OBJ_FLAG_HIDDEN);

        lv_obj_t *apop = lv_obj_create(lv_scr_act());
        lv_obj_set_size(apop, 480, 320);
        lv_obj_set_pos(apop, 0, 0);
        lv_obj_set_style_bg_color(apop, lv_color_hex(0x000000), 0);
        lv_obj_set_style_bg_opa(apop, LV_OPA_70, 0);
        lv_obj_set_style_border_width(apop, 0, 0);
        lv_obj_set_style_radius(apop, 0, 0);
        lv_obj_set_style_pad_all(apop, 0, 0);
        lv_obj_clear_flag(apop, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *abox = lv_obj_create(apop);
        lv_obj_set_size(abox, 460, 220);
        lv_obj_align(abox, LV_ALIGN_CENTER, 0, 0);
        lv_obj_set_style_bg_color(abox, lv_color_hex(0x0c1828), 0);
        lv_obj_set_style_border_color(abox, lv_color_hex(0x2a4080), 0);
        lv_obj_set_style_border_width(abox, 2, 0);
        lv_obj_set_style_radius(abox, 12, 0);
        lv_obj_set_style_pad_all(abox, 0, 0);
        lv_obj_clear_flag(abox, LV_OBJ_FLAG_SCROLLABLE);

        // Titel
        lv_obj_t *atitle = lv_label_create(abox);
        char atbuf[48]; strncpy(atbuf, T(STR_AUTO_WEIGHT_TITLE), sizeof(atbuf)-1); atbuf[sizeof(atbuf)-1] = '\0';
        lv_label_set_text(atitle, atbuf);
        lv_obj_set_style_text_color(atitle, lv_color_hex(0x28d49a), 0);
        lv_obj_set_style_text_font(atitle, &lv_font_montserrat_ext_16, 0);
        lv_obj_set_style_text_align(atitle, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_set_width(atitle, 444);
        lv_obj_set_pos(atitle, 8, 10);

        // Info-Text
        lv_obj_t *ainfo = lv_label_create(abox);
        char aibuf[160]; strncpy(aibuf, T(STR_AUTO_WEIGHT_INFO), sizeof(aibuf)-1); aibuf[sizeof(aibuf)-1] = '\0';
        lv_label_set_text(ainfo, aibuf);
        lv_obj_set_style_text_color(ainfo, lv_color_hex(0xc8d8f0), 0);
        lv_obj_set_style_text_font(ainfo, &lv_font_montserrat_ext_14, 0);
        lv_obj_set_style_text_align(ainfo, LV_TEXT_ALIGN_CENTER, 0);
        lv_label_set_long_mode(ainfo, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(ainfo, 444);
        lv_obj_set_pos(ainfo, 8, 38);

        // Bestaetigen-Button
        lv_obj_t *abtn_ok = lv_btn_create(abox);
        lv_obj_set_size(abtn_ok, 222, 52);
        lv_obj_set_pos(abtn_ok, 8, 156);
        lv_obj_set_style_bg_color(abtn_ok, lv_color_hex(0x1a3020), 0);
        lv_obj_set_style_bg_color(abtn_ok, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
        lv_obj_set_style_radius(abtn_ok, 8, 0);
        lv_obj_set_style_shadow_width(abtn_ok, 0, 0);
        lv_obj_add_event_cb(abtn_ok, [](lv_event_t *e) {
          lv_obj_t *apop = lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e)));
          // Aktivieren
          g_auto_weight = true;
          auto_weight_stable_ms = 0;
          auto_weight_last_val = -9999.0f;
          prefsPutBoolInNamespace("spool", "auto_weight", true);
          logSD("Auto-Weight: aktiviert");
          if (lbl_weight_main_lbl) {
            char wmbuf[48];
            snprintf(wmbuf, sizeof(wmbuf), "%s (A)", g_lang == LANG_DE ? "Gewicht updaten" : "Update Weight");
            lv_label_set_text(lbl_weight_main_lbl, wmbuf);
            lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x28d49a), 0);
          }
          lv_obj_del(apop);         // zweites Popup weg
          closeConfirmPopup();      // erstes Popup weg
        }, LV_EVENT_CLICKED, NULL);
        lv_obj_t *abtn_ok_lbl = lv_label_create(abtn_ok);
        char acbuf[32]; strncpy(acbuf, T(STR_CONFIRM), sizeof(acbuf)-1); acbuf[sizeof(acbuf)-1] = '\0';
        lv_label_set_text(abtn_ok_lbl, acbuf);
        lv_obj_set_style_text_color(abtn_ok_lbl, lv_color_hex(0x40c080), 0);
        lv_obj_set_style_text_font(abtn_ok_lbl, &lv_font_montserrat_ext_14, 0);
        lv_obj_align(abtn_ok_lbl, LV_ALIGN_CENTER, 0, 0);

        // Abbrechen-Button
        lv_obj_t *abtn_cancel = lv_btn_create(abox);
        lv_obj_set_size(abtn_cancel, 222, 52);
        lv_obj_set_pos(abtn_cancel, 238, 156);
        lv_obj_set_style_bg_color(abtn_cancel, lv_color_hex(0x3a1010), 0);
        lv_obj_set_style_bg_color(abtn_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
        lv_obj_set_style_radius(abtn_cancel, 8, 0);
        lv_obj_set_style_shadow_width(abtn_cancel, 0, 0);
        lv_obj_add_event_cb(abtn_cancel, [](lv_event_t *e) {
          lv_obj_t *apop = lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e)));
          lv_obj_del(apop);
          // Erstes Popup wieder einblenden
          if (confirm_popup) lv_obj_clear_flag(confirm_popup, LV_OBJ_FLAG_HIDDEN);
        }, LV_EVENT_CLICKED, NULL);
        lv_obj_t *abtn_cancel_lbl = lv_label_create(abtn_cancel);
        char acancelbuf[32]; strncpy(acancelbuf, T(STR_CANCEL), sizeof(acancelbuf)-1); acancelbuf[sizeof(acancelbuf)-1] = '\0';
        lv_label_set_text(abtn_cancel_lbl, acancelbuf);
        lv_obj_set_style_text_color(abtn_cancel_lbl, lv_color_hex(0xff8080), 0);
        lv_obj_set_style_text_font(abtn_cancel_lbl, &lv_font_montserrat_ext_14, 0);
        lv_obj_align(abtn_cancel_lbl, LV_ALIGN_CENTER, 0, 0);
      }
    }, LV_EVENT_CLICKED, NULL);
    lbl_auto_weight_btn = lv_label_create(btn5);
    {
      char abuf[48];
      strncpy(abuf, g_auto_weight ? T(STR_AUTO_WEIGHT_DISABLE) : T(STR_AUTO_WEIGHT_ENABLE), sizeof(abuf)-1);
      abuf[sizeof(abuf)-1] = '\0';
      lv_label_set_text(lbl_auto_weight_btn, abuf);
    }
    lv_obj_set_style_text_color(lbl_auto_weight_btn, g_auto_weight ? lv_color_hex(0x28d49a) : lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_auto_weight_btn, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(lbl_auto_weight_btn, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(lbl_auto_weight_btn);

    // ── Row 3 right: empty / archive ──
    lv_obj_t *btn6 = lv_btn_create(box);
    lv_obj_set_size(btn6, BW2, H_ROW3);
    lv_obj_set_pos(btn6, XR, Y3);
    lv_obj_set_style_bg_color(btn6, lv_color_hex(0x3a1a00), 0);
    lv_obj_set_style_bg_color(btn6, lv_color_hex(0x6a3000), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn6, 8, 0);
    lv_obj_set_style_shadow_width(btn6, 0, 0);
    lv_obj_add_event_cb(btn6, [](lv_event_t *e) {
      closeConfirmPopup();
      // Separate confirmation popup for archiving
      showConfirmPopup(T(STR_ARCHIVE_CONFIRM), 3);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l6 = lv_label_create(btn6);
    lv_label_set_text(l6, T(STR_BTN_ARCHIVE_EMPTY));
    lv_obj_set_style_text_color(l6, lv_color_hex(0xffb060), 0);
    lv_obj_set_style_text_font(l6, &lv_font_montserrat_ext_14, 0);
    lv_obj_set_style_text_align(l6, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l6);

    // ── Row 4: cancel (full width) ──
    const int BW_FULL = BOX_W - 2*EDGE;
    lv_obj_t *btn7 = lv_btn_create(box);
    lv_obj_set_size(btn7, BW_FULL, H_ROW4);
    lv_obj_set_pos(btn7, XL, Y4);
    lv_obj_set_style_bg_color(btn7, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn7, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn7, 8, 0);
    lv_obj_set_style_shadow_width(btn7, 0, 0);
    lv_obj_add_event_cb(btn7, [](lv_event_t *e){ closeConfirmPopup(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l7 = lv_label_create(btn7);
    lv_label_set_text(l7, T(STR_CANCEL));
    lv_obj_set_style_text_color(l7, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l7, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l7, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l7);

  } else {
    // Standard popup (dried): yes / no
    lv_obj_set_size(box, 400, 200);
    lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_pad_all(box, 0, 0);
    lv_obj_set_width(lbl_q, 360);
    lv_obj_align(lbl_q, LV_ALIGN_TOP_MID, 0, 20);

    lv_obj_t *btn_ja = lv_btn_create(box);
    lv_obj_set_size(btn_ja, 170, 56);
    lv_obj_set_pos(btn_ja, 12, 122);
    lv_obj_set_style_bg_color(btn_ja, lv_color_hex(0x1a4020), 0);
    lv_obj_set_style_bg_color(btn_ja, lv_color_hex(0x2a7030), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_ja, 8, 0);
    lv_obj_set_style_shadow_width(btn_ja, 0, 0);
    lv_obj_add_event_cb(btn_ja, [](lv_event_t *e) {
      int act = confirm_action;
      closeConfirmPopup();
      if (act == 1) btn_dried_cb(nullptr);
      if (act == 3) patchArchiveSpool();
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_ja = lv_label_create(btn_ja);
    lv_label_set_text(lbl_ja, T(STR_BTN_CONFIRMED));
    lv_obj_set_style_text_font(lbl_ja, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_color(lbl_ja, lv_color_hex(0x80ffb0), 0);
    lv_obj_center(lbl_ja);

    lv_obj_t *btn_nein = lv_btn_create(box);
    lv_obj_set_size(btn_nein, 170, 56);
    lv_obj_set_pos(btn_nein, 218, 122);
    lv_obj_set_style_bg_color(btn_nein, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_nein, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_nein, 8, 0);
    lv_obj_set_style_shadow_width(btn_nein, 0, 0);
    lv_obj_add_event_cb(btn_nein, [](lv_event_t *e){ closeConfirmPopup(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_nein = lv_label_create(btn_nein);
    lv_label_set_text(lbl_nein, T(STR_CANCEL));
    lv_obj_set_style_text_font(lbl_nein, &lv_font_montserrat_ext_18, 0);
    lv_obj_set_style_text_color(lbl_nein, lv_color_hex(0xff8080), 0);
    lv_obj_center(lbl_nein);
  }
}

// ============================================================
//  UPDATE HEADER STATUS
//  Central function - always call when wifi_ok, nfc_ok changes
//  or scan_count changes.
// ============================================================
// Hilfsfunktion: WiFi-Farbe je nach RSSI
//   green (0x28d49a): connected, good signal  (>= -65 dBm)
//   gelb  (0xf0b838): verbunden, Signal mittel (-75..-66 dBm)
//   orange(0xe06020): verbunden, Signal schwach (< -75 dBm)
//   rot   (0xe04040): nicht verbunden
static lv_color_t wifiColor() {
  if (!wifi_ok) return lv_color_hex(0xe04040);
  int rssi = wifiManagerRSSI();
  if (rssi >= -65) return lv_color_hex(0x28d49a);
  if (rssi >= -75) return lv_color_hex(0xf0b838);
  return lv_color_hex(0xe06020);
}

void updateHeaderStatus() {
  if (!lbl_hdr_wifi) return;

  // WiFi-Symbol: Farbe je nach Verbindung + RSSI
  lv_obj_set_style_text_color(lbl_hdr_wifi, wifiColor(), 0);

  // NFC: green if OK, red if error
  if (lbl_hdr_nfc) {
    lv_label_set_text(lbl_hdr_nfc, nfc_ok ? "NFC" : "NFC!");
    lv_obj_set_style_text_color(lbl_hdr_nfc,
      nfc_ok ? lv_color_hex(0x28d49a) : lv_color_hex(0xe04040), 0);
  }

  // SCL: green if NAU7802 connected, red if not
  if (lbl_hdr_scl) {
    lv_label_set_text(lbl_hdr_scl, scl_ok ? "SCL" : "SCL!");
    lv_obj_set_style_text_color(lbl_hdr_scl,
      scl_ok ? lv_color_hex(0x28d49a) : lv_color_hex(0xe04040), 0);
  }

  // Fix 10: Spoolman reachability
  if (lbl_hdr_sm) {
    lv_obj_set_style_text_color(lbl_hdr_sm,
      sm_reachable ? lv_color_hex(0x28d49a) : lv_color_hex(0xe04040), 0);
  }

  // Scan counter: muted dark blue
  if (lbl_hdr_scans) {
    char buf[12];
    snprintf(buf, sizeof(buf), "#%d", scan_count);
    lv_label_set_text(lbl_hdr_scans, buf);
  }
}

// ============================================================
//  UI BAUEN  — Redesign Beta_0.4.100
//  Zone 1: Header      y=0..25   (26px)  Name/Version | WiFi NFC
//  Zone 2: Status      y=26..47  (22px)  dot + status text | #scans
//  Zone 3: Spool Info  y=48..183 (136px) full width: swatch/id/mat/name | vendor/temp | dates/more
//  Zone 4: Weights     y=184..263 (80px) Spoolman(+bar) | Scale(+diff) | TARE btn
//  Zone 5: Buttons     y=264..319 (56px) [Update Weight] [Dried today] [Settings]
// ============================================================
void buildUI() {
  lv_obj_set_style_bg_color(lv_scr_act(), lv_color_hex(0x0a1020), 0);

  // ── ZONE 1: Header y=0..25 (26px) ───────────────────────
  // Name+Version left | WiFi NFC right — scan counter moved to status bar
  lv_obj_t *hdr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(hdr, 480, 26);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *hdr_lbl = lv_label_create(hdr);
  lv_label_set_text(hdr_lbl, "SpoolmanScale " FW_VERSION);
  lv_obj_set_style_text_color(hdr_lbl, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(hdr_lbl, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(hdr_lbl, LV_ALIGN_LEFT_MID, 6, 0);

  // SD card indicator in header — only visible when sd_available
  lv_obj_t *lbl_sd_hdr = lv_label_create(hdr);
  lv_label_set_text(lbl_sd_hdr, LV_SYMBOL_SD_CARD);
  lv_obj_set_style_text_color(lbl_sd_hdr, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sd_hdr, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_sd_hdr, LV_ALIGN_RIGHT_MID, -120, 0);
  if (!sd_available) lv_obj_add_flag(lbl_sd_hdr, LV_OBJ_FLAG_HIDDEN);

  lbl_hdr_wifi = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_wifi, LV_SYMBOL_WIFI);
  lv_obj_set_style_text_color(lbl_hdr_wifi, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_wifi, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_wifi, LV_ALIGN_RIGHT_MID, -100, 0);

  lbl_hdr_nfc = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_nfc, "NFC");
  lv_obj_set_style_text_color(lbl_hdr_nfc, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_nfc, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_nfc, LV_ALIGN_RIGHT_MID, -68, 0);

  lbl_hdr_scl = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_scl, "SCL");
  lv_obj_set_style_text_color(lbl_hdr_scl, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_scl, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_scl, LV_ALIGN_RIGHT_MID, -36, 0);

  // Fix 10: Spoolman reachability indicator
  lbl_hdr_sm = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_sm, "SPM");
  lv_obj_set_style_text_color(lbl_hdr_sm, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_sm, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_sm, LV_ALIGN_RIGHT_MID, -4, 0);

  // ── ZONE 2: Status bar y=26..47 (22px) ──────────────────
  // dot + status text centered | #scan_count right
  // Fix 9: status bar same color as background — no odd contrast stripe
  lv_obj_t *status_bar = lv_obj_create(lv_scr_act());
  lv_obj_set_size(status_bar, 480, 22);
  lv_obj_set_pos(status_bar, 0, 26);
  lv_obj_set_style_bg_color(status_bar, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(status_bar, 0, 0);
  lv_obj_set_style_radius(status_bar, 0, 0);
  lv_obj_set_style_pad_all(status_bar, 0, 0);
  lv_obj_clear_flag(status_bar, LV_OBJ_FLAG_SCROLLABLE);

  lbl_nfc_dot = lv_label_create(status_bar);
  lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_nfc_dot, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(lbl_nfc_dot, LV_ALIGN_LEFT_MID, 6, 0);

  lbl_status = lv_label_create(status_bar);
  lv_label_set_text(lbl_status, T(STR_BOOTING));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x5090e0), 0);
  lv_obj_set_style_text_font(lbl_status, &lv_font_montserrat_ext_14, 0);
  lv_obj_align(lbl_status, LV_ALIGN_LEFT_MID, 22, 0);

  // Scan counter: right side of status bar
  lbl_hdr_scans = lv_label_create(status_bar);
  lv_label_set_text(lbl_hdr_scans, "#0");
  lv_obj_set_style_text_color(lbl_hdr_scans, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hdr_scans, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_hdr_scans, LV_ALIGN_RIGHT_MID, -6, 0);

  lbl_scan_count = lbl_hdr_scans;

  // Thin separator line
  lv_obj_t *sep1 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(sep1, 480, 1);
  lv_obj_set_pos(sep1, 0, 48);
  lv_obj_set_style_bg_color(sep1, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(sep1, 0, 0);
  lv_obj_set_style_radius(sep1, 0, 0);
  lv_obj_set_style_pad_all(sep1, 0, 0);

  // ── ZONE 3: Spool Info y=49..184 (136px) full width ─────
  // Row A: [swatch] [#ID] [Material] [FilamentName]
  // Row B: Vendor / Temp + More info btn top-right
  // separator
  // Row C: Last used / Last dried

  // Swatch (42x42, y=63)
  lbl_color_swatch = lv_obj_create(lv_scr_act());
  lv_obj_set_size(lbl_color_swatch, 42, 42);
  lv_obj_set_pos(lbl_color_swatch, 8, 54);
  lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(0x333333), 0);
  lv_obj_set_style_radius(lbl_color_swatch, 6, 0);
  lv_obj_set_style_border_color(lbl_color_swatch, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_border_width(lbl_color_swatch, 1, 0);
  lv_obj_set_style_pad_all(lbl_color_swatch, 0, 0);
  lv_obj_clear_flag(lbl_color_swatch, LV_OBJ_FLAG_SCROLLABLE);

  // Cap: ID (x=58, y=51)
  lv_obj_t *lbl_id_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_id_cap, "ID");
  lv_obj_set_style_text_color(lbl_id_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_id_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_id_cap, 58, 51);

  // SM-ID value (x=58, y=65)
  lbl_spoolman_id = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_id, "?");
  lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spoolman_id, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_spoolman_id, 58, 65);

  // Cap: Material (x=92, y=51)
  lv_obj_t *lbl_mat_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_mat_cap, "Material");
  lv_obj_set_style_text_color(lbl_mat_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_mat_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_mat_cap, 92, 51);

  // Material value (x=92, y=65)
  lbl_material = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_material, "-");
  lv_obj_set_style_text_color(lbl_material, lv_color_hex(0xf0f0f0), 0);
  lv_obj_set_style_text_font(lbl_material, &lv_font_montserrat_ext_20, 0);
  lv_obj_set_pos(lbl_material, 92, 63);
  lv_label_set_long_mode(lbl_material, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_material, 160);

  // Cap: Filament (x=260, y=51)
  lv_obj_t *lbl_fil_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_fil_cap, "Filament");
  lv_obj_set_style_text_color(lbl_fil_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_fil_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_fil_cap, 232, 51);  // Fix 5: slightly left

  // Filament Name value (x=260, y=65)
  lbl_filament_name = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_filament_name, "-");
  lv_obj_set_style_text_color(lbl_filament_name, lv_color_hex(0xf0f0f0), 0);  // Fix 8: same as material
  lv_obj_set_style_text_font(lbl_filament_name, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_filament_name, 232, 66);  // Fix 5: slightly left
  lv_label_set_long_mode(lbl_filament_name, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_filament_name, 212);

  // Hex color: hidden dummy (only shown in More Info screen)
  lbl_color = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_color, "");
  lv_obj_add_flag(lbl_color, LV_OBJ_FLAG_HIDDEN);

  // Row B: Vendor (x=8, y=98) | Temp (x=210, y=98) | More info btn TOP RIGHT bigger
  lv_obj_t *lbl_vendor_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_vendor_cap, T(STR_LBL_VENDOR));
  lv_obj_set_style_text_color(lbl_vendor_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_vendor_cap, &lv_font_montserrat_ext_14, 0);  // Fix 5: +1 size
  lv_obj_set_pos(lbl_vendor_cap, 8, 98);

  lbl_vendor = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_vendor, "-");
  lv_obj_set_style_text_color(lbl_vendor, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_vendor, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_vendor, 8, 115);  // Fix 5: +2px gap
  lv_label_set_long_mode(lbl_vendor, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_vendor, 190);

  lv_obj_t *lbl_temp_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_temp_cap, T(STR_LBL_TEMP));
  lv_obj_set_style_text_color(lbl_temp_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_temp_cap, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_temp_cap, 248, 98);  // Fix 5: more right

  lbl_temp = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_temp, "-");
  lv_obj_set_style_text_color(lbl_temp, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_temp, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_temp, 248, 115);  // Fix 5: more right

  // "More info" button — Fix 4: more prominent, teal border
  lv_obj_t *btn_more = lv_btn_create(lv_scr_act());
  lv_obj_set_size(btn_more, 84, 34);
  lv_obj_set_pos(btn_more, 388, 100);
  lv_obj_set_style_bg_color(btn_more, lv_color_hex(0x0d1f38), 0);
  lv_obj_set_style_bg_color(btn_more, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_more, 1, 0);
  lv_obj_set_style_border_color(btn_more, lv_color_hex(0x28d49a), 0);  // teal border
  lv_obj_set_style_radius(btn_more, 6, 0);
  lv_obj_set_style_shadow_width(btn_more, 0, 0);
  lv_obj_add_event_cb(btn_more, [](lv_event_t *e){ logSD("BTN: Main -> MoreInfo"); showMoreInfoScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_more = lv_label_create(btn_more);
  lv_label_set_text(lbl_more, g_lang == LANG_DE ? "Mehr Info" : "More info");
  lv_obj_set_style_text_color(lbl_more, lv_color_hex(0x28d49a), 0);  // teal text
  lv_obj_set_style_text_font(lbl_more, &lv_font_montserrat_ext_12, 0);
  lv_obj_center(lbl_more);

  // Inner separator y=136 — Fix 2: slightly lower to give More info btn breathing room
  lv_obj_t *sep_inner = lv_obj_create(lv_scr_act());
  lv_obj_set_size(sep_inner, 464, 1);
  lv_obj_set_pos(sep_inner, 8, 138);
  lv_obj_set_style_bg_color(sep_inner, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(sep_inner, 0, 0);
  lv_obj_set_style_radius(sep_inner, 0, 0);
  lv_obj_set_style_pad_all(sep_inner, 0, 0);

  // Row C: Last used / Last dried — Fix 3: date values lower (y=158 instead of y=152)
  lbl_lu_cap = lv_label_create(lv_scr_act());
  // Cap text depends on last_used_mode
  char lu_cap_buf[32];
  if (last_used_mode == 1)
    strncpy(lu_cap_buf, g_lang == LANG_DE ? "Zuletzt gewogen:" : "Last weighed:", sizeof(lu_cap_buf)-1);
  else {
    strncpy(lu_cap_buf, T(STR_LBL_LAST_USED), sizeof(lu_cap_buf)-1);
  }
  lu_cap_buf[sizeof(lu_cap_buf)-1] = 0;
  lv_label_set_text(lbl_lu_cap, lu_cap_buf);
  lv_obj_set_style_text_color(lbl_lu_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_lu_cap, &lv_font_montserrat_ext_14, 0);  // Fix 5
  lv_obj_set_pos(lbl_lu_cap, 8, 142);

  lbl_last_used = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_last_used, "-");
  lv_obj_set_style_text_color(lbl_last_used, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_last_used, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_last_used, 8, 158);  // Fix 3: more gap
  lv_label_set_long_mode(lbl_last_used, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_last_used, 228);

  lv_obj_t *lbl_ld_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_ld_cap, T(STR_LBL_LAST_DRIED));
  lv_obj_set_style_text_color(lbl_ld_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_ld_cap, &lv_font_montserrat_ext_14, 0);  // Fix 5
  lv_obj_set_pos(lbl_ld_cap, 244, 142);

  lbl_spoolman_dried_val = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_dried_val, "-");
  lv_obj_set_style_text_color(lbl_spoolman_dried_val, lv_color_hex(0x5090e0), 0);
  lv_obj_set_style_text_font(lbl_spoolman_dried_val, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_spoolman_dried_val, 244, 158);  // Fix 3
  lv_label_set_long_mode(lbl_spoolman_dried_val, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_spoolman_dried_val, 210);
  lbl_spoolman_dried = lbl_spoolman_dried_val;
  // Ampel-Symbol (WARNING) rechts vom Datum, standardmaessig versteckt
  lbl_dried_sym = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_dried_sym, LV_SYMBOL_WARNING);
  lv_obj_set_style_text_color(lbl_dried_sym, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_dried_sym, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_dried_sym, 456, 158);
  lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);

  // Unused labels still needed by updateDisplay / querySpoolman
  // lbl_uid, lbl_tray_uuid, lbl_detail, lbl_date — hidden dummy labels
  lbl_uid = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_uid, "");
  lv_obj_add_flag(lbl_uid, LV_OBJ_FLAG_HIDDEN);

  lbl_tray_uuid = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_tray_uuid, "");
  lv_obj_add_flag(lbl_tray_uuid, LV_OBJ_FLAG_HIDDEN);

  lbl_detail = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_detail, "");
  lv_obj_add_flag(lbl_detail, LV_OBJ_FLAG_HIDDEN);

  lbl_date = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_date, "");
  lv_obj_add_flag(lbl_date, LV_OBJ_FLAG_HIDDEN);

  // Separator zone 3/4
  lv_obj_t *sep2 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(sep2, 480, 1);
  lv_obj_set_pos(sep2, 0, 184);
  lv_obj_set_style_bg_color(sep2, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(sep2, 0, 0);
  lv_obj_set_style_radius(sep2, 0, 0);
  lv_obj_set_style_pad_all(sep2, 0, 0);

  // ── ZONE 4: Weights y=185..263 (79px) ───────────────────
  // Left  (x=0..209):  Spoolman filament remaining (big) + % + bar
  // Right (x=210..424): Scale filament netto (big) + SM diff | live total | live -bag
  // Far right (x=425..479): TARE

  // Spoolman section — caption
  lv_obj_t *lbl_sm_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_sm_cap, T(STR_LBL_SPOOLMAN));
  lv_obj_set_style_text_color(lbl_sm_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sm_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_sm_cap, 8, 188);

  // Spoolman filament remaining — BIG
  lbl_spoolman_weight = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_weight, wifi_ok ? "..." : T(STR_NO_WIFI));
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spoolman_weight, &lv_font_montserrat_ext_20, 0);
  lv_obj_set_pos(lbl_spoolman_weight, 8, 204);

  // Percent — Fix 3: right of weight, same row
  lbl_spoolman_pct = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_obj_set_style_text_color(lbl_spoolman_pct, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spoolman_pct, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_spoolman_pct, 88, 208);  // right of weight, vertically centered

  // Progress bar — Fix 3: higher (y=230) and thicker (6px)
  lv_obj_t *bar_bg = lv_obj_create(lv_scr_act());
  lv_obj_set_size(bar_bg, 190, 8);
  lv_obj_set_pos(bar_bg, 8, 244);
  lv_obj_set_style_bg_color(bar_bg, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_border_width(bar_bg, 0, 0);
  lv_obj_set_style_radius(bar_bg, 4, 0);
  lv_obj_set_style_pad_all(bar_bg, 0, 0);
  lv_obj_clear_flag(bar_bg, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *bar_fill = lv_obj_create(bar_bg);
  lv_obj_set_size(bar_fill, 0, 8);
  lv_obj_set_pos(bar_fill, 0, 0);
  lv_obj_set_style_bg_color(bar_fill, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(bar_fill, 0, 0);
  lv_obj_set_style_radius(bar_fill, 4, 0);
  lv_obj_set_style_pad_all(bar_fill, 0, 0);
  lv_obj_clear_flag(bar_fill, LV_OBJ_FLAG_SCROLLABLE);
  lbl_scale_diff = (lv_obj_t*)bar_fill;

  // Vertical divider left/mid
  lv_obj_t *vdiv1 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(vdiv1, 1, 76);
  lv_obj_set_pos(vdiv1, 210, 186);
  lv_obj_set_style_bg_color(vdiv1, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(vdiv1, 0, 0);
  lv_obj_set_style_radius(vdiv1, 0, 0);
  lv_obj_set_style_pad_all(vdiv1, 0, 0);

  // Scale filament netto caption — Fix 3: "Waage - Spule" / "Scale - Spool"
  lv_obj_t *lbl_sc_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_sc_cap, g_lang == LANG_DE ? "Waage - Spule" : "Scale - Spool");
  lv_obj_set_style_text_color(lbl_sc_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sc_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_sc_cap, 218, 188);

  // Scale filament netto — BIG
  lbl_scale_weight = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_scale_weight, scale_ready ? "0 g" : "---");
  lv_obj_set_style_text_color(lbl_scale_weight, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_scale_weight, &lv_font_montserrat_ext_20, 0);
  lv_obj_set_pos(lbl_scale_weight, 218, 204);

  // SM diff caption + value — both diffs stacked on right side (Fix 3)
  lv_obj_t *lbl_diff_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_diff_cap, "Diff:");
  lv_obj_set_style_text_color(lbl_diff_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_diff_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_diff_cap, 362, 188);

  lbl_raw_info = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_raw_info, "");
  lv_obj_set_style_text_color(lbl_raw_info, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_raw_info, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_raw_info, 362, 204);  // Fix 3: right column

  // Fix 1: "Gesamt" / "Total" — Fix 4: value x same as o.Beutel value
  lv_obj_t *lbl_live_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_live_cap, g_lang == LANG_DE ? "Gesamt:" : "Total:");
  lv_obj_set_style_text_color(lbl_live_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_live_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_live_cap, 218, 228);

  lbl_spoolman_dried = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_dried, "");
  lv_obj_set_style_text_color(lbl_spoolman_dried, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_spoolman_dried, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_spoolman_dried, 286, 226);  // Fix 4: same x as o.Beutel value

  // Fix 2: "o. Beutel" / "w/o Bag"
  lv_obj_t *lbl_bag_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_bag_cap, g_lang == LANG_DE ? "o. Beutel:" : "w/o Bag:");
  lv_obj_set_style_text_color(lbl_bag_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_bag_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(lbl_bag_cap, 218, 246);

  lv_obj_t *lbl_bag_diff = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_bag_diff, "");
  lv_obj_set_style_text_color(lbl_bag_diff, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_bag_diff, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(lbl_bag_diff, 286, 244);
  lbl_keys = lbl_bag_diff;

  // Fix 3+4: bag SM diff — stacked below Waage-Spule diff, with "g"
  lbl_bag_sm_diff = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_bag_sm_diff, "");
  lv_obj_set_style_text_color(lbl_bag_sm_diff, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_bag_sm_diff, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_bag_sm_diff, 362, 244);  // same x as Waage-Spule diff, below

  // Vertical divider zone 4 mid/right — Fix 7: moved left for TARE breathing room
  lv_obj_t *vdiv2 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(vdiv2, 0, 0);
  lv_obj_set_pos(vdiv2, 418, 186);
  lv_obj_set_style_bg_color(vdiv2, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(vdiv2, 0, 0);
  lv_obj_set_style_radius(vdiv2, 0, 0);
  lv_obj_set_style_pad_all(vdiv2, 0, 0);

  // TARE button — Fix 1: 50px width (same as menu btn), divider gives left breathing room
  lv_obj_t *btn_tare = lv_btn_create(lv_scr_act());
  lv_obj_set_size(btn_tare, 54, 70);
  lv_obj_set_pos(btn_tare, 422, 188);
  lv_obj_set_style_bg_color(btn_tare, lv_color_hex(0x2a2010), 0);
  lv_obj_set_style_bg_color(btn_tare, lv_color_hex(0x4a4020), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_tare, 1, 0);
  lv_obj_set_style_border_color(btn_tare, lv_color_hex(0x3a3010), 0);
  lv_obj_set_style_radius(btn_tare, 8, 0);
  lv_obj_set_style_shadow_width(btn_tare, 0, 0);
  lv_obj_add_event_cb(btn_tare, [](lv_event_t *e) {
    logSD("UI: Button -> TARE (main)");
    if (scale_ready) {
      int32_t raw = scaleHardwareReadRaw();
      saveTareOffset(raw);
      scale_weight_g = 0.0f;
      memset(scale_filter_buf, 0, sizeof(scale_filter_buf));
      scale_filter_idx = 0; scale_filter_full = false;
      lv_label_set_text(lbl_scale_weight, "0 g");
      Serial.println("TARE (main)");
      logSDf("TARE applied (raw=%d)", raw);
    } else {
      logSD("TARE: scale not ready");
    }
  }, LV_EVENT_CLICKED, NULL);
  // Icon top, text bottom — both centered
  lv_obj_t *lbl_tare_icon = lv_label_create(btn_tare);
  lv_label_set_text(lbl_tare_icon, LV_SYMBOL_REFRESH);
  lv_obj_set_style_text_color(lbl_tare_icon, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_tare_icon, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_tare_icon, LV_ALIGN_CENTER, 0, -10);
  lv_obj_t *lbl_tare_txt = lv_label_create(btn_tare);
  lv_label_set_text(lbl_tare_txt, "TARE");
  lv_obj_set_style_text_color(lbl_tare_txt, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_tare_txt, &lv_font_montserrat_ext_10, 0);
  lv_obj_align(lbl_tare_txt, LV_ALIGN_CENTER, 0, 12);

  // Separator zone 4/5
  lv_obj_t *sep3 = lv_obj_create(lv_scr_act());
  lv_obj_set_size(sep3, 480, 1);
  lv_obj_set_pos(sep3, 0, 264);
  lv_obj_set_style_bg_color(sep3, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(sep3, 0, 0);
  lv_obj_set_style_radius(sep3, 0, 0);
  lv_obj_set_style_pad_all(sep3, 0, 0);

  // ── ZONE 5: Button bar y=265..319 (55px) ────────────────
  // [Update Weight flex:1] [Dried today flex:1] [Settings 44px]
  // When no link: both replaced by [Link spool flex:1] [Settings 44px]
  lv_obj_t *btn_bar = lv_obj_create(lv_scr_act());
  lv_obj_set_size(btn_bar, 480, 55);
  lv_obj_set_pos(btn_bar, 0, 265);
  lv_obj_set_style_bg_color(btn_bar, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(btn_bar, 0, 0);
  lv_obj_set_style_radius(btn_bar, 0, 0);
  lv_obj_set_style_pad_all(btn_bar, 0, 0);
  lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);

  // "Update Weight" button (x=6, w=204)
  btn_weight_main = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_weight_main, 204, 40);
  lv_obj_set_pos(btn_weight_main, 6, 8);
  lv_obj_set_style_bg_color(btn_weight_main, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_weight_main, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_weight_main, 1, 0);
  lv_obj_set_style_border_color(btn_weight_main, lv_color_hex(0x2a5030), 0);
  lv_obj_set_style_radius(btn_weight_main, 8, 0);
  lv_obj_set_style_shadow_width(btn_weight_main, 0, 0);
  lv_obj_add_event_cb(btn_weight_main, [](lv_event_t *e) {
    logSD("UI: Button -> Update Weight");
    showConfirmPopup(T(STR_POPUP_WEIGHT_Q), 2);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_wm = lv_label_create(btn_weight_main);
  lbl_weight_main_lbl = lbl_wm;
  {
    char wmbuf[48];
    if (g_auto_weight)
      snprintf(wmbuf, sizeof(wmbuf), "%s (A)", g_lang == LANG_DE ? "Gewicht updaten" : "Update Weight");
    else {
      strncpy(wmbuf, T(STR_BTN_WEIGHT), sizeof(wmbuf)-1);
      wmbuf[sizeof(wmbuf)-1] = '\0';
    }
    lv_label_set_text(lbl_wm, wmbuf);
  }
  lv_obj_set_style_text_color(lbl_wm, g_auto_weight ? lv_color_hex(0x28d49a) : lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_wm, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_wm, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_wm, LV_ALIGN_CENTER, 0, 0);

  // "Dried today" button (x=216, w=204)
  btn_dried = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_dried, 204, 40);
  lv_obj_set_pos(btn_dried, 216, 8);
  lv_obj_set_style_bg_color(btn_dried, lv_color_hex(0x0a2040), 0);
  lv_obj_set_style_bg_color(btn_dried, lv_color_hex(0x1a4080), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_dried, 1, 0);
  lv_obj_set_style_border_color(btn_dried, lv_color_hex(0x1a4080), 0);
  lv_obj_set_style_radius(btn_dried, 8, 0);
  lv_obj_set_style_shadow_width(btn_dried, 0, 0);
  lv_obj_add_event_cb(btn_dried, [](lv_event_t *e) {
    logSD("UI: Button -> Dried (popup)");
    if (!sm_found || sm_id == 0) { btn_dried_cb(nullptr); return; }
    showConfirmPopup(T(STR_POPUP_DRIED_Q), 1);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_dr = lv_label_create(btn_dried);
  lv_label_set_text(lbl_dr, T(STR_BTN_DRIED));
  lv_obj_set_style_text_color(lbl_dr, lv_color_hex(0x5090e0), 0);
  lv_obj_set_style_text_font(lbl_dr, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_dr, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_dr, LV_ALIGN_CENTER, 0, 0);

  // "Link spool" button — same slot, initially hidden
  // Link button — 204px, olive-green, matches Update Weight style
  // ID= >100 spools recommended | List= <100 spools recommended
  btn_link = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_link, 204, 40);
  lv_obj_set_pos(btn_link, 6, 8);
  lv_obj_set_style_bg_color(btn_link, lv_color_hex(0x1e3000), 0);
  lv_obj_set_style_bg_color(btn_link, lv_color_hex(0x2e5000), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_link, 1, 0);
  lv_obj_set_style_border_color(btn_link, lv_color_hex(0x4a7800), 0);
  lv_obj_set_style_radius(btn_link, 8, 0);
  lv_obj_set_style_shadow_width(btn_link, 0, 0);
  lv_obj_add_flag(btn_link, LV_OBJ_FLAG_HIDDEN);
  lv_obj_add_event_cb(btn_link, [](lv_event_t *e) {
    logSD("UI: Button -> Link Spool");
    link_popup_dismissed = false;
    showLinkEntryPopup(strlen(g_tag.tray_uuid) == 32);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_lk = lv_label_create(btn_link);
  char lbl_lk_buf[32]; strncpy(lbl_lk_buf, T(STR_BTN_LINK), sizeof(lbl_lk_buf)-1);
  lv_label_set_text(lbl_lk, lbl_lk_buf);
  lv_obj_set_style_text_color(lbl_lk, lv_color_hex(0xb8e030), 0);
  lv_obj_set_style_text_font(lbl_lk, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_lk, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_lk, LV_ALIGN_CENTER, 0, 0);

  // Copy spool button — 204px, teal, matches Dried Today style
  // ID= >100 spools recommended | List= <100 spools recommended
  btn_copy = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_copy, 204, 40);
  lv_obj_set_pos(btn_copy, 216, 8);
  lv_obj_set_style_bg_color(btn_copy, lv_color_hex(0x00222a), 0);
  lv_obj_set_style_bg_color(btn_copy, lv_color_hex(0x003a48), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_copy, 1, 0);
  lv_obj_set_style_border_color(btn_copy, lv_color_hex(0x00b8d4), 0);
  lv_obj_set_style_radius(btn_copy, 8, 0);
  lv_obj_set_style_shadow_width(btn_copy, 0, 0);
  lv_obj_add_flag(btn_copy, LV_OBJ_FLAG_HIDDEN);
  lv_obj_add_event_cb(btn_copy, [](lv_event_t *e) {
    logSD("UI: Button -> Copy Spool");
    showCopyEntryPopup();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cp = lv_label_create(btn_copy);
  char lbl_cp_buf[32]; strncpy(lbl_cp_buf, T(STR_BTN_COPY_SPOOL), sizeof(lbl_cp_buf)-1);
  lv_label_set_text(lbl_cp, lbl_cp_buf);
  lv_obj_set_style_text_color(lbl_cp, lv_color_hex(0x20d8f8), 0);
  lv_obj_set_style_text_font(lbl_cp, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_cp, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_cp, LV_ALIGN_CENTER, 0, 0);

  // Settings/Burger button (x=426, w=48)
  lv_obj_t *btn_menu = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_menu, 44, 40);
  lv_obj_set_pos(btn_menu, 429, 8);
  lv_obj_set_style_bg_color(btn_menu, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_menu, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_menu, 1, 0);
  lv_obj_set_style_border_color(btn_menu, lv_color_hex(0x1a2840), 0);
  lv_obj_set_style_radius(btn_menu, 8, 0);
  lv_obj_set_style_shadow_width(btn_menu, 0, 0);
  lv_obj_add_event_cb(btn_menu, [](lv_event_t *e){ logSD("UI: Button -> Burger Menu"); showSettingsScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_menu = lv_label_create(btn_menu);
  lv_label_set_text(lbl_menu, LV_SYMBOL_LIST);
  lv_obj_set_style_text_color(lbl_menu, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_menu, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_menu);

  // Red circle badge on burger button — iOS-style notification dot, shown when update available
  // Position: on the top-right border radius of btn_menu (x=429,y=273 absolute → dot center x=464, y=266)
  lbl_burger_badge = lv_obj_create(lv_scr_act());
  lv_obj_set_size(lbl_burger_badge, 14, 14);
  lv_obj_set_pos(lbl_burger_badge, 457, 263);
  lv_obj_set_style_radius(lbl_burger_badge, 7, 0);
  lv_obj_set_style_bg_color(lbl_burger_badge, lv_color_hex(0xe03030), 0);
  lv_obj_set_style_border_color(lbl_burger_badge, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(lbl_burger_badge, 2, 0);
  lv_obj_set_style_pad_all(lbl_burger_badge, 0, 0);
  lv_obj_clear_flag(lbl_burger_badge, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(lbl_burger_badge, LV_OBJ_FLAG_HIDDEN);

  page_main = lv_scr_act();
  // lbl_raw_info points to SM diff label on main screen (see above)
}

// ============================================================
//  MAINSCREEN: UPDATE BUTTON VISIBILITY
//  btn_dried visible when spool known, btn_link when unknown + tag present
// ============================================================
void updateLinkButton() {
  if (!btn_dried || !btn_link || !btn_weight_main || !btn_copy) return;
  if (tag_present && !sm_found) {
    // Tag present but not linked: show Link + Copy, hide Weight+Dried
    lv_obj_add_flag(btn_weight_main,   LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_dried,         LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_link,        LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_copy,        LV_OBJ_FLAG_HIDDEN);
  } else {
    // No tag, or tag linked: show Weight+Dried, hide Link+Copy
    lv_obj_clear_flag(btn_weight_main, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_dried,       LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_link,          LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_copy,          LV_OBJ_FLAG_HIDDEN);
  }
}

// ============================================================
//  COPY SPOOL FLOW
//  Creates a new Spoolman spool based on an existing spool template
//  (active or archived). Uses 3 API calls: fetch list, POST spool, PATCH tag.
//  Limit: COPY_SPOOL_LIMIT spools shown (recommend <100 for stability).
// ============================================================

void closeCopyEntryPopup() {
  if (scr_copy_entry) { lv_obj_del(scr_copy_entry); scr_copy_entry = nullptr; }
}

void closeCopyIdInputPopup() {
  if (scr_copy_id) { lv_obj_del(scr_copy_id); scr_copy_id = nullptr; }
}

void closeCopyListPopup() {
  if (scr_copy_list) { lv_obj_del(scr_copy_list); scr_copy_list = nullptr; }
}

void closeCopyConfirmPopup() {
  if (scr_copy_confirm) { lv_obj_del(scr_copy_confirm); scr_copy_confirm = nullptr; }
}

// Patch newly created spool with tag UID and query it on main screen
void finishCopyFlow(int new_spool_id) {
  // Bambu tags: use tray_uuid (long UUID from NFC block 9) — same logic as doLinkPatch
  // NTAG: use link_tag_uid (short UID used as Spoolman key)
  bool is_bambu_tag = (strlen(g_tag.tray_uuid) == 32);
  const char* tag_to_write = is_bambu_tag ? g_tag.tray_uuid : link_tag_uid;
  logSDf("finishCopyFlow: spool=%d bambu=%d tag=%s", new_spool_id, (int)is_bambu_tag, tag_to_write);
  patchSpoolTag(new_spool_id, tag_to_write);
  sm_id = new_spool_id;
  sm_found = true;
  spoolman_queried_uid[0] = '\0';
  if (is_bambu_tag) {
    querySpoolman(g_tag.tray_uuid);
  } else {
    querySpoolmanById(new_spool_id);
  }
  updateLinkButton();
  showMainScreen();  // navigate to main after copy flow completes
}

// POST /api/v1/spool with template data, then PATCH tag
void doCopySpoolCreate(int template_filament_id, float template_initial, float template_spool_w) {
  if (!wifi_ok) return;
  float netto = scale_weight_g - template_spool_w;
  if (netto < 0) netto = 0;

  int new_id = 0;
  int code = spoolmanCreateSpool(cfg_spoolman_base, template_filament_id, template_initial,
    template_spool_w, netto, &new_id, 8000);
  if ((code == 200 || code == 201) && new_id > 0) {
    Serial.printf("Copy spool created: new ID=%d\n", new_id);
    logSDf("Copy spool created: filament_id=%d new_spool_id=%d", template_filament_id, new_id);
    finishCopyFlow(new_id);
    lv_label_set_text(lbl_status, T(STR_COPY_OK));
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
    return;
  }
  Serial.printf("Copy spool POST failed: HTTP %d\n", code);
  lv_label_set_text(lbl_status, T(STR_COPY_FAIL));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xff8080), 0);
}

// Confirm popup: shows template name + current scale weight, then creates
void showCopyConfirmPopup(int template_filament_id, const char* template_name,
                           float template_remaining, float template_initial, float template_spool_w) {
  closeCopyConfirmPopup();
  copy_template_filament_id = template_filament_id;
  copy_template_initial      = template_initial;
  copy_template_spool_w      = template_spool_w;
  strncpy(copy_template_name, template_name, sizeof(copy_template_name)-1);

  scr_copy_confirm = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_copy_confirm, 480, 320);
  lv_obj_set_pos(scr_copy_confirm, 0, 0);
  lv_obj_set_style_bg_color(scr_copy_confirm, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_copy_confirm, LV_OPA_70, 0);
  lv_obj_set_style_border_width(scr_copy_confirm, 0, 0);
  lv_obj_set_style_pad_all(scr_copy_confirm, 0, 0);
  lv_obj_clear_flag(scr_copy_confirm, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *box = lv_obj_create(scr_copy_confirm);
  lv_obj_set_size(box, 420, 260);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0c1828), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, 10, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Title
  lv_obj_t *lbl_title = lv_label_create(box);
  char title_buf[32]; strncpy(title_buf, T(STR_COPY_CONFIRM_TITLE), sizeof(title_buf)-1);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 14);

  // Info text
  lv_obj_t *lbl_info = lv_label_create(box);
  char info_buf[192];
  float display_netto = scale_weight_g - template_spool_w;
  if (display_netto < 0) display_netto = 0;
  snprintf(info_buf, sizeof(info_buf), T(STR_COPY_CONFIRM_MSG), template_name, template_remaining, display_netto);
  lv_label_set_text(lbl_info, info_buf);
  lv_obj_set_style_text_color(lbl_info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_info, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_info, 380);
  lv_obj_align(lbl_info, LV_ALIGN_TOP_MID, 0, 48);

  // Confirm button
  lv_obj_t *btn_ok = lv_btn_create(box);
  lv_obj_set_size(btn_ok, 180, 52);
  lv_obj_set_pos(btn_ok, 16, 192);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x1a4020), 0);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x2a7030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok, 8, 0);
  lv_obj_set_style_shadow_width(btn_ok, 0, 0);
  lv_obj_add_event_cb(btn_ok, [](lv_event_t *e) {
    int fid   = copy_template_filament_id;
    float ini = copy_template_initial;
    float spw = copy_template_spool_w;
    closeCopyConfirmPopup();
    closeCopyListPopup();
    closeCopyIdInputPopup();
    closeCopyEntryPopup();
    doCopySpoolCreate(fid, ini, spw);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok = lv_label_create(btn_ok);
  char ok_buf[32]; strncpy(ok_buf, T(STR_BTN_CONFIRMED), sizeof(ok_buf)-1);
  lv_label_set_text(lbl_ok, ok_buf);
  lv_obj_set_style_text_color(lbl_ok, lv_color_hex(0x80ffb0), 0);
  lv_obj_set_style_text_font(lbl_ok, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_ok, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_ok, LV_ALIGN_CENTER, 0, 0);

  // Cancel button
  lv_obj_t *btn_no = lv_btn_create(box);
  lv_obj_set_size(btn_no, 180, 52);
  lv_obj_set_pos(btn_no, 224, 192);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_no, 8, 0);
  lv_obj_set_style_shadow_width(btn_no, 0, 0);
  lv_obj_add_event_cb(btn_no, [](lv_event_t *e) {
    logSD("BTN: CopyConfirm -> Cancel (back to list)");
    closeCopyConfirmPopup();
    if (scr_copy_list) lv_obj_clear_flag(scr_copy_list, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_no = lv_label_create(btn_no);
  char no_buf[32]; strncpy(no_buf, T(STR_CANCEL), sizeof(no_buf)-1);
  lv_label_set_text(lbl_no, no_buf);
  lv_obj_set_style_text_color(lbl_no, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_no, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(lbl_no, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_no, LV_ALIGN_CENTER, 0, 0);
}

// Fetch spools for copy list (active or archived, material-filtered)
// Uses PSRAM allocator. Max COPY_SPOOL_LIMIT entries shown.
void fetchSpoolsForCopy(bool archived, const char* material_filter, bool is_bambu_tag) {
  // Free previous list
  if (link_spools) { free(link_spools); link_spools = nullptr; link_spool_count = 0; }

  if (!wifi_ok) return;

  SpiRamAllocator alloc;
  JsonDocument doc(&alloc);
  DeserializationError err = DeserializationError::Ok;
  int code = spoolmanGetSpoolListJson(cfg_spoolman_base, true, doc, 10000, nullptr, &err);
  if (code != 200 || err) { Serial.printf("fetchSpoolsForCopy JSON error: %s\n", err.c_str()); return; }

  JsonArray arr = doc.as<JsonArray>();
  // Count matching entries first (for allocation)
  int count = 0;
  for (JsonObject spool : arr) {
    bool is_archived = spool["archived"] | false;
    if (is_archived != archived) continue;
    // Bambu tag: only show Bambu Lab spools
    if (is_bambu_tag) {
      const char* vname = spool["filament"]["vendor"]["name"] | "";
      if (strncasecmp(vname, "Bambu", 5) != 0) continue;
    }
    const char* mat = spool["filament"]["material"] | "";
    if (material_filter && strlen(material_filter) > 0) {
      if (isSupportMaterial(material_filter)) {
        if (!isSupportSpoolmanMat(mat)) continue;
        // No color filter for support filaments
      } else {
        int flen = strlen(material_filter) < 3 ? (int)strlen(material_filter) : 3;
        if (strncasecmp(mat, material_filter, flen) != 0) continue;
        if (isSupportSpoolmanMat(mat)) continue;
        char subkw[16];
        if (extractBambuSubtype(material_filter, subkw, sizeof(subkw))) {
          const char* fname = spool["filament"]["name"] | "";
          if (!containsIgnoreCase(mat, subkw) && !containsIgnoreCase(fname, subkw)) continue;
        }
        if (g_tag.color_hex[0] == '#') {
          const char* col = spool["filament"]["color_hex"] | "";
          char col_buf[8]; snprintf(col_buf, sizeof(col_buf), "#%s", col);
          if (colorDistance(g_tag.color_hex, col_buf) > 120) continue;
        }
      }
    }
    count++;
    if (count >= spool_list_limit + 1) break;
  }

  bool limit_hit = (count > spool_list_limit);
  int alloc_count = limit_hit ? spool_list_limit : count;

  link_spools = (UnlinkedSpool*)heap_caps_malloc(alloc_count * sizeof(UnlinkedSpool), MALLOC_CAP_SPIRAM);
  if (!link_spools) link_spools = (UnlinkedSpool*)malloc(alloc_count * sizeof(UnlinkedSpool));
  if (!link_spools) { link_spool_count = 0; return; }

  int idx = 0;
  for (JsonObject spool : arr) {
    if (idx >= alloc_count) break;
    bool is_archived = spool["archived"] | false;
    if (is_archived != archived) continue;
    // Bambu tag: only show Bambu Lab spools
    if (is_bambu_tag) {
      const char* vname = spool["filament"]["vendor"]["name"] | "";
      if (strncasecmp(vname, "Bambu", 5) != 0) continue;
    }
    const char* mat = spool["filament"]["material"] | "";
    if (material_filter && strlen(material_filter) > 0) {
      if (isSupportMaterial(material_filter)) {
        if (!isSupportSpoolmanMat(mat)) continue;
        // No color filter for support filaments
      } else {
        int flen = strlen(material_filter) < 3 ? (int)strlen(material_filter) : 3;
        if (strncasecmp(mat, material_filter, flen) != 0) continue;
        if (isSupportSpoolmanMat(mat)) continue;
        char subkw[16];
        if (extractBambuSubtype(material_filter, subkw, sizeof(subkw))) {
          const char* fname2 = spool["filament"]["name"] | "";
          if (!containsIgnoreCase(mat, subkw) && !containsIgnoreCase(fname2, subkw)) continue;
        }
        if (g_tag.color_hex[0] == '#') {
          const char* col2 = spool["filament"]["color_hex"] | "";
          char col_buf2[8]; snprintf(col_buf2, sizeof(col_buf2), "#%s", col2);
          if (colorDistance(g_tag.color_hex, col_buf2) > 120) continue;
        }
      }
    }
    UnlinkedSpool& s = link_spools[idx];
    s.id = spool["id"] | 0;
    // Store filament_id in existing_tag field (reuse struct field)
    snprintf(s.existing_tag, sizeof(s.existing_tag), "%d", (int)(spool["filament"]["id"] | 0));
    strncpy(s.name,     spool["filament"]["name"]           | "", sizeof(s.name)-1);
    strncpy(s.vendor,   spool["filament"]["vendor"]["name"] | "", sizeof(s.vendor)-1);
    strncpy(s.material, mat,                                      sizeof(s.material)-1);
    const char* col = spool["filament"]["color_hex"] | "333333";
    snprintf(s.color_hex, sizeof(s.color_hex), "#%s", col);
    s.total     = spool["filament"]["weight"]  | 1000.0f;
    s.remaining = spool["remaining_weight"]    | 0.0f;
    // Store spool_weight in remaining temporarily (we need it for the copy POST)
    // Use a global for spool_weight — stored in existing_tag we repurpose below
    // Actually store as: existing_tag = "filament_id:spool_weight_int"
    float spw = spool["spool_weight"] | 0.0f;
    snprintf(s.existing_tag, sizeof(s.existing_tag), "%d:%.0f", (int)(spool["filament"]["id"] | 0), spw);
    s.filament_id  = spool["filament"]["id"] | 0;
    s.spool_weight = spw;
    idx++;
  }
  link_spool_count = idx;

  if (limit_hit) {
    Serial.printf("fetchSpoolsForCopy: limit hit (%d), showing %d\n", count, spool_list_limit);
  }
  if (link_spool_count > 0) logSDf("[verbose] fetchSpoolsForCopy[0]: spool_id=%d fid=%d spw=%.0f",
    link_spools[0].id, link_spools[0].filament_id, link_spools[0].spool_weight);
  Serial.printf("fetchSpoolsForCopy: %d spools loaded (archived=%d mat=%s)\n",
    link_spool_count, (int)archived, material_filter ? material_filter : "");
}

// Spool list for copy flow — identical layout to FilteredSpoolList
void showCopySpoolList() {
  logSDf("SHOW: CopySpoolList archived=%d count=%d", (int)copy_flow_archived, link_spool_count);
  closeCopyListPopup();

  scr_copy_list = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_copy_list, 480, 320);
  lv_obj_set_pos(scr_copy_list, 0, 0);
  lv_obj_set_style_bg_color(scr_copy_list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr_copy_list, 0, 0);
  lv_obj_set_style_pad_all(scr_copy_list, 0, 0);
  lv_obj_set_style_radius(scr_copy_list, 0, 0);
  lv_obj_clear_flag(scr_copy_list, LV_OBJ_FLAG_SCROLLABLE);

  // Header: 52px, Back left, Cancel/X right, title center
  char title_buf[48];
  char title_str[32]; strncpy(title_str, T(STR_COPY_TITLE), sizeof(title_str)-1);
  snprintf(title_buf, sizeof(title_buf), "%s - %d", title_str, link_spool_count);

  lv_obj_t *hdr = lv_obj_create(scr_copy_list);
  lv_obj_set_size(hdr, 480, 52);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(hdr);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *btn_hdr_back = lv_btn_create(hdr);
  lv_obj_set_size(btn_hdr_back, 44, 44);
  lv_obj_set_pos(btn_hdr_back, 4, 4);
  lv_obj_set_style_bg_color(btn_hdr_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_hdr_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_hdr_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_hdr_back, 0, 0);
  lv_obj_set_style_border_width(btn_hdr_back, 0, 0);
  lv_obj_add_event_cb(btn_hdr_back, [](lv_event_t *e) {
    logSD("BTN: CopyList -> Back");
    closeCopyListPopup();
    if (scr_copy_entry) lv_obj_clear_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_hdr_back);
    lv_label_set_text(l, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(l, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(l); }

  lv_obj_t *btn_hdr_cancel = lv_btn_create(hdr);
  lv_obj_set_size(btn_hdr_cancel, 44, 44);
  lv_obj_align(btn_hdr_cancel, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_hdr_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_hdr_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_hdr_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_hdr_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_hdr_cancel, 0, 0);
  lv_obj_add_event_cb(btn_hdr_cancel, [](lv_event_t *e) {
    logSD("BTN: CopyList -> Cancel");
    closeCopyListPopup();
    closeCopyEntryPopup();
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn_hdr_cancel);
    lv_label_set_text(l, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_18, 0);
    lv_obj_center(l); }

  // Separator
  lv_obj_t *div = lv_obj_create(scr_copy_list);
  lv_obj_set_size(div, 480, 1); lv_obj_set_pos(div, 0, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  if (link_spool_count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_copy_list);
    char empty_buf[48]; strncpy(empty_buf, T(STR_COPY_NO_SPOOLS), sizeof(empty_buf)-1);
    lv_label_set_text(lbl_empty, empty_buf);
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, 0);
    return;
  }

  lv_obj_t *list = lv_obj_create(scr_copy_list);
  lv_obj_set_size(list, 460, 264);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  int copy_display_count = (link_spool_count > spool_list_limit) ? spool_list_limit : link_spool_count;
  if (link_spool_count > spool_list_limit) {
    logSDf("CopySpoolList: limit %d applied, showing %d of %d", spool_list_limit, copy_display_count, link_spool_count);
  }
  for (int i = 0; i < copy_display_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    lv_obj_t *row = lv_btn_create(list);
    lv_obj_set_size(row, 452, 56);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    lv_obj_t *lbl_id = lv_label_create(row);
    char id_buf[10]; snprintf(id_buf, sizeof(id_buf), "%d", s.id);
    lv_label_set_text(lbl_id, id_buf);
    lv_obj_set_style_text_color(lbl_id, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_id, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_id, LV_ALIGN_TOP_LEFT, 6, 5);

    lv_obj_t *lbl_name = lv_label_create(row);
    char full_name[64];
    if (s.material[0]) {
      bool nm = (s.name[0] && strncasecmp(s.name, s.material, strlen(s.material)) == 0);
      if (nm) strncpy(full_name, s.name, sizeof(full_name)-1);
      else snprintf(full_name, sizeof(full_name), "%s %s", s.material, s.name);
    } else {
      strncpy(full_name, s.name, sizeof(full_name)-1);
    }
    full_name[sizeof(full_name)-1] = '\0';
    lv_label_set_text(lbl_name, full_name);
    lv_obj_set_style_text_color(lbl_name, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl_name, &lv_font_montserrat_ext_16, 0);
    lv_obj_align(lbl_name, LV_ALIGN_TOP_LEFT, 50, 5);
    lv_label_set_long_mode(lbl_name, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_name, 396);

    lv_obj_t *swatch = lv_obj_create(row);
    lv_obj_set_size(swatch, 14, 14);
    lv_obj_align(swatch, LV_ALIGN_BOTTOM_LEFT, 6, -6);
    lv_obj_set_style_radius(swatch, 3, 0);
    lv_obj_set_style_border_width(swatch, 1, 0);
    lv_obj_set_style_border_color(swatch, lv_color_hex(0x2a4060), 0);
    lv_obj_set_style_pad_all(swatch, 0, 0);
    lv_obj_clear_flag(swatch, LV_OBJ_FLAG_SCROLLABLE);
    uint32_t swatch_col = 0x333333;
    if (s.color_hex[0] == '#' && strlen(s.color_hex) >= 7) {
      unsigned int r, g, b;
      sscanf(s.color_hex + 1, "%02X%02X%02X", &r, &g, &b);
      swatch_col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
    }
    lv_obj_set_style_bg_color(swatch, lv_color_hex(swatch_col), 0);

    lv_obj_t *lbl_rest = lv_label_create(row);
    char rest_buf[24];
    if (s.remaining <= 0 && s.total > 0) snprintf(rest_buf, sizeof(rest_buf), "%.0fg neu", s.total);
    else snprintf(rest_buf, sizeof(rest_buf), "%.0fg", s.remaining);
    lv_label_set_text(lbl_rest, rest_buf);
    lv_obj_set_style_text_color(lbl_rest, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_rest, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(lbl_rest, LV_ALIGN_BOTTOM_LEFT, 26, -5);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      lv_obj_t *btn = lv_event_get_target(e);
      lv_obj_t *par = lv_obj_get_parent(btn);
      int idx = 0;
      uint32_t child_cnt = lv_obj_get_child_cnt(par);
      for (uint32_t c = 0; c < child_cnt; c++) {
        if (lv_obj_get_child(par, c) == btn) { idx = (int)c; break; }
      }
      if (idx >= link_spool_count) return;
      UnlinkedSpool &sel = link_spools[idx];
      int fid = sel.filament_id;
      float spw = sel.spool_weight;
      char tmpl_name[80];
      snprintf(tmpl_name, sizeof(tmpl_name), "%s %s (%s)", sel.material, sel.name, sel.vendor);
      logSDf("BTN: CopyList row -> spool id=%d fid=%d", sel.id, fid);
      // Flag pattern: do not build new LVGL objects inside a list row callback
      copy_confirm_pending = true;
      copy_confirm_fid = fid;
      copy_confirm_remaining = sel.remaining;
      copy_confirm_initial = sel.total;
      copy_confirm_spool_w = spw;
      strncpy(copy_confirm_name, tmpl_name, sizeof(copy_confirm_name)-1);
    }, LV_EVENT_CLICKED, NULL);
  }
  if (link_spool_count > spool_list_limit) {
    addListMoreInfo(list, STR_LIST_MORE_SPOOLS);
  }
}

// ID input popup for copy flow — reuses same numpad style as link ID input
void showCopyIdInputPopup() {
  logSD("SHOW: CopyIdInputPopup");
  closeCopyIdInputPopup();
  copy_id_input[0] = '\0';

  scr_copy_id = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_copy_id, 480, 320);
  lv_obj_set_pos(scr_copy_id, 0, 0);
  lv_obj_set_style_bg_color(scr_copy_id, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr_copy_id, 0, 0);
  lv_obj_set_style_pad_all(scr_copy_id, 0, 0);
  lv_obj_set_style_radius(scr_copy_id, 0, 0);
  lv_obj_clear_flag(scr_copy_id, LV_OBJ_FLAG_SCROLLABLE);

  addBackButton(scr_copy_id, [](lv_event_t *e) { closeCopyIdInputPopup(); });

  lv_obj_t *lbl_title = lv_label_create(scr_copy_id);
  char title_buf[32]; strncpy(title_buf, T(STR_COPY_ID_BTN), sizeof(title_buf)-1);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 8);

  // Digit display
  lbl_copy_id_display = lv_label_create(scr_copy_id);
  lv_label_set_text(lbl_copy_id_display, "_");
  lv_obj_set_style_text_color(lbl_copy_id_display, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_copy_id_display, &lv_font_montserrat_ext_24, 0);
  lv_obj_align(lbl_copy_id_display, LV_ALIGN_TOP_MID, 0, 36);

  // Status label
  lbl_copy_id_status = lv_label_create(scr_copy_id);
  lv_label_set_text(lbl_copy_id_status, "");
  lv_obj_set_style_text_color(lbl_copy_id_status, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_copy_id_status, &lv_font_montserrat_ext_12, 0);
  lv_obj_align(lbl_copy_id_status, LV_ALIGN_TOP_MID, 0, 66);

  // Numpad: same style as link ID input (104x30, gap 4)
  const int NP_W = 104, NP_H = 30, NP_GAP = 4;
  const int NP_X0 = (480 - 3*(NP_W+NP_GAP)+NP_GAP) / 2;
  const int NP_Y0 = 84;
  const char* keys[] = {"1","2","3","4","5","6","7","8","9","<","0","OK"};
  for (int k = 0; k < 12; k++) {
    int row = k / 3, col = k % 3;
    lv_obj_t *btn = lv_btn_create(scr_copy_id);
    lv_obj_set_size(btn, NP_W, NP_H);
    lv_obj_set_pos(btn, NP_X0 + col*(NP_W+NP_GAP), NP_Y0 + row*(NP_H+NP_GAP));
    bool is_ok  = (k == 11);
    bool is_del = (k == 9);
    lv_obj_set_style_bg_color(btn, is_ok ? lv_color_hex(0x1a3020) : (is_del ? lv_color_hex(0x1a2030) : lv_color_hex(0x0a1828)), 0);
    lv_obj_set_style_radius(btn, 6, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_set_style_border_width(btn, 0, 0);
    lv_obj_t *lbl = lv_label_create(btn);
    lv_label_set_text(lbl, keys[k]);
    lv_obj_set_style_text_color(lbl, is_ok ? lv_color_hex(0x40c080) : lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 0);
    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      lv_obj_t *b = lv_event_get_target(e);
      lv_obj_t *l = lv_obj_get_child(b, 0);
      const char *txt = lv_label_get_text(l);
      if (strcmp(txt, "<") == 0) {
        int len = strlen(copy_id_input);
        if (len > 0) copy_id_input[len-1] = '\0';
      } else if (strcmp(txt, "OK") == 0) {
        if (strlen(copy_id_input) == 0) return;
        int entered_id = atoi(copy_id_input);
        if (entered_id <= 0) { lv_label_set_text(lbl_copy_id_status, "Invalid ID"); return; }
        // Fetch spool data from Spoolman (allow archived)
        if (!wifi_ok) { lv_label_set_text(lbl_copy_id_status, T(STR_LINK_NO_WIFI)); return; }
        StaticJsonDocument<512> doc;
        DeserializationError derr = DeserializationError::Ok;
        int code = spoolmanGetSpoolJson(cfg_spoolman_base, entered_id, doc, 8000, &derr);
        if (code != 200) {
          char err_buf[32]; snprintf(err_buf, sizeof(err_buf), T(STR_LINK_ID_NOT_FOUND), entered_id);
          lv_label_set_text(lbl_copy_id_status, err_buf);
          return;
        }
        int fid      = doc["filament"]["id"] | 0;
        float ini    = doc["filament"]["weight"] | 1000.0f;
        float spw    = doc["spool_weight"] | 0.0f;
        const char *fname = doc["filament"]["name"] | "?";
        const char *fmat  = doc["filament"]["material"] | "";
        const char *fvnd  = doc["filament"]["vendor"]["name"] | "";
        char tmpl[80];
        float rem2 = doc["remaining_weight"] | 0.0f;
        snprintf(tmpl, sizeof(tmpl), "%s %s (%s)", fmat, fname, fvnd);
        showCopyConfirmPopup(fid, tmpl, rem2, ini, spw);
      } else {
        if (strlen(copy_id_input) < 6) {
          strncat(copy_id_input, txt, 1);
        }
      }
      // Update display
      char disp[10];
      snprintf(disp, sizeof(disp), "%s_", strlen(copy_id_input)?copy_id_input:"");
      lv_label_set_text(lbl_copy_id_display, disp);
    }, LV_EVENT_CLICKED, NULL);
  }
}

// Entry popup: choose ID / Active spools / Archived spools
void showCopyEntryPopup() {
  logSD("SHOW: CopyEntryPopup");
  link_selected_material[0] = 0;  // clear so NTAG always goes via vendor/material picker
  link_selected_material_full[0] = 0;
  link_stage3_shown = false;
  closeCopyEntryPopup();

  scr_copy_entry = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_copy_entry, 480, 320);
  lv_obj_set_pos(scr_copy_entry, 0, 0);
  lv_obj_set_style_bg_color(scr_copy_entry, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr_copy_entry, 0, 0);
  lv_obj_set_style_pad_all(scr_copy_entry, 0, 0);
  lv_obj_set_style_radius(scr_copy_entry, 0, 0);
  lv_obj_clear_flag(scr_copy_entry, LV_OBJ_FLAG_SCROLLABLE);

  // Title
  lv_obj_t *lbl_title = lv_label_create(scr_copy_entry);
  char title_buf[32]; strncpy(title_buf, T(STR_COPY_TITLE), sizeof(title_buf)-1);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_style_text_align(lbl_title, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 22);

  // Separator
  lv_obj_t *div = lv_obj_create(scr_copy_entry);
  lv_obj_set_size(div, 472, 1); lv_obj_set_pos(div, 4, 52);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  // Context: material info if available
  lv_obj_t *lbl_ctx = lv_label_create(scr_copy_entry);
  char ctx_buf[56];
  if (strlen(g_tag.material) > 0) {
    snprintf(ctx_buf, sizeof(ctx_buf), T(STR_LINK_CTX_NOT_IN_SM), g_tag.material);
  } else if (strlen(link_tag_uid) > 0) {
    snprintf(ctx_buf, sizeof(ctx_buf), "UID: %s", link_tag_uid);
  } else {
    snprintf(ctx_buf, sizeof(ctx_buf), "UID: %s", g_tag.uid_str);
  }
  lv_label_set_text(lbl_ctx, ctx_buf);
  lv_obj_set_style_text_color(lbl_ctx, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_ctx, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(lbl_ctx, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_ctx, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_ctx, 450);
  lv_obj_align(lbl_ctx, LV_ALIGN_TOP_MID, 0, 60);

  // Button layout: 3 buttons + cancel, ID= >100 recommended | List= <100 recommended
  const int BTN_W = 380, BTN_H = 48, BTN_GAP = 8;
  const int Y1 = 92, Y2 = Y1+BTN_H+BTN_GAP, Y3 = Y2+BTN_H+BTN_GAP, Y4 = Y3+BTN_H+BTN_GAP;

  // Button 1: Enter ID (works for active + archived, >100 spools recommended)
  lv_obj_t *btn1 = lv_btn_create(scr_copy_entry);
  lv_obj_set_size(btn1, BTN_W, BTN_H);
  lv_obj_align(btn1, LV_ALIGN_TOP_MID, 0, Y1);
  lv_obj_set_style_bg_color(btn1, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn1, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn1, 10, 0);
  lv_obj_set_style_shadow_width(btn1, 0, 0);
  lv_obj_set_style_border_width(btn1, 1, 0);
  lv_obj_set_style_border_color(btn1, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn1, [](lv_event_t *e) { link_id_input[0] = '\0'; showIdInputPopup(strlen(g_tag.tray_uuid) == 32, true); }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn1);
    char b[40]; strncpy(b, T(STR_COPY_ID_BTN), sizeof(b)-1);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }

  // Button 2: Active spools (<100 recommended)
  lv_obj_t *btn2 = lv_btn_create(scr_copy_entry);
  lv_obj_set_size(btn2, BTN_W, BTN_H);
  lv_obj_align(btn2, LV_ALIGN_TOP_MID, 0, Y2);
  lv_obj_set_style_bg_color(btn2, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn2, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn2, 10, 0);
  lv_obj_set_style_shadow_width(btn2, 0, 0);
  lv_obj_set_style_border_width(btn2, 1, 0);
  lv_obj_set_style_border_color(btn2, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn2, [](lv_event_t *e) {
    logSD("BTN: CopyEntry -> Active spools");
    copy_flow_archived = false;
    bool is_bambu_tag = (strlen(g_tag.tray_uuid) == 32);
    if (is_bambu_tag) {
      // Bambu: use material filter if available, else show all
      fetchSpoolsForCopy(false, strlen(g_tag.material) > 0 ? g_tag.material : "", true);
      showCopySpoolList();
    } else {
      // NTAG: always go via 4-stage vendor/material picker
      copy_flow_via_list = true;
      link_flow_is_bambu = false;
      link_selected_material[0] = 0;
      link_selected_material_full[0] = 0;
      link_stage3_shown = false;
      fetchAllSpoolsForLink(false, "", false);  // active spools only
      showVendorList();
    }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn2);
    char b[40]; strncpy(b, T(STR_COPY_ACTIVE_BTN), sizeof(b)-1);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }

  // Button 3: Archived spools (<100 recommended)
  lv_obj_t *btn3 = lv_btn_create(scr_copy_entry);
  lv_obj_set_size(btn3, BTN_W, BTN_H);
  lv_obj_align(btn3, LV_ALIGN_TOP_MID, 0, Y3);
  lv_obj_set_style_bg_color(btn3, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn3, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn3, 10, 0);
  lv_obj_set_style_shadow_width(btn3, 0, 0);
  lv_obj_set_style_border_width(btn3, 1, 0);
  lv_obj_set_style_border_color(btn3, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn3, [](lv_event_t *e) {
    logSD("BTN: CopyEntry -> Archived spools");
    copy_flow_archived = true;
    bool is_bambu_tag = (strlen(g_tag.tray_uuid) == 32);
    if (is_bambu_tag) {
      fetchSpoolsForCopy(true, strlen(g_tag.material) > 0 ? g_tag.material : "", true);
      showCopySpoolList();
    } else {
      // NTAG: always go via 4-stage vendor/material picker (archived only)
      copy_flow_via_list = true;
      link_flow_is_bambu = false;
      link_selected_material[0] = 0;
      link_selected_material_full[0] = 0;
      link_stage3_shown = false;
      fetchAllSpoolsForLink(false, "", true);  // archived only
      showVendorList();
    }
  }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn3);
    char b[40]; strncpy(b, T(STR_COPY_ARCHIVED_BTN), sizeof(b)-1);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }

  // Button 4: Cancel
  lv_obj_t *btn4 = lv_btn_create(scr_copy_entry);
  lv_obj_set_size(btn4, BTN_W, BTN_H);
  lv_obj_align(btn4, LV_ALIGN_TOP_MID, 0, Y4);
  lv_obj_set_style_bg_color(btn4, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn4, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn4, 10, 0);
  lv_obj_set_style_shadow_width(btn4, 0, 0);
  lv_obj_set_style_border_width(btn4, 0, 0);
  lv_obj_add_event_cb(btn4, [](lv_event_t *e) { closeCopyEntryPopup(); }, LV_EVENT_CLICKED, NULL);
  { lv_obj_t *l = lv_label_create(btn4);
    char b[16]; strncpy(b, T(STR_CANCEL), sizeof(b)-1);
    lv_label_set_text(l, b);
    lv_obj_set_style_text_color(l, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_ext_16, 0);
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 0); }
}

// ============================================================
//  MORE INFO FILAMENT SCREEN
//  Overlay with teal border (8px margin), shows UID, UUID,
//  article nr, production date, spool weight (empty), free slot.
//  Always rebuilt on open. Only one close button (X).
// ============================================================
void showMoreInfoScreen() {
  logSD("SHOW: MoreInfoScreen");
  logSD("UI: Screen -> MoreInfo");
  // Delete old instance if exists
  if (scr_more_info) { lv_obj_del(scr_more_info); scr_more_info = nullptr; }
  buildMoreInfoScreen();
}

// ── Location Picker ─────────────────────────────────────────
static lv_obj_t *scr_location_picker = nullptr;

void showLocationPicker() {
  if (scr_location_picker) { lv_obj_del(scr_location_picker); scr_location_picker = nullptr; }
  if (!sm_found || sm_id <= 0) return;

  // Backdrop
  scr_location_picker = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_location_picker, 480, 320);
  lv_obj_set_pos(scr_location_picker, 0, 0);
  lv_obj_set_style_bg_color(scr_location_picker, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_location_picker, LV_OPA_70, 0);
  lv_obj_set_style_border_width(scr_location_picker, 0, 0);
  lv_obj_set_style_radius(scr_location_picker, 0, 0);
  lv_obj_set_style_pad_all(scr_location_picker, 0, 0);
  lv_obj_clear_flag(scr_location_picker, LV_OBJ_FLAG_SCROLLABLE);

  // Inner box
  lv_obj_t *box = lv_obj_create(scr_location_picker);
  lv_obj_set_size(box, 400, 280);
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0b1525), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, 10, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // Header
  lv_obj_t *hdr = lv_obj_create(box);
  lv_obj_set_size(hdr, 400, 44);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *lbl_title = lv_label_create(hdr);
  char title_buf[48];
  strncpy(title_buf, T(STR_LOCATION_TITLE), sizeof(title_buf)-1);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *btn_x = lv_btn_create(hdr);
  lv_obj_set_size(btn_x, 40, 40);
  lv_obj_align(btn_x, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_x, 1, 0);
  lv_obj_set_style_border_color(btn_x, lv_color_hex(0x601010), 0);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e) {
    if (scr_location_picker) { lv_obj_del(scr_location_picker); scr_location_picker = nullptr; }
    if (g_loc_picker_from_popup) { showMainScreen(); }
    else { showMoreInfoScreen(); }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);

  // Status label (loading / error)
  lv_obj_t *lbl_status = lv_label_create(box);
  char status_buf[48];
  strncpy(status_buf, T(STR_LOCATION_LOADING), sizeof(status_buf)-1);
  lv_label_set_text(lbl_status, status_buf);
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_status, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_status, LV_ALIGN_CENTER, 0, 10);

  // Scrollable list container
  lv_obj_t *list = lv_obj_create(box);
  lv_obj_set_size(list, 380, 220);
  lv_obj_set_pos(list, 10, 50);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0b1525), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_style_pad_all(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_add_flag(list, LV_OBJ_FLAG_HIDDEN);

  // Store refs for async fetch
  loc_status_obj = lbl_status;
  loc_list_obj   = list;

  // Trigger async HTTP fetch via loop()
  if (!wifiManagerIsConnected()) {
    char buf[32]; strncpy(buf, T(STR_LOCATION_NO_WIFI), sizeof(buf)-1);
    lv_label_set_text(lbl_status, buf);
    return;
  }
  fetch_locations_pending = true;
}

void fetchAndFillLocationList() {
  logSD("LOC: fetchAndFillLocationList called");
  if (!loc_list_obj || !loc_status_obj) { logSD("LOC: null refs, abort"); return; }
  if (!scr_location_picker) { logSD("LOC: picker gone, abort"); return; }

  // Mehrere LVGL-Ticks geben damit das Overlay vollständig gerendert ist
  for (int i = 0; i < 5; i++) {
    lv_task_handler();
    delay(20);
  }

  logSDf("LOC: GET %s/api/v1/location", cfg_spoolman_base);
  JsonDocument doc;
  DeserializationError err = DeserializationError::Ok;
  int code = spoolmanGetLocationsJson(cfg_spoolman_base, doc, 8000, &err);
  logSDf("LOC: HTTP code=%d", code);
  if (code != 200) {
    char buf[48];
    snprintf(buf, sizeof(buf), "HTTP %d", code);
    lv_label_set_text(loc_status_obj, buf);
    return;
  }
  logSDf("LOC: parse err=%s isArray=%d", err.c_str(), (int)doc.is<JsonArray>());
  if (err || !doc.is<JsonArray>()) {
    char buf[48];
    snprintf(buf, sizeof(buf), "Parse: %s", err.c_str());
    lv_label_set_text(loc_status_obj, buf);
    return;
  }

  JsonArray locs = doc.as<JsonArray>();
  logSDf("LOC: locs.size()=%d", (int)locs.size());
  if (locs.size() == 0) {
    char buf[48]; strncpy(buf, T(STR_LOCATION_NO_LOCATIONS), sizeof(buf)-1);
    lv_label_set_text(loc_status_obj, buf);
    return;
  }

  // Hide status, show list
  lv_obj_add_flag(loc_status_obj, LV_OBJ_FLAG_HIDDEN);
  lv_obj_clear_flag(loc_list_obj, LV_OBJ_FLAG_HIDDEN);
  lv_obj_t *list = loc_list_obj;

  // "Kein Lagerort" Row
  lv_obj_t *btn_none = lv_btn_create(list);
  lv_obj_set_size(btn_none, 370, 44);
  lv_obj_set_style_bg_color(btn_none, lv_color_hex(0x0d2040), 0);
  lv_obj_set_style_bg_color(btn_none, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_border_color(btn_none, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(btn_none, 1, 0);
  lv_obj_set_style_radius(btn_none, 6, 0);
  lv_obj_set_style_shadow_width(btn_none, 0, 0);
  lv_obj_set_style_pad_bottom(btn_none, 4, 0);
  lv_obj_t *lbl_none = lv_label_create(btn_none);
  char none_buf[48]; strncpy(none_buf, T(STR_LOCATION_NONE), sizeof(none_buf)-1);
  lv_label_set_text(lbl_none, none_buf);
  lv_obj_set_style_text_color(lbl_none, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_none, &lv_font_montserrat_ext_16, 0);
  lv_obj_center(lbl_none);
  lv_obj_add_event_cb(btn_none, [](lv_event_t *e) {
    if (!wifiManagerIsConnected() || sm_id <= 0) return;
    int code = spoolmanPatchSpoolLocation(cfg_spoolman_base, sm_id, nullptr, 8000);
    if (code == 200) {
      sm_location_id = 0;
      sm_location_name[0] = '\0';
    }
    if (scr_location_picker) { lv_obj_del(scr_location_picker); scr_location_picker = nullptr; }
    if (g_loc_picker_from_popup) { showMainScreen(); }
    else { showMoreInfoScreen(); }
  }, LV_EVENT_CLICKED, NULL);

  // Location rows — API gibt Array von Strings zurück
  int loc_shown = 0;
  bool loc_limit_hit = false;
  for (JsonVariant v : locs) {
    if (loc_shown >= location_list_limit) { loc_limit_hit = true; break; }
    char loc_name[48];
    strncpy(loc_name, v.as<const char*>() ? v.as<const char*>() : "-", sizeof(loc_name)-1);
    loc_name[sizeof(loc_name)-1] = '\0';

    lv_obj_t *row = lv_btn_create(list);
    lv_obj_set_size(row, 370, 44);
    bool is_current = (strlen(sm_location_name) > 0 && strcmp(loc_name, sm_location_name) == 0);
    lv_obj_set_style_bg_color(row, is_current ? lv_color_hex(0x0d3020) : lv_color_hex(0x0d2040), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(row, is_current ? lv_color_hex(0x28d49a) : lv_color_hex(0x0f1e30), 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_pad_bottom(row, 4, 0);

    lv_obj_t *lbl_row = lv_label_create(row);
    lv_label_set_text(lbl_row, loc_name);
    lv_obj_set_style_text_color(lbl_row, is_current ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0f0f0), 0);
    lv_obj_set_style_text_font(lbl_row, &lv_font_montserrat_ext_16, 0);
    lv_obj_center(lbl_row);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      lv_obj_t *lbl = lv_obj_get_child(lv_event_get_target(e), 0);
      if (!lbl || !wifiManagerIsConnected() || sm_id <= 0) return;
      const char* sel_name = lv_label_get_text(lbl);
      int code = spoolmanPatchSpoolLocation(cfg_spoolman_base, sm_id, sel_name, 8000);
      if (code == 200) {
        strncpy(sm_location_name, sel_name, sizeof(sm_location_name)-1);
        sm_location_id = 0;
        // Mark popup as shown so it doesn't re-trigger on next tag-remove
        g_loc_popup_shown_for_id = sm_id;
        logSDf("[verbose] LOC: location saved '%s' id=%d from_popup=%d", sel_name, sm_id, (int)g_loc_picker_from_popup);
      }
      if (scr_location_picker) { lv_obj_del(scr_location_picker); scr_location_picker = nullptr; }
      if (g_loc_picker_from_popup) { showMainScreen(); }
      else { showMoreInfoScreen(); }
    }, LV_EVENT_CLICKED, NULL);
    loc_shown++;
  }
  // Hinweis: Limit erreicht
  if (loc_limit_hit) {
    lv_obj_t *limit_row = lv_obj_create(loc_list_obj);
    lv_obj_set_size(limit_row, 360, 40);
    lv_obj_set_style_bg_color(limit_row, lv_color_hex(0x1a0808), 0);
    lv_obj_set_style_radius(limit_row, 6, 0);
    lv_obj_set_style_border_width(limit_row, 1, 0);
    lv_obj_set_style_border_color(limit_row, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_pad_all(limit_row, 0, 0);
    lv_obj_clear_flag(limit_row, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *limit_lbl = lv_label_create(limit_row);
    char limit_buf[64]; strncpy(limit_buf, T(STR_LOCATION_LIMIT_HIT), sizeof(limit_buf)-1);
    lv_label_set_text(limit_lbl, limit_buf);
    lv_obj_set_style_text_color(limit_lbl, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(limit_lbl, &lv_font_montserrat_ext_12, 0);
    lv_obj_set_style_text_align(limit_lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(limit_lbl, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(limit_lbl, 350);
    lv_obj_center(limit_lbl);
  }
  // Hinweis: leere Lagerorte werden nicht angezeigt
  lv_obj_t *hint_row = lv_obj_create(loc_list_obj);
  lv_obj_set_size(hint_row, 360, 40);
  lv_obj_set_style_bg_color(hint_row, lv_color_hex(0x1a1a08), 0);
  lv_obj_set_style_radius(hint_row, 6, 0);
  lv_obj_set_style_border_width(hint_row, 1, 0);
  lv_obj_set_style_border_color(hint_row, lv_color_hex(0x3a3010), 0);
  lv_obj_set_style_pad_all(hint_row, 0, 0);
  lv_obj_clear_flag(hint_row, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
  lv_obj_t *hint_lbl = lv_label_create(hint_row);
  char hint_buf[64]; strncpy(hint_buf, T(STR_LOCATION_HINT_EMPTY), sizeof(hint_buf)-1);
  lv_label_set_text(hint_lbl, hint_buf);
  lv_obj_set_style_text_color(hint_lbl, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(hint_lbl, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_style_text_align(hint_lbl, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(hint_lbl, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint_lbl, 350);
  lv_obj_center(hint_lbl);
}

void buildMoreInfoScreen() {
  logSD("BUILD: MoreInfoScreen");
  // Full-screen dimmed backdrop
  scr_more_info = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_more_info, 480, 320);
  lv_obj_set_pos(scr_more_info, 0, 0);
  lv_obj_set_style_bg_color(scr_more_info, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(scr_more_info, LV_OPA_50, 0);
  lv_obj_set_style_border_width(scr_more_info, 0, 0);
  lv_obj_set_style_radius(scr_more_info, 0, 0);
  lv_obj_set_style_pad_all(scr_more_info, 0, 0);
  lv_obj_clear_flag(scr_more_info, LV_OBJ_FLAG_SCROLLABLE);

  // Inner box: 464x300, teal border, 8px margins
  lv_obj_t *box = lv_obj_create(scr_more_info);
  lv_obj_set_size(box, 464, 300);
  lv_obj_set_pos(box, 8, 10);
  lv_obj_set_style_bg_color(box, lv_color_hex(0x0b1525), 0);
  lv_obj_set_style_border_color(box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(box, 1, 0);
  lv_obj_set_style_radius(box, 10, 0);
  lv_obj_set_style_pad_all(box, 0, 0);
  lv_obj_clear_flag(box, LV_OBJ_FLAG_SCROLLABLE);

  // ── Header 52px (larger for 44px X button) ──────────────
  lv_obj_t *hdr = lv_obj_create(box);
  lv_obj_set_size(hdr, 464, 52);
  lv_obj_set_pos(hdr, 0, 0);
  lv_obj_set_style_bg_color(hdr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(hdr, 0, 0);
  lv_obj_set_style_radius(hdr, 0, 0);
  lv_obj_set_style_pad_all(hdr, 0, 0);
  lv_obj_clear_flag(hdr, LV_OBJ_FLAG_SCROLLABLE);

  // Title — Fix 12: always "More info filament" in both languages
  lv_obj_t *lbl_title = lv_label_create(hdr);
  lv_label_set_text(lbl_title, "Filament");
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_ext_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_CENTER, 0, 0);

  // Close X button — Fix 10: 44x44px proper size
  lv_obj_t *btn_x = lv_btn_create(hdr);
  lv_obj_set_size(btn_x, 44, 44);
  lv_obj_align(btn_x, LV_ALIGN_RIGHT_MID, -4, 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_x, 1, 0);
  lv_obj_set_style_border_color(btn_x, lv_color_hex(0x601010), 0);
  lv_obj_set_style_radius(btn_x, 8, 0);
  lv_obj_set_style_shadow_width(btn_x, 0, 0);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e) {
    if (scr_more_info) { lv_obj_del(scr_more_info); scr_more_info = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_ext_18, 0);
  lv_obj_center(lbl_x);

  // Header separator (below header, Fix 10: at y=52)
  lv_obj_t *hdiv = lv_obj_create(box);
  lv_obj_set_size(hdiv, 464, 1);
  lv_obj_set_pos(hdiv, 0, 52);
  lv_obj_set_style_bg_color(hdiv, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(hdiv, 0, 0);
  lv_obj_set_style_radius(hdiv, 0, 0);
  lv_obj_set_style_pad_all(hdiv, 0, 0);

  // ── Swatch row: caps y=55, values y=70 ───────────────────
  // Cap: ID
  lv_obj_t *mi_id_cap = lv_label_create(box);
  lv_label_set_text(mi_id_cap, "ID");
  lv_obj_set_style_text_color(mi_id_cap, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(mi_id_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(mi_id_cap, 60, 55);

  lv_obj_t *swatch = lv_obj_create(box);
  lv_obj_set_size(swatch, 42, 42);
  lv_obj_set_pos(swatch, 10, 60);
  lv_obj_set_style_radius(swatch, 6, 0);
  lv_obj_set_style_border_color(swatch, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_border_width(swatch, 1, 0);
  lv_obj_set_style_pad_all(swatch, 0, 0);
  lv_obj_clear_flag(swatch, LV_OBJ_FLAG_SCROLLABLE);
  // Swatch color: prefer tag color (Bambu), fall back to Spoolman color (NTAG)
  const char* swatch_hex = (strlen(g_tag.color_hex) == 7) ? g_tag.color_hex :
                           (strlen(sm_color_global) >= 6 ? sm_color_global : nullptr);
  if (swatch_hex) {
    const char* h = (swatch_hex[0] == '#') ? swatch_hex + 1 : swatch_hex;
    unsigned int r, g, b;
    sscanf(h, "%02X%02X%02X", &r, &g, &b);
    lv_obj_set_style_bg_color(swatch, lv_color_hex(((uint32_t)r<<16)|((uint32_t)g<<8)|b), 0);
  } else {
    lv_obj_set_style_bg_color(swatch, lv_color_hex(0x333333), 0);
  }

  // SM-ID value
  lv_obj_t *lbl_id = lv_label_create(box);
  char id_buf[12];
  if (sm_found && sm_id > 0) snprintf(id_buf, sizeof(id_buf), "%d", sm_id);
  else strncpy(id_buf, "?", sizeof(id_buf));
  lv_label_set_text(lbl_id, id_buf);
  lv_obj_set_style_text_color(lbl_id,
    (sm_found && sm_id > 0) ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_id, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_id, 60, 70);

  // Cap: Material
  lv_obj_t *mi_mat_cap = lv_label_create(box);
  lv_label_set_text(mi_mat_cap, "Material");
  lv_obj_set_style_text_color(mi_mat_cap, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(mi_mat_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(mi_mat_cap, 98, 55);

  // Material value — for NTAG spools use sm_material (from Spoolman), for Bambu use g_tag.material
  lv_obj_t *lbl_mat = lv_label_create(box);
  lbl_mi_mat = nullptr;  // not used for live update
  const char* mat_val = (strlen(sm_material_global) > 0) ? sm_material_global :
                        (strlen(g_tag.material) > 0 ? g_tag.material : "-");
  lv_label_set_text(lbl_mat, mat_val);
  lv_obj_set_style_text_color(lbl_mat, lv_color_hex(0xf0f0f0), 0);
  lv_obj_set_style_text_font(lbl_mat, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_pos(lbl_mat, 98, 68);
  lv_label_set_long_mode(lbl_mat, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_mat, 160);

  // Cap: Filament
  lv_obj_t *mi_fn_cap = lv_label_create(box);
  lv_label_set_text(mi_fn_cap, "Filament");
  lv_obj_set_style_text_color(mi_fn_cap, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(mi_fn_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(mi_fn_cap, 264, 55);

  // Filament name value
  lv_obj_t *lbl_fn = lv_label_create(box);
  lv_label_set_text(lbl_fn, strlen(sm_filament_name) > 0 ? sm_filament_name : "-");
  lv_obj_set_style_text_color(lbl_fn, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_fn, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(lbl_fn, 264, 70);
  lv_label_set_long_mode(lbl_fn, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_fn, 188);

  // Separator after swatch row
  lv_obj_t *div1 = lv_obj_create(box);
  lv_obj_set_size(div1, 444, 1);
  lv_obj_set_pos(div1, 10, 108);
  lv_obj_set_style_bg_color(div1, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(div1, 0, 0);
  lv_obj_set_style_radius(div1, 0, 0);
  lv_obj_set_style_pad_all(div1, 0, 0);

  // ── Fix 11: 2x3 grid — new order ────────────────────────
  // Col A: x=10, Col B: x=242
  // Row 1 y=114: Hex Color (A) | Production date (B)
  // Row 2 y=150: Article no. (A) | Spool weight empty (B)
  // separator y=186
  // Row 3 y=192: UID (A, full width label)
  // Row 4 y=228: Spoolman UUID (full width)
  const int CA = 10, CB = 242;
  const int VF = 18; // gap from cap to value

  // Row 1 Left: Fix 11 — Hex Color / Color — Fix 6: larger
  const char *hex_cap = g_lang == LANG_DE ? "Farbe" : "Hex Color";
  lv_obj_t *c1 = lv_label_create(box);
  lv_label_set_text(c1, hex_cap);
  lv_obj_set_style_text_color(c1, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c1, &lv_font_montserrat_ext_14, 0);  // Fix 6: 12→14
  lv_obj_set_pos(c1, CA, 114);
  lv_obj_t *v1 = lv_label_create(box);
  const char* color_display = (strlen(g_tag.color_hex) > 1) ? g_tag.color_hex :
                              (strlen(sm_color_global) > 1 ? sm_color_global : "-");
  lv_label_set_text(v1, color_display);
  lv_obj_set_style_text_color(v1, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(v1, &lv_font_montserrat_ext_18, 0);  // Fix 6: 16→18
  lv_obj_set_pos(v1, CA, 114 + VF);

  // Row 1 Right: Production date — Fix 6
  const char *prod_cap = g_lang == LANG_DE ? "Produktionsdatum" : "Production date";
  lv_obj_t *c2 = lv_label_create(box);
  lv_label_set_text(c2, prod_cap);
  lv_obj_set_style_text_color(c2, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c2, &lv_font_montserrat_ext_14, 0);  // Fix 6
  lv_obj_set_pos(c2, CB, 114);
  lv_obj_t *v2 = lv_label_create(box);
  lv_label_set_text(v2, strlen(g_tag.production_date) > 4 ? g_tag.production_date : "-");
  lv_obj_set_style_text_color(v2, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(v2, &lv_font_montserrat_ext_18, 0);  // Fix 6
  lv_obj_set_pos(v2, CB, 114 + VF);

  // Row 2 Left: Article no. — Fix 6: larger — Fix 2: more space (y=160)
  const char *art_cap = g_lang == LANG_DE ? "Artikelnr." : "Article no.";
  lv_obj_t *c3 = lv_label_create(box);
  lv_label_set_text(c3, art_cap);
  lv_obj_set_style_text_color(c3, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c3, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(c3, CA, 158);
  lv_obj_t *v3 = lv_label_create(box);
  lv_label_set_text(v3, strlen(sm_article_nr) > 0 ? sm_article_nr : "-");
  lv_obj_set_style_text_color(v3, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(v3, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_pos(v3, CA, 158 + VF);

  // Row 2 Right: Spool weight (empty)
  const char *sw_cap = g_lang == LANG_DE ? "Leergewicht Spule" : "Spool weight (empty)";
  lv_obj_t *c4 = lv_label_create(box);
  lv_label_set_text(c4, sw_cap);
  lv_obj_set_style_text_color(c4, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c4, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(c4, CB, 158);
  lv_obj_t *v4 = lv_label_create(box);
  char sw_buf[16];
  if (sm_spool_weight > 0) snprintf(sw_buf, sizeof(sw_buf), "%.0f g", sm_spool_weight);
  else strncpy(sw_buf, "-", sizeof(sw_buf));
  lv_label_set_text(v4, sw_buf);
  lv_obj_set_style_text_color(v4, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(v4, &lv_font_montserrat_ext_18, 0);
  lv_obj_set_pos(v4, CB, 158 + VF);

  // Separator before UID+UUID — Fix 2: shifted down (y=200)
  lv_obj_t *div2 = lv_obj_create(box);
  lv_obj_set_size(div2, 444, 1);
  lv_obj_set_pos(div2, 10, 200);
  lv_obj_set_style_bg_color(div2, lv_color_hex(0x0f1e30), 0);
  lv_obj_set_style_border_width(div2, 0, 0);
  lv_obj_set_style_radius(div2, 0, 0);
  lv_obj_set_style_pad_all(div2, 0, 0);

  // Fix 7: UID left + Spoolman ID right — shifted down (y=206)
  lv_obj_t *c_uid = lv_label_create(box);
  lv_label_set_text(c_uid, "UID");
  lv_obj_set_style_text_color(c_uid, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c_uid, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_pos(c_uid, 10, 206);
  lv_obj_t *v_uid = lv_label_create(box);
  lv_label_set_text(v_uid, strlen(g_tag.uid_str) > 0 ? g_tag.uid_str : "-");
  lv_obj_set_style_text_color(v_uid, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(v_uid, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(v_uid, 10, 206 + 13);

  // Location button — bottom right of row 3 (replaces duplicate Spoolman ID)
  lv_obj_t *btn_loc = lv_btn_create(box);
  lv_obj_set_size(btn_loc, 220, 46);
  lv_obj_set_pos(btn_loc, CB - 10, 204);
  lv_obj_set_style_bg_color(btn_loc, lv_color_hex(0x0d2040), 0);
  lv_obj_set_style_bg_color(btn_loc, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_border_color(btn_loc, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(btn_loc, 1, 0);
  lv_obj_set_style_radius(btn_loc, 8, 0);
  lv_obj_set_style_shadow_width(btn_loc, 0, 0);
  lv_obj_set_style_pad_all(btn_loc, 0, 0);
  // Cap label — centered, shifted 2px up from center
  lv_obj_t *btn_loc_cap = lv_label_create(btn_loc);
  char loc_cap_buf[32];
  strncpy(loc_cap_buf, T(STR_BTN_LOCATION), sizeof(loc_cap_buf)-1);
  lv_label_set_text(btn_loc_cap, loc_cap_buf);
  lv_obj_set_style_text_color(btn_loc_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(btn_loc_cap, &lv_font_montserrat_ext_12, 0);
  lv_obj_set_style_text_align(btn_loc_cap, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(btn_loc_cap, LV_ALIGN_CENTER, 0, -11);
  // Value label — centered
  lv_obj_t *btn_loc_val = lv_label_create(btn_loc);
  char loc_val_buf[48];
  strncpy(loc_val_buf, sm_location_name[0] ? sm_location_name : "-", sizeof(loc_val_buf)-1);
  lv_label_set_text(btn_loc_val, loc_val_buf);
  lv_obj_set_style_text_color(btn_loc_val, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(btn_loc_val, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_style_text_align(btn_loc_val, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(btn_loc_val, 204);
  lv_label_set_long_mode(btn_loc_val, LV_LABEL_LONG_DOT);
  lv_obj_align(btn_loc_val, LV_ALIGN_CENTER, 0, 7);
  lv_obj_add_event_cb(btn_loc, [](lv_event_t *e) {
    if (!wifiManagerIsConnected()) {
      return;
    }
    g_loc_picker_from_popup = false;
    show_location_picker_pending = true;
  }, LV_EVENT_CLICKED, NULL);

  // Spoolman UUID — shifted down (y=246)
  lv_obj_t *c_uuid = lv_label_create(box);
  lv_label_set_text(c_uuid, "Spoolman UUID");
  lv_obj_set_style_text_color(c_uuid, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c_uuid, &lv_font_montserrat_ext_14, 0);
  lv_obj_set_pos(c_uuid, 10, 248);
  lv_obj_t *v_uuid = lv_label_create(box);
  lv_label_set_text(v_uuid,
    strlen(g_tag.tray_uuid) == 32 ? g_tag.tray_uuid : "-");
  lv_obj_set_style_text_color(v_uuid, lv_color_hex(0x4a7080), 0);
  lv_obj_set_style_text_font(v_uuid, &lv_font_montserrat_ext_16, 0);
  lv_obj_set_pos(v_uuid, 10, 264);
  lv_label_set_long_mode(v_uuid, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v_uuid, 330);  // shortened to make room for Unlink button

  // Unlink button — bottom right, only visible when spool is linked (sm_found && sm_id > 0)
  if (sm_found && sm_id > 0) {
    lv_obj_t *btn_unlink = lv_btn_create(box);
    lv_obj_set_size(btn_unlink, 104, 34);
    lv_obj_set_pos(btn_unlink, 348, 258);
    lv_obj_set_style_bg_color(btn_unlink, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_unlink, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_unlink, 8, 0);
    lv_obj_set_style_shadow_width(btn_unlink, 0, 0);
    lv_obj_set_style_border_width(btn_unlink, 1, 0);
    lv_obj_set_style_border_color(btn_unlink, lv_color_hex(0x601010), 0);
    lv_obj_add_event_cb(btn_unlink, [](lv_event_t *e) {
      // Build confirmation popup on lv_scr_act() so it sits above more_info
      lv_obj_t *pop = lv_obj_create(lv_scr_act());
      lv_obj_set_size(pop, 480, 320);
      lv_obj_set_pos(pop, 0, 0);
      lv_obj_set_style_bg_color(pop, lv_color_hex(0x000000), 0);
      lv_obj_set_style_bg_opa(pop, LV_OPA_80, 0);
      lv_obj_set_style_border_width(pop, 0, 0);
      lv_obj_set_style_radius(pop, 0, 0);
      lv_obj_set_style_pad_all(pop, 0, 0);
      lv_obj_clear_flag(pop, LV_OBJ_FLAG_SCROLLABLE);

      lv_obj_t *box2 = lv_obj_create(pop);
      lv_obj_set_size(box2, 420, 210);
      lv_obj_align(box2, LV_ALIGN_CENTER, 0, 0);
      lv_obj_set_style_bg_color(box2, lv_color_hex(0x1a0808), 0);
      lv_obj_set_style_border_color(box2, lv_color_hex(0x602020), 0);
      lv_obj_set_style_border_width(box2, 2, 0);
      lv_obj_set_style_radius(box2, 12, 0);
      lv_obj_set_style_pad_all(box2, 0, 0);
      lv_obj_clear_flag(box2, LV_OBJ_FLAG_SCROLLABLE);

      lv_obj_t *lbl_t = lv_label_create(box2);
      char buf_t[48]; strncpy(buf_t, T(STR_UNLINK_TITLE), sizeof(buf_t)-1);
      lv_label_set_text(lbl_t, buf_t);
      lv_obj_set_style_text_color(lbl_t, lv_color_hex(0xff8080), 0);
      lv_obj_set_style_text_font(lbl_t, &lv_font_montserrat_ext_18, 0);
      lv_obj_align(lbl_t, LV_ALIGN_TOP_MID, 0, 16);

      lv_obj_t *lbl_m = lv_label_create(box2);
      char buf_m[192]; strncpy(buf_m, T(STR_UNLINK_MSG), sizeof(buf_m)-1);
      lv_label_set_text(lbl_m, buf_m);
      lv_obj_set_style_text_color(lbl_m, lv_color_hex(0xc8d8f0), 0);
      lv_obj_set_style_text_font(lbl_m, &lv_font_montserrat_ext_14, 0);
      lv_obj_set_style_text_align(lbl_m, LV_TEXT_ALIGN_CENTER, 0);
      lv_label_set_long_mode(lbl_m, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(lbl_m, 380);
      lv_obj_align(lbl_m, LV_ALIGN_TOP_MID, 0, 48);

      // Cancel (links)
      lv_obj_t *btn_no = lv_btn_create(box2);
      lv_obj_set_size(btn_no, 170, 44);
      lv_obj_set_pos(btn_no, 12, 154);
      lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x0a1828), 0);
      lv_obj_set_style_bg_color(btn_no, lv_color_hex(0x1a2840), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn_no, 8, 0);
      lv_obj_set_style_shadow_width(btn_no, 0, 0);
      lv_obj_set_style_border_width(btn_no, 1, 0);
      lv_obj_set_style_border_color(btn_no, lv_color_hex(0x1a2840), 0);
      lv_obj_add_event_cb(btn_no, [](lv_event_t *e) {
        lv_obj_del(lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e))));
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_no = lv_label_create(btn_no);
      char buf_no[32]; strncpy(buf_no, T(STR_CANCEL), sizeof(buf_no)-1);
      lv_label_set_text(lbl_no, buf_no);
      lv_obj_set_style_text_color(lbl_no, lv_color_hex(0x4a6fa0), 0);
      lv_obj_set_style_text_font(lbl_no, &lv_font_montserrat_ext_14, 0);
      lv_obj_align(lbl_no, LV_ALIGN_CENTER, 0, 0);

      // Confirm unlink (rechts, rot)
      lv_obj_t *btn_yes = lv_btn_create(box2);
      lv_obj_set_size(btn_yes, 220, 44);
      lv_obj_set_pos(btn_yes, 190, 154);
      lv_obj_set_style_bg_color(btn_yes, lv_color_hex(0x3a1010), 0);
      lv_obj_set_style_bg_color(btn_yes, lv_color_hex(0x602020), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn_yes, 8, 0);
      lv_obj_set_style_shadow_width(btn_yes, 0, 0);
      lv_obj_set_style_border_width(btn_yes, 1, 0);
      lv_obj_set_style_border_color(btn_yes, lv_color_hex(0x602020), 0);
      lv_obj_add_event_cb(btn_yes, [](lv_event_t *e) {
        // Close popup
        lv_obj_del(lv_obj_get_parent(lv_obj_get_parent(lv_event_get_target(e))));
        // Patch tag field to empty string
        patchSpoolTag(sm_id, "");
        logSDf("Unlink spool ID=%d", sm_id);
        Serial.printf("Unlink spool ID=%d\n", sm_id);
        // Close More Info and reset display — NFC will re-scan and find no match
        if (scr_more_info) { lv_obj_del(scr_more_info); scr_more_info = nullptr; }
        clearTagDisplay();
        showMainScreen();
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_yes = lv_label_create(btn_yes);
      char buf_yes[48]; strncpy(buf_yes, T(STR_UNLINK_CONFIRM), sizeof(buf_yes)-1);
      lv_label_set_text(lbl_yes, buf_yes);
      lv_obj_set_style_text_color(lbl_yes, lv_color_hex(0xff8080), 0);
      lv_obj_set_style_text_font(lbl_yes, &lv_font_montserrat_ext_14, 0);
      lv_obj_align(lbl_yes, LV_ALIGN_CENTER, 0, 0);
    }, LV_EVENT_CLICKED, NULL);

    lv_obj_t *lbl_unlink = lv_label_create(btn_unlink);
    char buf_ul[16]; strncpy(buf_ul, T(STR_UNLINK_BTN), sizeof(buf_ul)-1);
    lv_label_set_text(lbl_unlink, buf_ul);
    lv_obj_set_style_text_color(lbl_unlink, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_unlink, &lv_font_montserrat_ext_14, 0);
    lv_obj_align(lbl_unlink, LV_ALIGN_CENTER, 0, 0);
  }
}

// ============================================================
//  FILL DISPLAY WITH TAG DATA
// ============================================================
void updateDisplay() {
  scan_count++;
  updateHeaderStatus();

  // Status bar: green dot + tag found
  lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);
  lv_label_set_text(lbl_status, T(STR_TAG_FOUND));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);

  // Material (Zone 3 Row A)
  lv_label_set_text(lbl_material,
    strlen(g_tag.material) > 0 ? g_tag.material : T(STR_UNKNOWN));

  // SM-ID: shown as "?" until querySpoolman fills it
  lv_label_set_text(lbl_spoolman_id, "?");
  lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0xf0b838), 0);

  // Filament name: cleared until Spoolman responds
  lv_label_set_text(lbl_filament_name, "");

  // Color swatch + hex text
  lv_label_set_text(lbl_color,
    strlen(g_tag.color_hex) > 1 ? g_tag.color_hex : "-");
  if (strlen(g_tag.color_hex) == 7) {
    unsigned int r, g, b;
    sscanf(g_tag.color_hex + 1, "%02X%02X%02X", &r, &g, &b);
    uint32_t col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
    lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(col), 0);
  }

  // Temp (Zone 3 Row B)
  char temp_str[24];
  if (g_tag.temp_min > 0 && g_tag.temp_max > 0) {
    snprintf(temp_str, sizeof(temp_str), "%d - %d C", g_tag.temp_min, g_tag.temp_max);
  } else {
    strncpy(temp_str, T(STR_UNKNOWN), sizeof(temp_str));
  }
  lv_label_set_text(lbl_temp, temp_str);

  // Vendor (Zone 3 Row B)
  lv_label_set_text(lbl_vendor,
    strlen(g_tag.vendor) > 0 ? g_tag.vendor : "Bambu Lab");

  // Hidden labels still written for More Info screen compatibility
  lv_label_set_text(lbl_uid, g_tag.uid_str);
  lv_label_set_text(lbl_tray_uuid,
    strlen(g_tag.tray_uuid) == 32 ? g_tag.tray_uuid : T(STR_NOT_READABLE));
  lv_label_set_text(lbl_date,
    strlen(g_tag.production_date) > 4 ? g_tag.production_date : T(STR_UNKNOWN));
  lv_label_set_text(lbl_detail, sm_article_nr[0] ? sm_article_nr : "-");

  // (lbl_raw_info is now used for SM diff display, updated in loop)
}

// ============================================================
//  DATE HELPER
// ============================================================

// ISO date "YYYY-MM-DD" -> local format based on g_date_fmt:
//   0 = DD.MM.YYYY  (German style)
//   1 = YYYY-MM-DD  (ISO)
void isoToLocal(const char* iso, char* out, size_t len) {
  if (strlen(iso) >= 10 && iso[4] == '-' && iso[7] == '-') {
    if (g_date_fmt == 1) {
      // ISO belassen
      snprintf(out, len, "%.10s", iso);
    } else {
      // DD.MM.YYYY
      snprintf(out, len, "%.2s.%.2s.%.4s", iso+8, iso+5, iso);
    }
  } else {
    strncpy(out, iso, len-1);
    out[len-1] = '\0';
  }
}
// Legacy alias so all existing calls continue to work
void isoToDe(const char* iso, char* out, size_t len) { isoToLocal(iso, out, len); }

// Days since a localized date until today
// Supports DD.MM.YYYY (fmt 0) and YYYY-MM-DD (fmt 1)
int daysSince(const char* local_date) {
  if (!local_date || strlen(local_date) < 10) return -1;
  int day, month, year;
  if (g_date_fmt == 1) {
    // YYYY-MM-DD
    if (sscanf(local_date, "%d-%d-%d", &year, &month, &day) != 3) return -1;
  } else {
    // DD.MM.YYYY
    if (sscanf(local_date, "%d.%d.%d", &day, &month, &year) != 3) return -1;
  }
  struct tm ti;
  if (!getLocalTime(&ti)) return -1;
  // Datum als Unix-Timestamp
  struct tm then = {};
  then.tm_mday = day;
  then.tm_mon  = month - 1;
  then.tm_year = year - 1900;
  then.tm_hour = 12; then.tm_min = 0; then.tm_sec = 0;
  time_t t_then = mktime(&then);
  // Heute Mittag
  struct tm today = ti;
  today.tm_hour = 12; today.tm_min = 0; today.tm_sec = 0;
  time_t t_today = mktime(&today);
  if (t_then < 0 || t_today < 0) return -1;
  int days = (int)((t_today - t_then) / 86400);
  return days >= 0 ? days : -1;
}

// Drying date as display string: "DD.MM.YYYY  (N days ago)" or just date
void driedDisplayStr(const char* de_date, char* out, size_t len) {
  if (!de_date || strcmp(de_date, "-") == 0 || strlen(de_date) < 8) {
    strncpy(out, "-", len-1);
    return;
  }
  int days = daysSince(de_date);
  if (days < 0) {
    strncpy(out, de_date, len-1);
  } else if (days == 0) {
    snprintf(out, len, "%s  (%s)", de_date, T(STR_TODAY));
  } else if (days == 1) {
    snprintf(out, len, "%s  (%s)", de_date, T(STR_YESTERDAY));
  } else {
    char rel[32]; snprintf(rel, sizeof(rel), T(STR_DAYS_AGO), days);
    snprintf(out, len, "%s  (%s)", de_date, rel);
  }
}

// Same logic for last used
// ── Ampel: last_dried Label mit Farbe + Symbol setzen ────────
// Ruft driedDisplayStr + dryingAlertLevel auf und setzt Farbe/Symbol.
// lbl_sym darf nullptr sein (kein Symbol-Label).
static void applyDriedLabel(lv_obj_t* lbl_val, lv_obj_t* lbl_sym, const char* de_date) {
  if (!lbl_val) return;
  // Text
  char disp[56];
  driedDisplayStr(de_date, disp, sizeof(disp));
  lv_label_set_text(lbl_val, disp);
  // Ampel-Level
  int level = dryingAlertLevel(de_date);
  if (sd_verbose) logSDf("[verbose] applyDriedLabel: date=%s level=%d mode=%d", de_date, level, g_dry_mode);
  uint32_t col;
  if      (level == 2) col = 0xe04040;  // rot
  else if (level == 1) col = 0xf0b838;  // gelb
  else if (level == 0) col = 0x28d49a;  // gruen
  else                 col = 0x5090e0;  // kein Modus / kein Datum -> neutral blau
  lv_obj_set_style_text_color(lbl_val, lv_color_hex(col), 0);
  // Symbol (nur bei Warnung/Alarm)
  if (lbl_sym) {
    if (level == 1 || level == 2) {
      lv_label_set_text(lbl_sym, LV_SYMBOL_WARNING);
      lv_obj_set_style_text_color(lbl_sym, lv_color_hex(col), 0);
      lv_obj_clear_flag(lbl_sym, LV_OBJ_FLAG_HIDDEN);
    } else {
      lv_obj_add_flag(lbl_sym, LV_OBJ_FLAG_HIDDEN);
    }
  }
}

// ============================================================
//  HELPER: Ampel-Level fuer last_dried (0=gruen,1=gelb,2=rot,-1=kein Datum)
// ============================================================
static int dryingAlertLevel(const char* last_dried_local) {
  if (g_dry_mode == 0) return -1;
  if (!last_dried_local || strlen(last_dried_local) < 8 || strcmp(last_dried_local, "-") == 0)
    return -1;
  int days = daysSince(last_dried_local);
  if (sd_verbose) logSDf("[verbose] dryingAlertLevel: date=%s days=%d mode=%d mat=%s", last_dried_local, days, g_dry_mode, sm_material_global);
  if (days < 0) return -1;
  int yellow_thresh = g_dry_man_yellow;
  int red_thresh    = g_dry_man_red;
  if (g_dry_mode == 1) {
    int mat_idx = -1;
    for (int i = 0; i < DRY_MAT_COUNT; i++) {
      if (strncasecmp(sm_material_global, DRY_MAT_NAMES[i], strlen(DRY_MAT_NAMES[i])) == 0) {
        mat_idx = i; break;
      }
    }
    if (mat_idx >= 0) {
      float mult = g_dry_mat_sealed[mat_idx] ? g_dry_mult_sealed : 1.0f;
      yellow_thresh = (int)(g_dry_mat_yellow[mat_idx] * mult);
      red_thresh    = (int)(g_dry_mat_red[mat_idx]    * mult);
    } else {
      // Unbekanntes Material im Material-Mode -> kein Signal
      if (sd_verbose) logSDf("[verbose] dryingAlertLevel: material '%s' not in list -> no alert", sm_material_global);
      return -1;
    }
  }
  if (days >= red_thresh)    return 2;
  if (days >= yellow_thresh) return 1;
  return 0;
}

// Sync NTP time (after WiFi connection)
void syncNTP() {
  configTime(3600, 3600, "pool.ntp.org", "time.nist.gov"); // UTC+1 + Sommerzeit
  Serial.print("NTP sync...");
  struct tm ti;
  for (int i = 0; i < 20; i++) {
    delay(500);
    if (getLocalTime(&ti)) {
      Serial.printf("OK! %02d.%02d.%04d\n", ti.tm_mday, ti.tm_mon+1, ti.tm_year+1900);
      return;
    }
    Serial.print(".");
  }
  Serial.println("NTP ERROR");
}

// Current date as ISO string "YYYY-MM-DD"
String getTodayISO() {
  struct tm ti;
  if (!getLocalTime(&ti)) return "2026-01-01";
  char buf[16];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02d", ti.tm_year+1900, ti.tm_mon+1, ti.tm_mday);
  return String(buf);
}

// ============================================================
//  CONNECT WIFI
// ============================================================
void wifiConnect() {
  Serial.printf("WiFi: %s\n", cfg_wifi_ssid);
  // Update status bar — may already be set from setup(), but ensure it's shown
  if (lbl_status) {
    char wifi_buf[32];
    strncpy(wifi_buf, T(STR_WIFI_CONNECTING_BOOT), sizeof(wifi_buf)-1);
    lv_label_set_text(lbl_status, wifi_buf);
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x5090e0), 0);
    lv_timer_handler();
  }
  if (wifiManagerConnect(cfg_wifi_ssid, cfg_wifi_password, 20, 500)) {
      wifi_ok = true;
      Serial.printf("WiFi OK! IP: %s\n", wifiManagerLocalIP().toString().c_str());
      updateHeaderStatus();
      syncNTP();
      // SD logging: write boot block once time is available
      if (sd_available) {
        cleanOldLogs();   // requires synced time
        writeBootBlock("Boot");
        logSDf("WiFi connected: %s | RSSI: %d dBm",
          cfg_wifi_ssid, wifiManagerRSSI());
      }
      // Fix 2: immediate Spoolman health check after WiFi connect
      if (strlen(cfg_spoolman_base) > 4) {
        int code = spoolmanGetHealthCode(cfg_spoolman_base, 3000);
        sm_reachable = (code == 200);
        logSDf("Spoolman health check: HTTP %d -> %s",
          code, sm_reachable ? "OK" : "FAIL");
        Serial.printf("Spoolman health: HTTP %d -> %s\n", code, sm_reachable ? "OK" : "FAIL");
        // Fetch Spoolman version from /api/v1/info
        if (sm_reachable) {
          char ver[32] = "?";
          if (spoolmanGetVersion(cfg_spoolman_base, ver, sizeof(ver), 3000)) {
            logSDf("Spoolman version: %s", ver);
            Serial.printf("Spoolman version: %s\n", ver);
          }
        }
      }
      updateHeaderStatus();
      lv_label_set_text(lbl_spoolman_weight, T(STR_WAIT_SCAN_SM));
      lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
      lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
      lv_timer_handler();
      // silent_ota_check_pending disabled
      return;
  }
  Serial.println("WiFi FAILED – continuing without Spoolman");
  logSD("WiFi connection FAILED");
  updateHeaderStatus();
  lv_label_set_text(lbl_spoolman_weight, T(STR_NO_WIFI));
  lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
  lv_timer_handler();
}

// ============================================================
//  SPOOLMAN QUERY BY ID
//  Used after link-flow — fetches only one spool by ID.
//  Fills same globals and labels as querySpoolman().
// ============================================================
void querySpoolmanById(int spool_id) {
  if (!wifi_ok) return;
  Serial.printf("querySpoolmanById: ID=%d\n", spool_id);
  logSDf("Spoolman: query by ID=%d", spool_id);
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (before byID GET)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  DynamicJsonDocument doc(8192);
  DeserializationError err = DeserializationError::Ok;
  int code = spoolmanGetSpoolJson(cfg_spoolman_base, spool_id, doc, 8000, &err);
  if (code != 200) {
    Serial.printf("querySpoolmanById HTTP error: %d\n", code);
    logSDf("Spoolman byID: HTTP error %d", code);
    if (code == -2) {
      Serial.println("querySpoolmanById: JSON error");
      logSD("Spoolman byID: JSON error");
    }
    return;
  }
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (after byID parse)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  JsonObject spool = doc.as<JsonObject>();
  bool is_bambu_tag = (strlen(g_tag.material) > 0);

  sm_found        = true;
  sm_id           = spool["id"] | 0;
  sm_filament_id  = spool["filament"]["id"] | 0;
  sm_vendor_id    = spool["filament"]["vendor"]["id"] | 0;
  sm_remaining    = spool["remaining_weight"] | 0.0f;
  sm_total        = spool["filament"]["weight"] | 1000.0f;
  sm_spool_weight = spool["spool_weight"] | 0.0f;
  logSDf("Spoolman: byID OK ID=%d remaining=%.1fg", sm_id, sm_remaining);

  String art_nr = spool["filament"]["article_number"] | "";
  art_nr.trim();
  strncpy(sm_article_nr, art_nr.c_str(), sizeof(sm_article_nr)-1);

  String fil_name = spool["filament"]["name"] | String("");
  fil_name.trim();
  strncpy(sm_filament_name, fil_name.c_str(), sizeof(sm_filament_name)-1);

  // Location — Spoolman gibt location als einfachen String zurück
  sm_location_id = 0;
  sm_location_name[0] = '\0';
  if (!spool["location"].isNull() && spool["location"].is<const char*>()) {
    String loc_name = spool["location"] | String("");
    loc_name.trim();
    strncpy(sm_location_name, loc_name.c_str(), sizeof(sm_location_name)-1);
  }

  // last_dried
  sm_last_dried[0] = '\0';
  if (spool.containsKey("extra") && spool["extra"].containsKey("last_dried")) {
    String dried = spool["extra"]["last_dried"].as<String>();
    dried.replace("\"", "");
    String iso = dried.substring(0, 10);
    char de_date[12];
    isoToDe(iso.c_str(), de_date, sizeof(de_date));
    strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
  } else {
    strncpy(sm_last_dried, "-", sizeof(sm_last_dried)-1);
  }

  // Material, vendor, color — only for NTAG (Bambu has it from tag itself)
  String sm_material = spool["filament"]["material"] | String("");
  sm_material.trim();
  String sm_vendor_name = "";
  if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull()) {
    sm_vendor_name = spool["filament"]["vendor"]["name"] | String("");
    sm_vendor_name.trim();
  }
  String sm_color = spool["filament"]["color_hex"] | String("");
  sm_color.trim();

  bool is_ntag = !is_bambu_tag;
  if (is_ntag) {
    lv_label_set_text(lbl_material, sm_material.length() > 0 ? sm_material.c_str() : "-");
    lv_label_set_text(lbl_vendor,   sm_vendor_name.length() > 0 ? sm_vendor_name.c_str() : "-");
    strncpy(sm_material_global, sm_material.c_str(), sizeof(sm_material_global)-1);
    sm_material_global[sizeof(sm_material_global)-1] = '\0';
    strncpy(sm_color_global, sm_color.c_str(), sizeof(sm_color_global)-1);
    sm_color_global[sizeof(sm_color_global)-1] = '\0';
  } else {
    // Bambu-Tag: Material aus g_tag.material in sm_material_global schreiben
    // damit dryingAlertLevel() das Material korrekt auflösen kann
    if (g_tag.material[0]) {
      strncpy(sm_material_global, g_tag.material, sizeof(sm_material_global)-1);
      sm_material_global[sizeof(sm_material_global)-1] = '\0';
    }
  }
  if (is_ntag && sm_color.length() >= 6) {
    String hex = sm_color;
    if (hex.startsWith("#")) hex = hex.substring(1);
    unsigned int r, g, b;
    sscanf(hex.c_str(), "%02X%02X%02X", &r, &g, &b);
    uint32_t col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
    lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(col), 0);
  }

  // Update display labels
  char weight_str[32];
  snprintf(weight_str, sizeof(weight_str), "%.0f g", sm_remaining);
  lv_label_set_text(lbl_spoolman_weight, weight_str);
  float pct = (sm_total > 0) ? (sm_remaining / sm_total) * 100.0f : 0;
  uint32_t pct_color;
  if (pct <= 10.0f)      pct_color = 0xe04040;
  else if (pct <= 30.0f) pct_color = 0xf0b838;
  else                   pct_color = 0x28d49a;
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(pct_color), 0);

  char pct_str[16];
  snprintf(pct_str, sizeof(pct_str), "%.1f %%", pct);
  lv_label_set_text(lbl_spoolman_pct, pct_str);
  lv_obj_set_style_text_color(lbl_spoolman_pct, lv_color_hex(pct_color), 0);

  if (lbl_scale_diff) {
    int bar_w = (int)((pct / 100.0f) * 190.0f);
    if (bar_w < 0) bar_w = 0;
    if (bar_w > 190) bar_w = 190;
    lv_obj_set_width(lbl_scale_diff, bar_w);
    lv_obj_set_style_bg_color(lbl_scale_diff, lv_color_hex(pct_color), 0);
  }

  char sm_id_str[16];
  snprintf(sm_id_str, sizeof(sm_id_str), "%d", sm_id);
  lv_label_set_text(lbl_spoolman_id, sm_id_str);
  lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0x28d49a), 0);

  char dried_display[48];
  driedDisplayStr(sm_last_dried, dried_display, sizeof(dried_display));
  applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, sm_last_dried);

  lv_label_set_text(lbl_detail,        strlen(sm_article_nr)    > 0 ? sm_article_nr    : "-");
  lv_label_set_text(lbl_filament_name, strlen(sm_filament_name) > 0 ? sm_filament_name : "-");

  // last_used
  if (spool.containsKey("last_used") && !spool["last_used"].isNull()) {
    String lu = spool["last_used"].as<String>();
    char de_lu[12];
    isoToDe(lu.substring(0, 10).c_str(), de_lu, sizeof(de_lu));
    strncpy(sm_last_used, de_lu, sizeof(sm_last_used)-1);
  } else {
    strncpy(sm_last_used, "-", sizeof(sm_last_used)-1);
  }
  char last_used_display[48];
  driedDisplayStr(sm_last_used, last_used_display, sizeof(last_used_display));
  lv_label_set_text(lbl_last_used, last_used_display);

  Serial.printf("querySpoolmanById OK: ID=%d %.1fg dried=%s\n", sm_id, sm_remaining, sm_last_dried);
  updateLinkButton();
}

// ============================================================
//  SPOOLMAN QUERY
//  Finds spool by tray_uuid in extra.tag field
// ============================================================
void querySpoolman(const char* tray_uuid) {
  if (!wifi_ok) return;
  logSDf("Spoolman: query tray_uuid=%.16s...", tray_uuid ? tray_uuid : "");

  // Reset all Spoolman labels before new query
  lv_label_set_text(lbl_spoolman_weight, T(STR_WAIT));
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_label_set_text(lbl_spoolman_dried_val, "");
  if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
  lv_label_set_text(lbl_detail, "-");
  lv_label_set_text(lbl_filament_name, "-");
  lv_label_set_text(lbl_last_used, "-");
  if (lbl_scale_diff) lv_obj_set_width(lbl_scale_diff, 0);
  if (lbl_spoolman_dried) lv_label_set_text(lbl_spoolman_dried, "");
  if (lbl_keys) lv_label_set_text(lbl_keys, "");
  if (lbl_raw_info) lv_label_set_text(lbl_raw_info, "");
  if (lbl_bag_sm_diff) lv_label_set_text(lbl_bag_sm_diff, "");
  // bei Bambu kommen diese Felder aus dem Tag selbst (updateDisplay) nicht aus Spoolman
  bool is_bambu_tag = (strlen(g_tag.material) > 0);
  if (!is_bambu_tag) {
    lv_label_set_text(lbl_material, "-");
    lv_label_set_text(lbl_vendor, "-");
    lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(0x333333), 0);
  }
  sm_last_dried[0] = '\0';
  sm_article_nr[0] = '\0';
  sm_filament_name[0] = '\0';
  sm_material_global[0] = '\0';
  sm_color_global[0] = '\0';
  sm_last_used[0] = '\0';
  sm_location_name[0] = '\0'; sm_location_id = 0;
  sm_found = false;
  sm_id = 0;
  sm_spool_weight = 0;
  sm_remaining = 0;
  sm_total = 1000;
  lv_timer_handler();

  Serial.printf("DBG free heap: %d bytes  free PSRAM: %d bytes\n", ESP.getFreeHeap(), ESP.getFreePsram());
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (before Spoolman GET)",
    ESP.getFreeHeap(), ESP.getFreePsram());

  // Filter: only parse needed fields — reduces RAM, works with 100+ spools
  // Filter must be Array-wrapped to match the API array response structure
  StaticJsonDocument<512> filter;
  JsonArray filter_arr = filter.to<JsonArray>();
  JsonObject filter_spool = filter_arr.createNestedObject();
  filter_spool["id"] = true;
  filter_spool["archived"] = true;
  filter_spool["remaining_weight"] = true;
  filter_spool["spool_weight"] = true;
  filter_spool["last_used"] = true;
  filter_spool["location"] = true;
  filter_spool["extra"]["tag"] = true;
  filter_spool["extra"]["last_dried"] = true;
  filter_spool["filament"]["id"] = true;
  filter_spool["filament"]["name"] = true;
  filter_spool["filament"]["material"] = true;
  filter_spool["filament"]["weight"] = true;
  filter_spool["filament"]["article_number"] = true;
  filter_spool["filament"]["color_hex"] = true;
  filter_spool["filament"]["vendor"]["id"] = true;
  filter_spool["filament"]["vendor"]["name"] = true;

  // Use PSRAM for this document — frees internal RAM for LVGL
  SpiRamAllocator psram_alloc;
  JsonDocument doc(&psram_alloc);
  DeserializationError err = DeserializationError::Ok;

  // Up to 2 attempts: first try, then 1 retry on IncompleteInput / connection issues.
  // 20s timeout is generous for large Spoolman datasets (200+ spools over WiFi).
  for (int attempt = 1; attempt <= 2; attempt++) {
    if (attempt > 1) {
      Serial.printf("Spoolman: retry attempt %d after %s\n", attempt, err.c_str());
      logSDf("Spoolman: retry attempt %d (prev err=%s)", attempt, err.c_str());
      delay(300);  // brief pause before retry
      doc.clear();
    }

    int code = spoolmanGetSpoolListJson(cfg_spoolman_base, false, doc, 20000, &filter, &err);
    if (code != 200) {
      Serial.printf("Spoolman HTTP error: %d (attempt %d)\n", code, attempt);
      logSDf("Spoolman: HTTP error %d (attempt %d)", code, attempt);
      if (attempt == 2) {
        lv_label_set_text(lbl_spoolman_weight, code == -2 ? T(STR_LINK_JSON_ERR) : T(STR_API_ERROR));
        return;
      }
      if (code == -2 &&
          err != DeserializationError::IncompleteInput &&
          err != DeserializationError::EmptyInput) {
        break;
      }
      continue;  // retry on HTTP or transient parse error too
    }

    // Stream directly from HTTP — avoids allocating a 40KB+ String in RAM

    if (!err) break;  // success
    // Parse failed -> retry only on transient stream issues
    if (err != DeserializationError::IncompleteInput &&
        err != DeserializationError::EmptyInput) {
      break;  // other errors are not transient -> don't retry
    }
  }

  Serial.printf("DBG free heap after parse: %d bytes  free PSRAM: %d bytes\n", ESP.getFreeHeap(), ESP.getFreePsram());
  if (sd_verbose) logSDf("[verbose] heap=%d PSRAM=%d (after Spoolman parse)",
    ESP.getFreeHeap(), ESP.getFreePsram());
  if (err) {
    Serial.printf("Spoolman JSON error (final): %s\n", err.c_str());
    logSDf("Spoolman: JSON error final=%s", err.c_str());
    lv_label_set_text(lbl_spoolman_weight, T(STR_LINK_JSON_ERR));
    return;
  }

  JsonArray spools = doc.as<JsonArray>();
  for (JsonObject spool : spools) {
    if (!spool.containsKey("extra")) continue;
    JsonObject extra = spool["extra"];
    if (!extra.containsKey("tag")) continue;

    String tag_val = extra["tag"].as<String>();
    tag_val.replace("\"", "");
    tag_val.trim();

    if (!tag_val.equalsIgnoreCase(tray_uuid)) continue;

    // FOUND
    sm_found    = true;
    sm_id       = spool["id"] | 0;
    sm_filament_id = spool["filament"]["id"] | 0;
    sm_vendor_id   = spool["filament"]["vendor"]["id"] | 0;
    sm_remaining = spool["remaining_weight"] | 0.0f;
    sm_total    = spool["filament"]["weight"] | 1000.0f;
    sm_spool_weight = spool["spool_weight"] | 0.0f;
    logSDf("Spoolman: found ID=%d remaining=%.1fg total=%.0fg",
      sm_id, sm_remaining, sm_total);
    logSDf("[verbose] LOC: querySpoolman id=%d shown_for=%d", sm_id, g_loc_popup_shown_for_id);
    String art_nr = spool["filament"]["article_number"] | "";
    art_nr.trim();
    strncpy(sm_article_nr, art_nr.c_str(), sizeof(sm_article_nr)-1);
    String fil_name = spool["filament"]["name"] | String("");
    fil_name.trim();
    strncpy(sm_filament_name, fil_name.c_str(), sizeof(sm_filament_name)-1);

    // Location — einfacher String in Spoolman
    sm_location_name[0] = '\0';
    if (!spool["location"].isNull() && spool["location"].is<const char*>()) {
      String loc = spool["location"] | String("");
      loc.trim();
      strncpy(sm_location_name, loc.c_str(), sizeof(sm_location_name)-1);
    }
    if (extra.containsKey("last_dried")) {
      String dried = extra["last_dried"].as<String>();
      dried.replace("\"", "");
      String iso = dried.substring(0, 10);
      char de_date[12];
      isoToDe(iso.c_str(), de_date, sizeof(de_date));
      strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
    } else {
      strncpy(sm_last_dried, "-", sizeof(sm_last_dried)-1);
    }

    Serial.printf("Spoolman: ID=%d, %.1fg, dried: %s\n",
      sm_id, sm_remaining, sm_last_dried);

    // Read material, vendor, color from Spoolman
    // → shown when no Bambu tag (g_tag.material empty)
    String sm_material = spool["filament"]["material"] | String("");
    sm_material.trim();
    String sm_vendor_name = "";
    if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull()) {
      sm_vendor_name = spool["filament"]["vendor"]["name"] | String("");
      sm_vendor_name.trim();
    }
    String sm_color = spool["filament"]["color_hex"] | String("");
    sm_color.trim();

    // Only fill fields from Spoolman if no Bambu tag present
    bool is_ntag = !is_bambu_tag;
    Serial.printf("is_ntag=%d material='%s' vendor='%s' color='%s'\n",
      is_ntag, sm_material.c_str(), sm_vendor_name.c_str(), sm_color.c_str());
    if (is_ntag) {
      lv_label_set_text(lbl_material, sm_material.length() > 0 ? sm_material.c_str() : "-");
      lv_label_set_text(lbl_vendor, sm_vendor_name.length() > 0 ? sm_vendor_name.c_str() : "-");
      strncpy(sm_material_global, sm_material.c_str(), sizeof(sm_material_global)-1);
      sm_material_global[sizeof(sm_material_global)-1] = '\0';
      strncpy(sm_color_global, sm_color.c_str(), sizeof(sm_color_global)-1);
      sm_color_global[sizeof(sm_color_global)-1] = '\0';
      // Color swatch from Spoolman color_hex (#RRGGBB or RRGGBB)
      if (sm_color.length() >= 6) {
        String hex = sm_color;
        if (hex.startsWith("#")) hex = hex.substring(1);
        unsigned int r, g, b;
        sscanf(hex.c_str(), "%02X%02X%02X", &r, &g, &b);
        uint32_t col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
        lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(col), 0);
        Serial.printf("Color set: #%06X\n", col);
      }
    }

    // Update display — Fix 5: color based on remaining %
    char weight_str[32];
    snprintf(weight_str, sizeof(weight_str), "%.0f g", sm_remaining);
    lv_label_set_text(lbl_spoolman_weight, weight_str);
    float pct = (sm_total > 0) ? (sm_remaining / sm_total) * 100.0f : 0;

    // Choose color: 0-10% red, 11-30% orange, 31-100% green
    uint32_t pct_color;
    if (pct <= 10.0f)       pct_color = 0xe04040;
    else if (pct <= 30.0f)  pct_color = 0xf0b838;
    else                    pct_color = 0x28d49a;

    lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(pct_color), 0);

    char pct_str[16];
    snprintf(pct_str, sizeof(pct_str), "%.1f %%", pct);
    lv_label_set_text(lbl_spoolman_pct, pct_str);
    lv_obj_set_style_text_color(lbl_spoolman_pct, lv_color_hex(pct_color), 0);

    // Update progress bar fill width (max 190px) with same color
    if (lbl_scale_diff) {
      int bar_w = (int)((pct / 100.0f) * 190.0f);
      if (bar_w < 0) bar_w = 0;
      if (bar_w > 190) bar_w = 190;
      lv_obj_set_width(lbl_scale_diff, bar_w);
      lv_obj_set_style_bg_color(lbl_scale_diff, lv_color_hex(pct_color), 0);
    }

    // Show SM-ID in green (linked)
    char sm_id_str[16];
    snprintf(sm_id_str, sizeof(sm_id_str), "%d", sm_id);
    lv_label_set_text(lbl_spoolman_id, sm_id_str);
    lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0x28d49a), 0);

    // Last drying: set value with "N days ago"
    char dried_display[48];
    driedDisplayStr(sm_last_dried, dried_display, sizeof(dried_display));
    applyDriedLabel(lbl_spoolman_dried_val, lbl_dried_sym, sm_last_dried);

    lv_label_set_text(lbl_detail, strlen(sm_article_nr) > 0 ? sm_article_nr : "-");
    lv_label_set_text(lbl_filament_name, strlen(sm_filament_name) > 0 ? sm_filament_name : "-");

    // last_used is directly in the spool object (not in extra!)
    if (spool.containsKey("last_used") && !spool["last_used"].isNull()) {
      String lu = spool["last_used"].as<String>();
      char de_lu[12]; isoToDe(lu.substring(0, 10).c_str(), de_lu, sizeof(de_lu));
      strncpy(sm_last_used, de_lu, sizeof(sm_last_used)-1);
    } else {
      strncpy(sm_last_used, "-", sizeof(sm_last_used)-1);
    }
    char last_used_display[48];
    driedDisplayStr(sm_last_used, last_used_display, sizeof(last_used_display));
    lv_label_set_text(lbl_last_used, last_used_display);

    updateLinkButton();
    return;
  }

  // Not found in active spools — check if archived
  Serial.println("Spoolman: not in active spools, checking archive...");
  doc.clear();  // RAM freigeben vor zweitem Call

  // Second call with allow_archived=true
  DynamicJsonDocument doc2(16384);
  DeserializationError err2 = DeserializationError::Ok;
  StaticJsonDocument<256> filter2;
  JsonArray filter2_arr = filter2.to<JsonArray>();
  JsonObject f2 = filter2_arr.createNestedObject();
  f2["id"] = true;
  f2["archived"] = true;
  f2["extra"]["tag"] = true;
  int code2 = spoolmanGetSpoolListJson(cfg_spoolman_base, true, doc2, 8000, &filter2, &err2);
  if (code2 == 200) {
    if (!err2) {
      JsonArray spools2 = doc2.as<JsonArray>();
      for (JsonObject spool : spools2) {
        // Only check truly archived spools (explicit bool cast needed for JsonVariant)
        bool is_archived = spool["archived"].as<bool>();
        if (!is_archived) continue;
        if (!spool.containsKey("extra")) continue;
        JsonObject extra = spool["extra"];
        if (!extra.containsKey("tag")) continue;
        String tag_val = extra["tag"].as<String>();
        tag_val.replace("\"", ""); tag_val.trim();
        if (!tag_val.equalsIgnoreCase(tray_uuid)) continue;
        // Archived spool found
        Serial.printf("Spoolman: spool archived (ID=%d)\n", spool["id"] | 0);
        lv_label_set_text(lbl_spoolman_weight, T(STR_ARCHIVED));
        lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x808080), 0);
        lv_label_set_text(lbl_spoolman_pct, "");
        lv_label_set_text(lbl_spoolman_dried_val, "-");
        if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
        lv_label_set_text(lbl_last_used, "-");
        lv_label_set_text(lbl_detail, "-");
        lv_label_set_text(lbl_filament_name, "-");
        // Reset progress bar and diff labels
        if (lbl_scale_diff) lv_obj_set_width(lbl_scale_diff, 0);
        if (lbl_spoolman_dried) lv_label_set_text(lbl_spoolman_dried, "");
        if (lbl_keys) lv_label_set_text(lbl_keys, "");
        sm_found = false;
        updateLinkButton();
        return;
      }
    }
  }

  // Truly not found
  Serial.println("Spoolman: spool not found");
  logSD("Spoolman: spool not found");
  lv_label_set_text(lbl_spoolman_weight, T(STR_NOT_IN_SPOOLMAN));
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  sm_found = false;
  updateLinkButton();
}

// ============================================================
//  POWER MANAGEMENT
// ============================================================

void resetActivityTimer() {
  last_activity_ms = millis();
  if (is_dimmed) {
    displaySetBrightness((uint8_t)bright_normal);
    is_dimmed = false;
  }
}

void handlePowerManagement() {
  unsigned long elapsed = millis() - last_activity_ms;

  if (elapsed >= sleep_timeout_ms) {
    Serial.println("Deep sleep...");
    logSD("Deep sleep: entering");
    displayPrepareDeepSleep();
    delay(100);
    esp_deep_sleep_start();
  }

  if (!is_dimmed && elapsed >= dim_timeout_ms) {
    displaySetBrightness(BRIGHT_DIM_DEFAULT);
    is_dimmed = true;
  }
}

// ============================================================
//  SETUP
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("=== SpoolmanScale " FW_VERSION " ===");
  Serial.println("KDF Master: 9a759cf2c4f7caff222cb9769b41bc96");
  Serial.println("Context:    RFID-B");

  loadPrefs();

  // SD card init (early so logs can capture boot sequence)
  // Note: cleanOldLogs() is deferred until after NTP sync (in wifiConnect)
  initSD();

  displayHardwareBegin(resetActivityTimer);

  I2C_EXT.begin(hw_pins::I2C_EXT_SDA, hw_pins::I2C_EXT_SCL, 100000);

  // Build UI immediately after display init — user sees screen right away
  // lbl_status shows STR_BOOTING until wifiConnect() completes
  buildUI();
  lv_timer_handler();
  updateHeaderStatus();

  delay(500);

  Serial.print("Looking for PN532... ");
  uint32_t ver = 0;
  if (nfcHardwareBegin(&I2C_EXT, hw_pins::PN532_RESET, &ver)) {
    nfc_ok = true;
    Serial.printf("OK (FW %d.%d)\n", (ver >> 16) & 0xFF, (ver >> 8) & 0xFF);
    logSDf("NFC ready (PN532 FW %d.%d)", (ver >> 16) & 0xFF, (ver >> 8) & 0xFF);
  } else {
    Serial.println("ERROR!");
    logSD("NFC init FAILED");
  }

  Serial.print("Looking for NAU7802... ");
  if (scaleHardwareBegin(&I2C_EXT, [](){
    Serial.print(".");
    delay(100);
    lv_tick_inc(100);
    lv_timer_handler();
  })) {
    scl_ok = true;
    scale_ready = true;
    Serial.printf("OK! cal_factor=%.4f  zero_offset=%d\n", cal_factor, zero_offset);
    logSDf("Scale ready (cal=%.4f zero=%d)", cal_factor, zero_offset);
  } else {
    Serial.println("ERROR! NAU7802 not found (address 0x2A)");
    logSD("Scale init FAILED");
  }

  updateHeaderStatus();
  Serial.println("Ready. Hold spool near reader...");

  // Boot logic:
  // 1. lang_set=false → language selection (always first)
  // 2. lang_set=true, first_boot=true, SSID empty → first boot welcome screen (in correct language)
  // 3. lang_set=true, first_boot=false, SSID empty → WiFi setup (direct, no welcome)
  // 4. lang_set=true, SSID set → normal start
  if (!cfg_lang_set) {
    Serial.println("First install -> language selection");
    showWelcomeScreen();
  } else if (cfg_first_boot && strlen(cfg_wifi_ssid) == 0) {
    Serial.println("First boot -> welcome screen (language already set)");
    showFirstBootScreen();
  } else if (strlen(cfg_wifi_ssid) == 0) {
    Serial.println("SSID empty -> WiFi setup");
    showWifiSetupScreen();
  } else {
    wifiConnect();
  }
}

// ============================================================
//  LOOP
// ============================================================
unsigned long last_counter_ms = 0;
int loop_count = 0;

void loop() {
  lv_tick_inc(5);
  lv_timer_handler();
  handlePowerManagement();

  // ── Loop heartbeat (every 5s, verbose only) ──────────────
  // Helps diagnose freezes: last heartbeat timestamp = roughly when loop stopped
  static unsigned long last_heartbeat_ms = 0;
  static uint32_t heartbeat_count = 0;
  if (sd_verbose && millis() - last_heartbeat_ms >= 5000) {
    last_heartbeat_ms = millis();
    heartbeat_count++;
    logSDf("[verbose] heartbeat #%u heap=%d PSRAM=%d uptime=%lus",
      heartbeat_count, ESP.getFreeHeap(), ESP.getFreePsram(), millis() / 1000);
  }

  // OTA web server bedienen wenn aktiv
  handleOtaServerClient();

  // Silent background OTA auto-check disabled

  // Extra fields check/create — deferred from LVGL event callback to loop
  if (extra_fields_check_pending) {
    extra_fields_check_pending = false;
    checkAndCreateExtraFields(false);
  }
  if (extra_fields_create_pending) {
    extra_fields_create_pending = false;
    checkAndCreateExtraFields(true);
  }
  if (cal_reminder_pending) {
    cal_reminder_pending = false;
    showCalReminderScreen();
  }
  if (show_id_input_pending) {
    show_id_input_pending = false;
    id_input_open = false;
    link_id_lookup_pending = 0;
    copy_id_lookup_pending = 0;
    if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
    lbl_link_id_display = nullptr;
    lbl_link_id_status  = nullptr;
    // Clean up entry popups if they were hidden by X button
    if (scr_copy_entry && (lv_obj_has_flag(scr_copy_entry, LV_OBJ_FLAG_HIDDEN))) {
      lv_obj_del(scr_copy_entry); scr_copy_entry = nullptr;
    }
    if (scr_link_entry && (lv_obj_has_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN))) {
      lv_obj_del(scr_link_entry); scr_link_entry = nullptr;
    }
  }
  if (show_id_input_rebuild) {
    show_id_input_rebuild = false;
    link_id_lookup_pending = 0;
    copy_id_lookup_pending = 0;
    link_id_input[0] = '\0';
    lbl_link_id_display = nullptr;
    lbl_link_id_status  = nullptr;
    // Delete old numpad BEFORE showIdInputPopup — prevents residual touch events
    // from firing the confirm callback during lv_obj_del inside showIdInputPopup
    if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
    // Free the single-slot link_spools buffer allocated during the failed lookup
    // so the next lookup starts with a clean slate and no out-of-bounds risk
    if (link_spools != nullptr) {
      free(link_spools);
      link_spools = nullptr;
    }
    link_spool_count = 0;
    // Pump LVGL twice to flush all residual events from the deleted screen
    lv_timer_handler();
    lv_timer_handler();
    // Clear all pending flags AFTER pump — residual confirm-callbacks may have re-set them
    link_id_lookup_pending = 0;
    copy_id_lookup_pending = 0;
    showIdInputPopup(link_flow_is_bambu);
  }
  if (copy_confirm_pending) {
    copy_confirm_pending = false;
    // Hide copy list (keep it for cancel-back navigation), delete others
    if (scr_copy_list) lv_obj_add_flag(scr_copy_list, LV_OBJ_FLAG_HIDDEN);
    if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
    if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
    if (scr_link_mat_sub){ lv_obj_del(scr_link_mat_sub);scr_link_mat_sub= nullptr; }
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_copy_entry)  { lv_obj_del(scr_copy_entry);  scr_copy_entry  = nullptr; }
    showCopyConfirmPopup(copy_confirm_fid, copy_confirm_name,
                        copy_confirm_remaining, copy_confirm_initial, copy_confirm_spool_w);
  }
  // link_id_lookup_pending removed — direct call in callback (was causing PANIC)
  if (link_id_lookup_pending > 0 && scr_link_warn_a == nullptr && scr_link_warn_b == nullptr) {
    int pid = link_id_lookup_pending;
    bool pbambu = link_id_lookup_is_bambu;
    link_id_lookup_pending = 0;
    // Close numpad before HTTP call
    if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
    lbl_link_id_display = nullptr; lbl_link_id_status = nullptr;
    id_input_open = false;
    linkIdLookupAndPatch(pid, pbambu);
  }
  if (copy_id_lookup_pending > 0) {
    int cid = copy_id_lookup_pending;
    copy_id_lookup_pending = 0;
    // Fetch spool data for copy confirm — done in loop to avoid stack overflow in lambda
    DynamicJsonDocument cdoc(1024);
    DeserializationError derr2 = DeserializationError::Ok;
    int hcode = spoolmanGetSpoolJson(cfg_spoolman_base, cid, cdoc, 5000, &derr2);
    if (hcode != 200) {
      if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_ID_NOT_FOUND));
    } else {
      if (!derr2) {
        int cfid   = cdoc["filament"]["id"] | 0;
        float cini = cdoc["filament"]["weight"] | 1000.0f;
        float cspw = cdoc["spool_weight"] | 0.0f;
        float crem = cdoc["remaining_weight"] | 0.0f;
        const char *cfname = cdoc["filament"]["name"] | "?";
        const char *cfmat  = cdoc["filament"]["material"] | "";
        const char *cfvnd  = cdoc["filament"]["vendor"]["name"] | "";
        char ctmpl[80];
        snprintf(ctmpl, sizeof(ctmpl), "%s %s (%s)", cfmat, cfname, cfvnd);
        lbl_link_id_display = nullptr;
        lbl_link_id_status  = nullptr;
        if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
        showCopyConfirmPopup(cfid, ctmpl, crem, cini, cspw);
      } else {
        if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_JSON_ERR));
      }
    }
  }
  if (show_bag_pending) {
    show_bag_pending = false;
    if (!scr_bag) buildBagScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_bag, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_factor_pending) {
    show_factor_pending = false;
    showFactorScreen();
  }
  if (show_drying_reminder_pending) {
    show_drying_reminder_pending = false;
    showDryingReminderScreen();
    lv_obj_clear_flag(scr_drying_reminder, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_lastused_pending) {
    show_lastused_pending = false;
    // Always rebuild for fresh button states (active mode highlighting)
    if (scr_lastused) { lv_obj_del(scr_lastused); scr_lastused = nullptr; }
    buildLastUsedScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_lastused, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_spoolman_pending) {
    show_spoolman_pending = false;
    // Always rebuild — sp_ip_input is reset on entry
    if (scr_spoolman) { lv_obj_del(scr_spoolman); scr_spoolman = nullptr; }
    if (scr_spoolman_fail) { lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
    buildSpoolmanScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_spoolman, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_connection_from_spoolman_pending) {
    show_connection_from_spoolman_pending = false;
    if (scr_spoolman)   { lv_obj_del(scr_spoolman);   scr_spoolman   = nullptr; }
    if (scr_connection) { lv_obj_del(scr_connection); scr_connection = nullptr; }
    buildConnectionScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_ota_pending) {
    show_ota_pending = false;
    if (scr_ota) { lv_obj_del(scr_ota); scr_ota = nullptr; }
    buildOtaScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_ota, LV_OBJ_FLAG_HIDDEN);
  }
  if (show_info_pending) {
    show_info_pending = false;
    if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
    showInfoScreen();  // builds + shows scr_info
  }
  if (show_location_picker_pending) {
    show_location_picker_pending = false;
    logSDf("[verbose] LOC: show_location_picker_pending fired from_popup=%d id=%d", (int)g_loc_picker_from_popup, sm_id);
    showLocationPicker();
  }
  // Debounced auto-location popup — fires 2500ms after tag removal, only if tag still absent
  if (loc_popup_pending_id > 0 && !tag_present && (millis() - last_tag_seen_ms) >= 2500) {
    int pending_id = loc_popup_pending_id;
    loc_popup_pending_id = -1;
    if (g_loc_popup_shown_for_id != pending_id && sm_id == pending_id) {
      logSDf("[verbose] LOC: debounce fired, showing popup id=%d", pending_id);
      g_loc_popup_shown_for_id = pending_id;
      g_loc_picker_from_popup = true;
      show_location_picker_pending = true;
    } else {
      logSDf("[verbose] LOC: debounce cancelled id=%d shown_for=%d sm_id=%d", pending_id, g_loc_popup_shown_for_id, sm_id);
    }
  }
  // Cancel pending popup if tag came back
  if (loc_popup_pending_id > 0 && tag_present) {
    logSDf("[verbose] LOC: debounce cancelled — tag back id=%d", loc_popup_pending_id);
    loc_popup_pending_id = -1;
  }
  if (fetch_locations_pending) {
    fetch_locations_pending = false;
    fetchAndFillLocationList();
  }
  if (show_more_info_pending) {
    show_more_info_pending = false;
    buildMoreInfoScreen();
  }
  if (show_system_pending) {
    show_system_pending = false;
    // Coming back from OTA / Info / Language to System screen
    if (scr_ota)         { lv_obj_del(scr_ota);         scr_ota         = nullptr; }
    if (scr_ota_browser) { lv_obj_del(scr_ota_browser); scr_ota_browser = nullptr; }
    if (scr_ota_github)  { lv_obj_del(scr_ota_github);  scr_ota_github  = nullptr; }
    if (scr_info)        { lv_obj_del(scr_info);        scr_info        = nullptr; }
    if (scr_system)      { lv_obj_del(scr_system);      scr_system      = nullptr; }
    buildSystemScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_system, LV_OBJ_FLAG_HIDDEN);
  }
  if (skip_setup_pending) {
    skip_setup_pending = false;
    if (scr_welcome)    { lv_obj_del(scr_welcome);    scr_welcome    = nullptr; }
    if (scr_first_boot) { lv_obj_del(scr_first_boot); scr_first_boot = nullptr; }
    showMainScreen();
  }
  if (lang_selected_no_reboot) {
    lang_selected_no_reboot = false;
    if (scr_welcome) { lv_obj_del(scr_welcome); scr_welcome = nullptr; }
    showFirstBootScreen();
  }
  // Hide tare confirmation
  if (tare_msg_ms > 0 && millis() - tare_msg_ms > 800) {
    if (lbl_ok_ptr) { lv_obj_del(lbl_ok_ptr); lbl_ok_ptr = nullptr; }
    tare_msg_ms = 0;
  }

  // No-tag timer: clear display if no tag detected for too long
  // Only clear if truly no tag present (tag_present=false)
  if (!tag_present && sm_found &&
      last_tag_seen_ms > 0 && millis() - last_tag_seen_ms > NO_TAG_CLEAR_MS) {
    clearTagDisplay();
    last_tag_seen_ms = 0;
    spoolman_queried_uid[0] = '\0';
  }

  // Fill display with new tag data
  if (g_tag_ready) {
    g_tag_ready = false;
    g_tag_displayed = true;
    g_tag_shown_ms = millis();
    updateDisplay();
    if (!id_input_open && strlen(g_tag.tray_uuid) == 32 && strcmp(g_tag.uid_str, spoolman_queried_uid) != 0) {
      querySpoolman(g_tag.tray_uuid);
      strncpy(spoolman_queried_uid, g_tag.uid_str, sizeof(spoolman_queried_uid));
      if (!sm_found && wifi_ok) {
        link_tag_first_seen_ms = millis();
        link_popup_dismissed = false;
      }
    }
  }

  // After 10s reset status line to "searching" (data stays visible!)
  if (g_tag_displayed && millis() - g_tag_shown_ms > 10000) {
    g_tag_displayed = false;
    lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
    lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0xf0b838), 0);  // yellow
    lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
    lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
  }

  // NAU7802: read weight every 200ms and update labels
  if (scale_ready && millis() - last_scale_ms >= 200) {
    last_scale_ms = millis();
    int32_t raw = scaleHardwareReadRaw();
    float raw_g = (float)(raw - zero_offset) / cal_factor;

    // Moving average over SCALE_FILTER_SIZE readings
    scale_filter_buf[scale_filter_idx] = raw_g;
    scale_filter_idx = (scale_filter_idx + 1) % SCALE_FILTER_SIZE;
    if (scale_filter_idx == 0) scale_filter_full = true;
    int count = scale_filter_full ? SCALE_FILTER_SIZE : scale_filter_idx;
    float sum = 0;
    for (int i = 0; i < count; i++) sum += scale_filter_buf[i];
    scale_weight_g = sum / count;

    char w_str[16];
    // Fix 4: show filament netto (without spool) as big scale value
    if (sm_spool_weight > 0) {
      float netto = scale_weight_g - sm_spool_weight;
      if (netto < 0) netto = 0;
      fmtG(w_str, sizeof(w_str), netto);
    } else {
      fmtG(w_str, sizeof(w_str), scale_weight_g);
    }
    lv_label_set_text(lbl_scale_weight, w_str);
    // Also update live weight in calibration screen if open
    if (lbl_factor_cal_weight && scr_factor && !lv_obj_has_flag(scr_factor, LV_OBJ_FLAG_HIDDEN)) {
      char cal_str[16];
      fmtG(cal_str, sizeof(cal_str), scale_weight_g);  // Fix 6: raw weight
      lv_label_set_text(lbl_factor_cal_weight, cal_str);
    }

    // Fix 4: update live/bag below, SM diff next to netto
    if (sm_found && sm_spool_weight > 0) {
      float netto = scale_weight_g - sm_spool_weight;
      if (netto < 0) netto = 0;

      // SM diff: filament netto vs Spoolman remaining
      if (lbl_raw_info && sm_remaining > 0) {
        float sm_diff = netto - sm_remaining;
        char sd_str[16];
        snprintf(sd_str, sizeof(sd_str), sm_diff >= 0 ? "+%.0f g" : "%.0f g", sm_diff);
        lv_label_set_text(lbl_raw_info, sd_str);
        lv_obj_set_style_text_color(lbl_raw_info,
          sm_diff >= 0 ? lv_color_hex(0x40c080) : lv_color_hex(0xe04040), 0);
      }

      // Live total (with spool)
      if (lbl_spoolman_dried) {
        char lt_str[16];
        fmtG(lt_str, sizeof(lt_str), scale_weight_g);
        lv_label_set_text(lbl_spoolman_dried, lt_str);
        lv_obj_set_style_text_color(lbl_spoolman_dried, lv_color_hex(0x8ab0d8), 0);
      }

      // Fix 4: ohne Beutel = live - spool - bag; fixed color like scale netto; diff green/red
      if (lbl_keys) {
        float ohne_beutel = scale_weight_g - sm_spool_weight - bag_weight_g;
        if (ohne_beutel < 0) ohne_beutel = 0;
        char b_str[16];
        fmtG(b_str, sizeof(b_str), ohne_beutel);
        lv_label_set_text(lbl_keys, b_str);
        lv_obj_set_style_text_color(lbl_keys, lv_color_hex(0xf0b838), 0);  // same as scale netto

        // bag SM diff
        if (lbl_bag_sm_diff && sm_remaining > 0) {
          float bag_diff = ohne_beutel - sm_remaining;
          char bd_str[16];
          snprintf(bd_str, sizeof(bd_str), bag_diff >= 0 ? "+%.0f g" : "%.0f g", bag_diff);
          lv_label_set_text(lbl_bag_sm_diff, bd_str);
          lv_obj_set_style_text_color(lbl_bag_sm_diff,
            bag_diff >= 0 ? lv_color_hex(0x40c080) : lv_color_hex(0xe04040), 0);
        }
      }
    } else if (sm_found) {
      if (lbl_raw_info) lv_label_set_text(lbl_raw_info, "");
      if (lbl_bag_sm_diff) lv_label_set_text(lbl_bag_sm_diff, "");
      if (lbl_spoolman_dried) {
        char lt_str[16];
        fmtG(lt_str, sizeof(lt_str), scale_weight_g);
        lv_label_set_text(lbl_spoolman_dried, lt_str);
      }
      if (lbl_keys) lv_label_set_text(lbl_keys, "");
    } else {
      if (lbl_raw_info) lv_label_set_text(lbl_raw_info, "");
      if (lbl_bag_sm_diff) lv_label_set_text(lbl_bag_sm_diff, "");
      if (lbl_spoolman_dried) lv_label_set_text(lbl_spoolman_dried, "");
      if (lbl_keys) lv_label_set_text(lbl_keys, "");
    }
  }

  // ── Auto-Weight: Hintergrund-Stabilitaetserkennung + Countdown ──
  // aw_done: einmal gespeichert -> kein weiterer Patch bis Spule abgenommen
  if (g_auto_weight) {
    static int  aw_last_shown_s = -1;  // verhindert unnoetige Label-Updates
    static bool aw_done = false;       // diese Spule bereits gespeichert?

    // Spule abgenommen -> Reset fuer naechste Spule
    if (!tag_present && aw_done) {
      aw_done = false;
      auto_weight_stable_ms = 0;
      auto_weight_last_val = -9999.0f;
      aw_last_shown_s = -1;
      if (lbl_weight_main_lbl) {
        char wmbuf[48];
        snprintf(wmbuf, sizeof(wmbuf), "%s (A)",
          g_lang == LANG_DE ? "Gewicht updaten" : "Update Weight");
        lv_label_set_text(lbl_weight_main_lbl, wmbuf);
        lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x28d49a), 0);
      }
    }

    if (!aw_done && !confirm_popup && sm_found && sm_id > 0 && scale_ready && tag_present) {
      float cur = scale_weight_g;
      if (fabsf(cur - auto_weight_last_val) > AUTO_WEIGHT_THRESH_G) {
        // Gewicht bewegt sich -> Timer neu starten
        auto_weight_last_val = cur;
        auto_weight_stable_ms = millis();
        aw_last_shown_s = -1;
      } else if (auto_weight_stable_ms > 0 &&
                 millis() - auto_weight_stable_ms >= AUTO_WEIGHT_STABLE_MS) {
        // 3 Sekunden stabil -> einmalig speichern
        aw_done = true;
        auto_weight_stable_ms = 0;
        aw_last_shown_s = -1;
        float netto = cur - (float)sm_spool_weight;
        if (netto < 0) netto = 0;
        logSDf("Auto-Weight: %.1fg stabil (3s) -> patch %.1fg", cur, netto);
        // Haekchen im Button — bleibt bis Spule abgenommen wird
        if (lbl_weight_main_lbl) {
          char wmbuf[48];
          snprintf(wmbuf, sizeof(wmbuf), "%s " LV_SYMBOL_OK,
            g_lang == LANG_DE ? "Gewicht updaten" : "Update Weight");
          lv_label_set_text(lbl_weight_main_lbl, wmbuf);
          lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x40ff80), 0);
        }
        patchSpoolmanWeight(netto);
      } else if (auto_weight_stable_ms == 0) {
        auto_weight_last_val = cur;
        auto_weight_stable_ms = millis();
      } else {
        // Countdown: sekuendlich Button-Text aktualisieren
        unsigned long elapsed = millis() - auto_weight_stable_ms;
        int rem = (int)((AUTO_WEIGHT_STABLE_MS - elapsed) / 1000) + 1;
        if (rem < 1) rem = 1;
        if (rem != aw_last_shown_s && lbl_weight_main_lbl) {
          aw_last_shown_s = rem;
          char wmbuf[48];
          snprintf(wmbuf, sizeof(wmbuf), "%s %ds",
            g_lang == LANG_DE ? "Gewicht updaten" : "Update Weight", rem);
          lv_label_set_text(lbl_weight_main_lbl, wmbuf);
          lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x60f0c0), 0);
        }
      }
    } else if (!aw_done && !tag_present) {
      // Kein Tag, kein Countdown -> Idle-Text "(A)"
      if (auto_weight_stable_ms > 0) {
        auto_weight_stable_ms = 0;
        auto_weight_last_val = -9999.0f;
        aw_last_shown_s = -1;
      }
      if (aw_last_shown_s != 0 && lbl_weight_main_lbl) {
        aw_last_shown_s = 0;
        char wmbuf[48];
        snprintf(wmbuf, sizeof(wmbuf), "%s (A)",
          g_lang == LANG_DE ? "Gewicht updaten" : "Update Weight");
        lv_label_set_text(lbl_weight_main_lbl, wmbuf);
        lv_obj_set_style_text_color(lbl_weight_main_lbl, lv_color_hex(0x28d49a), 0);
      }
    }
  } else {
    // Auto AUS: Timer sauber halten
    if (auto_weight_stable_ms > 0) {
      auto_weight_stable_ms = 0;
      auto_weight_last_val = -9999.0f;
    }
  }

  // Fix 10: Spoolman health check every 30s
  if (wifi_ok) {
    static unsigned long last_sm_check_ms = 0;
    if (millis() - last_sm_check_ms >= 30000 && !id_input_open) {
      last_sm_check_ms = millis();
      int code = spoolmanGetHealthCode(cfg_spoolman_base, 3000);
      bool was_reachable = sm_reachable;
      sm_reachable = (code == 200);
      if (sm_reachable != was_reachable) updateHeaderStatus();
    }
  }

  // Periodic NAU7802 I2C ping every 5s (independent of WiFi)
  {
    static unsigned long last_scl_check_ms = 0;
    if (millis() - last_scl_check_ms >= 5000) {
      last_scl_check_ms = millis();
      I2C_EXT.beginTransmission(0x2A);
      bool prev = scl_ok;
      scl_ok = (I2C_EXT.endTransmission() == 0);
      if (scl_ok != prev) updateHeaderStatus();
    }
  }

  // ============================================================
  //  NFC SCAN LOGIC (0.4.21)
  //  - uidLen==4: MIFARE Classic → Bambu flow (unchanged)
  //  - uidLen==7: NTAG detected:
  //      "SPSC" magic → SpoolScale tag → querySpoolman by ID
  //      Blank (0x00) → show spool list + link
  //      Unknown      → ignore
  // ============================================================
  if (nfc_ok) {
    static unsigned long last_nfc_check_ms = 0;
    if (millis() - last_nfc_check_ms >= 500) {
      last_nfc_check_ms = millis();
      uint8_t uid[7], uidLen = 0;
      bool found = nfcReadPassiveTarget(uid, &uidLen, 150);

      if (found && uidLen == 4) {
        // ── MIFARE Classic (Bambu) ────────────────────────────
        last_tag_seen_ms = millis();
        tag_present = true;
        resetActivityTimer();

        char uid_str[24];
        snprintf(uid_str, sizeof(uid_str), "%02X:%02X:%02X:%02X",
          uid[0], uid[1], uid[2], uid[3]);

        bool uid_changed = (strcmp(uid_str, g_tag.uid_str) != 0);
        bool uuid_missing = (strlen(g_tag.tray_uuid) < 32);

        if (uid_changed) {
          Serial.printf("NFC: New Bambu UID %s\n", uid_str);
          nfc_retry_count = 0; nfc_absent_count = 0;
          lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
          lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);
          lv_label_set_text(lbl_status, T(STR_READING_TAG));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
          scanTag(uid, uidLen);
        } else if (uuid_missing && nfc_retry_count < NFC_MAX_RETRIES) {
          nfc_retry_count++;
          Serial.printf("NFC: tray_uuid empty, retry %d/%d\n", nfc_retry_count, NFC_MAX_RETRIES);
          lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
          lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);
          lv_label_set_text(lbl_status, T(STR_READING_TAG));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
          scanTag(uid, uidLen);
        } else {
          if (uuid_missing && nfc_retry_count >= NFC_MAX_RETRIES) {
            lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
            lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0xf0b838), 0);
            lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
            lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
          } else {
            // tray_uuid present — query Spoolman if not done yet
            if (!id_input_open && strcmp(g_tag.uid_str, spoolman_queried_uid) != 0 && strlen(g_tag.tray_uuid) == 32) {
              querySpoolman(g_tag.tray_uuid);
              strncpy(spoolman_queried_uid, g_tag.uid_str, sizeof(spoolman_queried_uid)-1);
              if (!sm_found && wifi_ok) {
                link_tag_first_seen_ms = millis();  // Start timer
                link_popup_dismissed = false;
              }
            } else if (!sm_found && !link_popup_dismissed && scr_link_entry == nullptr &&
                       wifi_ok && strlen(g_tag.tray_uuid) == 32) {
              // Auto-popup disabled — user uses the Link/Copy buttons in Zone 5
              (void)link_tag_first_seen_ms;
            }
            lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
            lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);
            lv_label_set_text(lbl_status, sm_found ? T(STR_TAG_FOUND) : T(STR_NOT_IN_SPOOLMAN));
            lv_obj_set_style_text_color(lbl_status,
              sm_found ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0b838), 0);
          }
        }

      } else if (found && uidLen == 7) {
        // ── NTAG detected ──────────────────────────────────────
        last_tag_seen_ms = millis();
        tag_present = true;
        resetActivityTimer();

        char uid_str[24];
        snprintf(uid_str, sizeof(uid_str), "%02X:%02X:%02X:%02X:%02X:%02X:%02X",
          uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]);

        Serial.printf("NFC: NTAG UID=%s\n", uid_str);

        bool uid_changed_ntag_log = (strcmp(uid_str, g_tag.uid_str) != 0);
        if (uid_changed_ntag_log) logSDf("NFC: NTAG UID=%s", uid_str);

        lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
        lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0x28d49a), 0);

        bool uid_changed_ntag = (strcmp(uid_str, g_tag.uid_str) != 0);

        if (uid_changed_ntag) {
          // New UID — clear old tag data
          strncpy(g_tag.uid_str, uid_str, sizeof(g_tag.uid_str)-1);
          g_tag.tray_uuid[0] = '\0';
          g_tag.material[0] = '\0';
          g_tag.color_hex[0] = '\0';
          g_tag.vendor[0] = '\0';
          spoolman_queried_uid[0] = '\0';
          lv_label_set_text(lbl_uid, uid_str);
          lv_label_set_text(lbl_tray_uuid, "-");
          lv_label_set_text(lbl_material, "-");
          lv_label_set_text(lbl_filament_name, "-");
          lv_label_set_text(lbl_vendor, "-");
          lv_label_set_text(lbl_detail, "-");
          lv_label_set_text(lbl_last_used, "-");
          lv_label_set_text(lbl_spoolman_dried_val, "-");
        if (lbl_dried_sym) lv_obj_add_flag(lbl_dried_sym, LV_OBJ_FLAG_HIDDEN);
          lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(0x333333), 0);
          lv_label_set_text(lbl_status, T(STR_READING_TAG));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
          lv_timer_handler();

          if (wifi_ok && !id_input_open) {
            querySpoolman(uid_str);
            strncpy(spoolman_queried_uid, uid_str, sizeof(spoolman_queried_uid)-1);

            if (!sm_found) {
              Serial.println("NTAG: not in Spoolman -> waiting for delay");
              strncpy(link_tag_uid, uid_str, sizeof(link_tag_uid)-1);
              link_tag_first_seen_ms = millis();
              link_popup_dismissed = false;
            } else {
              lv_label_set_text(lbl_status, T(STR_TAG_FOUND));
              lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
              strncpy(g_tag.tray_uuid, uid_str, sizeof(g_tag.tray_uuid)-1);
              updateLinkButton();
            }
          } else {
            lv_label_set_text(lbl_status, T(STR_TAG_FOUND));
            lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
          }
        } else {
          // Same UID — show popup after delay if not dismissed
          // Auto-popup disabled — user uses the Link/Copy buttons in Zone 5
          (void)link_tag_first_seen_ms;
          lv_label_set_text(lbl_status, sm_found ? T(STR_TAG_FOUND) : T(STR_NOT_IN_SPOOLMAN));
          lv_obj_set_style_text_color(lbl_status,
            sm_found ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0b838), 0);
        }

      } else {
        // No tag found
        if (tag_present) {
          nfc_absent_count++;
          if (nfc_absent_count < 4) return;  // wait for 4 consecutive misses (2s) before declaring removed
          nfc_absent_count = 0;
          Serial.println("NFC: tag removed");
          logSD("NFC: tag removed");
          tag_present = false;
          nfc_retry_count = 0; nfc_absent_count = 0;
          last_tag_seen_ms = millis();
          spoolman_queried_uid[0] = '\0';  // allow re-query when same tag is placed again
          link_popup_dismissed = false;   // Reset flag → next spool can show popup
          link_tag_first_seen_ms = 0;
          lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
          lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0xf0b838), 0);
          lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
          // Auto location popup: if enabled, spool is linked, and not shown for this spool yet
          // Debounce: only trigger after 1500ms — avoids spurious remove during NTAG read
          if (g_auto_loc_popup && sm_found && sm_id > 0 && wifi_ok && g_loc_popup_shown_for_id != sm_id) {
            loc_popup_pending_id = sm_id;  // schedule — will fire after debounce in loop
            logSDf("[verbose] LOC: tag removed, popup scheduled id=%d (debounce 2500ms)", sm_id);
          } else if (g_auto_loc_popup) {
            logSDf("[verbose] LOC: tag removed, popup suppressed id=%d shown_for=%d sm_found=%d wifi=%d", sm_id, g_loc_popup_shown_for_id, (int)sm_found, (int)wifi_ok);
          }
          // Do NOT close list — user should be able to select spool
          // even if tag is temporarily removed
        }
      }
    }
  }

  delay(5);
}
