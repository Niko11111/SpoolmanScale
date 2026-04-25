// ============================================================
//  SpoolmanScale – Bambu NFC Tag Reader & Decoder
//  Board:   WT32-SC01 Plus (ESP32-S3)
//  Version: v0.5.2-beta
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
#include <Adafruit_PN532.h>
#include <Adafruit_NAU7802.h>   // NAU7802 Waage ADC (I2C 0x2A)
#include <LovyanGFX.hpp>
#include <lvgl.h>
#include "mbedtls/md.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <WebServer.h>
#include <Update.h>
#include <ArduinoJson.h>

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
#include <Preferences.h>
// LVGL built-in QR-Code: LV_USE_QRCODE muss in lv_conf.h auf 1 gesetzt sein!
#include "extra/libs/qrcode/lv_qrcode.h"
#include "lang.h"

// ============================================================
//  FORWARD DECLARATIONS
// ============================================================
void resetActivityTimer();
void isoToDe(const char* iso, char* out, size_t len);
void driedDisplayStr(const char* de_date, char* out, size_t len);
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
void showIdInputPopup(bool is_bambu);
void closeIdInputPopup();
// ID-Eingabe: HTTP-Lookup und Verknuepfung (ausgelagert wegen Stack-Groesse in Lambda)
void linkIdLookupAndPatch(int entered_id, bool is_bambu);
void showWarnPopupA(int spool_id, const char* existing_tag, bool is_bambu, const char* link_uuid);
void showWarnPopupB(int spool_id, bool is_bambu);
void fetchAllSpoolsForLink();
void doLinkPatch(int spool_id, bool is_bambu);
void showVendorList();
void showMaterialList(const char* vendor_name);
void showFilteredSpoolList(const char* vendor_name, const char* material_prefix);
bool writeSpoolScaleTag(int spool_id, const char* uuid_hex);
bool readSpoolScaleTag(int* out_spool_id, char* out_uuid, size_t uuid_len);
void generateUUID(char* out, size_t len);
void updateHeaderStatus();
void showMoreInfoScreen();
void buildMoreInfoScreen();
void updateMoreInfoScreen();
void hideAllOverlays();
void showMainScreen();
void showSettingsScreen();
void buildConnectionScreen();
void buildScaleSubScreen();
void buildDisplayScreen();
void buildSystemScreen();
void buildOtaGithubScreen();
void showOtaGithubScreen();
void doGithubOtaCheck();
void doGithubOtaCheckSilent();
void doGithubOtaFlash(const char* version);
void showUpdateBadges(bool show);
void buildOtaScreen();
void buildOtaBrowserScreen();
void showOtaScreen();
void showOtaBrowserScreen();
void startOtaServer();
void stopOtaServer();
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
void buildSubHeader(lv_obj_t *parent, const char *title, lv_event_cb_t back_cb, const char *back_hint = nullptr);
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



// ============================================================
//  PINS
// ============================================================
#define I2C_SDA     10   // PN532 + NAU7802 Bus
#define I2C_SCL     11   // PN532 + NAU7802 Bus
#define TOUCH_SDA    6   // FT6336U interner Board-Bus
#define TOUCH_SCL    5   // FT6336U interner Board-Bus
#define LCD_BL_PIN        45
#define BRIGHT_NORMAL_DEFAULT  255   // 100% — Standardwert
#define BRIGHT_DIM_DEFAULT       77   // 30%  — Standardwert
#define DIM_TIMEOUT_DEFAULT   300000  // 5 Min — Standardwert
#define SLEEP_TIMEOUT_DEFAULT 1200000 // 20 Min — Standardwert

// Runtime variables (loaded from NVS, configurable via display menu)
static int     bright_normal   = BRIGHT_NORMAL_DEFAULT;
static int     dim_timeout_ms  = DIM_TIMEOUT_DEFAULT;
static int     sleep_timeout_ms = SLEEP_TIMEOUT_DEFAULT;
#define TOUCH_INT_PIN       7   // FT6336U INT fuer Wake-Up
#define FW_VERSION  "v0.5.2-beta"
#define DONATION_URL "ko-fi.com/formfollowsfunction"

// NAU7802 calibration
// CAL_FACTOR: raw value per gram. Determined via calibration and saved in NVS.
// Default 1.0 means: raw values are displayed directly as grams.
#define CAL_FACTOR_DEFAULT  1.0f

// Two separate I2C instances
// I2C_TOUCH: Bus 0, GPIO5/6  -> Touch controller
// I2C_EXT:   Bus 1, GPIO10/11 -> PN532 + NAU7802
TwoWire I2C_TOUCH = TwoWire(0);
TwoWire I2C_EXT   = TwoWire(1);

// NAU7802 scale (on I2C_EXT, address 0x2A)
Adafruit_NAU7802 nau;

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
static uint8_t last_used_mode = 0;                   // 0=OpenSpoolMan, 1=Last Weighed
Preferences prefs;

// ============================================================
//  BAMBU KDF – Master Key (from Bambu-Research-Group/RFID-Tag-Guide)
//  HKDF with SHA256, context "RFID-B\\0", 16 keys of 6 bytes each
// ============================================================
static const uint8_t BAMBU_MASTER_KEY[16] = {
  0x9a, 0x75, 0x9c, 0xf2, 0xc4, 0xf7, 0xca, 0xff,
  0x22, 0x2c, 0xb9, 0x76, 0x9b, 0x41, 0xbc, 0x96
};
static const uint8_t BAMBU_KDF_CONTEXT[] = "RFID-B";  // incl. \\0

// ============================================================
//  DISPLAY (LovyanGFX)
// ============================================================
class LGFX : public lgfx::LGFX_Device {
  lgfx::Panel_ST7796  _panel;
  lgfx::Bus_Parallel8 _bus;
  lgfx::Light_PWM     _light;
  lgfx::Touch_FT5x06  _touch;
public:
  LGFX(void) {
    { auto cfg = _bus.config();
      cfg.pin_wr=47; cfg.pin_rd=-1; cfg.pin_rs=0;
      cfg.pin_d0=9;  cfg.pin_d1=46; cfg.pin_d2=3;
      cfg.pin_d3=8;  cfg.pin_d4=18; cfg.pin_d5=17;
      cfg.pin_d6=16; cfg.pin_d7=15;
      _bus.config(cfg); _panel.setBus(&_bus); }
    { auto cfg = _panel.config();
      cfg.pin_cs=-1; cfg.pin_rst=4; cfg.pin_busy=-1;
      cfg.memory_width=320; cfg.memory_height=480;
      cfg.panel_width=320;  cfg.panel_height=480;
      cfg.invert=true; cfg.rgb_order=false;
      _panel.config(cfg); }
    { auto cfg = _light.config();
      cfg.pin_bl=LCD_BL_PIN; cfg.invert=false;
      cfg.freq=44100; cfg.pwm_channel=7;
      _light.config(cfg); _panel.setLight(&_light); }
    { auto cfg = _touch.config();
      cfg.x_min=0; cfg.x_max=319; cfg.y_min=0; cfg.y_max=479;
      cfg.pin_int=7; cfg.bus_shared=false; cfg.offset_rotation=0;
      cfg.i2c_port=0; cfg.i2c_addr=0x38;
      cfg.pin_sda=TOUCH_SDA; cfg.pin_scl=TOUCH_SCL; cfg.freq=400000;
      _touch.config(cfg); _panel.setTouch(&_touch); }
    setPanel(&_panel);
  }
};

// ============================================================
//  GLOBAL OBJECTS
// ============================================================
static LGFX tft;
static lv_disp_draw_buf_t draw_buf;
static lv_color_t disp_buf[480 * 10];

Adafruit_PN532 nfc(-1, 12, &I2C_EXT);  // IRQ=nicht verdrahtet, RST=GPIO12, Bus=I2C_EXT
bool nfc_ok = false;
bool scl_ok = false;          // NAU7802 scale connected

// Parsed tag data
struct BambuTagData {
  uint8_t  uid[4];
  char     uid_str[24];  // 4-byte UID: "XX:XX:XX:XX" = 11+1, 7-byte UID: "XX:XX:XX:XX:XX:XX:XX" = 23+1
  uint8_t  keys[16][6];       // 16 abgeleitete Keys
  uint8_t  blocks[64][16];    // all 64 blocks (16 sectors x 4 blocks)
  bool     block_ok[64];      // which blocks were successfully read
  // Parsed fields (NFC tag)
  char     tray_uuid[36];
  char     material[16];
  char     color_hex[8];      // #RRGGBB
  char     vendor[32];
  char     detailed_filament[64];
  int      temp_min;
  int      temp_max;
  float    spool_weight;
  char     production_date[12];
  char     short_uid[20];
  // Spoolman fields (filled after API query)
  bool     spoolman_found;
  int      spoolman_id;
  float    spoolman_remaining;  // g
  float    spoolman_total;      // g
  char     spoolman_last_dried[32];
};

BambuTagData g_tag;
bool g_tag_ready = false;
bool g_tag_displayed = false;
unsigned long g_tag_shown_ms = 0;
bool wifi_ok = false;
static bool sm_reachable = false;  // Fix 10: Spoolman reachability status

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
lv_obj_t *scr_scale_sub  = nullptr;  // Scale (bag weight + calibration)
lv_obj_t *scr_display    = nullptr;  // Display (brightness + timeouts)
lv_obj_t *scr_system     = nullptr;  // System (update + info/donate)
lv_obj_t *scr_ota        = nullptr;  // OTA selection (browser / GitHub)
lv_obj_t *scr_ota_browser = nullptr; // OTA browser upload screen
lv_obj_t *scr_ota_github  = nullptr; // OTA GitHub check screen

// OTA web server
static WebServer ota_server(80);
static bool ota_server_running = false;
static lv_obj_t *lbl_ota_status = nullptr;  // Status-Label im Browser-OTA Screen

// GitHub OTA state
static lv_obj_t *lbl_gh_status      = nullptr;
static lv_obj_t *lbl_gh_installed   = nullptr;
static lv_obj_t *lbl_gh_latest      = nullptr;
static lv_obj_t *btn_gh_update      = nullptr;
static lv_obj_t *lbl_gh_update_btn  = nullptr;
static char gh_latest_version[32]   = "";
bool update_available = false;   // set by silent background check
static bool silent_ota_check_pending = false;  // trigger once after WiFi connect
static lv_obj_t *lbl_burger_badge   = nullptr; // yellow dot on burger button (mainscreen)
static lv_obj_t *lbl_system_badge   = nullptr; // yellow dot on System tile (settings)
static lv_obj_t *lbl_fw_badge       = nullptr; // yellow dot on Firmware Update button
static lv_obj_t *lbl_gh_btn_badge   = nullptr; // yellow dot on GitHub Update button (OTA screen)
lv_obj_t *lbl_wifi_info = nullptr; // WiFi-Info Label
// ta_spoolman_ip, kb_spoolman: replaced by custom numpad — removed
// ta_factor_weight, kb_factor: replaced by custom numpad in buildFactorScreen()
lv_obj_t *ta_factor_weight = nullptr; // (nicht mehr aktiv genutzt)
lv_obj_t *kb_factor     = nullptr;    // (nicht mehr aktiv genutzt)
lv_obj_t *lbl_factor_result = nullptr;

// WiFi setup state
static char  wifi_setup_ssid[33]  = "";   // selected SSID from scan list
static lv_obj_t *lbl_wifi_setup_status = nullptr;  // Status-Label im Setup
static lv_obj_t *lbl_wifi_scan_list    = nullptr;  // Scan-Listen Container
static lv_obj_t *ta_wifi_pass          = nullptr;  // Password textarea
static lv_obj_t *kb_wifi_pass          = nullptr;  // Passwort-Tastatur
static lv_obj_t *scr_wifi_pass         = nullptr;  // Passwort-Unterscreen
static lv_obj_t *scr_wifi_connecting   = nullptr;  // Connecting screen

// Power management
unsigned long last_activity_ms = 0;  // last activity (NFC or touch)
bool is_dimmed = false;              // Display dimmed?

// Spoolman data kept separate – NOT reset on every scan
static int   sm_id = 0;
static int   sm_filament_id = 0;   // for PATCH /api/v1/filament/{id}
static int   sm_vendor_id = 0;     // for PATCH /api/v1/vendor/{id}
static bool  sm_found = false;
static float sm_remaining = 0;
static float sm_total = 1000;
static float sm_spool_weight = 0;   // Empty spool weight (for scale calculation)
static char  sm_last_dried[32] = "";
static char  sm_article_nr[32] = "";
static char  sm_filament_name[32] = "";
static char  sm_material_global[32] = "";
static char  sm_color_global[16] = "";   // Spoolman hex color for NTAG spools

// Scale (NAU7802)
static float scale_weight_g = 0.0f;
bool scale_ready = false;
static float cal_factor = CAL_FACTOR_DEFAULT;
static int32_t zero_offset = 0;
static unsigned long last_scale_ms = 0;

// Moving average for NAU7802 (dampens +/-0.2g noise)
#define SCALE_FILTER_SIZE  8
static float scale_filter_buf[SCALE_FILTER_SIZE] = {0};
static int   scale_filter_idx = 0;
static bool  scale_filter_full = false;

// Bag weight (configurable in settings)
static float bag_weight_g = 50.0f;  // Standard: 50g (Vakuumbeutel + Silikagel)

// Spoolman query: UID of the last queried spool
// Cleared after clearTagDisplay() → forces new query even for same UID
static char spoolman_queried_uid[24] = "";  // max 7-byte UID: "XX:XX:XX:XX:XX:XX:XX" = 23+1
static char  sm_last_used[32] = "";

// NFC retry: counter for re-scan attempts when tray_uuid is empty
static int nfc_retry_count = 0;
#define NFC_MAX_RETRIES  5

// ── Third-party tag linking ──────────────────────────────────
#define LINK_MAX_SPOOLS  50

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
};
static UnlinkedSpool link_spools[LINK_MAX_SPOOLS];
static int           link_spool_count = 0;
static char          link_tag_uid[24] = "";   // UID of the tag to be linked
static lv_obj_t     *scr_link_list = nullptr; // Spool selection overlay (old, kept for compatibility)

// Neuer Link-Flow Overlays
static lv_obj_t *scr_link_entry   = nullptr;  // Entry popup
static lv_obj_t *scr_link_id      = nullptr;  // Numeric keypad
static lv_obj_t *scr_link_warn_a  = nullptr;  // Warning popup A (already linked)
static lv_obj_t *scr_link_warn_b  = nullptr;  // Warning popup B (material mismatch)
static lv_obj_t *scr_link_vendor  = nullptr;  // Vendor-Auswahl (Flow B Pfad 2)
static lv_obj_t *scr_link_mat     = nullptr;  // Material selection (flow B path 2)
static lv_obj_t *scr_link_spools  = nullptr;  // Spool list (all path 2)

// State for ID input
static char link_id_input[8] = "";            // Input buffer for numeric keypad
static lv_obj_t *lbl_link_id_display = nullptr; // Label for digit display
static lv_obj_t *lbl_link_id_status  = nullptr; // Error label in numeric keypad

// State for path-2 navigation
static char link_selected_vendor[32]   = "";   // selected vendor
static char link_selected_material[8]  = "";   // 3-char material prefix
static bool link_flow_is_bambu = false;         // which flow is active

// Popup control: prevents immediate re-display after cancel
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
//  LVGL CALLBACKS
// ============================================================
void lvgl_flush(lv_disp_drv_t *drv, const lv_area_t *area, lv_color_t *color_p) {
  uint32_t w = area->x2 - area->x1 + 1;
  uint32_t h = area->y2 - area->y1 + 1;
  tft.startWrite();
  tft.setAddrWindow(area->x1, area->y1, w, h);
  tft.writePixels((lgfx::rgb565_t*)color_p, w * h);
  tft.endWrite();
  lv_disp_flush_ready(drv);
}

void lvgl_touch(lv_indev_drv_t *drv, lv_indev_data_t *data) {
  uint16_t x, y;
  if (tft.getTouch(&x, &y)) {
    data->state = LV_INDEV_STATE_PR;
    data->point.x = x; data->point.y = y;
    resetActivityTimer();
    static unsigned long last_log = 0;
    if (millis() - last_log > 200) {
      Serial.printf("TOUCH x=%d y=%d\n", x, y);
      last_log = millis();
    }
  } else {
    data->state = LV_INDEV_STATE_REL;
  }
}

// ============================================================
//  HKDF manually implemented
//  Extract: PRK = HMAC-SHA256(salt=MASTER_KEY, IKM=uid)
//  Expand:  OKM with context "RFID-B\0"
// ============================================================

static bool hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *out) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return mbedtls_md_hmac(info, key, key_len, data, data_len, out) == 0;
}

static bool hkdf_expand(const uint8_t *prk,  size_t prk_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *okm,        size_t okm_len) {
  uint8_t t[32] = {0};
  size_t  t_len = 0;
  size_t  done  = 0;
  uint8_t counter = 1;
  while (done < okm_len) {
    uint8_t input[256];
    size_t  input_len = 0;
    memcpy(input, t, t_len);                   input_len += t_len;
    memcpy(input + input_len, info, info_len); input_len += info_len;
    input[input_len++] = counter++;
    if (!hmac_sha256(prk, prk_len, input, input_len, t)) return false;
    t_len = 32;
    size_t copy = (okm_len - done < 32) ? (okm_len - done) : 32;
    memcpy(okm + done, t, copy);
    done += copy;
  }
  return true;
}

bool deriveKeys(const uint8_t *uid, uint8_t uid_len, uint8_t keys[16][6]) {
  // HKDF-Extract: PRK = HMAC-SHA256(salt=MASTER_KEY, IKM=uid)
  uint8_t prk[32];
  if (!hmac_sha256(BAMBU_MASTER_KEY, 16, uid, uid_len, prk)) {
    Serial.println("HKDF-Extract error");
    return false;
  }
  // HKDF-Expand with context "RFID-B\0"
  uint8_t okm[96];
  if (!hkdf_expand(prk, 32, BAMBU_KDF_CONTEXT, 7, okm, 96)) {
    Serial.println("HKDF-Expand error");
    return false;
  }
  for (int i = 0; i < 16; i++) {
    memcpy(keys[i], okm + i * 6, 6);
  }
  return true;
}

// ============================================================
//  MIFARE CLASSIC – authenticate and read sector
//  Key B is used for Bambu-encrypted sectors
// ============================================================
bool readSector(int sector, uint8_t key[6], uint8_t uid[4], uint8_t blocks[4][16]) {
  uint8_t trailer_block = sector * 4 + 3;

  // Authenticate with key B
  if (!nfc.mifareclassic_AuthenticateBlock(uid, 4, trailer_block,
        MIFARE_CMD_AUTH_B, key)) {
    // Fallback: try key A
    if (!nfc.mifareclassic_AuthenticateBlock(uid, 4, trailer_block,
          MIFARE_CMD_AUTH_A, key)) {
      return false;
    }
  }

  // Read 3 data blocks (block 3 = trailer, contains keys)
  bool ok = true;
  for (int b = 0; b < 3; b++) {
    int block_num = sector * 4 + b;
    if (!nfc.mifareclassic_ReadDataBlock(block_num, blocks[b])) {
      memset(blocks[b], 0, 16);
      ok = false;
    }
  }
  return ok;
}

// ============================================================
//  PARSE TAG DATA
//  Based on BambuLabRfid.md documentation
// ============================================================
void parseTagData(BambuTagData &tag) {
  // tray_uuid: block 9 (verified with Spoolman: 4E3C9740796645ACBC2732FDD6456A0D)
  if (tag.block_ok[9]) {
    char uuid[33] = "";
    for (int i = 0; i < 16; i++) {
      sprintf(uuid + i * 2, "%02X", tag.blocks[9][i]);
    }
    strncpy(tag.tray_uuid, uuid, 32);
    tag.tray_uuid[32] = '\0';
  }

  // Material: sector 2, block 8
  // Material: block 4 (long form, e.g. "PETG HF")
  if (tag.block_ok[4]) {
    memset(tag.material, 0, sizeof(tag.material));
    strncpy(tag.material, (char*)tag.blocks[4], 15);
    for (int i = 0; i < 15; i++) {
      if (tag.material[i] < 0x20 || tag.material[i] > 0x7E) {
        tag.material[i] = 0; break;
      }
    }
  }

  // Color: block 5, bytes 0-2 = R,G,B (verified: FF D0 0B = #FFD00B)
  if (tag.block_ok[5]) {
    sprintf(tag.color_hex, "#%02X%02X%02X",
      tag.blocks[5][0], tag.blocks[5][1], tag.blocks[5][2]);
  }

  // Temperatures: block 6, bytes 8-9 = max, 10-11 = min (little endian, directly in °C)
  if (tag.block_ok[6]) {
    int t1 = tag.blocks[6][8]  | (tag.blocks[6][9]  << 8);  // 0x0104 = 260°C
    int t2 = tag.blocks[6][10] | (tag.blocks[6][11] << 8);  // 0x00E6 = 230°C
    if (t1 > 100 && t1 < 400) tag.temp_max = t1;
    if (t2 > 100 && t2 < 400) tag.temp_min = t2;
  }

  // Vendor/Vendor: Block 16 (ASCII, z.B. "Bambu Lab")
  if (tag.block_ok[16]) {
    memset(tag.vendor, 0, sizeof(tag.vendor));
    for (int i = 0; i < 16 && tag.blocks[16][i] != 0; i++) {
      char c = tag.blocks[16][i];
      if (c >= 0x20 && c <= 0x7E) tag.vendor[i] = c;
      else { tag.vendor[i] = 0; break; }
    }
  }

  // Production date: block 12 as ASCII "2025_03_07_04_18"
  if (tag.block_ok[12]) {
    char raw[17] = "";
    memcpy(raw, tag.blocks[12], 16);
    raw[16] = 0;
    // Format: YYYY_MM_DD_HH_MM -> DD.MM.YYYY
    if (raw[4] == '_' && raw[7] == '_') {
      snprintf(tag.production_date, sizeof(tag.production_date),
        "%.2s.%.2s.%.4s", raw+8, raw+5, raw);
    }
  }
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

  // Read all 16 sectors
  Serial.println("Reading sectors...");
  int success_count = 0;
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
  }

  Serial.printf("%d/48 blocks read\n", success_count);

  // Sector 0, block 0 is always readable (manufacturer data)
  uint8_t block0[16];
  if (nfc.mifareclassic_ReadDataBlock(0, block0)) {
    memcpy(g_tag.blocks[0], block0, 16);
    g_tag.block_ok[0] = true;
  }

  // Parse data
  parseTagData(g_tag);

  Serial.printf("tray_uuid: %s\n", g_tag.tray_uuid);
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

  // PATCH /api/v1/spool/{id}
  HTTPClient http;
  String url = String(cfg_spoolman_base) + "/api/v1/spool/" + sm_id;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);

  // Body: update extra field
  // Spoolman stores extra fields as escaped strings (with quotes)
  String body = "{\"extra\": {\"last_dried\": \"\\\"" + iso_full + "\\\"\"}}"; 
  Serial.println("PATCH body: " + body);
  int code = http.PATCH(body);
  http.end();

  if (code == 200) {
    // Update display
    char de_date[12];
    isoToDe(today.c_str(), de_date, sizeof(de_date));
    strncpy(sm_last_dried, de_date, sizeof(sm_last_dried)-1);
    char dried_display[48];
    driedDisplayStr(de_date, dried_display, sizeof(dried_display));
    lv_label_set_text(lbl_spoolman_dried_val, dried_display);
    Serial.println("last_dried set!");
  } else {
    Serial.printf("PATCH error: %d\n", code);
    lv_label_set_text(lbl_spoolman_dried_val, T(STR_ERR_SAVE));
  }
}

// ============================================================
//  PREFERENCES (NVS)
// ============================================================
void loadPrefs() {
  prefs.begin("spoolscale", false);
  String ssid = prefs.getString("wifi_ssid", cfg_wifi_ssid);
  String pass = prefs.getString("wifi_pass", cfg_wifi_password);
  String ip   = prefs.getString("spoolman_ip", cfg_spoolman_ip);
  strncpy(cfg_wifi_ssid,     ssid.c_str(), sizeof(cfg_wifi_ssid)-1);
  strncpy(cfg_wifi_password, pass.c_str(), sizeof(cfg_wifi_password)-1);
  strncpy(cfg_spoolman_ip,   ip.c_str(),   sizeof(cfg_spoolman_ip)-1);
  snprintf(cfg_spoolman_base, sizeof(cfg_spoolman_base), "http://%s", cfg_spoolman_ip);
  // NAU7802: Kalibrierfaktor und Tare-Offset laden
  cal_factor  = prefs.getFloat("cal_factor",   CAL_FACTOR_DEFAULT);
  zero_offset = prefs.getInt("zero_offset", 0);
  bag_weight_g = prefs.getFloat("bag_weight", 50.0f);
  // Display-Einstellungen laden
  bright_normal    = prefs.getUChar("bright",    BRIGHT_NORMAL_DEFAULT);
  int dim_min      = prefs.getUInt("dim_min",    DIM_TIMEOUT_DEFAULT / 60000);
  int sleep_min    = prefs.getUInt("sleep_min",  SLEEP_TIMEOUT_DEFAULT / 60000);
  dim_timeout_ms   = dim_min * 60000;
  sleep_timeout_ms = sleep_min * 60000;
  g_lang     = (Lang)prefs.getUChar("lang",     1);  // Default EN
  g_date_fmt =       prefs.getUChar("date_fmt", 0);
  cfg_lang_set =     prefs.getBool("lang_set",  false);
  cfg_first_boot =   prefs.getBool("first_boot", true);
  last_used_mode =   prefs.getUChar("lu_mode",  0);  // 0=OpenSpoolMan, 1=Last Weighed
  prefs.end();
  Serial.printf("Prefs: SSID=%s Spoolman=%s\n", cfg_wifi_ssid, cfg_spoolman_base);
  Serial.printf("Scale: cal_factor=%.4f  zero_offset=%d  bag_weight=%.1fg\n",
    cal_factor, zero_offset, bag_weight_g);
  Serial.printf("Display: bright=%d dim=%dmin sleep=%dmin\n",
    bright_normal, dim_min, sleep_min);
}

void saveCalFactor(float factor) {
  cal_factor = factor;
  prefs.begin("spoolscale", false);
  prefs.putFloat("cal_factor", factor);
  prefs.end();
  Serial.printf("cal_factor saved: %.4f\n", factor);
}

void saveBagWeight(float weight) {
  bag_weight_g = weight;
  prefs.begin("spoolscale", false);
  prefs.putFloat("bag_weight", weight);
  prefs.end();
  Serial.printf("bag_weight saved: %.1fg\n", weight);
}

void saveTareOffset(int32_t offset) {
  zero_offset = offset;
  prefs.begin("spoolscale", false);
  prefs.putInt("zero_offset", offset);
  prefs.end();
  Serial.printf("zero_offset saved: %d\n", offset);
}

void saveWifiCredentials(const char* ssid, const char* pass) {
  strncpy(cfg_wifi_ssid,     ssid, sizeof(cfg_wifi_ssid)-1);
  strncpy(cfg_wifi_password, pass, sizeof(cfg_wifi_password)-1);
  prefs.begin("spoolscale", false);
  prefs.putString("wifi_ssid", ssid);
  prefs.putString("wifi_pass",  pass);
  prefs.end();
  Serial.printf("WiFi saved: SSID=%s\n", ssid);
}


void saveSpoolmanIP(const char* ip) {
  strncpy(cfg_spoolman_ip, ip, sizeof(cfg_spoolman_ip)-1);
  snprintf(cfg_spoolman_base, sizeof(cfg_spoolman_base), "http://%s", ip);
  prefs.begin("spoolscale", false);
  prefs.putString("spoolman_ip", ip);
  prefs.end();
}

// ============================================================
//  HELPER FUNCTIONS: Consistent navigation buttons
//  Back (←): top left, 36x36, goes one level up
//  Close (✕): top right, 36x36, goes directly to main screen
// ============================================================
void addBackButton(lv_obj_t *parent, lv_event_cb_t cb) {
  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, 44, 44);
  lv_obj_align(btn, LV_ALIGN_TOP_LEFT, 4, 2);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
  lv_obj_set_style_text_color(lbl, lv_color_hex(0x28d49a), 0);
  lv_obj_center(lbl);
}

void addCloseButton(lv_obj_t *parent) {
  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, 44, 44);
  lv_obj_align(btn, LV_ALIGN_TOP_RIGHT, -4, 2);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn, 8, 0);
  lv_obj_set_style_shadow_width(btn, 0, 0);
  lv_obj_set_style_border_width(btn, 0, 0);
  lv_obj_add_event_cb(btn, [](lv_event_t *e){ showMainScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl = lv_label_create(btn);
  lv_label_set_text(lbl, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
  lv_obj_set_style_text_color(lbl, lv_color_hex(0xff8080), 0);
  lv_obj_center(lbl);
}

// ============================================================
//  SETTINGS SCREENS
// ============================================================

// Helper: go back to main screen
void hideAllOverlays() {
  // More info screen is always rebuilt, so delete it
  if (scr_more_info) { lv_obj_del(scr_more_info); scr_more_info = nullptr; }
  if (scr_settings)      lv_obj_add_flag(scr_settings,      LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi)          lv_obj_add_flag(scr_wifi,          LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman)      lv_obj_add_flag(scr_spoolman,      LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman_fail) lv_obj_add_flag(scr_spoolman_fail, LV_OBJ_FLAG_HIDDEN);
  if (scr_factor)        lv_obj_add_flag(scr_factor,        LV_OBJ_FLAG_HIDDEN);
  if (scr_bag)           lv_obj_add_flag(scr_bag,           LV_OBJ_FLAG_HIDDEN);
  if (scr_lastused)      lv_obj_add_flag(scr_lastused,      LV_OBJ_FLAG_HIDDEN);
  if (scr_connection)    lv_obj_add_flag(scr_connection,    LV_OBJ_FLAG_HIDDEN);
  if (scr_scale_sub)     lv_obj_add_flag(scr_scale_sub,     LV_OBJ_FLAG_HIDDEN);
  if (scr_display)       lv_obj_add_flag(scr_display,       LV_OBJ_FLAG_HIDDEN);
  if (scr_system)        lv_obj_add_flag(scr_system,        LV_OBJ_FLAG_HIDDEN);
  if (scr_ota)           lv_obj_add_flag(scr_ota,           LV_OBJ_FLAG_HIDDEN);
  if (scr_ota_browser)   lv_obj_add_flag(scr_ota_browser,   LV_OBJ_FLAG_HIDDEN);
  if (scr_ota_github)    lv_obj_add_flag(scr_ota_github,    LV_OBJ_FLAG_HIDDEN);
  if (scr_welcome)       lv_obj_add_flag(scr_welcome,       LV_OBJ_FLAG_HIDDEN);
  if (scr_first_boot)    lv_obj_add_flag(scr_first_boot,    LV_OBJ_FLAG_HIDDEN);
  if (scr_extra_fields)  lv_obj_add_flag(scr_extra_fields,  LV_OBJ_FLAG_HIDDEN);
  if (scr_cal_reminder)  lv_obj_add_flag(scr_cal_reminder,  LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_setup)    lv_obj_add_flag(scr_wifi_setup,    LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_pass)     lv_obj_add_flag(scr_wifi_pass,     LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_connecting) lv_obj_add_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN);
}

void showMainScreen() {
  hideAllOverlays();
  resetActivityTimer();
}

void showSettingsScreen() {
  hideAllOverlays();
  if (!scr_settings) {
    buildSettingsScreen();
  }
  lv_obj_clear_flag(scr_settings, LV_OBJ_FLAG_HIDDEN);
  resetActivityTimer();
}

// ============================================================
//  WELCOME SCREEN (first boot — SSID empty)
// ============================================================
void showWelcomeScreen() {
  hideAllOverlays();
  if (!scr_welcome) buildWelcomeScreen();
  lv_obj_clear_flag(scr_welcome, LV_OBJ_FLAG_HIDDEN);
}

void buildWelcomeScreen() {
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
  lv_obj_set_style_text_font(lbl_logo, &lv_font_montserrat_24, 0);
  lv_obj_align(lbl_logo, LV_ALIGN_TOP_MID, 0, 24);

  lv_obj_t *lbl_sub = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_sub, T(STR_WELCOME_LANG_TITLE));
  lv_obj_set_style_text_color(lbl_sub, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_sub, &lv_font_montserrat_16, 0);
  lv_obj_align(lbl_sub, LV_ALIGN_TOP_MID, 0, 64);

  lv_obj_t *lbl_hint = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_hint, T(STR_WELCOME_LANG_HINT));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_12, 0);
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
    lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_18, 0);
    lv_obj_center(lbl_x);
    lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ showMainScreen(); }, LV_EVENT_CLICKED, NULL);
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
  lv_obj_set_style_text_font(lbl_en, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_en);
  lv_obj_add_event_cb(btn_en, [](lv_event_t *e){
    g_lang = LANG_EN;
    Preferences p; p.begin("spoolscale", false);
    p.putUChar("lang", 1);
    p.putBool("lang_set", true);
    p.putBool("first_boot", true);  // show welcome screen after restart
    p.end();
    ESP.restart();
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
  lv_obj_set_style_text_font(lbl_de, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_de);
  lv_obj_add_event_cb(btn_de, [](lv_event_t *e){
    g_lang = LANG_DE;
    Preferences p; p.begin("spoolscale", false);
    p.putUChar("lang", 0);
    p.putBool("lang_set", true);
    p.putBool("first_boot", true);  // show welcome screen after restart
    p.end();
    ESP.restart();
  }, LV_EVENT_CLICKED, NULL);

  // Bottom hint
  lv_obj_t *lbl_skip = lv_label_create(scr_welcome);
  lv_label_set_text(lbl_skip, T(STR_LANG_HINT));
  lv_obj_set_style_text_color(lbl_skip, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_skip, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_align(lbl_skip, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_skip, LV_ALIGN_BOTTOM_MID, 0, -10);
}

// ============================================================
//  FIRST BOOT SCREEN (very first launch — before language selection)
// ============================================================
void showFirstBootScreen() {
  hideAllOverlays();
  if (!scr_first_boot) buildFirstBootScreen();
  lv_obj_clear_flag(scr_first_boot, LV_OBJ_FLAG_HIDDEN);
}

void buildFirstBootScreen() {
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
  lv_obj_set_style_text_font(lbl_logo, &lv_font_montserrat_24, 0);
  lv_obj_align(lbl_logo, LV_ALIGN_TOP_MID, 0, 32);

  // Welcome title
  lv_obj_t *lbl_title = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_title, T(STR_FIRSTBOOT_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0xe8f0ff), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_20, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 72);

  // Subtitle
  lv_obj_t *lbl_sub = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_sub, T(STR_FIRSTBOOT_SUB));
  lv_obj_set_style_text_color(lbl_sub, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_sub, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_sub, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_sub, LV_ALIGN_TOP_MID, 0, 104);

  // Hint
  lv_obj_t *lbl_hint = lv_label_create(scr_first_boot);
  lv_label_set_text(lbl_hint, T(STR_FIRSTBOOT_HINT));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_14, 0);
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
    lv_obj_add_event_cb(btn_cx, [](lv_event_t *e){ showMainScreen(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_cx = lv_label_create(btn_cx);
    lv_label_set_text(lbl_cx, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(lbl_cx, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_cx, &lv_font_montserrat_18, 0);
    lv_obj_center(lbl_cx);
  }

  // Get started button
  lv_obj_t *btn_start = lv_btn_create(scr_first_boot);
  lv_obj_set_size(btn_start, 240, 52);
  lv_obj_align(btn_start, LV_ALIGN_BOTTOM_MID, 0, -28);
  lv_obj_set_style_bg_color(btn_start, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_start, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_start, 10, 0);
  lv_obj_set_style_shadow_width(btn_start, 0, 0);
  lv_obj_set_style_border_width(btn_start, 1, 0);
  lv_obj_set_style_border_color(btn_start, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_start, [](lv_event_t *e) {
    // Mark first boot as done
    Preferences p; p.begin("spoolscale", false);
    p.putBool("first_boot", false);
    p.end();
    cfg_first_boot = false;
    // Go to WiFi setup
    showWifiSetupScreen();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_start = lv_label_create(btn_start);
  lv_label_set_text(lbl_start, T(STR_FIRSTBOOT_BTN));
  lv_obj_set_style_text_color(lbl_start, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_start, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_start);
}

// ============================================================
//  EXTRA FIELDS SCREEN
//  Check/create Spoolman extra fields 'tag' and 'last_dried'
// ============================================================

// Required extra fields — extend this array for future fields
static const char* REQUIRED_EXTRA_FIELDS_BASE[] = { "tag", "last_dried" };
static const int   REQUIRED_EXTRA_FIELDS_BASE_COUNT = 2;

void showExtraFieldsScreen(bool is_setup_flow) {
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
    // Setup flow: title + Back (→ Spoolman IP) + X (→ main screen)
    lv_obj_t *lbl_title = lv_label_create(scr_extra_fields);
    lv_label_set_text(lbl_title, T(STR_EXTRA_FIELDS_TITLE));
    lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_18, 0);
    lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

    // Back → Spoolman IP screen
    lv_obj_t *btn_bk = lv_btn_create(scr_extra_fields);
    lv_obj_set_size(btn_bk, 44, 44);
    lv_obj_set_pos(btn_bk, 4, 2);
    lv_obj_set_style_bg_color(btn_bk, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(btn_bk, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_bk, 8, 0);
    lv_obj_set_style_shadow_width(btn_bk, 0, 0);
    lv_obj_set_style_border_width(btn_bk, 0, 0);
    lv_obj_add_event_cb(btn_bk, [](lv_event_t *e){
      hideAllOverlays();
      if (scr_spoolman) { lv_obj_del(scr_spoolman); scr_spoolman = nullptr; }
      buildSpoolmanScreen();
      lv_obj_clear_flag(scr_spoolman, LV_OBJ_FLAG_HIDDEN);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_bk = lv_label_create(btn_bk);
    lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(lbl_bk, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_18, 0);
    lv_obj_center(lbl_bk);

    // X → main screen (exit setup)
    lv_obj_t *btn_x = lv_btn_create(scr_extra_fields);
    lv_obj_set_size(btn_x, 44, 44);
    lv_obj_align(btn_x, LV_ALIGN_TOP_RIGHT, -4, 2);
    lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x3a1010), 0);
    lv_obj_set_style_bg_color(btn_x, lv_color_hex(0x602020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn_x, 8, 0);
    lv_obj_set_style_shadow_width(btn_x, 0, 0);
    lv_obj_set_style_border_width(btn_x, 0, 0);
    lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ showMainScreen(); }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_x = lv_label_create(btn_x);
    lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_18, 0);
    lv_obj_center(lbl_x);
  }

  // Hint text
  lv_obj_t *lbl_hint = lv_label_create(scr_extra_fields);
  lv_label_set_text(lbl_hint, T(STR_EXTRA_FIELDS_HINT));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_12, 0);
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
    checkAndCreateExtraFields(false);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_check = lv_label_create(btn_check);
  lv_label_set_text(lbl_check, T(STR_EXTRA_FIELDS_CHECK_BTN));
  lv_obj_set_style_text_color(lbl_check, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_check, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_check);

  // Status label — below check button
  lbl_extra_fields_status = lv_label_create(scr_extra_fields);
  lv_label_set_text(lbl_extra_fields_status, "");
  lv_obj_set_style_text_color(lbl_extra_fields_status, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_extra_fields_status, &lv_font_montserrat_14, 0);
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
    lv_obj_set_style_text_font(lbl_ct, &lv_font_montserrat_18, 0);
    lv_obj_align(lbl_ct, LV_ALIGN_TOP_MID, 0, 18);

    lv_obj_t *lbl_cm = lv_label_create(box);
    lv_label_set_text(lbl_cm, T(STR_EXTRA_FIELDS_CONFIRM_MSG));
    lv_obj_set_style_text_color(lbl_cm, lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(lbl_cm, &lv_font_montserrat_14, 0);
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
      checkAndCreateExtraFields(true);
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *lbl_conf = lv_label_create(btn_conf);
    lv_label_set_text(lbl_conf, T(STR_CONFIRM));
    lv_obj_set_style_text_color(lbl_conf, lv_color_hex(0x40c080), 0);
    lv_obj_set_style_text_font(lbl_conf, &lv_font_montserrat_16, 0);
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
    lv_obj_set_style_text_font(lbl_can, &lv_font_montserrat_16, 0);
    lv_obj_center(lbl_can);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *lbl_create = lv_label_create(btn_extra_fields_create);
  lv_label_set_text(lbl_create, T(STR_EXTRA_FIELDS_CREATE_BTN));
  lv_obj_set_style_text_color(lbl_create, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_create, &lv_font_montserrat_16, 0);
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
    if (extra_fields_setup_flow) showCalReminderScreen();
    else {
      if (!scr_connection) buildConnectionScreen();
      hideAllOverlays(); lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_skip_b = lv_label_create(btn_skip_bottom);
  char skip_buf[32];
  snprintf(skip_buf, sizeof(skip_buf), "%s  " LV_SYMBOL_RIGHT, T(STR_EXTRA_FIELDS_SKIP));
  lv_label_set_text(lbl_skip_b, skip_buf);
  lv_obj_set_style_text_color(lbl_skip_b, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_skip_b, &lv_font_montserrat_14, 0);
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
    // Create spoolscale_test field directly in Spoolman
    HTTPClient http;
    String url = String(cfg_spoolman_base) + "/api/v1/field/spool/spoolscale_test";
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(1500);
    String body = "{\"name\":\"spoolscale_test\",\"field_type\":\"text\",\"default_value\":\"\\\"\\\"\"}";
    int code = http.POST(body);
    http.end();
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
  lv_obj_set_style_text_font(lbl_test, &lv_font_montserrat_14, 0);
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

  // GET /api/v1/field/spool — list all existing extra fields
  HTTPClient http;
  String url = String(cfg_spoolman_base) + "/api/v1/field/spool";
  http.begin(url);
  http.setTimeout(1500);
  int code = http.GET();
  String payload = "";
  if (code == 200) payload = http.getString();
  http.end();

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
  if (code == 200 && payload.length() > 0) {
    DynamicJsonDocument doc(8192);
    if (!deserializeJson(doc, payload)) {
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

  char fail_fields[64] = "";
  int fail_count = 0;
  for (int i = 0; i < ef_count; i++) {
    if (field_exists[i]) continue;
    HTTPClient http2;
    String create_url = String(cfg_spoolman_base) + "/api/v1/field/spool/" + REQUIRED_EXTRA_FIELDS_BASE[i];
    http2.begin(create_url);
    http2.addHeader("Content-Type", "application/json");
    http2.setTimeout(1500);
    String body = "{\"name\":\"" + String(REQUIRED_EXTRA_FIELDS_BASE[i]) + "\",\"field_type\":\"text\",\"default_value\":\"\\\"\\\"\" }";
    int c2 = http2.POST(body);
    http2.end();
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
    checkAndCreateExtraFields(false);
  }
}

// ============================================================
//  CALIBRATION REMINDER SCREEN (end of first setup)
// ============================================================
void showCalReminderScreen() {
  hideAllOverlays();
  if (scr_cal_reminder) { lv_obj_del(scr_cal_reminder); scr_cal_reminder = nullptr; }
  buildCalReminderScreen();
  lv_obj_clear_flag(scr_cal_reminder, LV_OBJ_FLAG_HIDDEN);
}

void buildCalReminderScreen() {
  scr_cal_reminder = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_cal_reminder, 480, 320);
  lv_obj_set_pos(scr_cal_reminder, 0, 0);
  lv_obj_add_flag(scr_cal_reminder, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_cal_reminder, 0, 0);
  lv_obj_set_style_border_width(scr_cal_reminder, 0, 0);
  lv_obj_set_style_pad_all(scr_cal_reminder, 0, 0);
  lv_obj_clear_flag(scr_cal_reminder, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_cal_reminder, lv_color_hex(0x0a1020), 0);

  // Copy strings to RAM buffers
  char buf_title[48], buf_msg[256], buf_later[32], buf_now[48];
  strncpy(buf_title, T(STR_CAL_REMINDER_TITLE), sizeof(buf_title)-1); buf_title[sizeof(buf_title)-1]=0;
  strncpy(buf_msg,   T(STR_CAL_REMINDER_MSG),   sizeof(buf_msg)-1);   buf_msg[sizeof(buf_msg)-1]=0;
  strncpy(buf_later, T(STR_CAL_REMINDER_LATER), sizeof(buf_later)-1); buf_later[sizeof(buf_later)-1]=0;
  strncpy(buf_now,   T(STR_CAL_REMINDER_NOW),   sizeof(buf_now)-1);   buf_now[sizeof(buf_now)-1]=0;

  // Title
  lv_obj_t *lbl_title = lv_label_create(scr_cal_reminder);
  lv_label_set_text(lbl_title, buf_title);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 20);

  // Back → extra fields screen
  addBackButton(scr_cal_reminder, [](lv_event_t *e){
    showExtraFieldsScreen(true);
  });
  addCloseButton(scr_cal_reminder);

  // Icon
  lv_obj_t *lbl_icon = lv_label_create(scr_cal_reminder);
  lv_label_set_text(lbl_icon, LV_SYMBOL_EDIT);
  lv_obj_set_style_text_color(lbl_icon, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_icon, &lv_font_montserrat_24, 0);
  lv_obj_align(lbl_icon, LV_ALIGN_TOP_MID, 0, 52);

  // Message
  lv_obj_t *lbl_msg = lv_label_create(scr_cal_reminder);
  lv_label_set_text(lbl_msg, buf_msg);
  lv_obj_set_style_text_color(lbl_msg, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_msg, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_align(lbl_msg, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_msg, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_msg, 440);
  lv_obj_align(lbl_msg, LV_ALIGN_TOP_MID, 0, 88);

  // Later button
  lv_obj_t *btn_later = lv_btn_create(scr_cal_reminder);
  lv_obj_set_size(btn_later, 200, 48);
  lv_obj_align(btn_later, LV_ALIGN_BOTTOM_LEFT, 16, -20);
  lv_obj_set_style_bg_color(btn_later, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_later, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_later, 8, 0);
  lv_obj_set_style_shadow_width(btn_later, 0, 0);
  lv_obj_set_style_border_width(btn_later, 1, 0);
  lv_obj_set_style_border_color(btn_later, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_later, [](lv_event_t *e) {
    showMainScreen();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_later = lv_label_create(btn_later);
  lv_label_set_text(lbl_later, buf_later);
  lv_obj_set_style_text_color(lbl_later, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_later, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_later);

  // Calibrate now button
  lv_obj_t *btn_cal = lv_btn_create(scr_cal_reminder);
  lv_obj_set_size(btn_cal, 220, 48);
  lv_obj_align(btn_cal, LV_ALIGN_BOTTOM_RIGHT, -16, -20);
  lv_obj_set_style_bg_color(btn_cal, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_cal, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cal, 8, 0);
  lv_obj_set_style_shadow_width(btn_cal, 0, 0);
  lv_obj_set_style_border_width(btn_cal, 1, 0);
  lv_obj_set_style_border_color(btn_cal, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_cal, [](lv_event_t *e) {
    showFactorScreen();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cal = lv_label_create(btn_cal);
  lv_label_set_text(lbl_cal, buf_now);
  lv_obj_set_style_text_color(lbl_cal, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_cal, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_cal);
}

// ============================================================
//  WIFI SETUP: STEP 1 — Network scan + selection
// ============================================================
void showWifiSetupScreen() {
  hideAllOverlays();
  if (scr_wifi_setup) { lv_obj_del(scr_wifi_setup); scr_wifi_setup = nullptr; }
  // Null global pointers — otherwise they point to deleted objects
  lbl_wifi_scan_list    = nullptr;
  lbl_wifi_setup_status = nullptr;
  buildWifiSetupScreen();
  lv_obj_clear_flag(scr_wifi_setup, LV_OBJ_FLAG_HIDDEN);
}

void buildWifiSetupScreen() {
  scr_wifi_setup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_wifi_setup, 480, 320);
  lv_obj_set_pos(scr_wifi_setup, 0, 0);
  lv_obj_add_flag(scr_wifi_setup, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_wifi_setup, 0, 0);
  lv_obj_set_style_border_width(scr_wifi_setup, 0, 0);
  lv_obj_set_style_pad_all(scr_wifi_setup, 0, 0);
  lv_obj_clear_flag(scr_wifi_setup, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_wifi_setup, lv_color_hex(0x0a1020), 0);

  // Header
  lv_obj_t *title = lv_label_create(scr_wifi_setup);
  lv_label_set_text(title, T(STR_WIFI_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 14);

  // Back button (←)
  addBackButton(scr_wifi_setup, [](lv_event_t *e) {
    if (strlen(cfg_wifi_ssid) == 0) {
      showWelcomeScreen();
    } else {
      showSettingsScreen();
    }
  });

  // X button (✕)
  addCloseButton(scr_wifi_setup);

  // Refresh button (next to title, center-right)
  lv_obj_t *btn_scan = lv_btn_create(scr_wifi_setup);
  lv_obj_set_size(btn_scan, 44, 36);
  lv_obj_align(btn_scan, LV_ALIGN_TOP_MID, 100, 4);
  lv_obj_set_style_bg_color(btn_scan, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_scan, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_scan, 6, 0);
  lv_obj_set_style_shadow_width(btn_scan, 0, 0);
  lv_obj_set_style_border_width(btn_scan, 0, 0);
  lv_obj_t *lbl_scan_btn = lv_label_create(btn_scan);
  lv_label_set_text(lbl_scan_btn, LV_SYMBOL_REFRESH);
  lv_obj_set_style_text_color(lbl_scan_btn, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_scan_btn, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_scan_btn);

  // Scrollable network list (y=50 → y=56 due to header)
  lv_obj_t *list = lv_obj_create(scr_wifi_setup);
  lv_obj_set_size(list, 460, 218);
  lv_obj_set_pos(list, 10, 56);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);
  lv_obj_clear_flag(list, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(list, LV_OBJ_FLAG_SCROLLABLE);
  lbl_wifi_scan_list = list;

  // Status label (initially "scanning...")
  lbl_wifi_setup_status = lv_label_create(scr_wifi_setup);
  lv_label_set_text(lbl_wifi_setup_status, T(STR_WIFI_SCAN));
  lv_obj_set_style_text_color(lbl_wifi_setup_status, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_wifi_setup_status, &lv_font_montserrat_14, 0);
  lv_obj_align(lbl_wifi_setup_status, LV_ALIGN_BOTTOM_MID, 0, -8);

  // Scan button callback (after building list)
  lv_obj_add_event_cb(btn_scan, [](lv_event_t *e) {
    lv_label_set_text(lbl_wifi_setup_status, T(STR_WIFI_SCAN));
    doWifiScan();
  }, LV_EVENT_CLICKED, NULL);

  // Immediate scan on open
  doWifiScan();
}

// Perform scan and populate list
void doWifiScan() {
  // Liste leeren
  lv_obj_clean(lbl_wifi_scan_list);
  lv_timer_handler();

  // Disconnect required after failed WiFi.begin() —
  // otherwise scanNetworks() returns 0
  WiFi.disconnect(true);
  delay(100);
  WiFi.mode(WIFI_STA);
  delay(100);
  int n = WiFi.scanNetworks();

  if (n == 0) {
    lv_label_set_text(lbl_wifi_setup_status, T(STR_WIFI_NO_NET));
    return;
  }

  char status_buf[48];
  snprintf(status_buf, sizeof(status_buf), T(STR_WIFI_NETWORKS_FOUND), n);
  lv_label_set_text(lbl_wifi_setup_status, status_buf);

  // Sort: strongest first (bubble sort, n is small)
  for (int i = 0; i < n - 1; i++) {
    for (int j = 0; j < n - i - 1; j++) {
      if (WiFi.RSSI(j) < WiFi.RSSI(j + 1)) {
        // Swap via scan index — LVGL-independent, WiFi.SSID() returns directly
        // Arduino WiFi.scanNetworks() returns sorted after scan, only needed if not:
        // Wir nutzen einen Index-Array-Trick nicht — direkt ausgeben reicht da n<20
      }
    }
  }

  for (int i = 0; i < n && i < 20; i++) {
    int rssi = WiFi.RSSI(i);
    String ssid = WiFi.SSID(i);
    if (ssid.length() == 0) continue;

    // Signal bar (3 levels)
    const char* signal_icon;
    if      (rssi >= -65) signal_icon = LV_SYMBOL_WIFI "   ";
    else if (rssi >= -80) signal_icon = LV_SYMBOL_WIFI "   ";
    else                  signal_icon = LV_SYMBOL_WIFI "   ";

    // Signal color
    uint32_t sig_color;
    if      (rssi >= -65) sig_color = 0x28d49a;  // green
    else if (rssi >= -80) sig_color = 0xf0b838;  // yellow
    else                  sig_color = 0xff8000;   // orange

    // Row button
    lv_obj_t *row = lv_btn_create(lbl_wifi_scan_list);
    lv_obj_set_size(row, 452, 46);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(row, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(row, 6, 0);
    lv_obj_set_style_shadow_width(row, 0, 0);
    lv_obj_set_style_border_color(row, lv_color_hex(0x1a2840), 0);
    lv_obj_set_style_border_width(row, 1, 0);
    lv_obj_set_style_pad_all(row, 0, 0);

    // SSID Label
    lv_obj_t *lbl_ssid = lv_label_create(row);
    lv_label_set_text(lbl_ssid, ssid.c_str());
    lv_obj_set_style_text_color(lbl_ssid, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl_ssid, &lv_font_montserrat_16, 0);
    lv_obj_align(lbl_ssid, LV_ALIGN_LEFT_MID, 12, 0);
    lv_label_set_long_mode(lbl_ssid, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_ssid, 300);

    // RSSI Label
    char rssi_buf[16];
    snprintf(rssi_buf, sizeof(rssi_buf), "%d dBm", rssi);
    lv_obj_t *lbl_rssi = lv_label_create(row);
    lv_label_set_text(lbl_rssi, rssi_buf);
    lv_obj_set_style_text_color(lbl_rssi, lv_color_hex(sig_color), 0);
    lv_obj_set_style_text_font(lbl_rssi, &lv_font_montserrat_12, 0);
    lv_obj_align(lbl_rssi, LV_ALIGN_RIGHT_MID, -8, 0);

    // Click: store SSID → password screen
    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      lv_obj_t *btn = (lv_obj_t*)lv_event_get_target(e);
      lv_obj_t *lbl = lv_obj_get_child(btn, 0);
      const char* ssid_str = lv_label_get_text(lbl);
      strncpy(wifi_setup_ssid, ssid_str, sizeof(wifi_setup_ssid)-1);
      showWifiPassScreen();
    }, LV_EVENT_CLICKED, NULL);
  }

  WiFi.scanDelete();
}

// ============================================================
//  WIFI SETUP: STEP 2 — Password entry
// ============================================================
void showWifiPassScreen() {
  hideAllOverlays();
  if (scr_wifi_pass) { lv_obj_del(scr_wifi_pass); scr_wifi_pass = nullptr; }
  ta_wifi_pass = nullptr;
  kb_wifi_pass = nullptr;
  buildWifiPassScreen();
  lv_obj_clear_flag(scr_wifi_pass, LV_OBJ_FLAG_HIDDEN);
}

void buildWifiPassScreen() {
  scr_wifi_pass = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_wifi_pass, 480, 320);
  lv_obj_set_pos(scr_wifi_pass, 0, 0);
  lv_obj_add_flag(scr_wifi_pass, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_wifi_pass, 0, 0);
  lv_obj_set_style_border_width(scr_wifi_pass, 0, 0);
  lv_obj_set_style_pad_all(scr_wifi_pass, 0, 0);
  lv_obj_clear_flag(scr_wifi_pass, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_wifi_pass, lv_color_hex(0x0a1020), 0);

  // Back button
  addBackButton(scr_wifi_pass, [](lv_event_t *e) { showWifiSetupScreen(); });
  addCloseButton(scr_wifi_pass);

  // Title
  lv_obj_t *title = lv_label_create(scr_wifi_pass);
  lv_label_set_text(title, T(STR_WIFI_PASS_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 14);

  // Show selected SSID
  char ssid_hint[64];
  snprintf(ssid_hint, sizeof(ssid_hint), T(STR_WIFI_PASS_HINT), wifi_setup_ssid);
  lv_obj_t *lbl_ssid_show = lv_label_create(scr_wifi_pass);
  lv_label_set_text(lbl_ssid_show, ssid_hint);
  lv_obj_set_style_text_color(lbl_ssid_show, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_ssid_show, &lv_font_montserrat_14, 0);
  lv_obj_align(lbl_ssid_show, LV_ALIGN_TOP_MID, 0, 52);

  // Password textarea
  ta_wifi_pass = lv_textarea_create(scr_wifi_pass);
  lv_textarea_set_one_line(ta_wifi_pass, true);
  lv_textarea_set_password_mode(ta_wifi_pass, false);
  lv_textarea_set_placeholder_text(ta_wifi_pass, "Passwort...");
  lv_obj_set_size(ta_wifi_pass, 380, 44);
  lv_obj_align(ta_wifi_pass, LV_ALIGN_TOP_MID, 0, 74);
  lv_obj_set_style_text_font(ta_wifi_pass, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_color(ta_wifi_pass, lv_color_hex(0xffffff), 0);
  lv_obj_set_style_bg_color(ta_wifi_pass, lv_color_hex(0x1e2e4a), 0);
  lv_obj_set_style_border_color(ta_wifi_pass, lv_color_hex(0x2a4080), 0);

  // Keyboard
  kb_wifi_pass = lv_keyboard_create(scr_wifi_pass);
  lv_keyboard_set_textarea(kb_wifi_pass, ta_wifi_pass);
  lv_obj_set_size(kb_wifi_pass, 480, 160);
  lv_obj_align(kb_wifi_pass, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_style_bg_color(kb_wifi_pass, lv_color_hex(0x182238), 0);
  lv_obj_set_style_border_width(kb_wifi_pass, 0, 0);

  // Enter on keyboard → connect
  lv_obj_add_event_cb(kb_wifi_pass, [](lv_event_t *e) {
    if (lv_event_get_code(e) == LV_EVENT_READY) {
      const char* pass = lv_textarea_get_text(ta_wifi_pass);
      saveWifiCredentials(wifi_setup_ssid, pass);
      showWifiConnectingScreen();
    }
  }, LV_EVENT_ALL, NULL);
}

// ============================================================
//  WIFI SETUP: STEP 3 — Connect + result
// ============================================================
void showWifiConnectingScreen() {
  hideAllOverlays();
  if (scr_wifi_connecting) { lv_obj_del(scr_wifi_connecting); scr_wifi_connecting = nullptr; }
  buildWifiConnectingScreen();
  lv_obj_clear_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN);
  lv_timer_handler();

  // Actually connect now
  wifi_ok = false;
  WiFi.disconnect(true);
  delay(200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(cfg_wifi_ssid, cfg_wifi_password);

  lv_obj_t *status_lbl = (lv_obj_t*)lv_obj_get_user_data(scr_wifi_connecting);

  for (int i = 0; i < 20; i++) {
    delay(500);
    lv_timer_handler();
    if (WiFi.status() == WL_CONNECTED) {
      wifi_ok = true;
      break;
    }
  }

  if (wifi_ok) {
    syncNTP();
    updateHeaderStatus();
    lv_label_set_text(lbl_spoolman_weight, T(STR_WAIT_SCAN_SM));
    char ok_buf[80];
    snprintf(ok_buf, sizeof(ok_buf), T(STR_WIFI_CONNECTED_IP), WiFi.localIP().toString().c_str());
    if (status_lbl) lv_label_set_text(status_lbl, ok_buf);
    lv_obj_set_style_text_color(status_lbl, lv_color_hex(0x28d49a), 0);

    // Show next button
    lv_obj_t *btn_next = (lv_obj_t*)lv_obj_get_child(scr_wifi_connecting, -1);
    if (btn_next) lv_obj_clear_flag(btn_next, LV_OBJ_FLAG_HIDDEN);
  } else {
    updateHeaderStatus();
    char fail_buf[80];
    snprintf(fail_buf, sizeof(fail_buf), T(STR_WIFI_CONN_FAILED), cfg_wifi_ssid);
    if (status_lbl) lv_label_set_text(status_lbl, fail_buf);
    lv_obj_set_style_text_color(status_lbl, lv_color_hex(0xff8080), 0);

    // Show retry button
    lv_obj_t *btn_retry = (lv_obj_t*)lv_obj_get_child(scr_wifi_connecting, -2);
    if (btn_retry) lv_obj_clear_flag(btn_retry, LV_OBJ_FLAG_HIDDEN);
    lv_obj_t *btn_next = (lv_obj_t*)lv_obj_get_child(scr_wifi_connecting, -1);
    if (btn_next) lv_obj_clear_flag(btn_next, LV_OBJ_FLAG_HIDDEN);
  }
  lv_timer_handler();
}

void buildWifiConnectingScreen() {
  scr_wifi_connecting = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_wifi_connecting, 480, 320);
  lv_obj_set_pos(scr_wifi_connecting, 0, 0);
  lv_obj_add_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_wifi_connecting, 0, 0);
  lv_obj_set_style_border_width(scr_wifi_connecting, 0, 0);
  lv_obj_set_style_pad_all(scr_wifi_connecting, 0, 0);
  lv_obj_clear_flag(scr_wifi_connecting, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_wifi_connecting, lv_color_hex(0x0a1020), 0);

  lv_obj_t *title = lv_label_create(scr_wifi_connecting);
  lv_label_set_text(title, T(STR_WIFI_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 24);

  addBackButton(scr_wifi_connecting, [](lv_event_t *e) { showWifiSetupScreen(); });
  addCloseButton(scr_wifi_connecting);

  char conn_buf[64];
  snprintf(conn_buf, sizeof(conn_buf), T(STR_WIFI_CONNECTING), wifi_setup_ssid);
  lv_obj_t *lbl_connecting = lv_label_create(scr_wifi_connecting);
  lv_label_set_text(lbl_connecting, conn_buf);
  lv_obj_set_style_text_color(lbl_connecting, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_connecting, &lv_font_montserrat_16, 0);
  lv_obj_align(lbl_connecting, LV_ALIGN_TOP_MID, 0, 68);

  // Status label — larger font, filled after connection
  lv_obj_t *lbl_status_conn = lv_label_create(scr_wifi_connecting);
  lv_label_set_text(lbl_status_conn, "");
  lv_obj_set_style_text_color(lbl_status_conn, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_status_conn, &lv_font_montserrat_20, 0);
  lv_obj_set_style_text_align(lbl_status_conn, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_status_conn, LV_ALIGN_CENTER, 0, 10);
  lv_label_set_long_mode(lbl_status_conn, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_status_conn, 420);
  lv_obj_set_user_data(scr_wifi_connecting, lbl_status_conn);

  // Retry button (initially hidden)
  lv_obj_t *btn_retry = lv_btn_create(scr_wifi_connecting);
  lv_obj_set_size(btn_retry, 200, 48);
  lv_obj_align(btn_retry, LV_ALIGN_BOTTOM_MID, -110, -20);
  lv_obj_add_flag(btn_retry, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_retry, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_retry, 8, 0);
  lv_obj_set_style_shadow_width(btn_retry, 0, 0);
  lv_obj_set_style_border_width(btn_retry, 0, 0);
  lv_obj_add_event_cb(btn_retry, [](lv_event_t *e) { showWifiSetupScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_retry = lv_label_create(btn_retry);
  lv_label_set_text(lbl_retry, LV_SYMBOL_LEFT "  "); { char rb[32]; snprintf(rb,sizeof(rb),"%s",T(STR_RETRY)); lv_label_set_text(lbl_retry,rb); }
  lv_obj_set_style_text_color(lbl_retry, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_retry, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_retry);

  // Next button → Spoolman IP (initially hidden)
  lv_obj_t *btn_next = lv_btn_create(scr_wifi_connecting);
  lv_obj_set_size(btn_next, 200, 48);
  lv_obj_align(btn_next, LV_ALIGN_BOTTOM_MID, 110, -20);
  lv_obj_add_flag(btn_next, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_bg_color(btn_next, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_next, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_next, 8, 0);
  lv_obj_set_style_shadow_width(btn_next, 0, 0);
  lv_obj_set_style_border_width(btn_next, 0, 0);
  lv_obj_add_event_cb(btn_next, [](lv_event_t *e) {
    hideAllOverlays();
    if (scr_spoolman) { lv_obj_del(scr_spoolman); scr_spoolman = nullptr; }
    buildSpoolmanScreen();
    lv_obj_clear_flag(scr_spoolman, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_next = lv_label_create(btn_next);
  lv_label_set_text(lbl_next, "Spoolman  " LV_SYMBOL_RIGHT);
  lv_obj_set_style_text_color(lbl_next, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_next, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_next);
}

// ── WiFi info screen ──
void buildWifiScreen() {
  scr_wifi = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_wifi, 480, 320);
  lv_obj_set_pos(scr_wifi, 0, 0);
  lv_obj_add_flag(scr_wifi, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_wifi, 0, 0);
  lv_obj_set_style_border_width(scr_wifi, 0, 0);
  lv_obj_set_style_pad_all(scr_wifi, 0, 0);
  lv_obj_clear_flag(scr_wifi, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_wifi, lv_color_hex(0x0a1020), 0);

  lv_obj_t *title_wifi = lv_label_create(scr_wifi);
  lv_label_set_text(title_wifi, "WiFi Status");
  lv_obj_set_style_text_color(title_wifi, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title_wifi, &lv_font_montserrat_18, 0);
  lv_obj_align(title_wifi, LV_ALIGN_TOP_MID, 0, 14);

  lbl_wifi_info = lv_label_create(scr_wifi);
  lv_label_set_text(lbl_wifi_info, T(STR_WAIT));
  lv_obj_set_style_text_color(lbl_wifi_info, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_wifi_info, &lv_font_montserrat_16, 0);
  lv_obj_align(lbl_wifi_info, LV_ALIGN_CENTER, 0, 10);
  lv_label_set_long_mode(lbl_wifi_info, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_wifi_info, 380);
  lv_obj_set_style_text_align(lbl_wifi_info, LV_TEXT_ALIGN_LEFT, 0);

  addBackButton(scr_wifi, [](lv_event_t *e){ if (!scr_connection) buildConnectionScreen(); hideAllOverlays(); lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN); });
  addCloseButton(scr_wifi);
}

void updateWifiInfo() {
  if (!lbl_wifi_info) return;
  char buf[200];
  int rssi = WiFi.RSSI();
  const char* qual;
  if      (rssi >= -50) qual = T(STR_WIFI_QUAL_EXCELLENT);
  else if (rssi >= -65) qual = T(STR_WIFI_QUAL_GOOD);
  else if (rssi >= -75) qual = T(STR_WIFI_QUAL_MEDIUM);
  else                  qual = T(STR_WIFI_QUAL_WEAK);
  snprintf(buf, sizeof(buf),
    "SSID:    %s\n"
    "Status:  %s\n"
    "IP:      %s\n"
    "RSSI:    %d dBm  (%s)\n"
    "Spoolman:\n%s",
    cfg_wifi_ssid,
    wifi_ok ? T(STR_WIFI_STATUS_CONNECTED) : T(STR_WIFI_STATUS_DISCONNECTED),
    wifi_ok ? WiFi.localIP().toString().c_str() : "-",
    rssi, qual,
    cfg_spoolman_base
  );
  lv_label_set_text(lbl_wifi_info, buf);
}

// ── Spoolman IP screen (custom numpad with . and :) ──
// Input buffer for Spoolman IP
static char sp_ip_input[64] = "";
static lv_obj_t *lbl_sp_ip_display = nullptr;

void buildSpoolmanScreen() {
  scr_spoolman = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_spoolman, 480, 320);
  lv_obj_set_pos(scr_spoolman, 0, 0);
  lv_obj_add_flag(scr_spoolman, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_spoolman, 0, 0);
  lv_obj_set_style_border_width(scr_spoolman, 0, 0);
  lv_obj_set_style_pad_all(scr_spoolman, 0, 0);
  lv_obj_clear_flag(scr_spoolman, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_spoolman, lv_color_hex(0x0a1020), 0);

  // Header
  buildSubHeader(scr_spoolman, T(STR_SPOOLMAN_TITLE),
    [](lv_event_t *e){
      if (sp_ip_input[0]) saveSpoolmanIP(sp_ip_input);
      if (scr_connection) { lv_obj_del(scr_connection); scr_connection = nullptr; }
      buildConnectionScreen();
      hideAllOverlays(); lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
    });

  // Hint
  lv_obj_t *lbl_hint = lv_label_create(scr_spoolman);
  lv_label_set_text(lbl_hint, T(STR_SPOOLMAN_HINT));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_14, 0);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 56);

  // Input field (breit, zeigt aktuellen Wert oder Eingabe)
  strncpy(sp_ip_input, cfg_spoolman_ip, sizeof(sp_ip_input)-1);
  lv_obj_t *input_box = lv_obj_create(scr_spoolman);
  lv_obj_set_size(input_box, 420, 42);
  lv_obj_align(input_box, LV_ALIGN_TOP_MID, 0, 76);
  lv_obj_set_style_bg_color(input_box, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_border_color(input_box, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(input_box, 1, 0);
  lv_obj_set_style_radius(input_box, 6, 0);
  lv_obj_set_style_pad_all(input_box, 0, 0);
  lv_obj_clear_flag(input_box, LV_OBJ_FLAG_SCROLLABLE);

  lbl_sp_ip_display = lv_label_create(input_box);
  lv_label_set_text(lbl_sp_ip_display, sp_ip_input[0] ? sp_ip_input : "_");
  lv_obj_set_style_text_color(lbl_sp_ip_display, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_sp_ip_display, &lv_font_montserrat_18, 0);
  lv_obj_set_style_text_align(lbl_sp_ip_display, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(lbl_sp_ip_display);

  // ── Numpad: 4 rows, 3 columns ──
  // Row 1: 1 2 3
  // Row 2: 4 5 6
  // Row 3: 7 8 9
  // Row 4: . 0 :
  // Row 5: [⌫ delete] [✓ save] (half width each)
  const int NP_W = 130, NP_H = 34, NP_GAP = 4;
  const int NP_PAD_X = (480 - 3*NP_W - 2*NP_GAP) / 2;  // = 23
  const int NP_START_Y = 126;

  const char* np_labels[] = {
    "1","2","3",
    "4","5","6",
    "7","8","9",
    ".","0",":"
  };

  for (int i = 0; i < 12; i++) {
    int col = i % 3;
    int row = i / 3;
    int bx = NP_PAD_X + col * (NP_W + NP_GAP);
    int by = NP_START_Y + row * (NP_H + NP_GAP);

    lv_obj_t *btn = lv_btn_create(scr_spoolman);
    lv_obj_set_size(btn, NP_W, NP_H);
    lv_obj_set_pos(btn, bx, by);
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn, 6, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_set_style_border_width(btn, 1, 0);
    lv_obj_set_style_border_color(btn, lv_color_hex(0x1a2840), 0);

    lv_obj_t *lbl = lv_label_create(btn);
    lv_label_set_text(lbl, np_labels[i]);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_center(lbl);

    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      const char* ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
      int len = strlen(sp_ip_input);
      if (len < (int)sizeof(sp_ip_input)-1) {
        sp_ip_input[len] = ch[0];
        sp_ip_input[len+1] = '\0';
      }
      if (lbl_sp_ip_display) lv_label_set_text(lbl_sp_ip_display, sp_ip_input);
    }, LV_EVENT_CLICKED, NULL);
  }

  // Row 5 left: delete
  int by5 = NP_START_Y + 4 * (NP_H + NP_GAP);
  int bw5 = (3*NP_W + 2*NP_GAP - NP_GAP) / 2;

  lv_obj_t *btn_del = lv_btn_create(scr_spoolman);
  lv_obj_set_size(btn_del, bw5, NP_H);
  lv_obj_set_pos(btn_del, NP_PAD_X, by5);
  lv_obj_set_style_bg_color(btn_del, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_del, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_del, 6, 0);
  lv_obj_set_style_shadow_width(btn_del, 0, 0);
  lv_obj_set_style_border_width(btn_del, 1, 0);
  lv_obj_set_style_border_color(btn_del, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_del, [](lv_event_t *e) {
    int len = strlen(sp_ip_input);
    if (len > 0) sp_ip_input[len-1] = '\0';
    if (lbl_sp_ip_display) lv_label_set_text(lbl_sp_ip_display, sp_ip_input[0] ? sp_ip_input : "_");
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_del = lv_label_create(btn_del);
  lv_label_set_text(lbl_del, LV_SYMBOL_BACKSPACE);
  lv_obj_set_style_text_color(lbl_del, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_del, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_del);

  // Row 5 right: save
  lv_obj_t *btn_ok = lv_btn_create(scr_spoolman);
  lv_obj_set_size(btn_ok, bw5, NP_H);
  lv_obj_set_pos(btn_ok, NP_PAD_X + bw5 + NP_GAP, by5);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_ok, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok, 6, 0);
  lv_obj_set_style_shadow_width(btn_ok, 0, 0);
  lv_obj_set_style_border_width(btn_ok, 1, 0);
  lv_obj_set_style_border_color(btn_ok, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_ok, [](lv_event_t *e) {
    if (!sp_ip_input[0]) return;
    saveSpoolmanIP(sp_ip_input);
    bool in_setup = (strlen(cfg_wifi_ssid) > 0 && scr_connection == nullptr);
    if (in_setup) {
      showExtraFieldsScreen(true);
    } else {
      if (scr_connection) { lv_obj_del(scr_connection); scr_connection = nullptr; }
      buildConnectionScreen();
      hideAllOverlays(); lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok = lv_label_create(btn_ok);
  lv_label_set_text(lbl_ok, T(STR_BTN_SAVE));
  lv_obj_set_style_text_color(lbl_ok, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_ok, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_ok);
}

// ============================================================
//  SPOOLMAN CONNECTION FAILED SCREEN
// ============================================================
void showSpoolmanFailScreen(bool is_setup_flow) {
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
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 20);

  // Back → Spoolman IP
  addBackButton(scr_spoolman_fail, [](lv_event_t *e){
    if (scr_spoolman_fail) { lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
    hideAllOverlays();
    if (scr_spoolman) { lv_obj_del(scr_spoolman); scr_spoolman = nullptr; }
    buildSpoolmanScreen();
    lv_obj_clear_flag(scr_spoolman, LV_OBJ_FLAG_HIDDEN);
  });
  addCloseButton(scr_spoolman_fail);

  // Warning icon
  lv_obj_t *lbl_icon = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_icon, LV_SYMBOL_WARNING);
  lv_obj_set_style_text_color(lbl_icon, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_icon, &lv_font_montserrat_24, 0);
  lv_obj_align(lbl_icon, LV_ALIGN_TOP_MID, 0, 60);

  // IP entered
  char ip_buf[80];
  snprintf(ip_buf, sizeof(ip_buf), "http://%s", cfg_spoolman_ip);
  lv_obj_t *lbl_ip = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_ip, ip_buf);
  lv_obj_set_style_text_color(lbl_ip, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_ip, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_ip, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_ip, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_ip, 440);
  lv_obj_align(lbl_ip, LV_ALIGN_TOP_MID, 0, 96);

  // Error message (from RAM buffer)
  lv_obj_t *lbl_msg = lv_label_create(scr_spoolman_fail);
  lv_label_set_text(lbl_msg, buf_msg);
  lv_obj_set_style_text_color(lbl_msg, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_msg, &lv_font_montserrat_14, 0);
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
    if (scr_spoolman_fail) { lv_obj_del(scr_spoolman_fail); scr_spoolman_fail = nullptr; }
    hideAllOverlays();
    if (scr_spoolman) { lv_obj_del(scr_spoolman); scr_spoolman = nullptr; }
    buildSpoolmanScreen();
    lv_obj_clear_flag(scr_spoolman, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_r = lv_label_create(btn_retry);
  lv_label_set_text(lbl_r, buf_retry);
  lv_obj_set_style_text_color(lbl_r, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_r, &lv_font_montserrat_16, 0);
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
      hideAllOverlays(); lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_c = lv_label_create(btn_cont);
  lv_label_set_text(lbl_c, buf_skip);
  lv_obj_set_style_text_color(lbl_c, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_c, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_c);
}

// ── Calibration factor screen (custom numpad with .) ──
static char factor_input[16] = "";
static lv_obj_t *lbl_factor_display = nullptr;  // rebuilt on each open
static lv_obj_t *lbl_factor_cal_weight = nullptr; // live weight display in cal screen

void showFactorScreen() {
  // Null loop-update pointers first (loop checks these)
  lbl_factor_display    = nullptr;
  lbl_factor_result     = nullptr;
  lbl_factor_cal_weight = nullptr;
  // Always delete and rebuild — ensures clean state
  if (scr_factor) { lv_obj_del(scr_factor); scr_factor = nullptr; }
  buildFactorScreen();
  // Show it (hideAllOverlays would hide it again, so show directly)
  lv_obj_clear_flag(scr_factor, LV_OBJ_FLAG_HIDDEN);
  // Hide other overlays without touching scr_factor
  if (scr_settings)      lv_obj_add_flag(scr_settings,      LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi)          lv_obj_add_flag(scr_wifi,          LV_OBJ_FLAG_HIDDEN);
  if (scr_spoolman)      lv_obj_add_flag(scr_spoolman,      LV_OBJ_FLAG_HIDDEN);
  if (scr_bag)           lv_obj_add_flag(scr_bag,           LV_OBJ_FLAG_HIDDEN);
  if (scr_connection)    lv_obj_add_flag(scr_connection,    LV_OBJ_FLAG_HIDDEN);
  if (scr_scale_sub)     lv_obj_add_flag(scr_scale_sub,     LV_OBJ_FLAG_HIDDEN);
  if (scr_display)       lv_obj_add_flag(scr_display,       LV_OBJ_FLAG_HIDDEN);
  if (scr_system)        lv_obj_add_flag(scr_system,        LV_OBJ_FLAG_HIDDEN);
  if (scr_ota)           lv_obj_add_flag(scr_ota,           LV_OBJ_FLAG_HIDDEN);
  if (scr_ota_browser)   lv_obj_add_flag(scr_ota_browser,   LV_OBJ_FLAG_HIDDEN);
  if (scr_welcome)       lv_obj_add_flag(scr_welcome,       LV_OBJ_FLAG_HIDDEN);
  if (scr_first_boot)    lv_obj_add_flag(scr_first_boot,    LV_OBJ_FLAG_HIDDEN);
  if (scr_extra_fields)  lv_obj_add_flag(scr_extra_fields,  LV_OBJ_FLAG_HIDDEN);
  if (scr_cal_reminder)  lv_obj_add_flag(scr_cal_reminder,  LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_setup)    lv_obj_add_flag(scr_wifi_setup,    LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_pass)     lv_obj_add_flag(scr_wifi_pass,     LV_OBJ_FLAG_HIDDEN);
  if (scr_wifi_connecting) lv_obj_add_flag(scr_wifi_connecting, LV_OBJ_FLAG_HIDDEN);
  resetActivityTimer();
}

void buildFactorScreen() {
  scr_factor = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_factor, 480, 320);
  lv_obj_set_pos(scr_factor, 0, 0);
  lv_obj_add_flag(scr_factor, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_factor, 0, 0);
  lv_obj_set_style_border_width(scr_factor, 0, 0);
  lv_obj_set_style_pad_all(scr_factor, 0, 0);
  lv_obj_clear_flag(scr_factor, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_factor, lv_color_hex(0x0a1020), 0);

  // Crash protection: null label pointers (screen is rebuilt)
  lbl_factor_display = nullptr;
  lbl_factor_result  = nullptr;
  lbl_factor_cal_weight = nullptr;
  factor_input[0]    = '\0';

  buildSubHeader(scr_factor, T(STR_CAL_TITLE),
    [](lv_event_t *e){ if (!scr_scale_sub) buildScaleSubScreen(); hideAllOverlays(); lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN); });

  // Description / hint — single line, compact
  lv_obj_t *lbl_desc = lv_label_create(scr_factor);
  lv_label_set_text(lbl_desc, T(STR_CAL_TARE_HINT));
  lv_obj_set_style_text_color(lbl_desc, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_desc, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_align(lbl_desc, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_desc, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_desc, 440);
  lv_obj_align(lbl_desc, LV_ALIGN_TOP_MID, 0, 54);

  // Single status row: "Scale: <value>" left | "Factor: --" right
  lv_obj_t *lbl_cal_w_title = lv_label_create(scr_factor);
  lv_label_set_text(lbl_cal_w_title, T(STR_LBL_SCALE));
  lv_obj_set_style_text_color(lbl_cal_w_title, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_cal_w_title, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(lbl_cal_w_title, 12, 78);

  lbl_factor_cal_weight = lv_label_create(scr_factor);
  lv_label_set_text(lbl_factor_cal_weight, "-- g");
  lv_obj_set_style_text_color(lbl_factor_cal_weight, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_factor_cal_weight, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(lbl_factor_cal_weight, 56, 78);

  lbl_factor_result = lv_label_create(scr_factor);
  lv_label_set_text(lbl_factor_result, T(STR_CAL_FACTOR));
  lv_obj_set_style_text_color(lbl_factor_result, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_factor_result, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_align(lbl_factor_result, LV_TEXT_ALIGN_RIGHT, 0);
  lv_obj_set_width(lbl_factor_result, 220);
  lv_obj_set_pos(lbl_factor_result, 248, 78);

  // Input field — y=94 (below status row)
  lv_obj_t *input_box_f = lv_obj_create(scr_factor);
  lv_obj_set_size(input_box_f, 260, 34);
  lv_obj_align(input_box_f, LV_ALIGN_TOP_MID, 0, 94);
  lv_obj_set_style_bg_color(input_box_f, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_border_color(input_box_f, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(input_box_f, 1, 0);
  lv_obj_set_style_radius(input_box_f, 6, 0);
  lv_obj_set_style_pad_all(input_box_f, 0, 0);
  lv_obj_clear_flag(input_box_f, LV_OBJ_FLAG_SCROLLABLE);

  lbl_factor_display = lv_label_create(input_box_f);
  lv_label_set_text(lbl_factor_display, "_");
  lv_obj_set_style_text_color(lbl_factor_display, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_factor_display, &lv_font_montserrat_20, 0);
  lv_obj_set_style_text_align(lbl_factor_display, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(lbl_factor_display);

  // ── Numpad (104x30, start y=132) ──
  const int NP_W = 104, NP_H = 30, NP_GAP = 4;
  const int NP_PAD_X = (480 - 3*NP_W - 2*NP_GAP) / 2;
  const int NP_START_Y = 132;

  const char* np_labels_f[] = { "1","2","3","4","5","6","7","8","9",".","0","T" };

  for (int i = 0; i < 12; i++) {
    int col = i % 3, row = i / 3;
    lv_obj_t *btn = lv_btn_create(scr_factor);
    lv_obj_set_size(btn, NP_W, NP_H);
    lv_obj_set_pos(btn, NP_PAD_X + col*(NP_W+NP_GAP), NP_START_Y + row*(NP_H+NP_GAP));

    if (i == 11) {
      // TARE button in the free slot (bottom right of numpad)
      lv_obj_set_style_bg_color(btn, lv_color_hex(0x2a2010), 0);
      lv_obj_set_style_bg_color(btn, lv_color_hex(0x4a4020), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn, 6, 0);
      lv_obj_set_style_shadow_width(btn, 0, 0);
      lv_obj_set_style_border_width(btn, 1, 0);
      lv_obj_set_style_border_color(btn, lv_color_hex(0x3a3010), 0);
      lv_obj_add_event_cb(btn, [](lv_event_t *e) {
        if (!lbl_factor_result) return;
        if (scale_ready) {
          int32_t raw = nau.read();
          saveTareOffset(raw);
          scale_weight_g = 0.0f;
          memset(scale_filter_buf, 0, sizeof(scale_filter_buf));
          scale_filter_idx = 0; scale_filter_full = false;
          lv_label_set_text(lbl_factor_result, T(STR_TARE_OK));
          lv_label_set_text(lbl_scale_weight, "0 g");
          Serial.println("Tare (calibration screen) executed");
        } else {
          lv_label_set_text(lbl_factor_result, T(STR_TARE_NOT_READY));
        }
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl = lv_label_create(btn);
      lv_label_set_text(lbl, LV_SYMBOL_REFRESH "TARE");
      lv_obj_set_style_text_color(lbl, lv_color_hex(0xf0b838), 0);
      lv_obj_set_style_text_font(lbl, &lv_font_montserrat_14, 0);
      lv_obj_center(lbl);
    } else {
      lv_obj_set_style_bg_color(btn, lv_color_hex(0x0a1828), 0);
      lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
      lv_obj_set_style_radius(btn, 6, 0);
      lv_obj_set_style_shadow_width(btn, 0, 0);
      lv_obj_set_style_border_width(btn, 1, 0);
      lv_obj_set_style_border_color(btn, lv_color_hex(0x1a2840), 0);
      lv_obj_t *lbl = lv_label_create(btn);
      lv_label_set_text(lbl, np_labels_f[i]);
      lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
      lv_obj_set_style_text_font(lbl, &lv_font_montserrat_16, 0);
      lv_obj_center(lbl);
      lv_obj_add_event_cb(btn, [](lv_event_t *e) {
        if (!lbl_factor_display) return;
        const char* ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
        if (ch[0] == '.' && strchr(factor_input, '.')) return;
        int len = strlen(factor_input);
        if (len < (int)sizeof(factor_input)-1) { factor_input[len]=ch[0]; factor_input[len+1]='\0'; }
        lv_label_set_text(lbl_factor_display, factor_input[0] ? factor_input : "_");
      }, LV_EVENT_CLICKED, NULL);
    }
  }

  int by5_f = NP_START_Y + 4*(NP_H+NP_GAP);
  int bw5_f = (3*NP_W + 2*NP_GAP - NP_GAP) / 2;

  lv_obj_t *btn_del_f = lv_btn_create(scr_factor);
  lv_obj_set_size(btn_del_f, bw5_f, NP_H);
  lv_obj_set_pos(btn_del_f, NP_PAD_X, by5_f);
  lv_obj_set_style_bg_color(btn_del_f, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_del_f, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_del_f, 6, 0);
  lv_obj_set_style_shadow_width(btn_del_f, 0, 0);
  lv_obj_set_style_border_width(btn_del_f, 1, 0);
  lv_obj_set_style_border_color(btn_del_f, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_del_f, [](lv_event_t *e) {
    if (!lbl_factor_display) return;
    int len = strlen(factor_input);
    if (len > 0) factor_input[len-1] = '\0';
    lv_label_set_text(lbl_factor_display, factor_input[0] ? factor_input : "_");
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_del_f = lv_label_create(btn_del_f);
  lv_label_set_text(lbl_del_f, LV_SYMBOL_BACKSPACE);
  lv_obj_set_style_text_color(lbl_del_f, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_del_f, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_del_f);

  lv_obj_t *btn_ok_f = lv_btn_create(scr_factor);
  lv_obj_set_size(btn_ok_f, bw5_f, NP_H);
  lv_obj_set_pos(btn_ok_f, NP_PAD_X + bw5_f + NP_GAP, by5_f);
  lv_obj_set_style_bg_color(btn_ok_f, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_ok_f, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok_f, 6, 0);
  lv_obj_set_style_shadow_width(btn_ok_f, 0, 0);
  lv_obj_set_style_border_width(btn_ok_f, 1, 0);
  lv_obj_set_style_border_color(btn_ok_f, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_ok_f, [](lv_event_t *e) {
    if (!lbl_factor_result) return;
    float known_g = atof(factor_input);
    if (known_g > 0 && scale_ready) {
      int32_t raw = nau.read();
      float factor = (float)(raw - zero_offset) / known_g;
      saveCalFactor(factor);
      char buf[64];
      snprintf(buf, sizeof(buf), T(STR_CAL_OK), factor);
      lv_label_set_text(lbl_factor_result, buf);
    } else if (!scale_ready) {
      lv_label_set_text(lbl_factor_result, T(STR_TARE_NOT_READY));
    } else {
      lv_label_set_text(lbl_factor_result, T(STR_CAL_ZERO_ERR));
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok2_f = lv_label_create(btn_ok_f);
  lv_label_set_text(lbl_ok2_f, T(STR_BTN_CALCULATE));
  lv_obj_set_style_text_color(lbl_ok2_f, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_ok2_f, &lv_font_montserrat_14, 0);
  lv_obj_center(lbl_ok2_f);
}

// ── Bag weight screen (custom numpad with .) ──
static char bag_input[16] = "";
static lv_obj_t *lbl_bag_display = nullptr;
static lv_obj_t *lbl_bag_result_global = nullptr;

void buildBagScreen() {
  scr_bag = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_bag, 480, 320);
  lv_obj_set_pos(scr_bag, 0, 0);
  lv_obj_add_flag(scr_bag, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr_bag, 0, 0);
  lv_obj_set_style_border_width(scr_bag, 0, 0);
  lv_obj_set_style_pad_all(scr_bag, 0, 0);
  lv_obj_clear_flag(scr_bag, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(scr_bag, lv_color_hex(0x0a1020), 0);

  // Crash-Schutz: Pointer nullen
  lbl_bag_display      = nullptr;
  lbl_bag_result_global = nullptr;
  snprintf(bag_input, sizeof(bag_input), "%.1f", bag_weight_g);

  buildSubHeader(scr_bag, T(STR_BTN_BAGWEIGHT),
    [](lv_event_t *e){ if (!scr_scale_sub) buildScaleSubScreen(); hideAllOverlays(); lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN); });

  // Beschreibung — einzeilig
  lv_obj_t *lbl_desc = lv_label_create(scr_bag);
  lv_label_set_text(lbl_desc, T(STR_BAG_DESC));
  lv_obj_set_style_text_color(lbl_desc, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_desc, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_align(lbl_desc, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_desc, LV_ALIGN_TOP_MID, 0, 58);

  // Status-Label
  lbl_bag_result_global = lv_label_create(scr_bag);
  lv_label_set_text(lbl_bag_result_global, "");
  lv_obj_set_style_text_color(lbl_bag_result_global, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_bag_result_global, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_align(lbl_bag_result_global, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_bag_result_global, LV_ALIGN_TOP_MID, 0, 78);

  // Input field — vorbelegt
  lv_obj_t *input_box_b = lv_obj_create(scr_bag);
  lv_obj_set_size(input_box_b, 260, 38);
  lv_obj_align(input_box_b, LV_ALIGN_TOP_MID, 0, 98);
  lv_obj_set_style_bg_color(input_box_b, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_border_color(input_box_b, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_border_width(input_box_b, 1, 0);
  lv_obj_set_style_radius(input_box_b, 6, 0);
  lv_obj_set_style_pad_all(input_box_b, 0, 0);
  lv_obj_clear_flag(input_box_b, LV_OBJ_FLAG_SCROLLABLE);

  lbl_bag_display = lv_label_create(input_box_b);
  lv_label_set_text(lbl_bag_display, bag_input);
  lv_obj_set_style_text_color(lbl_bag_display, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bag_display, &lv_font_montserrat_20, 0);
  lv_obj_set_style_text_align(lbl_bag_display, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(lbl_bag_display);

  // ── Numpad (104x30, start y=144) ──
  const int NP_W = 104, NP_H = 30, NP_GAP = 4;
  const int NP_PAD_X = (480 - 3*NP_W - 2*NP_GAP) / 2;
  const int NP_START_Y = 144;

  const char* np_labels_b[] = { "1","2","3","4","5","6","7","8","9",".","0","" };

  for (int i = 0; i < 12; i++) {
    if (np_labels_b[i][0] == '\0') continue;
    int col = i % 3, row = i / 3;
    lv_obj_t *btn = lv_btn_create(scr_bag);
    lv_obj_set_size(btn, NP_W, NP_H);
    lv_obj_set_pos(btn, NP_PAD_X + col*(NP_W+NP_GAP), NP_START_Y + row*(NP_H+NP_GAP));
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x0a1828), 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn, 6, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_set_style_border_width(btn, 1, 0);
    lv_obj_set_style_border_color(btn, lv_color_hex(0x1a2840), 0);
    lv_obj_t *lbl = lv_label_create(btn);
    lv_label_set_text(lbl, np_labels_b[i]);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_16, 0);
    lv_obj_center(lbl);
    lv_obj_add_event_cb(btn, [](lv_event_t *e) {
      if (!lbl_bag_display) return;
      const char* ch = lv_label_get_text(lv_obj_get_child(lv_event_get_target(e), 0));
      if (ch[0] == '.' && strchr(bag_input, '.')) return;
      int len = strlen(bag_input);
      if (len < (int)sizeof(bag_input)-1) { bag_input[len]=ch[0]; bag_input[len+1]='\0'; }
      lv_label_set_text(lbl_bag_display, bag_input[0] ? bag_input : "_");
      if (lbl_bag_result_global) lv_label_set_text(lbl_bag_result_global, "");
    }, LV_EVENT_CLICKED, NULL);
  }

  int by5_b = NP_START_Y + 4*(NP_H+NP_GAP);
  int bw5_b = (3*NP_W + 2*NP_GAP - NP_GAP) / 2;

  lv_obj_t *btn_del_b = lv_btn_create(scr_bag);
  lv_obj_set_size(btn_del_b, bw5_b, NP_H);
  lv_obj_set_pos(btn_del_b, NP_PAD_X, by5_b);
  lv_obj_set_style_bg_color(btn_del_b, lv_color_hex(0x1a2030), 0);
  lv_obj_set_style_bg_color(btn_del_b, lv_color_hex(0x2a3040), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_del_b, 6, 0);
  lv_obj_set_style_shadow_width(btn_del_b, 0, 0);
  lv_obj_set_style_border_width(btn_del_b, 1, 0);
  lv_obj_set_style_border_color(btn_del_b, lv_color_hex(0x1a2840), 0);
  lv_obj_add_event_cb(btn_del_b, [](lv_event_t *e) {
    if (!lbl_bag_display) return;
    int len = strlen(bag_input);
    if (len > 0) bag_input[len-1] = '\0';
    lv_label_set_text(lbl_bag_display, bag_input[0] ? bag_input : "_");
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_del_b = lv_label_create(btn_del_b);
  lv_label_set_text(lbl_del_b, LV_SYMBOL_BACKSPACE);
  lv_obj_set_style_text_color(lbl_del_b, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_del_b, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_del_b);

  lv_obj_t *btn_ok_b = lv_btn_create(scr_bag);
  lv_obj_set_size(btn_ok_b, bw5_b, NP_H);
  lv_obj_set_pos(btn_ok_b, NP_PAD_X + bw5_b + NP_GAP, by5_b);
  lv_obj_set_style_bg_color(btn_ok_b, lv_color_hex(0x1a3020), 0);
  lv_obj_set_style_bg_color(btn_ok_b, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ok_b, 6, 0);
  lv_obj_set_style_shadow_width(btn_ok_b, 0, 0);
  lv_obj_set_style_border_width(btn_ok_b, 1, 0);
  lv_obj_set_style_border_color(btn_ok_b, lv_color_hex(0x2a5030), 0);
  lv_obj_add_event_cb(btn_ok_b, [](lv_event_t *e) {
    if (!lbl_bag_result_global) return;
    float w = atof(bag_input);
    if (w >= 0 && w < 1000) {
      saveBagWeight(w);
      char buf[32];
      snprintf(buf, sizeof(buf), T(STR_BAG_SAVED), w);
      lv_label_set_text(lbl_bag_result_global, buf);
    } else {
      lv_label_set_text(lbl_bag_result_global, T(STR_BAG_INVALID));
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_ok2_b = lv_label_create(btn_ok_b);
  lv_label_set_text(lbl_ok2_b, T(STR_BTN_SAVE));
  lv_obj_set_style_text_color(lbl_ok2_b, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_ok2_b, &lv_font_montserrat_14, 0);
  lv_obj_center(lbl_ok2_b);
}

// ── Settings Haupt-Screen ──
// ============================================================
//  HELPER: submenu header (back arrow + title + X)
// ============================================================
void buildSubHeader(lv_obj_t *parent, const char *title,
                    lv_event_cb_t back_cb, const char *back_hint) {
  // Back button (arrow top left)
  lv_obj_t *btn_back = lv_btn_create(parent);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_t *lbl_back = lv_label_create(btn_back);
  lv_label_set_text(lbl_back, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_back, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_back, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_back);
  lv_obj_add_event_cb(btn_back, back_cb, LV_EVENT_CLICKED, NULL);

  // Title Mitte
  lv_obj_t *lbl_title = lv_label_create(parent);
  lv_label_set_text(lbl_title, title);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

  // X-Button (rechts oben → Hauptscreen)
  lv_obj_t *btn_x = lv_btn_create(parent);
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
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_x);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ showMainScreen(); }, LV_EVENT_CLICKED, NULL);
  // Keine Trennlinie — wird von Buttons ueberlagert, sieht unschoen aus
}

// ============================================================
//  HELPER: Standard-Overlay-Screen erstellen
// ============================================================
lv_obj_t* buildOverlayScreen() {
  lv_obj_t *scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr, 480, 320);
  lv_obj_set_pos(scr, 0, 0);
  lv_obj_add_flag(scr, LV_OBJ_FLAG_HIDDEN);
  lv_obj_set_style_radius(scr, 0, 0);
  lv_obj_set_style_bg_color(scr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr, 0, 0);
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_pad_all(scr, 0, 0);
  return scr;
}

// ============================================================
//  SETTINGS MAIN SCREEN — 2x2 tiles (no TARE button)
// ============================================================
void buildSettingsScreen() {
  scr_settings = buildOverlayScreen();

  // Title
  lv_obj_t *title = lv_label_create(scr_settings);
  lv_label_set_text(title, T(STR_SETTINGS_TITLE));
  lv_obj_set_style_text_color(title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(title, &lv_font_montserrat_18, 0);
  lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 12);

  // X button — consistent 44x44 like all other screens
  lv_obj_t *btn_x = lv_btn_create(scr_settings);
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
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_x);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){ showMainScreen(); }, LV_EVENT_CLICKED, NULL);

  // 2x2 grid — y=60 top row, height=118, gap=8 → second row y=186, bottom y=304
  // Horizontal: x=8 and x=242, tile width=226, gap=8
  struct { const char *icon; const char *label; const char *sub; uint32_t col; } tiles[] = {
    { LV_SYMBOL_WIFI,     T(STR_TILE_CONNECTION), T(STR_TILE_CONN_SUB),    0x0d2a1a },
    { LV_SYMBOL_DRIVE,    T(STR_TILE_SCALE),      T(STR_TILE_SCALE_SUB),   0x0a1e30 },
    { LV_SYMBOL_IMAGE,    T(STR_TILE_DISPLAY),    T(STR_TILE_DISPLAY_SUB), 0x1a1a0a },
    { LV_SYMBOL_SETTINGS, T(STR_TILE_SYSTEM),     T(STR_TILE_SYSTEM_SUB),  0x1a0a1a },
  };
  int tx[] = { 8, 242, 8, 242 };
  int ty[] = { 60, 60, 186, 186 };

  for (int i = 0; i < 4; i++) {
    lv_obj_t *tile = lv_btn_create(scr_settings);
    lv_obj_set_size(tile, 226, 118);
    lv_obj_set_pos(tile, tx[i], ty[i]);
    lv_obj_set_style_bg_color(tile, lv_color_hex(tiles[i].col), 0);
    lv_obj_set_style_bg_color(tile, lv_color_hex(tiles[i].col + 0x101010), LV_STATE_PRESSED);
    lv_obj_set_style_radius(tile, 10, 0);
    lv_obj_set_style_shadow_width(tile, 0, 0);
    lv_obj_set_style_border_width(tile, 1, 0);
    lv_obj_set_style_border_color(tile, lv_color_hex(tiles[i].col + 0x181818), 0);

    lv_obj_t *ico = lv_label_create(tile);
    lv_label_set_text(ico, tiles[i].icon);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_TOP_LEFT, 10, 8);

    lv_obj_t *lbl = lv_label_create(tile);
    lv_label_set_text(lbl, tiles[i].label);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, -8);

    lv_obj_t *sub = lv_label_create(tile);
    lv_label_set_text(sub, tiles[i].sub);
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_12, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 16);

    lv_obj_add_event_cb(tile, [](lv_event_t *e) {
      intptr_t idx = (intptr_t)lv_event_get_user_data(e);
      switch (idx) {
        case 0:
          if (scr_connection) { lv_obj_del(scr_connection); scr_connection = nullptr; }
          buildConnectionScreen();
          hideAllOverlays(); lv_obj_clear_flag(scr_connection, LV_OBJ_FLAG_HIDDEN);
          break;
        case 1:
          if (!scr_scale_sub) buildScaleSubScreen();
          hideAllOverlays(); lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
          break;
        case 2:
          if (!scr_display) buildDisplayScreen();
          hideAllOverlays(); lv_obj_clear_flag(scr_display, LV_OBJ_FLAG_HIDDEN);
          break;
        case 3:
          if (!scr_system) buildSystemScreen();
          hideAllOverlays(); lv_obj_clear_flag(scr_system, LV_OBJ_FLAG_HIDDEN);
          break;
      }
      resetActivityTimer();
    }, LV_EVENT_CLICKED, (void*)(intptr_t)i);
  }

  // Yellow badge on System tile (top-right corner) — shown when update is available
  lbl_system_badge = lv_label_create(scr_settings);
  lv_label_set_text(lbl_system_badge, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_system_badge, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_system_badge, &lv_font_montserrat_18, 0);
  lv_obj_set_pos(lbl_system_badge, 456, 186);
  if (!update_available) lv_obj_add_flag(lbl_system_badge, LV_OBJ_FLAG_HIDDEN);
}

// ============================================================
//  SUBMENU: CONNECTION (WiFi + Spoolman IP + Extra Fields)
// ============================================================
void buildConnectionScreen() {
  scr_connection = buildOverlayScreen();
  buildSubHeader(scr_connection, T(STR_TILE_CONNECTION),
    [](lv_event_t *e){ showSettingsScreen(); });

  // All 3 buttons: 456x80, same layout, evenly spaced
  // y positions: 54, 142, 230 (gap 8px, fits within 320)
  const int BTN_W = 456, BTN_H = 80, BTN_X = 12;
  const int BTN_Y[] = { 54, 142, 230 };

  // ── WiFi Settings ──
  lv_obj_t *btn_wifi = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_wifi, BTN_W, BTN_H);
  lv_obj_set_pos(btn_wifi, BTN_X, BTN_Y[0]);
  lv_obj_set_style_bg_color(btn_wifi, lv_color_hex(0x0d2a1a), 0);
  lv_obj_set_style_bg_color(btn_wifi, lv_color_hex(0x1a4030), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_wifi, 10, 0);
  lv_obj_set_style_shadow_width(btn_wifi, 0, 0);
  lv_obj_set_style_border_width(btn_wifi, 1, 0);
  lv_obj_set_style_border_color(btn_wifi, lv_color_hex(0x1a4030), 0);
  { lv_obj_t *ico = lv_label_create(btn_wifi);
    lv_label_set_text(ico, LV_SYMBOL_WIFI);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_wifi);
    lv_label_set_text(lbl, T(STR_BTN_WIFI_SETTINGS));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_wifi);
    lv_label_set_text(sub, cfg_wifi_ssid[0] ? cfg_wifi_ssid : T(STR_BTN_WIFI_NONE));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_wifi, [](lv_event_t *e){ showWifiSetupScreen(); }, LV_EVENT_CLICKED, NULL);

  // ── Spoolman IP ──
  lv_obj_t *btn_sp = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_sp, BTN_W, BTN_H);
  lv_obj_set_pos(btn_sp, BTN_X, BTN_Y[1]);
  lv_obj_set_style_bg_color(btn_sp, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_sp, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_sp, 10, 0);
  lv_obj_set_style_shadow_width(btn_sp, 0, 0);
  lv_obj_set_style_border_width(btn_sp, 1, 0);
  lv_obj_set_style_border_color(btn_sp, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_sp);
    lv_label_set_text(ico, LV_SYMBOL_SETTINGS);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_sp);
    lv_label_set_text(lbl, "Spoolman IP");
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_sp);
    lv_label_set_text(sub, cfg_spoolman_ip[0] ? cfg_spoolman_ip : T(STR_BTN_WIFI_NONE));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_sp, [](lv_event_t *e){
    if (!scr_spoolman) buildSpoolmanScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_spoolman, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);

  // ── Spoolman Extra Fields ──
  lv_obj_t *btn_ef = lv_btn_create(scr_connection);
  lv_obj_set_size(btn_ef, BTN_W, BTN_H);
  lv_obj_set_pos(btn_ef, BTN_X, BTN_Y[2]);
  lv_obj_set_style_bg_color(btn_ef, lv_color_hex(0x0a1a0a), 0);
  lv_obj_set_style_bg_color(btn_ef, lv_color_hex(0x1a3020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_ef, 10, 0);
  lv_obj_set_style_shadow_width(btn_ef, 0, 0);
  lv_obj_set_style_border_width(btn_ef, 1, 0);
  lv_obj_set_style_border_color(btn_ef, lv_color_hex(0x1a3020), 0);
  { lv_obj_t *ico = lv_label_create(btn_ef);
    lv_label_set_text(ico, LV_SYMBOL_LIST);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_ef);
    lv_label_set_text(lbl, T(STR_EXTRA_FIELDS_TITLE));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_ef);
    lv_label_set_text(sub, "tag, last_dried");
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_ef, [](lv_event_t *e){
    showExtraFieldsScreen(false);
  }, LV_EVENT_CLICKED, NULL);
}

// Update the Last used/weighed cap label on the mainscreen
void updateLastUsedCapLabel() {
  if (!lbl_lu_cap) return;
  char buf[32];
  if (last_used_mode == 1)
    strncpy(buf, g_lang == LANG_DE ? "Zuletzt gewogen:" : "Last weighed:", sizeof(buf)-1);
  else
    strncpy(buf, T(STR_LBL_LAST_USED), sizeof(buf)-1);
  buf[sizeof(buf)-1] = 0;
  lv_label_set_text(lbl_lu_cap, buf);
}

// ============================================================
//  LAST USED MODE SCREEN
// ============================================================
void buildLastUsedScreen() {
  scr_lastused = buildOverlayScreen();
  buildSubHeader(scr_lastused, T(STR_LASTUSED_TITLE),
    [](lv_event_t *e){
      hideAllOverlays();
      if (!scr_scale_sub) buildScaleSubScreen();
      lv_obj_clear_flag(scr_scale_sub, LV_OBJ_FLAG_HIDDEN);
    });
  addCloseButton(scr_lastused);

  // Option 1: OpenSpoolMan
  lv_obj_t *btn_osm = lv_btn_create(scr_lastused);
  lv_obj_set_size(btn_osm, 210, 50);
  lv_obj_set_pos(btn_osm, 12, 58);
  bool osm_active = (last_used_mode == 0);
  lv_obj_set_style_bg_color(btn_osm, lv_color_hex(osm_active ? 0x1a3020 : 0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_osm, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_osm, 1, 0);
  lv_obj_set_style_border_color(btn_osm, lv_color_hex(osm_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_set_style_radius(btn_osm, 8, 0);
  lv_obj_set_style_shadow_width(btn_osm, 0, 0);
  lv_obj_add_event_cb(btn_osm, [](lv_event_t *e) {
    last_used_mode = 0;
    Preferences p; p.begin("spoolscale", false);
    p.putUChar("lu_mode", 0); p.end();
    updateLastUsedCapLabel();
    // Rebuild screen to update button states
    if (scr_lastused) { lv_obj_del(scr_lastused); scr_lastused = nullptr; }
    buildLastUsedScreen();
    lv_obj_clear_flag(scr_lastused, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_osm = lv_label_create(btn_osm);
  lv_label_set_text(lbl_osm, T(STR_LASTUSED_OPT_OSM));
  lv_obj_set_style_text_color(lbl_osm, lv_color_hex(osm_active ? 0x40c080 : 0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_osm, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_osm, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_osm, LV_ALIGN_CENTER, 0, 0);

  // Option 2: Last Weighed
  lv_obj_t *btn_lw = lv_btn_create(scr_lastused);
  lv_obj_set_size(btn_lw, 210, 50);
  lv_obj_set_pos(btn_lw, 238, 58);
  bool lw_active = (last_used_mode == 1);
  lv_obj_set_style_bg_color(btn_lw, lv_color_hex(lw_active ? 0x1a3020 : 0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_lw, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_lw, 1, 0);
  lv_obj_set_style_border_color(btn_lw, lv_color_hex(lw_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_set_style_radius(btn_lw, 8, 0);
  lv_obj_set_style_shadow_width(btn_lw, 0, 0);
  lv_obj_add_event_cb(btn_lw, [](lv_event_t *e) {
    last_used_mode = 1;
    Preferences p; p.begin("spoolscale", false);
    p.putUChar("lu_mode", 1); p.end();
    updateLastUsedCapLabel();
    if (scr_lastused) { lv_obj_del(scr_lastused); scr_lastused = nullptr; }
    buildLastUsedScreen();
    lv_obj_clear_flag(scr_lastused, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_lw = lv_label_create(btn_lw);
  lv_label_set_text(lbl_lw, T(STR_LASTUSED_OPT_WEIGHED));
  lv_obj_set_style_text_color(lbl_lw, lv_color_hex(lw_active ? 0x40c080 : 0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_lw, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_lw, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_lw, LV_ALIGN_CENTER, 0, 0);

  // Description text — shows text for active option
  lv_obj_t *lbl_desc = lv_label_create(scr_lastused);
  const char *desc = (last_used_mode == 0) ? T(STR_LASTUSED_DESC_OSM) : T(STR_LASTUSED_DESC_WEIGHED);
  char desc_buf[280];
  strncpy(desc_buf, desc, sizeof(desc_buf)-1); desc_buf[sizeof(desc_buf)-1] = 0;
  lv_label_set_text(lbl_desc, desc_buf);
  lv_obj_set_style_text_color(lbl_desc, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_desc, &lv_font_montserrat_14, 0);
  lv_label_set_long_mode(lbl_desc, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_desc, 448);
  lv_obj_set_style_text_align(lbl_desc, LV_TEXT_ALIGN_LEFT, 0);
  lv_obj_set_pos(lbl_desc, 16, 128);
}

// ============================================================
//  SUBMENU: SCALE (bag weight + calibration + last used mode)
// ============================================================
void buildScaleSubScreen() {
  scr_scale_sub = buildOverlayScreen();
  buildSubHeader(scr_scale_sub, T(STR_SCALE_TITLE),
    [](lv_event_t *e){ showSettingsScreen(); });

  // Bag weight button (y=58)
  lv_obj_t *btn_bag = lv_btn_create(scr_scale_sub);
  lv_obj_set_size(btn_bag, 456, 74);
  lv_obj_set_pos(btn_bag, 12, 58);
  lv_obj_set_style_bg_color(btn_bag, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_bag, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_bag, 10, 0);
  lv_obj_set_style_shadow_width(btn_bag, 0, 0);
  lv_obj_set_style_border_width(btn_bag, 1, 0);
  lv_obj_set_style_border_color(btn_bag, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_bag);
    lv_label_set_text(ico, LV_SYMBOL_DRIVE);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -20);
    lv_obj_t *lbl = lv_label_create(btn_bag);
    lv_label_set_text(lbl, T(STR_BTN_BAGWEIGHT));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    char buf[24]; snprintf(buf, sizeof(buf), T(STR_BAG_CURRENT), bag_weight_g);
    lv_obj_t *sub = lv_label_create(btn_bag);
    lv_label_set_text(sub, buf);
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 24); }
  lv_obj_add_event_cb(btn_bag, [](lv_event_t *e){
    if (!scr_bag) buildBagScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_bag, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);

  // Calibration button (y=140)
  lv_obj_t *btn_cal = lv_btn_create(scr_scale_sub);
  lv_obj_set_size(btn_cal, 456, 74);
  lv_obj_set_pos(btn_cal, 12, 140);
  lv_obj_set_style_bg_color(btn_cal, lv_color_hex(0x1a1a0a), 0);
  lv_obj_set_style_bg_color(btn_cal, lv_color_hex(0x2a2a1a), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cal, 10, 0);
  lv_obj_set_style_shadow_width(btn_cal, 0, 0);
  lv_obj_set_style_border_width(btn_cal, 1, 0);
  lv_obj_set_style_border_color(btn_cal, lv_color_hex(0x2a2a1a), 0);
  { lv_obj_t *ico = lv_label_create(btn_cal);
    lv_label_set_text(ico, LV_SYMBOL_EDIT);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -20);
    lv_obj_t *lbl = lv_label_create(btn_cal);
    lv_label_set_text(lbl, T(STR_BTN_CALIBRATE));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    char buf[32]; snprintf(buf, sizeof(buf), T(STR_CAL_FACTOR_SHORT), cal_factor);
    lv_obj_t *sub = lv_label_create(btn_cal);
    lv_label_set_text(sub, buf);
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 24); }
  lv_obj_add_event_cb(btn_cal, [](lv_event_t *e){
    showFactorScreen();
  }, LV_EVENT_CLICKED, NULL);

  // Last Used Mode button (y=222)
  lv_obj_t *btn_lu = lv_btn_create(scr_scale_sub);
  lv_obj_set_size(btn_lu, 456, 74);
  lv_obj_set_pos(btn_lu, 12, 222);
  lv_obj_set_style_bg_color(btn_lu, lv_color_hex(0x0a1e18), 0);
  lv_obj_set_style_bg_color(btn_lu, lv_color_hex(0x1a3028), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_lu, 10, 0);
  lv_obj_set_style_shadow_width(btn_lu, 0, 0);
  lv_obj_set_style_border_width(btn_lu, 1, 0);
  lv_obj_set_style_border_color(btn_lu, lv_color_hex(0x1a3028), 0);
  { lv_obj_t *ico = lv_label_create(btn_lu);
    lv_label_set_text(ico, LV_SYMBOL_SAVE);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -20);
    lv_obj_t *lbl = lv_label_create(btn_lu);
    char buf_t[32]; strncpy(buf_t, T(STR_BTN_LASTUSED_MODE), sizeof(buf_t)-1);
    lv_label_set_text(lbl, buf_t);
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_lu);
    char buf_s[48]; strncpy(buf_s, T(STR_BTN_LASTUSED_MODE_SUB), sizeof(buf_s)-1);
    lv_label_set_text(sub, buf_s);
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 24); }
  lv_obj_add_event_cb(btn_lu, [](lv_event_t *e){
    if (!scr_lastused) buildLastUsedScreen();
    hideAllOverlays();
    lv_obj_clear_flag(scr_lastused, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
}

// ============================================================
//  SUBMENU: DISPLAY (brightness + timeouts)
// ============================================================
void buildDisplayScreen() {
  scr_display = buildOverlayScreen();
  buildSubHeader(scr_display, T(STR_DISPLAY_TITLE),
    [](lv_event_t *e){ showSettingsScreen(); });

  // ── Brightness label (centered) ──
  lv_obj_t *lbl_bright = lv_label_create(scr_display);
  lv_label_set_text(lbl_bright, T(STR_BRIGHT_LABEL));
  lv_obj_set_style_text_color(lbl_bright, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_bright, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_bright, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_bright, LV_ALIGN_TOP_MID, 0, 54);

  // ── Brightness slider — full width ──
  lv_obj_t *slider = lv_slider_create(scr_display);
  lv_obj_set_size(slider, 456, 20);
  lv_obj_set_pos(slider, 12, 76);
  lv_slider_set_range(slider, 10, 255);
  lv_slider_set_value(slider, bright_normal, LV_ANIM_OFF);
  lv_obj_set_style_bg_color(slider, lv_color_hex(0x1a3060), LV_PART_MAIN);
  lv_obj_set_style_bg_color(slider, lv_color_hex(0x28d49a), LV_PART_INDICATOR);
  lv_obj_set_style_bg_color(slider, lv_color_hex(0x28d49a), LV_PART_KNOB);

  lv_obj_add_event_cb(slider, [](lv_event_t *e) {
    lv_obj_t *s = lv_event_get_target(e);
    int val = lv_slider_get_value(s);
    bright_normal = val;
    tft.setBrightness((uint8_t)val);
  }, LV_EVENT_VALUE_CHANGED, NULL);
  lv_obj_add_event_cb(slider, [](lv_event_t *e) {
    int val = lv_slider_get_value(lv_event_get_target(e));
    Preferences p; p.begin("spoolscale", false);
    p.putUChar("bright", (uint8_t)val);
    p.end();
    Serial.printf("Brightness saved: %d\n", val);
  }, LV_EVENT_RELEASED, NULL);

  // ── Dim timeout label (centered) ──
  lv_obj_t *lbl_dim = lv_label_create(scr_display);
  lv_label_set_text(lbl_dim, T(STR_DIM_LABEL));
  lv_obj_set_style_text_color(lbl_dim, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_dim, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_dim, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_dim, LV_ALIGN_TOP_MID, 0, 108);

  // ── Dim buttons: centered, 4 * 88px + 3 * 8px gap = 376px, offset = (480-376)/2 = 52 ──
  int dim_vals[] = {1, 2, 5, 10};
  int cur_dim = dim_timeout_ms / 60000;
  const int BTN_W = 88, BTN_H = 36, BTN_GAP = 8;
  const int BTN_START_X = (480 - 4*BTN_W - 3*BTN_GAP) / 2;
  for (int i = 0; i < 4; i++) {
    lv_obj_t *b = lv_btn_create(scr_display);
    lv_obj_set_size(b, BTN_W, BTN_H);
    lv_obj_set_pos(b, BTN_START_X + i * (BTN_W + BTN_GAP), 130);
    bool active = (cur_dim == dim_vals[i]);
    lv_obj_set_style_bg_color(b, active ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a3060), 0);
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    char buf[8]; snprintf(buf, sizeof(buf), "%d Min", dim_vals[i]);
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, active ? lv_color_hex(0x0a1020) : lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_14, 0);
    lv_obj_center(l);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      int val = (intptr_t)lv_event_get_user_data(e);
      dim_timeout_ms = val * 60000;
      Preferences prefs; prefs.begin("spoolscale", false);
      prefs.putUInt("dim_min", val);
      prefs.end();
      if (scr_display) { lv_obj_del(scr_display); scr_display = nullptr; }
      buildDisplayScreen();
      lv_obj_clear_flag(scr_display, LV_OBJ_FLAG_HIDDEN);
      Serial.printf("Dim timeout: %d min\n", val);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)dim_vals[i]);
  }

  // ── Sleep timeout label (centered) ──
  lv_obj_t *lbl_sleep = lv_label_create(scr_display);
  lv_label_set_text(lbl_sleep, T(STR_SLEEP_LABEL));
  lv_obj_set_style_text_color(lbl_sleep, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_sleep, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_sleep, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_sleep, LV_ALIGN_TOP_MID, 0, 178);

  int sleep_vals[] = {10, 20, 30, 60};
  int cur_sleep = sleep_timeout_ms / 60000;
  for (int i = 0; i < 4; i++) {
    lv_obj_t *b = lv_btn_create(scr_display);
    lv_obj_set_size(b, BTN_W, BTN_H);
    lv_obj_set_pos(b, BTN_START_X + i * (BTN_W + BTN_GAP), 200);
    bool active = (cur_sleep == sleep_vals[i]);
    lv_obj_set_style_bg_color(b, active ? lv_color_hex(0x28d49a) : lv_color_hex(0x1a3060), 0);
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_set_style_border_width(b, 0, 0);
    char buf[8]; snprintf(buf, sizeof(buf), "%d Min", sleep_vals[i]);
    lv_obj_t *l = lv_label_create(b);
    lv_label_set_text(l, buf);
    lv_obj_set_style_text_color(l, active ? lv_color_hex(0x0a1020) : lv_color_hex(0xc8d8f0), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_14, 0);
    lv_obj_center(l);
    lv_obj_add_event_cb(b, [](lv_event_t *e) {
      int val = (intptr_t)lv_event_get_user_data(e);
      sleep_timeout_ms = val * 60000;
      Preferences prefs; prefs.begin("spoolscale", false);
      prefs.putUInt("sleep_min", val);
      prefs.end();
      if (scr_display) { lv_obj_del(scr_display); scr_display = nullptr; }
      buildDisplayScreen();
      lv_obj_clear_flag(scr_display, LV_OBJ_FLAG_HIDDEN);
      Serial.printf("Sleep timeout: %d min\n", val);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)sleep_vals[i]);
  }

  // ── Hint (centered bottom) ──
  lv_obj_t *hint = lv_label_create(scr_display);
  lv_label_set_text(hint, T(STR_DISPLAY_HINT));
  lv_obj_set_style_text_color(hint, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint, 440);
  lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -8);
}

// ============================================================
// ============================================================
//  OTA — BROWSER UPLOAD
// ============================================================

void stopOtaServer() {
  if (ota_server_running) {
    ota_server.stop();
    ota_server_running = false;
    Serial.println("OTA server stopped");
  }
}

void startOtaServer() {
  if (!wifi_ok) return;

  // Route: Startseite mit Upload-Formular
  ota_server.on("/", HTTP_GET, []() {
    char ver_buf[20];
    strncpy(ver_buf, FW_VERSION, sizeof(ver_buf)-1);
    String version = String(ver_buf);
    String html =
      "<!DOCTYPE html><html><head>"
      "<meta charset='utf-8'>"
      "<meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<title>SpoolmanScale - Firmware Update</title>"
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
      "input[type=file]{width:100%;padding:12px;background:#06080f;border:1px dashed #1a3060;"
      "border-radius:8px;color:#4a6fa0;font-size:14px;margin-bottom:16px;cursor:pointer}"
      "input[type=file]:hover{border-color:#28d49a}"
      ".btn-flash{width:100%;padding:14px;background:#1a3020;color:#40c080;"
      "border:1px solid #2a5030;border-radius:8px;font-size:16px;font-weight:600;"
      "cursor:pointer;transition:background .2s}"
      ".btn-flash:hover{background:#2a5030}"
      ".hint{font-size:12px;color:#2a4060;margin-top:10px;text-align:center}"
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

      // Logo
      "<img src='data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCACWAJYDASIAAhEBAxEB/8QAHAAAAQUBAQEAAAAAAAAAAAAAAAECBAYHBQgD/8QAQRAAAQIFAgMFBQQHBwUAAAAAAQIDAAQFBhESIQcxQRMiUWFxFEKBkfAVMqGxCBYjJXLB0VJic4KSsuEzNlN0k//EABsBAAICAwEAAAAAAAAAAAAAAAABBAUCAwYH/8QALBEAAgEEAgEDAgUFAAAAAAAAAAECAwQRIQUSMRNBUSIyFDNxoeFhgbHw8f/aAAwDAQACEQMRAD8A8rwQQRtEJBCwQgGwQ4gQ2EMIII6FAotVr9UZplGp8zPzjxwhlhGpRHUnoEjO6iQB1IgFg58LG10jg5RaXLpevS4dTxwTKUxaQhO/JT6wdX+RIxvuecdOZsDhtPslmVaqMmvGEvJnnl4PjhwFJ+UaJXVKLw2SIWdaazGLMAgMW/iHYk/aLjcx26Z6lvq0szSE6cK6IWOQV4EbHy5RUI3pqSyjQ04vDEghxhMQCGwkOMJAAkEEEABBBBAB9YIXEJDAIIIIACDEEKkalBIzknGAMk+QHU+XWADq2hbVYuuuMUaiS6HZl3Kit1WlpltO63XFe62kbk+gGSQDvlLapdl0pdq2iTMzLgBqdUcRhyZV/eHuoGToZBwBurKiTEek0h3hxZbNBlGwbnrQQ7VVEgmWGAUsZHut5yr+04o9BgSaXINyUvpTqKjlSlHcqVzJPnFHyd+6a6Q8nUcJxMauK1bx7IY1KYcMw8tT7vVxzdX/ABEgggAjlyBxiHrBA2yOZhDggknl6Ryc3KTzJ7O4hTgo4itESpSTNSpsxS5xPaSswkBbeeeDkEeBBAIPMERmtX4T1xxxx22W3qu0k95kJw4jy1bIPxKT6xvtOt+TkZZucroU4+4ApqQB04B5KdI72DzCBgnrgHESpurKKEtK0NyzYwhpACGkDySMAfW8dJxVG7glJyxH4f8AujiecurGcnCEe0vla/6eU67ZF30SX9pqtt1OVYHNwtBaU+pQVY9TgRXuYBGCCMgjrHsiXnSF4cASCcbD6+X0cd462FJS8m5d1CYSwgKH2hLNp7neOO2SBsnc97GxB1dDnoFP5OWaMYMJDuRhIzENhIcYQjeABIIDBAB94SHGEhjEMJCmEgEEad+jzRJeaumZueotJckLdaTNaV7pcmlEiXQR1AUFOH/DT4xmSQVKCQNycCNzoMv9i8GKLS0Dspy4X11F453KFns2fkygnH94xouanp03Ik2dB160YfJ2KOt+p1Kbr80pThmVHSF/eCM8z6kk+pMdo4AJSkAZxv6xApuGJYNpGBgDHlgRKLgyG0nHr6xxFSt6s22ej/hnTiox9gKQpOwKvj5RZrXkmaZIprc42lT61EU9pwZGUnBeI6gHZI6qBPICOdb1NRUKg0ytZbaAU6+5/wCNpIBWv5bDzIibcFR9tnFLabSyykBDTKeTSEjCUAeQ/EnbeLLjLONafqSWl/n+Cj5nk6lCn6EXuX7L+SNOzjsy+pTyypSlFSlKOSSeZJPP65dYoUTu7qAzzwee34/j/FiHSzBm1YSQkJIKlYBA6j128Nue+DiOo1JyzYCS0lZxzcGomOlOOOWha0n9oMgbJA5Y/LHLy9N8SvZ2KlTpumzY7VubZUy4lQ2UFJx/P+sOqTLbWHkpwlRCSANknoR4dfwhtMKfaUEDfWMQCPIr7Dsq+5LPf9Vhamlk9VIJST8wYZHTuzH611nHL7Smsf8A2XHMjcYjTCQ4wQDGHlBCwQAfcw3EOMJDEJCQsITAA13PYOkEpKW1EEdCEkx6IvgNS9202jMgJl6VJtsNJHuhtpCMD5qjzs8Myz3+Er8jG635MlPEWYd1ZDgJB8jpP5ERXcmm6DwXXA9VeRbLFLrSpCNQHLc/CJLakYGoBRHIY84r8rOfs058N4ntzelJcGCEjOPHrHHOOD0dfUX6m/u+01zITh2ou6ABzDLR3/1OH4hMcYp1LAbGrWrGOfX+X9eRjs3An2RErIJUcSkq0yd+aggKUf8AUoxyacNU6lQ3GCojnjw+vIYJ5R2VnR9GhGH9P39zy7krj8RdTqe2dfotIj3jU36JQFmnhBm1ghoqGQD1WR19OpjzXLVWuNXu1PuVKdcqKJlKi6p5RK8qG3PGDywBjyjUuL9yOydzOU0A6W5ZpaR46tX9Pwir8LrbmLiu5FRfaIlZZYW4rG2RyH15RKRAN+m1l2mpUoAKXoVjz5mPlTtDep5ZCUNp1k+GBmCpuAutMJONJ1Hbby+vTxit8S6qaPYNRUhRTMTifZGMHcKc2J+Ccn4RnTh3koik8LJ53r8vOtVGYmpxkpTMvuPJcSdTatayrZQ2971jnRcqdMvEezbLZUO+hQynHoYrNdaZl6q83LthprYpQDsnI5DyibXt1TXZPRGoV+76tbIZhDCHJhD6xEJQEwQQQCJBhphVGEMMYkJ1hTEilyyZypysotam0PvobUpPNKSoAkeeM488QLbwJvCyRikKSUrB0qGD5iNLman9q2/Sa3q1zDLKZeb8e1bSEKJ/iSELHkYux4e2HVpNCafIIZUgYBbeWhw/xEHKj5mIZsaj0aRm5VtE4x2+DrU+pwBQ5HBOM9PSJNTjZ1IuLwRrfloUZqaTyciQnUONJUhQ5ZGI6tLmNc5LtqPdU+hJ9FKAMZrMTE/RXldo1mXQrca0gjzAzHcotyysw2Jlp0K7Ihekc8pOcY+Ecje8bVtpYktHo/HczSu44i9noC5Vl2rTSsbl1f8AuOI5kgtLc2gnACgU/Hb+ePnE6orTMKM02oFLh1pI6hXeH5xy3U946k4HUfXy+HpF8vBwktPDPnc9n0K4ptmbqcs6ZhlOgONOlBUnOdKscxnOPDJ8THSkpem0SRRKSUu3LtJHdbbAyfE784iCafSjHbrxv1Bx8SM/j8RDMal5Vk598nJP19eMZJGJ9ElTzxKyCsnfA29fr/mMh4qXAmtXAmnSyguTpmUBQ5KeP3z/AJRt8VeEWriPc5pUn9mU13NSmU7rG/YIPNR8/AdT47mMyk5ZEu2lShsPugnJUepPj4k9TFlZUXnuyHdVUl1PrLNhhrHvq3PkPCKtcav3w7v7qfyi0lRJyeZioXIv98vDPup/KN97+Wv1NFnup/YiZ84MiPmFecLqirLIfkQQzMEGAJZhIWEMAxOsT7c/7gp3/tN/7hEDrEmkPIl6vKTDqiltt9ClHwAUMmMofcjCe4s2aVmFtKSpDhbeG/dO8d+SuJSkBmpNh5vlqA3EVNsys+yl6WfQtkhOFNEYODnfHygW5MNrRrOtGpWVeXTbpiOi0znMfBYLgsyiXHLqek1oCyOQA5+kZPcNg1SiTJmGELRg7Lb5fXkY0OVmXGlh1hxSDzyDHfkribcQGKkyHEnbWB+ca6lKM1iSyb6VxOk8p4IfBi5hU6Ii3qmsoqcm3pQFbF1ofdUPEgYBHl4GLnMSym1E9c8+cVGftOl1BxM9SXS0+k60LZVpUg+II5GIhuutSqFS32hTp8t90uOpKFn1Kdj8hFZVsGt0/BY07+M39fkuOnCSVDu8iQIqV2Xi1T0OSVKUiYmyMFfNDO3XxPkPnFYrlwVifCm5meS0yeaGe4D6nOTFfLzbezSQSORI2HwjKjY7zMKl4sYgKpB1rmptxTrrqitSlHKlnxMfJaytRUo/LpDFrUtWpSiSesQ6hUJWRa1zLoTnkkbqV6CLBuMF8Ig/VN/LJucxSq+8h6sPqbOpIwnI5ZA3hlWuCanSW2My7J2wk95Xqf6Rzm9kiKy6uFUXWPgsLag4PMvJ9wYeFGPiDDgYhEs+oUCN4IZBDA6KjCGAwQAIYSFPOEEAMfITlQpcx7RTppxhROVJBylXqnkYutDvyVf0sVdoSjp27VO7Z9f7MUjMfNxCVDeJVKtOn9r0RqtvCr9yNnAZebDrK0kKOoLSQQdtoUKKCEae4E51c8knl+PWMdpVTqVHc1SEwUt57zKt21fDp8IvNBvWQnClmfHsMwTjvHLaj5H+RixpXcJ6emV1W1qQ8bRaJideZp025KvraWlpe6T5GKcFnAOTkgRaJ4tClzakAHW0sgjkdoqiT+zT44ESJeTRDGNClXWGOuobQpxxaUITuVKOAI5VWrspJZbQe3eHuJOw9TFTqVRm6g5qmHO6D3UDZKfhEKtdRhpbZNpW0p7ekd2rXMBlqnp1Hl2qht8B/WK0846+6XXlqcWrmVHJhEpPhDwgxW1KsqjzJlhCnGmsRQ1Ij7JhAnrDwkxqbybEJDkwoEOAgSAByggggA6J5wkLCGABQlSj3UlXoMwikqScKBB8xG+/o4WnQKzw/uWrS9pUW8bulJxDcpSqlMhKPZy2glYSdslXaDJ5lGMjEco8OZ/iFxBrEiLao/DBdGpLcxNyTjbi2VHWvLoI0gAjG41JwnnnMY9hmLcoDuY1mq8DqwqrWsxa9xUW5KbczzsvJ1KVKkModbSpSwsEqOAlCzkdUEEA4hLx4Jz9No32rbNz0W7GWqo3Sp1EiFNLlppa0toQrUoggrUlJORjIOCIzVQxwZIRkQx1nIwpPPyja7q4A1ClW/XHJC8KDV67QpL2mq0eUS4HpdJQVbKJOogbjupzjpmLjf3CGmXVeNn0C2GqNbinrSVUZp1MnhDykqbBUoIKSVHX94+cN1EwwzzbTatVKa0tiWfK5daSksubp3HTw+EfCpVepTLYaSBLoxhWg7q+Mbu3+j9TXZGmVVPFe1VUipu+yyk4mXcKX5nUU9k3+0wo5ChzHLlFZlOEUlL3nXrXuq/qDb85SphDTaH2HHVTaVI1hxtIUk6dJGc5wcjpmMvXl16p6MPRjntjZi4ZVD0MknGMmN7Y/R2qyr6rtszNy0iVRSqa1UhOuMuFp1lwqAJGrKMaFZyVRJp/CC37XvmyajXrjo9wWbXXnEInWtTDC3UtqLbSypZOhawkZB6EEDMauyNmDAjLOITlba0jxKSIQIEbPxPpF7MybFIqvCm1qOZ6aaZlZ+k0cNhbhWAlCJhDqk4USB38Eg+uK/elh21a76qXNcQae/WpWablp+VYpcyWpc6gHT2/3V9mCSQACdJA3gygM5xCjB3BB8wcxolz8PqVL2FUbttq7JevyNPW01OJ+zJiTUjtiUtrR2pw4nUMHGMc4unFWwadPcUL3q87UZC1rYpEzKsuTPsa3QXXZdrQ02y1gqJ7yjyAG++Tg7BgwjEGItHEK03bTqsqwmoS1Skp+RZqEhOMIUhMxLu50K0K7yT3SCk7jHnFaxGS2A3EEOxBABMhDCkwkIC+8L0cOOwefuu5bwoNWafzKv0ZhKkhrQnPeCStK9WrkQMYj0PY1/0PiFfF2vSjVSao1Ns72NU082n2uYRrWVukZO+OQODnOeceO4lU+pVCndv9n1Cdk/aGi097PMra7RB91WkjUPI5EYuOQyb1I8YbKsg2JRLKYrVYoVAm5icnZmbbS0/MduhxJShJwNu1KsnSO6ACckxHqnE6wrOtmdp3DpFbqs1V7hYrc2uotCXQwG3UO9inIyclATnBwFEk7AHAhgDAGAOQgg6jPSdwcV+Gskq9bytlVffum8JBMq5JTksES8mrs9GrWNlAbE4Ks422MT6Xxr4eNXRbNwOvVptyTtV+kTTHsBUG3D2JTgg97dC9xkYA5Z38uGEg6gazTb/oEtwRsK03DOfadEuUVKdSJclAYDy15Srko4UNhvGnS3Guw3rlvyYRVK9Ql1mclpiSq8lTQ5MhpuXaQprStKtHeQvmMYXkbx5aEIYfVAepqxxt4dzFzV6usTFa11i1U03snKerLbyFOFIJGxz2m5BI2jNZ68bLrnB/h/Y1VnqtJLpUy8qpvS8h2pbSpt0J0BWzneUkEDoT4RkUJC6oDYJW7rSsKzZ2j2vXKzc8xPT8hOIRMSKpKVlBKzCX9kqJy4sjSSkYxz8/jW6pwxTxATxClanVKimZrbdSft+ZpJSUhbmt5Cnyvs14UVKSBscAZxvGSmEh9RG8cQr/ALdrdjXnb8zf9frr1YLc1TEv0UsMSYae1pl8as5UDgrxpASPQ9ZzjFbr9yXixTLlrVAl66/KT8nV2KX2q5d1thLTjLjKslSSEjCh1/HzhiG4g6gXHi7XVV65mn/1uqV0oYlENJnZ2REqoHUoqQlvokZBBPPJ8Ipu0GIBGSWACCAwQASYMQQQhhiCCCABIMQQQDQYhMQQQCCA8swQQAJBiCCAAxCEQQQAJiDHSCCMhCEQ3rBBCGLzggggEf/Z' style='width:120px;height:120px;border-radius:12px;margin-bottom:8px'>"
      "<div class='version'>" + version + " &nbsp;|&nbsp; Firmware Update</div>"

      // Upload-Card
      "<div class='card'>"
      "<h2>Upload Firmware</h2>"
      "<form method='POST' action='/update' enctype='multipart/form-data'>"
      "<input type='file' name='firmware' accept='.bin' required>"
      "<button class='btn-flash' type='submit'>&#x2191;&nbsp; Flash Firmware</button>"
      "</form>"
      "<p class='hint'>Select SpoolmanScale vX.Y.Z.bin &mdash; device restarts automatically</p>"
      "</div>"

      // Links
      "<div class='links'>"
      "<a class='link-btn link-kofi' href='https://ko-fi.com/formfollowsfunction' target='_blank'>"
      "&#9749; Ko-fi</a>"
      "<a class='link-btn link-github' href='https://github.com/Niko11111/SpoolmanScale' target='_blank'>"
      "&#9873; GitHub</a>"
      "<a class='link-btn link-discord' href='https://discord.gg/GzQzGa5pBG' target='_blank'>"
      "&#128172; Discord</a>"
      "<a class='link-btn link-maker' href='https://makerworld.com/de/@FormFollowsF/upload' target='_blank'>"
      "&#11088; MakerWorld</a>"
      "</div>"

      "<div class='footer'>Not affiliated with Spoolman &mdash; Open Source Project</div>"
      "</body></html>";
    ota_server.send(200, "text/html", html);
  });

  // Route: Upload verarbeiten
  ota_server.on("/update", HTTP_POST,
    // Abschluss-Handler
    []() {
      bool ok = !Update.hasError();
      String msg = ok
        ? "<!DOCTYPE html><html><head><meta charset='utf-8'>"
          "<meta http-equiv='refresh' content='5;url=/'>"
          "<style>body{background:#06080f;color:#28d49a;font-family:-apple-system,sans-serif;"
          "display:flex;flex-direction:column;align-items:center;justify-content:center;"
          "min-height:100vh;gap:12px}"
          "h1{font-size:28px}p{color:#4a6fa0;font-size:14px}</style></head>"
          "<body><h1>&#10003; Update successful!</h1>"
          "<p>Device is restarting...</p><p style='color:#1a3060'>Redirecting in 5s</p></body></html>"
        : "<!DOCTYPE html><html><head><meta charset='utf-8'>"
          "<style>body{background:#06080f;color:#ff8080;font-family:-apple-system,sans-serif;"
          "display:flex;flex-direction:column;align-items:center;justify-content:center;"
          "min-height:100vh;gap:12px}"
          "h1{font-size:28px}p{color:#4a6fa0;font-size:14px}"
          "a{color:#28d49a}</style></head>"
          "<body><h1>&#10007; Update failed</h1>"
          "<p>Please try again.</p><a href='/'>&#8592; Back</a></body></html>";
      ota_server.send(200, "text/html", msg);
      if (ok) {
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_SUCCESS));
        lv_timer_handler();
        delay(1500);
        ESP.restart();
      } else {
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_FAIL));
      }
    },
    // Upload-Handler (chunk-weise)
    []() {
      HTTPUpload& upload = ota_server.upload();
      if (upload.status == UPLOAD_FILE_START) {
        Serial.printf("OTA start: %s\n", upload.filename.c_str());
        if (!Update.begin(UPDATE_SIZE_UNKNOWN)) {
          Serial.println("OTA begin() error");
        }
        if (lbl_ota_status) lv_label_set_text(lbl_ota_status,
          T(STR_OTA_UPLOADING));
        lv_timer_handler();
      } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
          Serial.println("OTA write() error");
        }
      } else if (upload.status == UPLOAD_FILE_END) {
        if (Update.end(true)) {
          Serial.printf("OTA end: %u bytes\n", upload.totalSize);
        } else {
          Serial.println("OTA end() error");
        }
      }
    }
  );

  ota_server.begin();
  ota_server_running = true;
  Serial.printf("OTA server started: http://%s/\n", WiFi.localIP().toString().c_str());
}

// OTA selection screen (browser / GitHub)
void showOtaScreen() {
  hideAllOverlays();
  if (!scr_ota) buildOtaScreen();
  lv_obj_clear_flag(scr_ota, LV_OBJ_FLAG_HIDDEN);
}

void buildOtaScreen() {
  scr_ota = buildOverlayScreen();
  buildSubHeader(scr_ota, T(STR_OTA_TITLE),
    [](lv_event_t *e){ showSettingsScreen(); /* via System */ });

  // Browser upload button
  lv_obj_t *btn_browser = lv_btn_create(scr_ota);
  lv_obj_set_size(btn_browser, 456, 80);
  lv_obj_set_pos(btn_browser, 12, 58);
  lv_obj_set_style_bg_color(btn_browser, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_browser, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_browser, 10, 0);
  lv_obj_set_style_shadow_width(btn_browser, 0, 0);
  lv_obj_set_style_border_width(btn_browser, 1, 0);
  lv_obj_set_style_border_color(btn_browser, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_browser);
    lv_label_set_text(ico, LV_SYMBOL_UPLOAD);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_browser);
    lv_label_set_text(lbl, T(STR_OTA_BROWSER));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_browser);
    lv_label_set_text(sub, T(STR_OTA_BROWSER_SUB));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_browser, [](lv_event_t *e){
    showOtaBrowserScreen();
  }, LV_EVENT_CLICKED, NULL);

  // GitHub OTA button — now active
  lv_obj_t *btn_gh = lv_btn_create(scr_ota);
  lv_obj_set_size(btn_gh, 456, 80);
  lv_obj_set_pos(btn_gh, 12, 150);
  lv_obj_set_style_bg_color(btn_gh, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_gh, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_gh, 10, 0);
  lv_obj_set_style_shadow_width(btn_gh, 0, 0);
  lv_obj_set_style_border_width(btn_gh, 1, 0);
  lv_obj_set_style_border_color(btn_gh, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_gh);
    lv_label_set_text(ico, LV_SYMBOL_DOWNLOAD);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_gh);
    lv_label_set_text(lbl, T(STR_OTA_GITHUB));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_gh);
    lv_label_set_text(sub, T(STR_OTA_GITHUB_SUB));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_gh, [](lv_event_t *e){
    showOtaGithubScreen();
  }, LV_EVENT_CLICKED, NULL);

  // Yellow badge top-right of GitHub button
  lbl_gh_btn_badge = lv_label_create(scr_ota);
  lv_label_set_text(lbl_gh_btn_badge, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_gh_btn_badge, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_gh_btn_badge, &lv_font_montserrat_18, 0);
  lv_obj_set_pos(lbl_gh_btn_badge, 456, 152);
  if (!update_available) lv_obj_add_flag(lbl_gh_btn_badge, LV_OBJ_FLAG_HIDDEN);

  // FW version at bottom
  lv_obj_t *ver_ota = lv_label_create(scr_ota);
  char ver_buf[32]; snprintf(ver_buf, sizeof(ver_buf), T(STR_OTA_CURRENT), FW_VERSION);
  lv_label_set_text(ver_ota, ver_buf);
  lv_obj_set_style_text_color(ver_ota, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(ver_ota, &lv_font_montserrat_12, 0);
  lv_obj_align(ver_ota, LV_ALIGN_BOTTOM_MID, 0, -8);
}

// OTA browser upload screen
void showOtaBrowserScreen() {
  hideAllOverlays();
  stopOtaServer();  // alten Server stoppen falls noch aktiv
  lbl_ota_status = nullptr;
  if (scr_ota_browser) { lv_obj_del(scr_ota_browser); scr_ota_browser = nullptr; }
  buildOtaBrowserScreen();
  lv_obj_clear_flag(scr_ota_browser, LV_OBJ_FLAG_HIDDEN);
  if (wifi_ok) startOtaServer();
}

void buildOtaBrowserScreen() {
  scr_ota_browser = buildOverlayScreen();
  buildSubHeader(scr_ota_browser, T(STR_OTA_BROWSER_TITLE),
    [](lv_event_t *e){
      stopOtaServer();
      showOtaScreen();
    });

  if (!wifi_ok) {
    lv_obj_t *lbl_err = lv_label_create(scr_ota_browser);
    lv_label_set_text(lbl_err, T(STR_OTA_NO_WIFI));
    lv_obj_set_style_text_color(lbl_err, lv_color_hex(0xff8080), 0);
    lv_obj_set_style_text_font(lbl_err, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_align(lbl_err, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_err, LV_ALIGN_CENTER, 0, 0);
    return;
  }

  // Show IP address
  char ip_buf[64];
  snprintf(ip_buf, sizeof(ip_buf), "http://%s/", WiFi.localIP().toString().c_str());

  lv_obj_t *lbl_hint = lv_label_create(scr_ota_browser);
  lv_label_set_text(lbl_hint, T(STR_OTA_OPEN_BROWSER));
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_14, 0);
  lv_obj_align(lbl_hint, LV_ALIGN_TOP_MID, 0, 58);

  lv_obj_t *lbl_ip = lv_label_create(scr_ota_browser);
  lv_label_set_text(lbl_ip, ip_buf);
  lv_obj_set_style_text_color(lbl_ip, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_ip, &lv_font_montserrat_20, 0);
  lv_obj_align(lbl_ip, LV_ALIGN_TOP_MID, 0, 80);

  lv_obj_t *lbl_hint2 = lv_label_create(scr_ota_browser);
  lv_label_set_text(lbl_hint2, T(STR_OTA_FILE_HINT));
  lv_obj_set_style_text_color(lbl_hint2, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hint2, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_align(lbl_hint2, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_hint2, LV_ALIGN_TOP_MID, 0, 112);
  lv_label_set_long_mode(lbl_hint2, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_hint2, 440);

  // Status label (filled by web server)
  lbl_ota_status = lv_label_create(scr_ota_browser);
  lv_label_set_text(lbl_ota_status, T(STR_OTA_WAITING));
  lv_obj_set_style_text_color(lbl_ota_status, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_ota_status, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_ota_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_ota_status, LV_ALIGN_CENTER, 0, 40);

  // Stop button
  lv_obj_t *btn_stop = lv_btn_create(scr_ota_browser);
  lv_obj_set_size(btn_stop, 200, 48);
  lv_obj_align(btn_stop, LV_ALIGN_BOTTOM_MID, 0, -20);
  lv_obj_set_style_bg_color(btn_stop, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_stop, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_stop, 8, 0);
  lv_obj_set_style_shadow_width(btn_stop, 0, 0);
  lv_obj_set_style_border_width(btn_stop, 0, 0);
  lv_obj_add_event_cb(btn_stop, [](lv_event_t *e){
    stopOtaServer();
    showOtaScreen();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_stop = lv_label_create(btn_stop);
  lv_label_set_text(lbl_stop, T(STR_BTN_STOP_SERVER));
  lv_obj_set_style_text_color(lbl_stop, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_stop, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_stop);
}

// ============================================================
//  GITHUB OTA: check latest release via API, download + flash
// ============================================================

// Parse semantic version "Beta_X.Y.Z" → comparable integer X*100000 + Y*1000 + Z
static int parseVersion(const char* v) {
  // Skip "Beta_" prefix if present
  const char *p = v;
  while (*p && !isdigit((unsigned char)*p)) p++;
  int major = 0, minor = 0, patch = 0;
  sscanf(p, "%d.%d.%d", &major, &minor, &patch);
  return major * 100000 + minor * 1000 + patch;
}

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
void doGithubOtaCheckSilent() {
  if (!wifi_ok) return;
  Serial.println("Silent OTA check...");

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  http.begin(client, "https://api.github.com/repos/Niko11111/SpoolmanScale/releases");
  http.addHeader("User-Agent", "SpoolmanScale-ESP32");
  http.setTimeout(8000);
  int code = http.GET();
  if (code != 200) { http.end(); Serial.printf("Silent OTA: HTTP %d\n", code); return; }

  String payload = http.getString();
  http.end();

  DynamicJsonDocument doc(4096);
  doc.clear();
  if (deserializeJson(doc, payload)) return;

  JsonArray arr = doc.as<JsonArray>();
  if (arr.size() == 0) return;

  const char* tag = arr[0]["tag_name"] | "";
  if (tag[0] == '\0') return;

  strncpy(gh_latest_version, tag, sizeof(gh_latest_version)-1);
  gh_latest_version[sizeof(gh_latest_version)-1] = 0;

  int cur    = parseVersion(FW_VERSION);
  int remote = parseVersion(gh_latest_version);
  Serial.printf("Silent OTA: installed=%s latest=%s\n", FW_VERSION, gh_latest_version);

  if (remote > cur) {
    update_available = true;
    showUpdateBadges(true);
    Serial.println("Update available — badge shown");
  }
}

void doGithubOtaCheck() {
  if (!lbl_gh_status) return;

  if (!wifi_ok) {
    char buf[64]; strncpy(buf, T(STR_GH_OTA_NO_WIFI), sizeof(buf)-1); buf[sizeof(buf)-1]=0;
    lv_label_set_text(lbl_gh_status, buf);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    return;
  }

  char buf[64]; strncpy(buf, T(STR_GH_OTA_CHECKING), sizeof(buf)-1); buf[sizeof(buf)-1]=0;
  lv_label_set_text(lbl_gh_status, buf);
  lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x4a6fa0), 0);
  lv_timer_handler();

  // Query GitHub releases API
  WiFiClientSecure client;
  client.setInsecure();  // skip cert check — connection is still encrypted
  HTTPClient http;
  http.begin(client, "https://api.github.com/repos/Niko11111/SpoolmanScale/releases/latest");
  http.addHeader("User-Agent", "SpoolmanScale-ESP32");
  http.setTimeout(8000);
  int code = http.GET();
  Serial.printf("GitHub API: %d\n", code);

  if (code != 200) {
    snprintf(buf, sizeof(buf), "HTTP %d", code);
    lv_label_set_text(lbl_gh_status, buf);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    http.end();
    return;
  }

  String payload = http.getString();
  http.end();

  // Parse tag_name
  DynamicJsonDocument doc(2048);
  doc.clear();
  if (deserializeJson(doc, payload)) {
    lv_label_set_text(lbl_gh_status, "JSON error");
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    return;
  }

  const char* tag = doc["tag_name"] | "";
  if (tag[0] == '\0') {
    lv_label_set_text(lbl_gh_status, "No release found");
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    return;
  }

  strncpy(gh_latest_version, tag, sizeof(gh_latest_version)-1);
  gh_latest_version[sizeof(gh_latest_version)-1] = 0;

  // Show installed / latest labels
  if (lbl_gh_installed) {
    char inst[48]; snprintf(inst, sizeof(inst), T(STR_GH_OTA_INSTALLED), FW_VERSION);
    lv_label_set_text(lbl_gh_installed, inst);
    lv_obj_clear_flag(lbl_gh_installed, LV_OBJ_FLAG_HIDDEN);
  }
  if (lbl_gh_latest) {
    char lat[48]; snprintf(lat, sizeof(lat), T(STR_GH_OTA_LATEST), gh_latest_version);
    lv_label_set_text(lbl_gh_latest, lat);
    lv_obj_clear_flag(lbl_gh_latest, LV_OBJ_FLAG_HIDDEN);
  }

  // Compare versions
  int cur = parseVersion(FW_VERSION);
  int remote = parseVersion(gh_latest_version);

  if (remote <= cur) {
    char upd[48]; strncpy(upd, T(STR_GH_OTA_UP_TO_DATE), sizeof(upd)-1); upd[sizeof(upd)-1]=0;
    lv_label_set_text(lbl_gh_status, upd);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x40c080), 0);
  } else {
    char avail[64]; snprintf(avail, sizeof(avail), T(STR_GH_OTA_UPDATE_AVAIL), gh_latest_version);
    lv_label_set_text(lbl_gh_status, avail);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xf0b838), 0);
    // Activate update button
    if (btn_gh_update) {
      lv_obj_clear_state(btn_gh_update, LV_STATE_DISABLED);
      lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x1a3020), 0);
      lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
      lv_obj_set_style_border_color(btn_gh_update, lv_color_hex(0x28d49a), 0);
      if (lbl_gh_update_btn) {
        char ubtn[48]; strncpy(ubtn, T(STR_GH_OTA_UPDATE_BTN), sizeof(ubtn)-1); ubtn[sizeof(ubtn)-1]=0;
        lv_label_set_text(lbl_gh_update_btn, ubtn);
        lv_obj_set_style_text_color(lbl_gh_update_btn, lv_color_hex(0x40c080), 0);
      }
    }
    update_available = true;
    showUpdateBadges(true);
  }
}

void doGithubOtaFlash(const char* version) {
  if (!lbl_gh_status) return;

  // Show fullscreen blocking overlay on top layer — survives any screen changes
  lv_obj_t *overlay = lv_obj_create(lv_layer_top());
  lv_obj_set_size(overlay, 480, 320);
  lv_obj_set_pos(overlay, 0, 0);
  lv_obj_set_style_bg_color(overlay, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_bg_opa(overlay, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(overlay, 0, 0);
  lv_obj_set_style_pad_all(overlay, 0, 0);
  lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_clear_flag(overlay, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *ico = lv_label_create(overlay);
  lv_label_set_text(ico, LV_SYMBOL_DOWNLOAD);
  lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
  lv_obj_align(ico, LV_ALIGN_CENTER, 0, -40);

  lv_obj_t *lbl_ov = lv_label_create(overlay);
  char buf_ov[64]; strncpy(buf_ov, T(STR_GH_OTA_FLASHING), sizeof(buf_ov)-1); buf_ov[sizeof(buf_ov)-1]=0;
  lv_label_set_text(lbl_ov, buf_ov);
  lv_obj_set_style_text_color(lbl_ov, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_ov, &lv_font_montserrat_18, 0);
  lv_obj_set_style_text_align(lbl_ov, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_ov, LV_ALIGN_CENTER, 0, 0);

  lv_obj_t *lbl_hint = lv_label_create(overlay);
  lv_label_set_text(lbl_hint, "~30-60 sec");
  lv_obj_set_style_text_color(lbl_hint, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_hint, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_align(lbl_hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_hint, LV_ALIGN_CENTER, 0, 30);

  // Force render — must happen before any blocking HTTP call
  lv_refr_now(NULL);
  lv_timer_handler();

  char buf[64]; strncpy(buf, T(STR_GH_OTA_FLASHING), sizeof(buf)-1); buf[sizeof(buf)-1]=0;
  lv_label_set_text(lbl_gh_status, buf);
  lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xf0b838), 0);
  if (btn_gh_update) lv_obj_add_flag(btn_gh_update, LV_OBJ_FLAG_HIDDEN);
  lv_timer_handler();

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;

  // GitHub Releases /latest/download/ redirects automatically
  String url = "https://github.com/Niko11111/SpoolmanScale/releases/latest/download/SpoolmanScale.bin";
  http.begin(client, url);
  http.addHeader("User-Agent", "SpoolmanScale-ESP32");
  http.setTimeout(60000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

  int code = http.GET();
  Serial.printf("GitHub OTA download: %d\n", code);

  if (code != 200) {
    snprintf(buf, sizeof(buf), "%s (HTTP %d)", T(STR_GH_OTA_FLASH_FAIL), code);
    lv_label_set_text(lbl_gh_status, buf);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    http.end();
    return;
  }

  int len = http.getSize();
  WiFiClient* stream = http.getStreamPtr();

  if (!Update.begin(len > 0 ? len : UPDATE_SIZE_UNKNOWN)) {
    lv_label_set_text(lbl_gh_status, T(STR_GH_OTA_FLASH_FAIL));
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
    http.end();
    return;
  }

  uint8_t buf8[512];
  size_t written = 0;
  while (http.connected() && (len > 0 || len == -1)) {
    size_t available = stream->available();
    if (available) {
      size_t toRead = min(available, sizeof(buf8));
      size_t rd = stream->readBytes(buf8, toRead);
      if (Update.write(buf8, rd) != rd) break;
      written += rd;
      if (len > 0) len -= rd;
    }
    lv_timer_handler();  // keep UI alive
    delay(1);
  }
  http.end();

  if (Update.end(true) && !Update.hasError()) {
    char ok[64]; strncpy(ok, T(STR_GH_OTA_FLASH_OK), sizeof(ok)-1); ok[sizeof(ok)-1]=0;
    lv_label_set_text(lbl_gh_status, ok);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x40c080), 0);
    lv_timer_handler();
    delay(2000);
    ESP.restart();
  } else {
    char fail[64]; strncpy(fail, T(STR_GH_OTA_FLASH_FAIL), sizeof(fail)-1); fail[sizeof(fail)-1]=0;
    lv_label_set_text(lbl_gh_status, fail);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xff8080), 0);
  }
}

void showOtaGithubScreen() {
  // Reset UI state but keep version info if background check already found an update
  lbl_gh_status     = nullptr;
  lbl_gh_installed  = nullptr;
  lbl_gh_latest     = nullptr;
  btn_gh_update     = nullptr;
  lbl_gh_update_btn = nullptr;
  if (!update_available) gh_latest_version[0] = '\0';  // keep if silent check found something

  if (scr_ota_github) { lv_obj_del(scr_ota_github); scr_ota_github = nullptr; }
  buildOtaGithubScreen();
  hideAllOverlays();
  lv_obj_clear_flag(scr_ota_github, LV_OBJ_FLAG_HIDDEN);
}

void buildOtaGithubScreen() {
  scr_ota_github = buildOverlayScreen();

  char buf_title[32];
  strncpy(buf_title, T(STR_GH_OTA_TITLE), sizeof(buf_title)-1); buf_title[sizeof(buf_title)-1]=0;
  buildSubHeader(scr_ota_github, buf_title,
    [](lv_event_t *e){ showOtaScreen(); });

  // ── "Check for Updates" button ──
  lv_obj_t *btn_check = lv_btn_create(scr_ota_github);
  lv_obj_set_size(btn_check, 280, 44);
  lv_obj_align(btn_check, LV_ALIGN_TOP_MID, 0, 56);
  lv_obj_set_style_bg_color(btn_check, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_check, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_check, 8, 0);
  lv_obj_set_style_shadow_width(btn_check, 0, 0);
  lv_obj_set_style_border_width(btn_check, 1, 0);
  lv_obj_set_style_border_color(btn_check, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_check, [](lv_event_t *e){ doGithubOtaCheck(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_check = lv_label_create(btn_check);
  char buf_check[48]; strncpy(buf_check, T(STR_GH_OTA_CHECK_BTN), sizeof(buf_check)-1); buf_check[sizeof(buf_check)-1]=0;
  lv_label_set_text(lbl_check, buf_check);
  lv_obj_set_style_text_color(lbl_check, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_check, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_check, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_check, LV_ALIGN_CENTER, 0, 0);

  // ── Status label ──
  lbl_gh_status = lv_label_create(scr_ota_github);
  lv_label_set_text(lbl_gh_status, "");
  lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_gh_status, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_align(lbl_gh_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_gh_status, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_gh_status, 440);
  lv_obj_align(lbl_gh_status, LV_ALIGN_TOP_MID, 0, 112);

  // ── Installed version label (hidden until check) ──
  lbl_gh_installed = lv_label_create(scr_ota_github);
  lv_label_set_text(lbl_gh_installed, "");
  lv_obj_set_style_text_color(lbl_gh_installed, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_gh_installed, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_align(lbl_gh_installed, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_gh_installed, LV_ALIGN_TOP_MID, 0, 148);
  lv_obj_add_flag(lbl_gh_installed, LV_OBJ_FLAG_HIDDEN);

  // ── Latest version label (hidden until check) ──
  lbl_gh_latest = lv_label_create(scr_ota_github);
  lv_label_set_text(lbl_gh_latest, "");
  lv_obj_set_style_text_color(lbl_gh_latest, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_gh_latest, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_align(lbl_gh_latest, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_gh_latest, LV_ALIGN_TOP_MID, 0, 170);
  lv_obj_add_flag(lbl_gh_latest, LV_OBJ_FLAG_HIDDEN);

  // ── Update button — always visible, greyed out until update available ──
  btn_gh_update = lv_btn_create(scr_ota_github);
  lv_obj_set_size(btn_gh_update, 280, 48);
  lv_obj_align(btn_gh_update, LV_ALIGN_BOTTOM_MID, 0, -24);
  lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x111820), 0);
  lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x111820), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_gh_update, 8, 0);
  lv_obj_set_style_shadow_width(btn_gh_update, 0, 0);
  lv_obj_set_style_border_width(btn_gh_update, 1, 0);
  lv_obj_set_style_border_color(btn_gh_update, lv_color_hex(0x1a2030), 0);
  lv_obj_add_state(btn_gh_update, LV_STATE_DISABLED);
  lv_obj_add_event_cb(btn_gh_update, [](lv_event_t *e){
    doGithubOtaFlash(gh_latest_version);
  }, LV_EVENT_CLICKED, NULL);

  lbl_gh_update_btn = lv_label_create(btn_gh_update);
  char buf_ubtn[48]; strncpy(buf_ubtn, T(STR_GH_OTA_UPDATE_BTN), sizeof(buf_ubtn)-1); buf_ubtn[sizeof(buf_ubtn)-1]=0;
  lv_label_set_text(lbl_gh_update_btn, buf_ubtn);
  lv_obj_set_style_text_color(lbl_gh_update_btn, lv_color_hex(0x2a3848), 0);
  lv_obj_set_style_text_font(lbl_gh_update_btn, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_gh_update_btn, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_gh_update_btn, LV_ALIGN_CENTER, 0, 0);

  // If background check already found an update, pre-activate button and show version info
  if (update_available && gh_latest_version[0] != '\0') {
    lv_obj_clear_state(btn_gh_update, LV_STATE_DISABLED);
    lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x1a3020), 0);
    lv_obj_set_style_bg_color(btn_gh_update, lv_color_hex(0x2a5030), LV_STATE_PRESSED);
    lv_obj_set_style_border_color(btn_gh_update, lv_color_hex(0x28d49a), 0);
    char ubtn2[48]; strncpy(ubtn2, T(STR_GH_OTA_UPDATE_BTN), sizeof(ubtn2)-1); ubtn2[sizeof(ubtn2)-1]=0;
    lv_label_set_text(lbl_gh_update_btn, ubtn2);
    lv_obj_set_style_text_color(lbl_gh_update_btn, lv_color_hex(0x40c080), 0);
    // Show version info labels
    char avail[64]; snprintf(avail, sizeof(avail), T(STR_GH_OTA_UPDATE_AVAIL), gh_latest_version);
    lv_label_set_text(lbl_gh_status, avail);
    lv_obj_set_style_text_color(lbl_gh_status, lv_color_hex(0xf0b838), 0);
    char inst[48]; snprintf(inst, sizeof(inst), T(STR_GH_OTA_INSTALLED), FW_VERSION);
    lv_label_set_text(lbl_gh_installed, inst);
    lv_obj_clear_flag(lbl_gh_installed, LV_OBJ_FLAG_HIDDEN);
    char lat[48]; snprintf(lat, sizeof(lat), T(STR_GH_OTA_LATEST), gh_latest_version);
    lv_label_set_text(lbl_gh_latest, lat);
    lv_obj_clear_flag(lbl_gh_latest, LV_OBJ_FLAG_HIDDEN);
  }
}

// ============================================================
//  SUBMENU: SYSTEM (language + update + info/donate)
// ============================================================
void showLanguageScreen();  // Forward

void buildSystemScreen() {
  scr_system = buildOverlayScreen();
  buildSubHeader(scr_system, T(STR_SYSTEM_TITLE),
    [](lv_event_t *e){ showSettingsScreen(); });

  // 3 buttons: same layout as Connection / Scale submenu
  // 3 * 80px + 2 * 8px gap = 256px, start y=52 -> ends at 308
  const int BTN_W = 456, BTN_H = 80, BTN_GAP = 8, BTN_X = 12, BTN_Y0 = 52;

  // ── Button 1: Language ──
  lv_obj_t *btn_lang = lv_btn_create(scr_system);
  lv_obj_set_size(btn_lang, BTN_W, BTN_H);
  lv_obj_set_pos(btn_lang, BTN_X, BTN_Y0);
  lv_obj_set_style_bg_color(btn_lang, lv_color_hex(0x0a1a2a), 0);
  lv_obj_set_style_bg_color(btn_lang, lv_color_hex(0x1a2a40), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_lang, 10, 0);
  lv_obj_set_style_shadow_width(btn_lang, 0, 0);
  lv_obj_set_style_border_width(btn_lang, 1, 0);
  lv_obj_set_style_border_color(btn_lang, lv_color_hex(0x1a2a40), 0);
  { lv_obj_t *ico = lv_label_create(btn_lang);
    lv_label_set_text(ico, LV_SYMBOL_LIST);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_lang);
    lv_label_set_text(lbl, T(STR_LANG_TITLE));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_lang);
    lv_label_set_text(sub, T(STR_BTN_LANG_SUB));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_lang, [](lv_event_t *e){ showLanguageScreen(); }, LV_EVENT_CLICKED, NULL);

  // ── Button 2: Firmware update ──
  lv_obj_t *btn_upd = lv_btn_create(scr_system);
  lv_obj_set_size(btn_upd, BTN_W, BTN_H);
  lv_obj_set_pos(btn_upd, BTN_X, BTN_Y0 + BTN_H + BTN_GAP);
  lv_obj_set_style_bg_color(btn_upd, lv_color_hex(0x1a1a2a), 0);
  lv_obj_set_style_bg_color(btn_upd, lv_color_hex(0x2a2a40), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_upd, 10, 0);
  lv_obj_set_style_shadow_width(btn_upd, 0, 0);
  lv_obj_set_style_border_width(btn_upd, 1, 0);
  lv_obj_set_style_border_color(btn_upd, lv_color_hex(0x2a2a40), 0);
  { lv_obj_t *ico = lv_label_create(btn_upd);
    lv_label_set_text(ico, LV_SYMBOL_DOWNLOAD);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_upd);
    lv_label_set_text(lbl, T(STR_BTN_FW_UPDATE));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_upd);
    lv_label_set_text(sub, T(STR_BTN_FW_SUB));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_upd, [](lv_event_t *e){ showOtaScreen(); }, LV_EVENT_CLICKED, NULL);

  // Yellow badge top-right of firmware update button
  lbl_fw_badge = lv_label_create(scr_system);
  lv_label_set_text(lbl_fw_badge, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_fw_badge, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_fw_badge, &lv_font_montserrat_18, 0);
  lv_obj_set_pos(lbl_fw_badge, 456, 142);
  if (!update_available) lv_obj_add_flag(lbl_fw_badge, LV_OBJ_FLAG_HIDDEN);

  // ── Button 3: Info & support ──
  lv_obj_t *btn_info = lv_btn_create(scr_system);
  lv_obj_set_size(btn_info, BTN_W, BTN_H);
  lv_obj_set_pos(btn_info, BTN_X, BTN_Y0 + 2*(BTN_H + BTN_GAP));
  lv_obj_set_style_bg_color(btn_info, lv_color_hex(0x0a1e30), 0);
  lv_obj_set_style_bg_color(btn_info, lv_color_hex(0x1a3050), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_info, 10, 0);
  lv_obj_set_style_shadow_width(btn_info, 0, 0);
  lv_obj_set_style_border_width(btn_info, 1, 0);
  lv_obj_set_style_border_color(btn_info, lv_color_hex(0x1a3050), 0);
  { lv_obj_t *ico = lv_label_create(btn_info);
    lv_label_set_text(ico, LV_SYMBOL_BELL);
    lv_obj_set_style_text_color(ico, lv_color_hex(0x28d49a), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_24, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -24);
    lv_obj_t *lbl = lv_label_create(btn_info);
    lv_label_set_text(lbl, T(STR_BTN_INFO));
    lv_obj_set_style_text_color(lbl, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_18, 0);
    lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 4);
    lv_obj_t *sub = lv_label_create(btn_info);
    lv_label_set_text(sub, T(STR_BTN_INFO_SUB));
    lv_obj_set_style_text_color(sub, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_CENTER, 0, 26); }
  lv_obj_add_event_cb(btn_info, [](lv_event_t *e){ showInfoScreen(); }, LV_EVENT_CLICKED, NULL);
}



// ============================================================
//  REBOOT POPUP (language/date format change)
// ============================================================
void showRebootPopup() {
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
  lv_obj_set_style_text_font(t, &lv_font_montserrat_18, 0);
  lv_obj_align(t, LV_ALIGN_TOP_MID, 0, 16);

  lv_obj_t *m = lv_label_create(box);
  lv_label_set_text(m, T(STR_REBOOT_MSG));
  lv_obj_set_style_text_color(m, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(m, &lv_font_montserrat_14, 0);
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
  lv_obj_add_event_cb(btn_rb, [](lv_event_t *e){ ESP.restart(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *rb_lbl = lv_label_create(btn_rb);
  lv_label_set_text(rb_lbl, T(STR_REBOOT_BTN));
  lv_obj_set_style_text_color(rb_lbl, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(rb_lbl, &lv_font_montserrat_14, 0);
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
  lv_obj_set_style_text_font(c_lbl, &lv_font_montserrat_14, 0);
  lv_obj_center(c_lbl);
}

// ============================================================
//  LANGUAGE SCREEN (System > Language)
// ============================================================
void showLanguageScreen() {
  lv_obj_t *scr = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr, 480, 320);
  lv_obj_set_pos(scr, 0, 0);
  lv_obj_set_style_bg_color(scr, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr, 0, 0);
  lv_obj_set_style_radius(scr, 0, 0);
  lv_obj_set_style_pad_all(scr, 0, 0);
  lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);

  // Header
  lv_obj_t *btn_back = lv_btn_create(scr);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_bk);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e){
    lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *hdr = lv_label_create(scr);
  lv_label_set_text(hdr, "Language / Sprache");
  lv_obj_set_style_text_color(hdr, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(hdr, &lv_font_montserrat_18, 0);
  lv_obj_align(hdr, LV_ALIGN_TOP_MID, 0, 12);

  lv_obj_t *btn_x = lv_btn_create(scr);
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
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_x);
  // X deletes this screen overlay and goes to main screen
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){
    lv_obj_t *scr_lang = lv_obj_get_parent(lv_event_get_target(e));
    lv_obj_del(scr_lang);
    showMainScreen();
  }, LV_EVENT_CLICKED, NULL);

  // Hint
  lv_obj_t *hint = lv_label_create(scr);
  lv_label_set_text(hint, T(STR_LANG_HINT));
  lv_obj_set_style_text_color(hint, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(hint, 440);
  lv_obj_align(hint, LV_ALIGN_TOP_MID, 0, 52);

  // ── Language buttons (2 side by side) ──
  const int LB_W = 218, LB_H = 52, LB_Y0 = 90;

  // DE button
  lv_obj_t *btn_de = lv_btn_create(scr);
  lv_obj_set_size(btn_de, LB_W, LB_H);
  lv_obj_set_pos(btn_de, 8, LB_Y0);
  bool de_active = (g_lang == LANG_DE);
  lv_obj_set_style_bg_color(btn_de, lv_color_hex(de_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_de, 10, 0);
  lv_obj_set_style_shadow_width(btn_de, 0, 0);
  lv_obj_set_style_border_width(btn_de, 2, 0);
  lv_obj_set_style_border_color(btn_de, lv_color_hex(de_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_de = lv_label_create(btn_de);
  lv_label_set_text(lbl_de, "DE   Deutsch");
  lv_obj_set_style_text_color(lbl_de, lv_color_hex(de_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_de, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_de);
  lv_obj_add_event_cb(btn_de, [](lv_event_t *e){
    g_lang = LANG_DE;
    Preferences p; p.begin("spoolscale", false); p.putUChar("lang", 0); p.end();
    Serial.println("Language: German -> Reboot");
    showRebootPopup();
  }, LV_EVENT_CLICKED, NULL);

  // EN button
  lv_obj_t *btn_en = lv_btn_create(scr);
  lv_obj_set_size(btn_en, LB_W, LB_H);
  lv_obj_set_pos(btn_en, 254, LB_Y0);
  bool en_active = (g_lang == LANG_EN);
  lv_obj_set_style_bg_color(btn_en, lv_color_hex(en_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_en, 10, 0);
  lv_obj_set_style_shadow_width(btn_en, 0, 0);
  lv_obj_set_style_border_width(btn_en, 2, 0);
  lv_obj_set_style_border_color(btn_en, lv_color_hex(en_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_en = lv_label_create(btn_en);
  lv_label_set_text(lbl_en, "EN   English");
  lv_obj_set_style_text_color(lbl_en, lv_color_hex(en_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_en, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_en);
  lv_obj_add_event_cb(btn_en, [](lv_event_t *e){
    g_lang = LANG_EN;
    Preferences p; p.begin("spoolscale", false); p.putUChar("lang", 1); p.end();
    Serial.println("Language: English -> Reboot");
    showRebootPopup();
  }, LV_EVENT_CLICKED, NULL);

  // ── Date format label ──
  lv_obj_t *lbl_date = lv_label_create(scr);
  lv_label_set_text(lbl_date, T(STR_DATE_FMT_LABEL));
  lv_obj_set_style_text_color(lbl_date, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_date, &lv_font_montserrat_14, 0);
  lv_obj_set_pos(lbl_date, 12, 158);

  // ── Date format buttons (2 side by side) ──
  const int DB_W = 218, DB_H = 52, DB_Y = 178;

  // DD.MM.YYYY
  lv_obj_t *btn_dmy = lv_btn_create(scr);
  lv_obj_set_size(btn_dmy, DB_W, DB_H);
  lv_obj_set_pos(btn_dmy, 8, DB_Y);
  bool dmy_active = (g_date_fmt == 0);
  lv_obj_set_style_bg_color(btn_dmy, lv_color_hex(dmy_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_dmy, 10, 0);
  lv_obj_set_style_shadow_width(btn_dmy, 0, 0);
  lv_obj_set_style_border_width(btn_dmy, 2, 0);
  lv_obj_set_style_border_color(btn_dmy, lv_color_hex(dmy_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_dmy = lv_label_create(btn_dmy);
  lv_label_set_text(lbl_dmy, "DD.MM.YYYY");
  lv_obj_set_style_text_color(lbl_dmy, lv_color_hex(dmy_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_dmy, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_dmy);
  lv_obj_add_event_cb(btn_dmy, [](lv_event_t *e){
    g_date_fmt = 0;
    Preferences p; p.begin("spoolscale", false); p.putUChar("date_fmt", 0); p.end();
    showRebootPopup();
  }, LV_EVENT_CLICKED, NULL);

  // YYYY-MM-DD
  lv_obj_t *btn_iso = lv_btn_create(scr);
  lv_obj_set_size(btn_iso, DB_W, DB_H);
  lv_obj_set_pos(btn_iso, 254, DB_Y);
  bool iso_active = (g_date_fmt == 1);
  lv_obj_set_style_bg_color(btn_iso, lv_color_hex(iso_active ? 0x0a2a40 : 0x0a1828), 0);
  lv_obj_set_style_radius(btn_iso, 10, 0);
  lv_obj_set_style_shadow_width(btn_iso, 0, 0);
  lv_obj_set_style_border_width(btn_iso, 2, 0);
  lv_obj_set_style_border_color(btn_iso, lv_color_hex(iso_active ? 0x28d49a : 0x1a3060), 0);
  lv_obj_t *lbl_iso = lv_label_create(btn_iso);
  lv_label_set_text(lbl_iso, "YYYY-MM-DD");
  lv_obj_set_style_text_color(lbl_iso, lv_color_hex(iso_active ? 0x28d49a : 0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_iso, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_iso);
  lv_obj_add_event_cb(btn_iso, [](lv_event_t *e){
    g_date_fmt = 1;
    Preferences p; p.begin("spoolscale", false); p.putUChar("date_fmt", 1); p.end();
    showRebootPopup();
  }, LV_EVENT_CLICKED, NULL);

  // Hint-Text unten
  lv_obj_t *hint2 = lv_label_create(scr);
  lv_label_set_text(hint2, T(STR_LANG_HINT));
  lv_obj_set_style_text_color(hint2, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(hint2, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_align(hint2, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(hint2, LV_ALIGN_BOTTOM_MID, 0, -8);
}

// ============================================================
//  INFO SCREEN (System > Info & Support)
//  3 QR-Code buttons: Ko-fi / GitHub / Discord
// ============================================================
static lv_obj_t *scr_info = nullptr;

// Static QR data outside lambdas (prevents index bug)
static const char* QR_TITLES[] = { "Ko-fi", "GitHub", "Discord", "MakerWorld" };
static const char* QR_URLS[]   = {
  "https://ko-fi.com/formfollowsfunction",
  "https://github.com/Niko11111/SpoolmanScale",
  "https://discord.gg/GzQzGa5pBG",
  "https://makerworld.com/de/@FormFollowsF/upload"
};
static const char* QR_URLS_DISPLAY[] = {
  "ko-fi.com/formfollowsfunction",
  "github.com/Niko11111/SpoolmanScale",
  "discord.gg/GzQzGa5pBG",
  "makerworld.com/de/@FormFollowsF/upload"
};

// QR_DESCS is filled directly via T() in the popup (runtime-dependent)
static const char* getQRDesc(int idx) {
  switch(idx) {
    case 0: return T(STR_QR_KOFI_DESC);
    case 1: return T(STR_QR_GITHUB_DESC);
    case 2: return T(STR_QR_DISCORD_DESC);
    case 3: return T(STR_QR_MAKER_DESC);
    default: return "";
  }
}

void showQRPopup(int idx) {
  lv_obj_t *popup = lv_obj_create(lv_scr_act());
  lv_obj_set_size(popup, 480, 320);
  lv_obj_set_pos(popup, 0, 0);
  lv_obj_set_style_bg_color(popup, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(popup, 0, 0);
  lv_obj_set_style_radius(popup, 0, 0);
  lv_obj_set_style_pad_all(popup, 0, 0);
  lv_obj_clear_flag(popup, LV_OBJ_FLAG_SCROLLABLE);

  // Zurueck
  lv_obj_t *btn_back = lv_btn_create(popup);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_bk);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e){
    lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
  }, LV_EVENT_CLICKED, NULL);

  // Title
  lv_obj_t *lbl_title = lv_label_create(popup);
  lv_label_set_text(lbl_title, QR_TITLES[idx]);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_18, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 12);

  // X
  lv_obj_t *btn_x = lv_btn_create(popup);
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
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_x);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){
    lv_obj_del(lv_obj_get_parent(lv_event_get_target(e)));
    if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
    showMainScreen();
  }, LV_EVENT_CLICKED, NULL);

  // Beschreibung — Font 16, weiss, y=50
  lv_obj_t *lbl_desc = lv_label_create(popup);
  lv_label_set_text(lbl_desc, getQRDesc(idx));
  lv_obj_set_style_text_color(lbl_desc, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_desc, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_desc, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_desc, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(lbl_desc, 440);
  lv_obj_align(lbl_desc, LV_ALIGN_TOP_MID, 0, 50);

  // URL — Font 16, gruen, y=84
  lv_obj_t *lbl_url = lv_label_create(popup);
  lv_label_set_text(lbl_url, QR_URLS_DISPLAY[idx]);
  lv_obj_set_style_text_color(lbl_url, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_url, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_url, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_url, LV_ALIGN_TOP_MID, 0, 84);

  // QR-Code — 160x160, centered, y-offset -8 from bottom (not flush to edge)
  lv_obj_t *qr = lv_qrcode_create(popup, 160, lv_color_hex(0x000000), lv_color_hex(0xffffff));
  lv_qrcode_update(qr, QR_URLS[idx], strlen(QR_URLS[idx]));
  lv_obj_align(qr, LV_ALIGN_BOTTOM_MID, 0, -20);
}

void showInfoScreen() {
  if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
  scr_info = lv_obj_create(lv_scr_act());
  lv_obj_set_size(scr_info, 480, 320);
  lv_obj_set_pos(scr_info, 0, 0);
  lv_obj_set_style_bg_color(scr_info, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(scr_info, 0, 0);
  lv_obj_set_style_radius(scr_info, 0, 0);
  lv_obj_set_style_pad_all(scr_info, 0, 0);
  lv_obj_clear_flag(scr_info, LV_OBJ_FLAG_SCROLLABLE);

  // Header
  lv_obj_t *btn_back = lv_btn_create(scr_info);
  lv_obj_set_size(btn_back, 44, 44);
  lv_obj_set_pos(btn_back, 4, 2);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 0, 0);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_bk);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e){
    if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
    if (!scr_system) buildSystemScreen();
    lv_obj_clear_flag(scr_system, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *hdr = lv_label_create(scr_info);
  lv_label_set_text(hdr, T(STR_BTN_INFO));
  lv_obj_set_style_text_color(hdr, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(hdr, &lv_font_montserrat_18, 0);
  lv_obj_align(hdr, LV_ALIGN_TOP_MID, 0, 12);

  lv_obj_t *btn_x = lv_btn_create(scr_info);
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
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_18, 0);
  lv_obj_center(lbl_x);
  lv_obj_add_event_cb(btn_x, [](lv_event_t *e){
    if (scr_info) { lv_obj_del(scr_info); scr_info = nullptr; }
    showMainScreen();
  }, LV_EVENT_CLICKED, NULL);

  // Version label — centered below header
  lv_obj_t *ver_lbl = lv_label_create(scr_info);
  char ver_buf[40];
  snprintf(ver_buf, sizeof(ver_buf), T(STR_INFO_VERSION), FW_VERSION);
  lv_label_set_text(ver_lbl, ver_buf);
  lv_obj_set_style_text_color(ver_lbl, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(ver_lbl, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_align(ver_lbl, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(ver_lbl, LV_ALIGN_TOP_MID, 0, 54);

  // 2x2 QR grid — vertically centered in remaining space (y=80..310)
  // QB_H=90: grid total = 2*90+8=188px. Start y = 80 + (230-188)/2 = 101 → use 82 for slight top bias
  const int QB_W = 228, QB_H = 90, QB_GAP = 8;
  const int QB_X0 = (480 - 2*QB_W - QB_GAP) / 2;
  const int QB_Y0 = 82;
  static const uint32_t QB_COLS[] = { 0x1a2800, 0x0a1828, 0x12103a, 0x1a0a18 };
  static const uint32_t QB_TEXT[] = { 0xa0d840, 0x28d49a, 0x8090ff, 0xc060e0 };

  lv_obj_t *btn_kofi = lv_btn_create(scr_info);
  lv_obj_set_size(btn_kofi, QB_W, QB_H);
  lv_obj_set_pos(btn_kofi, QB_X0, QB_Y0);
  lv_obj_set_style_bg_color(btn_kofi, lv_color_hex(QB_COLS[0]), 0);
  lv_obj_set_style_bg_color(btn_kofi, lv_color_hex(QB_COLS[0]+0x101010), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_kofi, 12, 0); lv_obj_set_style_shadow_width(btn_kofi, 0, 0);
  lv_obj_set_style_border_width(btn_kofi, 1, 0); lv_obj_set_style_border_color(btn_kofi, lv_color_hex(QB_TEXT[0]), 0);
  { lv_obj_t *ico = lv_label_create(btn_kofi); lv_label_set_text(ico, LV_SYMBOL_BELL);
    lv_obj_set_style_text_color(ico, lv_color_hex(QB_TEXT[0]), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_20, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -14);
    lv_obj_t *l = lv_label_create(btn_kofi); lv_label_set_text(l, "Ko-fi");
    lv_obj_set_style_text_color(l, lv_color_hex(QB_TEXT[0]), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_16, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 14); }
  lv_obj_add_event_cb(btn_kofi, [](lv_event_t *e){ showQRPopup(0); }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_gh = lv_btn_create(scr_info);
  lv_obj_set_size(btn_gh, QB_W, QB_H);
  lv_obj_set_pos(btn_gh, QB_X0 + QB_W + QB_GAP, QB_Y0);
  lv_obj_set_style_bg_color(btn_gh, lv_color_hex(QB_COLS[1]), 0);
  lv_obj_set_style_bg_color(btn_gh, lv_color_hex(QB_COLS[1]+0x101010), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_gh, 12, 0); lv_obj_set_style_shadow_width(btn_gh, 0, 0);
  lv_obj_set_style_border_width(btn_gh, 1, 0); lv_obj_set_style_border_color(btn_gh, lv_color_hex(QB_TEXT[1]), 0);
  { lv_obj_t *ico = lv_label_create(btn_gh); lv_label_set_text(ico, LV_SYMBOL_DOWNLOAD);
    lv_obj_set_style_text_color(ico, lv_color_hex(QB_TEXT[1]), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_20, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -14);
    lv_obj_t *l = lv_label_create(btn_gh); lv_label_set_text(l, "GitHub");
    lv_obj_set_style_text_color(l, lv_color_hex(QB_TEXT[1]), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_16, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 14); }
  lv_obj_add_event_cb(btn_gh, [](lv_event_t *e){ showQRPopup(1); }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_dc = lv_btn_create(scr_info);
  lv_obj_set_size(btn_dc, QB_W, QB_H);
  lv_obj_set_pos(btn_dc, QB_X0, QB_Y0 + QB_H + QB_GAP);
  lv_obj_set_style_bg_color(btn_dc, lv_color_hex(QB_COLS[2]), 0);
  lv_obj_set_style_bg_color(btn_dc, lv_color_hex(QB_COLS[2]+0x101010), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_dc, 12, 0); lv_obj_set_style_shadow_width(btn_dc, 0, 0);
  lv_obj_set_style_border_width(btn_dc, 1, 0); lv_obj_set_style_border_color(btn_dc, lv_color_hex(QB_TEXT[2]), 0);
  { lv_obj_t *ico = lv_label_create(btn_dc); lv_label_set_text(ico, LV_SYMBOL_BELL);
    lv_obj_set_style_text_color(ico, lv_color_hex(QB_TEXT[2]), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_20, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -14);
    lv_obj_t *l = lv_label_create(btn_dc); lv_label_set_text(l, "Discord");
    lv_obj_set_style_text_color(l, lv_color_hex(QB_TEXT[2]), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_16, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 14); }
  lv_obj_add_event_cb(btn_dc, [](lv_event_t *e){ showQRPopup(2); }, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_mw = lv_btn_create(scr_info);
  lv_obj_set_size(btn_mw, QB_W, QB_H);
  lv_obj_set_pos(btn_mw, QB_X0 + QB_W + QB_GAP, QB_Y0 + QB_H + QB_GAP);
  lv_obj_set_style_bg_color(btn_mw, lv_color_hex(QB_COLS[3]), 0);
  lv_obj_set_style_bg_color(btn_mw, lv_color_hex(QB_COLS[3]+0x101010), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_mw, 12, 0); lv_obj_set_style_shadow_width(btn_mw, 0, 0);
  lv_obj_set_style_border_width(btn_mw, 1, 0); lv_obj_set_style_border_color(btn_mw, lv_color_hex(QB_TEXT[3]), 0);
  { lv_obj_t *ico = lv_label_create(btn_mw); lv_label_set_text(ico, LV_SYMBOL_UPLOAD);
    lv_obj_set_style_text_color(ico, lv_color_hex(QB_TEXT[3]), 0);
    lv_obj_set_style_text_font(ico, &lv_font_montserrat_20, 0);
    lv_obj_align(ico, LV_ALIGN_CENTER, 0, -14);
    lv_obj_t *l = lv_label_create(btn_mw); lv_label_set_text(l, "MakerWorld");
    lv_obj_set_style_text_color(l, lv_color_hex(QB_TEXT[3]), 0);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_16, 0);
    lv_obj_align(l, LV_ALIGN_CENTER, 0, 14); }
  lv_obj_add_event_cb(btn_mw, [](lv_event_t *e){ showQRPopup(3); }, LV_EVENT_CLICKED, NULL);

  // Hint
  lv_obj_t *hint = lv_label_create(scr_info);
  lv_label_set_text(hint, T(STR_INFO_HINT));
  lv_obj_set_style_text_color(hint, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -8);
}

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
  tag_present = false;
  nfc_retry_count = 0;
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
//  WRITE SPOOLMAN WEIGHT
// ============================================================
void patchSpoolmanWeight(float remaining) {
  if (!wifi_ok) { Serial.println("patchSpoolmanWeight: no WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchSpoolmanWeight: no spool"); return; }
  HTTPClient http;
  String url = String(cfg_spoolman_base) + "/api/v1/spool/" + sm_id;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);
  char body[128];
  if (last_used_mode == 1) {
    // Mode: Last Weighed — also write last_used = today
    char today[12];
    time_t now = time(nullptr);
    struct tm *t = localtime(&now);
    snprintf(today, sizeof(today), "%04d-%02d-%02d", t->tm_year+1900, t->tm_mon+1, t->tm_mday);
    snprintf(body, sizeof(body), "{\"remaining_weight\": %.1f, \"last_used\": \"%s\"}", remaining, today);
  } else {
    snprintf(body, sizeof(body), "{\"remaining_weight\": %.1f}", remaining);
  }
  Serial.printf("PATCH weight: %.1fg -> %s\n", remaining, body);
  int code = http.PATCH(String(body));
  http.end();
  if (code == 200) {
    sm_remaining = remaining;
    char w_str[16]; snprintf(w_str, sizeof(w_str), "%.0f g", sm_remaining);
    lv_label_set_text(lbl_spoolman_weight, w_str);
    float pct = (sm_total > 0) ? (sm_remaining / sm_total * 100.0f) : 0;
    char p_str[16]; snprintf(p_str, sizeof(p_str), "%.1f %%", pct);
    lv_label_set_text(lbl_spoolman_pct, p_str);
    // Update last_used display if in Last Weighed mode
    if (last_used_mode == 1 && lbl_last_used) {
      char today_iso[12];
      time_t now = time(nullptr);
      struct tm *t = localtime(&now);
      snprintf(today_iso, sizeof(today_iso), "%04d-%02d-%02d", t->tm_year+1900, t->tm_mon+1, t->tm_mday);
      // Also update sm_last_used so querySpoolman won't overwrite on next scan
      // sm_last_used stores the local-format date (like querySpoolman does)
      char today_local[12];
      isoToDe(today_iso, today_local, sizeof(today_local));
      strncpy(sm_last_used, today_local, sizeof(sm_last_used)-1);
      char disp[48];
      lastUsedDisplayStr(today_local, disp, sizeof(disp));
      lv_label_set_text(lbl_last_used, disp);
    }
    Serial.printf("OK: %.1fg saved\n", remaining);
  } else {
    Serial.printf("PATCH error: %d\n", code);
  }
}

// ============================================================
//  ARCHIVE SPOOL IN SPOOLMAN (remaining=0 + archived=true)
// ============================================================
void patchArchiveSpool() {
  if (!wifi_ok) { Serial.println("patchArchiveSpool: no WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchArchiveSpool: no spool"); return; }
  HTTPClient http;
  String url = String(cfg_spoolman_base) + "/api/v1/spool/" + sm_id;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);
  const char* body = "{\"remaining_weight\": 0.0, \"archived\": true}";
  Serial.printf("PATCH archive: spool ID %d\n", sm_id);
  int code = http.PATCH(String(body));
  http.end();
  if (code == 200) {
    sm_remaining = 0;
    Serial.println("Spool archived!");
  } else {
    Serial.printf("PATCH archive error: %d\n", code);
  }
}

// ============================================================
//  READ NTAG (page 4 for magic check)
// ============================================================
bool ntagReadPage(uint8_t page, uint8_t *buf) {
  return nfc.ntag2xx_ReadPage(page, buf);
}

// ============================================================
//  WRITE NTAG (4 bytes per page)
// ============================================================
bool ntagWritePage(uint8_t page, uint8_t *data) {
  return nfc.ntag2xx_WritePage(page, data);
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
  if (!nfc.ntag2xx_ReadPage(4, page4)) return TAG_UNKNOWN;
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
void fetchAllSpoolsForLink() {
  link_spool_count = 0;
  if (!wifi_ok) return;

  HTTPClient http;
  http.begin(String(cfg_spoolman_base) + "/api/v1/spool?allow_archived=false");
  http.setTimeout(8000);
  int code = http.GET();
  if (code != 200) { http.end(); return; }

  String payload = http.getString();
  http.end();

  StaticJsonDocument<384> filterL;
  JsonArray filterL_arr = filterL.to<JsonArray>();
  JsonObject fL = filterL_arr.createNestedObject();
  fL["id"] = true;
  fL["remaining_weight"] = true;
  fL["extra"]["tag"] = true;
  fL["filament"]["name"] = true;
  fL["filament"]["material"] = true;
  fL["filament"]["weight"] = true;
  fL["filament"]["color_hex"] = true;
  fL["filament"]["vendor"]["name"] = true;
  DynamicJsonDocument doc(32768);
  if (deserializeJson(doc, payload, DeserializationOption::Filter(filterL))) return;

  JsonArray spools = doc.as<JsonArray>();
  for (JsonObject spool : spools) {
    if (link_spool_count >= LINK_MAX_SPOOLS) break;

    UnlinkedSpool &s = link_spools[link_spool_count];
    s.id = spool["id"] | 0;

    // extra.tag auslesen (fuer Ueberschreib-Check)
    s.existing_tag[0] = '\0';
    if (spool.containsKey("extra")) {
      JsonObject extra = spool["extra"];
      if (extra.containsKey("tag")) {
        String tv = extra["tag"].as<String>();
        tv.replace("\"",""); tv.trim();
        strncpy(s.existing_tag, tv.c_str(), sizeof(s.existing_tag)-1);
      }
    }

    // Filament name
    String fname = spool["filament"]["name"] | String("?");
    fname.trim();
    strncpy(s.name, fname.c_str(), sizeof(s.name)-1);

    // Vendor
    String vname = "";
    if (spool["filament"].containsKey("vendor") && !spool["filament"]["vendor"].isNull()) {
      vname = spool["filament"]["vendor"]["name"] | String("");
    }
    vname.trim();
    strncpy(s.vendor, vname.c_str(), sizeof(s.vendor)-1);

    // Material
    String mat = spool["filament"]["material"] | String("");
    mat.trim();
    strncpy(s.material, mat.c_str(), sizeof(s.material)-1);

    // Farbe
    String col = spool["filament"]["color_hex"] | String("");
    col.trim();
    if (col.length() > 0 && col[0] != '#') col = "#" + col;
    strncpy(s.color_hex, col.c_str(), sizeof(s.color_hex)-1);

    // Gewichte
    s.remaining = spool["remaining_weight"] | 0.0f;
    s.total = spool["filament"]["weight"] | 1000.0f;

    link_spool_count++;
  }
  Serial.printf("fetchAllSpoolsForLink: %d spools loaded\n", link_spool_count);
}

// Legacy wrapper for compatibility
void fetchUnlinkedSpools() { fetchAllSpoolsForLink(); }

// ============================================================
//  SPOOLMAN: SAVE TAG UUID (extra.tag)
// ============================================================
void patchSpoolTag(int spool_id, const char *uuid) {
  if (!wifi_ok) return;
  HTTPClient http;
  String url = String(cfg_spoolman_base) + "/api/v1/spool/" + spool_id;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);
  String body = "{\"extra\": {\"tag\": \"\\\"" + String(uuid) + "\\\"\"}}";
  Serial.printf("PATCH tag: %s -> %s\n", uuid, body.c_str());
  int code = http.PATCH(body);
  http.end();
  Serial.printf("patchSpoolTag: HTTP %d\n", code);
}

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
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
  if (scr_link_list)   { lv_obj_del(scr_link_list);   scr_link_list   = nullptr; }

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
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_16, 0);
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
  lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_14, 0);
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
  lv_obj_set_style_text_font(lbl_force, &lv_font_montserrat_16, 0);
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
    if (scr_link_warn_a) { lv_obj_del(scr_link_warn_a); scr_link_warn_a = nullptr; }
    link_id_input[0] = '\0';
    showIdInputPopup(warn_a_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_retry = lv_label_create(btn_retry);
  lv_label_set_text(lbl_retry, T(STR_ENTER_NEW_ID));
  lv_obj_set_style_text_color(lbl_retry, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_retry, &lv_font_montserrat_16, 0);
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
  lv_obj_set_style_text_font(lbl_cancel, &lv_font_montserrat_14, 0);
  lv_obj_center(lbl_cancel);
}

// ============================================================
//  LINK FLOW: WARNING POPUP B (material mismatch)
//  Nur Flow A (Bambu), Pfad 1
// ============================================================
void showWarnPopupB(int spool_id, bool is_bambu) {
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
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_16, 0);
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
  lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_14, 0);
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
  lv_obj_set_style_text_font(lbl_force, &lv_font_montserrat_16, 0);
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
  lv_obj_set_style_text_font(lbl_retry, &lv_font_montserrat_16, 0);
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
  lv_obj_set_style_text_font(lbl_cancel, &lv_font_montserrat_14, 0);
  lv_obj_center(lbl_cancel);
}

// ============================================================
//  LINK-FLOW: HTTP-LOOKUP + VERKNUEPFUNG (ausgelagert vom Lambda)
// ============================================================
void linkIdLookupAndPatch(int entered_id, bool is_bambu) {
  if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_CHECKING));
  lv_timer_handler();
  if (!wifi_ok) { if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_NO_WIFI)); return; }

  HTTPClient http;
  String url = String(cfg_spoolman_base) + "/api/v1/spool/" + entered_id;
  http.begin(url); http.setTimeout(5000);
  int code = http.GET();
  if (code == 404 || code < 0) {
    http.end();
    if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_ID_NOT_FOUND));
    return;
  }
  if (code != 200) {
    http.end();
    char err[32]; snprintf(err, sizeof(err), T(STR_LINK_HTTP_ERR), code);
    if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, err);
    return;
  }
  String payload = http.getString();
  http.end();

  DynamicJsonDocument doc(8192);
  if (deserializeJson(doc, payload)) {
    if (lbl_link_id_status) lv_label_set_text(lbl_link_id_status, T(STR_LINK_JSON_ERR));
    return;
  }

  String existing = "";
  if (doc.containsKey("extra") && doc["extra"].containsKey("tag")) {
    existing = doc["extra"]["tag"].as<String>();
    existing.replace("\"",""); existing.trim();
  }

  bool found_in_list = false;
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].id == entered_id) { found_in_list = true; break; }
  }
  if (!found_in_list && link_spool_count < LINK_MAX_SPOOLS) {
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
void showIdInputPopup(bool is_bambu) {
  if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
  lbl_link_id_display = nullptr;
  lbl_link_id_status  = nullptr;

  scr_link_id = buildLinkOverlay();

  // ── Header like settings menu ───────────────────────────
  // Title zentriert
  lv_obj_t *lbl_title = lv_label_create(scr_link_id);
  lv_label_set_text(lbl_title, T(STR_LINK_ID_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_18, 0);
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
    if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
    // Zurueck zum Entry-Popup
    if (scr_link_entry) lv_obj_clear_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_bk = lv_label_create(btn_back);
  lv_label_set_text(lbl_bk, LV_SYMBOL_LEFT);
  lv_obj_set_style_text_color(lbl_bk, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_bk, &lv_font_montserrat_18, 0);
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
    if (scr_link_id)    { lv_obj_del(scr_link_id);    scr_link_id    = nullptr; }
    if (scr_link_entry) { lv_obj_del(scr_link_entry); scr_link_entry = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_x = lv_label_create(btn_x);
  lv_label_set_text(lbl_x, LV_SYMBOL_CLOSE);
  lv_obj_set_style_text_color(lbl_x, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_18, 0);
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
  lv_obj_set_style_text_font(lbl_ctx, &lv_font_montserrat_14, 0);
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
  lv_obj_set_style_text_font(lbl_link_id_display, &lv_font_montserrat_24, 0);
  lv_obj_set_style_text_align(lbl_link_id_display, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_center(lbl_link_id_display);

  // Status-Label (Fehleranzeige) — y=124
  lbl_link_id_status = lv_label_create(scr_link_id);
  lv_label_set_text(lbl_link_id_status, "");
  lv_obj_set_style_text_color(lbl_link_id_status, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_link_id_status, &lv_font_montserrat_12, 0);
  lv_obj_set_style_text_align(lbl_link_id_status, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_link_id_status, LV_ALIGN_TOP_MID, 0, 124);

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

  static bool id_popup_is_bambu = false;
  id_popup_is_bambu = is_bambu;

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
    lv_obj_set_style_text_font(lbl, is_ok ? &lv_font_montserrat_20 : &lv_font_montserrat_18, 0);
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
        linkIdLookupAndPatch(entered_id, id_popup_is_bambu);
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
  if (scr_link_id) { lv_obj_del(scr_link_id); scr_link_id = nullptr; }
}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — SPULEN-LISTE (Stufe 3)
// ============================================================
void showFilteredSpoolList(const char* vendor_name, const char* material_prefix) {
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }

  scr_link_spools = buildLinkOverlay();

  char title_buf[48];
  if (link_flow_is_bambu) {
    snprintf(title_buf, sizeof(title_buf), T(STR_SPOOLS_BAMBU));
  } else if (material_prefix[0]) {
    snprintf(title_buf, sizeof(title_buf), "%.8s %.4s", vendor_name, material_prefix);
  } else {
    snprintf(title_buf, sizeof(title_buf), T(STR_SPOOLS_ALL));
  }
  lv_obj_t *lbl_title = lv_label_create(scr_link_spools);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 10);

  lv_obj_t *div = lv_obj_create(scr_link_spools);
  lv_obj_set_size(div, 472, 1); lv_obj_set_pos(div, 4, 32);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  // Scrollable list
  lv_obj_t *list = lv_obj_create(scr_link_spools);
  lv_obj_set_size(list, 460, 240);
  lv_obj_set_pos(list, 10, 36);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  int count = 0;
  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];

    // Filter: kein Tag, passender Vendor, passender Material-Prefix
    if (s.existing_tag[0] != '\0') continue;  // bereits verknuepft
    bool bambu_vendor = (strncasecmp(s.vendor, "Bambu", 5) == 0);
    if (link_flow_is_bambu) {
      // Bambu-Flow: vendor muss Bambu enthalten, Material muss passen
      if (!bambu_vendor) continue;
      if (g_tag.material[0] && s.material[0]) {
        if (strncasecmp(s.material, g_tag.material, 3) != 0) continue;
      }
    } else {
      // Flow B: vendor und material prefix filtern
      if (bambu_vendor) continue;  // Bambu-Spulen ausblenden
      if (vendor_name[0] && strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
      if (material_prefix[0] && strncasecmp(s.material, material_prefix, strlen(material_prefix)) != 0) continue;
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
    lv_obj_set_style_text_font(lbl_id, &lv_font_montserrat_16, 0);
    lv_obj_align(lbl_id, LV_ALIGN_TOP_LEFT, 6, 5);

    // Material + Name zusammen, abgeschnitten wenn zu lang
    lv_obj_t *lbl_name = lv_label_create(row);
    char full_name[64];
    if (s.material[0])
      snprintf(full_name, sizeof(full_name), "%s %s", s.material, s.name);
    else
      strncpy(full_name, s.name, sizeof(full_name)-1);
    lv_label_set_text(lbl_name, full_name);
    lv_obj_set_style_text_color(lbl_name, lv_color_hex(0xe8f0ff), 0);
    lv_obj_set_style_text_font(lbl_name, &lv_font_montserrat_16, 0);
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
    char rest_buf[32];
    if (s.remaining <= 0 && s.total > 0)
      snprintf(rest_buf, sizeof(rest_buf), "%.0fg  neu", s.total);
    else
      snprintf(rest_buf, sizeof(rest_buf), "%.0fg / %.0fg", s.remaining, s.total);
    lv_label_set_text(lbl_rest, rest_buf);
    lv_obj_set_style_text_color(lbl_rest, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_rest, &lv_font_montserrat_14, 0);
    lv_obj_align(lbl_rest, LV_ALIGN_BOTTOM_LEFT, 26, -5);

    // Vendor rechts unten
    lv_obj_t *lbl_vnd = lv_label_create(row);
    lv_label_set_text(lbl_vnd, s.vendor[0] ? s.vendor : "");
    lv_obj_set_style_text_color(lbl_vnd, lv_color_hex(0x2a4060), 0);
    lv_obj_set_style_text_font(lbl_vnd, &lv_font_montserrat_12, 0);
    lv_obj_align(lbl_vnd, LV_ALIGN_BOTTOM_RIGHT, -6, -6);
    lv_label_set_long_mode(lbl_vnd, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_vnd, 180);

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
      lv_label_set_text(lbl_q, T(STR_CONFIRM_LINK));
      lv_obj_set_style_text_color(lbl_q, lv_color_hex(0x28d49a), 0);
      lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_18, 0);
      lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);
      lv_obj_align(lbl_q, LV_ALIGN_TOP_MID, 0, 16);

      // Spulen-Info
      char info[80];
      snprintf(info, sizeof(info), "#%d  %s %s\n%.0fg / %.0fg",
        s.id, s.material, s.name, s.remaining, s.total);
      lv_obj_t *lbl_info = lv_label_create(box);
      lv_label_set_text(lbl_info, info);
      lv_obj_set_style_text_color(lbl_info, lv_color_hex(0xc8d8f0), 0);
      lv_obj_set_style_text_font(lbl_info, &lv_font_montserrat_16, 0);
      lv_obj_set_style_text_align(lbl_info, LV_TEXT_ALIGN_CENTER, 0);
      lv_label_set_long_mode(lbl_info, LV_LABEL_LONG_WRAP);
      lv_obj_set_width(lbl_info, 400);
      lv_obj_align(lbl_info, LV_ALIGN_TOP_MID, 0, 48);

      // Bestaetigen
      lv_obj_t *btn_yes = lv_btn_create(box);
      lv_obj_set_size(btn_yes, 420, 50);
      lv_obj_align(btn_yes, LV_ALIGN_TOP_MID, 0, 118);
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
        doLinkPatch(link_spools[cidx].id, link_flow_is_bambu);
      }, LV_EVENT_CLICKED, NULL);
      lv_obj_t *lbl_yes = lv_label_create(btn_yes);
      lv_label_set_text(lbl_yes, T(STR_LINK_OK));
      lv_obj_set_style_text_color(lbl_yes, lv_color_hex(0x40c080), 0);
      lv_obj_set_style_text_font(lbl_yes, &lv_font_montserrat_18, 0);
      lv_obj_center(lbl_yes);

      // Abbrechen
      lv_obj_t *btn_no = lv_btn_create(box);
      lv_obj_set_size(btn_no, 420, 40);
      lv_obj_align(btn_no, LV_ALIGN_BOTTOM_MID, 0, -8);
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
      lv_obj_set_style_text_font(lbl_no, &lv_font_montserrat_14, 0);
      lv_obj_center(lbl_no);

    }, LV_EVENT_CLICKED, (void*)(intptr_t)i);
  }

  if (count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_spools);
    lv_label_set_text(lbl_empty, T(STR_NO_SPOOLS));
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  }

  // Zurueck + Abbrechen
  lv_obj_t *btn_back = lv_btn_create(scr_link_spools);
  lv_obj_set_size(btn_back, 200, 40);
  lv_obj_align(btn_back, LV_ALIGN_BOTTOM_LEFT, 10, -6);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 1, 0);
  lv_obj_set_style_border_color(btn_back, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e) {
    if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
    if (link_flow_is_bambu) {
      // Bambu hat keine Hersteller/Material-Stufe — zurueck zu Entry
      if (scr_link_entry) lv_obj_clear_flag(scr_link_entry, LV_OBJ_FLAG_HIDDEN);
    } else {
      showMaterialList(link_selected_vendor);
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_back = lv_label_create(btn_back);
  lv_label_set_text(lbl_back, T(STR_BACK));
  lv_obj_set_style_text_color(lbl_back, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_back, &lv_font_montserrat_14, 0);
  lv_obj_center(lbl_back);

  lv_obj_t *btn_cancel = lv_btn_create(scr_link_spools);
  lv_obj_set_size(btn_cancel, 200, 40);
  lv_obj_align(btn_cancel, LV_ALIGN_BOTTOM_RIGHT, -10, -6);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_cancel, 0, 0);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e) {
    if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cancel = lv_label_create(btn_cancel);
  lv_label_set_text(lbl_cancel, T(STR_CANCEL));
  lv_obj_set_style_text_color(lbl_cancel, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_cancel, &lv_font_montserrat_14, 0);
  lv_obj_center(lbl_cancel);
}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — MATERIAL-AUSWAHL (Stufe 2)
// ============================================================
void showMaterialList(const char* vendor_name) {
  if (scr_link_mat) { lv_obj_del(scr_link_mat); scr_link_mat = nullptr; }
  strncpy(link_selected_vendor, vendor_name, sizeof(link_selected_vendor)-1);

  scr_link_mat = buildLinkOverlay();

  char title_buf[48];
  snprintf(title_buf, sizeof(title_buf), "%s | %.16s", T(STR_MAT_TITLE), vendor_name);
  lv_obj_t *lbl_title = lv_label_create(scr_link_mat);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 10);

  lv_obj_t *div = lv_obj_create(scr_link_mat);
  lv_obj_set_size(div, 472, 1); lv_obj_set_pos(div, 4, 32);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  lv_obj_t *list = lv_obj_create(scr_link_mat);
  lv_obj_set_size(list, 460, 240);
  lv_obj_set_pos(list, 10, 36);
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

  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (s.existing_tag[0] != '\0') continue;
    if (strncasecmp(s.vendor, vendor_name, strlen(vendor_name)) != 0) continue;
    if (strncasecmp(s.vendor, "Bambu", 5) == 0) continue;
    if (!s.material[0]) continue;
    char prefix[4]; strncpy(prefix, s.material, 3); prefix[3] = '\0';
    bool found = false;
    for (int j = 0; j < seen_count; j++) {
      if (strncasecmp(seen_mats[j], prefix, 3) == 0) { mat_counts[j]++; found = true; break; }
    }
    if (!found && seen_count < 20) {
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
    lv_obj_set_style_text_font(lbl_mat, &lv_font_montserrat_18, 0);
    lv_obj_align(lbl_mat, LV_ALIGN_LEFT_MID, 16, 0);

    lv_obj_t *lbl_cnt = lv_label_create(row);
    char cnt_buf[12]; snprintf(cnt_buf, sizeof(cnt_buf), "%d x", mat_counts[m]);
    lv_label_set_text(lbl_cnt, cnt_buf);
    lv_obj_set_style_text_color(lbl_cnt, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_cnt, &lv_font_montserrat_16, 0);
    lv_obj_align(lbl_cnt, LV_ALIGN_RIGHT_MID, -16, 0);

    lv_obj_add_event_cb(row, [](lv_event_t *e) {
      int idx = (intptr_t)lv_event_get_user_data(e);
      strncpy(link_selected_material, seen_mats[idx], sizeof(link_selected_material)-1);
      if (scr_link_mat) { lv_obj_del(scr_link_mat); scr_link_mat = nullptr; }
      showFilteredSpoolList(link_selected_vendor, link_selected_material);
    }, LV_EVENT_CLICKED, (void*)(intptr_t)m);
  }

  if (seen_count == 0) {
    lv_obj_t *lbl_empty = lv_label_create(scr_link_mat);
    lv_label_set_text(lbl_empty, T(STR_NO_MATERIALS));
    lv_obj_set_style_text_color(lbl_empty, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  }

  lv_obj_t *btn_back = lv_btn_create(scr_link_mat);
  lv_obj_set_size(btn_back, 200, 40);
  lv_obj_align(btn_back, LV_ALIGN_BOTTOM_LEFT, 10, -6);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x0a1828), 0);
  lv_obj_set_style_bg_color(btn_back, lv_color_hex(0x1a3060), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_back, 8, 0);
  lv_obj_set_style_shadow_width(btn_back, 0, 0);
  lv_obj_set_style_border_width(btn_back, 1, 0);
  lv_obj_set_style_border_color(btn_back, lv_color_hex(0x1a3060), 0);
  lv_obj_add_event_cb(btn_back, [](lv_event_t *e) {
    if (scr_link_mat) { lv_obj_del(scr_link_mat); scr_link_mat = nullptr; }
    showVendorList();
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_back = lv_label_create(btn_back);
  lv_label_set_text(lbl_back, T(STR_BACK));
  lv_obj_set_style_text_color(lbl_back, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_back, &lv_font_montserrat_14, 0);
  lv_obj_center(lbl_back);

  lv_obj_t *btn_cancel = lv_btn_create(scr_link_mat);
  lv_obj_set_size(btn_cancel, 200, 40);
  lv_obj_align(btn_cancel, LV_ALIGN_BOTTOM_RIGHT, -10, -6);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_cancel, 0, 0);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e) {
    if (scr_link_mat)    { lv_obj_del(scr_link_mat);    scr_link_mat    = nullptr; }
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cancel = lv_label_create(btn_cancel);
  lv_label_set_text(lbl_cancel, T(STR_CANCEL));
  lv_obj_set_style_text_color(lbl_cancel, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_cancel, &lv_font_montserrat_14, 0);
  lv_obj_center(lbl_cancel);
}

// ============================================================
//  LINK-FLOW: FLOW B PFAD 2 — HERSTELLER-AUSWAHL (Stufe 1)
// ============================================================
void showVendorList() {
  if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }

  scr_link_vendor = buildLinkOverlay();

  // Zaehle Spulen gesamt (ohne Bambu, ohne bereits verknuepft)
  int total_unlinked = 0;
  for (int i = 0; i < link_spool_count; i++) {
    if (link_spools[i].existing_tag[0] != '\0') continue;
    if (strncasecmp(link_spools[i].vendor, "Bambu", 5) == 0) continue;
    total_unlinked++;
  }

  char title_buf[40];
  snprintf(title_buf, sizeof(title_buf), T(STR_VENDOR_TITLE), total_unlinked);
  lv_obj_t *lbl_title = lv_label_create(scr_link_vendor);
  lv_label_set_text(lbl_title, title_buf);
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_TOP_MID, 0, 10);

  lv_obj_t *div = lv_obj_create(scr_link_vendor);
  lv_obj_set_size(div, 472, 1); lv_obj_set_pos(div, 4, 32);
  lv_obj_set_style_bg_color(div, lv_color_hex(0x1a3060), 0);
  lv_obj_set_style_border_width(div, 0, 0);
  lv_obj_set_style_radius(div, 0, 0);
  lv_obj_set_style_pad_all(div, 0, 0);

  lv_obj_t *list = lv_obj_create(scr_link_vendor);
  lv_obj_set_size(list, 460, 240);
  lv_obj_set_pos(list, 10, 36);
  lv_obj_set_style_bg_color(list, lv_color_hex(0x0a1020), 0);
  lv_obj_set_style_border_width(list, 0, 0);
  lv_obj_set_style_pad_all(list, 2, 0);
  lv_obj_set_style_radius(list, 0, 0);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_scroll_dir(list, LV_DIR_VER);

  // Dedupliziere Vendors (ohne Bambu)
  static char seen_vendors[20][32] = {};
  static int  vendor_counts[20]    = {};
  static int  seen_v               = 0;
  seen_v = 0;
  memset(seen_vendors, 0, sizeof(seen_vendors));
  memset(vendor_counts, 0, sizeof(vendor_counts));

  for (int i = 0; i < link_spool_count; i++) {
    UnlinkedSpool &s = link_spools[i];
    if (s.existing_tag[0] != '\0') continue;
    if (strncasecmp(s.vendor, "Bambu", 5) == 0) continue;
    const char* vn = s.vendor[0] ? s.vendor : "Unbekannt";
    bool found = false;
    for (int j = 0; j < seen_v; j++) {
      if (strcasecmp(seen_vendors[j], vn) == 0) { vendor_counts[j]++; found = true; break; }
    }
    if (!found && seen_v < 20) {
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
    lv_obj_set_style_text_font(lbl_vnd, &lv_font_montserrat_18, 0);
    lv_obj_align(lbl_vnd, LV_ALIGN_LEFT_MID, 16, 0);
    lv_label_set_long_mode(lbl_vnd, LV_LABEL_LONG_DOT);
    lv_obj_set_width(lbl_vnd, 320);

    lv_obj_t *lbl_cnt = lv_label_create(row);
    char cnt_buf[12]; snprintf(cnt_buf, sizeof(cnt_buf), "%d x", vendor_counts[v]);
    lv_label_set_text(lbl_cnt, cnt_buf);
    lv_obj_set_style_text_color(lbl_cnt, lv_color_hex(0x4a6fa0), 0);
    lv_obj_set_style_text_font(lbl_cnt, &lv_font_montserrat_16, 0);
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
    lv_obj_set_style_text_font(lbl_empty, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_align(lbl_empty, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(lbl_empty, LV_ALIGN_CENTER, 0, -20);
  }

  // Abbrechen
  lv_obj_t *btn_cancel = lv_btn_create(scr_link_vendor);
  lv_obj_set_size(btn_cancel, 200, 40);
  lv_obj_align(btn_cancel, LV_ALIGN_BOTTOM_MID, 0, -6);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x3a1010), 0);
  lv_obj_set_style_bg_color(btn_cancel, lv_color_hex(0x602020), LV_STATE_PRESSED);
  lv_obj_set_style_radius(btn_cancel, 8, 0);
  lv_obj_set_style_shadow_width(btn_cancel, 0, 0);
  lv_obj_set_style_border_width(btn_cancel, 0, 0);
  lv_obj_add_event_cb(btn_cancel, [](lv_event_t *e) {
    if (scr_link_vendor) { lv_obj_del(scr_link_vendor); scr_link_vendor = nullptr; }
    if (scr_link_entry)  { lv_obj_del(scr_link_entry);  scr_link_entry  = nullptr; }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_cancel = lv_label_create(btn_cancel);
  lv_label_set_text(lbl_cancel, T(STR_CANCEL));
  lv_obj_set_style_text_color(lbl_cancel, lv_color_hex(0xff8080), 0);
  lv_obj_set_style_text_font(lbl_cancel, &lv_font_montserrat_14, 0);
  lv_obj_center(lbl_cancel);
}

// ============================================================
//  LINK-FLOW: EINSTIEGS-POPUP (Flow A + B)
// ============================================================
void closeLinkEntryPopup() {
  if (scr_link_entry) { lv_obj_del(scr_link_entry); scr_link_entry = nullptr; }
}

void showLinkEntryPopup(bool is_bambu) {
  closeLinkEntryPopup();
  link_flow_is_bambu = is_bambu;
  link_id_input[0]   = '\0';

  scr_link_entry = buildLinkOverlay();

  // Header-Titel
  lv_obj_t *lbl_title = lv_label_create(scr_link_entry);
  lv_label_set_text(lbl_title, is_bambu ? T(STR_LINK_BAMBU_TITLE) : T(STR_LINK_NTAG_TITLE));
  lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_18, 0);
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
  lv_obj_set_style_text_font(lbl_ctx, &lv_font_montserrat_14, 0);
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
  lv_obj_set_style_border_color(btn1, lv_color_hex(0x28d49a), 0);
  lv_obj_add_event_cb(btn1, [](lv_event_t *e) {
    link_id_input[0] = '\0';
    showIdInputPopup(link_flow_is_bambu);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *l1 = lv_label_create(btn1);
  lv_label_set_text(l1, T(STR_BTN_ENTER_ID));
  lv_obj_set_style_text_color(l1, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(l1, &lv_font_montserrat_18, 0);
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
    // Spulen laden und passenden Flow starten
    fetchAllSpoolsForLink();
    if (link_flow_is_bambu) {
      showFilteredSpoolList("", "");  // Flow A: direkt Spulen-Liste (Bambu, Material-gefiltert)
    } else {
      showVendorList();               // Flow B: 3-stufig
    }
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *l2 = lv_label_create(btn2);
  lv_label_set_text(l2, T(STR_BTN_FROM_LIST));
  lv_obj_set_style_text_color(l2, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(l2, &lv_font_montserrat_18, 0);
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
  lv_obj_set_style_text_font(l3, &lv_font_montserrat_16, 0);
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
  if (scr_link_spools) { lv_obj_del(scr_link_spools); scr_link_spools = nullptr; }
}

void showLinkList() {
  // Wird nicht mehr direkt aufgerufen — Entry-Popup uebernimmt
  showLinkEntryPopup(false);
}

// ============================================================
//  SPOOLMAN INITIAL_WEIGHT SCHREIBEN (neue volle Spule)
//  Wert = aktuelles Gewicht - spool_weight = reines Filament
// ============================================================
void patchInitialWeight(float initial_w) {
  if (!wifi_ok) { Serial.println("patchInitialWeight: kein WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchInitialWeight: keine Spule"); return; }
  HTTPClient http;
  String url = String(cfg_spoolman_base) + "/api/v1/spool/" + sm_id;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);
  char body[80];
  snprintf(body, sizeof(body), "{\"initial_weight\": %.1f, \"remaining_weight\": %.1f}",
    initial_w, initial_w);  // initial und remaining gleichzeitig setzen
  Serial.printf("PATCH initial_weight: %.1fg -> %s\n", initial_w, body);
  int code = http.PATCH(String(body));
  http.end();
  if (code == 200) {
    sm_remaining = initial_w;
    sm_total = initial_w;
    Serial.printf("initial_weight OK: %.1fg\n", initial_w);
  } else {
    Serial.printf("PATCH initial_weight Fehler: %d\n", code);
  }
}

// ============================================================
//  SPOOLMAN SPOOL_WEIGHT SCHREIBEN (leere Spule mit Kern)
// ============================================================
void patchSpoolWeight(float spool_w) {
  if (!wifi_ok) { Serial.println("patchSpoolWeight: no WiFi"); return; }
  if (!sm_found || sm_id == 0) { Serial.println("patchSpoolWeight: no spool"); return; }
  HTTPClient http;
  String url = String(cfg_spoolman_base) + "/api/v1/spool/" + sm_id;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);
  char body[64];
  snprintf(body, sizeof(body), "{\"spool_weight\": %.1f}", spool_w);
  Serial.printf("PATCH spool_weight: %.1fg -> %s\n", spool_w, body);
  int code = http.PATCH(String(body));
  http.end();
  if (code == 200) {
    sm_spool_weight = spool_w;
    Serial.printf("spool_weight OK: %.1fg\n", spool_w);
  } else {
    Serial.printf("PATCH spool_weight Fehler: %d\n", code);
  }
}

// ============================================================
//  SPOOLMAN FILAMENT SPOOL_WEIGHT SCHREIBEN
// ============================================================
void patchFilamentSpoolWeight(float spool_w) {
  if (!wifi_ok) return;
  if (sm_filament_id == 0) { Serial.println("patchFilamentSpoolWeight: keine filament_id"); return; }
  HTTPClient http;
  String url = String(cfg_spoolman_base) + "/api/v1/filament/" + sm_filament_id;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);
  char body[64];
  snprintf(body, sizeof(body), "{\"spool_weight\": %.1f}", spool_w);
  Serial.printf("PATCH filament spool_weight: ID=%d %.1fg\n", sm_filament_id, spool_w);
  int code = http.PATCH(String(body));
  http.end();
  Serial.printf("patchFilamentSpoolWeight: HTTP %d\n", code);
}

// ============================================================
//  SPOOLMAN VENDOR EMPTY_SPOOL_WEIGHT SCHREIBEN
// ============================================================
void patchVendorSpoolWeight(float spool_w) {
  if (!wifi_ok) return;
  if (sm_vendor_id == 0) { Serial.println("patchVendorSpoolWeight: keine vendor_id"); return; }
  HTTPClient http;
  String url = String(cfg_spoolman_base) + "/api/v1/vendor/" + sm_vendor_id;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(5000);
  char body[64];
  snprintf(body, sizeof(body), "{\"empty_spool_weight\": %.1f}", spool_w);
  Serial.printf("PATCH vendor empty_spool_weight: ID=%d %.1fg\n", sm_vendor_id, spool_w);
  int code = http.PATCH(String(body));
  http.end();
  Serial.printf("patchVendorSpoolWeight: HTTP %d\n", code);
}

void closeConfirmPopup() {
  if (confirm_popup) { lv_obj_del(confirm_popup); confirm_popup = nullptr; }
  confirm_action = 0;
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
  lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_q, LV_TEXT_ALIGN_CENTER, 0);
  lv_label_set_long_mode(lbl_q, LV_LABEL_LONG_WRAP);

  if (action == 2) {
    // Layout: 4 Zeilen — Row1=66, Row2=52, Row3=52, Row4=42
    // BOX_H = 8+28+6+66+6+52+6+52+6+42+8 = 280px
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
    lv_obj_set_style_text_font(lbl_q, &lv_font_montserrat_14, 0);
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
    lv_obj_set_style_text_font(l1, &lv_font_montserrat_16, 0);
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
    lv_obj_set_style_text_font(l2, &lv_font_montserrat_16, 0);
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
    lv_obj_set_style_text_font(l3, &lv_font_montserrat_14, 0);
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
      lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
      lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

      // Button 1: this spool
      lv_obj_t *b1 = lv_btn_create(popup);
      lv_obj_set_size(b1, 460, 60); lv_obj_set_pos(b1, 10, 36);
      lv_obj_set_style_bg_color(b1, lv_color_hex(0x0a2040), 0);
      lv_obj_set_style_radius(b1, 8, 0); lv_obj_set_style_shadow_width(b1, 0, 0);
      { lv_obj_t *l = lv_label_create(b1);
        lv_label_set_text(l, T(STR_BTN_THIS_SPOOL));
        lv_obj_set_style_text_color(l, lv_color_hex(0xc8d8f0), 0);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_16, 0);
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
        lv_obj_set_style_text_font(l, &lv_font_montserrat_16, 0);
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
        lv_obj_set_style_text_font(l, &lv_font_montserrat_16, 0);
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
        lv_obj_set_style_text_font(l, &lv_font_montserrat_14, 0);
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
    lv_obj_set_style_text_font(l4, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(l4, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l4);

    // ── Row 3 left: TARE ──
    lv_obj_t *btn5 = lv_btn_create(box);
    lv_obj_set_size(btn5, BW2, H_ROW3);
    lv_obj_set_pos(btn5, XL, Y3);
    lv_obj_set_style_bg_color(btn5, lv_color_hex(0x2a2010), 0);
    lv_obj_set_style_bg_color(btn5, lv_color_hex(0x4a4020), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn5, 8, 0);
    lv_obj_set_style_shadow_width(btn5, 0, 0);
    lv_obj_add_event_cb(btn5, [](lv_event_t *e) {
      if (scale_ready) {
        int32_t raw = nau.read();
        saveTareOffset(raw);
        scale_weight_g = 0.0f;
        memset(scale_filter_buf, 0, sizeof(scale_filter_buf));
        scale_filter_idx = 0; scale_filter_full = false;
        lv_label_set_text(lbl_scale_weight, "0 g");
        Serial.println("TARE (popup)");
      }
      closeConfirmPopup();
    }, LV_EVENT_CLICKED, NULL);
    lv_obj_t *l5 = lv_label_create(btn5);
    lv_label_set_text(l5, T(STR_BTN_TARE_ZERO));
    lv_obj_set_style_text_color(l5, lv_color_hex(0xf0b838), 0);
    lv_obj_set_style_text_font(l5, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_align(l5, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(l5);

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
    lv_obj_set_style_text_font(l6, &lv_font_montserrat_14, 0);
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
    lv_obj_set_style_text_font(l7, &lv_font_montserrat_16, 0);
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
    lv_obj_set_style_text_font(lbl_ja, &lv_font_montserrat_18, 0);
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
    lv_obj_set_style_text_font(lbl_nein, &lv_font_montserrat_18, 0);
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
  int rssi = WiFi.RSSI();
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
  lv_obj_set_style_text_font(hdr_lbl, &lv_font_montserrat_12, 0);
  lv_obj_align(hdr_lbl, LV_ALIGN_LEFT_MID, 6, 0);

  lbl_hdr_wifi = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_wifi, LV_SYMBOL_WIFI);
  lv_obj_set_style_text_color(lbl_hdr_wifi, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_wifi, &lv_font_montserrat_12, 0);
  lv_obj_align(lbl_hdr_wifi, LV_ALIGN_RIGHT_MID, -100, 0);

  lbl_hdr_nfc = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_nfc, "NFC");
  lv_obj_set_style_text_color(lbl_hdr_nfc, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_nfc, &lv_font_montserrat_12, 0);
  lv_obj_align(lbl_hdr_nfc, LV_ALIGN_RIGHT_MID, -68, 0);

  lbl_hdr_scl = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_scl, "SCL");
  lv_obj_set_style_text_color(lbl_hdr_scl, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_scl, &lv_font_montserrat_12, 0);
  lv_obj_align(lbl_hdr_scl, LV_ALIGN_RIGHT_MID, -36, 0);

  // Fix 10: Spoolman reachability indicator
  lbl_hdr_sm = lv_label_create(hdr);
  lv_label_set_text(lbl_hdr_sm, "SPM");
  lv_obj_set_style_text_color(lbl_hdr_sm, lv_color_hex(0x606060), 0);
  lv_obj_set_style_text_font(lbl_hdr_sm, &lv_font_montserrat_12, 0);
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
  lv_obj_set_style_text_font(lbl_nfc_dot, &lv_font_montserrat_14, 0);
  lv_obj_align(lbl_nfc_dot, LV_ALIGN_LEFT_MID, 6, 0);

  lbl_status = lv_label_create(status_bar);
  lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
  lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_status, &lv_font_montserrat_14, 0);
  lv_obj_align(lbl_status, LV_ALIGN_LEFT_MID, 22, 0);

  // Scan counter: right side of status bar
  lbl_hdr_scans = lv_label_create(status_bar);
  lv_label_set_text(lbl_hdr_scans, "#0");
  lv_obj_set_style_text_color(lbl_hdr_scans, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(lbl_hdr_scans, &lv_font_montserrat_12, 0);
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
  lv_obj_set_style_text_font(lbl_id_cap, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(lbl_id_cap, 58, 51);

  // SM-ID value (x=58, y=65)
  lbl_spoolman_id = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_id, "?");
  lv_obj_set_style_text_color(lbl_spoolman_id, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spoolman_id, &lv_font_montserrat_16, 0);
  lv_obj_set_pos(lbl_spoolman_id, 58, 65);

  // Cap: Material (x=92, y=51)
  lv_obj_t *lbl_mat_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_mat_cap, "Material");
  lv_obj_set_style_text_color(lbl_mat_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_mat_cap, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(lbl_mat_cap, 92, 51);

  // Material value (x=92, y=65)
  lbl_material = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_material, "-");
  lv_obj_set_style_text_color(lbl_material, lv_color_hex(0xf0f0f0), 0);
  lv_obj_set_style_text_font(lbl_material, &lv_font_montserrat_20, 0);
  lv_obj_set_pos(lbl_material, 92, 63);
  lv_label_set_long_mode(lbl_material, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_material, 160);

  // Cap: Filament (x=260, y=51)
  lv_obj_t *lbl_fil_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_fil_cap, "Filament");
  lv_obj_set_style_text_color(lbl_fil_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_fil_cap, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(lbl_fil_cap, 232, 51);  // Fix 5: slightly left

  // Filament Name value (x=260, y=65)
  lbl_filament_name = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_filament_name, "-");
  lv_obj_set_style_text_color(lbl_filament_name, lv_color_hex(0xf0f0f0), 0);  // Fix 8: same as material
  lv_obj_set_style_text_font(lbl_filament_name, &lv_font_montserrat_16, 0);
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
  lv_obj_set_style_text_font(lbl_vendor_cap, &lv_font_montserrat_14, 0);  // Fix 5: +1 size
  lv_obj_set_pos(lbl_vendor_cap, 8, 98);

  lbl_vendor = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_vendor, "-");
  lv_obj_set_style_text_color(lbl_vendor, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_vendor, &lv_font_montserrat_16, 0);
  lv_obj_set_pos(lbl_vendor, 8, 115);  // Fix 5: +2px gap
  lv_label_set_long_mode(lbl_vendor, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_vendor, 190);

  lv_obj_t *lbl_temp_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_temp_cap, T(STR_LBL_TEMP));
  lv_obj_set_style_text_color(lbl_temp_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_temp_cap, &lv_font_montserrat_14, 0);
  lv_obj_set_pos(lbl_temp_cap, 248, 98);  // Fix 5: more right

  lbl_temp = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_temp, "-");
  lv_obj_set_style_text_color(lbl_temp, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(lbl_temp, &lv_font_montserrat_16, 0);
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
  lv_obj_add_event_cb(btn_more, [](lv_event_t *e){ showMoreInfoScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_more = lv_label_create(btn_more);
  lv_label_set_text(lbl_more, g_lang == LANG_DE ? "Mehr Info" : "More info");
  lv_obj_set_style_text_color(lbl_more, lv_color_hex(0x28d49a), 0);  // teal text
  lv_obj_set_style_text_font(lbl_more, &lv_font_montserrat_12, 0);
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
  lv_obj_set_style_text_font(lbl_lu_cap, &lv_font_montserrat_14, 0);  // Fix 5
  lv_obj_set_pos(lbl_lu_cap, 8, 142);

  lbl_last_used = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_last_used, "-");
  lv_obj_set_style_text_color(lbl_last_used, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_last_used, &lv_font_montserrat_16, 0);
  lv_obj_set_pos(lbl_last_used, 8, 158);  // Fix 3: more gap
  lv_label_set_long_mode(lbl_last_used, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_last_used, 228);

  lv_obj_t *lbl_ld_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_ld_cap, T(STR_LBL_LAST_DRIED));
  lv_obj_set_style_text_color(lbl_ld_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_ld_cap, &lv_font_montserrat_14, 0);  // Fix 5
  lv_obj_set_pos(lbl_ld_cap, 244, 142);

  lbl_spoolman_dried_val = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_dried_val, "-");
  lv_obj_set_style_text_color(lbl_spoolman_dried_val, lv_color_hex(0x5090e0), 0);
  lv_obj_set_style_text_font(lbl_spoolman_dried_val, &lv_font_montserrat_16, 0);
  lv_obj_set_pos(lbl_spoolman_dried_val, 244, 158);  // Fix 3
  lv_label_set_long_mode(lbl_spoolman_dried_val, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_spoolman_dried_val, 228);
  lbl_spoolman_dried = lbl_spoolman_dried_val;

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
  lv_obj_set_style_text_font(lbl_sm_cap, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(lbl_sm_cap, 8, 188);

  // Spoolman filament remaining — BIG
  lbl_spoolman_weight = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_weight, wifi_ok ? "..." : T(STR_NO_WIFI));
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spoolman_weight, &lv_font_montserrat_20, 0);
  lv_obj_set_pos(lbl_spoolman_weight, 8, 204);

  // Percent — Fix 3: right of weight, same row
  lbl_spoolman_pct = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_obj_set_style_text_color(lbl_spoolman_pct, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(lbl_spoolman_pct, &lv_font_montserrat_14, 0);
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
  lv_obj_set_style_text_font(lbl_sc_cap, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(lbl_sc_cap, 218, 188);

  // Scale filament netto — BIG
  lbl_scale_weight = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_scale_weight, scale_ready ? "0 g" : "---");
  lv_obj_set_style_text_color(lbl_scale_weight, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_scale_weight, &lv_font_montserrat_20, 0);
  lv_obj_set_pos(lbl_scale_weight, 218, 204);

  // SM diff caption + value — both diffs stacked on right side (Fix 3)
  lv_obj_t *lbl_diff_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_diff_cap, "Diff:");
  lv_obj_set_style_text_color(lbl_diff_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_diff_cap, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(lbl_diff_cap, 362, 188);

  lbl_raw_info = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_raw_info, "");
  lv_obj_set_style_text_color(lbl_raw_info, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_raw_info, &lv_font_montserrat_16, 0);
  lv_obj_set_pos(lbl_raw_info, 362, 204);  // Fix 3: right column

  // Fix 1: "Gesamt" / "Total" — Fix 4: value x same as o.Beutel value
  lv_obj_t *lbl_live_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_live_cap, g_lang == LANG_DE ? "Gesamt:" : "Total:");
  lv_obj_set_style_text_color(lbl_live_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_live_cap, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(lbl_live_cap, 218, 228);

  lbl_spoolman_dried = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_spoolman_dried, "");
  lv_obj_set_style_text_color(lbl_spoolman_dried, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_spoolman_dried, &lv_font_montserrat_14, 0);
  lv_obj_set_pos(lbl_spoolman_dried, 286, 226);  // Fix 4: same x as o.Beutel value

  // Fix 2: "o. Beutel" / "w/o Bag"
  lv_obj_t *lbl_bag_cap = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_bag_cap, g_lang == LANG_DE ? "o. Beutel:" : "w/o Bag:");
  lv_obj_set_style_text_color(lbl_bag_cap, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_bag_cap, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(lbl_bag_cap, 218, 246);

  lv_obj_t *lbl_bag_diff = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_bag_diff, "");
  lv_obj_set_style_text_color(lbl_bag_diff, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_bag_diff, &lv_font_montserrat_14, 0);
  lv_obj_set_pos(lbl_bag_diff, 286, 244);
  lbl_keys = lbl_bag_diff;

  // Fix 3+4: bag SM diff — stacked below Waage-Spule diff, with "g"
  lbl_bag_sm_diff = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_bag_sm_diff, "");
  lv_obj_set_style_text_color(lbl_bag_sm_diff, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_bag_sm_diff, &lv_font_montserrat_16, 0);
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
    if (scale_ready) {
      int32_t raw = nau.read();
      saveTareOffset(raw);
      scale_weight_g = 0.0f;
      memset(scale_filter_buf, 0, sizeof(scale_filter_buf));
      scale_filter_idx = 0; scale_filter_full = false;
      lv_label_set_text(lbl_scale_weight, "0 g");
      Serial.println("TARE (main)");
    }
  }, LV_EVENT_CLICKED, NULL);
  // Icon top, text bottom — both centered
  lv_obj_t *lbl_tare_icon = lv_label_create(btn_tare);
  lv_label_set_text(lbl_tare_icon, LV_SYMBOL_REFRESH);
  lv_obj_set_style_text_color(lbl_tare_icon, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_tare_icon, &lv_font_montserrat_18, 0);
  lv_obj_align(lbl_tare_icon, LV_ALIGN_CENTER, 0, -10);
  lv_obj_t *lbl_tare_txt = lv_label_create(btn_tare);
  lv_label_set_text(lbl_tare_txt, "TARE");
  lv_obj_set_style_text_color(lbl_tare_txt, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_tare_txt, &lv_font_montserrat_10, 0);
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
    showConfirmPopup(T(STR_POPUP_WEIGHT_Q), 2);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_wm = lv_label_create(btn_weight_main);
  lv_label_set_text(lbl_wm, T(STR_BTN_WEIGHT));
  lv_obj_set_style_text_color(lbl_wm, lv_color_hex(0x40c080), 0);
  lv_obj_set_style_text_font(lbl_wm, &lv_font_montserrat_16, 0);
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
    if (!sm_found || sm_id == 0) { btn_dried_cb(nullptr); return; }
    showConfirmPopup(T(STR_POPUP_DRIED_Q), 1);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_dr = lv_label_create(btn_dried);
  lv_label_set_text(lbl_dr, T(STR_BTN_DRIED));
  lv_obj_set_style_text_color(lbl_dr, lv_color_hex(0x5090e0), 0);
  lv_obj_set_style_text_font(lbl_dr, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_align(lbl_dr, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(lbl_dr, LV_ALIGN_CENTER, 0, 0);

  // "Link spool" button — same slot, initially hidden
  btn_link = lv_btn_create(btn_bar);
  lv_obj_set_size(btn_link, 416, 40);
  lv_obj_set_pos(btn_link, 6, 8);
  lv_obj_set_style_bg_color(btn_link, lv_color_hex(0x1a2800), 0);
  lv_obj_set_style_bg_color(btn_link, lv_color_hex(0x2a4000), LV_STATE_PRESSED);
  lv_obj_set_style_border_width(btn_link, 1, 0);
  lv_obj_set_style_border_color(btn_link, lv_color_hex(0x3a5000), 0);
  lv_obj_set_style_radius(btn_link, 8, 0);
  lv_obj_set_style_shadow_width(btn_link, 0, 0);
  lv_obj_add_flag(btn_link, LV_OBJ_FLAG_HIDDEN);
  lv_obj_add_event_cb(btn_link, [](lv_event_t *e) {
    link_popup_dismissed = false;
    showLinkEntryPopup(strlen(g_tag.tray_uuid) == 32);
  }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_lk = lv_label_create(btn_link);
  lv_label_set_text(lbl_lk, T(STR_BTN_LINK));
  lv_obj_set_style_text_color(lbl_lk, lv_color_hex(0xa0c820), 0);
  lv_obj_set_style_text_font(lbl_lk, &lv_font_montserrat_14, 0);
  lv_obj_center(lbl_lk);

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
  lv_obj_add_event_cb(btn_menu, [](lv_event_t *e){ showSettingsScreen(); }, LV_EVENT_CLICKED, NULL);
  lv_obj_t *lbl_menu = lv_label_create(btn_menu);
  lv_label_set_text(lbl_menu, LV_SYMBOL_LIST);
  lv_obj_set_style_text_color(lbl_menu, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(lbl_menu, &lv_font_montserrat_16, 0);
  lv_obj_center(lbl_menu);

  // Yellow update badge on burger — shown when background check finds newer version
  // Position: top-right corner of burger button (btn_bar y=265, btn y=8 → absolute y=273-14=259+265=274... use scr_act coords)
  // btn_bar at y=265, btn_menu at x=429,y=8 inside btn_bar → absolute x=429+44-8=465, y=265+8-8=265
  lbl_burger_badge = lv_label_create(lv_scr_act());
  lv_label_set_text(lbl_burger_badge, LV_SYMBOL_BULLET);
  lv_obj_set_style_text_color(lbl_burger_badge, lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(lbl_burger_badge, &lv_font_montserrat_18, 0);
  lv_obj_set_pos(lbl_burger_badge, 466, 260);
  lv_obj_add_flag(lbl_burger_badge, LV_OBJ_FLAG_HIDDEN);

  page_main = lv_scr_act();
  // lbl_raw_info points to SM diff label on main screen (see above)
}

// ============================================================
//  MAINSCREEN: UPDATE BUTTON VISIBILITY
//  btn_dried visible when spool known, btn_link when unknown + tag present
// ============================================================
void updateLinkButton() {
  if (!btn_dried || !btn_link || !btn_weight_main) return;
  if (tag_present && !sm_found) {
    // Tag present but not linked: show Link (full width), hide Weight+Dried
    lv_obj_add_flag(btn_weight_main,   LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_dried,         LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_link,        LV_OBJ_FLAG_HIDDEN);
  } else {
    // No tag, or tag linked: show Weight+Dried, hide Link
    lv_obj_clear_flag(btn_weight_main, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(btn_dried,       LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(btn_link,          LV_OBJ_FLAG_HIDDEN);
  }
}

// ============================================================
//  MORE INFO FILAMENT SCREEN
//  Overlay with teal border (8px margin), shows UID, UUID,
//  article nr, production date, spool weight (empty), free slot.
//  Always rebuilt on open. Only one close button (X).
// ============================================================
void showMoreInfoScreen() {
  // Delete old instance if exists
  if (scr_more_info) { lv_obj_del(scr_more_info); scr_more_info = nullptr; }
  buildMoreInfoScreen();
}

void buildMoreInfoScreen() {
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
  lv_obj_set_style_text_font(lbl_title, &lv_font_montserrat_16, 0);
  lv_obj_align(lbl_title, LV_ALIGN_LEFT_MID, 10, 0);

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
  lv_obj_set_style_text_font(lbl_x, &lv_font_montserrat_18, 0);
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
  lv_obj_set_style_text_font(mi_id_cap, &lv_font_montserrat_12, 0);
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
  lv_obj_set_style_text_font(lbl_id, &lv_font_montserrat_16, 0);
  lv_obj_set_pos(lbl_id, 60, 70);

  // Cap: Material
  lv_obj_t *mi_mat_cap = lv_label_create(box);
  lv_label_set_text(mi_mat_cap, "Material");
  lv_obj_set_style_text_color(mi_mat_cap, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(mi_mat_cap, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(mi_mat_cap, 98, 55);

  // Material value — for NTAG spools use sm_material (from Spoolman), for Bambu use g_tag.material
  lv_obj_t *lbl_mat = lv_label_create(box);
  lbl_mi_mat = nullptr;  // not used for live update
  const char* mat_val = (strlen(sm_material_global) > 0) ? sm_material_global :
                        (strlen(g_tag.material) > 0 ? g_tag.material : "-");
  lv_label_set_text(lbl_mat, mat_val);
  lv_obj_set_style_text_color(lbl_mat, lv_color_hex(0xf0f0f0), 0);
  lv_obj_set_style_text_font(lbl_mat, &lv_font_montserrat_18, 0);
  lv_obj_set_pos(lbl_mat, 98, 68);
  lv_label_set_long_mode(lbl_mat, LV_LABEL_LONG_DOT);
  lv_obj_set_width(lbl_mat, 160);

  // Cap: Filament
  lv_obj_t *mi_fn_cap = lv_label_create(box);
  lv_label_set_text(mi_fn_cap, "Filament");
  lv_obj_set_style_text_color(mi_fn_cap, lv_color_hex(0x2a4060), 0);
  lv_obj_set_style_text_font(mi_fn_cap, &lv_font_montserrat_12, 0);
  lv_obj_set_pos(mi_fn_cap, 264, 55);

  // Filament name value
  lv_obj_t *lbl_fn = lv_label_create(box);
  lv_label_set_text(lbl_fn, strlen(sm_filament_name) > 0 ? sm_filament_name : "-");
  lv_obj_set_style_text_color(lbl_fn, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(lbl_fn, &lv_font_montserrat_16, 0);
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
  lv_obj_set_style_text_font(c1, &lv_font_montserrat_14, 0);  // Fix 6: 12→14
  lv_obj_set_pos(c1, CA, 114);
  lv_obj_t *v1 = lv_label_create(box);
  const char* color_display = (strlen(g_tag.color_hex) > 1) ? g_tag.color_hex :
                              (strlen(sm_color_global) > 1 ? sm_color_global : "-");
  lv_label_set_text(v1, color_display);
  lv_obj_set_style_text_color(v1, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(v1, &lv_font_montserrat_18, 0);  // Fix 6: 16→18
  lv_obj_set_pos(v1, CA, 114 + VF);

  // Row 1 Right: Production date — Fix 6
  const char *prod_cap = g_lang == LANG_DE ? "Produktionsdatum" : "Production date";
  lv_obj_t *c2 = lv_label_create(box);
  lv_label_set_text(c2, prod_cap);
  lv_obj_set_style_text_color(c2, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c2, &lv_font_montserrat_14, 0);  // Fix 6
  lv_obj_set_pos(c2, CB, 114);
  lv_obj_t *v2 = lv_label_create(box);
  lv_label_set_text(v2, strlen(g_tag.production_date) > 4 ? g_tag.production_date : "-");
  lv_obj_set_style_text_color(v2, lv_color_hex(0x8ab0d8), 0);
  lv_obj_set_style_text_font(v2, &lv_font_montserrat_18, 0);  // Fix 6
  lv_obj_set_pos(v2, CB, 114 + VF);

  // Row 2 Left: Article no. — Fix 6: larger — Fix 2: more space (y=160)
  const char *art_cap = g_lang == LANG_DE ? "Artikelnr." : "Article no.";
  lv_obj_t *c3 = lv_label_create(box);
  lv_label_set_text(c3, art_cap);
  lv_obj_set_style_text_color(c3, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c3, &lv_font_montserrat_14, 0);
  lv_obj_set_pos(c3, CA, 158);
  lv_obj_t *v3 = lv_label_create(box);
  lv_label_set_text(v3, strlen(sm_article_nr) > 0 ? sm_article_nr : "-");
  lv_obj_set_style_text_color(v3, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(v3, &lv_font_montserrat_18, 0);
  lv_obj_set_pos(v3, CA, 158 + VF);

  // Row 2 Right: Spool weight (empty)
  const char *sw_cap = g_lang == LANG_DE ? "Leergewicht Spule" : "Spool weight (empty)";
  lv_obj_t *c4 = lv_label_create(box);
  lv_label_set_text(c4, sw_cap);
  lv_obj_set_style_text_color(c4, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c4, &lv_font_montserrat_14, 0);
  lv_obj_set_pos(c4, CB, 158);
  lv_obj_t *v4 = lv_label_create(box);
  char sw_buf[16];
  if (sm_spool_weight > 0) snprintf(sw_buf, sizeof(sw_buf), "%.0f g", sm_spool_weight);
  else strncpy(sw_buf, "-", sizeof(sw_buf));
  lv_label_set_text(v4, sw_buf);
  lv_obj_set_style_text_color(v4, lv_color_hex(0xc8d8f0), 0);
  lv_obj_set_style_text_font(v4, &lv_font_montserrat_18, 0);
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
  lv_obj_set_style_text_font(c_uid, &lv_font_montserrat_14, 0);
  lv_obj_set_pos(c_uid, 10, 206);
  lv_obj_t *v_uid = lv_label_create(box);
  lv_label_set_text(v_uid, strlen(g_tag.uid_str) > 0 ? g_tag.uid_str : "-");
  lv_obj_set_style_text_color(v_uid, lv_color_hex(0x28d49a), 0);
  lv_obj_set_style_text_font(v_uid, &lv_font_montserrat_18, 0);
  lv_obj_set_pos(v_uid, 10, 206 + VF);

  // Spoolman ID right
  lv_obj_t *c_smid2 = lv_label_create(box);
  lv_label_set_text(c_smid2, "Spoolman ID");
  lv_obj_set_style_text_color(c_smid2, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c_smid2, &lv_font_montserrat_14, 0);
  lv_obj_set_pos(c_smid2, CB, 206);
  lv_obj_t *v_smid2 = lv_label_create(box);
  char smid_buf[12];
  if (sm_found && sm_id > 0) snprintf(smid_buf, sizeof(smid_buf), "%d", sm_id);
  else strncpy(smid_buf, "?", sizeof(smid_buf));
  lv_label_set_text(v_smid2, smid_buf);
  lv_obj_set_style_text_color(v_smid2,
    (sm_found && sm_id > 0) ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0b838), 0);
  lv_obj_set_style_text_font(v_smid2, &lv_font_montserrat_18, 0);
  lv_obj_set_pos(v_smid2, CB, 206 + VF);

  // Spoolman UUID — shifted down (y=246)
  lv_obj_t *c_uuid = lv_label_create(box);
  lv_label_set_text(c_uuid, "Spoolman UUID");
  lv_obj_set_style_text_color(c_uuid, lv_color_hex(0x4a6fa0), 0);
  lv_obj_set_style_text_font(c_uuid, &lv_font_montserrat_14, 0);
  lv_obj_set_pos(c_uuid, 10, 248);
  lv_obj_t *v_uuid = lv_label_create(box);
  lv_label_set_text(v_uuid,
    strlen(g_tag.tray_uuid) == 32 ? g_tag.tray_uuid : "-");
  lv_obj_set_style_text_color(v_uuid, lv_color_hex(0x4a7080), 0);
  lv_obj_set_style_text_font(v_uuid, &lv_font_montserrat_16, 0);
  lv_obj_set_pos(v_uuid, 10, 264);
  lv_label_set_long_mode(v_uuid, LV_LABEL_LONG_DOT);
  lv_obj_set_width(v_uuid, 444);
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
void lastUsedDisplayStr(const char* de_date, char* out, size_t len) {
  driedDisplayStr(de_date, out, len);  // identische Formatierung
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
  WiFi.mode(WIFI_STA);
  WiFi.begin(cfg_wifi_ssid, cfg_wifi_password);
  for (int i = 0; i < 20; i++) {
    delay(500);
    if (WiFi.status() == WL_CONNECTED) {
      wifi_ok = true;
      Serial.printf("WiFi OK! IP: %s\n", WiFi.localIP().toString().c_str());
      updateHeaderStatus();
      syncNTP();
      // Fix 2: immediate Spoolman health check after WiFi connect
      if (strlen(cfg_spoolman_base) > 4) {
        HTTPClient hc;
        String url = String(cfg_spoolman_base) + "/api/v1/health";
        hc.begin(url);
        hc.setTimeout(3000);
        int code = hc.GET();
        hc.end();
        sm_reachable = (code == 200);
      }
      updateHeaderStatus();
      lv_label_set_text(lbl_spoolman_weight, T(STR_WAIT_SCAN_SM));
      lv_timer_handler();
      silent_ota_check_pending = true;  // background OTA check after WiFi up
      return;
    }
  }
  Serial.println("WiFi FAILED – continuing without Spoolman");
  updateHeaderStatus();
  lv_label_set_text(lbl_spoolman_weight, T(STR_NO_WIFI));
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

  HTTPClient http;
  http.begin(String(cfg_spoolman_base) + "/api/v1/spool/" + spool_id);
  http.setTimeout(8000);
  int code = http.GET();
  if (code != 200) {
    Serial.printf("querySpoolmanById HTTP error: %d\n", code);
    http.end();
    return;
  }
  String payload = http.getString();
  http.end();

  DynamicJsonDocument doc(8192);
  if (deserializeJson(doc, payload)) {
    Serial.println("querySpoolmanById: JSON error");
    return;
  }

  JsonObject spool = doc.as<JsonObject>();
  bool is_bambu_tag = (strlen(g_tag.material) > 0);

  sm_found        = true;
  sm_id           = spool["id"] | 0;
  sm_filament_id  = spool["filament"]["id"] | 0;
  sm_vendor_id    = spool["filament"]["vendor"]["id"] | 0;
  sm_remaining    = spool["remaining_weight"] | 0.0f;
  sm_total        = spool["filament"]["weight"] | 1000.0f;
  sm_spool_weight = spool["spool_weight"] | 0.0f;

  String art_nr = spool["filament"]["article_number"] | "";
  art_nr.trim();
  strncpy(sm_article_nr, art_nr.c_str(), sizeof(sm_article_nr)-1);

  String fil_name = spool["filament"]["name"] | String("");
  fil_name.trim();
  strncpy(sm_filament_name, fil_name.c_str(), sizeof(sm_filament_name)-1);

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
    if (sm_color.length() >= 6) {
      String hex = sm_color;
      if (hex.startsWith("#")) hex = hex.substring(1);
      unsigned int r, g, b;
      sscanf(hex.c_str(), "%02X%02X%02X", &r, &g, &b);
      uint32_t col = ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
      lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(col), 0);
    }
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
  lv_label_set_text(lbl_spoolman_dried_val, dried_display);

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
  lastUsedDisplayStr(sm_last_used, last_used_display, sizeof(last_used_display));
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

  // Reset all Spoolman labels before new query
  lv_label_set_text(lbl_spoolman_weight, T(STR_WAIT));
  lv_obj_set_style_text_color(lbl_spoolman_weight, lv_color_hex(0x28d49a), 0);
  lv_label_set_text(lbl_spoolman_pct, "");
  lv_label_set_text(lbl_spoolman_dried_val, "");
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
  sm_found = false;
  sm_id = 0;
  sm_spool_weight = 0;
  sm_remaining = 0;
  sm_total = 1000;
  lv_timer_handler();

  HTTPClient http;
  Serial.printf("DBG free heap: %d bytes  free PSRAM: %d bytes\n", ESP.getFreeHeap(), ESP.getFreePsram());
  http.begin(String(cfg_spoolman_base) + "/api/v1/spool");
  http.setTimeout(8000);
  int code = http.GET();
  if (code != 200) {
    Serial.printf("Spoolman HTTP error: %d\n", code);
    lv_label_set_text(lbl_spoolman_weight, T(STR_API_ERROR));
    http.end();
    return;
  }

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

  // Stream directly from HTTP — avoids allocating a 40KB+ String in RAM
  WiFiClient* stream = http.getStreamPtr();
  // Use PSRAM for this document — frees internal RAM for LVGL
  SpiRamAllocator psram_alloc;
  JsonDocument doc(&psram_alloc);
  DeserializationError err = deserializeJson(doc, *stream, DeserializationOption::Filter(filter));
  http.end();
  Serial.printf("DBG free heap after parse: %d bytes  free PSRAM: %d bytes\n", ESP.getFreeHeap(), ESP.getFreePsram());
  if (err) {
    Serial.printf("Spoolman JSON error: %s\n", err.c_str());
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
    String art_nr = spool["filament"]["article_number"] | "";
    art_nr.trim();
    strncpy(sm_article_nr, art_nr.c_str(), sizeof(sm_article_nr)-1);
    String fil_name = spool["filament"]["name"] | String("");
    fil_name.trim();
    strncpy(sm_filament_name, fil_name.c_str(), sizeof(sm_filament_name)-1);

    // last_dried
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
    lv_label_set_text(lbl_spoolman_dried_val, dried_display);

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
    lastUsedDisplayStr(sm_last_used, last_used_display, sizeof(last_used_display));
    lv_label_set_text(lbl_last_used, last_used_display);

    updateLinkButton();
    return;
  }

  // Not found in active spools — check if archived
  Serial.println("Spoolman: not in active spools, checking archive...");
  doc.clear();  // RAM freigeben vor zweitem Call

  // Second call with allow_archived=true
  HTTPClient http2;
  http2.begin(String(cfg_spoolman_base) + "/api/v1/spool?allow_archived=true");
  http2.setTimeout(8000);
  int code2 = http2.GET();
  if (code2 == 200) {
    DynamicJsonDocument doc2(16384);
    StaticJsonDocument<256> filter2;
    JsonArray filter2_arr = filter2.to<JsonArray>();
    JsonObject f2 = filter2_arr.createNestedObject();
    f2["id"] = true;
    f2["archived"] = true;
    f2["extra"]["tag"] = true;
    WiFiClient* stream2 = http2.getStreamPtr();
    if (!deserializeJson(doc2, *stream2, DeserializationOption::Filter(filter2))) {
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
    http2.end();
  } else {
    http2.end();
  }

  // Truly not found
  Serial.println("Spoolman: spool not found");
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
    tft.setBrightness(bright_normal);
    is_dimmed = false;
  }
}

void handlePowerManagement() {
  unsigned long elapsed = millis() - last_activity_ms;

  if (elapsed >= sleep_timeout_ms) {
    Serial.println("Deep sleep...");
    tft.setBrightness(0);
    esp_sleep_enable_ext0_wakeup((gpio_num_t)TOUCH_INT_PIN, 0);
    delay(100);
    esp_deep_sleep_start();
  }

  if (!is_dimmed && elapsed >= dim_timeout_ms) {
    tft.setBrightness(BRIGHT_DIM_DEFAULT);
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

  I2C_TOUCH.begin(TOUCH_SDA, TOUCH_SCL, 400000);
  tft.init();
  tft.setRotation(1);
  tft.setBrightness(204);
  tft.fillScreen(TFT_BLACK);

  I2C_EXT.begin(I2C_SDA, I2C_SCL, 100000);

  lv_init();
  lv_disp_draw_buf_init(&draw_buf, disp_buf, NULL, 480 * 10);
  static lv_disp_drv_t disp_drv;
  lv_disp_drv_init(&disp_drv);
  disp_drv.hor_res = 480; disp_drv.ver_res = 320;
  disp_drv.flush_cb = lvgl_flush; disp_drv.draw_buf = &draw_buf;
  lv_disp_drv_register(&disp_drv);
  static lv_indev_drv_t indev_drv;
  lv_indev_drv_init(&indev_drv);
  indev_drv.type = LV_INDEV_TYPE_POINTER;
  indev_drv.read_cb = lvgl_touch;
  lv_indev_drv_register(&indev_drv);

  delay(500);

  Serial.print("Looking for PN532... ");
  nfc.begin();
  delay(100);
  uint32_t ver = nfc.getFirmwareVersion();
  if (ver) {
    nfc_ok = true;
    nfc.SAMConfig();
    Serial.printf("OK (FW %d.%d)\n", (ver >> 16) & 0xFF, (ver >> 8) & 0xFF);
  } else {
    Serial.println("ERROR!");
  }

  Serial.print("Looking for NAU7802... ");
  if (nau.begin(&I2C_EXT)) {
    scl_ok = true;
    nau.setLDO(NAU7802_3V0);
    nau.setGain(NAU7802_GAIN_128);
    nau.setRate(NAU7802_RATE_10SPS);
    delay(300);
    while (!nau.calibrate(NAU7802_CALMOD_INTERNAL)) {
      Serial.print(".");
      delay(100);
    }
    scale_ready = true;
    Serial.printf("OK! cal_factor=%.4f  zero_offset=%d\n", cal_factor, zero_offset);
  } else {
    Serial.println("ERROR! NAU7802 not found (address 0x2A)");
  }

  buildUI();
  lv_timer_handler();
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

  // OTA web server bedienen wenn aktiv
  if (ota_server_running) ota_server.handleClient();

  // Silent background OTA check — once after WiFi connect, with 5s startup delay
  static unsigned long ota_check_trigger_ms = 0;
  if (silent_ota_check_pending && wifi_ok) {
    if (ota_check_trigger_ms == 0) ota_check_trigger_ms = millis();
    if (millis() - ota_check_trigger_ms > 5000) {
      silent_ota_check_pending = false;
      ota_check_trigger_ms = 0;
      doGithubOtaCheckSilent();
    }
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
    if (strlen(g_tag.tray_uuid) == 32 && strcmp(g_tag.uid_str, spoolman_queried_uid) != 0) {
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
    int32_t raw = nau.read();
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
      snprintf(w_str, sizeof(w_str), "%.1f g", netto);
    } else {
      snprintf(w_str, sizeof(w_str), "%.1f g", scale_weight_g);
    }
    lv_label_set_text(lbl_scale_weight, w_str);
    // Also update live weight in calibration screen if open
    if (lbl_factor_cal_weight && scr_factor && !lv_obj_has_flag(scr_factor, LV_OBJ_FLAG_HIDDEN)) {
      char cal_str[16];
      snprintf(cal_str, sizeof(cal_str), "%.1f g", scale_weight_g);  // Fix 6: raw weight
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
        snprintf(lt_str, sizeof(lt_str), "%.1f g", scale_weight_g);
        lv_label_set_text(lbl_spoolman_dried, lt_str);
        lv_obj_set_style_text_color(lbl_spoolman_dried, lv_color_hex(0x8ab0d8), 0);
      }

      // Fix 4: ohne Beutel = live - spool - bag; fixed color like scale netto; diff green/red
      if (lbl_keys) {
        float ohne_beutel = scale_weight_g - sm_spool_weight - bag_weight_g;
        if (ohne_beutel < 0) ohne_beutel = 0;
        char b_str[16];
        snprintf(b_str, sizeof(b_str), "%.1f g", ohne_beutel);
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
        snprintf(lt_str, sizeof(lt_str), "%.1f g", scale_weight_g);
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

  // Fix 10: Spoolman health check every 30s
  if (wifi_ok) {
    static unsigned long last_sm_check_ms = 0;
    if (millis() - last_sm_check_ms >= 30000) {
      last_sm_check_ms = millis();
      HTTPClient hc;
      String url = String(cfg_spoolman_base) + "/api/v1/health";
      hc.begin(url);
      hc.setTimeout(3000);
      int code = hc.GET();
      hc.end();
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
      bool found = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 100);

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
          nfc_retry_count = 0;
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
            if (strcmp(g_tag.uid_str, spoolman_queried_uid) != 0 && strlen(g_tag.tray_uuid) == 32) {
              querySpoolman(g_tag.tray_uuid);
              strncpy(spoolman_queried_uid, g_tag.uid_str, sizeof(spoolman_queried_uid)-1);
              if (!sm_found && wifi_ok) {
                link_tag_first_seen_ms = millis();  // Start timer
                link_popup_dismissed = false;
              }
            } else if (!sm_found && !link_popup_dismissed && scr_link_entry == nullptr &&
                       wifi_ok && strlen(g_tag.tray_uuid) == 32) {
              // 3s delay elapsed?
              if (link_tag_first_seen_ms > 0 &&
                  millis() - link_tag_first_seen_ms >= LINK_POPUP_DELAY_MS) {
                Serial.println("Bambu: not in Spoolman -> entry popup (after delay)");
                showLinkEntryPopup(true);
              }
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
          lv_obj_set_style_bg_color(lbl_color_swatch, lv_color_hex(0x333333), 0);
          lv_label_set_text(lbl_status, T(STR_READING_TAG));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(0x28d49a), 0);
          lv_timer_handler();

          if (wifi_ok) {
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
          bool no_popup = (scr_link_entry == nullptr && scr_link_id == nullptr &&
                           scr_link_vendor == nullptr && scr_link_spools == nullptr);
          if (!sm_found && no_popup && wifi_ok && !link_popup_dismissed) {
            if (link_tag_first_seen_ms > 0 &&
                millis() - link_tag_first_seen_ms >= LINK_POPUP_DELAY_MS) {
              strncpy(link_tag_uid, uid_str, sizeof(link_tag_uid)-1);
              showLinkEntryPopup(false);
            }
          }
          lv_label_set_text(lbl_status, sm_found ? T(STR_TAG_FOUND) : T(STR_NOT_IN_SPOOLMAN));
          lv_obj_set_style_text_color(lbl_status,
            sm_found ? lv_color_hex(0x28d49a) : lv_color_hex(0xf0b838), 0);
        }

      } else {
        // No tag found
        if (tag_present) {
          Serial.println("NFC: tag removed");
          tag_present = false;
          nfc_retry_count = 0;
          last_tag_seen_ms = millis();
          link_popup_dismissed = false;   // Reset flag → next spool can show popup
          link_tag_first_seen_ms = 0;
          lv_label_set_text(lbl_nfc_dot, LV_SYMBOL_BULLET);
          lv_obj_set_style_text_color(lbl_nfc_dot, lv_color_hex(0xf0b838), 0);
          lv_label_set_text(lbl_status, T(STR_WAIT_SCAN));
          lv_obj_set_style_text_color(lbl_status, lv_color_hex(0xf0b838), 0);
          // Do NOT close list — user should be able to select spool
          // even if tag is temporarily removed
        }
      }
    }
  }

  delay(5);
}
