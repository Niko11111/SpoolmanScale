// ============================================================
//  SpoolmanScale – Localization (i18n)
//  lang.h — String IDs, enum, T() macro
//  Languages: DE (0) | EN (1)
// ============================================================
#pragma once
#include <stdint.h>

enum Lang { LANG_DE = 0, LANG_EN = 1 };
extern Lang g_lang;

// Date format: 0 = DD.MM.YYYY  |  1 = YYYY-MM-DD
extern uint8_t g_date_fmt;

enum StringID {
  // Navigation
  STR_CANCEL,
  STR_BACK,
  STR_SAVE,
  STR_CONFIRM,
  STR_CLOSE,
  STR_RETRY,
  STR_FORCE_LINK,
  STR_ENTER_NEW_ID,

  // Mainscreen Labels
  STR_LBL_UID,
  STR_LBL_UUID,
  STR_LBL_MATERIAL,
  STR_LBL_SPOOLMAN,
  STR_LBL_SCALE,
  STR_LBL_LAST_USED,
  STR_LBL_LAST_DRIED,
  STR_LBL_TEMP,
  STR_LBL_VENDOR,
  STR_LBL_ARTICLE,
  STR_LBL_PRODUCTION,
  STR_LBL_SPOOLMAN_ID,

  // Mainscreen Status
  STR_WAIT_SCAN,
  STR_TAG_FOUND,
  STR_NO_WIFI,
  STR_WAIT,
  STR_WAIT_SCAN_SM,
  STR_UNKNOWN,
  STR_NOT_READABLE,
  STR_TODAY,
  STR_YESTERDAY,
  STR_DAYS_AGO,
  STR_ERR_SAVE,
  STR_NOT_IN_SPOOLMAN,
  STR_ARCHIVED,
  STR_READING_TAG,
  STR_READING_BAMBU_SECTOR,
  // The long phase after the tag is read: the fast lookups missed and the
  // whole inventory is being pulled. Without a line of its own the display
  // sits on "reading tag" for seconds and looks like a failed read.
  STR_SEARCHING_INVENTORY,
  STR_SEARCHING_INVENTORY_KB,

  // Mainscreen Buttons
  STR_BTN_WEIGHT,
  STR_BTN_DRIED,
  STR_BTN_LINK,

  // Welcome Screen
  STR_WELCOME_SUB,
  STR_WELCOME_HINT,
  STR_BTN_SETUP_NOW,

  // WiFi Setup
  STR_WIFI_TITLE,
  STR_WIFI_SCAN,
  STR_WIFI_SELECT,
  STR_WIFI_RESCAN,
  STR_WIFI_NO_NET,
  STR_WIFI_PASS_TITLE,
  STR_WIFI_PASS_HINT,
  STR_WIFI_PASS_PLACEHOLDER,
  STR_WIFI_CONNECTING,
  STR_WIFI_SUCCESS,
  STR_WIFI_FAIL,
  STR_BTN_CONNECT,

  // Spoolman IP
  STR_SPOOLMAN_TITLE,
  STR_SPOOLMAN_HINT,

  // Settings
  STR_SETTINGS_TITLE,
  STR_TILE_CONNECTION,
  STR_TILE_CONN_SUB,
  STR_TILE_SCALE,
  STR_TILE_SCALE_SUB,
  STR_TILE_DISPLAY,
  STR_TILE_DISPLAY_SUB,
  STR_TILE_SYSTEM,
  STR_TILE_SYSTEM_SUB,
  STR_BTN_TARE,

  // Connection
  STR_CONN_TITLE,
  STR_BTN_WIFI_SETTINGS,
  STR_BTN_WIFI_NONE,
  STR_BTN_WIFI_STATUS,
  STR_BTN_WIFI_STATUS_SUB,
  STR_BTN_WEB_SUB,
  STR_WEB_SERVER,
  STR_WEB_MAINT,
  STR_WEB_CONFIG,
  STR_WEB_SERVER_HINT,
  STR_WEB_SERVER_INFO,
  STR_WEB_MAINT_HINT,
  STR_WEB_MAINT_SUB,
  STR_WEB_CONFIG_HINT,
  STR_WEB_CONFIG_SUB,
  STR_BTN_SPOOLMAN,

  // Scale
  STR_SCALE_TITLE,
  STR_BTN_CALIBRATE,
  STR_BTN_CAL_SUB,
  STR_BTN_BAGWEIGHT,
  STR_BTN_BAG_SUB,

  // Calibration
  STR_CAL_TITLE,
  STR_CAL_DESC,
  STR_CAL_FACTOR,
  STR_CAL_OK,
  STR_CAL_SCALE_NOT_READY,
  STR_CAL_ZERO_ERR,
  STR_BTN_CALCULATE,

  // Bag weight
  STR_BAG_TITLE,
  STR_BAG_DESC,
  STR_BAG_SAVED,
  STR_BAG_INVALID,

  // Display
  STR_DISPLAY_TITLE,
  STR_BRIGHT_LABEL,
  STR_DIM_LABEL,
  STR_SLEEP_LABEL,
  STR_DISPLAY_HINT,

  // System
  STR_SYSTEM_TITLE,
  STR_BTN_LANGUAGE,
  STR_BTN_LANG_SUB,
  STR_BTN_FW_UPDATE,
  STR_BTN_FW_SUB,
  STR_BTN_INFO,
  STR_BTN_INFO_SUB,

  // Language screen
  STR_LANG_TITLE,
  STR_LANG_HINT,
  STR_LANG_EN_SUB,
  STR_DATE_FMT_LABEL,

  // OTA
  STR_OTA_TITLE,
  STR_OTA_BROWSER,
  STR_OTA_BROWSER_SUB,
  STR_OTA_GITHUB,
  STR_OTA_GITHUB_SUB,
  STR_OTA_BROWSER_TITLE,
  STR_OTA_NO_WIFI,
  STR_OTA_OPEN_BROWSER,
  STR_OTA_FILE_HINT,
  STR_OTA_WAITING,
  STR_OTA_UPLOADING,
  STR_OTA_SUCCESS,
  STR_OTA_FAIL,
  STR_BTN_STOP_SERVER,
  STR_OTA_CURRENT,

  // Info Screen
  STR_INFO_TITLE,
  STR_INFO_VERSION,
  STR_INFO_HINT,

  // QR Popups
  STR_QR_KOFI_DESC,
  STR_QR_GITHUB_DESC,
  STR_QR_DISCORD_DESC,
  STR_QR_MAKER_DESC,

  // Weight popup
  STR_POPUP_DRIED_Q,
  STR_POPUP_WEIGHT_Q,
  STR_BTN_NO_BAG,
  STR_BTN_WITH_BAG,
  STR_BTN_NEW_SPOOL,
  STR_BTN_EMPTY_SPOOL,
  STR_BTN_ARCHIVE,
  STR_BTN_CONFIRMED,

  // Spool weight sub-popup
  STR_SPOOL_WEIGHT_TITLE,
  STR_BTN_THIS_SPOOL,
  STR_BTN_THIS_FILAMENT,
  STR_BTN_THIS_VENDOR,

  // Link Flow
  STR_LINK_BAMBU_TITLE,
  STR_LINK_NTAG_TITLE,
  STR_LINK_NOT_IN_SM,
  STR_BTN_ENTER_ID,
  STR_BTN_FROM_LIST,
  STR_LINK_ID_TITLE,
  STR_LINK_CHECKING,
  STR_LINK_ID_NOT_FOUND,
  STR_LINK_HTTP_ERR,
  STR_LINK_JSON_ERR,
  STR_LINK_NO_WIFI,
  STR_WARN_A_TITLE,
  STR_WARN_A_INFO,
  STR_BTN_OVERWRITE,
  STR_WARN_B_TITLE,
  STR_WARN_B_DETAILS,
  STR_VENDOR_TITLE,
  STR_MAT_TITLE,
  STR_SPOOLS_TITLE,
  STR_NO_VENDORS,
  STR_NO_MATERIALS,
  STR_NO_SPOOLS,
  STR_CONFIRM_LINK,
  STR_LINK_OK,
  STR_LINK_FAIL,

  // Tare
  STR_TARE_TITLE,
  STR_TARE_DESC,
  STR_TARE_OK,
  STR_TARE_NOT_READY,

  STR_API_ERROR,

  // Reboot popup
  STR_REBOOT_TITLE,
  STR_REBOOT_MSG,
  STR_REBOOT_BTN,

  // WiFi connecting result
  STR_WIFI_CONNECTED_IP,
  STR_WIFI_CONN_FAILED,

  // WiFi quality
  STR_WIFI_QUAL_EXCELLENT,
  STR_WIFI_QUAL_GOOD,
  STR_WIFI_QUAL_MEDIUM,
  STR_WIFI_QUAL_WEAK,
  STR_WIFI_STATUS_CONNECTED,
  STR_WIFI_STATUS_DISCONNECTED,

  // Numpad buttons
  STR_BTN_SAVE,

  // Spool list title
  STR_SPOOLS_BAMBU,
  STR_SPOOLS_ALL,

  // Settings calibration sub
  STR_CAL_FACTOR_SHORT,

  // Archive confirm
  STR_ARCHIVE_CONFIRM,

  // Weight popup archive button
  STR_BTN_ARCHIVE_EMPTY,

  // Welcome language select
  STR_WELCOME_LANG_TITLE,
  STR_WELCOME_LANG_HINT,

  // WiFi scan count
  STR_WIFI_NETWORKS_FOUND,

  // Bag weight current label
  STR_BAG_CURRENT,

  // Warn popup A fields
  STR_WARN_A_SPOOL_INFO,
  STR_WARN_A_SPOOL_SHORT,

  // Link entry context
  STR_LINK_CTX_NOT_IN_SM,

  // Weight popup buttons (with snprintf)
  STR_BTN_NO_BAG_VAL,
  STR_BTN_WITH_BAG_VAL,
  STR_BTN_NEW_SPOOL_VAL,
  STR_BTN_TARE_ZERO,

  // First boot welcome screen
  STR_FIRSTBOOT_TITLE,
  STR_FIRSTBOOT_SUB,
  STR_FIRSTBOOT_HINT,
  STR_FIRSTBOOT_BTN,

  // Extra fields screen
  STR_EXTRA_FIELDS_TITLE,
  STR_EXTRA_FIELDS_CHECKING,
  STR_EXTRA_FIELDS_ALL_OK,
  STR_EXTRA_FIELDS_MISSING,
  STR_EXTRA_FIELDS_CREATE_BTN,
  STR_EXTRA_FIELDS_CONFIRM_TITLE,
  STR_EXTRA_FIELDS_CONFIRM_MSG,
  STR_EXTRA_FIELDS_CREATING,
  STR_EXTRA_FIELDS_CREATED_OK,
  STR_EXTRA_FIELDS_CREATE_FAIL,
  STR_EXTRA_FIELDS_NO_WIFI,
  STR_EXTRA_FIELDS_NO_SPOOLMAN,
  STR_EXTRA_FIELDS_SKIP,

  // Calibration reminder screen (end of first setup)
  STR_CAL_REMINDER_TITLE,
  STR_CAL_REMINDER_MSG,
  STR_CAL_REMINDER_LATER,
  STR_CAL_REMINDER_NOW,

  // Calibration TARE hint
  STR_CAL_TARE_HINT,

  // Extra fields test button
  STR_EF_TEST_BTN,
  STR_EF_TEST_CREATED,
  STR_EF_TEST_EXISTS,
  STR_EF_TEST_FAIL,

  // Spoolman IP validation
  STR_SPOOLMAN_TESTING,
  STR_SPOOLMAN_OK,
  STR_SPOOLMAN_FAIL,
  STR_SPOOLMAN_RETRY,
  STR_SPOOLMAN_SKIP,

  // More info filament screen
  STR_BTN_MORE_INFO,

  // GitHub OTA check screen
  STR_GH_OTA_TITLE,
  STR_GH_OTA_CHECK_BTN,
  STR_GH_OTA_CHECKING,
  STR_GH_OTA_NO_WIFI,
  STR_GH_OTA_UP_TO_DATE,
  STR_GH_OTA_UPDATE_AVAIL,
  STR_GH_OTA_UPDATE_BTN,
  STR_GH_OTA_FLASHING,
  STR_GH_OTA_FLASH_OK,
  STR_GH_OTA_FLASH_FAIL,
  STR_GH_OTA_INSTALLED,
  STR_GH_OTA_LATEST,
  STR_GH_OTA_PRERELEASE,
  STR_GH_OTA_AUTOCHECK,
  STR_GH_OTA_OLDER,
  STR_GH_OTA_DOWNGRADE_BTN,
  STR_GH_OTA_DOWNGRADE_ASK,

  // Last Used Mode screen
  STR_BTN_LASTUSED_MODE,
  STR_BTN_LASTUSED_MODE_SUB,
  STR_LASTUSED_TITLE,
  STR_LASTUSED_OPT_OSM,
  STR_LASTUSED_OPT_WEIGHED,
  STR_LASTUSED_DESC_OSM,
  STR_LASTUSED_DESC_WEIGHED,
  STR_LASTUSED_OPT_FILAMAN,
  STR_LASTUSED_DESC_FILAMAN_USED,
  STR_LASTUSED_DESC_FILAMAN_WEIGHED,
  STR_BTN_LASTUSED_MODE_SUB_FM,
  STR_LASTUSED_OPT_BAMBUDDY,
  STR_LASTUSED_DESC_BAMBUDDY_USED,
  STR_LASTUSED_DESC_BAMBUDDY_WEIGHED,
  STR_BTN_LASTUSED_MODE_SUB_BB,
  STR_BB_CAP_TITLE,
  STR_BB_CAP_BODY,
  STR_BB_CAP_RAISE,
  STR_BB_CAP_KEEP,
  STR_BB_DRIED_TITLE,
  STR_BB_DRIED_OFF,
  STR_BB_DRIED_OFF_SUB,
  STR_BB_DRIED_SPOOLMAN,
  STR_BB_DRIED_SPOOLMAN_SUB,
  STR_BB_DRIED_SPOOLMAN_NA,
  STR_BB_DRIED_NOTE,
  STR_BB_DRIED_NOTE_SUB,
  STR_BB_DRIED_INFO,
  STR_BB_INV_OWN,
  STR_BB_INV_SPOOLMAN,
  STR_BACKEND_INVENTORY,

  // Factory Reset
  STR_BTN_FACTORY_RESET,
  STR_BTN_FACTORY_RESET_SUB,
  STR_FACTORY_RESET_TITLE,
  STR_FACTORY_RESET_MSG,
  STR_FACTORY_RESET_CONFIRM,

  // Copy spool flow
  STR_BTN_COPY_SPOOL,
  STR_COPY_TITLE,
  STR_COPY_ID_BTN,
  STR_COPY_ACTIVE_BTN,
  STR_COPY_ARCHIVED_BTN,
  STR_COPY_CONFIRM_TITLE,
  STR_COPY_CONFIRM_MSG,
  STR_COPY_OK,
  STR_COPY_FAIL,
  STR_COPY_NO_SPOOLS,
  STR_COPY_LIMIT_HIT,

  // First boot skip button
  STR_BTN_SKIP_SETUP,

  // Unlink spool
  STR_UNLINK_BTN,
  STR_UNLINK_TITLE,
  STR_UNLINK_MSG,
  STR_UNLINK_CONFIRM,

  // Scale boot status
  STR_SCALE_CALIBRATING,
  STR_WIFI_CONNECTING_BOOT,
  STR_BOOTING,

  // Reboot button in system screen
  STR_BTN_REBOOT,
  STR_BTN_REBOOT_SUB,

  // Whole gram toggle
  STR_WHOLE_GRAM,

  // List limit info items
  STR_LIST_MORE_SPOOLS,
  STR_LIST_MORE_VENDORS,
  STR_LIST_MORE_MATS,

  // Auto-Weight
  STR_AUTO_WEIGHT_TITLE,
  STR_AUTO_WEIGHT_INFO,
  STR_AUTO_WEIGHT_ENABLE,
  STR_AUTO_WEIGHT_DISABLE,

  // Location
  STR_BTN_LOCATION,
  STR_LOCATION_TITLE,
  STR_LOCATION_NONE,
  STR_LOCATION_LOADING,
  STR_LOCATION_NO_WIFI,
  STR_LOCATION_SAVED,
  STR_LOCATION_FAIL,
  STR_LOCATION_NO_LOCATIONS,
  STR_LOCATION_HINT_EMPTY,
  STR_LOCATION_LIMIT_HIT,

  // No spools hint (link flow)
  STR_NO_SPOOLS_HINT,

  // Auto location popup toggle
  STR_BTN_AUTO_LOC_POPUP,
  STR_BTN_AUTO_LOC_POPUP_SUB,
  STR_AUTO_LOC_POPUP_TITLE,
  STR_AUTO_LOC_POPUP_MSG,

  // Drying reminder
  STR_BTN_DRYING_REMINDER,
  STR_BTN_DRYING_REMINDER_SUB,
  STR_DRYING_REMINDER_TITLE,
  STR_DRYING_REMINDER_COMING_SOON,

  // Drying Reminder Screen
  STR_DRY_MODE_OFF,
  STR_DRY_MODE_MATERIAL,
  STR_DRY_MODE_MANUAL,
  STR_DRY_OFF_DESC,
  STR_DRY_MAT_HINT,
  STR_DRY_MAT_HDR_MAT,
  STR_DRY_MAT_HDR_YELLOW,
  STR_DRY_MAT_HDR_RED,
  STR_DRY_MAT_HDR_MULT,
  STR_DRY_MAT_FOOTNOTE,
  STR_DRY_MAN_YELLOW_LBL,
  STR_DRY_MAN_RED_LBL,
  STR_DRY_MAN_EDIT_HINT,
  STR_DRY_MAN_INFO,
  STR_DRY_DAYS_UNIT,
  STR_DRY_NUMPAD_YELLOW_TITLE,
  STR_DRY_NUMPAD_RED_TITLE,
  STR_DRY_MAT_EFF_NOTE,
  STR_DRY_SEALED_HDR,

  // Backend selection (Spoolman / FilaMan)
  STR_BACKEND_TITLE,
  STR_BACKEND_TILE_SUB,
  STR_BACKEND_ADDRESS,
  STR_BACKEND_APIKEY,
  STR_BACKEND_DEVICE_TOKEN,
  STR_BACKEND_SET,
  STR_BACKEND_MISSING,

  // Web interface, shared by the firmware upload and the credential entry
  STR_WEB_TITLE,
  STR_WEB_SETUP_HINT,
  STR_WEB_SETUP_HINT_BB,
  STR_BTN_WEB_SETUP,
  STR_BTN_FINISH,
  STR_BTN_NEXT,
  STR_SETUP_BACKEND_HINT,
  STR_CONNECTED,
  STR_ON,
  STR_OFF,
  STR_BTN_OPEN_BROWSER,
  STR_NOT_AFFILIATED,
  STR_LINK_NO_TAG,

  // Main screen weight box and More-info detail grid. These were inline
  // g_lang ternaries until they moved into the table.
  STR_LBL_SCALE_SPOOL_CAP,
  STR_LBL_TOTAL_CAP,
  STR_LBL_WO_BAG_CAP,
  STR_LBL_HEX_COLOR,
  STR_LBL_PRODUCTION_DATE,
  STR_LBL_ARTICLE_NO_SHORT,
  STR_LBL_SPOOL_WEIGHT_EMPTY,

  // Status bar address selector on the WiFi status screen. The third state
  // labels itself with backendName() and needs no entry of its own.
  STR_BTN_IP_STATUSBAR,
  STR_IP_BAR_DEVICE,

  // Remote link, triggered from the FilaMan web UI
  STR_REMOTE_LINK_TITLE,
  STR_REMOTE_LINK_QUESTION,
  STR_REMOTE_LINK_CONFIRM,
  STR_REMOTE_LINK_MISMATCH,
  STR_REMOTE_LINK_NO_DETAILS,
  STR_REMOTE_LINK_TIMEOUT,
  STR_SLEEP_OFF,

  // Tag versus spool comparison, shown in the remote link popup on a mismatch
  STR_REMOTE_LINK_COL_TAG,
  STR_REMOTE_LINK_COL_SPOOL,
  STR_REMOTE_LINK_ROW_MATERIAL,
  STR_REMOTE_LINK_ROW_COLOR,

  // FilaMan options sub screen
  STR_BTN_MORE_OPTIONS,
  // Snapmaker U1 / SpoolLink: writing to Spoolman's card_uids list
  STR_CU_WRITE,
  STR_CU_WRITE_SUB,
  STR_CU_WRITE_INFO,
  STR_CU_NOT_WRITTEN,
  STR_TAG_ON_OTHER_SPOOL,
  STR_WARN_A_ADD_TITLE,
  STR_WARN_A_ADD_INFO,
  STR_WARN_A_ADD_SHORT,
  STR_BTN_ADD_UID,
  STR_UNLINK_MULTI_MSG,
  STR_BTN_UNLINK_ONE,
  STR_BTN_UNLINK_ALL,
  STR_FLM_AUTOLINK,
  STR_FLM_AUTOLINK_SUB,

  STR_TARE_FROM_FILAMENT,
  STR_TARE_FROM_BRAND,
  STR_SPOOL_WEIGHT_BAG_HINT,
  STR_FLM_TAGLESS,
  STR_FLM_TAGLESS_SUB,
  STR_REMOTE_LINK_WEIGH,
  STR_WAKE_ON_LOAD,
  STR_SCREENOFF_LABEL,
  STR_SCREENOFF_NEVER,
  STR_FLM_AUTOLINK_INFO,
  STR_FLM_TAGLESS_INFO,
  STR_BTN_THIS_SPOOL_FM,
  STR_BTN_THIS_FILAMENT_FM,
  STR_BTN_THIS_VENDOR_FM,
  STR_BTN_ARCHIVE_EMPTY_FM,
  // Auto AMS assignment (FilaMan)
  STR_AMS_TITLE,
  STR_AMS_SUB,
  STR_AMS_INFO,
  STR_AMS_MODE_OFF,
  STR_AMS_MODE_ASK,
  STR_AMS_MODE_ALWAYS,
  STR_AMS_OFF_DESC,
  STR_AMS_ASK_DESC,
  STR_AMS_ALWAYS_DESC,
  STR_AMS_WINDOW_LBL,
  STR_AMS_WINDOW_HINT,
  STR_AMS_SEC_UNIT,
  STR_AMS_TIMER_LBL,
  STR_AMS_TIMER_HINT,
  STR_AMS_TIMER_YES,
  STR_AMS_TIMER_NO,
  STR_AMS_POPUP_Q,
  STR_AMS_POPUP_STARTS_IN,
  STR_AMS_POPUP_CLOSES_IN,
  STR_AMS_BTN_YES,
  STR_AMS_ERR_FORBIDDEN,
  STR_AMS_ERR_HTTP,
  STR_AMS_POPUP_SAVED,
  STR_AMS_WINDOW_RUNNING,
  STR_AMS_SRV_ON,
  STR_AMS_SRV_OFF,
  STR_AMS_POPUP_WILL_SAVE,

  // Creating a spool from the tag itself, when no template fits
  STR_NEWTAG_BTN,
  STR_NEWTAG_TITLE,
  STR_NEWTAG_MSG,
  STR_NEWTAG_LABEL_W,
  STR_NEWTAG_OK,
  STR_NEWTAG_FAIL,

  // Which Spoolman extra field holds the tag UID. Every project in the
  // ecosystem picked a different one, so the scale lets the user say.
  STR_TAG_FIELD,
  STR_TAG_FIELD_INFO,
  STR_TF_NATIVE,
  STR_TF_NATIVE_SUB,
  STR_TF_NATIVE_NA,
  STR_TF_NATIVE_INFO,
  STR_TF_TAG,
  STR_TF_TAG_SUB,
  STR_TF_TAG_INFO,
  STR_TF_NFCID,
  STR_TF_NFCID_SUB,
  STR_TF_NFCID_INFO,
  STR_TF_CARDUIDS,
  STR_TF_CARDUIDS_SUB,
  STR_TF_CARDUIDS_INFO,
  // The extra fields menu the choice lives in
  STR_EF_LAST_DRIED,
  STR_EF_LAST_DRIED_SUB,
  STR_EF_LAST_DRIED_INFO,
  STR_EF_PRESENT,
  STR_EF_MISSING,
  STR_EF_CREATE_ROW,
  // Shown while a list flow is loading the inventory, which blocks for
  // seconds on a large one.
  STR_LOADING_SPOOLS,
  STR_LOADING_FILTER,

  // Web interface. Prefixed STR_W_ so the block stays together and a web
  // string is recognisable at the call site.
  STR_W_NAV_STATUS,
  STR_W_NAV_BACKEND,
  STR_W_NAV_DRYING,
  STR_W_NAV_TAGS,
  STR_W_NAV_SETTINGS,
  STR_W_NAV_LOGS,
  STR_W_NAV_FIRMWARE,
  STR_W_DISCLAIMER,
  STR_W_SAVE,
  STR_W_SAVED,
  STR_W_ERROR,
  STR_W_DEFAULTS,
  STR_W_OFF_TITLE,
  STR_W_OFF_BODY,
  STR_W_OFF_WHERE,
  STR_W_OFF_PATH,
  STR_W_OFF_RELOAD,
  STR_W_BACK_STATUS,
  STR_W_C_NETWORK,
  STR_W_C_HARDWARE,
  STR_W_C_INVENTORY,
  STR_W_C_ACCESS,
  STR_W_C_DEVICE,
  STR_W_R_WIFI,
  STR_W_R_ADDRESS,
  STR_W_R_NAME,
  STR_W_R_GATEWAY,
  STR_W_R_SCALE,
  STR_W_R_NFC,
  STR_W_R_SD,
  STR_W_R_UPTIME,
  STR_W_R_BACKEND,
  STR_W_R_REACHABLE,
  STR_W_R_SCANS,
  STR_W_R_VERBOSE,
  STR_W_S_READY,
  STR_W_S_MISSING,
  STR_W_S_ON,
  STR_W_S_OFF,
  STR_W_S_YES,
  STR_W_S_NO,
  STR_W_S_NOWIFI,
  STR_W_ACCESS_NOTE,
  STR_W_RESTART,
  STR_W_RESTART_NOTE,
  STR_W_RESTART_ASK,
  STR_W_RESTARTING,
  STR_W_RESTART_WAIT,
  STR_W_RESTART_SD,
  STR_W_RESTART_LONG,
  STR_W_RESTART_GONE,
  STR_W_RELOAD,
  STR_W_C_BACKEND_ADDR,
  STR_W_HOST_LABEL,
  STR_W_HOST_HINT,
  STR_W_HOST_PORTHINT,
  STR_W_HOST_EMPTY,
  STR_W_HOST_HTTPS,
  STR_W_HOST_TESTING,
  STR_W_HOST_OK,
  STR_W_HOST_FAIL,
  STR_W_C_CREDS,
  STR_W_APIKEY,
  STR_W_DEVICE_CODE,
  STR_W_REGISTER,
  STR_W_SET,
  STR_W_UNSET,
  STR_W_NO_CREDS,
  STR_W_C_DRYING,
  STR_W_DRY_MATERIAL,
  STR_W_DRY_YELLOW,
  STR_W_DRY_RED,
  STR_W_DRY_STORAGE,
  STR_W_DRY_OPEN,
  STR_W_DRY_SEALED,
  STR_W_DRY_DAYS,
  STR_W_DRY_MULT,
  STR_W_DRY_MULT_HINT,
  STR_W_C_DEVNAME,
  STR_W_DEVNAME_HINT,
  STR_W_DEVNAME_BAD,
  STR_W_DEVNAME_NOW,
  STR_W_C_LIMITS,
  STR_W_LIMIT_SPOOLS,
  STR_W_LIMIT_LOCS,
  STR_W_LIMIT_HINT,
  STR_W_LIMIT_WARN,
  STR_W_C_DISPLAY,
  STR_W_GAIN,
  STR_W_GAIN_HINT,
  STR_W_C_WRITETAG,
  STR_W_TAG_SPOOL,
  STR_W_TAG_PICK,
  STR_W_TAG_FORMAT,
  STR_W_TAG_ONTAG,
  STR_W_TAG_WILLBE,
  STR_W_TAG_NOTAG,
  STR_W_TAG_ONREADER,
  STR_W_TAG_PICKFIRST,
  STR_W_TAG_BLANK,
  STR_W_TAG_UNKNOWN,
  STR_W_TAG_WRITE,
  STR_W_TAG_OVERWRITE,
  STR_W_TAG_MATCHES,
  STR_W_TAG_ERASE,
  STR_W_TAG_ERASE_ASK,
  STR_W_TAG_LINK,
  STR_W_TAG_RELINK,
  STR_W_TAG_QUEUED,
  STR_W_TAG_NOLIST,
  STR_W_TAG_SKU,
  STR_W_TAG_NOZZLE,
  STR_W_TAG_BED,
  STR_W_TAG_WEIGHT,
  STR_W_TAG_DIA,
  STR_W_TAG_LENGTH,
  STR_W_TAG_COMPARE,
  STR_W_C_LOGS,
  STR_W_LOG_VIEW,
  STR_W_LOG_DELETE,
  STR_W_LOG_DELETE_ASK,
  STR_W_LOG_NOSD,
  STR_W_LOG_NOSD_HINT,
  STR_W_LOG_EMPTY,
  STR_W_C_FIRMWARE,
  STR_W_FW_INSTALLED,
  STR_W_FW_FILE,
  STR_W_FW_FLASH,
  STR_W_FW_HINT,
  STR_W_FW_OK,
  STR_W_FW_RESTARTING,
  STR_W_FW_FAIL,
  STR_W_FW_RETRY,
  STR_W_C_FW_GITHUB,
  STR_W_FW_CHANNEL,
  STR_W_FW_CH_STABLE,
  STR_W_FW_CH_PRE,
  STR_W_FW_LATEST,
  STR_W_FW_CHECK,
  STR_W_FW_CHECKING,
  STR_W_FW_UPTODATE,
  STR_W_FW_AVAIL,
  STR_W_FW_INSTALL,
  STR_W_FW_INSTALLING,
  STR_W_FW_NOWIFI,
  STR_W_FW_BUSY,
  STR_W_FW_CHECK_FAIL,
  STR_W_FW_GH_HINT,
  STR_W_FW_RELEASED,
  STR_W_FW_SINCE,
  STR_W_FW_NOTES,
  STR_W_FW_WHATSNEW,
  STR_W_FW_UNPUBLISHED,
  STR_W_FW_UNKNOWN,
  STR_W_FW_HIDE,
  STR_W_FW_CONFIRM,
  STR_W_FW_REBOOTS,
  STR_W_FW_OLDER,
  STR_W_FW_DOWNGRADE,
  STR_W_FW_DOWNWARN,
  STR_W_R_WEIGHT,
  STR_W_LOAD_FAIL,
  STR_W_LOG_NOTE,
  STR_W_C_SESSION,
  STR_W_SESSION_NOTE,
  STR_W_SESSION_EMPTY,
  STR_W_SESSION_REFRESH,
  STR_W_SESSION_BUSY,
  STR_W_SESSION_UPDATED,
  STR_W_SESSION_LINES,
  STR_W_SESSION_PAUSED,
  STR_W_SESSION_NEW,
  STR_W_SESSION_COPY,
  STR_W_SESSION_COPIED,
  STR_W_SESSION_COPYFAIL,
  STR_W_TAG_NOTE,
  STR_W_TAG_SIZES,
  STR_W_FM_SETUP,
  STR_W_BB_SETUP,
  STR_OTA_KEEP_POWER,
  STR_W_KOFI,
  STR_SP_LOCKED_TITLE,
  STR_SP_LOCKED_INFO,
  STR_SP_WEB_OFF,
  STR_SP_CLEAR,
  STR_SP_CLEAR_ASK,
  STR_W_LOG_DELETE_ALL,
  STR_W_LOG_DELETE_ALL_ASK,
  STR_W_LOG_COUNT,
  STR_W_LOG_COUNT_ONE,
  STR_W_LOG_DELETE_ALL_ASK_ONE,
  STR_TZ_TITLE,
  STR_TZ_HINT,
  STR_W_TZ_NOTE,

  // FilaMan fields: what the scale writes, and what it leaves to the Bambu
  // Lab plugin
  STR_FLM_FIELDS,
  STR_FLM_FIELDS_SUB,
  STR_FLM_FIELDS_INFO,
  STR_FLM_TAGFIELD,
  STR_FLM_TAGFIELD_INFO,
  STR_FLM_BTAGS,
  STR_FLM_BTAGS_SUB,
  STR_FLM_BTAGS_INFO,
  STR_FLM_EXTID,
  STR_FLM_EXTID_SUB,
  STR_FLM_EXTID_INFO,
  STR_TAG_FOUND_DUP,

  // Device name: the whole name rather than a label with ".local" nailed on,
  // and what the network makes of it
  STR_W_R_MDNS,
  STR_W_DEVNAME_ALSO,
  STR_W_DEVNAME_DNS_WAIT,
  STR_W_DEVNAME_DNS_OK,
  STR_W_DEVNAME_DNS_OTHER,
  STR_W_DEVNAME_DNS_NONE,
  STR_W_MDNS,
  STR_W_MDNS_HINT,

  // Spool status (FilaMan). Six fixed ids on the server, no CRUD endpoint,
  // so the labels are static here. Id 6 reuses STR_ARCHIVED.
  STR_STATUS_TITLE,
  STR_STATUS_NEW,
  STR_STATUS_OPENED,
  STR_STATUS_DRYING,
  STR_STATUS_ACTIVE,
  STR_STATUS_EMPTY,
  STR_STATUS_UNKNOWN,

  // Writing a tag. The remote trigger offers the write next to the link, the
  // device asks after a link of its own, and the results come back as ids
  // because tag_write.cpp cannot include lang.h - T() collides with
  // ArduinoJson's template parameter.
  STR_REMOTE_LINK_WRITE,
  STR_REMOTE_LINK_Q_WRITE,
  STR_TW_ASK_TITLE,
  STR_TW_ASK_HINT,
  STR_TW_BTN_WRITE,
  STR_TW_BTN_SKIP,
  STR_TW_OK,
  STR_TW_ERR_NO_TAG,
  STR_TW_ERR_NOT_NTAG,
  STR_TW_ERR_BACKEND,
  STR_TW_ERR_SPACE,
  STR_TW_ERR_WRITE,
  STR_FLM_REMOTE_WRITE,
  STR_FLM_REMOTE_WRITE_SUB,
  STR_FLM_REMOTE_WRITE_INFO,
  STR_W_TAG_TOOSMALL,
  // Results of a write or an erase, shown as their own modal: the status line
  // is repainted by the NFC poll later in the same loop pass, so anything put
  // there is gone before it can be read.
  STR_TW_FAILED,
  STR_TW_OK_INFO,
  STR_TW_ERASE_ASK_TITLE,
  STR_TW_ERASE_ASK_HINT,
  STR_TW_BTN_ERASE,
  STR_TW_BTN_KEEP,
  STR_TW_ERASED,
  STR_TW_ERASED_INFO,
  STR_TW_ERASE_FAILED,
  STR_BTN_OK,

  // A device screen that points at a web page opens the switch that page
  // needs and says so. The web footer names the same menu on every page, so
  // the line on the device stays short enough for one row at font 12 - and
  // it spells the path with ">" rather than the entity the web strings use.
  STR_WEB_GATE_OPENED,
  STR_W_FOOT_GATE_OFF,
  STR_W_FOOT_GATE_ALL,

  // Replaces the archive button on a spool that is already archived. Carries
  // the weight in its subtitle, so the button says what it will write.
  STR_BTN_REACTIVATE,

  // The backend options, mirrored in the browser from the one registry.
  // Appended rather than grouped with the other web strings: the array in
  // lang.cpp is positional, so inserting in the middle moves every entry
  // after it - and this table gets appended to from two branches at once.
  STR_W_LOADING,
  STR_W_ON_DEVICE,
  STR_W_NO_OPTIONS,
  STR_W_C_BACKEND,
  STR_W_BACKEND_NOTE,
  STR_W_BACKEND_ASK,

  // Waking on load. Documented in user_options.h from the day it was written
  // and never switchable - loadPrefs() read it, display_power.cpp acted on it,
  // and nothing ever wrote it.
  STR_W_C_PANEL,
  STR_W_WAKE,
  STR_W_WAKE_HINT,

  // The scale saying what it actually knows. A calibration taken while the ADC
  // was off the bus stores a factor built from -1 samples, and until now the
  // only way back was erasing NVS.
  STR_BTN_CAL_RESET,
  STR_BTN_CAL_RESET_SUB,
  STR_CAL_RESET_CONFIRM,
  STR_CAL_RESET_DONE,
  STR_CAL_RANGE_ERR,
  STR_CAL_IMPLAUSIBLE,
  STR_W_R_I2C,
  STR_W_RESCAN,

  // Writing a tag after a link. Backend independent: what goes on a tag is an
  // agreement between the tag and whoever reads it, and no backend sees it.
  STR_TW_OPT_ASK,
  STR_TW_OPT_ASK_SUB,
  STR_TW_OPT_ASK_INFO,
  STR_TW_OPT_FMT,
  STR_TW_OPT_FMT_INFO,
  STR_TW_FMT_OPENSPOOL,
  STR_TW_FMT_FILAMAN,
  STR_TW_FMT_ACE,
  STR_W_C_TAGOPTS,
  STR_W_TAGOPT_ASK,
  STR_W_TAGOPT_FMT,
  STR_W_TAGOPT_NOTE,
  STR_W_LOG_DOWNLOAD,
  // Same in both languages: it labels a 68px button and "Kalibrierung
  // zuruecksetzen" does not fit on one.
  STR_BTN_CAL_RESET_SHORT,
  // Shown at the top of the link list when nothing matched the tag's material
  // and the filter was dropped to keep the list from being empty.
  STR_LIST_MAT_IGNORED,
  // The tag disagrees with the spool it is bound to. The hint carries one %s,
  // which is both sides of the comparison already laid out over two lines.
  STR_TW_OPT_MISM,
  STR_TW_OPT_MISM_SUB,
  STR_TW_OPT_MISM_INFO,
  STR_TW_MISM_TITLE,
  STR_TW_MISM_HINT,
  STR_TW_BTN_REWRITE,
  STR_TW_MISM_TAG,
  STR_TW_MISM_SERVER,
  STR_W_TAGOPT_MISM,
  // The tag page says in German what tag_write.cpp reports in English. That
  // file cannot reach lang.h - T() collides with ArduinoJson's template
  // parameter - so it hands out the parts and page_tags.cpp assembles them.
  STR_W_TW_WRITING,
  STR_W_TW_ERASING,
  STR_W_TW_WROTE,
  STR_W_TW_LINKED,
  STR_W_TW_LINKED_NOTE,
  STR_W_TW_LINK_FAIL,
  STR_W_TW_ERASED,
  STR_W_TW_ERASE_FAIL,
  STR_W_TAG_KIND_MIFARE,
  STR_W_TAG_KIND_NTAG,
  STR_W_TAG_KIND_BYTES,
  // What the unlink is about to clear, listed by name.
  STR_UNLINK_SOURCES,
  // Writing after a link: off, ask, or straight away.
  STR_TW_MODE_OFF,
  STR_TW_MODE_ASK,
  STR_TW_MODE_ALWAYS,

  // Hardware self diagnosis. One banner string, one title and one body per
  // finding - the banner has to fit a 480 px strip, the body explains the
  // cause and names the wire to look at.
  STR_DIAG_TAP,
  STR_DIAG_BTN_LATER,
  STR_DIAG_BTN_RECHECK,
  STR_DIAG_BUS_EMPTY_BANNER,
  STR_DIAG_BUS_EMPTY_TITLE,
  STR_DIAG_BUS_EMPTY_TEXT,
  STR_DIAG_NAU_MISSING_BANNER,
  STR_DIAG_NAU_MISSING_TITLE,
  STR_DIAG_NAU_MISSING_TEXT,
  STR_DIAG_PN532_MISSING_BANNER,
  STR_DIAG_PN532_MISSING_TITLE,
  STR_DIAG_PN532_MISSING_TEXT,
  STR_DIAG_PN532_MUTE_BANNER,
  STR_DIAG_PN532_MUTE_TITLE,
  STR_DIAG_PN532_MUTE_TEXT,
  STR_DIAG_UNCAL_BANNER,
  STR_DIAG_UNCAL_TITLE,
  STR_DIAG_UNCAL_TEXT,
  STR_DIAG_INVERTED_BANNER,
  STR_DIAG_INVERTED_TITLE,
  STR_DIAG_INVERTED_TEXT,
  STR_DIAG_NOISY_BANNER,
  STR_DIAG_NOISY_TITLE,
  STR_DIAG_NOISY_TEXT,
  // The full instruction behind the "?" on the calibration screen. The screen
  // itself has room for one line and a numpad, not for four steps.
  STR_CAL_HELP_TITLE,
  STR_CAL_HELP_TEXT,
  // The same finding on the status page in the browser.
  STR_W_R_DIAG,
  STR_W_S_DIAG_OK,

  STR_COUNT
};

// Deliberately without a bound: it comes from the initializer in lang.cpp, so
// the static_assert there can compare the two. Spelled [STR_COUNT][2] here,
// the definition inherits that bound, a short initializer is padded with
// nullptr, and nothing complains.
extern const char* const STRINGS[][2];

// Which string explains a TagWriteResult. Lives here rather than in either
// caller: the device popup and the tag page in the browser say the same thing
// about the same code, and two tables would have drifted apart.
StringID tagWriteResultString(uint8_t code);

// Macro: T(STR_XXX) -> returns the string in the current language
#define T(id) STRINGS[id][g_lang]
