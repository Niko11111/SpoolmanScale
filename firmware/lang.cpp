// ============================================================
//  SpoolmanScale – Localization (i18n)
//  lang.cpp — String table DE / EN
// ============================================================
#include <lvgl.h>
#include "lang.h"

Lang   g_lang     = LANG_EN;
uint8_t g_date_fmt = 0;  // 0=DD.MM.YYYY  1=YYYY-MM-DD

// Order MUST exactly match the StringID enum in lang.h!
// Format: { "Deutsch", "English" }
const char* const STRINGS[STR_COUNT][2] = {

  // Navigation
  { "Abbrechen",              "Cancel"           },  // STR_CANCEL
  { "Zurueck",                "Back"             },  // STR_BACK
  { "Speichern",              "Save"             },  // STR_SAVE
  { "Bestaetigen",            "Confirm"          },  // STR_CONFIRM
  { "Schliessen",             "Close"            },  // STR_CLOSE
  { "Erneut versuchen",       "Try again"        },  // STR_RETRY
  { "Trotzdem verknuepfen",   "Link anyway"      },  // STR_FORCE_LINK
  { "ID neu eingeben",        "Enter new ID"     },  // STR_ENTER_NEW_ID

  // Mainscreen Labels
  { "UID:",                   "UID:"             },  // STR_LBL_UID
  { "Spoolman UUID:",         "Spoolman UUID:"   },  // STR_LBL_UUID
  { "Material:",              "Material:"        },  // STR_LBL_MATERIAL
  { "Spoolman:",              "Spoolman:"        },  // STR_LBL_SPOOLMAN
  { "Waage:",                 "Scale:"           },  // STR_LBL_SCALE
  { "Letzte Benutzung:",      "Last used:"       },  // STR_LBL_LAST_USED
  { "Letzte Trocknung:",      "Last dried:"      },  // STR_LBL_LAST_DRIED
  { "Temperatur:",            "Temperature:"     },  // STR_LBL_TEMP
  { "Hersteller:",            "Vendor:"          },  // STR_LBL_VENDOR
  { "Artikelnummer:",         "Article no.:"     },  // STR_LBL_ARTICLE
  { "Produktion:",            "Production:"      },  // STR_LBL_PRODUCTION
  { "Spoolman ID:",           "Spoolman ID:"     },  // STR_LBL_SPOOLMAN_ID

  // Mainscreen Status
  { "Spule an Reader halten...", "Hold spool near reader..." },  // STR_WAIT_SCAN
  { "NFC Tag erkannt",        "NFC tag detected"           },  // STR_TAG_FOUND
  { "Kein WiFi",              "No WiFi"                    },  // STR_NO_WIFI
  { "Warte...",               "Please wait..."             },  // STR_WAIT
  { "Warte auf Scan...",      "Waiting for scan..."        },  // STR_WAIT_SCAN_SM
  { "unbekannt",              "unknown"                    },  // STR_UNKNOWN
  { "nicht lesbar",           "not readable"               },  // STR_NOT_READABLE
  { "heute",                  "today"                      },  // STR_TODAY
  { "gestern",                "yesterday"                  },  // STR_YESTERDAY
  { "vor %d Tagen",           "%d days ago"                },  // STR_DAYS_AGO
  { "Fehler beim Speichern",  "Error saving"               },  // STR_ERR_SAVE
  { "Nicht in Spoolman",      "Not in Spoolman"            },  // STR_NOT_IN_SPOOLMAN
  { "Archiviert",             "Archived"                   },  // STR_ARCHIVED
  { "Lese Tag...",            "Reading tag..."             },  // STR_READING_TAG

  // Mainscreen Buttons
  { "Gewicht updaten",        "Update Weight"     },  // STR_BTN_WEIGHT
  { "Heute getrocknet",       "Dried today"       },  // STR_BTN_DRIED
  { "Verknuepfen",            "Link"              },  // STR_BTN_LINK

  // Welcome Screen
  { "Willkommen! Bitte WiFi einrichten.",
    "Welcome! Please set up WiFi."              },  // STR_WELCOME_SUB
  { "Verbinde mit WiFi und gib die\nSpoolman-Server-IP ein.",
    "Connect to WiFi and enter\nyour Spoolman server IP." },  // STR_WELCOME_HINT
  { "Jetzt einrichten",       "Set up now"        },  // STR_BTN_SETUP_NOW

  // WiFi Setup
  { "WiFi einrichten",        "WiFi Setup"        },  // STR_WIFI_TITLE
  { "Netzwerke suchen...",    "Scanning networks..." },  // STR_WIFI_SCAN
  { "Netzwerk auswaehlen:",   "Select network:"   },  // STR_WIFI_SELECT
  { "Erneut suchen",          "Scan again"        },  // STR_WIFI_RESCAN
  { "Keine Netzwerke gefunden", "No networks found" },  // STR_WIFI_NO_NET
  { "WiFi Passwort",          "WiFi Password"     },  // STR_WIFI_PASS_TITLE
  { "Passwort fuer: %s",      "Password for: %s"  },  // STR_WIFI_PASS_HINT
  { "Verbinde mit %s...",     "Connecting to %s..." },  // STR_WIFI_CONNECTING
  { "Verbunden!",             "Connected!"        },  // STR_WIFI_SUCCESS
  { "Verbindung fehlgeschlagen", "Connection failed" },  // STR_WIFI_FAIL
  { "Verbinden",              "Connect"           },  // STR_BTN_CONNECT

  // Spoolman IP
  { "Spoolman Server",        "Spoolman Server"   },  // STR_SPOOLMAN_TITLE
  { "IP:Port  (z.B. 192.168.x.x:7912)",
    "IP:Port  (e.g. 192.168.x.x:7912)"          },  // STR_SPOOLMAN_HINT

  // Settings
  { "Einstellungen",          "Settings"          },  // STR_SETTINGS_TITLE
  { "Verbindung",             "Connection"        },  // STR_TILE_CONNECTION
  { "WiFi & Spoolman",        "WiFi & Spoolman"   },  // STR_TILE_CONN_SUB
  { "Waage",                  "Scale"             },  // STR_TILE_SCALE
  { "Kalibrierung & Tare",    "Calibration & Tare" },  // STR_TILE_SCALE_SUB
  { "Display",                "Display"           },  // STR_TILE_DISPLAY
  { "Helligkeit & Timeout",   "Brightness & Timeout" },  // STR_TILE_DISPLAY_SUB
  { "System",                 "System"            },  // STR_TILE_SYSTEM
  { "Sprache | Update | Info","Language | Update | Info" },  // STR_TILE_SYSTEM_SUB
  { "TARE  -  Waage auf Null setzen", "TARE  -  Zero the scale" },  // STR_BTN_TARE

  // Connection
  { "Verbindung",             "Connection"        },  // STR_CONN_TITLE
  { "WiFi Einstellungen",     "WiFi Settings"     },  // STR_BTN_WIFI_SETTINGS
  { "Nicht konfiguriert",     "Not configured"    },  // STR_BTN_WIFI_NONE
  { "Spoolman Server",        "Spoolman Server"   },  // STR_BTN_SPOOLMAN

  // Scale
  { "Waage",                  "Scale"             },  // STR_SCALE_TITLE
  { "Kalibrierung",           "Calibration"       },  // STR_BTN_CALIBRATE
  { "Faktor: %.4f",           "Factor: %.4f"      },  // STR_BTN_CAL_SUB
  { "Beutelgewicht",          "Bag weight"        },  // STR_BTN_BAGWEIGHT
  { "Aktuell: %.1fg",         "Current: %.1fg"    },  // STR_BTN_BAG_SUB

  // Calibration
  { "Kalibrierung",           "Calibration"       },  // STR_CAL_TITLE
  { "Bekanntes Gewicht auflegen, Gramm eingeben, berechnen.",
    "Place known weight, enter grams, calculate." },  // STR_CAL_DESC
  { "Faktor: --",             "Factor: --"        },  // STR_CAL_FACTOR
  { "Faktor: %.4f",           "Factor: %.4f"      },  // STR_CAL_OK
  { LV_SYMBOL_WARNING "  Waage nicht bereit",
    LV_SYMBOL_WARNING "  Scale not ready"         },  // STR_CAL_SCALE_NOT_READY
  { "Fehler: Gewicht = 0",    "Error: weight = 0" },  // STR_CAL_ZERO_ERR
  { LV_SYMBOL_OK "  Berechnen", LV_SYMBOL_OK "  Calculate" },  // STR_BTN_CALCULATE

  // Bag weight
  { "Beutelgewicht",          "Bag weight"        },  // STR_BAG_TITLE
  { "Vakuumbeutel inkl. Silikagelpack (in Gramm)",
    "Vacuum bag incl. silica gel pack (in grams)" },  // STR_BAG_DESC
  { "%.1fg gespeichert",      "%.1fg saved"       },  // STR_BAG_SAVED
  { "Ungueltiger Wert",       "Invalid value"     },  // STR_BAG_INVALID

  // Display
  { "Display",                "Display"           },  // STR_DISPLAY_TITLE
  { LV_SYMBOL_IMAGE "  Helligkeit",
    LV_SYMBOL_IMAGE "  Brightness"               },  // STR_BRIGHT_LABEL
  { LV_SYMBOL_MINUS "  Dimmen nach (Min.)",
    LV_SYMBOL_MINUS "  Dim after (min.)"         },  // STR_DIM_LABEL
  { LV_SYMBOL_POWER "  Sleep nach (Min.)",
    LV_SYMBOL_POWER "  Sleep after (min.)"       },  // STR_SLEEP_LABEL
  { "Werte werden sofort gespeichert.",
    "Values are saved immediately."              },  // STR_DISPLAY_HINT

  // System
  { "System",                 "System"            },  // STR_SYSTEM_TITLE
  { "Sprache / Language",     "Sprache / Language" },  // STR_BTN_LANGUAGE
  { "Deutsch / English",      "Deutsch / English"  },  // STR_BTN_LANG_SUB
  { "Firmware Update",        "Firmware Update"    },  // STR_BTN_FW_UPDATE
  { "Browser oder GitHub",    "Browser or GitHub"  },  // STR_BTN_FW_SUB
  { "Info & Unterstutzung",   "Info & Support"     },  // STR_BTN_INFO
  { "Ko-fi - GitHub - Discord - MakerWorld", "Ko-fi - GitHub - Discord - MakerWorld" },  // STR_BTN_INFO_SUB

  // Language screen
  { "Sprache / Language",     "Sprache / Language" },  // STR_LANG_TITLE
  { "Geraet startet nach Auswahl neu.",
    "Device will reboot after selection." },  // STR_LANG_HINT
  { "coming soon",            "coming soon"        },  // STR_LANG_EN_SUB
  { "Datum / Date format:",   "Datum / Date format:" },  // STR_DATE_FMT_LABEL

  // OTA
  { "Firmware Update",        "Firmware Update"    },  // STR_OTA_TITLE
  { "Upload via Webbrowser",  "Upload via web browser" },  // STR_OTA_BROWSER
  { ".bin Datei vom PC hochladen", "Upload .bin file from PC" },  // STR_OTA_BROWSER_SUB
  { "Update via GitHub",      "Update via GitHub"  },  // STR_OTA_GITHUB
  { "Direkt-Update aus GitHub Releases", "Direct update from GitHub Releases" },  // STR_OTA_GITHUB_SUB
  { "Browser Update",         "Browser Update"     },  // STR_OTA_BROWSER_TITLE
  { LV_SYMBOL_WARNING "  Kein WiFi\nBitte zuerst WiFi einrichten.",
    LV_SYMBOL_WARNING "  No WiFi\nPlease set up WiFi first." },  // STR_OTA_NO_WIFI
  { "Browser oeffnen und aufrufen:",
    "Open browser and go to:"                   },  // STR_OTA_OPEN_BROWSER
  { "Datei auswaehlen: SpoolmanScale vX.Y.Z.bin",
    "Select file: SpoolmanScale vX.Y.Z.bin" },  // STR_OTA_FILE_HINT
  { LV_SYMBOL_WIFI "  Warte auf Upload...",
    LV_SYMBOL_WIFI "  Waiting for upload..."    },  // STR_OTA_WAITING
  { LV_SYMBOL_DOWNLOAD "  Lade hoch...",
    LV_SYMBOL_DOWNLOAD "  Uploading..."         },  // STR_OTA_UPLOADING
  { LV_SYMBOL_OK "  Update OK! Starte neu...",
    LV_SYMBOL_OK "  Update OK! Restarting..."   },  // STR_OTA_SUCCESS
  { LV_SYMBOL_WARNING "  Update fehlgeschlagen",
    LV_SYMBOL_WARNING "  Update failed"         },  // STR_OTA_FAIL
  { LV_SYMBOL_CLOSE "  Server stoppen",
    LV_SYMBOL_CLOSE "  Stop server"             },  // STR_BTN_STOP_SERVER
  { "Aktuell: %s",            "Current: %s"        },  // STR_OTA_CURRENT

  // Info Screen
  { "Info & Unterstutzung",   "Info & Support"     },  // STR_INFO_TITLE
  { "SpoolmanScale  %s",      "SpoolmanScale  %s"  },  // STR_INFO_VERSION
  { "Tippe einen Button um den QR-Code anzuzeigen.",
    "Tap a button to show the QR code."         },  // STR_INFO_HINT

  // QR Popups
  { "Projekt gefaellt dir? Kauf mir einen Kaffee!",
    "Support this project!"                     },  // STR_QR_KOFI_DESC
  { "Quellcode, Releases & Dokumentation",
    "Source code, releases & docs"              },  // STR_QR_GITHUB_DESC
  { "Community, Fragen & Support",
    "Community, questions & support"            },  // STR_QR_DISCORD_DESC
  { "3D-Modelle & Designs auf MakerWorld",
    "3D models & designs on MakerWorld"         },  // STR_QR_MAKER_DESC

  // Weight popup
  { "Heute getrocknet\nspeichern?",  "Save dried\ntoday?"    },  // STR_POPUP_DRIED_Q
  { "Gewicht in\nSpoolman updaten?", "Update weight\nin Spoolman?" },  // STR_POPUP_WEIGHT_Q
  { "Ohne Beutel\n%.0fg",            "No bag\n%.0fg"          },  // STR_BTN_NO_BAG
  { "Mit Beutel\n%.0fg - %.0fg",     "With bag\n%.0fg - %.0fg" },  // STR_BTN_WITH_BAG
  { "Neue Spule\n%.0fg netto",        "New spool\n%.0fg net"   },  // STR_BTN_NEW_SPOOL
  { "Leere Spule\n(Kern messen)",     "Empty spool\n(measure core)" },  // STR_BTN_EMPTY_SPOOL
  { "Spule archivieren\n(leer, 0g)", "Archive spool\n(empty, 0g)" },  // STR_BTN_ARCHIVE
  { "Ja, bestaetigen",               "Yes, confirm"           },  // STR_BTN_CONFIRMED

  // Spool weight sub-popup
  { "Spulengewicht: %.0f g speichern als...",
    "Save spool weight: %.0f g as..."           },  // STR_SPOOL_WEIGHT_TITLE
  { "Diese Spule\n(spool_weight)",   "This spool\n(spool_weight)"     },  // STR_BTN_THIS_SPOOL
  { "Dieses Filament\n(spool_weight)", "This filament\n(spool_weight)" },  // STR_BTN_THIS_FILAMENT
  { "Hersteller\n(empty_spool_weight)", "Vendor\n(empty_spool_weight)" },  // STR_BTN_THIS_VENDOR

  // Link Flow
  { "Bambu-Spule verknuepfen",  "Link Bambu spool"   },  // STR_LINK_BAMBU_TITLE
  { "Unbekannte Spule",         "Unknown spool"       },  // STR_LINK_NTAG_TITLE
  { "%s | nicht in Spoolman",   "%s | not in Spoolman" },  // STR_LINK_NOT_IN_SM
  { "Spool-ID eingeben",        "Enter Spool-ID"      },  // STR_BTN_ENTER_ID
  { "Aus Liste waehlen",        "Choose from list"    },  // STR_BTN_FROM_LIST
  { "Spoolman Spool-ID",        "Spoolman Spool-ID"   },  // STR_LINK_ID_TITLE
  { "Pruefe...",                "Checking..."         },  // STR_LINK_CHECKING
  { "ID nicht gefunden",        "ID not found"        },  // STR_LINK_ID_NOT_FOUND
  { "HTTP Fehler %d",           "HTTP Error %d"       },  // STR_LINK_HTTP_ERR
  { "JSON Fehler",              "JSON error"          },  // STR_LINK_JSON_ERR
  { "Kein WiFi",                "No WiFi"             },  // STR_LINK_NO_WIFI
  { LV_SYMBOL_WARNING "  Spule bereits verknuepft",
    LV_SYMBOL_WARNING "  Tag already assigned!"  },  // STR_WARN_A_TITLE
  { "Spule #%d hat bereits\nein Tag: %s",
    "Spool #%d already has\na tag: %s"          },  // STR_WARN_A_INFO
  { LV_SYMBOL_WARNING "  Trotzdem verknuepfen",
    LV_SYMBOL_WARNING "  Link anyway"           },  // STR_BTN_OVERWRITE
  { "Material stimmt nicht ueberein", "Material mismatch" },  // STR_WARN_B_TITLE
  { "Tag:      %s\nSpoolman: %s  (#%d)\n\nFalsche ID? Bitte nochmal pruefen.",
    "Tag:      %s\nSpoolman: %s  (#%d)\n\nWrong ID? Please double-check." },  // STR_WARN_B_DETAILS
  { "Hersteller waehlen  (%d Spulen)", "Choose vendor  (%d spools)" },  // STR_VENDOR_TITLE
  { "Material waehlen",         "Choose material"     },  // STR_MAT_TITLE
  { "Spule auswaehlen  (%d)",   "Select spool  (%d)"  },  // STR_SPOOLS_TITLE
  { "Keine Spulen ohne Tag\nin Spoolman gefunden.",
    "No unlinked spools\nfound in Spoolman."    },  // STR_NO_VENDORS
  { "Keine Materialien gefunden.", "No materials found." },  // STR_NO_MATERIALS
  { "Keine passenden Spulen.",  "No matching spools." },  // STR_NO_SPOOLS
  { "Verknuepfen?",             "Link this spool?"    },  // STR_CONFIRM_LINK
  { LV_SYMBOL_OK "  Verknuepft!", LV_SYMBOL_OK "  Linked!" },  // STR_LINK_OK
  { "Fehler beim Verknuepfen",  "Error linking"       },  // STR_LINK_FAIL

  // Tare
  { "Tare / Nullpunkt",        "Tare / Zero point"   },  // STR_TARE_TITLE
  { "Waage leeren und\nTare-Button druecken.",
    "Empty the scale and\npress the TARE button." },  // STR_TARE_DESC
  { LV_SYMBOL_OK "  Tare gesetzt!", LV_SYMBOL_OK "  Tare set!" },  // STR_TARE_OK
  { LV_SYMBOL_WARNING "  Waage nicht bereit",
    LV_SYMBOL_WARNING "  Scale not ready"       },  // STR_TARE_NOT_READY
  { "API Fehler",               "API Error"          },  // STR_API_ERROR

  // Reboot popup
  { "Neustart erforderlich",    "Restart required"   },  // STR_REBOOT_TITLE
  { "Einstellung wird nach\ndem Neustart aktiv.",
    "Setting takes effect\nafter restart."           },  // STR_REBOOT_MSG
  { LV_SYMBOL_REFRESH "  Jetzt neu starten",
    LV_SYMBOL_REFRESH "  Restart now"               },  // STR_REBOOT_BTN

  // WiFi connecting result
  { LV_SYMBOL_OK "  Verbunden!\nIP: %s",
    LV_SYMBOL_OK "  Connected!\nIP: %s"             },  // STR_WIFI_CONNECTED_IP
  { LV_SYMBOL_WARNING "  Verbindung fehlgeschlagen.\nSSID: %s",
    LV_SYMBOL_WARNING "  Connection failed.\nSSID: %s" },  // STR_WIFI_CONN_FAILED

  // WiFi quality
  { "Ausgezeichnet",            "Excellent"          },  // STR_WIFI_QUAL_EXCELLENT
  { "Gut",                      "Good"               },  // STR_WIFI_QUAL_GOOD
  { "Mittel",                   "Medium"             },  // STR_WIFI_QUAL_MEDIUM
  { "Schwach",                  "Weak"               },  // STR_WIFI_QUAL_WEAK
  { "Verbunden",                "Connected"          },  // STR_WIFI_STATUS_CONNECTED
  { "Getrennt",                 "Disconnected"       },  // STR_WIFI_STATUS_DISCONNECTED

  // Numpad buttons
  { LV_SYMBOL_OK "  Speichern", LV_SYMBOL_OK "  Save"       },  // STR_BTN_SAVE

  // Spool list title
  { "Bambu",                    "Bambu"              },  // STR_SPOOLS_BAMBU
  { "Alle",                     "All"                },  // STR_SPOOLS_ALL

  // Settings calibration sub
  { "Faktor: %.2f",             "Factor: %.2f"       },  // STR_CAL_FACTOR_SHORT

  // Archive confirm
  { "Spule wirklich\narchivieren?", "Really archive\nthis spool?" },  // STR_ARCHIVE_CONFIRM

  // Weight popup archive button
  { LV_SYMBOL_CLOSE " leer / Archivieren\nremaining=0",
    LV_SYMBOL_CLOSE " empty / Archive\nremaining=0" },  // STR_BTN_ARCHIVE_EMPTY

  // Welcome language select screen
  { "Sprache waehlen",          "Choose language"    },  // STR_WELCOME_LANG_TITLE
  { "Sprache kann spaeter\nim Settings geaendert werden.",
    "Language can be changed\nlater in Settings."   },  // STR_WELCOME_LANG_HINT

  // WiFi scan count
  { "%d Netzwerke gefunden",    "%d networks found"  },  // STR_WIFI_NETWORKS_FOUND

  // Bag weight current label
  { "Aktuell: %.0f g",          "Current: %.0f g"    },  // STR_BAG_CURRENT

  // Warn popup A fields
  { "Spule #%d  |  %s %s\nAkt. Tag: %s",
    "Spool #%d  |  %s %s\nCur. tag: %s"            },  // STR_WARN_A_SPOOL_INFO
  { "Spule #%d\nAkt. Tag: %s",
    "Spool #%d\nCur. tag: %s"                       },  // STR_WARN_A_SPOOL_SHORT

  // Link entry context
  { "%s | nicht in Spoolman",   "%s | not in Spoolman" },  // STR_LINK_CTX_NOT_IN_SM

  // Weight popup buttons (with snprintf)
  { LV_SYMBOL_OK " Ohne Beutel\n%.0fg",
    LV_SYMBOL_OK " No bag\n%.0fg"                   },  // STR_BTN_NO_BAG_VAL
  { LV_SYMBOL_OK " Mit Beutel\n%.0fg - %.0fg",
    LV_SYMBOL_OK " With bag\n%.0fg - %.0fg"         },  // STR_BTN_WITH_BAG_VAL
  { LV_SYMBOL_PLUS " Neue Spule\n%.0fg netto",
    LV_SYMBOL_PLUS " New spool\n%.0fg net"          },  // STR_BTN_NEW_SPOOL_VAL
  { LV_SYMBOL_REFRESH " TARE\nZero scale",
    LV_SYMBOL_REFRESH " TARE\nZero scale"           },  // STR_BTN_TARE_ZERO

  // First boot welcome screen
  { "Willkommen!",
    "Welcome!"                                    },  // STR_FIRSTBOOT_TITLE
  { "Dein SpoolmanScale ist bereit.",
    "Your SpoolmanScale is ready."                },  // STR_FIRSTBOOT_SUB
  { "In wenigen Schritten richten wir\nWiFi, Spoolman und die Waage ein.",
    "In a few steps we will set up\nWiFi, Spoolman and the scale."  },  // STR_FIRSTBOOT_HINT
  { LV_SYMBOL_RIGHT "  Los geht's",
    LV_SYMBOL_RIGHT "  Get started"               },  // STR_FIRSTBOOT_BTN

  // Extra fields screen
  { "Spoolman Extra-Felder",
    "Spoolman Extra Fields"                       },  // STR_EXTRA_FIELDS_TITLE
  { LV_SYMBOL_REFRESH "  Felder pruefen",
    LV_SYMBOL_REFRESH "  Check fields"            },  // STR_EXTRA_FIELDS_CHECK_BTN
  { "Pruefen...",
    "Checking..."                                 },  // STR_EXTRA_FIELDS_CHECKING
  { LV_SYMBOL_OK "  Alle Felder vorhanden - alles OK!",
    LV_SYMBOL_OK "  All fields present - all OK!" },  // STR_EXTRA_FIELDS_ALL_OK
  { LV_SYMBOL_WARNING "  Fehlende Felder: %s",
    LV_SYMBOL_WARNING "  Missing fields: %s"      },  // STR_EXTRA_FIELDS_MISSING
  { LV_SYMBOL_PLUS "  Fehlende Felder anlegen",
    LV_SYMBOL_PLUS "  Create missing fields"      },  // STR_EXTRA_FIELDS_CREATE_BTN
  { "Felder anlegen?",
    "Create fields?"                              },  // STR_EXTRA_FIELDS_CONFIRM_TITLE
  { "SpoolmanScale legt die fehlenden\nExtra-Felder in Spoolman an.\n\nFortfahren?",
    "SpoolmanScale will create the\nmissing extra fields in Spoolman.\n\nProceed?" },  // STR_EXTRA_FIELDS_CONFIRM_MSG
  { "Lege Felder an...",
    "Creating fields..."                          },  // STR_EXTRA_FIELDS_CREATING
  { LV_SYMBOL_OK "  Felder erfolgreich angelegt!",
    LV_SYMBOL_OK "  Fields created successfully!" },  // STR_EXTRA_FIELDS_CREATED_OK
  { LV_SYMBOL_WARNING "  Fehler beim Anlegen: %s",
    LV_SYMBOL_WARNING "  Error creating: %s"      },  // STR_EXTRA_FIELDS_CREATE_FAIL
  { LV_SYMBOL_WARNING "  Kein WiFi",
    LV_SYMBOL_WARNING "  No WiFi"                 },  // STR_EXTRA_FIELDS_NO_WIFI
  { LV_SYMBOL_WARNING "  Kein Spoolman konfiguriert",
    LV_SYMBOL_WARNING "  No Spoolman configured"  },  // STR_EXTRA_FIELDS_NO_SPOOLMAN
  { "Ueberspringen",
    "Skip"                                        },  // STR_EXTRA_FIELDS_SKIP
  { "SpoolmanScale benoetigt die Extra-Felder\n'tag' und 'last_dried' in Spoolman\num alle Funktionen zu nutzen.",
    "SpoolmanScale needs the extra fields\n'tag' and 'last_dried' in Spoolman\nto use all features."  },  // STR_EXTRA_FIELDS_HINT

  // Calibration reminder screen
  { "Waage kalibrieren",
    "Calibrate scale"                             },  // STR_CAL_REMINDER_TITLE
  { "Fuer genaue Messungen muss die Waage\nkalibriert werden.\n\nLege ein bekanntes Gewicht auf\nund gehe zu Einstellungen > Waage\n> Kalibrierung.\n\nDies kann auch spaeter gemacht werden.",
    "For accurate measurements the scale\nneeds to be calibrated.\n\nPlace a known weight on the scale\nand go to Settings > Scale > Calibration.\n\nYou can also do this later."  },  // STR_CAL_REMINDER_MSG
  { "Verstanden",
    "Got it!"                                     },  // STR_CAL_REMINDER_LATER
  { LV_SYMBOL_EDIT "  Jetzt kalibrieren",
    LV_SYMBOL_EDIT "  Calibrate now"              },  // STR_CAL_REMINDER_NOW

  // Calibration TARE hint
  { "Zuerst ohne Gewicht TARE druecken!\nDann Gewicht auflegen und berechnen.",
    "First press TARE without weight!\nThen place weight and calculate."  },  // STR_CAL_TARE_HINT

  // Extra fields test button
  { LV_SYMBOL_EDIT "  Testfeld erstellen",
    LV_SYMBOL_EDIT "  Generate test field"                               },  // STR_EF_TEST_BTN
  { LV_SYMBOL_OK "  'spoolscale_test' erstellt!\nIn Spoolman nach dem Test loeschen.",
    LV_SYMBOL_OK "  'spoolscale_test' created!\nDelete it in Spoolman after testing." },  // STR_EF_TEST_CREATED
  { LV_SYMBOL_WARNING "  Feld existiert bereits in Spoolman.",
    LV_SYMBOL_WARNING "  Field already exists in Spoolman."              },  // STR_EF_TEST_EXISTS
  { LV_SYMBOL_WARNING "  Testfeld konnte nicht erstellt werden.",
    LV_SYMBOL_WARNING "  Test field creation failed."                    },  // STR_EF_TEST_FAIL

  // Spoolman IP validation
  { "Verbindung wird geprueft...",
    "Testing connection..."                                               },  // STR_SPOOLMAN_TESTING
  { LV_SYMBOL_OK "  Spoolman erreichbar",
    LV_SYMBOL_OK "  Spoolman reachable"                                  },  // STR_SPOOLMAN_OK
  { LV_SYMBOL_WARNING "  Spoolman nicht erreichbar",
    LV_SYMBOL_WARNING "  Spoolman not reachable"                         },  // STR_SPOOLMAN_FAIL
  { "Erneut versuchen",
    "Retry"                                                               },  // STR_SPOOLMAN_RETRY
  { "Ueberspringen",
    "Skip"                                                                },  // STR_SPOOLMAN_SKIP

  // More info filament screen
  { "Mehr Info",
    "More info"                                                           },  // STR_BTN_MORE_INFO

  // GitHub OTA check screen
  { "GitHub Update",
    "GitHub Update"                                                       },  // STR_GH_OTA_TITLE
  { "Auf Updates pruefen",
    "Check for Updates"                                                   },  // STR_GH_OTA_CHECK_BTN
  { "Pruefen...",
    "Checking..."                                                         },  // STR_GH_OTA_CHECKING
  { "Kein WiFi - bitte zuerst verbinden",
    "No WiFi - please connect first"                                      },  // STR_GH_OTA_NO_WIFI
  { "Bereits aktuell",
    "Already up to date"                                                  },  // STR_GH_OTA_UP_TO_DATE
  { "Update verfuegbar: %s",
    "Update available: %s"                                                },  // STR_GH_OTA_UPDATE_AVAIL
  { "Jetzt installieren",
    "Install Now"                                                         },  // STR_GH_OTA_UPDATE_BTN
  { "Installiere... bitte warten",
    "Installing... please wait"                                           },  // STR_GH_OTA_FLASHING
  { "Update erfolgreich - startet neu...",
    "Update successful - restarting..."                                   },  // STR_GH_OTA_FLASH_OK
  { "Update fehlgeschlagen",
    "Update failed"                                                       },  // STR_GH_OTA_FLASH_FAIL
  { "Installiert: %s",
    "Installed: %s"                                                       },  // STR_GH_OTA_INSTALLED
  { "Aktuell: %s",
    "Latest: %s"                                                          },  // STR_GH_OTA_LATEST

  { "Last Used Modus",
    "Last Used Mode"                                                      },  // STR_BTN_LASTUSED_MODE
  { "OpenSpoolMan oder SpoolmanScale",
    "OpenSpoolMan or SpoolmanScale"                                       },  // STR_BTN_LASTUSED_MODE_SUB
  { "Last Used Modus",
    "Last Used Mode"                                                      },  // STR_LASTUSED_TITLE
  { "OpenSpoolMan",
    "OpenSpoolMan"                                                        },  // STR_LASTUSED_OPT_OSM
  { "Zuletzt gewogen",
    "Last Weighed"                                                        },  // STR_LASTUSED_OPT_WEIGHED
  { "Wird die Nutzung deines Filaments in Spoolman genau getrackt, z.B. automatisch durch OpenSpoolMan beim Bambu Lab Drucker, dann wird auf dem Hauptscreen das Datum der letzten Benutzung aus Spoolman angezeigt.",
    "If your filament usage is tracked in Spoolman, e.g. automatically via OpenSpoolMan with a Bambu Lab printer, the main screen will show the date of the last use from Spoolman."
                                                                          },  // STR_LASTUSED_DESC_OSM
  { "Wird das 'Last Used' Feld in Spoolman nicht aktiv von dir genutzt, dann benutzt SpoolmanScale dieses Feld, um das Datum des letzten Gewichtsupdates zu speichern. Der Hauptscreen zeigt dann 'Zuletzt gewogen' statt 'Zuletzt benutzt'.",
    "If you don't actively use the 'Last Used' field in Spoolman, SpoolmanScale will use it to store the date of the last weight update. The main screen will then show 'Last Weighed' instead of 'Last Used'."
                                                                          },  // STR_LASTUSED_DESC_WEIGHED
  { "Werkseinstellungen",       "Factory Reset"              },  // STR_BTN_FACTORY_RESET
  { "Alle Einstellungen loeschen", "Erase all settings"      },  // STR_BTN_FACTORY_RESET_SUB
  { "Werkseinstellungen?",      "Factory Reset?"             },  // STR_FACTORY_RESET_TITLE
  { "Alle Einstellungen werden geloescht:\nWiFi, Spoolman IP, Kalibrierung,\nSprache und alle anderen Daten.\nDanach startet das Geraet neu.",
    "All settings will be erased:\nWiFi, Spoolman IP, calibration,\nlanguage and all other data.\nThe device will restart afterwards." },  // STR_FACTORY_RESET_MSG
  { "Ja, alles loeschen",       "Yes, erase everything"      },  // STR_FACTORY_RESET_CONFIRM
  { "Setup ueberspringen",      "Skip setup"                 },  // STR_BTN_SKIP_SETUP
  { "Unlink",                   "Unlink"                     },  // STR_UNLINK_BTN
  { "Spule unlinken?",          "Unlink spool?"              },  // STR_UNLINK_TITLE
  { "Loescht den Eintrag im Tag-Feld in Spoolman.\nDie Spule bleibt erhalten.",
    "Clears the tag field entry in Spoolman.\nThe spool itself is kept." },  // STR_UNLINK_MSG
  { "Ja, unlinken",             "Yes, unlink"                },  // STR_UNLINK_CONFIRM
  { "Waage initialisiert...",   "Scale calibrating..."       },  // STR_SCALE_CALIBRATING
  { "Verbinde mit WiFi...",     "Connecting to WiFi..."      },  // STR_WIFI_CONNECTING_BOOT
  { "Waage und WiFi werden gestartet...", "Starting up, please wait..." },  // STR_BOOTING
};
