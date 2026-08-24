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
  { "Zurück",                "Back"             },  // STR_BACK
  { "Speichern",              "Save"             },  // STR_SAVE
  { "Bestätigen",            "Confirm"          },  // STR_CONFIRM
  { "Schließen",             "Close"            },  // STR_CLOSE
  { "Erneut versuchen",       "Try again"        },  // STR_RETRY
  { "Trotzdem verknüpfen",   "Link anyway"      },  // STR_FORCE_LINK
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
  { "Lese Bambu Sektor %02d...", "Reading Bambu sector %02d..." },  // STR_READING_BAMBU_SECTOR
  { "Durchsuche Inventar...", "Searching inventory..."        },  // STR_SEARCHING_INVENTORY
  { "Durchsuche Inventar... %u KB", "Searching inventory... %u KB" },  // STR_SEARCHING_INVENTORY_KB

  // Mainscreen Buttons
  { "Gewicht updaten",        "Update Weight"     },  // STR_BTN_WEIGHT
  { "Heute getrocknet",       "Dried today"       },  // STR_BTN_DRIED
  { "Spule verknüpfen",      "Link Spool"        },  // STR_BTN_LINK

  // Welcome Screen
  { "Willkommen! Bitte WiFi einrichten.",
    "Welcome! Please set up WiFi."              },  // STR_WELCOME_SUB
  { "Verbinde mit WiFi und gib die\nSpoolman-Server-IP ein.",
    "Connect to WiFi and enter\nyour Spoolman server IP." },  // STR_WELCOME_HINT
  { "Jetzt einrichten",       "Set up now"        },  // STR_BTN_SETUP_NOW

  // WiFi Setup
  { "WiFi einrichten",        "WiFi Setup"        },  // STR_WIFI_TITLE
  { "Netzwerke suchen...",    "Scanning networks..." },  // STR_WIFI_SCAN
  { "Netzwerk auswählen:",   "Select network:"   },  // STR_WIFI_SELECT
  { "Erneut suchen",          "Scan again"        },  // STR_WIFI_RESCAN
  { "Keine Netzwerke gefunden", "No networks found" },  // STR_WIFI_NO_NET
  { "WiFi Passwort",          "WiFi Password"     },  // STR_WIFI_PASS_TITLE
  { "Passwort für: %s",      "Password for: %s"  },  // STR_WIFI_PASS_HINT
  { "Passwort...",             "Password..."       },  // STR_WIFI_PASS_PLACEHOLDER
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
  { "Cal. | Bag | Mehr",     "Cal. | Bag | More"  },  // STR_TILE_SCALE_SUB
  { "Display",                "Display"           },  // STR_TILE_DISPLAY
  { "Helligkeit & Timeout",   "Brightness & Timeout" },  // STR_TILE_DISPLAY_SUB
  { "System",                 "System"            },  // STR_TILE_SYSTEM
  { "Sprache | Update | Info","Language | Update | Info" },  // STR_TILE_SYSTEM_SUB
  { "TARE  -  Waage auf Null setzen", "TARE  -  Zero the scale" },  // STR_BTN_TARE

  // Connection
  { "Verbindung",             "Connection"        },  // STR_CONN_TITLE
  { "WiFi Einstellungen",     "WiFi Settings"     },  // STR_BTN_WIFI_SETTINGS
  { "Nicht konfiguriert",     "Not configured"    },  // STR_BTN_WIFI_NONE
  { "WLAN Status",            "WiFi Status"       },  // STR_BTN_WIFI_STATUS
  { "Nicht verbunden",        "Not connected"     },  // STR_BTN_WIFI_STATUS_SUB
  { "Server, OTA, Logs",      "Server, OTA, logs" },  // STR_BTN_WEB_SUB
  { "Webserver",              "Web server"        },  // STR_WEB_SERVER
  { "Wartung",                "Maintenance"       },  // STR_WEB_MAINT
  { "Einstellungen",          "Settings"          },  // STR_WEB_CONFIG
  { "Aus: Port 80 antwortet nicht.",
    "Off: nothing answers on port 80." },  // STR_WEB_SERVER_HINT
  { "Schaltet die Weboberfläche im Netz an und aus. Ausgeschaltet antwortet Port 80 nicht mehr - außer FilaMan hat ein Geräte-Token hinterlegt, dann bleibt allein dessen Tag-Auslöser erreichbar.",
    "Turns the web interface on and off across the network. Switched off, port 80 stops answering - unless FilaMan holds a device token, in which case only its tag trigger stays reachable." },  // STR_WEB_SERVER_INFO
  { "Liefert Firmware-Upload, Logs, Neustart und das Tag-Schreiben. Standardmäßig aus: schreibt Firmware und NFC-Tags, ohne Passwort.",
    "Serves firmware upload, logs, restart and tag writing. Off by default: these write firmware and NFC tags, with no password." },  // STR_WEB_MAINT_HINT
  { "Firmware, Logs, Tags, Neustart",
    "Firmware, logs, tags, restart" },  // STR_WEB_MAINT_SUB
  { "Liefert Listenlimits, Trocknung, Anzeige und die Backend-Zugangsdaten. Standardmäßig aus: ändert Einstellungen ohne Passwort.",
    "Serves list limits, drying, display and the backend credentials. Off by default: changes settings with no password." },  // STR_WEB_CONFIG_HINT
  { "Listenlimits, Trocknung, Anzeige",
    "List limits, drying, display" },  // STR_WEB_CONFIG_SUB
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
  { "Ungültiger Wert",       "Invalid value"     },  // STR_BAG_INVALID

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
  { "Info & Unterstützung",   "Info & Support"     },  // STR_BTN_INFO
  { "Ko-fi - GitHub - Discord - MakerWorld", "Ko-fi - GitHub - Discord - MakerWorld" },  // STR_BTN_INFO_SUB

  // Language screen
  { "Sprache / Language",     "Sprache / Language" },  // STR_LANG_TITLE
  { "Gerät startet nach Auswahl neu.",
    "Device will reboot after selection." },  // STR_LANG_HINT
  { "coming soon",            "coming soon"        },  // STR_LANG_EN_SUB
  { "Datum / Date format:",   "Datum / Date format:" },  // STR_DATE_FMT_LABEL

  // OTA
  { "Firmware Update",        "Firmware Update"    },  // STR_OTA_TITLE
  { "Upload via Webbrowser",  "Upload via web browser" },  // STR_OTA_BROWSER
  { ".bin vom PC + SD-Logging",    "Upload from PC + SD logging" },  // STR_OTA_BROWSER_SUB
  { "Update via GitHub",      "Update via GitHub"  },  // STR_OTA_GITHUB
  { "Direkt-Update aus GitHub Releases", "Direct update from GitHub Releases" },  // STR_OTA_GITHUB_SUB
  { "Browser Update",         "Browser Update"     },  // STR_OTA_BROWSER_TITLE
  { LV_SYMBOL_WARNING "  Kein WiFi\nBitte zuerst WiFi einrichten.",
    LV_SYMBOL_WARNING "  No WiFi\nPlease set up WiFi first." },  // STR_OTA_NO_WIFI
  { "Browser öffnen und aufrufen:",
    "Open browser and go to:"                   },  // STR_OTA_OPEN_BROWSER
  { "Datei auswählen: SpoolmanScale vX.Y.Z.bin",
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
  { "Info & Unterstützung",   "Info & Support"     },  // STR_INFO_TITLE
  { "SpoolmanScale  %s",      "SpoolmanScale  %s"  },  // STR_INFO_VERSION
  { "Tippe einen Button um den QR-Code anzuzeigen.",
    "Tap a button to show the QR code."         },  // STR_INFO_HINT

  // QR Popups
  { "Projekt gefällt dir? Kauf mir einen Kaffee!",
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
  { "Leere Spule\n(Spule + Kern messen)",     "Empty spool\n(measure spool + core)" },  // STR_BTN_EMPTY_SPOOL
  { "Spule archivieren\n(leer, 0g)", "Archive spool\n(empty, 0g)" },  // STR_BTN_ARCHIVE
  { "Ja, bestätigen",               "Yes, confirm"           },  // STR_BTN_CONFIRMED

  // Spool weight sub-popup
  { "Spulengewicht: %.0f g speichern als...",
    "Save spool weight: %.0f g as..."           },  // STR_SPOOL_WEIGHT_TITLE
  { "Diese Spule\n(spool_weight)",   "This spool\n(spool_weight)"     },  // STR_BTN_THIS_SPOOL
  { "Dieses Filament\n(spool_weight)", "This filament\n(spool_weight)" },  // STR_BTN_THIS_FILAMENT
  { "Hersteller\n(empty_spool_weight)", "Vendor\n(empty_spool_weight)" },  // STR_BTN_THIS_VENDOR

  // Link Flow
  { "Bambu-Spule verknüpfen",  "Link Bambu spool"   },  // STR_LINK_BAMBU_TITLE
  { "Unbekannte Spule",         "Unknown spool"       },  // STR_LINK_NTAG_TITLE
  { "%s | nicht in Spoolman",   "%s | not in Spoolman" },  // STR_LINK_NOT_IN_SM
  { "Spool-ID eingeben",        "Enter Spool-ID"      },  // STR_BTN_ENTER_ID
  { "Aus Liste wählen",        "Choose from list"    },  // STR_BTN_FROM_LIST
  { "Spoolman Spool-ID",        "Spoolman Spool-ID"   },  // STR_LINK_ID_TITLE
  { "Prüfe...",                "Checking..."         },  // STR_LINK_CHECKING
  { "ID nicht gefunden",        "ID not found"        },  // STR_LINK_ID_NOT_FOUND
  { "HTTP Fehler %d",           "HTTP Error %d"       },  // STR_LINK_HTTP_ERR
  { "JSON Fehler",              "JSON error"          },  // STR_LINK_JSON_ERR
  { "Kein WiFi",                "No WiFi"             },  // STR_LINK_NO_WIFI
  { LV_SYMBOL_WARNING "  Spule bereits verknüpft",
    LV_SYMBOL_WARNING "  Tag already assigned!"  },  // STR_WARN_A_TITLE
  { "Spule #%d hat bereits\nein Tag: %s",
    "Spool #%d already has\na tag: %s"          },  // STR_WARN_A_INFO
  { LV_SYMBOL_WARNING "  Trotzdem verknüpfen",
    LV_SYMBOL_WARNING "  Link anyway"           },  // STR_BTN_OVERWRITE
  { "Material stimmt nicht überein", "Material mismatch" },  // STR_WARN_B_TITLE
  { "Tag:      %s\nSpoolman: %s  (#%d)\n\nFalsche ID? Bitte nochmal prüfen.",
    "Tag:      %s\nSpoolman: %s  (#%d)\n\nWrong ID? Please double-check." },  // STR_WARN_B_DETAILS
  { "Hersteller wählen  (%d Spulen)", "Choose vendor  (%d spools)" },  // STR_VENDOR_TITLE
  { "Material wählen",         "Choose material"     },  // STR_MAT_TITLE
  { "Spule auswählen  (%d)",   "Select spool  (%d)"  },  // STR_SPOOLS_TITLE
  { "Keine Spulen ohne Tag\nin Spoolman gefunden.",
    "No unlinked spools\nfound in Spoolman."    },  // STR_NO_VENDORS
  { "Keine Materialien gefunden.", "No materials found." },  // STR_NO_MATERIALS
  { "Keine passenden Spulen.\nBitte per ID verlinken.",  "No matching spools.\nPlease link via ID." },  // STR_NO_SPOOLS
  { "Verknüpfen?",             "Link this spool?"    },  // STR_CONFIRM_LINK
  { LV_SYMBOL_OK "  Verknüpfen", LV_SYMBOL_OK "  Link"      },  // STR_LINK_OK
  { "Fehler beim Verknüpfen",  "Error linking"       },  // STR_LINK_FAIL

  // Tare
  { "Tare / Nullpunkt",        "Tare / Zero point"   },  // STR_TARE_TITLE
  { "Waage leeren und\nTare-Button drücken.",
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
  { "Sprache wählen",          "Choose language"    },  // STR_WELCOME_LANG_TITLE
  { "Sprache kann später\nim Settings geändert werden.",
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
  { "Deine SpoolmanScale ist fast bereit.",
    "Your SpoolmanScale is almost ready."         },  // STR_FIRSTBOOT_SUB
  // Both backends are named here because this screen appears before the user
  // has chosen one. It must therefore not go through backendText().
  { "In wenigen Schritten richten wir\nWiFi, Spoolman/FilaMan und die Waage ein.",
    "In a few steps we will set up\nWiFi, Spoolman/FilaMan and the scale."  },  // STR_FIRSTBOOT_HINT
  { LV_SYMBOL_RIGHT "  Los geht's",
    LV_SYMBOL_RIGHT "  Get started"               },  // STR_FIRSTBOOT_BTN

  // Extra fields screen
  { "Spoolman Extra-Felder",
    "Spoolman Extra Fields"                       },  // STR_EXTRA_FIELDS_TITLE
  { "Prüfen...",
    "Checking..."                                 },  // STR_EXTRA_FIELDS_CHECKING
  { LV_SYMBOL_OK "  Vorhanden: %s",
    LV_SYMBOL_OK "  Present: %s" },  // STR_EXTRA_FIELDS_ALL_OK
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
  { "Überspringen",
    "Skip"                                        },  // STR_EXTRA_FIELDS_SKIP

  // Calibration reminder screen
  { "Waage kalibrieren",
    "Calibrate scale"                             },  // STR_CAL_REMINDER_TITLE
  { "Für genaue Messungen muss die Waage\nkalibriert werden.\n\nLege ein bekanntes Gewicht auf\nund gehe zu Einstellungen > Waage\n> Kalibrierung.\n\nDies kann auch später gemacht werden.",
    "For accurate measurements the scale\nneeds to be calibrated.\n\nPlace a known weight on the scale\nand go to Settings > Scale > Calibration.\n\nYou can also do this later."  },  // STR_CAL_REMINDER_MSG
  { "Verstanden",
    "Got it!"                                     },  // STR_CAL_REMINDER_LATER
  { LV_SYMBOL_EDIT "  Jetzt kalibrieren",
    LV_SYMBOL_EDIT "  Calibrate now"              },  // STR_CAL_REMINDER_NOW

  // Calibration TARE hint
  { "Zuerst ohne Gewicht TARE drücken!\nDann Gewicht auflegen und berechnen.",
    "First press TARE without weight!\nThen place weight and calculate."  },  // STR_CAL_TARE_HINT

  // Extra fields test button
  { LV_SYMBOL_EDIT "  Testfeld erstellen",
    LV_SYMBOL_EDIT "  Generate test field"                               },  // STR_EF_TEST_BTN
  { LV_SYMBOL_OK "  'spoolscale_test' erstellt!\nIn Spoolman nach dem Test löschen.",
    LV_SYMBOL_OK "  'spoolscale_test' created!\nDelete it in Spoolman after testing." },  // STR_EF_TEST_CREATED
  { LV_SYMBOL_WARNING "  Feld existiert bereits in Spoolman.",
    LV_SYMBOL_WARNING "  Field already exists in Spoolman."              },  // STR_EF_TEST_EXISTS
  { LV_SYMBOL_WARNING "  Testfeld konnte nicht erstellt werden.",
    LV_SYMBOL_WARNING "  Test field creation failed."                    },  // STR_EF_TEST_FAIL

  // Spoolman IP validation
  { "Verbindung wird geprüft...",
    "Testing connection..."                                               },  // STR_SPOOLMAN_TESTING
  { LV_SYMBOL_OK "  Spoolman erreichbar",
    LV_SYMBOL_OK "  Spoolman reachable"                                  },  // STR_SPOOLMAN_OK
  { LV_SYMBOL_WARNING "  Spoolman nicht erreichbar",
    LV_SYMBOL_WARNING "  Spoolman not reachable"                         },  // STR_SPOOLMAN_FAIL
  { "Erneut versuchen",
    "Retry"                                                               },  // STR_SPOOLMAN_RETRY
  { "Überspringen",
    "Skip"                                                                },  // STR_SPOOLMAN_SKIP

  // More info filament screen
  { "Mehr Info",
    "More info"                                                           },  // STR_BTN_MORE_INFO

  // GitHub OTA check screen
  { "GitHub Update",
    "GitHub Update"                                                       },  // STR_GH_OTA_TITLE
  { "Auf Updates prüfen",
    "Check for Updates"                                                   },  // STR_GH_OTA_CHECK_BTN
  { "Prüfen...",
    "Checking..."                                                         },  // STR_GH_OTA_CHECKING
  { "Kein WiFi - bitte zuerst verbinden",
    "No WiFi - please connect first"                                      },  // STR_GH_OTA_NO_WIFI
  { "Bereits aktuell",
    "Already up to date"                                                  },  // STR_GH_OTA_UP_TO_DATE
  { "Update verfügbar: %s",
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
  { "Pre-release",
    "Pre-release"                                                         },  // STR_GH_OTA_PRERELEASE
  { "Autom. Suche",
    "Auto check"                                                          },  // STR_GH_OTA_AUTOCHECK

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
  // FilaMan keeps both values itself, so the wording differs from Spoolman:
  // nothing is written, the scale only picks which source it reads.
  { "FilaMan",
    "FilaMan"                                                             },  // STR_LASTUSED_OPT_FILAMAN
  { "FilaMan pflegt 'Zuletzt benutzt' selbst und trägt dort echten Druckverbrauch ein, z.B. über seine Druckeranbindung. Solange noch kein Druck erfasst wurde, zeigt der Hauptscreen ersatzweise die letzte Wägung an.",
    "FilaMan maintains 'Last Used' itself and records real print consumption there, e.g. through its printer integration. Until a print has been recorded, the main screen falls back to the last weighing."
                                                                          },  // STR_LASTUSED_DESC_FILAMAN_USED
  { "FilaMan protokolliert jede Wägung mit Zeitstempel, auch die von dieser Waage. Der Hauptscreen zeigt dann 'Zuletzt gewogen' und damit, wann du die Spule zuletzt in der Hand hattest. Es wird nichts zusätzlich gespeichert.",
    "FilaMan logs every weighing with a timestamp, including the ones from this scale. The main screen then shows 'Last Weighed', i.e. when you last handled the spool. Nothing extra is stored."
                                                                          },  // STR_LASTUSED_DESC_FILAMAN_WEIGHED
  { "Druckverbrauch oder Wägung",
    "Print usage or weighing"                                             },  // STR_BTN_LASTUSED_MODE_SUB_FM
  // BamBuddy keeps both dates itself: last_used is stamped when a print
  // consumes the spool, last_weighed_at when a weight is written. Neither is
  // ours to fill, so unlike Spoolman nothing is repurposed here.
  { "BamBuddy",
    "BamBuddy"                                                            },  // STR_LASTUSED_OPT_BAMBUDDY
  { "BamBuddy trägt 'Zuletzt benutzt' selbst ein, wenn ein Druck von dieser Spule verbraucht. Solange kein Druck erfasst wurde, zeigt der Hauptscreen ersatzweise die letzte Wägung an.",
    "BamBuddy fills 'last used' itself when a print consumes this spool. Until a print has been recorded, the main screen falls back to the last weighing."
                                                                          },  // STR_LASTUSED_DESC_BAMBUDDY_USED
  { "BamBuddy stempelt jede Wägung mit Zeitstempel, auch die von dieser Waage. Der Hauptscreen zeigt dann 'Zuletzt gewogen'. Nur das BamBuddy-Inventar führt dieses Feld - mit einem Spoolman-Server dahinter bleibt es leer.",
    "BamBuddy stamps every weighing, including the ones from this scale. The main screen then shows 'last weighed'. Only the BamBuddy inventory keeps this field - with a Spoolman server behind it, it stays empty."
                                                                          },  // STR_LASTUSED_DESC_BAMBUDDY_WEIGHED
  { "Druckverbrauch oder Wägung",
    "Print usage or weighing"                                             },  // STR_BTN_LASTUSED_MODE_SUB_BB
  // BamBuddy's own inventory stores consumption and derives the rest, so it
  // cannot hold more filament than the label promises. Asked before writing
  // rather than letting the value snap back on the next scan.
  { "Mehr als das Etikett",
    "More than the label"                                                 },  // STR_BB_CAP_TITLE
  { "Gemessen: %.0f g. Das Etikett sagt %.0f g. BamBuddy kann nicht mehr speichern, als das Etikett hergibt - der Rest stünde danach wieder auf voll.",
    "Measured: %.0f g. The label says %.0f g. BamBuddy cannot store more than the label allows, so the remainder would read as full again."
                                                                          },  // STR_BB_CAP_BODY
  { "Etikett auf %.0f g anheben",
    "Raise label to %.0f g"                                               },  // STR_BB_CAP_RAISE
  { "Etikett behalten",
    "Keep the label"                                                      },  // STR_BB_CAP_KEEP
  { "Trocknungsdatum",
    "Drying date"                                                         },  // STR_BB_DRIED_TITLE
  { "Nicht speichern",
    "Do not store"                                                        },  // STR_BB_DRIED_OFF
  { "Das Datum bleibt leer",
    "The date stays empty"                                                },  // STR_BB_DRIED_OFF_SUB
  { "Spoolman hinter BamBuddy",
    "Spoolman behind BamBuddy"                                            },  // STR_BB_DRIED_SPOOLMAN
  { "In extra.last_dried auf dem Spoolman-Server",
    "Into extra.last_dried on the Spoolman server"                        },  // STR_BB_DRIED_SPOOLMAN_SUB
  { "Nur wenn BamBuddy auf einen Spoolman-Server zeigt",
    "Only when BamBuddy points at a Spoolman server"                      },  // STR_BB_DRIED_SPOOLMAN_NA
  { "Ins Notizfeld",
    "Into the note field"                                                 },  // STR_BB_DRIED_NOTE
  { "Als [last_dried:JJJJ-MM-TT] in der Notiz",
    "As [last_dried:YYYY-MM-DD] in the note"                              },  // STR_BB_DRIED_NOTE_SUB
  { "BamBuddy hat kein Feld für ein Trocknungsdatum. Das Notizfeld geht immer und behält den übrigen Text. Der andere Weg schreibt in last_dried auf dem Spoolman-Server hinter BamBuddy.",
    "BamBuddy has no field for a drying date. The note field always works and keeps the rest of the text. The other route writes into last_dried on the Spoolman server behind BamBuddy."
                                                                          },  // STR_BB_DRIED_INFO
  // Short forms for the connection test line, which has room for about 34
  // characters. The "Inventar:" prefix is what says this names the data
  // source and not the backend - bare "Spoolman" always means the native one.
  { "Inventar: BamBuddy",
    "Inventory: BamBuddy"                                                 },  // STR_BB_INV_OWN
  { "Inventar: Spoolman",
    "Inventory: Spoolman"                                                 },  // STR_BB_INV_SPOOLMAN
  // Label above the database name on the backend screen. Same word as the
  // short form above, so the two places do not invent two vocabularies.
  { "Inventar",
    "Inventory"                                                           },  // STR_BACKEND_INVENTORY
  { "Werkseinstellungen",       "Factory Reset"              },  // STR_BTN_FACTORY_RESET
  { "Alle Einstellungen löschen", "Erase all settings"      },  // STR_BTN_FACTORY_RESET_SUB
  { "Werkseinstellungen?",      "Factory Reset?"             },  // STR_FACTORY_RESET_TITLE
  { "Alle Einstellungen werden gelöscht:\nWiFi, Spoolman IP, Kalibrierung,\nSprache und alle anderen Daten.\nDanach startet das Gerät neu.",
    "All settings will be erased:\nWiFi, Spoolman IP, calibration,\nlanguage and all other data.\nThe device will restart afterwards." },  // STR_FACTORY_RESET_MSG
  { "Ja, alles löschen",       "Yes, erase everything"      },  // STR_FACTORY_RESET_CONFIRM
  { "Spule kopieren",            "Copy spool"                 },  // STR_BTN_COPY_SPOOL
  { "Spule kopieren",            "Copy spool"                 },  // STR_COPY_TITLE
  { "Spoolman-ID eingeben",      "Enter Spoolman ID"          },  // STR_COPY_ID_BTN
  { "Aktive Spulen",             "Active spools"              },  // STR_COPY_ACTIVE_BTN
  { "Archivierte Spulen",        "Archived spools"            },  // STR_COPY_ARCHIVED_BTN
  { "Neue Spule anlegen?",       "Create new spool?"          },  // STR_COPY_CONFIRM_TITLE
  { "Vorlage: %s\nZuletzt bekannt: %.0f g\nWaagengewicht (netto): %.0f g\n-> wird übernommen", "Template: %s\nLast known: %.0f g\nNew spool weight (net): %.0f g\n-> will be saved" },  // STR_COPY_CONFIRM_MSG
  { "Spule erstellt!",           "Spool created!"             },  // STR_COPY_OK
  { "Fehler beim Erstellen",     "Error creating spool"       },  // STR_COPY_FAIL
  { "Keine Spulen gefunden",     "No spools found"            },  // STR_COPY_NO_SPOOLS
  { "Zu viele Ergebnisse.\nBitte ID verwenden.", "Too many results.\nPlease use ID instead." },  // STR_COPY_LIMIT_HIT
  { "Setup überspringen",      "Skip setup"                 },  // STR_BTN_SKIP_SETUP
  { "Unlink",                   "Unlink"                     },  // STR_UNLINK_BTN
  { "Spule unlinken?",          "Unlink spool?"              },  // STR_UNLINK_TITLE
  { "Löscht den Eintrag im Tag-Feld in Spoolman.\nDie Spule bleibt erhalten.",
    "Clears the tag field entry in Spoolman.\nThe spool itself is kept." },  // STR_UNLINK_MSG
  { "Ja, unlinken",             "Yes, unlink"                },  // STR_UNLINK_CONFIRM
  { "Waage initialisiert...",   "Scale calibrating..."       },  // STR_SCALE_CALIBRATING
  { "Verbinde mit WiFi...",     "Connecting to WiFi..."      },  // STR_WIFI_CONNECTING_BOOT
  { "Waage und WiFi werden gestartet...", "Starting up, please wait..." },  // STR_BOOTING
  { "Neustart",                 "Reboot"                     },  // STR_BTN_REBOOT
  { "Gerät neu starten",       "Restart device"             },  // STR_BTN_REBOOT_SUB
  { "Ganze g",                  "Whole g"                    },  // STR_WHOLE_GRAM
  { "Mehr Spulen gefunden - nicht gelistet? Per Spool-ID verknüpfen",   "More spools found - not listed? Use Spool-ID"   },  // STR_LIST_MORE_SPOOLS
  { "Mehr Hersteller gefunden - nicht gelistet? Per Spool-ID verknüpfen", "More vendors found - not listed? Use Spool-ID" },  // STR_LIST_MORE_VENDORS
  { "Mehr Materialien gefunden - nicht gelistet? Per Spool-ID verknüpfen", "More materials found - not listed? Use Spool-ID" },  // STR_LIST_MORE_MATS

  // Auto-Weight
  { "Auto-Gewichtsupdate",
    "Auto weight update"                                                   },  // STR_AUTO_WEIGHT_TITLE
  { "Sobald eine Spule erkannt und das Gewicht\n3 Sekunden stabil ist, wird es automatisch\ngespeichert (ohne Beutel).",
    "Once a spool is detected and the weight\nis stable for 3 seconds, it will be saved\nautomatically (without bag)."  },  // STR_AUTO_WEIGHT_INFO
  { LV_SYMBOL_PLAY " Auto aktivieren",
    LV_SYMBOL_PLAY " Enable auto"                                          },  // STR_AUTO_WEIGHT_ENABLE
  { LV_SYMBOL_STOP " Auto deaktivieren",
    LV_SYMBOL_STOP " Disable auto"                                         },  // STR_AUTO_WEIGHT_DISABLE
  { "Lagerort",
    "Location"                                                             },  // STR_BTN_LOCATION
  { "Lagerort wählen",
    "Select location"                                                      },  // STR_LOCATION_TITLE
  { LV_SYMBOL_CLOSE " Kein Lagerort",
    LV_SYMBOL_CLOSE " No location"                                         },  // STR_LOCATION_NONE
  { "Lade...",
    "Loading..."                                                           },  // STR_LOCATION_LOADING
  { "Kein WLAN",
    "No WiFi"                                                              },  // STR_LOCATION_NO_WIFI
  { LV_SYMBOL_OK " Gespeichert",
    LV_SYMBOL_OK " Saved"                                                  },  // STR_LOCATION_SAVED
  { LV_SYMBOL_WARNING " Fehler",
    LV_SYMBOL_WARNING " Error"                                             },  // STR_LOCATION_FAIL
  { "Keine Spoolman-Lagerorte gefunden",
    "No Spoolman locations found"                                          },  // STR_LOCATION_NO_LOCATIONS
  { "Leere Lagerorte werden nicht angezeigt",
    "Empty locations are not shown"                                        },  // STR_LOCATION_HINT_EMPTY
  { "Zu viele Lagerorte - nicht alle angezeigt",
    "Too many locations - not all shown"                                   },  // STR_LOCATION_LIMIT_HIT
  { "Bitte per ID verlinken",        "Please link via ID"                 },  // STR_NO_SPOOLS_HINT
  { "Ortsabfrage bei Entnahme",      "Location on removal"                },  // STR_BTN_AUTO_LOC_POPUP
  { "Lagerort-Auswahl automatisch",  "Auto location picker"               },  // STR_BTN_AUTO_LOC_POPUP_SUB
  { "Lagerort speichern?",           "Save location?"                     },  // STR_AUTO_LOC_POPUP_TITLE
  { "Wo wird die Spule gelagert?",   "Where is the spool stored?"         },  // STR_AUTO_LOC_POPUP_MSG
  { "Trocknungserinnerung",          "Drying Reminder"                    },  // STR_BTN_DRYING_REMINDER
  { "Ampelsystem",                   "Alert system"                       },  // STR_BTN_DRYING_REMINDER_SUB
  { "Trocknungserinnerung",          "Drying Reminder"                    },  // STR_DRYING_REMINDER_TITLE
  { "Kommt bald",                    "Coming soon"                        },  // STR_DRYING_REMINDER_COMING_SOON

  // Drying Reminder Screen
  { "Aus",                           "Off"                                },  // STR_DRY_MODE_OFF
  { "Material",                      "Material"                           },  // STR_DRY_MODE_MATERIAL
  { "Manuell",                       "Manual"                             },  // STR_DRY_MODE_MANUAL
  { "Kein Ampelsignal aktiv.\n\nMaterial: Schwellwerte pro Filamenttyp\n(konfigurierbar im Browser).\n\nManuell: Eigene Grenzwerte in Tagen.",
    "No alert signal active.\n\nMaterial: Thresholds per filament type\n(configurable in browser).\n\nManual: Custom limits in days."
  },  // STR_DRY_OFF_DESC
  { "Schwellwerte im Browser editierbar.", "Thresholds editable in browser." },  // STR_DRY_MAT_HINT
  { "Material",                      "Material"                           },  // STR_DRY_MAT_HDR_MAT
  { "Gelb (Tage)",                   "Yellow (days)"                      },  // STR_DRY_MAT_HDR_YELLOW
  { "Rot (Tage)",                    "Red (days)"                         },  // STR_DRY_MAT_HDR_RED
  { "Vers.*",                        "Mult.*"                             },  // STR_DRY_MAT_HDR_MULT
  { "* Multiplikator für luftdicht","* Multiplier for airtight storage"  },  // STR_DRY_MAT_FOOTNOTE
  { "Gelb ab",                       "Yellow from"                        },  // STR_DRY_MAN_YELLOW_LBL
  { "Rot ab",                        "Red from"                           },  // STR_DRY_MAN_RED_LBL
  { "Tippen zum Bearbeiten",         "Tap to edit"                        },  // STR_DRY_MAN_EDIT_HINT
  { "Grenzwerte gelten für alle Materialien.", "Limits apply to all materials." },  // STR_DRY_MAN_INFO
  { "Tage",                          "days"                               },  // STR_DRY_DAYS_UNIT
  { "Gelb-Schwellwert",              "Yellow threshold"                   },  // STR_DRY_NUMPAD_YELLOW_TITLE
  { "Rot-Schwellwert",               "Red threshold"                      },  // STR_DRY_NUMPAD_RED_TITLE
  { "Effektive Werte (%.1fx Multiplikator eingerechnet)", "Effective values (%.1fx multiplier included)" },  // STR_DRY_MAT_EFF_NOTE
  { "Versiegelt",                    "Sealed"                             },  // STR_DRY_SEALED_HDR

  // Backend selection. "Spoolman" and "FilaMan" are product names and stay
  // untranslated, so they are not in this table.
  // "Server" described the technology, not the purpose. Both Spoolman and
  // FilaMan manage a filament inventory, and that is what the user picks
  // here. The address screen keeps "Server", because a server address is
  // literally what gets typed in there.
  { "Filamentverwaltung",            "Filament manager"                   },  // STR_BACKEND_TITLE
  { "Programm und Zugangsdaten",     "Application and credentials"        },  // STR_BACKEND_TILE_SUB
  { "Adresse",                       "Address"                            },  // STR_BACKEND_ADDRESS
  { "API-Key",                       "API key"                            },  // STR_BACKEND_APIKEY
  { "Device-Token",                  "Device token"                       },  // STR_BACKEND_DEVICE_TOKEN
  { "gesetzt",                       "set"                                },  // STR_BACKEND_SET
  { "fehlt",                         "missing"                            },  // STR_BACKEND_MISSING

  // Web interface. The same server serves the firmware upload and the
  // FilaMan credentials, so the screen title stays neutral.
  { "Weboberfläche",                 "Web interface"                      },  // STR_WEB_TITLE
  { "Adresse am Rechner im Browser öffnen und dort API-Key und Gerätecode eintragen. Der Status unten aktualisiert sich von selbst.",
    "Open this address in a browser on your computer and enter the API key and device code there. The status below updates on its own."
                                                                          },  // STR_WEB_SETUP_HINT
  // BamBuddy has one credential where FilaMan has two, so the sentence that
  // tells the user what to type differs.
  { "Adresse am Rechner im Browser öffnen und dort den API-Key eintragen. Der Status unten aktualisiert sich von selbst.",
    "Open this address in a browser on your computer and enter the API key there. The status below updates on its own."
                                                                          },  // STR_WEB_SETUP_HINT_BB
  { "Im Browser einrichten",         "Set up in browser"                  },  // STR_BTN_WEB_SETUP
  { "Fertig",                        "Done"                               },  // STR_BTN_FINISH
  { "Weiter",                        "Next"                               },  // STR_BTN_NEXT
  { "Welche Filamentverwaltung benutzt du? Das lässt sich später jederzeit im Menü ändern.",
    "Which filament manager do you use? This can be changed in the menu at any time."
                                                                          },  // STR_SETUP_BACKEND_HINT
  // Shown instead of a spool count when the server answered but the number
  // could not be asked for yet, which is the normal FilaMan setup case.
  { "verbunden",                     "connected"                          },  // STR_CONNECTED
  { "AN",                            "ON"                                 },  // STR_ON
  { "AUS",                           "OFF"                                },  // STR_OFF
  { "Im Browser öffnen",             "Open in browser"                    },  // STR_BTN_OPEN_BROWSER
  // Names every product in both languages and in every backend mode. Not
  // passed through backendText(), see the comment at the call site.
  { "Nicht mit Spoolman, FilaMan oder BamBuddy verbunden",
    "Not affiliated with Spoolman, FilaMan or BamBuddy"                   },  // STR_NOT_AFFILIATED
  { "Kein Tag erkannt, bitte neu auflegen",
    "No tag detected, place it again"                                    },  // STR_LINK_NO_TAG

  // Main screen weight box and More-info detail grid
  { "Waage - Spule",                 "Scale - Spool"                      },  // STR_LBL_SCALE_SPOOL_CAP
  { "Gesamt:",                       "Total:"                             },  // STR_LBL_TOTAL_CAP
  { "o. Beutel:",                    "w/o Bag:"                           },  // STR_LBL_WO_BAG_CAP
  { "Farbe",                         "Hex Color"                          },  // STR_LBL_HEX_COLOR
  { "Produktionsdatum",              "Production date"                    },  // STR_LBL_PRODUCTION_DATE
  { "Artikelnr.",                    "Article no."                        },  // STR_LBL_ARTICLE_NO_SHORT
  { "Leergewicht Spule",             "Spool weight (empty)"               },  // STR_LBL_SPOOL_WEIGHT_EMPTY

  // Status bar address selector
  { "Im Statusbalken zeigen",        "Show in status bar"                 },  // STR_BTN_IP_STATUSBAR
  { "Gerät",                         "Device"                             },  // STR_IP_BAR_DEVICE

  // Remote link. Deliberately not passed through backendText(): this only
  // ever happens in FilaMan mode, so naming it outright is clearer than a
  // substitution that can never differ.
  { "FilaMan: Spule verknüpfen?",   "FilaMan: link spool?"                },  // STR_REMOTE_LINK_TITLE
  { "Aufliegenden Tag mit dieser Spule verknüpfen?",
    "Link the tag on the scale to this spool?"                            },  // STR_REMOTE_LINK_QUESTION
  { "Verknüpfen",                   "Link"                                },  // STR_REMOTE_LINK_CONFIRM
  { "Material weicht ab: Tag %s, Spule %s",
    "Material mismatch: tag %s, spool %s"                                 },  // STR_REMOTE_LINK_MISMATCH
  { "Details nicht abrufbar",        "Details unavailable"                },  // STR_REMOTE_LINK_NO_DETAILS
  { "Verknüpfung abgelaufen",       "Link request timed out"              },  // STR_REMOTE_LINK_TIMEOUT
  { "Aus",                           "Off"                                },  // STR_SLEEP_OFF

  // Tag versus spool comparison
  { "Tag",                           "Tag"                                },  // STR_REMOTE_LINK_COL_TAG
  { "Spule",                         "Spool"                              },  // STR_REMOTE_LINK_COL_SPOOL
  { "Material",                      "Material"                           },  // STR_REMOTE_LINK_ROW_MATERIAL
  { "Farbe",                         "Colour"                             },  // STR_REMOTE_LINK_ROW_COLOR

  // FilaMan options sub screen
  { "Weitere Optionen",              "More options"                       },  // STR_BTN_MORE_OPTIONS
  { "Mehrere Tags verknüpfen",      "Link multiple tags"                 },  // STR_CU_WRITE
  { "Schreibt in Spoolmans Feld card_uids",
    "Writes to Spoolman's card_uids field"                                },  // STR_CU_WRITE_SUB
  { "An: eine gescannte UID kommt an die Liste, statt sie zu ersetzen. "
    "Verknüpfte Spulen erscheinen wieder in der Verlinken-Liste, damit ein "
    "zweites Tag dazukommen kann.\n\n"
    "Aus: in card_uids steht immer nur eine UID.\n\n"
    "Nur für card_uids, weil es als einziges Extra-Feld eine Liste aufnimmt. "
    "Spoolman NFC kann mehrere Tags von Haus aus und braucht den Schalter "
    "nicht.",
    "On: a scanned UID is appended to the list instead of replacing it. Linked "
    "spools show up in the link list again so a second tag can join them.\n\n"
    "Off: card_uids only ever holds one UID.\n\n"
    "card_uids only, because it is the one extra field that holds a list. "
    "Spoolman NFC does several tags natively and needs no switch."          },  // STR_CU_WRITE_INFO
  { "UID nicht hinzugefügt",        "UID not added"                      },  // STR_CU_NOT_WRITTEN
  { "Tag hängt schon an Spule #%d", "Tag already on spool #%d"           },  // STR_TAG_ON_OTHER_SPOOL
  { LV_SYMBOL_WARNING "  Spule hat schon UIDs",
    LV_SYMBOL_WARNING "  Spool already has UIDs"                          },  // STR_WARN_A_ADD_TITLE
  { "Spule #%d  |  %s %s\nHat bereits %d UID(s)",
    "Spool #%d  |  %s %s\nAlready has %d UID(s)"                          },  // STR_WARN_A_ADD_INFO
  { "Spule #%d\nHat bereits %d UID(s)",
    "Spool #%d\nAlready has %d UID(s)"                                    },  // STR_WARN_A_ADD_SHORT
  { "UID hinzufügen",               "Add UID"                            },  // STR_BTN_ADD_UID
  { "Diese Spule hat %d UIDs.\nNur das aufliegende Tag entfernen\noder die ganze Verknüpfung lösen?",
    "This spool has %d UIDs.\nRemove only the tag on the scale\nor the whole binding?" },  // STR_UNLINK_MULTI_MSG
  { "Nur dieses Tag",                "Only this tag"                      },  // STR_BTN_UNLINK_ONE
  { "Alle lösen",                   "Unlink all"                         },  // STR_BTN_UNLINK_ALL
  { "Ohne Nachfrage verknüpfen",     "Link without asking"                },  // STR_FLM_AUTOLINK
  { "wenn die Spule schon aufliegt", "when the spool is already on"       },  // STR_FLM_AUTOLINK_SUB
  { " (Filament)",                   " (filament)"                        },  // STR_TARE_FROM_FILAMENT
  { " (Hersteller)",                 " (brand)"                           },  // STR_TARE_FROM_BRAND
  { "Ohne Beutel wiegen - sonst %.0f g zu viel",
    "Weigh without the bag - %.0f g too much otherwise" },  // STR_SPOOL_WEIGHT_BAG_HINT
  { "Ohne Tag wiegen",              "Weigh without a tag"                },  // STR_FLM_TAGLESS
  { "wenn kein Tag aufgelegt wird", "when no tag is presented"           },  // STR_FLM_TAGLESS_SUB
  { "Spule gewählt - jetzt wiegen", "Spool selected - weigh it now"      },  // STR_REMOTE_LINK_WEIGH
  { "Wecken bei Auflage",           "Wake on load"                       },  // STR_WAKE_ON_LOAD
  { LV_SYMBOL_EYE_CLOSE "  Bildschirm aus nach (Min.)",
    LV_SYMBOL_EYE_CLOSE "  Screen off after (min.)"        },  // STR_SCREENOFF_LABEL
  { "Nie",                           "Never"                              },  // STR_SCREENOFF_NEVER
  { "Löst FilaMan eine Verknüpfung aus und die Spule liegt schon auf der Waage, wird ohne Rückfrage verknüpft. Passen Material oder Farbe nicht zusammen, fragt die Waage trotzdem nach.",
    "When FilaMan triggers a link and the spool is already on the scale, it is linked without asking. If the material or colour do not match, the scale asks anyway." },  // STR_FLM_AUTOLINK_INFO
  { "Wird nach einer Verknüpfung aus FilaMan kein Tag aufgelegt, lädt die Waage nach 10 Sekunden trotzdem die gewählte Spule und lässt sie wiegen. Es wird nichts auf einen Tag geschrieben.",
    "If no tag is presented after a link from FilaMan, the scale loads the chosen spool anyway after 10 seconds and lets it be weighed. Nothing is written to any tag." },  // STR_FLM_TAGLESS_INFO
  // FilaMan variants of the spool-weight scope buttons. The Spoolman ones
  // carry the REST field name in brackets, which is a real reading aid there
  // because the three scopes use three different names. In FilaMan two of
  // the three are called the same thing, so the bracket helps nobody and is
  // simply wrong on top. FilaMan also calls a vendor a manufacturer.
  { "Diese Spule",                   "This spool"                         },  // STR_BTN_THIS_SPOOL_FM
  { "Dieses Filament",               "This filament"                      },  // STR_BTN_THIS_FILAMENT_FM
  { "Hersteller",                    "Manufacturer"                       },  // STR_BTN_THIS_VENDOR_FM
  { LV_SYMBOL_CLOSE " leer / Archivieren\nRest wird 0",
    LV_SYMBOL_CLOSE " empty / Archive\nremaining set to 0" },  // STR_BTN_ARCHIVE_EMPTY_FM

  // Auto AMS assignment. FilaMan marks a freshly weighed spool as pending on
  // every printer driver for a few seconds, so the next tray to be loaded
  // gets it. The wording avoids "auto assign" on its own because the whole
  // point of the ask mode is that it is not automatic.
  { "Auto AMS-Zuordnung",            "Auto AMS assign"                    },  // STR_AMS_TITLE
  { "Spule beim Einlegen zuordnen",  "assign the spool as it goes in"     },  // STR_AMS_SUB
  { "FilaMan merkt eine gewogene Spule einige Sekunden vor. Wer in dieser Zeit ein AMS-Fach belädt, bekommt sie zugeordnet. Geöffnet wird das Fenster nur von einem Gewicht, deshalb bucht die Waage beim Zuordnen ein zweites Mal: die Messung steht dann doppelt im Protokoll, der Wert bleibt gleich. Wandert die Spule ohnehin gleich in den Drucker, genügt kurz auflegen.",
    "FilaMan reserves a weighed spool for a few seconds. Whoever loads an AMS tray in that time gets it assigned. Only a weight opens that window, so assigning books the value a second time: the measurement then shows twice in the log, the value stays the same. If the spool is going into the printer anyway, just resting it on the pad is enough." },  // STR_AMS_INFO
  { "Aus",                           "Off"                                },  // STR_AMS_MODE_OFF
  { "Nachfragen",                    "Ask"                                },  // STR_AMS_MODE_ASK
  { "Immer an",                      "Always"                             },  // STR_AMS_MODE_ALWAYS
  { "Es wird nichts vorgemerkt. Wiegen und Lagerort verhalten sich genau wie bisher.",
    "Nothing is reserved. Weighing and location behave exactly as before." },  // STR_AMS_OFF_DESC
  { "Beim Abnehmen wird gefragt, ob die Spule in den Drucker wandert. Ein Ja sendet das Gewicht und öffnet das Fenster.",
    "When the spool is lifted you are asked whether it goes into the printer. A yes sends the weight and opens the window." },  // STR_AMS_ASK_DESC
  { "Jede Wiegung merkt die Spule vor, ohne Nachfrage. Auch wenn du nur kurz nachwiegen wolltest.",
    "Every weighing reserves the spool, without asking. Even when you only wanted to check a weight." },  // STR_AMS_ALWAYS_DESC
  { "Fenster",                       "Window"                             },  // STR_AMS_WINDOW_LBL
  { "wie lange die Spule vorgemerkt bleibt", "how long the spool stays reserved" },  // STR_AMS_WINDOW_HINT
  { "s",                             "s"                                  },  // STR_AMS_SEC_UNIT
  { "Bei Ablauf",                    "When it runs out"                   },  // STR_AMS_TIMER_LBL
  { "wenn niemand antwortet",        "when nobody answers"                },  // STR_AMS_TIMER_HINT
  { "Ja",                            "Yes"                                },  // STR_AMS_TIMER_YES
  { "Nein",                          "No"                                 },  // STR_AMS_TIMER_NO
  { "Spule jetzt ins AMS legen?",    "Putting the spool into the AMS?"    },  // STR_AMS_POPUP_Q
  { "Zuordnung startet in %d s",     "Assignment starts in %d s"          },  // STR_AMS_POPUP_STARTS_IN
  { "Ohne Zuordnung in %d s",        "Without assigning in %d s"          },  // STR_AMS_POPUP_CLOSES_IN
  { "Ja, zuordnen",                  "Yes, assign"                        },  // STR_AMS_BTN_YES
  { "Der ApiKey darf keine Geräte verwalten",
    "This ApiKey may not manage devices" },  // STR_AMS_ERR_FORBIDDEN
  { "Server antwortet nicht (HTTP %d)", "Server not answering (HTTP %d)"  },  // STR_AMS_ERR_HTTP
  { "%.0f g sind gespeichert",       "%.0f g are saved"                   },  // STR_AMS_POPUP_SAVED
  { "Zuordnung %d s",                "Assigning %d s"                     },  // STR_AMS_WINDOW_RUNNING
  { "Server: Zuordnung aktiv",       "Server: assigning active"           },  // STR_AMS_SRV_ON
  { "Server: aus",                   "Server: off"                        },  // STR_AMS_SRV_OFF
  { "%.0f g werden dabei gespeichert", "%.0f g will be saved too"           },  // STR_AMS_POPUP_WILL_SAVE
  { "Neu aus Tag anlegen",           "Create from tag"                    },  // STR_NEWTAG_BTN
  { "Spule aus Tag anlegen?",        "Create spool from tag?"             },  // STR_NEWTAG_TITLE
  { "%s %s\nFarbe: %s\nWaagengewicht (netto): %.0f g", "%s %s\nColour: %s\nScale weight (net): %.0f g" },  // STR_NEWTAG_MSG
  { "Nenngewicht",                   "Label weight"                       },  // STR_NEWTAG_LABEL_W
  { "Spule angelegt!",               "Spool created!"                     },  // STR_NEWTAG_OK
  { "Anlegen fehlgeschlagen",        "Could not create spool"             },  // STR_NEWTAG_FAIL

  { "Tag-Feld",                      "Tag field"                          },  // STR_TAG_FIELD
  { "Jedes Projekt legt die Tag-UID in ein anderes Extra-Feld, weil Spoolman "
    "lange keines dafür hatte. Das ändert sich gerade: Spoolman bekommt ein "
    "eigenes Tag-Modell.\n\n"
    "Hier wird bestimmt, wohin die Waage schreibt. Kann der Server das native "
    "Modell, wählt sie es beim ersten Scan von selbst - eine Auswahl, die du "
    "selbst getroffen hast, bleibt stehen.\n\n"
    "Gelesen wird immer aus allen Quellen, damit beim Umstellen keine Spule "
    "unsichtbar wird. Beim nächsten Verknüpfen wandert eine anderswo gefundene "
    "UID in die gewählte Quelle.\n\n"
    "Ein Extra-Feld muss dafür auf dem Server existieren - sonst lehnt Spoolman "
    "jedes Schreiben mit HTTP 400 ab und die schnelle Suche fällt auf das Laden "
    "des ganzen Inventars zurück. Für Spoolman NFC gilt das nicht, dort ist "
    "kein Feld anzulegen.",
    "Every project puts the tag UID in a different extra field, because "
    "Spoolman had none for it for a long time. That is changing: Spoolman has "
    "grown a tag model of its own.\n\n"
    "This is where you say what the scale writes to. On a server that has the "
    "native model it picks that by itself on the first scan; a choice you made "
    "yourself is left alone.\n\n"
    "Every source is always read, so nothing goes missing when you switch. On "
    "the next link a UID found elsewhere moves into the selected source.\n\n"
    "An extra field has to exist on the server for that - otherwise Spoolman "
    "rejects every write with HTTP 400 and the fast search falls back to "
    "loading the whole inventory. Spoolman NFC is exempt: there is no field to "
    "create."                                                              },  // STR_TAG_FIELD_INFO

  { "Spoolman NFC (nativ)",          "Spoolman NFC (native)"              },  // STR_TF_NATIVE
  { "Vom Server unterstützt",        "Supported by the server"            },  // STR_TF_NATIVE_SUB
  { "Erst ab Spoolman v0.27",        "Spoolman v0.27 and later"           },  // STR_TF_NATIVE_NA
  { "Spoolman hat inzwischen ein eigenes Tag-Modell, statt einer UID in einem "
    "Extra-Feld. Es ist noch in keiner Version enthalten - diese Zeile wird "
    "erst wählbar, wenn der Server es kann.\n\n"
    "Was es besser macht: eine Spule kann mehrere Tags tragen, ohne Liste in "
    "einem Textfeld. Ein Scan ist eine einzige Anfrage, die die Spule gleich "
    "mitliefert, statt Suche plus Nachprüfung. Und ein Tag, der schon an einer "
    "anderen Spule hängt, wird als solcher gemeldet statt still "
    "überschrieben.\n\n"
    "Die Extra-Felder bleiben trotzdem wählbar: SpoolLink, SpoolSense und "
    "FilaMan schreiben weiter ihre eigenen, und wer eines davon parallel "
    "betreibt, braucht es.",
    "Spoolman has grown a tag model of its own, instead of a UID in an extra "
    "field. No release carries it yet - this entry only becomes selectable "
    "once the server has it.\n\n"
    "What it does better: a spool can hold several tags with no list squeezed "
    "into a text field. A scan is one request that returns the spool with it, "
    "rather than a search plus a verification pass. And a tag that already "
    "belongs to another spool is reported as such instead of being silently "
    "overwritten.\n\n"
    "The extra fields stay selectable regardless: SpoolLink, SpoolSense and "
    "FilaMan keep writing their own, and anyone running one of them alongside "
    "still needs it."                                                     },  // STR_TF_NATIVE_INFO
  { "extra.tag",                     "extra.tag"                          },  // STR_TF_TAG
  { "Diese Waage, OpenSpoolman",     "This scale, OpenSpoolman"           },  // STR_TF_TAG_SUB
  { "Das Feld, das diese Waage seit jeher benutzt, und das auch OpenSpoolman "
    "und spoolnymous schreiben.\n\n"
    "Ein Wert pro Spule, kein Listenformat. Die Waage legt die UID so ab, wie "
    "sie sie liest - mit Doppelpunkten, bei Bambu-Tags die tray_uuid. "
    "OpenSpoolman legt dort eine eigene UUID ab, die Feldbelegung ist also "
    "gleich, der Inhalt nicht zwingend.\n\n"
    "Die richtige Wahl, wenn nichts dagegen spricht.",
    "The field this scale has always used, and the one OpenSpoolman and "
    "spoolnymous write as well.\n\n"
    "One value per spool, no list format. The scale stores the UID the way it "
    "reads it, with colons, and the tray_uuid for Bambu tags. OpenSpoolman "
    "puts a UUID of its own in there, so the field matches but the contents "
    "need not.\n\n"
    "The right choice unless something speaks against it."                },  // STR_TF_TAG_INFO

  { "extra.nfc_id",                  "extra.nfc_id"                       },  // STR_TF_NFCID
  { "FilaMan, nfc2klipper, SpoolSense", "FilaMan, nfc2klipper, SpoolSense" },  // STR_TF_NFCID_SUB
  { "Das Feld, auf das sich FilaMan, nfc2klipper und SpoolSense geeinigt "
    "haben.\n\n"
    "Ein Wert pro Spule, kein Listenformat. Erwartet wird reines Hex in "
    "Grossbuchstaben ohne Trenner - die Waage schreibt hier also "
    "04A1B2C3D4E5F6 statt 04:A1:B2:C3:D4:E5:F6, sonst finden die anderen "
    "Programme die UID nicht.\n\n"
    "Sinnvoll, wenn eines davon parallel auf dieselbe Spoolman-Datenbank "
    "zugreift.",
    "The field FilaMan, nfc2klipper and SpoolSense settled on.\n\n"
    "One value per spool, no list format. It expects plain uppercase hex "
    "without separators, so the scale writes 04A1B2C3D4E5F6 rather than "
    "04:A1:B2:C3:D4:E5:F6 - otherwise the other tools will not find the "
    "UID.\n\n"
    "Useful when one of them works on the same Spoolman database."        },  // STR_TF_NFCID_INFO

  { "extra.card_uids",               "extra.card_uids"                    },  // STR_TF_CARDUIDS
  { "SpoolLink, Snapmaker U1",       "SpoolLink, Snapmaker U1"            },  // STR_TF_CARDUIDS_SUB
  { "Das Feld, das SpoolLink in der Snapmaker-Firmware und Spool Studio "
    "benutzen.\n\n"
    "Das einzige Extra-Feld, das eine Liste aufnimmt: mehrere UIDs, "
    "kommagetrennt, reines Hex in Grossbuchstaben. Beim Snapmaker U1 ist das "
    "die Regel, weil eine Spule je ein Tag pro Flansch trägt und auf beide "
    "Seiten des Druckers passen muss.\n\n"
    "Von den Extra-Feldern lässt nur dieses die Option \"Mehrere Tags "
    "verknüpfen\" zu. Spoolman NFC kann das ebenfalls und braucht keinen "
    "Schalter dafür, weil mehrere Tags dort der Normalfall sind statt eines "
    "Formats in einem Textfeld. Wer die Wahl hat, nimmt Spoolman NFC - dieses "
    "Feld ist die richtige Wahl, wenn SpoolLink daneben laufen soll.",
    "The field SpoolLink in the Snapmaker firmware and Spool Studio use.\n\n"
    "The only extra field that holds a list: several UIDs, comma separated, "
    "plain uppercase hex. On the Snapmaker U1 that is the rule, because a "
    "spool carries one tag per flange so it fits either side of the "
    "printer.\n\n"
    "Of the extra fields only this one allows \"Link multiple tags\". Spoolman "
    "NFC can do it too and needs no switch, because several tags are the "
    "normal case there rather than a format squeezed into a text field. Given "
    "the choice, take Spoolman NFC - this field is the right one when "
    "SpoolLink is to run alongside."                                       },  // STR_TF_CARDUIDS_INFO

  { "Trocknungsdatum",               "Drying date"                        },  // STR_EF_LAST_DRIED
  { "extra.last_dried",              "extra.last_dried"                   },  // STR_EF_LAST_DRIED_SUB
  { "Wann die Spule zuletzt getrocknet wurde. Spoolman hat dafür kein eigenes "
    "Feld, deshalb schreibt die Waage es nach extra.last_dried.\n\n"
    "Fehlt das Feld, bleibt die Trocknungsanzeige leer und der Knopf "
    "\"Getrocknet\" kann nichts speichern. Sonst ändert sich nichts.",
    "When the spool was last dried. Spoolman has no field of its own for it, "
    "so the scale writes it to extra.last_dried.\n\n"
    "Without the field the drying line stays empty and the \"Dried\" button "
    "has nowhere to save. Nothing else changes."                          },  // STR_EF_LAST_DRIED_INFO

  { "vorhanden",                     "present"                            },  // STR_EF_PRESENT
  { "fehlt auf dem Server",          "missing on the server"              },  // STR_EF_MISSING
  { "Feld auf dem Server anlegen",   "Create the field on the server"     },  // STR_EF_CREATE_ROW
  { "Lade Spulen ...",               "Loading spools ..."                 },  // STR_LOADING_SPOOLS
  { "%d Spulen, sortiere ...",       "%d spools, sorting ..."             },  // STR_LOADING_FILTER

  // ── Web interface ─────────────────────────────────────
  { "Status",
    "Status" },  // STR_W_NAV_STATUS
  { "Backend",
    "Backend" },  // STR_W_NAV_BACKEND
  { "Trocknung",
    "Drying" },  // STR_W_NAV_DRYING
  { "Tags schreiben",
    "Write tags" },  // STR_W_NAV_TAGS
  { "Einstellungen",
    "Settings" },  // STR_W_NAV_SETTINGS
  { "Logs",
    "Logs" },  // STR_W_NAV_LOGS
  { "Firmware",
    "Firmware" },  // STR_W_NAV_FIRMWARE
  { "Keine Verbindung zu Spoolman, FilaMan oder BamBuddy - Open-Source-Projekt",
    "Not affiliated with Spoolman, FilaMan or BamBuddy - Open Source Project" },  // STR_W_DISCLAIMER
  { "Speichern",
    "Save" },  // STR_W_SAVE
  { "Gespeichert",
    "Saved" },  // STR_W_SAVED
  { "Fehler",
    "Error" },  // STR_W_ERROR
  { "Auf Standard zurück",
    "Reset to defaults" },  // STR_W_DEFAULTS
  { "%s ist ausgeschaltet",
    "%s is switched off" },  // STR_W_OFF_TITLE
  { "Dieser Bereich ist am Gerät abgeschaltet und wird deshalb nicht ausgeliefert.",
    "This section is disabled on the device, so it is not being served." },  // STR_W_OFF_BODY
  { "Hier einschalten:",
    "Turn it on here:" },  // STR_W_OFF_WHERE
  { "Einstellungen &rsaquo; System &rsaquo; Weboberfläche",
    "Settings &rsaquo; System &rsaquo; Web interface" },  // STR_W_OFF_PATH
  { "Danach diese Seite neu laden.",
    "Then reload this page." },  // STR_W_OFF_RELOAD
  { "Zurück zum Status",
    "Back to status" },  // STR_W_BACK_STATUS
  { "Netzwerk",
    "Network" },  // STR_W_C_NETWORK
  { "Hardware",
    "Hardware" },  // STR_W_C_HARDWARE
  { "Bestandsverwaltung",
    "Inventory" },  // STR_W_C_INVENTORY
  { "Zugriff",
    "Access" },  // STR_W_C_ACCESS
  { "Gerät",
    "Device" },  // STR_W_C_DEVICE
  { "WLAN",
    "WiFi" },  // STR_W_R_WIFI
  { "Adresse",
    "Address" },  // STR_W_R_ADDRESS
  { "Name",
    "Name" },  // STR_W_R_NAME
  { "Gateway",
    "Gateway" },  // STR_W_R_GATEWAY
  { "Waage",
    "Scale" },  // STR_W_R_SCALE
  { "NFC-Leser",
    "NFC reader" },  // STR_W_R_NFC
  { "SD-Karte",
    "SD card" },  // STR_W_R_SD
  { "Laufzeit",
    "Uptime" },  // STR_W_R_UPTIME
  { "Backend",
    "Backend" },  // STR_W_R_BACKEND
  { "Erreichbar",
    "Reachable" },  // STR_W_R_REACHABLE
  { "Tags gescannt",
    "Tags scanned" },  // STR_W_R_SCANS
  { "Ausführliches Protokoll",
    "Verbose logging" },  // STR_W_R_VERBOSE
  { "bereit",
    "ready" },  // STR_W_S_READY
  { "fehlt",
    "missing" },  // STR_W_S_MISSING
  { "an",
    "on" },  // STR_W_S_ON
  { "aus",
    "off" },  // STR_W_S_OFF
  { "ja",
    "yes" },  // STR_W_S_YES
  { "nein",
    "no" },  // STR_W_S_NO
  { "nicht verbunden",
    "not connected" },  // STR_W_S_NOWIFI
  { "Was ausgeschaltet ist, wird nicht ausgeliefert - auch die Endpunkte dahinter nicht. Umschalten am Gerät unter",
    "A section that is off is not served at all, and neither are the endpoints behind it. Switch it on the device under" },  // STR_W_ACCESS_NOTE
  { "Neu starten",
    "Restart" },  // STR_W_RESTART
  { "Alle Einstellungen liegen im NVS, ein Neustart verliert nichts.",
    "Settings are kept in NVS, so a restart loses nothing." },  // STR_W_RESTART_NOTE
  { "Gerät jetzt neu starten?",
    "Restart the device now?" },  // STR_W_RESTART_ASK
  { "Startet neu",
    "Restarting" },  // STR_W_RESTARTING
  { "warte auf das Gerät",
    "waiting for the device" },  // STR_W_RESTART_WAIT
  { " (SD-Karte steckt, der Start dauert rund 20 s länger)",
    " (SD card fitted, boot takes about 20s longer)" },  // STR_W_RESTART_SD
  { "immer noch am Warten",
    "still waiting" },  // STR_W_RESTART_LONG
  { "Das Gerät hat nicht geantwortet. Vielleicht ist es nicht mehr im Netz -",
    "The device has not answered. It may be off the network -" },  // STR_W_RESTART_GONE
  { "neu laden",
    "reload" },  // STR_W_RELOAD
  { "Adresse",
    "Address" },  // STR_W_C_BACKEND_ADDR
  { "Adresse des Backends",
    "Backend address" },  // STR_W_HOST_LABEL
  { "Hostname oder IP, bei Bedarf mit Port. Ein Name funktioniert auch hinter einem Reverse Proxy, wo die IP allein nicht ans Ziel führt.",
    "Host name or IP, with a port when one is needed. A name also works behind a reverse proxy, where the IP alone does not reach the target." },  // STR_W_HOST_HINT
  { "Ohne Port geht es auf 80. Üblich sind Spoolman 7912, FilaMan 8002, BamBuddy 8000.",
    "Without a port this goes to 80. The usual ones are Spoolman 7912, FilaMan 8002, BamBuddy 8000." },  // STR_W_HOST_PORTHINT
  { "Die Adresse darf nicht leer sein.",
    "The address cannot be empty." },  // STR_W_HOST_EMPTY
  { "https wird noch nicht unterstützt. Die Waage spricht nur http.",
    "https is not supported yet. The scale speaks plain http only." },  // STR_W_HOST_HTTPS
  { "Verbinde ...",
    "Connecting ..." },  // STR_W_HOST_TESTING
  { "Erreichbar",
    "Reachable" },  // STR_W_HOST_OK
  { "Nicht erreichbar",
    "Not reachable" },  // STR_W_HOST_FAIL
  { "Zugangsdaten",
    "Credentials" },  // STR_W_C_CREDS
  { "API-Key",
    "API key" },  // STR_W_APIKEY
  { "Gerätecode",
    "Device code" },  // STR_W_DEVICE_CODE
  { "Registrieren",
    "Register" },  // STR_W_REGISTER
  { "hinterlegt",
    "set" },  // STR_W_SET
  { "fehlt",
    "missing" },  // STR_W_UNSET
  { "Spoolman braucht keine Zugangsdaten.",
    "Spoolman needs no credentials." },  // STR_W_NO_CREDS
  { "Schwellwerte je Material",
    "Thresholds per material" },  // STR_W_C_DRYING
  { "Material",
    "Material" },  // STR_W_DRY_MATERIAL
  { "Gelb ab",
    "Amber after" },  // STR_W_DRY_YELLOW
  { "Rot ab",
    "Red after" },  // STR_W_DRY_RED
  { "Lagerung",
    "Storage" },  // STR_W_DRY_STORAGE
  { "offen",
    "open" },  // STR_W_DRY_OPEN
  { "trocken",
    "sealed" },  // STR_W_DRY_SEALED
  { "Tage",
    "days" },  // STR_W_DRY_DAYS
  { "Faktor für trockene Lagerung",
    "Multiplier for sealed storage" },  // STR_W_DRY_MULT
  { "Luftdicht gelagert hält Filament länger. Die Schwellwerte oben werden für diese Materialien mit dem Faktor multipliziert.",
    "Filament stored airtight lasts longer. The thresholds above are multiplied by this factor for those materials." },  // STR_W_DRY_MULT_HINT
  { "Gerätename",
    "Device name" },  // STR_W_C_DEVNAME
  { "Name oder ganze Adresse, zum Beispiel scale.home.arpa. Der Teil vor dem ersten Punkt ist auch der Name, den der Router zeigt.",
    "A name, or a whole address such as scale.home.arpa. The part before the first dot is also the name your router shows." },  // STR_W_DEVNAME_HINT
  { "Buchstaben, Ziffern und Bindestriche, durch Punkte getrennt. Kein Bindestrich am Anfang oder Ende, keine Leerzeichen, kein leerer Teil zwischen zwei Punkten.",
    "Letters, digits and hyphens, separated by dots. No hyphen at the start or end, no spaces, no empty part between two dots." },  // STR_W_DEVNAME_BAD
  { "Jetzt erreichbar unter %s - beim Router nach dem nächsten Verbinden.",
    "Reachable now at %s - the router shows it after the next connection." },  // STR_W_DEVNAME_NOW
  { "Listenlimits",
    "List limits" },  // STR_W_C_LIMITS
  { "Spulenliste",
    "Spool list" },  // STR_W_LIMIT_SPOOLS
  { "Standortliste",
    "Location list" },  // STR_W_LIMIT_LOCS
  { "Wie viele Einträge die Auswahl am Gerät zeigt.",
    "How many entries the picker on the device shows." },  // STR_W_LIMIT_HINT
  { "Zu viele können einen Neustart auslösen.",
    "Too many may cause a reboot." },  // STR_W_LIMIT_WARN
  { "Anzeige",
    "Display" },  // STR_W_C_DISPLAY
  { "Helligkeitsanhebung",
    "Brightness lift" },  // STR_W_GAIN
  { "100 ist aus. Die Hintergrundbeleuchtung ist bei 255 schon am Anschlag, das hier ist der verbleibende Hebel auf ein dunkles Panel.",
    "100 is off. The backlight is already at its ceiling at 255, so this is the only remaining lever on a dim panel." },  // STR_W_GAIN_HINT
  { "Tag beschreiben",
    "Write a tag" },  // STR_W_C_WRITETAG
  { "Spule",
    "Spool" },  // STR_W_TAG_SPOOL
  { "-- Spule wählen --",
    "-- pick a spool --" },  // STR_W_TAG_PICK
  { "Format",
    "Format" },  // STR_W_TAG_FORMAT
  { "Auf dem Tag",
    "On the tag" },  // STR_W_TAG_ONTAG
  { "Würde geschrieben",
    "Will be written" },  // STR_W_TAG_WILLBE
  { "Kein Tag auf dem Leser.",
    "No tag on the reader." },  // STR_W_TAG_NOTAG
  { "Tag auf dem Leser:",
    "Tag on the reader:" },  // STR_W_TAG_ONREADER
  { "Erst eine Spule wählen.",
    "Pick a spool first." },  // STR_W_TAG_PICKFIRST
  { "Leerer Tag",
    "Blank tag" },  // STR_W_TAG_BLANK
  { "Daten, die diese Firmware nicht lesen kann",
    "Data this firmware cannot read" },  // STR_W_TAG_UNKNOWN
  { "Tag beschreiben",
    "Write tag" },  // STR_W_TAG_WRITE
  { "Tag überschreiben",
    "Overwrite tag" },  // STR_W_TAG_OVERWRITE
  { "Tag stimmt bereits überein",
    "Tag already matches" },  // STR_W_TAG_MATCHES
  { "Tag leeren",
    "Erase tag" },  // STR_W_TAG_ERASE
  { "Alles auf diesem Tag löschen?",
    "Erase everything on this tag?" },  // STR_W_TAG_ERASE_ASK
  { "Spule mit diesem Tag verknüpfen",
    "Link the spool to this tag" },  // STR_W_TAG_LINK
  { "Diese Spule hängt an %s, das damit zum vorherigen Tag wird.",
    "This spool is linked to %s, which becomes its previous tag." },  // STR_W_TAG_RELINK
  { "Eingereiht.",
    "Queued." },  // STR_W_TAG_QUEUED
  { "Spulenliste nicht verfügbar",
    "Spool list unavailable" },  // STR_W_TAG_NOLIST
  { "SKU",
    "SKU" },  // STR_W_TAG_SKU
  { "Düse",
    "Nozzle" },  // STR_W_TAG_NOZZLE
  { "Bett",
    "Bed" },  // STR_W_TAG_BED
  { "Gewicht",
    "Weight" },  // STR_W_TAG_WEIGHT
  { "Durchmesser",
    "Diameter" },  // STR_W_TAG_DIA
  { "Länge",
    "Length" },  // STR_W_TAG_LENGTH
  { "Beide Seiten kommen aus demselben Formatierer, deshalb sind sie Zeichen für Zeichen vergleichbar.",
    "Both sides come from the same formatter, so they compare character for character." },  // STR_W_TAG_COMPARE
  { "SD-Karte",
    "SD card" },  // STR_W_C_LOGS
  { "Ansehen",
    "View" },  // STR_W_LOG_VIEW
  { "Löschen",
    "Delete" },  // STR_W_LOG_DELETE
  { "Diese Datei löschen?",
    "Delete this file?" },  // STR_W_LOG_DELETE_ASK
  { "Keine SD-Karte erkannt",
    "No SD card detected" },  // STR_W_LOG_NOSD
  { "Eine FAT32-formatierte Karte einlegen, um die Diagnoseprotokolle zu aktivieren. Mit Karte dauert der Start rund 20 Sekunden länger.",
    "Insert a FAT32 formatted card to enable diagnostic logging. Booting with a card takes about 20 seconds longer." },  // STR_W_LOG_NOSD_HINT
  { "Noch keine Protokolle.",
    "No logs yet." },  // STR_W_LOG_EMPTY
  { "Firmware",
    "Firmware" },  // STR_W_C_FIRMWARE
  { "Installiert",
    "Installed" },  // STR_W_FW_INSTALLED
  { "Datei hochladen",
    "Upload a file" },  // STR_W_FW_FILE
  { "Flashen",
    "Flash" },  // STR_W_FW_FLASH
  { "Das Gerät startet nach dem Schreiben von selbst neu. Strom nicht trennen.",
    "The device restarts by itself once written. Do not cut the power." },  // STR_W_FW_HINT
  { "Update erfolgreich",
    "Update successful" },  // STR_W_FW_OK
  { "Das Gerät startet neu ...",
    "Device is restarting ..." },  // STR_W_FW_RESTARTING
  { "Update fehlgeschlagen",
    "Update failed" },  // STR_W_FW_FAIL
  { "Bitte erneut versuchen.",
    "Please try again." },  // STR_W_FW_RETRY
  { "Gewicht",
    "Weight" },  // STR_W_R_WEIGHT
  { "Konnte nicht geladen werden.",
    "Could not be loaded." },  // STR_W_LOAD_FAIL
  { "Eine eingelegte SD-Karte verlängert den Start um rund 20 Sekunden. Für den normalen Betrieb ohne Karte laufen lassen und sie nur zum Suchen eines Fehlers einlegen.",
    "A fitted SD card makes the device take about 20 seconds longer to start. Run it without a card normally and insert one only to chase a fault." },  // STR_W_LOG_NOTE
  { "Einen beschreibbaren NTAG auflegen, Spule wählen, schreiben. Was auf dem Tag steht, wird ersetzt. Werkstags sind meist MIFARE Classic oder gesperrt und lassen sich nur lesen.",
    "Place a writable NTAG on the reader, pick a spool, and write it. Whatever is already on the tag is replaced. Factory tags are usually MIFARE Classic or locked, and can only be read." },  // STR_W_TAG_NOTE
  { "<b>Welcher Tag für welches Format.</b> OpenSpool braucht rund 170 Byte und damit einen <b>NTAG215</b> (496 Byte) oder <b>NTAG216</b> (872 Byte). Auf einen NTAG213 (144 Byte) passt davon nichts, dort geht nur Anycubic ACE, das mit 112 Byte auskommt. Meldet ein Tag keine Größe, rechnet die Waage sicherheitshalber mit den 144 Byte eines NTAG213 - dann den Tag einmal mit einer NFC-App als NDEF formatieren, das trägt die Größe ein.",
    "<b>Which tag for which format.</b> OpenSpool needs about 170 bytes, so it wants an <b>NTAG215</b> (496 bytes) or an <b>NTAG216</b> (872 bytes). None of it fits an NTAG213 (144 bytes), which leaves Anycubic ACE, and that needs only 112. A tag that reports no size at all is treated as the 144 bytes of an NTAG213 to stay safe - format such a tag as NDEF once with any NFC app and it will report its real size." },  // STR_W_TAG_SIZES
  { "In FilaMan auf den Benutzernamen klicken, dort <b>API keys</b> wählen und einen Schlüssel anlegen. Er wird nur einmal angezeigt, also gleich kopieren. Danach zeigt FilaMan einen sechsstelligen Gerätecode - den unten eintragen und registrieren.",
    "In FilaMan, click your user name, choose <b>API keys</b> and create a key. It is shown once, so copy it right away. FilaMan then shows a six character device code - enter it below and register." },  // STR_W_FM_SETUP
  { "Der Schlüssel steht in BamBuddy unter den Einstellungen. Läuft die Instanz ohne Anmeldung, bleibt das Feld leer.",
    "The key is in BamBuddy under settings. Leave the field empty if the instance runs without authentication." },  // STR_W_BB_SETUP
  { "Strom nicht trennen",
    "Do not cut the power" },  // STR_OTA_KEEP_POWER
  { "Kaffee ausgeben",
    "Buy me a coffee" },  // STR_W_KOFI
  { "Adresse ist ein Name",
    "Address is a name" },  // STR_SP_LOCKED_TITLE
  { "Dieser Ziffernblock kann nur Zahlen. Die Adresse im Browser ändern:",
    "This keypad can only make numbers. Change the address in the browser:" },  // STR_SP_LOCKED_INFO
  { "Weboberfläche aus: Einstellungen > System > Weboberfläche",
    "Web interface off: Settings > System > Web interface" },  // STR_SP_WEB_OFF
  { "Adresse leeren",
    "Clear address" },  // STR_SP_CLEAR
  { "Adresse verwerfen? Danach ist das Backend nicht mehr eingerichtet, und am Gerät lässt sich nur eine IP eingeben.",
    "Discard the address? The backend is then no longer set up, and the device itself can only enter an IP." },  // STR_SP_CLEAR_ASK
  { "Alle löschen",
    "Delete all" },  // STR_W_LOG_DELETE_ALL
  { "{n} Dateien löschen? Das Log von heute wird dabei neu begonnen.",
    "Delete {n} files? Today's log is started over." },  // STR_W_LOG_DELETE_ALL_ASK
  { "{n} Dateien",
    "{n} files" },  // STR_W_LOG_COUNT
  // Its own entry rather than a rule in code: which counts need their own
  // wording is a property of the language, not of the list.
  { "1 Datei",
    "1 file" },  // STR_W_LOG_COUNT_ONE
  { "Eine Datei löschen? Das Log von heute wird dabei neu begonnen.",
    "Delete one file? Today's log is started over." },  // STR_W_LOG_DELETE_ALL_ASK_ONE

  { "Felder",
    "Fields" },  // STR_FLM_FIELDS
  { "wohin der Tag geschrieben wird",
    "where the tag is written" },  // STR_FLM_FIELDS_SUB
  { "FilaMan hat ein eigenes Feld für NFC-Tags, und die Waage benutzt es. Daneben führt das Bambu-Lab-Plugin zwei Felder für die RFID-Chips einer Bambu-Spule und merkt sich die Tray-UUID in external_id.\n\nGelesen werden alle vier, immer und ohne Schalter: eine Spule, die der Drucker kennt, soll die Waage auch erkennen. Geschrieben wird nur, was hier eingeschaltet ist.",
    "FilaMan has a field of its own for NFC tags and the scale uses it. Alongside it the Bambu Lab plugin keeps two fields for the RFID chips of a Bambu spool, and remembers the tray uuid in external_id.\n\nAll four are read, always and without a switch: a spool the printer knows is a spool this scale should recognise. Only what is switched on here is written." },  // STR_FLM_FIELDS_INFO

  { "Tag-Feld",
    "Tag field" },  // STR_FLM_TAGFIELD
  { "Anders als bei Spoolman gibt es hier nichts zu wählen, und das ist gut so. rfid_uid ist FilaMans eigenes Feld für genau diesen Zweck, es ist das einzige, das die Server-Suche durchsucht, und das Bambu-Plugin fasst es laut eigener Zusage nie an.\n\nEin Ausweichfeld würde jeden Scan vom Schnellpfad auf den vollen Inventar-Scan werfen: unter 1 kB gegen 176 kB bei 280 Spulen.",
    "Unlike Spoolman there is nothing to choose here, and that is a good thing. rfid_uid is FilaMan's own field for exactly this, it is the only one the server side search covers, and the Bambu plugin never touches it - its own documentation says so.\n\nWriting somewhere else would drop every scan from the fast path to a full inventory load: under 1 kB against 176 kB on a library of 280." },  // STR_FLM_TAGFIELD_INFO

  { "Bambu-Tag-Felder pflegen",
    "Maintain the Bambu tag fields" },  // STR_FLM_BTAGS
  { "Chip-UID in den ersten freien Slot",
    "chip uid into the first free slot" },  // STR_FLM_BTAGS_SUB
  { "Eine Bambu-Spule trägt zwei RFID-Chips, einen je Seite. Das Plugin füllt nur den ersten der beiden Felder, mit dem, was der Drucker gemeldet hat; den zweiten hält es für einen weiteren Leser frei.\n\nAn: die Waage trägt die Chip-UID der aufliegenden Seite in den ersten freien der beiden Slots ein. Ein belegter Slot wird nie überschrieben. Legt man beide Seiten auf, sind danach beide gefüllt.\n\nNutzen: die Spule wird auch dann gefunden, wenn sich ihr Tag nicht entschlüsseln lässt und nur seine Chip-UID hergibt.",
    "A Bambu spool carries two RFID chips, one per flange. The plugin fills only the first of the two fields, with what the printer reported, and keeps the second free for another reader.\n\nOn: the scale writes the chip uid of the side on the reader into the first free of the two slots. A slot that holds something is never overwritten. Present both sides and both end up filled.\n\nWhat it buys: the spool is still found when its tag will not decrypt and has nothing but its chip uid to offer." },  // STR_FLM_BTAGS_INFO

  { "external_id mitschreiben",
    "Write external_id too" },  // STR_FLM_EXTID
  { "verhindert doppelte Spulen",
    "stops duplicate spools" },  // STR_FLM_EXTID_SUB
  { "Das Bambu-Plugin prüft vor dem Anlegen einer Spule nur external_id. Eine von der Waage verknüpfte Spule trägt die Tray-UUID aber in rfid_uid und ist für diese Prüfung unsichtbar - sie wird ein zweites Mal angelegt.\n\nAn: die Waage trägt bambulab:<Tray-UUID> nach, solange das Feld leer ist. Damit hören die Doppel auf.\n\nDer Preis: das Plugin behandelt die Spule danach als seine und schreibt das Restgewicht aus der AMS-Schätzung fort. Bis zur nächsten Wägung steht dann eine Schätzung dort, wo ein gemessener Wert stand.",
    "Before creating a spool the Bambu plugin looks at external_id and nothing else. A spool linked by this scale carries the tray uuid in rfid_uid instead and is invisible to that check, so it gets created a second time.\n\nOn: the scale fills in bambulab:<tray uuid> while the field is empty. That ends the duplicates.\n\nThe price: the plugin then treats the spool as its own and maintains the remaining weight from the AMS estimate. Until the next weighing an estimate stands where a measured value stood." },  // STR_FLM_EXTID_INFO

  { "Tag gefunden - mehrere Spulen",
    "Tag found - several spools" },  // STR_TAG_FOUND_DUP

  // ---- device name --------------------------------------------------
  { "mDNS",
    "mDNS" },  // STR_W_R_MDNS
  { "Auch erreichbar über",
    "Also reachable at" },  // STR_W_DEVNAME_ALSO
  { "wird geprüft ...",
    "checking ..." },  // STR_W_DEVNAME_DNS_WAIT
  { "Der Name wird in deinem Netz aufgelöst und zeigt auf diese Waage.",
    "This name resolves on your network and points at this scale." },  // STR_W_DEVNAME_DNS_OK
  { "Der Name zeigt auf %s, nicht auf diese Waage.",
    "This name points at %s, not at this scale." },  // STR_W_DEVNAME_DNS_OTHER
  { "Dein DNS-Server kennt diesen Namen nicht.",
    "Your DNS server does not know this name." },  // STR_W_DEVNAME_DNS_NONE
  { "Im lokalen Netz auf .local antworten (mDNS)",
    "Answer to .local on the local network (mDNS)" },  // STR_W_MDNS
  { "Findet die Waage ohne DNS-Server. Aus, wenn in deinem Netz kein .local laufen soll.",
    "Finds the scale with no DNS server involved. Off if your network should carry no .local traffic." },  // STR_W_MDNS_HINT

  // Spool status (FilaMan). Id 6 is covered by STR_ARCHIVED above.
  { "Status wählen",         "Select status"              },  // STR_STATUS_TITLE
  { "Neu",                    "New"                        },  // STR_STATUS_NEW
  { "Geöffnet",              "Opened"                     },  // STR_STATUS_OPENED
  { "Trocknet",               "Drying"                     },  // STR_STATUS_DRYING
  { "Aktiv",                  "Active"                     },  // STR_STATUS_ACTIVE
  { "Leer",                   "Empty"                      },  // STR_STATUS_EMPTY
  { "Unbekannt",              "Unknown"                    },  // STR_STATUS_UNKNOWN
};
